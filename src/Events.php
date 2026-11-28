<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/Attest/Common.php';

use Atlas\Pca\Attest\Common;

/**
 * Typed step-up lifecycle events and Stripe-style signed webhooks: content-addressed events (the id is the digest of every other
 * field), `t=<unix>,v1=<hex HMAC-SHA256 of "<t>.<payload>">` signatures with a tolerance window and secret rotation, and
 * verifyDelivery (signature + freshness + a well-formed event + a first sight of its id). A transport contract, not a decision.
 * Mirrors @atlasauth/pca-events. A secret is a byte string (a text secret is its UTF-8 bytes); a payload is UTF-8 text.
 */
final class Events
{
    public const EVENT_TYPES = ['step_up.created', 'step_up.approved', 'step_up.denied', 'step_up.expired'];
    public const MIN_SECRET_BYTES = 16;
    private const MAX_HEADER_CHARS = 2048;
    private const EVENT_DOMAIN = 'atlas-pca/stepup-event/v1';

    /** base64url(sha256(strictCanonical(fields))); a missing member is refused, as the reference's canonical form refuses undefined. */
    private static function eventId(array $e): string
    {
        foreach (['type', 'at', 'grant_ref', 'tier'] as $k) {
            if (!array_key_exists($k, $e)) {
                throw new JsonError('canonicalize: unsupported type undefined');
            }
        }
        $a = $e['action'];
        if (!array_key_exists('verb', $a) || !array_key_exists('resource', $a)) {
            throw new JsonError('canonicalize: unsupported type undefined');
        }
        $f = Obj::of(['d' => self::EVENT_DOMAIN, 'type' => $e['type'], 'at' => $e['at'], 'grant_ref' => $e['grant_ref'],
            'action' => Obj::of(['verb' => $a['verb'], 'resource' => $a['resource']]), 'tier' => $e['tier']]);
        if (array_key_exists('actor', $e)) {
            $f->set('actor', $e['actor']);
        }
        try {
            return Pca::hashCanonical(IntentWb::norm($f));
        } catch (JsonError $x) {
            throw new JsonError(str_starts_with($x->getMessage(), 'canonicalize:') ? $x->getMessage() : 'canonicalize: ' . $x->getMessage());
        }
    }

    /** @param array<string,mixed> $out */
    private static function pick(mixed $h, string $k, array &$out): void
    {
        if (($h instanceof Obj && $h->has($k)) || (is_array($h) && array_key_exists($k, $h))) {
            $out[$k] = Js::opt($h, $k);
        }
    }

    private static function isObjLike(mixed $x): bool
    {
        return $x instanceof Obj || (is_array($x) && !array_is_list($x));
    }

    private static function wf(mixed $x): bool
    {
        return is_string($x) && !Json::hasLoneSurrogate($x);
    }

    /** The fields every event carries, checked the same way at build and at serialize time (fail closed on anything else). */
    private static function checkEventFields(string $who, mixed $e, bool $withId): void
    {
        $bad = static fn(string $m) => throw new \TypeError("$who: $m");
        if (!self::isObjLike($e)) {
            $bad('not an object');
        }
        $tier = Js::num(Js::opt($e, 'tier'));
        if (!in_array(Js::opt($e, 'type'), self::EVENT_TYPES, true) || ($tier !== 2.0 && $tier !== 3.0)) {
            $bad('unknown event type or tier');
        }
        if (Js::has($e, 'at')) {
            $at = Js::num(Js::opt($e, 'at'));
            if ($at === null || !is_finite($at)) {
                $bad('at must be a finite number');
            }
        }
        if (!self::wf(Js::opt($e, 'grant_ref'))) {
            $bad('grant_ref must be a well-formed string');
        }
        $a = Js::opt($e, 'action');
        if (!self::isObjLike($a) || !self::wf(Js::opt($a, 'verb')) || !self::wf(Js::opt($a, 'resource'))) {
            $bad('action must carry well-formed verb and resource strings');
        }
        if (Js::has($e, 'actor') && !self::wf(Js::opt($e, 'actor'))) {
            $bad('actor must be a well-formed string');
        }
        if ($withId && !self::wf(Js::opt($e, 'id'))) {
            $bad('id must be a well-formed string');
        }
    }

    /** Build a step-up event: `at` defaults to now (ms); the id is derived from every other field. */
    public static function buildStepUpEvent(mixed $type, mixed $data): array
    {
        $chk = self::isObjLike($data) ? ($data instanceof Obj ? (static function (Obj $d) use ($type): Obj { $c = clone $d; $c->set('type', $type); return $c; })($data) : ['type' => $type] + $data) : Obj::of(['type' => $type]);
        self::checkEventFields('buildStepUpEvent', $chk, false);
        $action = Js::opt($data, 'action');
        $base = ['type' => $type, 'at' => Js::opt($data, 'at') ?? (int)floor(self::clock() * 1000)];
        self::pick($data, 'grant_ref', $base);
        $act = [];
        self::pick($action, 'verb', $act);
        self::pick($action, 'resource', $act);
        $base['action'] = $act;
        self::pick($data, 'tier', $base);
        self::pick($data, 'actor', $base);
        $base['id'] = self::eventId($base);
        return $base;
    }

    /** JSON wire form (JSON.stringify). */
    public static function serializeEvent(mixed $e): string
    {
        self::checkEventFields('serializeEvent', $e, true);
        $at = Js::num(Js::opt($e, 'at'));
        if ($at === null || !is_finite($at)) {
            throw new \TypeError('serializeEvent: at must be a finite number');
        }
        return Js::stringify($e);
    }

    /** Parse + validate a JSON step-up event; throws on anything that is not a well-formed event or whose id is not its digest. */
    public static function parseEvent(mixed $s): array
    {
        if (!is_string($s)) {
            throw new \TypeError('parseEvent: not a string');
        }
        // the strict canonical profile (duplicate member, exponent or trailing-zero number, lone surrogate: refused), as the reference parses an event
        $o = IntentWb::norm(Json::parseStrict($s));
        if (!($o instanceof Obj) && !is_array($o)) {
            throw new \InvalidArgumentException('parseEvent: not an object');
        }
        $g = static fn(mixed $x, string $k): mixed => Js::opt($x, $k);
        $id = $g($o, 'id');
        if (!is_string($id) || $id === '') {
            throw new \InvalidArgumentException('parseEvent: bad id');
        }
        if (!in_array($g($o, 'type'), self::EVENT_TYPES, true)) {
            throw new \InvalidArgumentException('parseEvent: bad type');
        }
        $at = Js::num($g($o, 'at'));
        if ($at === null || !is_finite($at)) {
            throw new \InvalidArgumentException('parseEvent: bad at');
        }
        if (!is_string($g($o, 'grant_ref'))) {
            throw new \InvalidArgumentException('parseEvent: bad grant_ref');
        }
        $a = $g($o, 'action');
        if (!($a instanceof Obj) && !is_array($a)) {
            throw new \InvalidArgumentException('parseEvent: bad action');
        }
        if (!is_string($g($a, 'verb')) || !is_string($g($a, 'resource'))) {
            throw new \InvalidArgumentException('parseEvent: bad action fields');
        }
        $t = Js::num($g($o, 'tier'));
        if ($t !== 2.0 && $t !== 3.0) {
            throw new \InvalidArgumentException('parseEvent: bad tier');
        }
        $hasActor = $o instanceof Obj && $o->has('actor');
        if ($hasActor && !is_string($o->get('actor'))) {
            throw new \InvalidArgumentException('parseEvent: bad actor');
        }
        $ev = ['id' => $id, 'type' => $g($o, 'type'), 'at' => $g($o, 'at'), 'grant_ref' => $g($o, 'grant_ref'),
            'action' => ['verb' => $g($a, 'verb'), 'resource' => $g($a, 'resource')], 'tier' => (int)$t];
        if ($hasActor) {
            $ev['actor'] = $o->get('actor');
        }
        $fields = $ev;
        unset($fields['id']);
        if (self::eventId($fields) !== $id) {
            throw new \InvalidArgumentException('parseEvent: id does not match the event content');
        }
        return $ev;
    }

    private static function secretBytes(mixed $secret): ?string
    {
        return is_string($secret) && strlen($secret) >= self::MIN_SECRET_BYTES ? $secret : null;
    }

    /** @return ?array{t:int, v1:list<string>} of `t=<digits>,v1=<hex>[,v1=...]`; several v1 are allowed (rotation), two different t are not. */
    private static function parseSignatureHeader(mixed $h): ?array
    {
        if (!is_string($h) || Js::len($h) > self::MAX_HEADER_CHARS) {
            return null;
        }
        $t = null;
        $v1 = [];
        foreach (explode(',', $h) as $part) {
            $eq = strpos($part, '=');
            if ($eq === false) {
                continue;
            }
            $key = Common::jsTrim(substr($part, 0, $eq));
            $val = Common::jsTrim(substr($part, $eq + 1));
            if ($key === 't') {
                if (preg_match('/\A[0-9]{1,15}\z/', $val) !== 1) {
                    return null;
                }
                $n = (int)$val;
                if ($t !== null && $t !== $n) {
                    return null;
                }
                $t = $n;
            } elseif ($key === 'v1') {
                $v1[] = $val;
            }
        }
        return $t === null || $v1 === [] ? null : ['t' => $t, 'v1' => $v1];
    }

    private static function mac(string $key, mixed $t, string $payload): string
    {
        return hash_hmac('sha256', IntentWb::jsStr($t) . '.' . Js::utf8($payload), $key, true);
    }

    /** `t=<unixSeconds>,v1=<hex>`. Options: timestamp (default now). Throws on a short secret or a bad timestamp; the error never contains the secret. */
    public static function signWebhook(mixed $secret, string $payload, mixed $opts = null): string
    {
        $key = self::secretBytes($secret);
        if ($key === null) {
            throw new \RangeException('signWebhook: the secret must be at least ' . self::MIN_SECRET_BYTES . ' bytes');
        }
        $t = Js::opt($opts, 'timestamp') ?? time();
        if (!K3Sig::anySafeInt($t) || Js::num($t) < 0) {
            throw new \RangeException('signWebhook: timestamp must be a non-negative integer (unix seconds)');
        }
        return 't=' . IntentWb::jsStr($t) . ',v1=' . bin2hex(self::mac($key, $t, $payload));
    }

    /**
     * True iff the header carries a v1 HMAC of this payload within the tolerance (default 300 s). Never throws. Options:
     * toleranceSec, now (unix seconds). A valid signature is not proof of freshness beyond the window: use verifyDelivery.
     */
    public static function verifyWebhook(mixed $secret, mixed $payload, mixed $header, mixed $opts = null): bool
    {
        try {
            $key = self::secretBytes($secret);
            $parsed = self::parseSignatureHeader($header);
            if ($key === null || $parsed === null || !is_string($payload)) {
                return false;
            }
            $tolV = Js::opt($opts, 'toleranceSec') ?? 300;
            $nowV = Js::opt($opts, 'now') ?? time();
            $tol = Js::num($tolV);
            $now = Js::num($nowV);
            if ($tol === null || !is_finite($tol) || $tol < 0 || $now === null || !is_finite($now)) {
                return false;
            }
            if (abs($now - $parsed['t']) > $tol) {
                return false;
            }
            $expected = self::mac($key, $parsed['t'], $payload);
            $match = false;
            foreach ($parsed['v1'] as $v) {
                if (preg_match('/\A(?:[0-9a-fA-F]{2})*\z/', $v) !== 1) {
                    continue;
                }
                if (hash_equals($expected, (string)hex2bin($v))) {
                    $match = true; // no early exit: every candidate costs the same
                }
            }
            return $match;
        } catch (\Throwable) {
            return false;
        }
    }

    /** replayKey of the core package: `<namespace>:<b64u sha256 of the length-prefixed UTF-8 parts>`. */
    public static function replayKey(string $namespace, string ...$parts): string
    {
        $buf = '';
        foreach ([$namespace, ...$parts] as $p) {
            if (Json::hasLoneSurrogate($p)) {
                throw new \TypeError('replayKey: every part must be a well-formed string (no lone surrogates)');
            }
            $buf .= pack('N', strlen($p)) . $p;
        }
        return $namespace . ':' . Pca::b64u(hash('sha256', $buf, true));
    }

    /**
     * Accept one delivery: signature + freshness, a well-formed event, and a first sight of its id. Options: replay (an object
     * with consumeOnce(string $key, int $retainUntilMs, int $nowMs): bool, true on first sight), toleranceSec, now.
     * {ok: true, event} or {ok: false, reason}. Never throws; no reason carries the secret or the payload.
     */
    public static function verifyDelivery(mixed $secret, mixed $payload, mixed $header, mixed $opts): array
    {
        try {
            $replay = Js::opt($opts, 'replay');
            if (!is_object($replay) || !method_exists($replay, 'consumeOnce')) {
                return ['ok' => false, 'reason' => 'a replay store is required'];
            }
            if (!self::verifyWebhook($secret, $payload, $header, $opts)) {
                return ['ok' => false, 'reason' => 'bad signature'];
            }
            try {
                $event = self::parseEvent($payload);
            } catch (\Throwable $e) {
                return ['ok' => false, 'reason' => $e->getMessage()];
            }
            $sig = self::parseSignatureHeader($header);
            $now = Js::num(Js::opt($opts, 'now')) ?? (float)time();
            $tol = Js::num(Js::opt($opts, 'toleranceSec')) ?? 300.0;
            try {
                $first = $replay->consumeOnce(self::replayKey('pca-stepup-event/v1', $event['id']), (int)(($sig['t'] + $tol) * 1000 + 1), (int)($now * 1000));
                if ($first !== true) {
                    return ['ok' => false, 'reason' => 'replayed delivery'];
                }
            } catch (\Throwable) {
                return ['ok' => false, 'reason' => 'replay store unavailable'];
            }
            return ['ok' => true, 'event' => $event];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'bad signature'];
        }
    }

    /** The headers of an outbound webhook POST. */
    public static function webhookHeaders(mixed $secret, string $payload, mixed $opts = null): array
    {
        return ['PCA-Signature' => self::signWebhook($secret, $payload, $opts), 'content-type' => 'application/json'];
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
