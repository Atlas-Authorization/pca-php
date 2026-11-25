<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Intent statements (intent.ts + intent-binding.ts of the reference, re-exported by pca-intent statement.ts): the principal's
 * own words plus the structured reading, signed, with a content address (the intent ref) and the goal string that binds a
 * grant to it. Values are the parsed-JSON model (Obj, list arrays, string, Num / int / float, bool, null); options are an Obj or
 * an assoc array with the reference's names (`expectedSigner`, `pqPins`). Only Ed25519 signing is native.
 */
final class IntentStatement
{
    public const SIG_DOMAIN = "atlas-pca/intent/v1\0";
    public const REF_DOMAIN = 'atlas-pca/intent-ref/v1';
    public const GOAL_PREFIX = 'pca-intent:v1:';
    public const SOURCE_KINDS = ['conversation', 'ticket', 'document', 'form', 'other'];

    private const BODY_KEYS = ['v', 'principal', 'text', 'slots', 'sources', 'created_at', 'nonce'];

    private static function isObj(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    /** The signed body: suite fields and signatures excluded (the ref names the content). */
    public static function statementBody(mixed $s): Obj
    {
        $b = new Obj();
        foreach (self::BODY_KEYS as $k) {
            if (Js::has($s, $k)) {
                $b->set($k, Js::opt($s, $k));
            }
        }
        return $b;
    }

    /** Content address of an intent statement. */
    public static function intentRef(mixed $s): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::REF_DOMAIN, 's' => self::statementBody($s)]));
    }

    private static function shapeError(mixed $s): ?string
    {
        if (!self::isObj($s)) {
            return 'intent statement is not an object';
        }
        $v = Js::opt($s, 'v');
        if (!Js::isNum($v) || Js::num($v) !== 1.0) {
            return 'unsupported intent statement version';
        }
        if (Pca::unb64u(Js::opt($s, 'principal'), 32) === null) {
            return 'principal is not canonical base64url (32 bytes)';
        }
        $text = Js::opt($s, 'text');
        if (!is_string($text) || $text === '') {
            return 'text must be a non-empty string';
        }
        if (!self::isObj(Js::opt($s, 'slots'))) {
            return 'slots must be an object';
        }
        $sources = Js::opt($s, 'sources');
        if (!is_array($sources) || !array_is_list($sources)) {
            return 'sources must be an array';
        }
        foreach ($sources as $i => $src) {
            $kind = Js::opt($src, 'kind');
            if (!self::isObj($src) || !is_string($kind) || !in_array($kind, self::SOURCE_KINDS, true)) {
                return "sources[$i] has an unknown kind";
            }
            if ($src->has('uri') && !is_string($src->get('uri'))) {
                return "sources[$i].uri must be a string";
            }
            if (Pca::unb64u($src->get('digest'), 32) === null) {
                return "sources[$i].digest is not canonical base64url (32 bytes)";
            }
        }
        $ca = Js::opt($s, 'created_at');
        if (!IntentWb::isSafeInt($ca) || Js::num($ca) < 0) {
            return 'created_at must be a non-negative safe integer (epoch ms)';
        }
        $nonce = Js::opt($s, 'nonce');
        if (!is_string($nonce) || $nonce === '') {
            return 'nonce must be a non-empty string';
        }
        return null;
    }

    private static function suiteFieldsError(Obj $a): ?string
    {
        $alg = $a->has('alg') ? $a->get('alg') : null;
        if ($a->has('alg') && (!is_string($alg) || !in_array($alg, Pca::REGISTERED_SUITES, true))) {
            return 'unknown signature suite';
        }
        if ((!$a->has('alg') || $alg === 'ed25519') && ($a->has('pq_pk') || $a->has('pq_sig'))) {
            return 'an ed25519 artifact must not carry pq_pk / pq_sig';
        }
        return null;
    }

    private static function message(Obj $body): string
    {
        return self::SIG_DOMAIN . Json::canonicalizeNative($body);
    }

    /** The body with the suite fields bound (a non-ed25519 suite signs `alg` and `pq_pk`; an absent pq_pk is null here and the reference throws). */
    private static function bound(Obj $body, Obj $s): Obj
    {
        $alg = $s->has('alg') ? $s->get('alg') : 'ed25519';
        if ($alg === 'ed25519') {
            return $body;
        }
        if (!$s->has('pq_pk')) {
            throw new \InvalidArgumentException('pq_pk is missing');
        }
        $o = new Obj();
        foreach ($body->keys() as $k) {
            $o->set($k, $body->get($k));
        }
        $o->set('alg', $alg);
        $o->set('pq_pk', $s->get('pq_pk'));
        return $o;
    }

    /**
     * Sign a statement as its principal (an Ed25519 32-byte seed); `principal` defaults to the key of the seed. `$suite` other than
     * Ed25519 is refused (the PQ suites are not signed natively).
     */
    public static function signIntent(mixed $s, string $principalSecret, mixed $suite = null): Obj
    {
        $alg = Js::opt($suite, 'alg');
        if ($alg !== null && $alg !== 'ed25519') {
            throw new \InvalidArgumentException('signIntentStatement: only Ed25519 signing is supported natively');
        }
        $kp = sodium_crypto_sign_seed_keypair($principalSecret);
        $principal = Pca::b64u(sodium_crypto_sign_publickey($kp));
        if (Js::has($s, 'principal') && Js::opt($s, 'principal') !== $principal) {
            throw new \InvalidArgumentException('signIntentStatement: principal key mismatch');
        }
        $in = self::statementBody($s);
        $in->set('principal', $principal);
        $body = self::statementBody($in);
        $bad = self::shapeError($body);
        if ($bad !== null) {
            throw new \InvalidArgumentException("signIntentStatement: $bad");
        }
        $out = self::statementBody($body);
        $out->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::message($body), sodium_crypto_sign_secretkey($kp))));
        return $out;
    }

    /**
     * Verify a signed statement (shape, signer, suite signature; a PQ key must be pinned via `pqPins`). Never throws.
     * @return array{ok:bool,reason?:string}
     */
    public static function verifyIntent(mixed $s, mixed $opts = null): array
    {
        try {
            $bad = self::shapeError($s);
            if ($bad !== null) {
                return ['ok' => false, 'reason' => $bad];
            }
            /** @var Obj $s */
            if (Js::has($opts, 'expectedSigner') && $s->get('principal') !== Js::opt($opts, 'expectedSigner')) {
                return ['ok' => false, 'reason' => 'principal mismatch'];
            }
            $se = self::suiteFieldsError($s);
            if ($se !== null) {
                return ['ok' => false, 'reason' => $se];
            }
            $principal = (string)$s->get('principal');
            $msg = self::message(self::bound(self::statementBody($s), $s));
            $pin = null;
            $pqPins = Js::opt($opts, 'pqPins');
            if ($pqPins instanceof Obj && $pqPins->has($principal)) {
                $p = $pqPins->get($principal);
                $pin = is_string($p) ? $p : "\0\0not-a-string";
            }
            $ok = Pca::verifyPinnedSuite($s->has('alg') ? $s->get('alg') : null, $principal, $s->has('pq_pk') ? $s->get('pq_pk') : null,
                $msg, $s->has('sig') ? $s->get('sig') : null, $s->has('pq_sig') ? $s->get('pq_sig') : null, $pin);
            return $ok === true ? ['ok' => true] : ['ok' => false, 'reason' => 'bad signature'];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'malformed intent statement: ' . $e->getMessage()];
        }
    }

    /** The goal string that binds a grant to an intent statement (and optionally an Intent Map). */
    public static function intentGoal(string $ref, ?string $mapDigest = null): string
    {
        return self::GOAL_PREFIX . $ref . ($mapDigest !== null && $mapDigest !== '' ? ':' . $mapDigest : '');
    }

    /** @return array{intentRef:string,mapDigest?:string}|null null when the string is not an intent goal */
    public static function parseIntentGoal(mixed $goal): ?array
    {
        if (!is_string($goal) || !str_starts_with($goal, self::GOAL_PREFIX)) {
            return null;
        }
        $parts = explode(':', substr($goal, strlen(self::GOAL_PREFIX)));
        if ($parts[0] === '' || count($parts) > 2) {
            return null;
        }
        return isset($parts[1]) && $parts[1] !== '' ? ['intentRef' => $parts[0], 'mapDigest' => $parts[1]] : ['intentRef' => $parts[0]];
    }
}
