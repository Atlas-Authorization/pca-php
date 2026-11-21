<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Jose.php';
require_once __DIR__ . '/Js.php';

/** A misconfiguration or malformed input to the signals layer; `errorCode` names the check (misconfigured, bad_snapshot, unmapped_subject). */
final class SignalsError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * Subscriber-side revocation state. Both maps keep the `event_timestamp` of the revoking event; revocation is MONOTONE (a key,
 * once present, is never removed). Entries are stored as 'k'.key => [key, timestamp], so a numeric-looking id stays a string.
 */
final class SignalsRevocationState
{
    /** @var array<string,array{0:string,1:mixed}> grant_ref => event_timestamp */
    public array $revokedGrants = [];
    /** @var array<string,array{0:string,1:mixed}> agent id => event_timestamp of the kill-switch */
    public array $killedAgents = [];
    /** @var ?array<string,array{0:string,1:mixed}> intent revocation id => event_timestamp (created on first use) */
    public ?array $revokedIntentIds = null;
}

/**
 * A durable `jti` replay store for received SETs. addIfAbsent(string $jti, $expiresAtSec, $nowSec): bool MUST be atomic (of N
 * concurrent calls with the same jti exactly one returns true); an entry may be dropped once nowSec >= expiresAtSec. A store is
 * any object with that method (back it with a shared store when more than one process receives SETs).
 */
final class InMemorySetReplayStore
{
    /** @var array<string,float> */
    private array $seen = [];

    public function __construct(private readonly int $max)
    {
    }

    public function addIfAbsent(string $jti, mixed $expiresAtSec, mixed $nowSec): bool
    {
        $k = 'k' . $jti;
        $held = $this->seen[$k] ?? null;
        $now = (float) Js::num($nowSec);
        if (!is_finite($now) || !is_finite((float) Js::num($expiresAtSec))) {
            return false; // a non-finite clock or expiry admits nothing
        }
        if ($held !== null && !($now >= $held)) {
            return false;
        }
        if ($held === null && count($this->seen) >= $this->max) {
            foreach ($this->seen as $key => $exp) {
                if ($now >= $exp) {
                    unset($this->seen[$key]);
                }
            }
            if (count($this->seen) >= $this->max) {
                throw new \RuntimeException('replay store is full');
            }
        }
        $this->seen[$k] = (float) Js::num($expiresAtSec);
        return true;
    }
}

/**
 * Shared Signals Framework / CAEP for PCA: Security Event Tokens (RFC 8417) signed EdDSA, the subscriber-side revocation state
 * the resource server consults next to the PCActn check, a fail-closed SET receiver (size cap, canonical spelling, signature,
 * typ, iss / aud, iat window, atomic jti replay guard), CAEP / RISC revocation events, snapshot / restore, and hooks for
 * authorize(). The SSF stream bookkeeping is {@see SsfStream}, the stream management API {@see SsfManage}.
 *
 * Values are the parsed-JSON model (Obj, list arrays, string, Num / int / float, bool, null); options are an Obj or an assoc
 * array with the reference's camelCase names. Function-valued options are Closures.
 */
final class Signals
{
    public const SET_TYP = 'secevent+jwt';
    public const SET_ALG = 'EdDSA';
    public const SET_INMEMORY_MAX_ENTRIES = 100000;
    public const EVENT_TYPES = [
        'sessionRevoked' => 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
        'credentialChange' => 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
        'grantRevoked' => 'https://atlasauth.net/caep/grant-revoked',
        'killSwitch' => 'https://atlasauth.net/caep/kill-switch',
        'intentRevoked' => 'https://atlasauth.net/caep/intent-revoked',
        'verification' => 'https://schemas.openid.net/secevent/ssf/event-type/verification',
        'riskLevelChange' => 'https://schemas.openid.net/secevent/caep/event-type/risk-level-change',
        'assuranceLevelChange' => 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
    ];
    public const RISC_EVENT_TYPES = [
        'sessionsRevoked' => 'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked',
        'accountDisabled' => 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
        'accountPurged' => 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
        'credentialCompromise' => 'https://schemas.openid.net/secevent/risc/event-type/credential-compromise',
    ];

    // ---- JS-semantics helpers ---------------------------------------------------------------------

    /** `o.k`: a TypeError for null (a missing object), null for a missing member or a primitive. */
    public static function prop(mixed $o, string $k): mixed
    {
        if ($o === null) {
            throw new \TypeError("Cannot read properties of null (reading '$k')");
        }
        return Js::opt($o, $k);
    }

    /** `o?.k` */
    public static function optProp(mixed $o, string $k): mixed
    {
        return $o === null ? null : Js::opt($o, $k);
    }

    /** Object.entries(x) as [key, value] pairs; null throws, a primitive has none. @return list<array{0:string,1:mixed}> */
    public static function entries(mixed $x): array
    {
        if ($x === null) {
            throw new \TypeError('Cannot convert undefined or null to object');
        }
        $out = [];
        if ($x instanceof Obj) {
            foreach (Js::ownKeys($x->keys()) as $k) {
                $out[] = [$k, $x->get($k)];
            }
        } elseif (is_array($x) && array_is_list($x)) {
            foreach ($x as $i => $v) {
                $out[] = [(string) $i, $v];
            }
        } elseif (is_array($x)) {
            foreach ($x as $k => $v) {
                $out[] = [(string) $k, $v];
            }
        } elseif (is_string($x) && $x !== '') {
            foreach (str_split($x) as $i => $c) {
                $out[] = [(string) $i, $c];
            }
        }
        return $out;
    }

    private static function nonEmpty(mixed $x): bool
    {
        return is_string($x) && $x !== '';
    }

    /** A JSON number that is a plain number (not a bool). */
    private static function isNumber(mixed $x): bool
    {
        return Js::isNum($x);
    }

    private static function ts(mixed $ev): mixed
    {
        $t = self::prop($ev, 'event_timestamp');
        return self::isNumber($t) ? $t : 0;
    }

    /** Keep the maximum timestamp per key (a stale event never regresses it). @param array<string,array{0:string,1:mixed}> $m */
    private static function recordMax(array &$m, string $key, mixed $ts): void
    {
        $k = 'k' . $key;
        if (!isset($m[$k]) || (float) Js::num($ts) > (float) Js::num($m[$k][1])) {
            $m[$k] = [$key, $ts];
        }
    }

    // ---- SET build / verify ------------------------------------------------------------------------

    private static function uuid4(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        $h = bin2hex($b);
        return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20);
    }

    /**
     * Build a signed Security Event Token (RFC 8417): typ secevent+jwt, iss, iat (now), a random jti, aud, the `events` map (an
     * Obj with at least one event) and, when `$subject` is given, `sub` plus a structured opaque `sub_id`. `$key` is an Ed25519
     * private JWK, a 32-byte seed or a 64-byte libsodium secret key.
     */
    public static function buildSET(mixed $events, mixed $issuer, mixed $audience, mixed $key, mixed $subject = null): string
    {
        if (!($events instanceof Obj) || $events->keys() === []) {
            throw new \InvalidArgumentException('buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)');
        }
        $payload = new Obj();
        $payload->set('events', $events);
        if ($subject !== null) {
            $payload->set('sub_id', Obj::of(['format' => 'opaque', 'id' => $subject]));
        }
        if ($issuer !== null) {
            $payload->set('iss', $issuer);
        }
        $payload->set('iat', time());
        $payload->set('jti', self::uuid4());
        if ($audience !== null) {
            $payload->set('aud', $audience);
        }
        if ($subject !== null) {
            $payload->set('sub', $subject);
        }
        return Jose::signJwt($payload, Obj::of(['alg' => self::SET_ALG, 'typ' => self::SET_TYP]), $key);
    }

    private static function parseEvents(mixed $raw): Obj
    {
        if (!($raw instanceof Obj)) {
            throw new \InvalidArgumentException('SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)');
        }
        if ($raw->keys() === []) {
            throw new \InvalidArgumentException('SET invalid: `events` claim is empty (RFC 8417 §2.2)');
        }
        foreach (Js::ownKeys($raw->keys()) as $k) {
            if (!($raw->get($k) instanceof Obj)) {
                throw new \InvalidArgumentException("SET invalid: event payload for `$k` is not a JSON object (RFC 8417 §2.2)");
            }
        }
        return $raw;
    }

    /**
     * Verify a SET's EdDSA signature and standard claims, then parse it: {events, iss, jti, sub?, payload}. `$verifyKey` is a
     * public JWK or a 32-byte Ed25519 key. Options: issuer, audience, clockTolerance, currentDate (epoch ms), typ, requireTyp
     * (false skips the typ check). Throws on an invalid signature, wrong key, failed claim check or a malformed / empty `events`.
     *
     * @return array{events:Obj,iss:string,jti:string,sub?:string,payload:Obj}
     */
    public static function verifySET(mixed $set, mixed $verifyKey, mixed $opts = new Obj()): array
    {
        Jose::assertCanonicalCompactJws($set);
        if ($opts === null) {
            throw new \TypeError("Cannot read properties of null (reading 'issuer')");
        }
        $o = ['algorithms' => [self::SET_ALG]];
        foreach (['issuer', 'audience', 'clockTolerance'] as $k) {
            if (Js::opt($opts, $k) !== null) {
                $o[$k] = Js::opt($opts, $k);
            }
        }
        if (Js::opt($opts, 'currentDate') !== null) {
            $o['nowMs'] = Js::opt($opts, 'currentDate');
        }
        if (Js::opt($opts, 'requireTyp') !== false) {
            $o['typ'] = Js::opt($opts, 'typ') ?? self::SET_TYP;
        }
        [$payload] = Jose::jwtVerify($set, $verifyKey, $o);
        if (!is_string($payload->get('iss'))) {
            throw new \InvalidArgumentException('SET invalid: missing or non-string `iss`');
        }
        if (!is_string($payload->get('jti'))) {
            throw new \InvalidArgumentException('SET invalid: missing or non-string `jti` (RFC 8417 §2.2 requires it)');
        }
        $events = self::parseEvents($payload->get('events'));
        $out = ['events' => $events, 'iss' => $payload->get('iss'), 'jti' => $payload->get('jti')];
        if (is_string($payload->get('sub'))) {
            $out['sub'] = $payload->get('sub');
        }
        $out['payload'] = $payload;
        return $out;
    }

    // ---- revocation state ----------------------------------------------------------------------------

    public static function createRevocationState(): SignalsRevocationState
    {
        return new SignalsRevocationState();
    }

    /**
     * Fold one verified SET into the state: a `grant-revoked` adds its grant_ref; a `kill-switch` revokes every grant of its agent
     * (and any explicit grant_ref); `intent-revoked` records its namespaced ids. Each key keeps the MAX event_timestamp, so a stale
     * event never regresses the state and nothing is ever un-revoked. Returns the same (mutated) state.
     */
    public static function applySET(mixed $state, mixed $parsed): SignalsRevocationState
    {
        if (!($state instanceof SignalsRevocationState)) {
            throw new \TypeError('applySET: state must come from createRevocationState()');
        }
        foreach (self::entries(self::prop($parsed, 'events')) as [$type, $ev]) {
            $ts = self::ts($ev);
            if ($type === self::EVENT_TYPES['grantRevoked']) {
                $ref = self::prop($ev, 'grant_ref');
                if (self::nonEmpty($ref)) {
                    self::recordMax($state->revokedGrants, $ref, $ts);
                }
            } elseif ($type === self::EVENT_TYPES['killSwitch']) {
                $agent = self::prop($ev, 'agent');
                $ref = self::prop($ev, 'grant_ref');
                if (self::nonEmpty($agent)) {
                    self::recordMax($state->killedAgents, $agent, $ts);
                }
                if (self::nonEmpty($ref)) {
                    self::recordMax($state->revokedGrants, $ref, $ts);
                }
            } elseif ($type === self::EVENT_TYPES['intentRevoked']) {
                $ids = self::prop($ev, 'ids');
                if (is_array($ids) && array_is_list($ids)) {
                    foreach ($ids as $id) {
                        if (is_string($id) && str_starts_with($id, 'pca-intent:')) {
                            $state->revokedIntentIds ??= [];
                            self::recordMax($state->revokedIntentIds, $id, $ts);
                        }
                    }
                }
            }
        }
        return $state;
    }

    /** Has a pushed `intent-revoked` event named this intent revocation id? (Best effort; the epoch pull bound decides.) */
    public static function isIntentRevoked(SignalsRevocationState $state, string $id): bool
    {
        return isset($state->revokedIntentIds['k' . $id]);
    }

    /** Is this grant revoked: revoked directly, or (when `$agent` is given) its agent killed. Run next to the PCActn check. */
    public static function isRevoked(SignalsRevocationState $state, mixed $grantRef, mixed $agent = null): bool
    {
        if (is_string($grantRef) && isset($state->revokedGrants['k' . $grantRef])) {
            return true;
        }
        return is_string($agent) && isset($state->killedAgents['k' . $agent]);
    }

    private static function setTimestamp(mixed $p): float
    {
        $min = INF;
        foreach (self::entries(self::prop($p, 'events')) as [, $ev]) {
            $t = self::prop($ev, 'event_timestamp');
            if (self::isNumber($t) && (float) Js::num($t) < $min) {
                $min = (float) Js::num($t);
            }
        }
        return is_finite($min) ? $min : 0.0;
    }

    /**
     * Fold a list of verified SETs into one state in `event_timestamp` order (stable), so the delivery order of a push stream
     * cannot matter. Returns the supplied state or a fresh one.
     */
    public static function streamProcessor(mixed $parsedSets, ?SignalsRevocationState $state = null): SignalsRevocationState
    {
        if (!is_array($parsedSets) || !array_is_list($parsedSets)) {
            throw new \TypeError('parsedSets is not iterable');
        }
        $state ??= new SignalsRevocationState();
        // a one-element sort never calls the comparator, so a hostile lone set is applied (and fails) without being ranked first
        $keyed = array_map(static fn($p) => [count($parsedSets) > 1 ? self::setTimestamp($p) : 0.0, $p], $parsedSets);
        usort($keyed, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
        foreach ($keyed as [, $p]) {
            self::applySET($state, $p);
        }
        return $state;
    }

    // ---- replay store, receiver --------------------------------------------------------------------------

    /** A single-process store bounded to `maxEntries` live entries: when full a new jti THROWS (the receiver then refuses) instead of evicting a live one. */
    public static function createInMemorySetReplayStore(mixed $opts = new Obj()): InMemorySetReplayStore
    {
        $mx = self::prop($opts, 'maxEntries') ?? self::SET_INMEMORY_MAX_ENTRIES;
        $f = is_bool($mx) ? null : Js::num($mx);
        if ($f === null || !is_finite($f) || floor($f) !== $f || $f < 1) {
            throw new SignalsError('misconfigured', 'maxEntries must be a positive integer');
        }
        return new InMemorySetReplayStore($f >= 9.0e18 ? PHP_INT_MAX : (int)$f); // a float at or past 2^63 does not cast to an int
    }

    /**
     * Conformance suite for a replay store: the failed checks (empty = conformant). `$make` returns a FRESH, empty store each call.
     *
     * @return list<string>
     */
    public static function runSetReplayStoreConformance(callable $make): array
    {
        $failures = [];
        $check = static function (bool $ok, string $name) use (&$failures): void {
            if (!$ok) {
                $failures[] = $name;
            }
        };
        $s = $make();
        $check($s->addIfAbsent('a', 200, 100) === true, 'first sight of a jti returns true');
        $check($s->addIfAbsent('a', 200, 101) === false, 'second sight of the same jti returns false');
        $check($s->addIfAbsent('b', 200, 101) === true, 'a different jti is independent');
        $check($s->addIfAbsent('a', 200, 199) === false, 'still seen one second before expiry');
        $t = $make();
        $t->addIfAbsent('c', 200, 100);
        $check($t->addIfAbsent('c', 400, 200) === true, 'an expired entry may be added again (nowSec >= expiresAtSec)');
        $u = $make();
        $wins = 0;
        for ($i = 0; $i < 16; $i++) {
            if ($u->addIfAbsent('race', 200, 100)) {
                $wins++;
            }
        }
        $check($wins === 1, "16 concurrent adds of one jti: exactly one wins (got $wins)");
        return $failures;
    }

    /** @return array{ok:false,code:string,reason:string} */
    private static function fails(string $code, string $reason): array
    {
        return ['ok' => false, 'code' => $code, 'reason' => $reason];
    }

    /**
     * The recommended receive path: size cap, canonical spelling, EdDSA signature, `typ`, required iss and aud, `iat` freshness
     * window, atomic `jti` replay guard, then fold into `state`. The jti is recorded only after every other check passed (a
     * forged token cannot burn a real SET's id) and every error is a refusal VALUE, including a replay store that throws (the
     * SET is then NOT applied). Options: issuer, audience, replayStore, state, maxAgeSec (all required), clockSkewSec (60), nowSec,
     * maxBytes (16384), standardRevocations (see {@see planStandardRevocations}).
     *
     * @return array{ok:true,parsed:array}|array{ok:false,code:string,reason:string}
     */
    public static function receiveSET(mixed $set, mixed $verifyKey, mixed $opts): array
    {
        $store = Js::opt($opts, 'replayStore');
        $maxAge = Js::opt($opts, 'maxAgeSec');
        if (!Js::truthy($opts) || Js::opt($opts, 'issuer') === null || Js::opt($opts, 'audience') === null || !is_object($store)
            || !method_exists($store, 'addIfAbsent') || !Js::truthy(Js::opt($opts, 'state'))
            || !self::isNumber($maxAge) || !is_finite((float) Js::num($maxAge)) || (float) Js::num($maxAge) <= 0) {
            return self::fails('misconfigured', 'issuer, audience, replayStore, state and a positive maxAgeSec are all required');
        }
        $mb = Js::opt($opts, 'maxBytes');
        $limit = $mb === null ? 16384.0 : (Js::num($mb) ?? NAN);
        if (!is_string($set) || (float) Js::len($set) > $limit) {
            return self::fails('oversize', 'SET is not a string or exceeds maxBytes');
        }
        try {
            Jose::assertCanonicalCompactJws($set);
        } catch (\Throwable $e) {
            return self::fails('malformed', $e->getMessage());
        }
        $nowRaw = Js::opt($opts, 'nowSec');
        $now = $nowRaw === null ? (float) time() : (float) (Js::num($nowRaw) ?? NAN);
        try {
            $parsed = self::verifySET($set, $verifyKey, Obj::of([
                'issuer' => Js::opt($opts, 'issuer'), 'audience' => Js::opt($opts, 'audience'), 'currentDate' => $now * 1000,
            ]));
        } catch (\Throwable $e) {
            return self::fails('verify_failed', $e->getMessage());
        }
        $iat = $parsed['payload']->get('iat');
        if (!self::isNumber($iat) || !is_finite((float) Js::num($iat))) {
            return self::fails('iat_missing', 'SET has no numeric iat');
        }
        $iat = (float) Js::num($iat);
        $skewRaw = Js::opt($opts, 'clockSkewSec');
        $skew = $skewRaw === null ? 60.0 : (float) (Js::num($skewRaw) ?? NAN);
        $age = (float) Js::num($maxAge);
        if (!(is_finite($now) && is_finite($skew) && $iat <= $now + $skew)) {
            return self::fails('iat_future', 'SET iat is in the future');
        }
        if (!($now - $iat <= $age)) {
            return self::fails('iat_stale', 'SET is older than ' . Js::str($maxAge) . 's');
        }
        $plan = null;
        if (Js::opt($opts, 'standardRevocations') !== null) {
            try {
                $plan = self::planStandardRevocations($parsed, Js::opt($opts, 'standardRevocations'));
            } catch (\Throwable $e) {
                return self::fails('unmapped_subject', $e->getMessage());
            }
        }
        try {
            $fresh = $store->addIfAbsent($parsed['jti'], $iat + $age + $skew, $now);
        } catch (\Throwable $e) {
            return self::fails('replay_store_error', $e->getMessage());
        }
        if ($fresh !== true) {
            return self::fails('replay', "jti '{$parsed['jti']}' has already been received");
        }
        self::applySET(Js::opt($opts, 'state'), $parsed);
        if ($plan !== null) {
            self::applyStandardPlan(Js::opt($opts, 'state'), $plan);
        }
        return ['ok' => true, 'parsed' => $parsed];
    }

    // ---- standard (CAEP / RISC) revocation events ----------------------------------------------------------

    private static function defaultSubjectToAgent(mixed $subject): ?string
    {
        $id = Js::opt($subject, 'id');
        return Js::opt($subject, 'format') === 'opaque' && self::nonEmpty($id) ? $id : null;
    }

    private static function isRevokingStandardEvent(string $type, mixed $ev): bool
    {
        if ($type === self::EVENT_TYPES['sessionRevoked']) {
            return true;
        }
        if ($type === self::EVENT_TYPES['credentialChange']) {
            return self::prop($ev, 'change_type') !== 'create'; // an absent or unknown change type counts as a change (fail closed)
        }
        return in_array($type, array_values(self::RISC_EVENT_TYPES), true);
    }

    /**
     * Decide, without touching any state, which agents a verified SET's standard events revoke: CAEP `session-revoked`, CAEP
     * `credential-change` (every change_type except `create`; an absent or unknown one counts as a change) and the RISC types. The
     * subject is the event's own `subject`, else the SET-level `sub_id`. A revoking event with no subject, or one `subjectToAgent`
     * cannot map, is listed in `unmapped` (or throws unmapped_subject under `failOnUnmapped`). Options: subjectToAgent (Closure
     * over the subject, default an opaque subject's id), failOnUnmapped.
     *
     * @return array{agents:list<array{0:string,1:mixed}>,unmapped:list<string>}
     */
    public static function planStandardRevocations(mixed $parsed, mixed $opts = null): array
    {
        $toAgent = Js::opt($opts, 'subjectToAgent') ?? self::defaultSubjectToAgent(...);
        $plan = ['agents' => [], 'unmapped' => []];
        $subId = self::prop(self::prop($parsed, 'payload'), 'sub_id');
        $setSubject = Js::isObj($subId) ? $subId : null;
        foreach (self::entries(self::prop($parsed, 'events')) as [$type, $ev]) {
            if (!self::isRevokingStandardEvent($type, $ev)) {
                continue;
            }
            $evSubject = self::prop($ev, 'subject');
            $own = Js::isObj($evSubject) ? $evSubject : $setSubject;
            $agent = null;
            if ($own !== null && is_string(Js::opt($own, 'format'))) {
                try {
                    $agent = $toAgent($own);
                } catch (\Throwable) {
                    $agent = null; // a mapper that throws names no agent
                }
            }
            if (!self::nonEmpty($agent)) {
                if (Js::opt($opts, 'failOnUnmapped') === true) {
                    throw new SignalsError('unmapped_subject', "event '$type' names no mappable agent");
                }
                $plan['unmapped'][] = $type;
                continue;
            }
            $plan['agents'][] = [$agent, self::ts($ev)];
        }
        return $plan;
    }

    private static function applyStandardPlan(mixed $state, array $plan): void
    {
        if (!($state instanceof SignalsRevocationState)) {
            throw new \TypeError('state must come from createRevocationState()');
        }
        foreach ($plan['agents'] as [$agent, $ts]) {
            self::recordMax($state->killedAgents, $agent, $ts);
        }
    }

    /** {@see planStandardRevocations} then apply: monotone, max-timestamp. Returns the plan that was applied. */
    public static function applyStandardRevocations(mixed $state, mixed $parsed, mixed $opts = null): array
    {
        self::assertState($state);
        $plan = self::planStandardRevocations($parsed, $opts);
        self::applyStandardPlan($state, $plan);
        return $plan;
    }

    private static function assertState(mixed $state): void
    {
        if (!($state instanceof SignalsRevocationState)) {
            throw new SignalsError('misconfigured', 'state must come from createRevocationState()');
        }
    }

    // ---- adapters for authorize() ---------------------------------------------------------------------------

    private static function leafHolderAgent(mixed $ctx): mixed
    {
        $chain = self::prop(self::prop($ctx, 'pcactn'), 'cap_chain');
        if ($chain === null) {
            throw new \TypeError("Cannot read properties of undefined (reading 'length')");
        }
        $last = is_array($chain) && array_is_list($chain) && $chain !== [] ? $chain[count($chain) - 1] : null;
        return Js::isObj($last) ? Js::opt($last, 'holder') : null;
    }

    /** The reason a PCActn under `$grant` is revoked by `$state`, or null when it is not. Anything undecidable is a reason. */
    private static function revocationReason(SignalsRevocationState $state, mixed $pcactn, mixed $grant, callable $agentOf): ?string
    {
        try {
            $ref = self::prop($pcactn, 'grant_ref');
            if (!self::nonEmpty($ref)) {
                return 'grant_ref is missing';
            }
            if (isset($state->revokedGrants['k' . $ref])) {
                return 'grant revoked by signal';
            }
            $gid = self::optProp($grant, 'id');
            if (is_string($gid) && isset($state->revokedGrants['k' . $gid])) {
                return 'grant revoked by signal';
            }
            $agent = $agentOf(['pcactn' => $pcactn, 'grant' => $grant]);
            if (!self::nonEmpty($agent)) {
                return 'agent could not be determined';
            }
            return isset($state->killedAgents['k' . $agent]) ? 'agent killed by signal' : null;
        } catch (\Throwable) {
            return 'revocation check error (fail closed)';
        }
    }

    /**
     * A hook for authorize() / the verifier's `hooks.revocation`: reads `$state` LIVE on every call and always reports `enforced`;
     * a revoked grant, a revoked or undeterminable agent, or any error denies. Options: agentOf (Closure over ['pcactn', 'grant'],
     * default the leaf holder key of the capability chain). The hook takes ['pcactn' => ..., 'grant' => ...].
     */
    public static function createRevocationHook(mixed $state, mixed $opts = null): \Closure
    {
        self::assertState($state);
        $agentOf = Js::opt($opts, 'agentOf') ?? self::leafHolderAgent(...);
        return static function (mixed $ctx) use ($state, $agentOf): array {
            $reason = self::revocationReason($state, self::prop($ctx, 'pcactn'), self::prop($ctx, 'grant'), $agentOf);
            return $reason === null ? ['enforced' => true, 'ok' => true] : ['enforced' => true, 'ok' => false, 'reason' => $reason];
        };
    }

    /** The same decision as `isRevoked(grant, pcactn)` for authorizeExecution: true when revoked or undeterminable (fail closed). */
    public static function createIsRevoked(mixed $state, mixed $opts = null): \Closure
    {
        self::assertState($state);
        $agentOf = Js::opt($opts, 'agentOf') ?? self::leafHolderAgent(...);
        return static fn(mixed $grant, mixed $pcactn): bool => self::revocationReason($state, $pcactn, $grant, $agentOf) !== null;
    }

    // ---- snapshot / restore ---------------------------------------------------------------------------------------

    /**
     * A serialisable copy of the state: {v: 1, grants, agents, intents} of [key, timestamp] pairs. Persist it after every accepted
     * SET: an empty state after a restart revokes nothing.
     */
    public static function snapshotRevocationState(mixed $state): array
    {
        self::assertState($state);
        $pairs = static fn(?array $m): array => array_values($m ?? []);
        return ['v' => 1, 'grants' => $pairs($state->revokedGrants), 'agents' => $pairs($state->killedAgents), 'intents' => $pairs($state->revokedIntentIds)];
    }

    /** @return list<array{0:string,1:mixed}> */
    private static function pairs(mixed $v, string $what): array
    {
        if (!is_array($v) || !array_is_list($v)) {
            throw new SignalsError('bad_snapshot', "$what is not an array");
        }
        $out = [];
        foreach ($v as $p) {
            if (!is_array($p) || !array_is_list($p) || count($p) !== 2 || !self::nonEmpty($p[0]) || !self::isNumber($p[1]) || !is_finite((float) Js::num($p[1]))) {
                throw new SignalsError('bad_snapshot', "$what holds an entry that is not [string, number]");
            }
            $out[] = [$p[0], $p[1]];
        }
        return $out;
    }

    /**
     * Merge a snapshot into `$into` (a fresh state when omitted). Strict: any shape error throws `bad_snapshot` and `$into` is
     * not touched. Merging is monotone (max timestamp), so restoring never un-revokes anything already in `$into`.
     */
    public static function restoreRevocationState(mixed $snapshot, mixed $into = null): SignalsRevocationState
    {
        if (func_num_args() < 2) {
            $into = new SignalsRevocationState();
        }
        self::assertState($into);
        if (!Js::isObj($snapshot) || is_bool(Js::opt($snapshot, 'v')) || Js::num(Js::opt($snapshot, 'v')) !== 1.0) {
            throw new SignalsError('bad_snapshot', 'snapshot is not a version 1 object');
        }
        $keys = $snapshot instanceof Obj ? $snapshot->keys() : array_map('strval', array_keys($snapshot));
        foreach (Js::ownKeys($keys) as $k) {
            if (!in_array($k, ['v', 'grants', 'agents', 'intents'], true)) {
                throw new SignalsError('bad_snapshot', "snapshot has unknown member '$k'");
            }
        }
        $grants = self::pairs(Js::opt($snapshot, 'grants'), 'grants');
        $agents = self::pairs(Js::opt($snapshot, 'agents'), 'agents');
        $intents = self::pairs(Js::opt($snapshot, 'intents'), 'intents');
        foreach ($grants as [$k, $t]) {
            self::recordMax($into->revokedGrants, $k, $t);
        }
        foreach ($agents as [$k, $t]) {
            self::recordMax($into->killedAgents, $k, $t);
        }
        foreach ($intents as [$k, $t]) {
            $into->revokedIntentIds ??= [];
            self::recordMax($into->revokedIntentIds, $k, $t);
        }
        return $into;
    }

    // ---- CAEP builders -----------------------------------------------------------------------------------------------

    /** Emit CAEP `risk-level-change` (from the behavioural immune system). Args: issuer, audience, key, event. */
    public static function riskLevelChangeSET(mixed $a): string
    {
        return self::buildSET(Obj::of([self::EVENT_TYPES['riskLevelChange'] => Js::opt($a, 'event')]), Js::opt($a, 'issuer'), Js::opt($a, 'audience'), Js::opt($a, 'key'));
    }

    /**
     * Emit CAEP `assurance-level-change` (from a discharge change). `change_direction` is derived when both levels are in `order`.
     * Args: issuer, audience, key, event, order?.
     */
    public static function assuranceLevelChangeSET(mixed $a): string
    {
        $src = Js::opt($a, 'event');
        $e = new Obj();
        if ($src instanceof Obj) {
            foreach ($src->keys() as $k) {
                $e->set($k, $src->get($k));
            }
        }
        $order = Js::opt($a, 'order');
        if ($e->has('previous_level') && !$e->has('change_direction') && Js::truthy($order)) {
            if (!is_array($order) || !array_is_list($order)) {
                throw new \TypeError('order must be a list');
            }
            $i = array_search($e->get('previous_level'), $order, true);
            $j = array_search($e->get('current_level'), $order, true);
            if ($i !== false && $j !== false && $i !== $j) {
                $e->set('change_direction', $j > $i ? 'increase' : 'decrease');
            }
        }
        return self::buildSET(Obj::of([self::EVENT_TYPES['assuranceLevelChange'] => $e]), Js::opt($a, 'issuer'), Js::opt($a, 'audience'), Js::opt($a, 'key'));
    }
}
