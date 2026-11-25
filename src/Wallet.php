<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/SignersMore.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * Sliding-window question counter shared across sessions (the per-hour cap is an accumulator, so an agent cannot split around it by
 * opening sessions). Keeps only timestamps inside the window.
 */
final class SlidingWindowCounter
{
    private float $windowMs;
    /** @var list<float> */
    private array $times = [];

    public function __construct(mixed $windowMs = 3600000)
    {
        $f = Js::num($windowMs);
        if ($f === null || !is_finite($f) || $f != floor($f) || !($f > 0)) {
            throw new \InvalidArgumentException('SlidingWindowCounter: windowMs must be a positive integer');
        }
        $this->windowMs = $f;
    }

    private static function n(mixed $v): float
    {
        $f = Js::num($v);
        if ($f === null) {
            throw new \TypeError('SlidingWindowCounter: a number is required');
        }
        return $f;
    }

    private function prune(float $now): void
    {
        if (!is_finite($now)) {
            return; // an infinite clock must never forget a recorded event
        }
        while ($this->times && $this->times[0] <= $now - $this->windowMs) {
            array_shift($this->times);
        }
    }

    public function count(mixed $now): int
    {
        $this->prune(self::n($now));
        return count($this->times);
    }

    /** Record one event at `$now` if the count is below `$cap`; false (and nothing recorded) otherwise. */
    public function tryAdd(mixed $now, mixed $cap): bool
    {
        $now = self::n($now);
        if (!is_finite($now)) {
            return false;
        }
        $this->prune($now);
        if (!(count($this->times) < self::n($cap))) {
            return false;
        }
        if ($this->times && !($now >= $this->times[count($this->times) - 1])) {
            throw new \InvalidArgumentException('SlidingWindowCounter: time went backwards');
        }
        $this->times[] = $now;
        return true;
    }
}

/**
 * The wallet side of the PCA Intent Layer v2: the principal-signed answer (wire), friction tiers scaled by harm, cell coordinates over
 * the wallet's own outcome space, the statistics behind the noise estimates, attention canaries and the approval-fatigue model (the
 * reference's pca-wallet). The trusted card and clarification planning live in {@see WalletCard}, risk-priced escalation in
 * {@see WalletPricing}. Values are the parsed-JSON model; where the reference takes a callback or a Set, this port takes a Closure or
 * an array. A reference refusal that is a thrown Error is a thrown exception here. Floats follow the reference operation by operation.
 */
final class Wallet
{
    public const INTENT_ANSWER_SIG_DOMAIN = "atlas-pca/intent-obs/v2\0";
    public const INTENT_ANSWER_REF_DOMAIN = 'atlas-pca/intent-answer-ref/v1';
    public const INTENT_TYPED_DOMAIN = 'atlas-pca/intent-typed/v1';
    public const INTENT_DEVICE_CHALLENGE_DOMAIN = 'atlas-pca/intent-device/v1';
    public const INTENT_ACTION_DOMAIN = 'atlas-pca/intent-action/v1';
    public const MIN_HOLD_MS = 2000;
    public const FRICTION_ORDER = ['tap', 'hold', 'typed', 'device'];
    public const PROVENANCE_ORDER = ['trusted', 'first_party', 'tool', 'web', 'agent'];
    public const DEFAULT_FRICTION_THRESHOLDS = ['hTap' => 5, 'hDevice' => 100000];
    public const EMPTY_NOISE = ['falseYes' => 0, 'correctNo' => 0, 'falseNo' => 0, 'correctYes' => 0];
    public const NOISE_PRIOR = ['a' => 1, 'b' => 9];
    public const DEFAULT_FATIGUE = ['betaF' => 0.005, 'etaStop' => 0.15, 'deltaC' => 0.05, 'freezeOn' => 'mean', 'assumeNoiseFree' => false, 'delta' => 0.05];
    private const TAINTED = ['web', 'agent'];
    private const BELOW_HALF = 0.5 - 1e-9;
    private const MAX_SAFE = 9007199254740991;

    // ---- JavaScript value helpers -------------------------------------------------------------------------------------------

    /** `o[k]` of a dict; `Jsx::$U` (undefined) for an absent member or a non-dict. */
    public static function g(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->has($k) ? $o->get($k) : Jsx::$U;
        }
        if (is_array($o) && !array_is_list($o) && array_key_exists($k, $o)) {
            return $o[$k];
        }
        return Jsx::$U;
    }

    /** A required member (Python's KeyError): absent throws. */
    public static function req(mixed $o, string $k): mixed
    {
        $v = self::g($o, $k);
        if ($v instanceof Undef) {
            throw new \OutOfBoundsException("missing member $k");
        }
        return $v;
    }

    /** A required numeric member as a float (a non-number throws, as the comparison would in the reference). */
    public static function reqNum(mixed $o, string $k): float
    {
        $f = Js::num(self::req($o, $k));
        if ($f === null) {
            throw new \TypeError("member $k is not a number");
        }
        return $f;
    }

    public static function isDict(mixed $v): bool
    {
        return $v instanceof Obj || (is_array($v) && $v !== [] && !array_is_list($v));
    }

    /** @return list<string> the keys of a dict */
    public static function dictKeys(mixed $o): array
    {
        if ($o instanceof Obj) {
            return $o->keys();
        }
        return is_array($o) ? array_map('strval', array_keys($o)) : [];
    }

    /**
     * Object.entries of a JSON value (strings and arrays yield their indices; null and undefined throw).
     * @return list<array{0:string,1:mixed}>
     */
    public static function entries(mixed $v): array
    {
        $out = [];
        if ($v instanceof Obj) {
            foreach ($v->keys() as $k) {
                $out[] = [$k, $v->get($k)];
            }
        } elseif (is_array($v) && array_is_list($v)) {
            foreach ($v as $i => $x) {
                $out[] = [(string)$i, $x];
            }
        } elseif (is_array($v)) {
            foreach ($v as $k => $x) {
                $out[] = [(string)$k, $x];
            }
        } elseif (is_string($v)) {
            foreach (preg_split('//u', $v, -1, PREG_SPLIT_NO_EMPTY) ?: ($v === '' ? [] : str_split($v)) as $i => $c) {
                $out[] = [(string)$i, $c];
            }
        } elseif ($v === null || $v instanceof Undef) {
            throw new \TypeError('Cannot convert undefined or null to object');
        }
        return $out;
    }

    /** JSON.parse(JSON.stringify(v)): -0 becomes 0, an integral float an integer. */
    public static function jsPlain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::jsPlain($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::jsPlain(...), $v);
        }
        if (Js::isNum($v)) {
            $f = Js::num($v);
            if (is_finite($f) && $f == floor($f) && abs($f) <= self::MAX_SAFE) {
                return new Num((string)(int)$f); // JSON.parse(JSON.stringify(v)): -0 reads back as 0
            }
        }
        return $v;
    }

    private static function numEq(mixed $v, int $n): bool
    {
        return Js::isNum($v) && Js::num($v) === (float)$n;
    }

    private static function finiteNum(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f);
    }

    // ---- friction (wire, friction) ------------------------------------------------------------------------------------------

    public static function isFrictionTier(mixed $x): bool
    {
        return is_string($x) && in_array($x, self::FRICTION_ORDER, true);
    }

    public static function frictionRank(mixed $t): int
    {
        return is_string($t) && ($i = array_search($t, self::FRICTION_ORDER, true)) !== false ? $i : -1;
    }

    public static function maxFriction(mixed ...$ts): mixed
    {
        $best = 'tap';
        foreach ($ts as $t) {
            if (self::frictionRank($t) > self::frictionRank($best)) {
                $best = $t;
            }
        }
        return $best;
    }

    public static function satisfiesTier(mixed $given, mixed $required): bool
    {
        return self::frictionRank($given) >= self::frictionRank($required);
    }

    public static function isProvenanceLevel(mixed $x): bool
    {
        return is_string($x) && in_array($x, self::PROVENANCE_ORDER, true);
    }

    /** The least trusted level of a set; "agent" for an empty or unknown set (fail closed). */
    public static function worstProvenance(mixed $levels): string
    {
        if (is_string($levels)) { // a string iterates by character, none of which is a level
            return 'agent';
        }
        if (!is_array($levels) || !array_is_list($levels)) {
            throw new \TypeError('levels is not iterable');
        }
        $best = -1;
        foreach ($levels as $lv) {
            if (!self::isProvenanceLevel($lv)) {
                return 'agent';
            }
            $best = max($best, (int)array_search($lv, self::PROVENANCE_ORDER, true));
        }
        return $best < 0 ? 'agent' : self::PROVENANCE_ORDER[$best];
    }

    /**
     * The friction tier an expected-harm figure and its context require: ['tier' => ..., 'rules' => [...]].
     * `$th` = ['hTap' => ..., 'hDevice' => ...].
     * @return array{tier:string,rules:list<string>}
     */
    public static function frictionFor(mixed $inp, mixed $th = null): array
    {
        $th ??= self::DEFAULT_FRICTION_THRESHOLDS;
        $harm = Js::opt($inp, 'expectedHarm');
        $h = Js::num($harm);
        if ($h === null || !is_finite($h) || !($h >= 0)) {
            return ['tier' => 'device', 'rules' => ['harm-unknown']];
        }
        $rules = [];
        $tier = 'tap';
        $raise = static function (mixed $t, string $why) use (&$tier, &$rules): void {
            if (self::frictionRank($t) >= self::frictionRank($tier)) {
                $rules[] = $why;
            }
            $tier = self::maxFriction($tier, $t);
        };
        $rev = Js::opt($inp, 'reversibility');
        if ($rev === 'rate_limited') {
            $raise('hold', 'rate-limited');
        }
        if ($h >= self::reqNum($th, 'hTap')) {
            $raise('hold', 'harm>=h_tap');
        }
        if ($rev === 'irreversible') {
            $raise('typed', 'irreversible');
        }
        $prov = Js::opt($inp, 'provenance');
        $taintedCritical = false;
        if ($prov !== null) {
            if (is_array($prov) && array_is_list($prov)) {
                $items = $prov;
            } elseif ($prov instanceof Obj || is_string($prov)) {
                $items = $prov instanceof Obj ? $prov->keys() : (preg_split('//u', $prov, -1, PREG_SPLIT_NO_EMPTY) ?: str_split($prov));
            } else {
                throw new \TypeError('provenance is not iterable');
            }
            foreach ($items as $p) {
                if (!self::isDict($p)) {
                    throw new \TypeError('provenance entry is not an object');
                }
                if (Js::opt($p, 'sensitivity') === 'critical' && in_array(self::worstProvenance(Js::opt($p, 'levels')), self::TAINTED, true)) {
                    $taintedCritical = true;
                    break;
                }
            }
        }
        if ($taintedCritical) {
            $raise('typed', 'tainted-critical');
        }
        if (Jsx::truthy(Js::opt($inp, 'widensCriticalIdentity')) && $rev === 'irreversible') {
            $raise('device', 'critical-irreversible');
        }
        if ($h >= self::reqNum($th, 'hDevice')) {
            $raise('device', 'harm>=h_device');
        }
        if (Jsx::truthy(Js::opt($inp, 'singleSource'))) {
            $raise(self::FRICTION_ORDER[min(count(self::FRICTION_ORDER) - 1, self::frictionRank($tier) + 1)], 'single-source');
        }
        if (Js::has($inp, 'siteMin')) {
            $raise(Js::opt($inp, 'siteMin'), 'site-minimum');
        }
        return ['tier' => $tier, 'rules' => $rules];
    }

    // ---- helpers (wire) -----------------------------------------------------------------------------------------------------

    public static function isObj(mixed $v): bool
    {
        return self::isDict($v);
    }

    public static function isB64u32(mixed $v): bool
    {
        return Pca::unb64u($v, 32) !== null;
    }

    /** Cell coordinates as the core validates them (shared with `intent_required`). */
    public static function coordsError(mixed $c): ?string
    {
        return SignersMore::cellCoordsError($c);
    }

    /** The action digest of an attempted action (what `intent_required.action_digest` and a JIT consent bind to). */
    public static function pcaActionDigest(mixed $a): string
    {
        $params = self::g($a, 'params');
        $pd = Pca::paramsDigest($params instanceof Undef ? null : $params);
        $act = new Obj();
        foreach ([['verb', self::g($a, 'verb')], ['resource', self::g($a, 'resource')], ['params_digest', $pd], ['reversibility_class', self::g($a, 'reversibility_class')]] as [$k, $v]) {
            if ($v instanceof Undef) {
                throw new \TypeError('canonicalize: undefined');
            }
            $act->set($k, $v);
        }
        return Pca::hashCanonical(Obj::of(['d' => self::INTENT_ACTION_DOMAIN, 'action' => $act]));
    }

    /** The default projection of an attempted action onto Omega paths: the resource and every scalar param. */
    public static function actionValuesOf(mixed $a): Obj
    {
        $values = new Obj();
        $res = self::g($a, 'resource');
        if (!($res instanceof Undef)) {
            $values->set('action.resource', $res);
        }
        foreach (self::entries(self::g($a, 'params')) as [$k, $v]) {
            if (is_string($v) || (Js::isNum($v) && self::finiteNum($v))) {
                $values->set('action.params.' . $k, $v);
            }
        }
        $out = Obj::of(['values' => $values]);
        if (!(self::g($a, 'verb') instanceof Undef)) {
            $out->set('verb', self::g($a, 'verb'));
        }
        return $out;
    }

    // ---- the signed answer --------------------------------------------------------------------------------------------------

    private const ANS_KEYS = ['v', 'kind', 'map_digest', 'session', 'question_id', 'verb', 'cell', 'y', 'partial', 'source', 'observed_at', 'ux', 'signer', 'alg', 'sig'];
    private const UX_KEYS = ['tier', 'rendered_digest', 'typed_digest', 'hold_ms', 'webauthn', 'canary', 'action_digest', 'consent_for_action'];
    private const WA_KEYS = ['credential_id', 'authenticator_data', 'client_data_json', 'signature'];

    /** @param list<string> $allowed */
    private static function onlyKeys(mixed $o, array $allowed): ?string
    {
        foreach (self::dictKeys($o) as $k) {
            if (!in_array($k, $allowed, true)) {
                return "unknown member \"$k\"";
            }
        }
        return null;
    }

    private static function partialError(mixed $p): ?string
    {
        if (!self::isDict($p) || !is_string(Js::opt($p, 'path')) || Js::opt($p, 'path') === '') {
            return 'partial.path must be a non-empty string';
        }
        $keys = array_values(array_filter(self::dictKeys($p), static fn(string $k): bool => $k !== 'path'));
        if (count($keys) !== 1) {
            return 'partial must carry exactly one of upTo / from / except / notFor';
        }
        $k = $keys[0];
        $v = Js::opt($p, $k);
        if (($k === 'upTo' || $k === 'from') && !WalletOmega::isInt($v)) {
            return "partial.$k must be an integer";
        }
        if ($k === 'except' && !(is_array($v) && array_is_list($v) && count($v) > 0 && count(array_filter($v, static fn($x) => WalletOmega::isInt($x))) === count($v))) {
            return 'partial.except must be a non-empty integer array';
        }
        if ($k === 'notFor' && !(is_array($v) && array_is_list($v) && count($v) > 0 && count(array_filter($v, static fn($x) => is_string($x) && $x !== '')) === count($v))) {
            return 'partial.notFor must be a non-empty string array';
        }
        if (!in_array($k, ['upTo', 'from', 'except', 'notFor'], true)) {
            return "unknown partial member \"$k\"";
        }
        return null;
    }

    public static function answerShapeError(mixed $a): ?string
    {
        if (!self::isDict($a)) {
            return 'not an object';
        }
        $extra = self::onlyKeys($a, self::ANS_KEYS);
        if ($extra !== null) {
            return $extra;
        }
        if (!self::numEq(Js::opt($a, 'v'), 2) || Js::opt($a, 'kind') !== 'pca-intent-observation') {
            return 'not a pca-intent-observation v2';
        }
        foreach (['map_digest', 'session', 'signer'] as $k) {
            if (!self::isB64u32(Js::opt($a, $k))) {
                return "$k is not canonical base64url (32 bytes)";
            }
        }
        $qid = Js::opt($a, 'question_id');
        if (!is_string($qid) || preg_match('/\A[A-Za-z0-9_-]{1,64}\z/', $qid) !== 1) {
            return 'question_id must match [A-Za-z0-9_-]{1,64}';
        }
        if (!is_string(Js::opt($a, 'verb')) || Js::opt($a, 'verb') === '') {
            return 'verb must be a non-empty string';
        }
        $ce = self::coordsError(Js::opt($a, 'cell'));
        if ($ce !== null) {
            return 'cell: ' . $ce;
        }
        $y = Js::opt($a, 'y');
        if (!(self::numEq($y, 0) || self::numEq($y, 1))) {
            return 'y must be 0 or 1';
        }
        if (Js::has($a, 'partial')) {
            $pe = self::partialError(Js::opt($a, 'partial'));
            if ($pe !== null) {
                return $pe;
            }
            if (!self::numEq($y, 1)) {
                return 'a partial answer carries y = 1 (yes for the part)';
            }
        }
        if (!in_array(Js::opt($a, 'source'), ['elicitation', 'clarification'], true)) {
            return 'source must be elicitation or clarification';
        }
        $obs = Js::opt($a, 'observed_at');
        if (!WalletOmega::isInt($obs) || Js::num($obs) < 0) {
            return 'observed_at must be a non-negative safe integer';
        }
        if (Js::opt($a, 'alg') !== 'ed25519') {
            return 'alg must be ed25519';
        }
        $ux = Js::opt($a, 'ux');
        if (!self::isDict($ux)) {
            return 'ux must be an object';
        }
        $ue = self::onlyKeys($ux, self::UX_KEYS);
        if ($ue !== null) {
            return 'ux: ' . $ue;
        }
        if (!self::isFrictionTier(Js::opt($ux, 'tier'))) {
            return 'ux.tier is not a friction tier';
        }
        if (!self::isB64u32(Js::opt($ux, 'rendered_digest'))) {
            return 'ux.rendered_digest is not canonical base64url (32 bytes)';
        }
        if (!is_bool(Js::opt($ux, 'canary'))) {
            return 'ux.canary must be a boolean';
        }
        if (Js::has($ux, 'typed_digest') && !self::isB64u32(Js::opt($ux, 'typed_digest'))) {
            return 'ux.typed_digest is not canonical base64url (32 bytes)';
        }
        if (Js::has($ux, 'hold_ms') && !(WalletOmega::isInt(Js::opt($ux, 'hold_ms')) && Js::num(Js::opt($ux, 'hold_ms')) >= 0)) {
            return 'ux.hold_ms must be a non-negative integer';
        }
        if (Js::has($ux, 'action_digest') && !self::isB64u32(Js::opt($ux, 'action_digest'))) {
            return 'ux.action_digest is not canonical base64url (32 bytes)';
        }
        if (Js::has($ux, 'consent_for_action') && !is_bool(Js::opt($ux, 'consent_for_action'))) {
            return 'ux.consent_for_action must be a boolean';
        }
        if (Js::opt($ux, 'consent_for_action') === true && (!Js::has($ux, 'action_digest') || !self::numEq($y, 1) || Js::has($a, 'partial'))) {
            return 'consent_for_action needs action_digest and a plain yes';
        }
        if (Js::opt($ux, 'consent_for_action') === true && Js::opt($ux, 'canary') === true) {
            return 'a canary never consents to an action';
        }
        if (Js::has($ux, 'webauthn')) {
            $wa = Js::opt($ux, 'webauthn');
            if (!self::isDict($wa) || self::onlyKeys($wa, self::WA_KEYS) !== null) {
                return 'ux.webauthn is malformed';
            }
            foreach (self::WA_KEYS as $k) {
                if (!is_string(Js::opt($wa, $k))) {
                    return 'ux.webauthn is malformed';
                }
            }
        }
        if (self::numEq($y, 1) && !Js::opt($ux, 'canary')) {
            $tier = Js::opt($ux, 'tier');
            $hold = Js::opt($ux, 'hold_ms');
            if ($tier === 'hold' && !(WalletOmega::isInt($hold) && Js::num($hold) >= self::MIN_HOLD_MS)) {
                return 'hold tier needs hold_ms >= ' . self::MIN_HOLD_MS;
            }
            if ($tier === 'typed' && !Js::has($ux, 'typed_digest')) {
                return 'typed tier needs typed_digest';
            }
            if ($tier === 'device' && !Js::has($ux, 'webauthn')) {
                return 'device tier needs a WebAuthn assertion';
            }
        }
        return null;
    }

    private static function answerBody(mixed $a): Obj
    {
        $body = new Obj();
        foreach (['v', 'kind', 'map_digest', 'session', 'question_id', 'verb', 'cell', 'y', 'partial', 'source', 'observed_at', 'ux', 'signer', 'alg'] as $k) {
            if (Js::has($a, $k)) {
                $body->set($k, Js::opt($a, $k));
            }
        }
        /** @var Obj $plain */
        $plain = self::jsPlain($body);
        return $plain;
    }

    private static function domainMessage(string $domain, mixed $body): string
    {
        return $domain . Json::canonicalizeNative($body);
    }

    private static function secretKey(string $seed): string
    {
        return sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($seed));
    }

    /** Wallet side: sign the principal's answer with the principal key (Ed25519, domain-separated, over the canonical body). */
    public static function signIntentAnswer(mixed $a, string $principalSecret): Obj
    {
        $base = new Obj();
        foreach (self::dictKeys($a) as $k) {
            $base->set($k, Js::opt($a, $k));
        }
        $base->set('v', 2);
        $base->set('kind', 'pca-intent-observation');
        $base->set('signer', Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($principalSecret))));
        $base->set('alg', 'ed25519');
        $body = self::answerBody($base);
        $bad = self::answerShapeError($body);
        if ($bad !== null) {
            throw new \InvalidArgumentException('signIntentAnswer: ' . $bad);
        }
        $out = new Obj();
        foreach ($body->keys() as $k) {
            $out->set($k, $body->get($k));
        }
        $out->set('sig', Pca::b64u(sodium_crypto_sign_detached(self::domainMessage(self::INTENT_ANSWER_SIG_DOMAIN, $body), self::secretKey($principalSecret))));
        return $out;
    }

    /**
     * Verify a signed answer; `$principals` restricts the signer (the keys named in the session root). Never throws.
     * @return array{ok:bool,reason?:string}
     */
    public static function verifyIntentAnswer(mixed $a, mixed $principals = null): array
    {
        try {
            $bad = self::answerShapeError($a);
            if ($bad !== null) {
                return ['ok' => false, 'reason' => $bad];
            }
            if ($principals !== null) {
                $signer = Js::opt($a, 'signer');
                // a non-array (a string's includes() is a substring match, null, an object) restricts to nobody
                $in = is_array($principals) && array_is_list($principals) && in_array($signer, $principals, true);
                if (!$in) {
                    return ['ok' => false, 'reason' => 'signer is not a principal of the session'];
                }
            }
            $sig = Js::opt($a, 'sig');
            if (!is_string($sig)) {
                return ['ok' => false, 'reason' => 'bad signature'];
            }
            $pk = Pca::unb64u(Js::opt($a, 'signer'), 32);
            $sg = Pca::unb64u($sig, 64);
            if ($pk === null || $sg === null) {
                return ['ok' => false, 'reason' => 'bad signature'];
            }
            try {
                $ok = sodium_crypto_sign_verify_detached($sg, self::domainMessage(self::INTENT_ANSWER_SIG_DOMAIN, self::answerBody($a)), $pk);
            } catch (\SodiumException) {
                $ok = false;
            }
            return $ok ? ['ok' => true] : ['ok' => false, 'reason' => 'bad signature'];
        } catch (\Throwable $e) { // the reference turns every throw into a refusal
            return ['ok' => false, 'reason' => 'malformed answer'];
        }
    }

    /** Content address of a signed answer (evidence bundles and delta grants refer to it). */
    public static function answerRef(mixed $a): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::INTENT_ANSWER_REF_DOMAIN, 'a' => $a]));
    }

    public static function typedDigest(mixed $questionId, mixed $normalizedValue): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::INTENT_TYPED_DOMAIN, 'q' => $questionId, 'v' => $normalizedValue]));
    }

    /** The 32-byte WebAuthn challenge of a device-tier answer: binds the question, the card the human saw, y and the action. */
    public static function deviceChallenge(mixed $questionId, mixed $renderedDigest, mixed $y, mixed $actionDigest = null): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::INTENT_DEVICE_CHALLENGE_DOMAIN, 'q' => $questionId, 'r' => $renderedDigest, 'y' => $y, 'a' => $actionDigest]));
    }

    // ---- cell coordinates <-> the wallet's own Omega ------------------------------------------------------------------------

    public static function coordKeyOf(string $path): string
    {
        if (preg_match('/\Aenv\.acc\.([A-Za-z0-9_.-]+)\.post\z/', $path, $m) === 1) {
            return $m[1];
        }
        if (preg_match('/\Aenv\.mon\.([A-Za-z0-9_.-]+)\.state\z/', $path, $m) === 1) {
            return 'mon:' . $m[1];
        }
        if (preg_match('/\Aenv\.prov\.((?:[^\n\r\xE2]|\xE2(?!\x80[\xA8\xA9]))+)\z/', $path, $m) === 1) {
            return 'prov:' . $m[1];
        }
        if (preg_match('/\Aenv\.world\.([A-Za-z0-9_.-]+)\z/', $path, $m) === 1) {
            return $m[1];
        }
        return $path;
    }

    public static function catLabel(mixed $d, int $i): string
    {
        return Js::opt(Js::opt($d, 'values')[$i], 'value');
    }

    private static function isIntegral(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    private static function negZero(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    /**
     * Resolve coordinates to a box of cells of the verb's space: ['ok' => true, 'vs' => ..., 'box' => [[int]]] or ['ok' => false,
     * 'reason' => ...]. Every dimension must be named exactly once; anything the wallet cannot resolve exactly is refused.
     */
    public static function resolveCoords(mixed $omega, mixed $verb, mixed $coords): array
    {
        $vs = null;
        foreach (Js::opt($omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === $verb) {
                $vs = $v;
                break;
            }
        }
        if ($vs === null) {
            return ['ok' => false, 'reason' => 'verb ' . (is_string($verb) ? $verb : Jsx::str($verb)) . " is not in the wallet's outcome space"];
        }
        $dims = Js::opt($vs, 'dims');
        $byKey = [];
        foreach ($dims as $k => $d) {
            $byKey[(string)Js::opt($d, 'path')] = $k;
            $byKey[self::coordKeyOf((string)Js::opt($d, 'path'))] = $k;
        }
        $named = [];
        foreach (self::entries($coords) as [$key]) {
            $k = $byKey[$key] ?? null;
            if ($k === null) {
                return ['ok' => false, 'reason' => "unknown dimension $key"];
            }
            if (isset($named[$k])) {
                return ['ok' => false, 'reason' => 'dimension ' . Js::opt($dims[$k], 'path') . ' is named twice'];
            }
            $named[$k] = true;
        }
        $box = [];
        foreach ($dims as $d) {
            $path = (string)Js::opt($d, 'path');
            $c = self::g($coords, $path);
            if ($c instanceof Undef || $c === null) {
                $c = self::g($coords, self::coordKeyOf($path));
            }
            if ($c instanceof Undef) {
                return ['ok' => false, 'reason' => "coordinates leave out dimension $path"];
            }
            if ($c === null) {
                throw new \TypeError('Cannot read properties of null');
            }
            if (Js::opt($d, 'kind') === 'num') {
                if (!(is_array($c) && array_is_list($c) && count($c) === 2 && Js::isNum($c[0]) && Js::isNum($c[1]))) {
                    return ['ok' => false, 'reason' => "dimension $path is numeric: expected an index range"];
                }
                $lo = Js::num($c[0]);
                $hi = Js::num($c[1]);
                if (!(self::isIntegral($lo) && self::isIntegral($hi) && !self::negZero($lo) && !self::negZero($hi) && $lo >= 0 && $lo <= $hi && $hi < count(WalletOmega::numCells($d)))) {
                    return ['ok' => false, 'reason' => "index range of $path is out of range"];
                }
                $box[] = range((int)$lo, (int)$hi);
            } else {
                if (!is_array($c) || !array_is_list($c)) {
                    throw new \TypeError('c.every is not a function');
                }
                foreach ($c as $x) {
                    if (!is_string($x)) {
                        return ['ok' => false, 'reason' => "dimension $path is categorical: expected a value set"];
                    }
                }
                $ids = [];
                foreach ($c as $label) {
                    $hits = [];
                    foreach (Js::opt($d, 'values') as $j => $v) {
                        if (Js::opt($v, 'value') === $label) {
                            $hits[] = $j;
                        }
                    }
                    if (count($hits) === 0) {
                        return ['ok' => false, 'reason' => 'unknown value ' . Js::stringify($label) . " for $path"];
                    }
                    if (count($hits) > 1) {
                        return ['ok' => false, 'reason' => 'value ' . Js::stringify($label) . " names two cells of $path"];
                    }
                    $ids[] = $hits[0];
                }
                $ids = array_values(array_unique($ids));
                sort($ids);
                $box[] = $ids;
            }
        }
        return ['ok' => true, 'vs' => $vs, 'box' => $box];
    }

    /**
     * The coordinates of a box (the inverse of resolveCoords; numeric sides must be contiguous).
     * @param list<list<int>> $box
     */
    public static function coordsOfBox(mixed $vs, array $box): Obj
    {
        $out = new Obj();
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            $ids = $box[$k];
            if (Js::opt($d, 'kind') === 'num') {
                $lo = min($ids);
                $hi = max($ids);
                if ($hi - $lo + 1 !== count($ids)) {
                    throw new \InvalidArgumentException('coordsOfBox: numeric side of ' . Js::opt($d, 'path') . ' is not contiguous');
                }
                $out->set(Js::opt($d, 'path'), [new Num((string)$lo), new Num((string)$hi)]);
            } else {
                $out->set(Js::opt($d, 'path'), array_map(static fn(int $i): string => self::catLabel($d, $i), $ids));
            }
        }
        return $out;
    }

    /** @param list<int> $idx */
    public static function coordsOfCell(mixed $vs, array $idx): Obj
    {
        return self::coordsOfBox($vs, array_map(static fn(int $i): array => [$i], $idx));
    }

    /** @param list<list<int>> $box @param list<int|float> $idx */
    public static function cellInBox(array $box, array $idx): bool
    {
        if (count($box) !== count($idx)) {
            return false;
        }
        foreach ($box as $k => $ids) {
            $found = false;
            foreach ($ids as $i) {
                if ($i == $idx[$k]) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param list<list<int>> $box
     * @return list<list<int>>
     */
    public static function boxCells(array $box): array
    {
        $out = [[]];
        foreach ($box as $ids) {
            $next = [];
            foreach ($out as $pre) {
                foreach ($ids as $i) {
                    $next[] = [...$pre, $i];
                }
            }
            $out = $next;
        }
        return $out;
    }

    /** @param list<list<int>> $box */
    public static function boxSize(array $box): int
    {
        $n = 1;
        foreach ($box as $ids) {
            $n *= count($ids);
        }
        return $n;
    }

    /** The cell of a concrete action in the wallet's Omega (['vs' => ..., 'idx' => [...]]); null when it falls outside it (fail closed). */
    public static function cellOfAction(mixed $omega, mixed $a): ?array
    {
        if (!self::isDict($a)) {
            throw new \TypeError('action is not an object');
        }
        $vs = null;
        foreach (Js::opt($omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === Js::opt($a, 'verb')) {
                $vs = $v;
                break;
            }
        }
        if ($vs === null) {
            return null;
        }
        $values = Js::has($a, 'values') ? Js::opt($a, 'values') : null;
        if (!self::isDict($values) && !(is_array($values) && array_is_list($values))) {
            throw new \TypeError("Cannot use 'in' operator");
        }
        foreach (Js::opt($vs, 'dims') as $d) {
            if (!(self::isDict($values) && Js::has($values, (string)Js::opt($d, 'path')))) {
                return null;
            }
        }
        $idx = WalletOmega::cellOf($vs, Obj::of(['verb' => Js::opt($a, 'verb'), 'values' => $values]));
        return $idx !== null ? ['vs' => $vs, 'idx' => $idx] : null;
    }

    /** @param list<int> $idx */
    public static function flatIndex(mixed $vs, array $idx): int
    {
        $f = 0;
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            $f = $f * WalletOmega::cellCount($d) + $idx[$k];
        }
        return $f;
    }

    // ---- stats ---------------------------------------------------------------------------------------------------------------

    private const LANCZOS = [676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059, 12.507343278686905,
        -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7];

    private static function f(mixed $x): float
    {
        $f = Js::num($x);
        if ($f === null) {
            throw new \TypeError('a number is required');
        }
        return $f;
    }

    public static function lnGamma(mixed $x): float
    {
        $x = self::f($x);
        if ($x < 0.5) {
            return log(M_PI / sin(M_PI * $x)) - self::lnGamma(1 - $x);
        }
        $z = $x - 1;
        $a = 0.99999999999980993;
        $t = $z + 7.5;
        foreach (self::LANCZOS as $i => $c) {
            $a += $c / ($z + $i + 1);
        }
        return 0.5 * log(2 * M_PI) + ($z + 0.5) * log($t) - $t + log($a);
    }

    /** The continued fraction of I_x(a, b) (modified Lentz; a zero denominator is replaced by 1e-300, never divided by). */
    public static function betacf(mixed $a, mixed $b, mixed $x): float
    {
        $a = self::f($a);
        $b = self::f($b);
        $x = self::f($x);
        $tiny = 1e-300;
        $qab = $a + $b;
        $qap = $a + 1;
        $qam = $a - 1;
        $c = 1.0;
        $d = 1 - ($qab * $x) / $qap;
        if (abs($d) < $tiny) {
            $d = $tiny;
        }
        $d = 1 / $d;
        $h = $d;
        for ($m = 1; $m <= 300; $m++) {
            $m2 = 2 * $m;
            $aa = ($m * ($b - $m) * $x) / (($qam + $m2) * ($a + $m2));
            $d = 1 + $aa * $d;
            if (abs($d) < $tiny) {
                $d = $tiny;
            }
            $c = 1 + $aa / $c;
            if (abs($c) < $tiny) {
                $c = $tiny;
            }
            $d = 1 / $d;
            $h *= $d * $c;
            $aa = (-($a + $m) * ($qab + $m) * $x) / (($a + $m2) * ($qap + $m2));
            $d = 1 + $aa * $d;
            if (abs($d) < $tiny) {
                $d = $tiny;
            }
            $c = 1 + $aa / $c;
            if (abs($c) < $tiny) {
                $c = $tiny;
            }
            $d = 1 / $d;
            $dl = $d * $c;
            $h *= $dl;
            if (abs($dl - 1) < 1e-15) {
                break;
            }
        }
        return $h;
    }

    /** Regularized incomplete beta I_x(a, b), a, b > 0, x in [0, 1]. */
    public static function betaInc(mixed $x, mixed $a, mixed $b): float
    {
        $x = self::f($x);
        $a = self::f($a);
        $b = self::f($b);
        if (!($a > 0 && $b > 0)) {
            throw new \InvalidArgumentException('betaInc: a and b must be > 0');
        }
        if ($x <= 0) {
            return 0.0;
        }
        if ($x >= 1) {
            return 1.0;
        }
        $lbt = self::lnGamma($a + $b) - self::lnGamma($a) - self::lnGamma($b) + $a * log($x) + $b * log(1 - $x);
        $bt = exp($lbt);
        if ($x < ($a + 1) / ($a + $b + 2)) {
            return ($bt * self::betacf($a, $b, $x)) / $a;
        }
        return 1 - ($bt * self::betacf($b, $a, 1 - $x)) / $b;
    }

    /** The q-quantile of Beta(a, b) by bisection (200 steps). */
    public static function betaQuantile(mixed $q, mixed $a, mixed $b): float
    {
        $q = self::f($q);
        if (!($q >= 0 && $q <= 1)) {
            throw new \InvalidArgumentException('betaQuantile: q must be in [0, 1]');
        }
        if ($q == 0) {
            return 0.0;
        }
        if ($q == 1) {
            return 1.0;
        }
        $lo = 0.0;
        $hi = 1.0;
        for ($i = 0; $i < 200; $i++) {
            $mid = ($lo + $hi) / 2;
            if (self::betaInc($mid, $a, $b) < $q) {
                $lo = $mid;
            } else {
                $hi = $mid;
            }
        }
        return $hi;
    }

    /** Binary entropy in bits. */
    public static function binEnt(mixed $p): float
    {
        $p = self::f($p);
        if ($p <= 0 || $p >= 1) {
            return 0.0;
        }
        return -($p * (log($p) / M_LN2) + (1 - $p) * (log(1 - $p) / M_LN2));
    }

    /**
     * The upper bound q such that the Beta(a, b) posterior puts mass delta above it, for POSITIVE INTEGER a and b, exactly: I_x(a, b) =
     * P[Bin(a + b - 1, x) >= a], so the quantile at level 1 - delta is the Clopper-Pearson inversion with k = a - 1 successes in n = a + b - 1
     * trials (integer arithmetic, rounded outward). The freeze and admission decisions compare this value, so it must not depend on libm.
     */
    public static function betaUpperExact(mixed $delta, mixed $a, mixed $b): float
    {
        $af = self::f($a);
        $bf = self::f($b);
        if (!(is_finite($af) && floor($af) === $af && $af >= 1 && is_finite($bf) && floor($bf) === $bf && $bf >= 1)) {
            throw new \RangeException('betaUpperExact: a and b must be positive integers');
        }
        return self::clopperPearsonUpper($af - 1, $af + $bf - 1, $delta);
    }

    public static function clopperPearsonUpper(mixed $k, mixed $n, mixed $alpha): float
    {
        return WalletOmega::clopperPearsonUpper($k, $n, $alpha);
    }

    // ---- canaries ------------------------------------------------------------------------------------------------------------

    private static function count(mixed $n, string $k): float
    {
        return self::reqNum($n, $k);
    }

    /** Fold one canary answer into the counts (pure). */
    public static function recordCanary(mixed $n, mixed $expected, mixed $y): Obj
    {
        $out = new Obj();
        foreach (self::dictKeys($n) as $k) {
            $out->set($k, Js::opt($n, $k));
        }
        if (self::numEq($expected, 0)) {
            if (self::numEq($y, 1)) {
                $out->set('falseYes', self::count($n, 'falseYes') + 1);
            } else {
                $out->set('correctNo', self::count($n, 'correctNo') + 1);
            }
        } elseif (self::numEq($y, 0)) {
            $out->set('falseNo', self::count($n, 'falseNo') + 1);
        } else {
            $out->set('correctYes', self::count($n, 'correctYes') + 1);
        }
        return $out;
    }

    /** @return array<string,int|float> */
    public static function estimateNoise(mixed $n, mixed $deltaC = 0.05): array
    {
        $dc = self::f($deltaC);
        if (!($dc > 0 && $dc < 1)) {
            throw new \InvalidArgumentException('estimateNoise: deltaC must be in (0, 1)');
        }
        $fy = self::count($n, 'falseYes');
        $cn = self::count($n, 'correctNo');
        $fn = self::count($n, 'falseNo');
        $cy = self::count($n, 'correctYes');
        $ap = self::NOISE_PRIOR['a'] + $fy;
        $bp = self::NOISE_PRIOR['b'] + $cn;
        $an = self::NOISE_PRIOR['a'] + $fn;
        $bn = self::NOISE_PRIOR['b'] + $cy;
        $knownNo = $fy + $cn;
        $knownYes = $fn + $cy;
        return [
            'etaPos' => $ap / ($ap + $bp),
            'etaNeg' => $an / ($an + $bn),
            'etaPosUpper' => self::betaUpperExact($dc, $ap, $bp),
            'etaNegUpper' => self::betaUpperExact($dc, $an, $bn),
            'etaPosCP' => $knownNo == 0 ? 1 : self::clopperPearsonUpper($fy, $knownNo, $dc),
            'etaNegCP' => $knownYes == 0 ? 1 : self::clopperPearsonUpper($fn, $knownYes, $dc),
            'asked' => $knownNo + $knownYes,
        ];
    }

    /** @param list<mixed> $idx */
    public static function cellKey(mixed $verb, array $idx): string
    {
        $parts = [];
        foreach ($idx as $i) {
            $parts[] = self::isIntegral($i) ? (string)(int)Js::num($i) : Jsx::str($i);
        }
        return Jsx::str($verb) . '|' . implode(',', $parts);
    }

    /**
     * Cells one step outside the confirmed region in exactly one dimension (deterministic order).
     * @param list<mixed> $confirmed items {verb, idx}
     * @return list<array{verb:mixed,idx:list<int>}>
     */
    public static function boundaryNeighbours(mixed $omega, array $confirmed): array
    {
        $inside = [];
        foreach ($confirmed as $c) {
            $inside[self::cellKey(Js::opt($c, 'verb'), Js::opt($c, 'idx'))] = true;
        }
        $out = [];
        foreach ($confirmed as $c) {
            $vs = null;
            foreach (Js::opt($omega, 'verbs') as $v) {
                if (Js::opt($v, 'verb') === Js::opt($c, 'verb')) {
                    $vs = $v;
                    break;
                }
            }
            if ($vs === null) {
                continue;
            }
            $cidx = Js::opt($c, 'idx');
            foreach (Js::opt($vs, 'dims') as $k => $d) {
                $n = WalletOmega::cellCount($d);
                $cur = (int)Js::num($cidx[$k]);
                $alts = Js::opt($d, 'kind') === 'num' ? [$cur - 1, $cur + 1] : range(0, $n - 1);
                foreach ($alts as $a) {
                    if ($a < 0 || $a >= $n || $a === $cur) {
                        continue;
                    }
                    $idx = array_map(static fn($x): int => (int)Js::num($x), $cidx);
                    $idx[$k] = $a;
                    $key = self::cellKey(Js::opt($c, 'verb'), $idx);
                    if (!isset($inside[$key])) {
                        $out[$key] = ['verb' => Js::opt($c, 'verb'), 'idx' => $idx];
                    }
                }
            }
        }
        $keys = array_keys($out);
        usort($keys, static fn($a, $b): int => strcmp((string)mb_convert_encoding((string)$a, 'UTF-16BE', 'UTF-8'), (string)mb_convert_encoding((string)$b, 'UTF-16BE', 'UTF-8')));
        return array_map(static fn($k) => $out[$k], $keys);
    }

    /**
     * Decide whether to insert a canary now, and which (null: no canary this time). `$ctx` (an assoc array) carries omega, confirmed,
     * knownNo (Closure (verb, idx) -> "ceiling" | "veto" | null), knownYes, exclude (a list of `verb|i,j,..` keys), rand (Closure),
     * optional rho (default 0.1), lowHarmSession and canariesSoFar.
     */
    public static function pickCanary(mixed $ctx): ?array
    {
        $rho = Js::opt($ctx, 'rho');
        $rho = $rho === null ? 0.1 : self::f($rho);
        if (!($rho >= 0 && $rho <= 1)) {
            throw new \InvalidArgumentException('pickCanary: rho must be in [0, 1]');
        }
        $rand = Js::opt($ctx, 'rand');
        if (Jsx::truthy(Js::opt($ctx, 'lowHarmSession')) && self::f(Js::opt($ctx, 'canariesSoFar')) >= 1) {
            return null;
        }
        if (!($rand() < $rho)) {
            return null;
        }
        $exclude = array_flip(array_map('strval', Js::opt($ctx, 'exclude') ?? []));
        $knownNo = Js::opt($ctx, 'knownNo');
        $no = [];
        foreach (self::boundaryNeighbours(Js::opt($ctx, 'omega'), Js::opt($ctx, 'confirmed')) as $c) {
            if (isset($exclude[self::cellKey($c['verb'], $c['idx'])])) {
                continue;
            }
            $why = $knownNo($c['verb'], $c['idx']);
            if (Jsx::truthy($why)) {
                $no[] = ['verb' => $c['verb'], 'idx' => $c['idx'], 'expected' => 0, 'source' => $why];
            }
        }
        $yes = [];
        foreach (Js::opt($ctx, 'knownYes') as $c) {
            $idx = array_map(static fn($x): int => (int)Js::num($x), Js::opt($c, 'idx'));
            if (!isset($exclude[self::cellKey(Js::opt($c, 'verb'), $idx)])) {
                $yes[] = ['verb' => Js::opt($c, 'verb'), 'idx' => $idx, 'expected' => 1, 'source' => 'confirmed-yes'];
            }
        }
        if (!$no && !$yes) {
            return null;
        }
        if ($no && $yes) {
            $pool = $rand() < 0.5 ? $no : $yes;
        } else {
            $pool = $no ?: $yes;
        }
        return $pool[min(count($pool) - 1, (int)floor($rand() * count($pool)))];
    }

    // ---- approval fatigue ---------------------------------------------------------------------------------------------------

    /** eta+ under load: base + betaF * nRecent, capped at 1/2. */
    public static function etaUnderLoad(mixed $base, mixed $betaF, mixed $nRecent): float
    {
        $b = Js::num($base);
        $bf = Js::num($betaF);
        if (!($b !== null && $bf !== null && $b >= 0 && $bf >= 0 && self::isIntegral($nRecent) && Js::num($nRecent) >= 0)) {
            throw new \InvalidArgumentException('etaUnderLoad: bad arguments');
        }
        return min(0.5, $b + $bf * Js::num($nRecent));
    }

    /** @return array{etaPos:float,etaPosBar:float,etaNegBar:float,frozen:bool} */
    public static function noiseState(mixed $counts, mixed $nRecent, mixed $model = null): array
    {
        $model ??= self::DEFAULT_FATIGUE;
        $e = self::estimateNoise($counts, self::req($model, 'deltaC'));
        $betaF = self::req($model, 'betaF');
        $etaPos = self::etaUnderLoad($e['etaPos'], $betaF, $nRecent);
        $etaPosBar = self::etaUnderLoad($e['etaPosUpper'], $betaF, $nRecent);
        $stat = self::req($model, 'freezeOn') === 'mean' ? $etaPos : $etaPosBar;
        return ['etaPos' => $etaPos, 'etaPosBar' => $etaPosBar, 'etaNegBar' => min(0.5, $e['etaNegUpper']), 'frozen' => $stat > self::reqNum($model, 'etaStop')];
    }

    public static function admissionPolicy(mixed $state, mixed $model = null): array
    {
        $model ??= self::DEFAULT_FATIGUE;
        if (self::truthyPy(self::req($model, 'assumeNoiseFree'))) {
            return ['tau' => 1, 'etaPos' => 0, 'etaNeg' => 0, 'doubleConfirmIrreversible' => false, 'falseAdmitBound' => 0];
        }
        $delta = self::reqNum($model, 'delta');
        if (!($delta > 0 && $delta < 1)) {
            throw new \InvalidArgumentException('admissionPolicy: delta must be in (0, 1)');
        }
        $ep = min(self::BELOW_HALF, self::reqNum($state, 'etaPosBar'));
        $en = min(self::BELOW_HALF, self::reqNum($state, 'etaNegBar'));
        return ['tau' => 1 - $delta, 'etaPos' => $ep, 'etaNeg' => $en, 'doubleConfirmIrreversible' => $ep > 0, 'falseAdmitBound' => $ep * $ep];
    }

    private static function truthyPy(mixed $v): bool
    {
        return Jsx::truthy($v);
    }

    /** Two "yes" answers at typed or device tier, on different screens, with at least one other screen between them. */
    public static function doubleConfirmed(mixed $records): bool
    {
        $strong = [];
        foreach ($records as $r) {
            if (in_array(Js::opt($r, 'tier'), ['typed', 'device'], true)) {
                $strong[] = self::f(self::req($r, 'screen'));
            }
        }
        sort($strong);
        $n = count($strong);
        for ($i = 0; $i < $n; $i++) {
            for ($j = $i + 1; $j < $n; $j++) {
                if ($strong[$j] - $strong[$i] >= 2) {
                    return true;
                }
            }
        }
        return false;
    }
}
