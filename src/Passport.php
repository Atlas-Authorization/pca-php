<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Assurance.php';

/**
 * Signed agent passport verification (wire level): the native counterpart of `verifyPassport` in `@atlasauth/pca`, with the same
 * reason codes in the same check order (the text after the code is not part of the contract). A passport is the portable,
 * content-addressed statement of WHICH agent is acting (model, weights, operator, prompt, tools) signed by an issuer you trust,
 * bound to the agent's key.
 *
 * Every signature suite this verifier implements for PCActns ({@see Pca::supportedSuites}) is accepted: Ed25519 always, a
 * post-quantum or hybrid suite only under a PQ key pinned for the issuer (`pqPins`); a suite it does not implement is refused
 * with `unsupported_suite`. Hardware evidence: the age rule, the binding handed to the verifier and the identity comparison are
 * enforced here; the verifier is the integrator's `attest` callable or, when none is given, the built-in vendor verifier of
 * `defaultHardware` ({@see Attest\DefaultHardware}: AMD SEV-SNP, Intel TDX, Azure MAA, Google Confidential Space, NVIDIA GPU).
 * With neither, a hardware_rooted passport that passes every other check is refused with `hardware_verifier_missing`
 * (fail closed, never a software pass). Total: never throws.
 */
final class Passport
{
    public const SIG_DOMAIN = "atlas-pca/passport-sig/v1\0";
    public const VERSION = 1;
    public const MAX_SKEW_MS = 60_000;
    /** Default ceiling on the age of a hardware quote a passport carries (24 h). */
    public const DEFAULT_EVIDENCE_AGE_MS = 86_400_000;
    private const MAX_SAFE = 9007199254740991;

    /** A finite JSON number (Num or native) as a float, else null. */
    private static function f(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $v !== null && is_finite($v) ? $v : null;
    }

    /** Number.isSafeInteger over a JSON value (-0 is accepted: the passport wire is not the strict profile). */
    private static function safeInt(mixed $x): bool
    {
        $v = self::f($x);
        return $v !== null && floor($v) === $v && abs($v) <= self::MAX_SAFE;
    }

    private static function isStr(mixed $x): bool
    {
        return is_string($x) && $x !== '';
    }

    private static function g(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        return is_array($o) ? ($o[$k] ?? null) : null;
    }

    /** @return array{ok: false, reason: string, detail?: string} */
    private static function bad(string $reason, ?string $detail = null): array
    {
        $r = ['ok' => false, 'reason' => $reason];
        if ($detail !== null && $detail !== '') {
            $r['detail'] = $detail;
        }
        return $r;
    }

    /**
     * A registry of passports by id: a later passport with the same id replaces the earlier one in place (first-appearance order); ids are not validated.
     * @param list<mixed> $passports
     * @return array{get:\Closure(mixed):mixed,has:\Closure(mixed):bool,all:\Closure():list<mixed>}
     */
    public static function buildRegistry(array $passports): array
    {
        $by = [];
        foreach ($passports as $p) {
            $by['k' . Js::str(Js::get($p, 'id'))] = $p;
        }
        return ['get' => static fn(mixed $id): mixed => $by['k' . Js::str($id)] ?? null, 'has' => static fn(mixed $id): bool => isset($by['k' . Js::str($id)]),
            'all' => static fn(): array => array_values($by)];
    }

    /** The content fingerprint of the identity fields (the passport id). */
    public static function fingerprint(Obj $p): string
    {
        $o = new Obj();
        $o->set('d', 'atlas-pca/passport/v1');
        $o->set('model_id', $p->get('model_id'));
        foreach (['weights_digest', 'system_prompt_digest', 'tool_manifest_digest', 'runtime_measurement'] as $k) {
            $o->set($k, $p->get($k)); // absent and null are both null
        }
        $o->set('operator', $p->get('operator'));
        if (!$p->has('hardware_rooted')) { // an undefined member does not canonicalize
            throw new JsonError('canonicalize: unsupported type undefined');
        }
        $o->set('hardware_rooted', $p->get('hardware_rooted'));
        return Pca::hashCanonical($o);
    }

    /** The binding a hardware quote must carry: holder = subject key, grant = `passport:<id>`, epoch 0, nonce = the evidence nonce. */
    public static function evidenceBinding(mixed $passportId, mixed $subject, mixed $nonce): array
    {
        return ['holderPub' => $subject, 'grantRef' => 'passport:' . Js::str($passportId), 'epoch' => 0, 'nonce' => $nonce];
    }

    /**
     * Verify a signed passport (a parsed Obj). Options (a PHP array):
     *  - `trustedIssuers` list<string>: issuer keys (b64u Ed25519) you trust; empty trusts nobody
     *  - `now` int: epoch ms
     *  - `clockSkewMs` int|float: tolerance on nbf / exp (default 0, capped at 60000)
     *  - `subject` string: the agent key the presenter signs with; when given the passport's `sub` must equal it
     *  - `maxEvidenceAgeMs` int|float: oldest acceptable hardware evidence (default 24 h)
     *  - `pqPins` array|Obj: issuer key => the PQ public key pinned for it (required for every non-Ed25519 suite)
     *  - `attest` callable `(Obj $document, array $expected): array|Obj` answering `{ok, bound, measured, reason?}` for a
     *    hardware_rooted passport (`$expected` = holderPub, grantRef, epoch, nonce, nonceIssuedAt); a throw denies
     *  - `defaultHardware` Attest\DefaultHardware: the built-in vendor verifier used when `attest` is absent
     *  - `revocation` callable `(array{id,iss,sub}): bool`: true = revoked; REQUIRED (absent: `revocation_unavailable`); a throw denies
     *
     * @return array{ok: true, passport: Obj, iss: string, sub: string, exp: int, hardware_verified: bool}|array{ok: false, reason: string, detail?: string}
     */
    public static function verify(mixed $sp, array $o): array
    {
        try {
            return self::verifyInner($sp, $o);
        } catch (\Throwable $e) {
            return self::bad('malformed', $e->getMessage());
        }
    }

    private static function verifyInner(mixed $sp, array $o): array
    {
        if (!($sp instanceof Obj) || $sp->get('typ') !== 'atlas-pca/passport' || $sp->get('passport') === null) {
            return self::bad('malformed');
        }
        $s = $sp;
        $ver = $s->get('ver');
        if (!(self::safeInt($ver) && self::f($ver) === 1.0)) {
            return self::bad('unsupported_version', IntentWb::jsStr($ver));
        }
        $alg = $s->has('alg') ? $s->get('alg') : null;
        if ($s->has('alg') && !(is_string($alg) && Pca::suiteImplemented($alg))) {
            return self::bad('unsupported_suite', IntentWb::jsStr($alg));
        }
        $p = $s->get('passport');
        $iss = $s->get('iss');
        $sub = $s->get('sub');
        if (!self::isStr($iss) || !self::isStr($sub) || !self::isStr($s->get('sig')) || !self::isStr(self::g($p, 'id'))
            || !self::isStr(self::g($p, 'model_id')) || !self::isStr(self::g($p, 'operator'))
            || !is_bool(self::g($p, 'hardware_rooted')) || !($p instanceof Obj)) {
            return self::bad('malformed');
        }
        $now = $o['now'] ?? null;
        foreach ([$s->get('iat'), $s->get('nbf'), $s->get('exp'), $now] as $t) {
            if (!self::safeInt($t)) {
                return self::bad('malformed', 'times');
            }
        }
        if (!(self::f($s->get('exp')) > self::f($s->get('nbf')))) {
            return self::bad('malformed', 'times');
        }
        $nowF = (float)self::f($now);
        $trusted = $o['trustedIssuers'] ?? null;
        if (!is_array($trusted) || !in_array($iss, $trusted, true)) {
            return self::bad('unknown_issuer');
        }
        $body = $s->without('sig', 'pq_sig');
        $msg = self::SIG_DOMAIN . Json::canonicalizeNative($body);
        $pins = $o['pqPins'] ?? null;
        $pinned = self::g($pins, $iss);
        $pqPk = $s->has('pq_pk') ? $s->get('pq_pk') : null;
        $sigOk = Pca::verifyPinnedSuite($s->has('alg') ? $alg : null, $iss, $pqPk, $msg, $s->get('sig'),
            $s->has('pq_sig') ? $s->get('pq_sig') : null, is_string($pinned) ? $pinned : null);
        if ($sigOk !== true) {
            return self::bad('bad_signature');
        }
        if ($p->get('id') !== self::fingerprint($p)) {
            return self::bad('id_mismatch');
        }
        $skewIn = $o['clockSkewMs'] ?? 0;
        // Math.min(Math.max(skew, 0), MAX): a NaN skew stays NaN, so no comparison below holds
        // Math.max coerces a numeric string the way the + operator does not: "1000" is 1000; any other non-number is no skew
        $skewN = is_string($skewIn) ? Jsx::toNum($skewIn) : (self::f($skewIn) ?? 0.0);
        $skew = is_float($skewIn) && is_nan($skewIn) ? NAN : min(max(is_nan($skewN) ? 0.0 : $skewN, 0.0), (float)self::MAX_SKEW_MS);
        if ($nowF + $skew < self::f($s->get('nbf'))) {
            return self::bad('not_yet_valid');
        }
        if ($nowF - $skew >= self::f($s->get('exp'))) {
            return self::bad('expired');
        }
        if (isset($o['subject']) && $o['subject'] !== $sub) {
            return self::bad('subject_mismatch');
        }
        $rev = $o['revocation'] ?? null;
        if (!is_callable($rev)) {
            return self::bad('revocation_unavailable', 'no revocation source');
        }
        try {
            $revoked = $rev(['id' => $p->get('id'), 'iss' => $iss, 'sub' => $sub]) === true;
        } catch (\Throwable) {
            return self::bad('revocation_unavailable');
        }
        if ($revoked) {
            return self::bad('revoked');
        }
        if ($p->get('hardware_rooted') === true) {
            $fail = self::hardware($s, $p, $sub, $o, $nowF, $skew);
            if ($fail !== null) {
                return $fail;
            }
        }
        return ['ok' => true, 'passport' => $p, 'iss' => $iss, 'sub' => $sub, 'exp' => (int)self::f($s->get('exp')),
            'hardware_verified' => $p->get('hardware_rooted') === true];
    }

    /** The hardware branch: null = verified, else the refusal. */
    private static function hardware(Obj $s, Obj $p, string $sub, array $o, float $now, float $skew): ?array
    {
        $ev = $s->has('evidence') && $s->get('evidence') !== null ? $s->get('evidence') : new Obj();
        $doc = self::g($ev, 'document');
        if (!($doc instanceof Obj) || !self::isStr($doc->get('nonce'))) {
            return self::bad('hardware_evidence_missing');
        }
        $at = self::g($ev, 'at');
        if (!self::safeInt($at)) {
            return self::bad('hardware_evidence_missing', 'evidence.at');
        }
        $maxAge = self::f($o['maxEvidenceAgeMs'] ?? self::DEFAULT_EVIDENCE_AGE_MS);
        if ($maxAge === null || !is_finite($maxAge) || !is_finite((float)$now) || $maxAge < 0 || $now - (float)self::f($at) > $maxAge || (float)self::f($at) - $now > $skew) {
            return self::bad('hardware_evidence_stale');
        }
        $attest = $o['attest'] ?? null;
        if (!is_callable($attest) && isset($o['defaultHardware']) && is_object($o['defaultHardware'])) {
            $attest = $o['defaultHardware']->attest((int)$now);
        }
        if (!is_callable($attest)) {
            return self::bad('hardware_verifier_missing');
        }
        $expected = self::evidenceBinding((string)$p->get('id'), $sub, $doc->get('nonce')) + ['nonceIssuedAt' => (int)$now];
        try {
            $r = $attest($doc, $expected);
        } catch (\Throwable $e) {
            return self::bad('hardware_attestation_failed', $e->getMessage());
        }
        if (!is_array($r) && !($r instanceof Obj)) {
            return self::bad('hardware_attestation_failed');
        }
        if (self::g($r, 'ok') !== true || self::g($r, 'bound') !== true) {
            $why = self::g($r, 'reason');
            return self::bad('hardware_attestation_failed', is_string($why) ? $why : null);
        }
        if (!self::identityMatches($p, self::g($r, 'measured'))) {
            return self::bad('hardware_identity_mismatch');
        }
        return null;
    }

    /** The hardware-measured identity equals the claims (model and operator always; the optional digests and the runtime
     *  measurement when the passport states them; measured weights when it claims them). */
    private static function identityMatches(Obj $p, mixed $m): bool
    {
        if (!($m instanceof Obj) && !is_array($m)) {
            return false;
        }
        $eq = static fn(string $k): bool => is_string($p->get($k)) && is_string(self::g($m, $k)) && $p->get($k) === self::g($m, $k);
        if (!$eq('model_id') || !$eq('operator')) {
            return false;
        }
        foreach (['weights_digest', 'runtime_measurement', 'system_prompt_digest', 'tool_manifest_digest'] as $k) {
            if ($p->get($k) !== null && !$eq($k)) {
                return false;
            }
        }
        return !($p->get('weights_measured') === true && self::g($m, 'weights_measured') !== true);
    }

    // ---- binding match, trust score and assurance label (pure helpers over a parsed passport) ----

    /** Strict equality of two parsed-JSON scalars (numbers by value); an object or a list never equals anything. */
    private static function same(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) || Js::isNum($b)) {
            return Js::isNum($a) && Js::isNum($b) && Js::num($a) === Js::num($b);
        }
        return ($a === null || is_bool($a) || is_string($a)) && $a === $b;
    }

    /** The reference's `list.includes(value)`: membership in a list, a substring test on a string, a refusal on anything else. */
    private static function includes(mixed $list, bool $has, mixed $value): bool
    {
        if (is_string($list)) {
            return str_contains($list, $has ? Js::str($value) : 'undefined');
        }
        if (!is_array($list) || !array_is_list($list)) {
            throw new \TypeError('allowlist is not a list');
        }
        foreach ($list as $x) {
            if ($has && self::same($x, $value)) {
                return true;
            }
        }
        return false;
    }

    private static function text(mixed $o, string $k): string
    {
        return Js::has($o, $k) ? Js::str(Js::opt($o, $k)) : 'undefined';
    }

    /**
     * Does the passport satisfy an agent binding (model / weights / prompt / tool allowlists, operator, hardware and measured-weights
     * requirements, the pinned measurement or the minimum SVN)? Every unmet requirement is a reason, in the reference's order and
     * wording. A malformed `min_measurement` fails closed. `$p` and `$b` are parsed objects (Obj or assoc arrays); null throws.
     * @return array{ok:bool,reasons:list<string>}
     */
    public static function matchesBinding(mixed $p, mixed $b): array
    {
        if ($p === null || $b === null) {
            throw new \TypeError('matchesBinding: the passport and the binding must be objects');
        }
        $reasons = [];
        $model = Js::opt($b, 'model_allowlist');
        if (Js::truthy($model) && (is_string($model) || (is_array($model) && array_is_list($model) && $model !== []))
            && !self::includes($model, Js::has($p, 'model_id'), Js::opt($p, 'model_id'))) {
            $reasons[] = "model_id '" . self::text($p, 'model_id') . "' not in allowlist";
        }
        foreach ([['weights_allowlist', 'weights_digest'], ['system_prompt_allowlist', 'system_prompt_digest'], ['tool_manifest_allowlist', 'tool_manifest_digest']] as [$lk, $label]) {
            $list = Js::opt($b, $lk);
            if (!Js::truthy($list) || $list === []) {
                continue;
            }
            if (!Js::has($p, $label)) {
                $reasons[] = "$label required by binding but absent from passport";
            } elseif (!self::includes($list, true, Js::opt($p, $label))) {
                $reasons[] = "$label '" . Js::str(Js::opt($p, $label)) . "' not in allowlist";
            }
        }
        if (Js::has($b, 'operator') && !(Js::has($p, 'operator') && self::same(Js::opt($p, 'operator'), Js::opt($b, 'operator')))) {
            $reasons[] = "operator '" . self::text($p, 'operator') . "' != required '" . Js::str(Js::opt($b, 'operator')) . "'";
        }
        if (Js::truthy(Js::opt($b, 'require_hardware')) && !Js::truthy(Js::opt($p, 'hardware_rooted'))) {
            $reasons[] = 'binding requires a hardware-rooted attestation';
        }
        if (Js::truthy(Js::opt($b, 'require_measured_weights')) && !Js::truthy(Js::opt($p, 'weights_measured'))) {
            $reasons[] = 'binding requires hardware-measured weights';
        }
        if (Js::has($b, 'min_measurement')) {
            $mm = Js::opt($b, 'min_measurement');
            $rm = Js::opt($p, 'runtime_measurement');
            if (is_string($mm)) {
                if ($rm !== $mm) {
                    $reasons[] = 'runtime_measurement does not equal the pinned measurement';
                }
            } else {
                $one = ($mm instanceof Obj && count($mm->keys()) === 1) || (is_array($mm) && !array_is_list($mm) && count($mm) === 1);
                $bound = $one ? Js::num(Js::opt($mm, 'svn')) : null;
                if ($bound === null || !self::safeInt($bound) || $bound < 0 || ($bound === 0.0 && fdiv(1.0, $bound) < 0)) {
                    $reasons[] = 'min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)';
                } else {
                    $svn = is_string($rm) && preg_match('/\A(?:0|[1-9][0-9]*)\z/', $rm) === 1 ? (float) $rm : NAN;
                    if (!self::safeInt($svn) || $svn < $bound) {
                        $reasons[] = 'runtime SVN ' . self::text($p, 'runtime_measurement') . ' < required ' . Js::str($bound);
                    }
                }
            }
        }
        return ['ok' => $reasons === [], 'reasons' => $reasons];
    }

    /**
     * A reputation-free score in [0, 1] of how much of the identity is pinned: hardware-rooted 0.4, a weights digest 0.1 (0.2 when
     * hardware-measured), a prompt digest 0.1, a tool manifest digest 0.1, an operator named in `knownOperators` 0.2.
     * `$opts` is null or {knownOperators}. A null passport throws.
     */
    public static function trustScore(mixed $p, mixed $opts = null): float
    {
        if ($p === null) {
            throw new \TypeError('trustScore: the passport must be an object');
        }
        $s = 0.0;
        if (Js::truthy(Js::opt($p, 'hardware_rooted'))) {
            $s += 0.4;
        }
        if (Js::truthy(Js::opt($p, 'weights_digest'))) {
            $s += Js::truthy(Js::opt($p, 'weights_measured')) ? 0.2 : 0.1;
        }
        if (Js::truthy(Js::opt($p, 'system_prompt_digest'))) {
            $s += 0.1;
        }
        if (Js::truthy(Js::opt($p, 'tool_manifest_digest'))) {
            $s += 0.1;
        }
        $known = Js::opt($opts, 'knownOperators');
        if ($known !== null && self::includes($known, Js::has($p, 'operator'), Js::opt($p, 'operator'))) {
            $s += 0.2;
        }
        return max(0.0, min(1.0, $s));
    }

    /**
     * The assurance label of a verified passport (the `ok` verdict of {@see verify}): `software` unless its hardware evidence verified,
     * else the label attached to `$verifier` ({@see Assurance::setLabel}), `unknown` when it carries none.
     * @return array{level:string,vendor?:string}
     */
    public static function passportAssurance(mixed $verdict, mixed $verifier = null): array
    {
        if (!Js::truthy(Js::opt($verdict, 'hardware_verified'))) {
            return ['level' => 'software'];
        }
        $l = Assurance::labelOf($verifier);
        return ['level' => $l?->level ?? 'unknown'] + ($l !== null && $l->vendor !== null && $l->vendor !== '' ? ['vendor' => $l->vendor] : []);
    }
}
