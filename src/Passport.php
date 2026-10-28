<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentWb.php';

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

    private static function has(mixed $o, string $k): bool
    {
        return $o instanceof Obj ? $o->has($k) : (is_array($o) && array_key_exists($k, $o));
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
        $o->set('hardware_rooted', $p->get('hardware_rooted'));
        return Pca::hashCanonical($o);
    }

    /** The binding a hardware quote must carry: holder = subject key, grant = `passport:<id>`, epoch 0, nonce = the evidence nonce. */
    public static function evidenceBinding(string $passportId, string $subject, string $nonce): array
    {
        return ['holderPub' => $subject, 'grantRef' => 'passport:' . $passportId, 'epoch' => 0, 'nonce' => $nonce];
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
        $msg = self::SIG_DOMAIN . Json::canonicalizeStrict($body);
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
        $skew = min(max((float)(self::f($skewIn) ?? 0.0), 0.0), (float)self::MAX_SKEW_MS);
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
        if ($maxAge === null || $maxAge < 0 || $now - (float)self::f($at) > $maxAge || (float)self::f($at) - $now > $skew) {
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
}
