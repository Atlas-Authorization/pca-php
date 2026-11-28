<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Pq.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/WhatwgUrl.php';

/**
 * A signed, machine-readable statement of the risk-budget bound of a grant (the TypeScript reference safety-certificate.ts is
 * authoritative): from the risk policy's `bMax` and `kappa` it derives the bound `bMax / kappa`, a human statement and optional check
 * rows, signed by the guardian (Ed25519, ML-DSA-65 or the hybrid). Verification recomputes the bound from the certificate's own
 * parameters and refuses any mismatch. The certificate says what the signed parameters imply; it never says the agent is safe.
 *
 * Values are the parsed-JSON model (Obj, list arrays, string, Num, bool, null); a number may also be a PHP int or float.
 * A post-quantum guardian key is accepted only under a verifier-side pin (`pqPins`): the certificate's own key is never enough.
 */
final class SafetyCertificate
{
    public const SAFETY_CERT_DOMAIN = "atlas-pca/safety-cert/v1\0";
    public const SAFETY_CERT_VERSION = 1;
    public const SAFETY_CERT_SCOPE = 'risk-budget-bound';
    public const MAX_SAFETY_CHECKS = 64;
    public const MAX_JSON_BYTES = 1 << 20;
    /** Marks an argument that was not given (null is a value). */
    public const UNSET = "\0unset";
    private const MAX_CHECK_ID = 64;
    private const MAX_EVIDENCE_URL = 2048;
    private const MAX_SAFE = 9007199254740991.0;

    /** The double of a JSON or PHP number (NaN and the infinities included), else null. */
    private static function d(mixed $x): ?float
    {
        return $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : null);
    }

    private static function fin(mixed $x): ?float
    {
        $v = self::d($x);
        return $v !== null && is_finite($v) ? $v : null;
    }

    /** A parsed value as the plain arrays and doubles the risk-policy validator reads. */
    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::plain($v->get($k));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::plain(...), $v) : ($v instanceof Num ? $v->float() : $v);
    }

    /** A URL the platform parser accepts, with the https scheme and neither a username nor a password. */
    private static function plainHttps(string $ref): bool
    {
        $u = WhatwgUrl::parse($ref);
        if ($u === null || $u['scheme'] !== 'https') {
            return false;
        }
        $s = str_replace(["\t", "\n", "\r"], '', (string)preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $ref));
        $rest = (string)preg_replace('#\A[A-Za-z][A-Za-z0-9+.\-]*:[/\\\\]*#', '', $s);
        $authority = substr($rest, 0, strcspn($rest, "/\\?#"));
        $at = strrpos($authority, '@');
        return $at === false || in_array(substr($authority, 0, $at), ['', ':'], true); // "user", "user:pw" and ":pw" are credentials
    }

    /** Why a list of check rows is malformed, or null. A row is `{id, status: passed|failed|not_run, evidence: {kind: url|sha256, ref}, at}`. */
    public static function validateSafetyChecks(mixed $checks): ?string
    {
        if (!is_array($checks) || !array_is_list($checks)) {
            return 'checks must be an array';
        }
        if (count($checks) > self::MAX_SAFETY_CHECKS) {
            return 'more than ' . self::MAX_SAFETY_CHECKS . ' checks';
        }
        $seen = [];
        foreach ($checks as $c) {
            if (!($c instanceof Obj) && !is_array($c)) {
                return 'check is not an object';
            }
            $k = $c instanceof Obj ? $c : new Obj(); // a list is an object without these members
            $id = $k->get('id');
            if (!is_string($id) || $id === '' || Js::len($id) > self::MAX_CHECK_ID) {
                return 'check id must be a 1..64 char string';
            }
            if (isset($seen["k$id"])) {
                return "duplicate check id '$id'";
            }
            $seen["k$id"] = true;
            if (!in_array($k->get('status'), ['passed', 'failed', 'not_run'], true)) {
                return "check '$id' has an invalid status";
            }
            $at = self::fin($k->get('at'));
            if ($at === null || floor($at) !== $at || $at < 0 || $at > self::MAX_SAFE || K3Sig::isNegZero($k->get('at'))) {
                return "check '$id' has an invalid time";
            }
            $e = $k->get('evidence');
            $ref = $e instanceof Obj ? $e->get('ref') : null;
            if (!is_string($ref)) {
                return "check '$id' has no evidence link";
            }
            if ($e->get('kind') === 'sha256') {
                if (preg_match('/\A[0-9a-f]{64}\z/', $ref) !== 1) {
                    return "check '$id' evidence digest is not 64 lowercase hex";
                }
            } elseif ($e->get('kind') === 'url') {
                if (Js::len($ref) > self::MAX_EVIDENCE_URL || !self::plainHttps($ref)) {
                    return "check '$id' evidence URL must be a plain https URL";
                }
            } else {
                return "check '$id' has an invalid evidence kind";
            }
        }
        return null;
    }

    /** The bound `bMax / kappa` of `{bMax, kappa}`: 0 when kappa is not above 0, as the reference computes it for every double. */
    public static function safetyCertificateBound(mixed $p): float
    {
        $kappa = self::d(Js::opt($p, 'kappa'));
        if ($kappa === null || !($kappa > 0)) {
            return 0.0;
        }
        $bMax = self::d(Js::opt($p, 'bMax'));
        return fdiv($bMax === null || is_nan($bMax) ? NAN : max(0.0, $bMax), $kappa);
    }

    /** The fixed human statement of a bound. */
    public static function safetyCertificateStatement(mixed $bound): string
    {
        $b = self::d($bound);
        return 'Arithmetic consequence of the signed risk parameters: between two consecutive human co-signs, the total risk of autonomous actions Σ r(Aᵢ) ≤ '
            . ($b === null ? IntentWb::jsStr($bound) : IntentWb::jsNumStr($b)) . ' (= B_max / κ). This is not a claim that the agent or the system is safe.';
    }

    /** The signed bytes: the domain, then the canonical JSON of the certificate without `sig` and `pq_sig`. Throws on a value that has no canonical form. */
    public static function safetyCertificateMessage(mixed $certOrClaim): string
    {
        if (!($certOrClaim instanceof Obj)) {
            throw new \InvalidArgumentException('safetyCertificateMessage: not a certificate');
        }
        return self::SAFETY_CERT_DOMAIN . Json::canonicalizeLenient($certOrClaim->without('sig', 'pq_sig'));
    }

    /**
     * Issue a certificate for `$policy` (the grant's risk policy), signed by the guardian. `$issuedAt` is epoch milliseconds (null:
     * the clock); `$checks`, `$grantRef` and `$instance` are optional. `$alg` / `$pq` select a post-quantum or hybrid suite. Throws
     * on a malformed policy, malformed checks or an unknown suite.
     */
    public static function issueSafetyCertificate(mixed $policy, KeyPair $guardian, mixed $issuedAt = null, mixed $checks = self::UNSET, mixed $grantRef = self::UNSET,
                                                  mixed $instance = self::UNSET, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        $bad = Sign::riskPolicyError(self::plain($policy));
        if ($bad !== null) {
            throw new \InvalidArgumentException("issueSafetyCertificate: $bad");
        }
        if (Pq::resolveSigAlg($alg) === null) {
            throw new \InvalidArgumentException("issueSafetyCertificate: unknown signature alg '$alg'");
        }
        if ($checks !== self::UNSET && ($badChecks = self::validateSafetyChecks($checks)) !== null) {
            throw new \InvalidArgumentException("issueSafetyCertificate: $badChecks");
        }
        $bound = Sign::n(self::safetyCertificateBound($policy)); // a bound that is not finite has no canonical form: refused here
        $claim = Obj::of(['v' => new Num('1'), 'statement' => self::safetyCertificateStatement($bound), 'scope' => self::SAFETY_CERT_SCOPE]);
        if ($checks !== self::UNSET) {
            $claim->set('checks', array_map(static fn(Obj $c): Obj => Obj::of(['id' => $c->get('id'), 'status' => $c->get('status'),
                'evidence' => Obj::of(['kind' => $c->get('evidence')->get('kind'), 'ref' => $c->get('evidence')->get('ref')]), 'at' => $c->get('at')]), $checks));
        }
        $params = new Obj();
        foreach (['bMax', 'kappa', 'theta1', 'theta2', 'lambda', 'rho'] as $k) {
            $params->set($k, $policy->get($k));
        }
        $params->set('weights', $policy->get('weights')->without());
        $claim->set('params', $params);
        $claim->set('bound', $bound);
        $claim->set('blastRadiusPerCheckpoint', $bound);
        if ($grantRef !== self::UNSET) {
            $claim->set('grant_ref', $grantRef);
        }
        if ($instance !== self::UNSET) {
            $claim->set('instance', $instance);
        }
        $claim->set('issued_at', $issuedAt ?? new Num((string)(int)floor(self::clock() * 1000)));
        $claim->set('guardian', $guardian->public);
        if ($alg !== null && $alg !== 'ed25519') {
            $claim->set('alg', $alg);
            if (($pk = Pq::suitePqPublicKey($alg, $pq)) !== null) {
                $claim->set('pq_pk', $pk);
            }
        }
        foreach (Pq::signSuiteArtifact($alg, $guardian, $pq, self::safetyCertificateMessage($claim)) as $k => $v) {
            $claim->set($k, $v);
        }
        return $claim;
    }

    /**
     * Verify a certificate. `$opts` (an Obj or an array) may carry `guardian` (the pinned key), `requireChecks` (ids that must be
     * present and passed), `maxAgeMs` with `now`, and `pqPins` (guardian => PQ public key). Never throws; the reasons are the reference's.
     *
     * @return array{ok: bool, reason?: string, recomputedBound?: float}
     */
    public static function verifySafetyCertificate(mixed $cert, mixed $opts = null): array
    {
        try {
            $v = $cert instanceof Obj ? self::d($cert->get('v')) : null;
            if ($v !== 1.0) {
                return ['ok' => false, 'reason' => 'malformed certificate'];
            }
            if (!is_string($cert->get('sig')) || !is_string($cert->get('guardian'))) {
                return ['ok' => false, 'reason' => 'missing guardian/signature'];
            }
            if ($cert->get('scope') !== self::SAFETY_CERT_SCOPE) {
                return ['ok' => false, 'reason' => 'unknown scope'];
            }
            if ($cert->has('checks') && ($badChecks = self::validateSafetyChecks($cert->get('checks'))) !== null) {
                return ['ok' => false, 'reason' => "invalid checks: $badChecks"];
            }
            $params = $cert->get('params');
            $bad = Sign::riskPolicyError($params instanceof Obj ? self::plain($params) : []);
            if ($bad !== null) {
                return ['ok' => false, 'reason' => "invalid parameters: $bad"];
            }
            $recomputed = self::safetyCertificateBound($params);
            $no = static fn(string $reason): array => ['ok' => false, 'reason' => $reason, 'recomputedBound' => $recomputed];
            if (self::fin($cert->get('bound')) !== $recomputed) {
                return $no('stated bound does not equal B_max/κ recomputed from the parameters');
            }
            if (self::d($cert->get('blastRadiusPerCheckpoint')) !== $recomputed) {
                return $no('blastRadiusPerCheckpoint does not equal the recomputed bound');
            }
            $guardian = $cert->get('guardian');
            if (Js::has($opts, 'guardian') && Js::opt($opts, 'guardian') !== $guardian) {
                return $no('guardian key is not the pinned key');
            }
            $alg = $cert->has('alg') ? $cert->get('alg') : null;
            if ($cert->has('alg') && !Pq::isKnownSigAlg($alg)) {
                return $no('unknown signature alg');
            }
            $pin = Js::opt(Js::opt($opts, 'pqPins'), $guardian);
            if (Pca::verifyPinnedSuite($alg, $guardian, $cert->get('pq_pk'), self::safetyCertificateMessage($cert), $cert->get('sig'), $cert->get('pq_sig'), is_string($pin) ? $pin : null) !== true) {
                return $no('guardian signature does not verify');
            }
            if (Js::has($opts, 'maxAgeMs')) {
                $max = self::fin(Js::opt($opts, 'maxAgeMs'));
                $now = Js::opt($opts, 'now') === null ? floor(self::clock() * 1000) : self::fin(Js::opt($opts, 'now'));
                $issued = self::fin($cert->get('issued_at'));
                if ($max === null || $now === null || $issued === null) {
                    return $no('invalid age policy or issue time');
                }
                if ($issued > $now) {
                    return $no('certificate is issued in the future');
                }
                if ($now - $issued > $max) {
                    return $no('certificate is older than maxAgeMs');
                }
            }
            $required = Js::opt($opts, 'requireChecks') ?? [];
            if (!is_array($required) || !array_is_list($required)) {
                throw new \InvalidArgumentException('requireChecks is not a list');
            }
            foreach ($required as $id) {
                $row = null;
                foreach ($cert->has('checks') ? $cert->get('checks') : [] as $c) {
                    $row ??= is_string($id) && $c->get('id') === $id ? $c : null;
                }
                if ($row === null) {
                    return $no("required check '" . IntentWb::jsStr($id) . "' is not present");
                }
                if ($row->get('status') !== 'passed') {
                    return $no("required check '$id' is " . $row->get('status'));
                }
            }
            return ['ok' => true, 'recomputedBound' => $recomputed];
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'malformed certificate: ' . $e->getMessage()];
        }
    }

    /** The canonical JSON text of a certificate. */
    public static function encodeSafetyCertificate(mixed $cert): string
    {
        return Json::canonicalizeLenient($cert);
    }

    /** A certificate from JSON text, or null: only the shape is checked here ({@see verifySafetyCertificate} judges it). */
    public static function decodeSafetyCertificate(mixed $text): ?Obj
    {
        try {
            if (!is_string($text) || strlen($text) > self::MAX_JSON_BYTES) {
                return null;
            }
            $v = Js::parse($text);
            if (!($v instanceof Obj) || self::d($v->get('v')) !== 1.0 || !is_string($v->get('sig')) || !is_string($v->get('guardian'))) {
                return null;
            }
            return $v->get('params') instanceof Obj || is_array($v->get('params')) ? $v : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The evidence row a compliance report carries for a VERIFIED certificate (`$opts` as for {@see verifySafetyCertificate}), or null.
     *
     * @return array{control: string, guardian: string, issued_at: mixed, bound: mixed, checks: list<array{id: string, status: string, evidence: string}>}|null
     */
    public static function safetyCertificateForCompliance(mixed $cert, mixed $opts = null): ?array
    {
        if (!self::verifySafetyCertificate($cert, $opts)['ok']) {
            return null;
        }
        $rows = [];
        foreach ($cert->has('checks') ? $cert->get('checks') : [] as $c) {
            $e = $c->get('evidence');
            $rows[] = ['id' => $c->get('id'), 'status' => $c->get('status'), 'evidence' => $e->get('kind') === 'sha256' ? 'sha256:' . $e->get('ref') : $e->get('ref')];
        }
        return ['control' => self::SAFETY_CERT_SCOPE, 'guardian' => $cert->get('guardian'), 'issued_at' => $cert->get('issued_at'), 'bound' => $cert->get('bound'), 'checks' => $rows];
    }

    // ---- short names ------------------------------------------------------------------------------------------------

    /** {@see issueSafetyCertificate} */
    public static function issue(mixed $policy, KeyPair $guardian, mixed $issuedAt = null, mixed $checks = self::UNSET, mixed $grantRef = self::UNSET,
                                 mixed $instance = self::UNSET, ?string $alg = null, ?PqKeyPair $pq = null): Obj
    {
        return self::issueSafetyCertificate($policy, $guardian, $issuedAt, $checks, $grantRef, $instance, $alg, $pq);
    }

    /** {@see verifySafetyCertificate} @return array{ok: bool, reason?: string, recomputedBound?: float} */
    public static function verify(mixed $cert, mixed $opts = null): array
    {
        return self::verifySafetyCertificate($cert, $opts);
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
