<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/K3Sig.php';

/**
 * Runtime-class claims (verification side): a statement signed by a pinned attestor that an agent's sandbox runs at a class.
 * Valid only for this passport, inside its validity window, over evidence the caller has already verified (its digest is in
 * `$verifiedEvidence`), signed over domain || canonical(claim without sig), with no member beyond the eight. Anything else is
 * 'none'. Total.
 */
final class RuntimeClaim
{
    public const DOMAIN = "atlas-pca/runtime-class-claim/v1\0";
    private const CLASSES = ['none', 'os_confined', 'egress_default_deny', 'wasi_no_ambient'];
    private const KEYS = ['v', 'class', 'passport_digest', 'evidence_digest', 'iat', 'exp', 'attestor', 'sig'];

    /**
     * @param list<string> $pinnedAttestors
     * @param list<string> $verifiedEvidence
     */
    public static function verifiedClass(mixed $c, array $pinnedAttestors, string $passportDigest, array $verifiedEvidence, mixed $now): string
    {
        try {
            if (!($c instanceof Obj)) {
                return 'none';
            }
            $keys = $c->keys();
            if (count($keys) !== count(self::KEYS) || array_diff($keys, self::KEYS) !== [] || !K3Sig::isNumber($c->get('v'), 1.0)) {
                return 'none';
            }
            if (!in_array($c->get('class'), self::CLASSES, true)) {
                return 'none';
            }
            foreach (['attestor', 'passport_digest', 'evidence_digest'] as $k) {
                if (!K3Sig::isStr($c->get($k), 128)) {
                    return 'none';
                }
            }
            if (!K3Sig::isSafeInt($c->get('iat')) || !K3Sig::isSafeInt($c->get('exp')) || !K3Sig::isSafeInt($now)) {
                return 'none';
            }
            $t = K3Sig::num($now);
            if (!in_array($c->get('attestor'), $pinnedAttestors, true) || $c->get('passport_digest') !== $passportDigest
                || !in_array($c->get('evidence_digest'), $verifiedEvidence, true)
                || !(K3Sig::num($c->get('iat')) <= $t && $t < K3Sig::num($c->get('exp')))) {
                return 'none';
            }
            return K3Sig::verifyBody(self::DOMAIN, $c->without('sig'), $c->get('attestor'), $c->get('sig')) ? (string)$c->get('class') : 'none';
        } catch (\Throwable) {
            return 'none';
        }
    }
}
