<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * B4 post-quantum primitive: ML-DSA-65 (FIPS-204, CRYSTALS-Dilithium category 3) signature verification.
 *
 * Mirrors `mlDsa65Verify` in packages/pca/src/pq.ts (which uses @noble/post-quantum's ml_dsa65): raw public key 1952
 * bytes, signature 3309 bytes, pure mode, empty context, through OpenSSL >= 3.5 libcrypto ({@see OpensslPq}, which also
 * serves ML-DSA-87 and SLH-DSA). Never throws; a wrong length / unavailable library / malformed input returns false. If
 * no usable libcrypto is found, {@see available()} is false and verification returns false (fail-closed).
 */
final class Mldsa
{
    public const PUBLIC_KEY_BYTES = 1952;
    public const SIGNATURE_BYTES = 3309;

    /**
     * Candidate libcrypto paths ({@see OpensslPq::candidates()}).
     * @internal public for tests only
     * @return list<string>
     */
    public static function candidates(): array
    {
        return OpensslPq::candidates();
    }

    public static function available(): bool
    {
        return OpensslPq::available('ML-DSA-65');
    }

    public static function verify(string $pk, string $msg, string $sig): bool
    {
        return OpensslPq::verify('ML-DSA-65', $pk, $msg, $sig);
    }
}
