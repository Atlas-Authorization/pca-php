<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/MpcShake256.php';
require_once __DIR__ . '/OpensslMlKem.php';

/**
 * Key encapsulation: the hybrid X25519 + ML-KEM-768 KEM (custom HKDF combiner), the same at ML-KEM-1024 (own domain separator),
 * and X-Wing (draft-connolly-cfrg-xwing-kem-09, SHA3-256 combiner), plus the FIPS 203 section 7.2 / 7.3 checks for imported ML-KEM
 * keys. Each KEM establishes a 32-byte shared secret; no cipher is shipped (use the secret as the key of an AEAD you already trust).
 *
 * Primitives are never re-implemented: ML-KEM runs on OpenSSL >= 3.5 libcrypto through ext-ffi ({@see OpensslMlKem}), X25519 on
 * ext-sodium (a low-order peer point is refused), HKDF-SHA256 and SHA3-256 on ext-hash, SHAKE256 on libcrypto ({@see MpcShake256}).
 * Every input is length-checked and every failure throws (fail closed): \InvalidArgumentException for a malformed input,
 * \RuntimeException when a primitive refuses (a low-order X25519 point, no libcrypto).
 *
 * Layouts: hybrid public key = X25519 pub (32) || ML-KEM ek; ciphertext = ephemeral X25519 pub (32) || ML-KEM ct; secret key =
 * X25519 secret (32) || expanded ML-KEM decapsulation key. X-Wing: public key = ML-KEM-768 ek (1184) || X25519 pub (32), ciphertext =
 * ML-KEM-768 ct (1088) || X25519 pub (32), secret key = the 32-byte seed.
 */
final class Kem
{
    public const HYBRID_PUBLIC_KEY_LEN = 1216;
    public const HYBRID_CIPHERTEXT_LEN = 1120;
    public const HYBRID_SHARED_SECRET_LEN = 32;
    public const HYBRID_KEM_SUITE = 'x25519-ml-kem-768';

    public const XWING_SUITE = 'xwing';
    public const XWING_SEED_LEN = 32;
    public const XWING_SECRET_KEY_LEN = 32;
    public const XWING_PUBLIC_KEY_LEN = 1216;
    public const XWING_CIPHERTEXT_LEN = 1120;
    public const XWING_SHARED_SECRET_LEN = 32;
    /** Derandomised X-Wing encapsulation seed: ML-KEM message m (32) || X25519 ephemeral secret (32). */
    public const XWING_ESEED_LEN = 64;
    /** The 6-byte X-Wing domain label, ASCII `\.//^\` (hex 5c2e2f2f5e5c). */
    public const XWING_LABEL = "\x5c\x2e\x2f\x2f\x5e\x5c";

    public const HYBRID1024_PUBLIC_KEY_LEN = 1600;
    public const HYBRID1024_CIPHERTEXT_LEN = 1600;
    public const HYBRID1024_SHARED_SECRET_LEN = 32;
    public const HYBRID1024_KEM_SUITE = 'x25519-ml-kem-1024';

    private const DOMAIN = ['768' => "atlas-pca/kem/x25519-ml-kem-768/v1\0", '1024' => "atlas-pca/kem/x25519-ml-kem-1024/v1\0"];

    // ---- primitives ------------------------------------------------------------------------------

    /** X25519 with the all-zero (low-order peer) result refused. */
    private static function x25519(string $secret, string $peer): string
    {
        if (strlen($secret) !== 32 || strlen($peer) !== 32) {
            throw new \InvalidArgumentException('X25519: keys must be 32 bytes');
        }
        try {
            $r = sodium_crypto_scalarmult($secret, $peer);
        } catch (\SodiumException) {
            throw new \RuntimeException('X25519: low-order public key refused');
        }
        if (hash_equals(str_repeat("\0", 32), $r)) {
            throw new \RuntimeException('X25519: low-order public key refused');
        }
        return $r;
    }

    private static function x25519Pub(string $secret): string
    {
        if (strlen($secret) !== 32) {
            throw new \InvalidArgumentException('X25519: secret must be 32 bytes');
        }
        return sodium_crypto_scalarmult_base($secret);
    }

    private static function combine(int $level, string $ssM, string $ssX, string $ephPub, string $recipX): string
    {
        return hash_hkdf('sha256', $ssM . $ssX . $ephPub . $recipX, 32, self::DOMAIN[(string) $level], '');
    }

    /** FIPS 203 section 7.2 modulus check: every 12-bit coefficient of the first 384*k bytes is below q = 3329. */
    private static function coefficientsReduced(string $ek, int $k): bool
    {
        for ($i = 0, $n = 384 * $k; $i < $n; $i += 3) {
            $b0 = ord($ek[$i]);
            $b1 = ord($ek[$i + 1]);
            $b2 = ord($ek[$i + 2]);
            if (($b0 | (($b1 & 0x0f) << 8)) >= 3329 || (($b1 >> 4) | ($b2 << 4)) >= 3329) {
                return false;
            }
        }
        return true;
    }

    private static function requireReducedEk(string $ek, int $k, string $who): void
    {
        if (!self::coefficientsReduced($ek, $k)) {
            throw new \InvalidArgumentException("$who: ML-KEM encapsulation key fails the FIPS 203 modulus check");
        }
    }

    private static function levelOf(int $level): int
    {
        if (!isset(OpensslMlKem::LEVELS[$level])) {
            throw new \InvalidArgumentException("ML-KEM level must be 768 or 1024, got $level");
        }
        return OpensslMlKem::LEVELS[$level][1];
    }

    // ---- hybrid X25519 + ML-KEM -------------------------------------------------------------------

    /** @return array{publicKey:string,secretKey:string} */
    private static function hybridKeygen(int $level, string $rng): array
    {
        if (strlen($rng) !== 96) {
            throw new \InvalidArgumentException('hybrid keygen: randomness must be 96 bytes (x25519 secret 32, ML-KEM seed d||z 64)');
        }
        $x = substr($rng, 0, 32);
        $ml = OpensslMlKem::keygen($level, substr($rng, 32));
        return ['publicKey' => self::x25519Pub($x) . $ml['publicKey'], 'secretKey' => $x . $ml['secretKey']];
    }

    /** @return array{ciphertext:string,sharedSecret:string} */
    private static function hybridEnc(int $level, string $pk, string $rng, string $who): array
    {
        [, $k, $ekLen] = OpensslMlKem::LEVELS[$level];
        if (strlen($pk) !== 32 + $ekLen) {
            throw new \InvalidArgumentException("$who: public key must be " . (32 + $ekLen) . ' bytes (got ' . strlen($pk) . ')');
        }
        if (strlen($rng) !== 64) {
            throw new \InvalidArgumentException("$who: randomness must be 64 bytes (ephemeral x25519 secret 32, ML-KEM message 32)");
        }
        $recipX = substr($pk, 0, 32);
        $ephPriv = substr($rng, 0, 32);
        $ephPub = self::x25519Pub($ephPriv);
        $ssX = self::x25519($ephPriv, $recipX);
        $ek = substr($pk, 32);
        self::requireReducedEk($ek, $k, $who);
        $e = OpensslMlKem::encapsulate($level, $ek, substr($rng, 32));
        return ['ciphertext' => $ephPub . $e['cipherText'], 'sharedSecret' => self::combine($level, $e['sharedSecret'], $ssX, $ephPub, $recipX)];
    }

    private static function hybridDec(int $level, string $ct, string $sk, string $who): string
    {
        [, , , $ctLen, $dkLen] = OpensslMlKem::LEVELS[$level];
        if (strlen($ct) !== 32 + $ctLen) {
            throw new \InvalidArgumentException("$who: ciphertext must be " . (32 + $ctLen) . ' bytes (got ' . strlen($ct) . ')');
        }
        if (strlen($sk) !== 32 + $dkLen) { // the reference refuses a short key itself and every other length through the ML-KEM layer
            throw new \InvalidArgumentException("$who: malformed secret key");
        }
        $ephPub = substr($ct, 0, 32);
        $xPriv = substr($sk, 0, 32);
        $ssX = self::x25519($xPriv, $ephPub);
        $ssM = OpensslMlKem::decapsulate($level, substr($ct, 32), substr($sk, 32));
        return self::combine($level, $ssM, $ssX, $ephPub, self::x25519Pub($xPriv));
    }

    /** Generate a hybrid X25519 + ML-KEM-768 recipient key pair (secret key 2432 bytes). @return array{publicKey:string,secretKey:string} */
    public static function hybridKemKeygen(): array
    {
        return self::hybridKeygen(768, random_bytes(96));
    }

    /**
     * Test seam (not part of the stable API): keygen from fixed randomness x25519 secret (32) || d (32) || z (32).
     * @internal
     * @return array{publicKey:string,secretKey:string}
     */
    public static function hybridKemKeygenDerand(string $rng): array
    {
        return self::hybridKeygen(768, $rng);
    }

    /** Encapsulate to a hybrid recipient public key: the ciphertext (send it) and the 32-byte shared secret (keep it). @return array{ciphertext:string,sharedSecret:string} */
    public static function hybridEncapsulate(string $recipientPublicKey): array
    {
        return self::hybridEnc(768, $recipientPublicKey, random_bytes(64), 'hybridEncapsulate');
    }

    /**
     * Test seam (not part of the stable API): fixed randomness ephemeral X25519 secret (32) || ML-KEM message m (32).
     * @internal
     * @return array{ciphertext:string,sharedSecret:string}
     */
    public static function hybridEncapsulateDerand(string $recipientPublicKey, string $rng): array
    {
        return self::hybridEnc(768, $recipientPublicKey, $rng, 'hybridEncapsulate');
    }

    /** Decapsulate with the recipient secret key: recovers the shared secret (a tampered ciphertext gives the implicit-rejection secret). */
    public static function hybridDecapsulate(string $ciphertext, string $secretKey): string
    {
        return self::hybridDec(768, $ciphertext, $secretKey, 'hybridDecapsulate');
    }

    /** Generate a hybrid X25519 + ML-KEM-1024 recipient key pair (secret key 3200 bytes). @return array{publicKey:string,secretKey:string} */
    public static function hybridKem1024Keygen(): array
    {
        return self::hybridKeygen(1024, random_bytes(96));
    }

    /**
     * Test seam (not part of the stable API), see {@see hybridKemKeygenDerand}.
     * @internal
     * @return array{publicKey:string,secretKey:string}
     */
    public static function hybridKem1024KeygenDerand(string $rng): array
    {
        return self::hybridKeygen(1024, $rng);
    }

    /** @return array{ciphertext:string,sharedSecret:string} */
    public static function hybridEncapsulate1024(string $recipientPublicKey): array
    {
        return self::hybridEnc(1024, $recipientPublicKey, random_bytes(64), 'hybridEncapsulate1024');
    }

    /**
     * Test seam (not part of the stable API), see {@see hybridEncapsulateDerand}.
     * @internal
     * @return array{ciphertext:string,sharedSecret:string}
     */
    public static function hybridEncapsulate1024Derand(string $recipientPublicKey, string $rng): array
    {
        return self::hybridEnc(1024, $recipientPublicKey, $rng, 'hybridEncapsulate1024');
    }

    public static function hybridDecapsulate1024(string $ciphertext, string $secretKey): string
    {
        return self::hybridDec(1024, $ciphertext, $secretKey, 'hybridDecapsulate1024');
    }

    public static function encodeHybridPublicKey(string $k): string
    {
        return Pca::b64u($k);
    }

    public static function decodeHybridPublicKey(string $s): string
    {
        return self::unb64u($s);
    }

    public static function encodeHybridCiphertext(string $c): string
    {
        return Pca::b64u($c);
    }

    public static function decodeHybridCiphertext(string $s): string
    {
        return self::unb64u($s);
    }

    /** Strict unpadded base64url (no padding, no whitespace, canonical trailing bits); the decoded length is not checked. */
    private static function unb64u(string $s): string
    {
        return Pca::unb64u($s) ?? throw new \InvalidArgumentException('invalid base64url');
    }

    // ---- X-Wing -----------------------------------------------------------------------------------

    /** @return array{mlkemSecret:string,mlkemPublic:string,xSecret:string,xPublic:string} draft-09 section 5.2: SHAKE256(seed, 96) = d || z || skX */
    private static function expandXWing(string $seed): array
    {
        if (strlen($seed) !== self::XWING_SEED_LEN) {
            throw new \InvalidArgumentException('expandXWingKey: seed must be ' . self::XWING_SEED_LEN . ' bytes (got ' . strlen($seed) . ')');
        }
        $x = MpcShake256::hash($seed, 96);
        $ml = OpensslMlKem::keygen(768, substr($x, 0, 64));
        $xSecret = substr($x, 64, 32);
        return ['mlkemSecret' => $ml['secretKey'], 'mlkemPublic' => $ml['publicKey'], 'xSecret' => $xSecret, 'xPublic' => self::x25519Pub($xSecret)];
    }

    /** draft-09 section 5.3: SHA3-256(ssM || ssX || ctX || pkX || label); ct_M is deliberately not part of it. */
    private static function xwingCombiner(string $ssM, string $ssX, string $ctX, string $pkX): string
    {
        return hash('sha3-256', $ssM . $ssX . $ctX . $pkX . self::XWING_LABEL, true);
    }

    /**
     * Generate an X-Wing key pair; the 32-byte seed is the secret key (drawn from the system CSPRNG unless `$seed` is given, for KATs).
     * @return array{secretKey:string,publicKey:string}
     */
    public static function xwingKeygen(?string $seed = null): array
    {
        $sk = $seed ?? random_bytes(self::XWING_SEED_LEN);
        $ex = self::expandXWing($sk);
        return ['secretKey' => $sk, 'publicKey' => $ex['mlkemPublic'] . $ex['xPublic']];
    }

    /**
     * Derandomised X-Wing encapsulation: `$eseed` (64 bytes) = ML-KEM message m (32) || X25519 ephemeral secret (32). For known-answer
     * vectors; production code uses {@see xwingEncapsulate}.
     * @return array{ciphertext:string,sharedSecret:string}
     */
    public static function xwingEncapsulateDerand(string $recipientPublicKey, string $eseed): array
    {
        if (strlen($recipientPublicKey) !== self::XWING_PUBLIC_KEY_LEN) {
            throw new \InvalidArgumentException('xwingEncapsulateDerand: public key must be ' . self::XWING_PUBLIC_KEY_LEN . ' bytes (got ' . strlen($recipientPublicKey) . ')');
        }
        if (strlen($eseed) !== self::XWING_ESEED_LEN) {
            throw new \InvalidArgumentException('xwingEncapsulateDerand: eseed must be ' . self::XWING_ESEED_LEN . ' bytes (got ' . strlen($eseed) . ')');
        }
        $pkM = substr($recipientPublicKey, 0, 1184);
        $pkX = substr($recipientPublicKey, 1184);
        $ekX = substr($eseed, 32, 32);
        self::requireReducedEk($pkM, 3, 'xwingEncapsulateDerand');
        $e = OpensslMlKem::encapsulate(768, $pkM, substr($eseed, 0, 32));
        $ctX = self::x25519Pub($ekX);
        $ssX = self::x25519($ekX, $pkX);
        return ['ciphertext' => $e['cipherText'] . $ctX, 'sharedSecret' => self::xwingCombiner($e['sharedSecret'], $ssX, $ctX, $pkX)];
    }

    /** Encapsulate to an X-Wing public key with fresh randomness. @return array{ciphertext:string,sharedSecret:string} */
    public static function xwingEncapsulate(string $recipientPublicKey): array
    {
        return self::xwingEncapsulateDerand($recipientPublicKey, random_bytes(self::XWING_ESEED_LEN));
    }

    /** Decapsulate an X-Wing ciphertext with the 32-byte seed secret key. */
    public static function xwingDecapsulate(string $ciphertext, string $secretKey): string
    {
        if (strlen($ciphertext) !== self::XWING_CIPHERTEXT_LEN) {
            throw new \InvalidArgumentException('xwingDecapsulate: ciphertext must be ' . self::XWING_CIPHERTEXT_LEN . ' bytes (got ' . strlen($ciphertext) . ')');
        }
        $ex = self::expandXWing($secretKey);
        $ctX = substr($ciphertext, 1088);
        $ssM = OpensslMlKem::decapsulate(768, substr($ciphertext, 0, 1088), $ex['mlkemSecret']);
        $ssX = self::x25519($ex['xSecret'], $ctX);
        return self::xwingCombiner($ssM, $ssX, $ctX, $ex['xPublic']);
    }

    public static function encodeXWingPublicKey(string $k): string
    {
        return Pca::b64u($k);
    }

    public static function decodeXWingPublicKey(string $s): string
    {
        return self::unb64u($s);
    }

    public static function encodeXWingCiphertext(string $c): string
    {
        return Pca::b64u($c);
    }

    public static function decodeXWingCiphertext(string $s): string
    {
        return self::unb64u($s);
    }

    // ---- FIPS 203 input checks for imported keys --------------------------------------------------

    /** FIPS 203 section 7.2 type and modulus check of an ML-KEM encapsulation key (level 768 or 1024); false for a wrong length or a non-reduced coefficient. Throws for an unknown level. */
    public static function mlKemEncapsulationKeyCheck(int $level, string $ek): bool
    {
        $k = self::levelOf($level);
        return strlen($ek) === 384 * $k + 32 && self::coefficientsReduced($ek, $k);
    }

    /** FIPS 203 section 7.3 check of an ML-KEM decapsulation key: length, embedded H(ek) and the embedded key's modulus check. Throws for an unknown level. */
    public static function mlKemDecapsulationKeyCheck(int $level, string $dk): bool
    {
        $k = self::levelOf($level);
        if (strlen($dk) !== 768 * $k + 96) {
            return false;
        }
        $ek = substr($dk, 384 * $k, 384 * $k + 32);
        return hash_equals(hash('sha3-256', $ek, true), substr($dk, 768 * $k + 32, 32)) && self::mlKemEncapsulationKeyCheck($level, $ek);
    }
}
