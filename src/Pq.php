<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/OpensslPq.php';
require_once __DIR__ . '/Fndsa.php';
require_once __DIR__ . '/FndsaNative.php';
require_once __DIR__ . '/LessFfi.php';

/**
 * The public post-quantum signature surface of the TypeScript reference (packages/pca/src/pq.ts): size constants, the closed suite
 * registry, keygen / sign / verify per primitive (raw and base64url), public-key encoders, suite sign / verify, the LAMPS composite
 * and the PQ key checks. Everything delegates to the primitives the package already carries (OpenSSL >= 3.5 libcrypto over FFI for
 * ML-DSA / SLH-DSA, libfndsa, libatlas_less, libsodium), so there is no new cryptography here.
 *
 * Deviations from the reference, all structural:
 *  - ML-DSA and SLH-DSA keys live inside the libcrypto key handle, so `*Keygen` returns a {@see PqKeyPair} (public key: `->public`,
 *    base64url) and `*Sign` takes that pair, not raw secret-key bytes; the secret never leaves libcrypto. FN-DSA and LESS keep raw
 *    bytes: keygen returns `['verifyingKey'|'publicKey', 'signingKey'|'secretKey']` strings.
 *  - Byte strings are PHP strings; `unknown` inputs are `mixed`; an absent `alg` is `null`.
 *  - There is no WASM backend: `isFnDsaBackendActive` is {@see Fndsa::hasBackend}; the LESS probe is {@see LessFfi::status}.
 */
final class Pq
{
    public const ED25519_SIGNATURE_BYTES = 64;
    public const DEFAULT_SIG_ALG = 'ed25519';

    public const ML_DSA_65_PUBLIC_KEY_BYTES = 1952;
    public const ML_DSA_65_SIGNATURE_BYTES = 3309;
    public const ML_DSA_65_SEED_BYTES = 32;
    public const ML_DSA_87_PUBLIC_KEY_BYTES = 2592;
    public const ML_DSA_87_SIGNATURE_BYTES = 4627;
    public const ML_DSA_87_SEED_BYTES = 32;
    public const SLH_DSA_SHA2_128F_PUBLIC_KEY_BYTES = 32;
    public const SLH_DSA_SHA2_128F_SECRET_KEY_BYTES = 64;
    public const SLH_DSA_SHA2_128F_SIGNATURE_BYTES = 17088;
    public const SLH_DSA_SHA2_128F_SEED_BYTES = 48;
    public const SLH_DSA_SHA2_256S_PUBLIC_KEY_BYTES = 64;
    public const SLH_DSA_SHA2_256S_SECRET_KEY_BYTES = 128;
    public const SLH_DSA_SHA2_256S_SIGNATURE_BYTES = 29792;
    public const SLH_DSA_SHA2_256S_SEED_BYTES = 96;
    public const FN_DSA_512_PUBLIC_KEY_BYTES = 897;
    public const FN_DSA_512_SECRET_KEY_BYTES = 1345;
    public const FN_DSA_512_SIGNATURE_BYTES = 666;
    public const FN_DSA_1024_PUBLIC_KEY_BYTES = 1793;
    public const FN_DSA_1024_SECRET_KEY_BYTES = 2369;
    public const FN_DSA_1024_SIGNATURE_BYTES = 1280;
    public const FN_DSA_SEED_BYTES = 32;
    public const LESS_CAT1_PUBLIC_KEY_BYTES = 97484;
    public const LESS_CAT1_SECRET_KEY_BYTES = 32;
    public const LESS_CAT1_SIGNATURE_MAX_BYTES = 1329;
    public const LESS_CAT1_SIGNATURE_MIN_BYTES = 1153;
    public const LESS_CAT1_SIGNATURE_STEP_BYTES = 16;
    public const LESS_SEED_BYTES = 32;

    /** The composite-signature Prefix (draft-ietf-lamps-pq-composite-sigs). */
    public const COMPOSITE_PREFIX = 'CompositeAlgorithmSignatures2025';
    /** The registered Label for id-MLDSA65-Ed25519-SHA512. */
    public const COMPOSITE_LABEL = 'COMPSIG-MLDSA65-Ed25519-SHA512';
    /** ML-DSA-65 signature (3309) then Ed25519 signature (64). */
    public const COMPOSITE_SIGNATURE_BYTES = 3373;

    /**
     * The closed algorithm registry (SIG_SUITES), in registry order. Each entry: sigBytes, hasEd25519, needsPqPk, needsPqSig,
     * pqPkBytes, pqSigBytes, family (the PQ primitive, or null), varLen (LESS: min and step) and nested (SUF-CMA hybrid).
     * @var array<string,array<string,mixed>>
     */
    public const SIG_SUITES = [
        'ed25519' => ['sigBytes' => 64, 'hasEd25519' => true, 'needsPqPk' => false, 'needsPqSig' => false, 'pqPkBytes' => 0, 'pqSigBytes' => 0, 'family' => null],
        'ml-dsa-65' => ['sigBytes' => 3309, 'hasEd25519' => false, 'needsPqPk' => true, 'needsPqSig' => false, 'pqPkBytes' => 1952, 'pqSigBytes' => 0, 'family' => 'ML-DSA-65'],
        'hybrid-ed25519-ml-dsa-65' => ['sigBytes' => 64, 'hasEd25519' => true, 'needsPqPk' => true, 'needsPqSig' => true, 'pqPkBytes' => 1952, 'pqSigBytes' => 3309, 'family' => 'ML-DSA-65'],
        'hybrid-nested-ed25519-ml-dsa-65' => ['sigBytes' => 64, 'hasEd25519' => true, 'needsPqPk' => true, 'needsPqSig' => true, 'pqPkBytes' => 1952, 'pqSigBytes' => 3309, 'family' => 'ML-DSA-65', 'nested' => true],
        'slh-dsa-sha2-128f' => ['sigBytes' => 17088, 'hasEd25519' => false, 'needsPqPk' => true, 'needsPqSig' => false, 'pqPkBytes' => 32, 'pqSigBytes' => 0, 'family' => 'SLH-DSA-SHA2-128f'],
        'hybrid-ed25519-slh-dsa-sha2-128f' => ['sigBytes' => 64, 'hasEd25519' => true, 'needsPqPk' => true, 'needsPqSig' => true, 'pqPkBytes' => 32, 'pqSigBytes' => 17088, 'family' => 'SLH-DSA-SHA2-128f'],
        'ml-dsa-87' => ['sigBytes' => 4627, 'hasEd25519' => false, 'needsPqPk' => true, 'needsPqSig' => false, 'pqPkBytes' => 2592, 'pqSigBytes' => 0, 'family' => 'ML-DSA-87'],
        'hybrid-ed25519-ml-dsa-87' => ['sigBytes' => 64, 'hasEd25519' => true, 'needsPqPk' => true, 'needsPqSig' => true, 'pqPkBytes' => 2592, 'pqSigBytes' => 4627, 'family' => 'ML-DSA-87'],
        'slh-dsa-sha2-256s' => ['sigBytes' => 29792, 'hasEd25519' => false, 'needsPqPk' => true, 'needsPqSig' => false, 'pqPkBytes' => 64, 'pqSigBytes' => 0, 'family' => 'SLH-DSA-SHA2-256s'],
        'hybrid-ed25519-slh-dsa-sha2-256s' => ['sigBytes' => 64, 'hasEd25519' => true, 'needsPqPk' => true, 'needsPqSig' => true, 'pqPkBytes' => 64, 'pqSigBytes' => 29792, 'family' => 'SLH-DSA-SHA2-256s'],
        'fn-dsa-512' => ['sigBytes' => 666, 'hasEd25519' => false, 'needsPqPk' => true, 'needsPqSig' => false, 'pqPkBytes' => 897, 'pqSigBytes' => 0, 'family' => 'FN-DSA-512'],
        'less-cat1' => ['sigBytes' => 1329, 'hasEd25519' => false, 'needsPqPk' => true, 'needsPqSig' => false, 'pqPkBytes' => 97484, 'pqSigBytes' => 0, 'family' => 'LESS-cat1', 'varLen' => ['min' => 1153, 'step' => 16]],
        'hybrid-ed25519-less-cat1' => ['sigBytes' => 64, 'hasEd25519' => true, 'needsPqPk' => true, 'needsPqSig' => true, 'pqPkBytes' => 97484, 'pqSigBytes' => 1329, 'family' => 'LESS-cat1', 'varLen' => ['min' => 1153, 'step' => 16]],
        'fn-dsa-1024' => ['sigBytes' => 1280, 'hasEd25519' => false, 'needsPqPk' => true, 'needsPqSig' => false, 'pqPkBytes' => 1793, 'pqSigBytes' => 0, 'family' => 'FN-DSA-1024'],
    ];

    private const PQ_PUBLIC_KEY_LENGTHS = [1952, 32, 2592, 64, 897, 1793, 97484];

    public static function isKnownSigAlg(mixed $x): bool
    {
        return is_string($x) && isset(self::SIG_SUITES[$x]);
    }

    /** The suite descriptor for `$alg`: null (absent) is ed25519, a known name its suite, anything else null (fail closed). @return array<string,mixed>|null */
    public static function resolveSigAlg(mixed $alg): ?array
    {
        if ($alg === null) {
            return self::SIG_SUITES[self::DEFAULT_SIG_ALG] + ['alg' => self::DEFAULT_SIG_ALG];
        }
        return self::isKnownSigAlg($alg) ? self::SIG_SUITES[$alg] + ['alg' => $alg] : null;
    }

    // ---- ML-DSA / SLH-DSA (libcrypto) ----------------------------------------------------------

    private static function seeded(string $family, string $seed, string $name): PqKeyPair
    {
        $want = OpensslPq::SEED_BYTES[$family];
        if (strlen($seed) !== $want) {
            throw new \RangeException("$name: seed must be $want bytes");
        }
        return new PqKeyPair($family, $seed);
    }

    private static function signWith(string $family, mixed $key, string $msg, string $name): string
    {
        if (!($key instanceof PqKeyPair) || $key->family !== $family) {
            throw new \InvalidArgumentException("$name needs a $family key pair");
        }
        return $key->sign($msg);
    }

    private static function verifyRaw(string $family, mixed $pk, string $msg, mixed $sig): bool
    {
        return is_string($pk) && is_string($sig) && OpensslPq::verify($family, $pk, $msg, $sig);
    }

    private static function verifyB64u(string $family, mixed $pk, string $msg, mixed $sig): bool
    {
        [$pkLen, $sigLen] = OpensslPq::KEY_TYPES[$family];
        $p = Pca::unb64u($pk, $pkLen);
        $s = Pca::unb64u($sig, $sigLen);
        return $p !== null && $s !== null && OpensslPq::verify($family, $p, $msg, $s);
    }

    public static function mlDsa65Keygen(string $seed): PqKeyPair
    {
        return self::seeded('ML-DSA-65', $seed, 'mlDsa65Keygen');
    }

    public static function mlDsa65Sign(mixed $keyPair, string $msg): string
    {
        return self::signWith('ML-DSA-65', $keyPair, $msg, 'mlDsa65Sign');
    }

    public static function mlDsa65Verify(mixed $publicKey, string $msg, mixed $sig): bool
    {
        return self::verifyRaw('ML-DSA-65', $publicKey, $msg, $sig);
    }

    public static function mlDsa65VerifyB64u(mixed $publicKeyB64u, string $msg, mixed $sigB64u): bool
    {
        return self::verifyB64u('ML-DSA-65', $publicKeyB64u, $msg, $sigB64u);
    }

    public static function encodeMlDsaPublicKey(string $publicKey): string
    {
        return Pca::b64u($publicKey);
    }

    public static function mlDsa87Keygen(string $seed): PqKeyPair
    {
        return self::seeded('ML-DSA-87', $seed, 'mlDsa87Keygen');
    }

    public static function mlDsa87Sign(mixed $keyPair, string $msg): string
    {
        return self::signWith('ML-DSA-87', $keyPair, $msg, 'mlDsa87Sign');
    }

    public static function mlDsa87Verify(mixed $publicKey, string $msg, mixed $sig): bool
    {
        return self::verifyRaw('ML-DSA-87', $publicKey, $msg, $sig);
    }

    public static function mlDsa87VerifyB64u(mixed $publicKeyB64u, string $msg, mixed $sigB64u): bool
    {
        return self::verifyB64u('ML-DSA-87', $publicKeyB64u, $msg, $sigB64u);
    }

    public static function encodeMlDsa87PublicKey(string $publicKey): string
    {
        return Pca::b64u($publicKey);
    }

    public static function slhDsa128fKeygen(string $seed): PqKeyPair
    {
        return self::seeded('SLH-DSA-SHA2-128f', $seed, 'slhDsa128fKeygen');
    }

    public static function slhDsa128fSign(mixed $keyPair, string $msg): string
    {
        return self::signWith('SLH-DSA-SHA2-128f', $keyPair, $msg, 'slhDsa128fSign');
    }

    public static function slhDsa128fVerify(mixed $publicKey, string $msg, mixed $sig): bool
    {
        return self::verifyRaw('SLH-DSA-SHA2-128f', $publicKey, $msg, $sig);
    }

    public static function slhDsa128fVerifyB64u(mixed $publicKeyB64u, string $msg, mixed $sigB64u): bool
    {
        return self::verifyB64u('SLH-DSA-SHA2-128f', $publicKeyB64u, $msg, $sigB64u);
    }

    public static function encodeSlhDsaPublicKey(string $publicKey): string
    {
        return Pca::b64u($publicKey);
    }

    public static function slhDsa256sKeygen(string $seed): PqKeyPair
    {
        return self::seeded('SLH-DSA-SHA2-256s', $seed, 'slhDsa256sKeygen');
    }

    public static function slhDsa256sSign(mixed $keyPair, string $msg): string
    {
        return self::signWith('SLH-DSA-SHA2-256s', $keyPair, $msg, 'slhDsa256sSign');
    }

    public static function slhDsa256sVerify(mixed $publicKey, string $msg, mixed $sig): bool
    {
        return self::verifyRaw('SLH-DSA-SHA2-256s', $publicKey, $msg, $sig);
    }

    public static function slhDsa256sVerifyB64u(mixed $publicKeyB64u, string $msg, mixed $sigB64u): bool
    {
        return self::verifyB64u('SLH-DSA-SHA2-256s', $publicKeyB64u, $msg, $sigB64u);
    }

    public static function encodeSlhDsa256sPublicKey(string $publicKey): string
    {
        return Pca::b64u($publicKey);
    }

    // ---- FN-DSA (libfndsa through the registered backend) ---------------------------------------

    /** True once a FN-DSA backend is registered (the reference's wasm probe). */
    public static function isFnDsaBackendActive(): bool
    {
        return Fndsa::hasBackend();
    }

    /** @return array{verifyingKey:string,signingKey:string} */
    private static function fnKeygen(string $variant, string $seed, string $name): array
    {
        if (!Fndsa::hasBackend()) {
            throw new \RuntimeException("$name: FN-DSA backend unavailable");
        }
        if (strlen($seed) !== self::FN_DSA_SEED_BYTES) {
            throw new \RangeException("$name: seed must be " . self::FN_DSA_SEED_BYTES . ' bytes');
        }
        [$sk, $vk] = FndsaNative::keygen($variant, $seed);
        return ['verifyingKey' => $vk, 'signingKey' => $sk];
    }

    private static function fnSign(string $variant, string $sk, string $msg, string $seed, string $name): string
    {
        if (!Fndsa::hasBackend()) {
            throw new \RuntimeException("$name: FN-DSA backend unavailable");
        }
        return Fndsa::signSeeded($variant, $sk, $msg, $seed);
    }

    private static function fnVerifyB64u(string $variant, mixed $pk, string $msg, mixed $sig): bool
    {
        $p = Pca::unb64u($pk, $variant === 'fn-dsa-512' ? self::FN_DSA_512_PUBLIC_KEY_BYTES : self::FN_DSA_1024_PUBLIC_KEY_BYTES);
        $s = Pca::unb64u($sig, $variant === 'fn-dsa-512' ? self::FN_DSA_512_SIGNATURE_BYTES : self::FN_DSA_1024_SIGNATURE_BYTES);
        return $p !== null && $s !== null && self::fnVerify($variant, $p, $msg, $s);
    }

    private static function fnVerify(string $variant, mixed $pk, string $msg, mixed $sig): bool
    {
        try {
            return is_string($pk) && is_string($sig) && Fndsa::verify($variant, $pk, $msg, $sig);
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return array{verifyingKey:string,signingKey:string} */
    public static function fnDsa512Keygen(string $seed): array
    {
        return self::fnKeygen('fn-dsa-512', $seed, 'fnDsa512Keygen');
    }

    /** @return array{verifyingKey:string,signingKey:string} */
    public static function fnDsa1024Keygen(string $seed): array
    {
        return self::fnKeygen('fn-dsa-1024', $seed, 'fnDsa1024Keygen');
    }

    public static function fnDsa512Sign(string $signingKey, string $msg, string $seed): string
    {
        return self::fnSign('fn-dsa-512', $signingKey, $msg, $seed, 'fnDsa512Sign');
    }

    public static function fnDsa1024Sign(string $signingKey, string $msg, string $seed): string
    {
        return self::fnSign('fn-dsa-1024', $signingKey, $msg, $seed, 'fnDsa1024Sign');
    }

    public static function fnDsa512Verify(mixed $publicKey, string $msg, mixed $sig): bool
    {
        return self::fnVerify('fn-dsa-512', $publicKey, $msg, $sig);
    }

    public static function fnDsa1024Verify(mixed $publicKey, string $msg, mixed $sig): bool
    {
        return self::fnVerify('fn-dsa-1024', $publicKey, $msg, $sig);
    }

    public static function fnDsa512VerifyB64u(mixed $publicKeyB64u, string $msg, mixed $sigB64u): bool
    {
        return self::fnVerifyB64u('fn-dsa-512', $publicKeyB64u, $msg, $sigB64u);
    }

    public static function fnDsa1024VerifyB64u(mixed $publicKeyB64u, string $msg, mixed $sigB64u): bool
    {
        return self::fnVerifyB64u('fn-dsa-1024', $publicKeyB64u, $msg, $sigB64u);
    }

    public static function encodeFnDsaPublicKey(string $publicKey): string
    {
        return Pca::b64u($publicKey);
    }

    // ---- LESS (libatlas_less) -------------------------------------------------------------------

    public static function isLessBackendActive(): bool
    {
        return LessFfi::available();
    }

    /** @return array{available:bool,reason?:string} */
    public static function lessBackendStatus(): array
    {
        return LessFfi::status();
    }

    /** @return array{publicKey:string,secretKey:string} */
    public static function lessCat1Keygen(string $seed): array
    {
        return LessFfi::keygen($seed);
    }

    public static function lessCat1Sign(string $secretKey, string $msg, string $seed): string
    {
        return LessFfi::sign($secretKey, $msg, $seed);
    }

    public static function lessCat1Verify(mixed $publicKey, string $msg, mixed $sig): bool
    {
        return is_string($publicKey) && is_string($sig) && LessFfi::verify($publicKey, $msg, $sig);
    }

    public static function lessCat1VerifyB64u(mixed $publicKeyB64u, string $msg, mixed $sigB64u): bool
    {
        $p = Pca::unb64u($publicKeyB64u, self::LESS_CAT1_PUBLIC_KEY_BYTES);
        $s = Pca::unb64u($sigB64u);
        return $p !== null && $s !== null && LessFfi::sigLenOk(strlen($s)) && LessFfi::verify($p, $msg, $s);
    }

    public static function encodeLessPublicKey(string $publicKey): string
    {
        return Pca::b64u($publicKey);
    }

    // ---- suite dispatch -------------------------------------------------------------------------

    /**
     * The b64u PQ public key (`pq_pk`) a suite carries, from the signer's PQ key pair; null for ed25519, an unknown alg, or a pair of
     * the wrong family (signing then throws, fail closed).
     */
    public static function suitePqPublicKey(mixed $alg, ?PqKeyPair $pq): ?string
    {
        $suite = self::resolveSigAlg($alg);
        if ($suite === null || !$suite['needsPqPk'] || $pq === null || $pq->family !== $suite['family']) {
            return null;
        }
        return $pq->public;
    }

    /**
     * Sign `$msg` and return every wire field an artifact carries for the suite (signSuiteArtifact): only `sig` for ed25519, else also
     * `alg`, `pq_pk` and (hybrid) `pq_sig`. Throws on an unknown alg or missing key material (Sign::signWithSuite).
     * @return array<string,string>
     */
    public static function signSuiteArtifact(mixed $alg, ?KeyPair $ed, ?PqKeyPair $pq, string $msg): array
    {
        $suite = self::resolveSigAlg($alg);
        if ($suite === null) {
            throw new \RangeException("signSuiteArtifact: unknown signature alg '" . (is_string($alg) ? $alg : gettype($alg)) . "'");
        }
        $parts = Sign::signWithSuite($suite['alg'], $ed, $pq, $msg);
        if ($suite['alg'] === 'ed25519') {
            return ['sig' => $parts['sig']];
        }
        $out = ['sig' => $parts['sig'], 'alg' => $suite['alg']];
        $pk = self::suitePqPublicKey($suite['alg'], $pq);
        if ($pk !== null) {
            $out['pq_pk'] = $pk;
        }
        if (isset($parts['pq_sig'])) {
            $out['pq_sig'] = $parts['pq_sig'];
        }
        return $out;
    }

    /** Sign under a suite (the reference's signWithSuite; {@see Sign::signWithSuite}). @return array{sig:string,pq_sig?:string} */
    public static function signWithSuite(mixed $alg, ?KeyPair $ed, ?PqKeyPair $pq, string $msg): array
    {
        return Sign::signWithSuite($alg === null ? null : (string)$alg, $ed, $pq, $msg);
    }

    /**
     * Verify a suite signature ({@see Pca::verifyWithSuite}). `$keys`: edPub (b64u) and pq (a pinned key from {@see Pca::resolvePqVerifyKey}).
     * @param array{edPub?:mixed,pq?:mixed} $keys
     * @param array{sig?:mixed,pq_sig?:mixed} $s
     */
    public static function verifyWithSuite(mixed $alg, array $keys, string $msg, array $s): bool
    {
        return Pca::verifyWithSuite($alg, $keys, $msg, $s);
    }

    /** True when `$key` is an opaque pinned PQ key minted by {@see Pca::resolvePqVerifyKey}. */
    public static function isPinnedPqKey(mixed $key): bool
    {
        return $key instanceof PinnedPq;
    }

    /** True when `$pq` is canonical base64url of a byte string with the public-key length of a registered PQ suite. */
    public static function isWellFormedPqPublicKey(mixed $pq): bool
    {
        if (!is_string($pq)) {
            return false;
        }
        $b = Pca::unb64u($pq);
        return $b !== null && in_array(strlen($b), self::PQ_PUBLIC_KEY_LENGTHS, true);
    }

    // ---- LAMPS composite (ML-DSA-65 + Ed25519) --------------------------------------------------

    /** M' = Prefix || Label || len(ctx) || ctx || SHA-512(message). Throws RangeException if `$ctx` exceeds 255 bytes. */
    public static function compositeRepresentative(string $message, string $ctx = ''): string
    {
        if (strlen($ctx) > 255) {
            throw new \RangeException('compositeRepresentative: ctx exceeds 255 bytes');
        }
        return self::COMPOSITE_PREFIX . self::COMPOSITE_LABEL . chr(strlen($ctx)) . $ctx . hash('sha512', $message, true);
    }

    /** `mldsaSig || tradSig` over M'. */
    public static function compositeSign(KeyPair $ed, PqKeyPair $mlDsa, string $message, string $ctx = ''): string
    {
        $m = self::compositeRepresentative($message, $ctx);
        return self::signWith('ML-DSA-65', $mlDsa, $m, 'compositeSign') . $ed->sign($m);
    }

    /** Both halves over M' must verify; a wrong length or a ctx over 255 bytes is false. Never throws. */
    public static function compositeVerify(mixed $ed25519Pub, mixed $mlDsaPub, string $message, mixed $signature, string $ctx = ''): bool
    {
        try {
            if (!is_string($ed25519Pub) || !is_string($mlDsaPub) || !is_string($signature) || strlen($signature) !== self::COMPOSITE_SIGNATURE_BYTES) {
                return false;
            }
            $m = self::compositeRepresentative($message, $ctx);
            $mldsaOk = self::mlDsa65Verify($mlDsaPub, $m, substr($signature, 0, self::ML_DSA_65_SIGNATURE_BYTES));
            $tradOk = Pca::verifyEd25519B64u(Pca::b64u($ed25519Pub), $m, Pca::b64u(substr($signature, self::ML_DSA_65_SIGNATURE_BYTES)));
            return $mldsaOk && $tradOk;
        } catch (\Throwable) {
            return false;
        }
    }
}
