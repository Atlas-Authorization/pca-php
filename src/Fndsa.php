<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/FnDsaSuite.php';
require_once __DIR__ . '/FnDsaBackendMissing.php';

/**
 * FN-DSA (Falcon) suite registry, wire framing and the Ed25519+FN-DSA hybrid leaf composition (the TypeScript reference,
 * @atlasauth/pca-fndsa).
 *
 * Like the reference this class carries NO Falcon arithmetic: the primitive is a pluggable backend ({@see setFalconBackend}), so the
 * framing, lengths and hybrid fail-closed rules are testable without one, and verification refuses until a backend is installed.
 * Real primitive: {@see FndsaNative::backend()} is an ext-ffi backend over libfndsa (Thomas Pornin's fn-dsa 0.4.0 through a small C
 * library; set ATLAS_PCA_LIBFNDSA). FIPS 206 is not final, so this is a draft best guess pinned in lockstep with the TypeScript
 * reference, and it interoperates with that reference byte for byte. A round-3 Falcon library (liboqs, BouncyCastle, circl) has the same
 * signature lengths but is a different scheme: its keys and signatures do not verify here.
 */
final class Fndsa
{
    public const FN_DSA_512_PUBLIC_KEY_BYTES = 897;
    public const FN_DSA_512_SIGNATURE_BYTES = 666;
    public const FN_DSA_1024_PUBLIC_KEY_BYTES = 1793;
    public const FN_DSA_1024_SIGNATURE_BYTES = 1280;
    public const LEAF_DOMAIN = "atlas-pca/fn-dsa/leaf/v1\x00";
    public const NO_BACKEND_MESSAGE = 'no FN-DSA backend registered: supply one via Fndsa::setFalconBackend() (for example FndsaNative::backend())';

    private const MOCK_SK_TAG = "atlas-pca/fn-dsa/mock-sk/v1\x00";
    private const PK_BYTES = ['fn-dsa-512' => self::FN_DSA_512_PUBLIC_KEY_BYTES, 'fn-dsa-1024' => self::FN_DSA_1024_PUBLIC_KEY_BYTES];
    private const SIG_BYTES = ['fn-dsa-512' => self::FN_DSA_512_SIGNATURE_BYTES, 'fn-dsa-1024' => self::FN_DSA_1024_SIGNATURE_BYTES];

    /** Core suite key types => [variant, public key bytes, signature bytes] (the pure suites Pca::verify dispatches). */
    public const KEY_TYPES = [
        'FN-DSA-512' => ['fn-dsa-512', self::FN_DSA_512_PUBLIC_KEY_BYTES, self::FN_DSA_512_SIGNATURE_BYTES],
        'FN-DSA-1024' => ['fn-dsa-1024', self::FN_DSA_1024_PUBLIC_KEY_BYTES, self::FN_DSA_1024_SIGNATURE_BYTES],
    ];

    private static ?FalconBackend $current = null;
    /** @var array<string,FnDsaSuite>|null */
    private static ?array $suites = null;

    /** @return array<string,FnDsaSuite> */
    public static function suites(): array
    {
        if (self::$suites === null) {
            $mk = static function (string $alg, string $variant, bool $hybrid): FnDsaSuite {
                $pk = self::PK_BYTES[$variant];
                $sig = self::SIG_BYTES[$variant];
                return new FnDsaSuite($alg, $variant, $hybrid, $hybrid ? Pca::ED25519_SIGNATURE_BYTES : $sig, true, $pk, $hybrid, $hybrid ? $sig : 0, $sig);
            };
            self::$suites = [
                'fn-dsa-512' => $mk('fn-dsa-512', 'fn-dsa-512', false),
                'fn-dsa-1024' => $mk('fn-dsa-1024', 'fn-dsa-1024', false),
                'hybrid-ed25519-fn-dsa-512' => $mk('hybrid-ed25519-fn-dsa-512', 'fn-dsa-512', true),
                'hybrid-ed25519-fn-dsa-1024' => $mk('hybrid-ed25519-fn-dsa-1024', 'fn-dsa-1024', true),
            ];
        }
        return self::$suites;
    }

    public static function isKnownAlg(mixed $x): bool
    {
        return is_string($x) && array_key_exists($x, self::suites());
    }

    public static function resolveAlg(mixed $alg): ?FnDsaSuite
    {
        return self::isKnownAlg($alg) ? self::suites()[$alg] : null;
    }

    public static function isVariant(mixed $v): bool
    {
        return is_string($v) && array_key_exists($v, self::PK_BYTES);
    }

    // ---- backend seam

    public static function setFalconBackend(FalconBackend $backend): void
    {
        self::$current = $backend;
    }

    public static function getFalconBackend(): FalconBackend
    {
        return self::$current ?? self::noBackend();
    }

    public static function hasBackend(): bool
    {
        return self::$current !== null;
    }

    public static function resetFalconBackend(): void
    {
        self::$current = null;
    }

    private static function noBackend(): FalconBackend
    {
        $boom = static function (): never {
            throw new FnDsaBackendMissing(self::NO_BACKEND_MESSAGE);
        };
        return new FalconBackend($boom, $boom, $boom);
    }

    /** Signs `$msg` (any raw message) under the registered backend; the signature must have the variant's exact padded length. */
    public static function sign(mixed $variant, mixed $sk, mixed $msg): string
    {
        if (!self::isVariant($variant)) {
            throw new \InvalidArgumentException('fndsaSign: unknown FN-DSA variant');
        }
        if (!is_string($sk) || $sk === '') {
            throw new \TypeError('fndsaSign: secret key must be a non-empty byte string');
        }
        if (!is_string($msg)) {
            throw new \TypeError('fndsaSign: message must be bytes');
        }
        $sign = self::getFalconBackend()->sign;
        if ($sign === null) {
            throw new \RuntimeException('fndsaSign: FN-DSA backend is verify-only (no sign())');
        }
        $sig = $sign($sk, $msg);
        $expected = self::SIG_BYTES[$variant];
        if (!is_string($sig) || strlen($sig) !== $expected) {
            throw new \RuntimeException("fndsaSign: FN-DSA backend returned a bad signature; expected padded $expected bytes for '$variant'");
        }
        return $sig;
    }

    /**
     * Like {@see sign} with an explicit 32-byte sign seed (deterministic signature); a null seed is plain {@see sign}. A backend without
     * a seeded signer refuses (RuntimeException) rather than silently signing with fresh randomness.
     */
    public static function signSeeded(mixed $variant, mixed $sk, mixed $msg, ?string $seed): string
    {
        if ($seed === null) {
            return self::sign($variant, $sk, $msg);
        }
        if (!self::isVariant($variant)) {
            throw new \InvalidArgumentException('fndsaSign: unknown FN-DSA variant');
        }
        if (!is_string($sk) || $sk === '' || !is_string($msg)) {
            throw new \TypeError('fndsaSign: secret key and message must be non-empty / bytes');
        }
        if (strlen($seed) !== 32) {
            throw new \InvalidArgumentException('fndsaSign: sign seed must be 32 bytes');
        }
        $fn = self::getFalconBackend()->signSeeded ?? throw new \RuntimeException('fndsaSign: FN-DSA backend has no seeded signer');
        $sig = $fn($sk, $msg, $seed);
        if (!is_string($sig) || strlen($sig) !== self::SIG_BYTES[$variant]) {
            throw new \RuntimeException("fndsaSign: FN-DSA backend returned a bad signature; expected padded " . self::SIG_BYTES[$variant] . " bytes for '$variant'");
        }
        return $sig;
    }

    /** False for any length / type violation (before the backend is consulted); a backend that throws propagates. */
    public static function verify(mixed $variant, mixed $pk, mixed $msg, mixed $sig): bool
    {
        if (!self::isVariant($variant)) {
            return false;
        }
        if (!is_string($pk) || strlen($pk) !== self::PK_BYTES[$variant]) {
            return false;
        }
        if (!is_string($sig) || strlen($sig) !== self::SIG_BYTES[$variant]) {
            return false;
        }
        if (!is_string($msg)) {
            return false;
        }
        return (self::getFalconBackend()->verify)($pk, $msg, $sig) === true;
    }

    // ---- hybrid leaf composition

    /** thresholdMessage(leaf) || domain || alg || 0x00 || the base64url FN-DSA public key text (alg and key are bound). */
    public static function leafMessage(Obj $leaf, mixed $alg, mixed $pqPkB64u): string
    {
        if (!is_string($alg) || !is_string($pqPkB64u)) {
            throw new \TypeError('fndsaLeafMessage: alg and pq_pk must be strings');
        }
        return Pca::thresholdMessage($leaf) . self::LEAF_DOMAIN . $alg . "\x00" . $pqPkB64u;
    }

    /**
     * @param mixed $fnDsa array{pk:string,sk:string}; hybrid suites also need the Ed25519 seed
     * @return array<string,string> sig, alg, pq_pk[, pq_sig]
     */
    public static function signPca(mixed $alg, Obj $leaf, mixed $fnDsa, mixed $edSecret = null): array
    {
        $suite = self::resolveAlg($alg);
        if ($suite === null) {
            throw new \InvalidArgumentException('signPcaWithFndsa: unknown FN-DSA alg');
        }
        $pk = is_array($fnDsa) ? ($fnDsa['pk'] ?? null) : null;
        $sk = is_array($fnDsa) ? ($fnDsa['sk'] ?? null) : null;
        if (!is_string($pk) || strlen($pk) !== $suite->pqPkBytes) {
            throw new \TypeError("signPcaWithFndsa: '{$suite->alg}' requires a {$suite->pqPkBytes}-byte FN-DSA public key");
        }
        if (!is_string($sk) || $sk === '') {
            throw new \TypeError("signPcaWithFndsa: '{$suite->alg}' requires FN-DSA secret-key material");
        }
        $pqPk = Pca::b64u($pk);
        $msg = self::leafMessage($leaf, $suite->alg, $pqPk);
        $fnSig = self::sign($suite->variant, $sk, $msg);
        if (!$suite->hasEd25519) {
            return ['sig' => Pca::b64u($fnSig), 'alg' => $suite->alg, 'pq_pk' => $pqPk];
        }
        if (!is_string($edSecret) || strlen($edSecret) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \TypeError("signPcaWithFndsa: '{$suite->alg}' requires edSecret (a 32-byte Ed25519 seed)");
        }
        $edSig = sodium_crypto_sign_detached($msg, sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($edSecret)));
        return ['sig' => Pca::b64u($edSig), 'alg' => $suite->alg, 'pq_pk' => $pqPk, 'pq_sig' => Pca::b64u($fnSig)];
    }

    /** Fail closed. A hybrid needs BOTH the Ed25519 half and the FN-DSA half; every length / encoding check runs before the backend. */
    public static function verifyPca(mixed $alg, Obj $leaf, mixed $holder = null, mixed $pqPk = null, mixed $sig = null, mixed $pqSig = null): bool
    {
        $suite = self::resolveAlg($alg);
        if ($suite === null || !is_string($pqPk)) {
            return false;
        }
        $pk = Pca::unb64u($pqPk, $suite->pqPkBytes);
        if ($pk === null) {
            return false;
        }
        $msg = self::leafMessage($leaf, $suite->alg, $pqPk);
        if (!$suite->hasEd25519) {
            $fnSig = Pca::unb64u($sig, $suite->sigBytes);
            return $fnSig !== null && self::verify($suite->variant, $pk, $msg, $fnSig);
        }
        if (!is_string($holder) || !is_string($sig) || Pca::unb64u($sig, $suite->sigBytes) === null) {
            return false;
        }
        $edOk = Pca::verifyEd25519B64u($holder, $msg, $sig);
        $fnSig = Pca::unb64u($pqSig, $suite->pqSigBytes);
        if ($fnSig === null) {
            return false;
        }
        $pqOk = self::verify($suite->variant, $pk, $msg, $fnSig);
        return $edOk && $pqOk;
    }

    // ---- deterministic mock backend: TEST ONLY (anyone can forge its signatures; never register it in production)

    public static function hashKat(string $seed, int $outLen): string
    {
        if ($outLen < 0) {
            throw new \InvalidArgumentException("Invalid typed array length: $outLen");
        }
        $out = '';
        for ($c = 0; strlen($out) < $outLen; $c++) {
            $out .= hash('sha256', $seed . pack('N', $c), true);
        }
        return substr($out, 0, $outLen);
    }

    private static function deriveMockSig(string $pk, string $msg): ?string
    {
        $n = match (strlen($pk)) {
            self::FN_DSA_512_PUBLIC_KEY_BYTES => self::FN_DSA_512_SIGNATURE_BYTES,
            self::FN_DSA_1024_PUBLIC_KEY_BYTES => self::FN_DSA_1024_SIGNATURE_BYTES,
            default => null,
        };
        return $n === null ? null : self::hashKat("fn-dsa/mock-sig/v1\x00" . $pk . $msg, $n);
    }

    /** @return array{pk:string,sk:string} */
    public static function mockKeypair(mixed $variant, string $seed = 'default'): array
    {
        if (!self::isVariant($variant)) {
            throw new \InvalidArgumentException('mockKeypair: unknown FN-DSA variant');
        }
        $pk = self::hashKat($variant . '/' . $seed, self::PK_BYTES[$variant]);
        return ['pk' => $pk, 'sk' => self::MOCK_SK_TAG . $pk];
    }

    /**
     * TEST ONLY: installs a hash-derived backend (optionally with explicit known-answer vectors, each array{pk,msg,sig}, that take precedence).
     * @param list<array{pk:string,msg:string,sig:string}> $vectors
     */
    public static function registerTestBackend(array $vectors = []): FalconBackend
    {
        $table = [];
        foreach ($vectors as $v) {
            $table[Pca::b64u($v['pk']) . '|' . Pca::b64u($v['msg'])] = $v['sig'];
        }
        $verify = static function (string $pk, string $msg, string $sig) use ($table): bool {
            $expected = $table[Pca::b64u($pk) . '|' . Pca::b64u($msg)] ?? self::deriveMockSig($pk, $msg);
            return $expected !== null && strlen($sig) === strlen($expected) && hash_equals($expected, $sig);
        };
        $sign = static function (string $sk, string $msg) use ($table): string {
            $tag = self::MOCK_SK_TAG;
            if (strlen($sk) <= strlen($tag) || !hash_equals($tag, substr($sk, 0, strlen($tag)))) {
                throw new \InvalidArgumentException('mock FN-DSA backend: secret key was not minted by mockKeypair()');
            }
            $pk = substr($sk, strlen($tag));
            $known = $table[Pca::b64u($pk) . '|' . Pca::b64u($msg)] ?? null;
            if ($known !== null) {
                return $known;
            }
            return self::deriveMockSig($pk, $msg) ?? throw new \InvalidArgumentException('mock FN-DSA backend: public key length matches no FN-DSA variant');
        };
        $backend = new FalconBackend($verify, $sign, static fn(): array => self::mockKeypair('fn-dsa-512'));
        self::setFalconBackend($backend);
        return $backend;
    }
}
