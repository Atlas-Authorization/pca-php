<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/**
 * Real FN-DSA (Falcon) backend for {@see Fndsa} through ext-ffi over `libfndsa`: Thomas Pornin's fn-dsa 0.4.0 behind a small C library
 * (pca_fndsa.h), built from the flagship's crate with `cargo build --features capi`. FIPS 206 is not final, so this is a draft best guess
 * pinned in lockstep with the TypeScript reference: keys and signatures interoperate with it and with nothing that implements the earlier
 * round-3 Falcon. Point ATLAS_PCA_LIBFNDSA at the library (needs ffi.enable=true or preload; else libfndsa.so is tried). A missing or
 * mismatched library throws {@see FnDsaBackendMissing}; it never verifies.
 *
 *     Fndsa::setFalconBackend(FndsaNative::backend());
 */
final class FndsaNative
{
    public const SEED_BYTES = 32;
    public const MESSAGE_CAP = 8192;
    private const TAGS = ['fn-dsa-512' => 512, 'fn-dsa-1024' => 1024];
    private const SK_BYTES = ['fn-dsa-512' => 1345, 'fn-dsa-1024' => 2369];
    private const PK_BYTES = ['fn-dsa-512' => Fndsa::FN_DSA_512_PUBLIC_KEY_BYTES, 'fn-dsa-1024' => Fndsa::FN_DSA_1024_PUBLIC_KEY_BYTES];
    private const SIG_BYTES = ['fn-dsa-512' => Fndsa::FN_DSA_512_SIGNATURE_BYTES, 'fn-dsa-1024' => Fndsa::FN_DSA_1024_SIGNATURE_BYTES];

    private const CDEF = <<<'C'
        ptrdiff_t fndsa_len_vk(int32_t tag); ptrdiff_t fndsa_len_sk(int32_t tag); ptrdiff_t fndsa_len_sig(int32_t tag);
        size_t fndsa_len_seed(void); size_t fndsa_cap_msg(void);
        int32_t fndsa_c_keygen(int32_t tag, const uint8_t *seed, size_t seed_len, uint8_t *sk, size_t sk_len, uint8_t *vk, size_t vk_len);
        int32_t fndsa_c_sign(int32_t tag, const uint8_t *sk, size_t sk_len, const uint8_t *msg, size_t msg_len, const uint8_t *seed, size_t seed_len, uint8_t *sig, size_t sig_len);
        int32_t fndsa_c_verify(int32_t tag, const uint8_t *vk, size_t vk_len, const uint8_t *sig, size_t sig_len, const uint8_t *msg, size_t msg_len);
        C;

    private static ?\FFI $lib = null;

    private static function lib(): \FFI
    {
        if (self::$lib !== null) {
            return self::$lib;
        }
        if (!extension_loaded('FFI')) {
            throw new FnDsaBackendMissing('FN-DSA needs ext-ffi (ffi.enable=true)');
        }
        $env = getenv('ATLAS_PCA_LIBFNDSA');
        try {
            $lib = \FFI::cdef(self::CDEF, $env !== false && $env !== '' ? $env : (NativeDir::lib('fndsa') ?? 'libfndsa.so'));
            // the sizes this class hard-codes must be the ones the library was built with, or nothing is safe
            foreach (self::TAGS as $variant => $tag) {
                if ([$lib->fndsa_len_vk($tag), $lib->fndsa_len_sk($tag), $lib->fndsa_len_sig($tag)] !== [self::PK_BYTES[$variant], self::SK_BYTES[$variant], self::SIG_BYTES[$variant]]) {
                    throw new FnDsaBackendMissing("libfndsa reports different sizes for $variant");
                }
            }
            if ($lib->fndsa_len_seed() !== self::SEED_BYTES || $lib->fndsa_cap_msg() !== self::MESSAGE_CAP) {
                throw new FnDsaBackendMissing('libfndsa reports a different seed length or message cap');
            }
        } catch (FnDsaBackendMissing $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new FnDsaBackendMissing('libfndsa could not be loaded (set ATLAS_PCA_LIBFNDSA to the library built from the flagship\'s crate): ' . $e->getMessage(), 0, $e);
        }
        return self::$lib = $lib;
    }

    /** True when libfndsa can be loaded. */
    public static function available(): bool
    {
        try {
            self::lib();
            return true;
        } catch (FnDsaBackendMissing) {
            return false;
        }
    }

    private static function in(string $b): ?\FFI\CData
    {
        if ($b === '') {
            return null;
        }
        $buf = \FFI::new('uint8_t[' . strlen($b) . ']');
        \FFI::memcpy($buf, $b, strlen($b));
        return $buf;
    }

    private static function tag(string $variant): int
    {
        return self::TAGS[$variant] ?? throw new \InvalidArgumentException('fndsa native: unknown FN-DSA variant');
    }

    /** @return array{0:string,1:string} [sk, vk], deterministic in the 32-byte seed */
    public static function keygen(string $variant, string $seed): array
    {
        $tag = self::tag($variant);
        if (strlen($seed) !== self::SEED_BYTES) {
            throw new \InvalidArgumentException('fndsa native: seed must be ' . self::SEED_BYTES . ' bytes');
        }
        $lib = self::lib();
        $sk = \FFI::new('uint8_t[' . self::SK_BYTES[$variant] . ']');
        $vk = \FFI::new('uint8_t[' . self::PK_BYTES[$variant] . ']');
        $rc = $lib->fndsa_c_keygen($tag, self::in($seed), self::SEED_BYTES, $sk, self::SK_BYTES[$variant], $vk, self::PK_BYTES[$variant]);
        if ($rc !== 0) {
            throw new \RuntimeException("fndsa native: keygen refused ($rc)");
        }
        return [\FFI::string($sk, self::SK_BYTES[$variant]), \FFI::string($vk, self::PK_BYTES[$variant])];
    }

    /** Signature over a raw message. `$seed` is for known-answer tests only; by default 32 fresh bytes come from random_bytes. */
    public static function sign(string $variant, string $sk, string $msg, ?string $seed = null): string
    {
        $tag = self::tag($variant);
        if (strlen($sk) !== self::SK_BYTES[$variant]) {
            throw new \InvalidArgumentException('fndsa native: secret key must be ' . self::SK_BYTES[$variant] . " bytes for $variant");
        }
        if (strlen($msg) > self::MESSAGE_CAP) {
            throw new \InvalidArgumentException('fndsa native: message over ' . self::MESSAGE_CAP . ' bytes');
        }
        $seed ??= random_bytes(self::SEED_BYTES);
        if (strlen($seed) !== self::SEED_BYTES) {
            throw new \InvalidArgumentException('fndsa native: seed must be ' . self::SEED_BYTES . ' bytes');
        }
        $lib = self::lib();
        $out = \FFI::new('uint8_t[' . self::SIG_BYTES[$variant] . ']');
        $rc = $lib->fndsa_c_sign($tag, self::in($sk), strlen($sk), self::in($msg), strlen($msg), self::in($seed), self::SEED_BYTES, $out, self::SIG_BYTES[$variant]);
        if ($rc !== 0) {
            throw new \RuntimeException("fndsa native: sign failed ($rc)");
        }
        return \FFI::string($out, self::SIG_BYTES[$variant]);
    }

    /** True only when the library returns 0; any bad length, oversize message or nonzero return is false. An unknown variant throws. */
    public static function verify(string $variant, string $pk, string $msg, string $sig): bool
    {
        $tag = self::tag($variant);
        if (strlen($pk) !== self::PK_BYTES[$variant] || strlen($sig) !== self::SIG_BYTES[$variant] || strlen($msg) > self::MESSAGE_CAP) {
            return false;
        }
        return self::lib()->fndsa_c_verify($tag, self::in($pk), strlen($pk), self::in($sig), strlen($sig), self::in($msg), strlen($msg)) === 0;
    }

    /**
     * A {@see FalconBackend} over libfndsa (throws FnDsaBackendMissing now if the library is absent). The variant follows the key length;
     * keygen() draws a fresh fn-dsa-512 pair from random_bytes (use `keygen($variant, $seed)` for 1024).
     */
    public static function backend(): FalconBackend
    {
        self::lib();
        $byPk = array_flip(self::PK_BYTES);
        $bySk = array_flip(self::SK_BYTES);
        return new FalconBackend(
            static fn(string $pk, string $msg, string $sig): bool => isset($byPk[strlen($pk)]) && self::verify($byPk[strlen($pk)], $pk, $msg, $sig),
            static function (string $sk, string $msg) use ($bySk): string {
                if (!isset($bySk[strlen($sk)])) {
                    throw new \InvalidArgumentException('fndsa native: unrecognised FN-DSA secret-key length');
                }
                return self::sign($bySk[strlen($sk)], $sk, $msg);
            },
            static function (): array {
                [$sk, $pk] = self::keygen('fn-dsa-512', random_bytes(self::SEED_BYTES));
                return ['pk' => $pk, 'sk' => $sk];
            },
            static function (string $sk, string $msg, string $seed) use ($bySk): string {
                if (!isset($bySk[strlen($sk)])) {
                    throw new \InvalidArgumentException('fndsa native: unrecognised FN-DSA secret-key length');
                }
                return self::sign($bySk[strlen($sk)], $sk, $msg, $seed);
            },
        );
    }
}
