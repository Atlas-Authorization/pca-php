<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/**
 * LESS (less-252-45, the `less-cat1` / `hybrid-ed25519-less-cat1` suites; a NIST additional-signature round-2 candidate, not a
 * standard) through FFI to `libatlas_less`: the patched LESS reference C of the repository's sdks/pca-less-c built as a shared
 * library (`sdks/pca-less-c/build.sh`). The library is found at ATLAS_PCA_LIBLESS (one path, or several separated by
 * PATH_SEPARATOR), else in the repository's sdks/pca-less-c/build/. It counts only if it reports the less-252-45 sizes; without
 * one the LESS suites are left out of Pca::supportedSuites and fail closed with `unsupported_suite`. The detached signature is
 * variable-length (1,153..1,329 bytes in steps of 16). Never throws; a wrong length / missing library returns false.
 */
final class LessFfi
{
    public const KEY_TYPE = 'LESS-cat1';
    public const PUBLIC_KEY_BYTES = 97484;
    public const SIGNATURE_MIN_BYTES = 1153;
    public const SIGNATURE_MAX_BYTES = 1329;
    private const SIGNATURE_STEP_BYTES = 16;

    private static ?\FFI $ffi = null;
    private static bool $tried = false;

    /**
     * @internal public for tests only
     * @return list<string>
     */
    public static function candidates(): array
    {
        $env = getenv('ATLAS_PCA_LIBLESS');
        $paths = is_string($env) ? array_values(array_filter(explode(PATH_SEPARATOR, $env), fn($p) => $p !== '')) : [];
        $packaged = NativeDir::lib('atlas_less');
        if ($packaged !== null) {
            $paths[] = $packaged; // after an explicit override, before the in-tree build
        }
        foreach (['libatlas_less.so', 'libatlas_less.dylib', 'atlas_less.dll'] as $name) {
            $paths[] = __DIR__ . '/../../pca-less-c/build/' . $name;
        }
        return $paths;
    }

    private static function ffi(): ?\FFI
    {
        if (self::$tried) {
            return self::$ffi;
        }
        self::$tried = true;
        if (!extension_loaded('FFI')) {
            return null;
        }
        $cdef = <<<'CDEF'
            size_t atlas_less_cat1_public_key_bytes(void);
            size_t atlas_less_cat1_signature_min_bytes(void);
            size_t atlas_less_cat1_signature_max_bytes(void);
            int atlas_less_cat1_verify(const char* pk, size_t pk_len, const char* msg, size_t msg_len, const char* sig, size_t sig_len);
            CDEF;
        foreach (self::candidates() as $path) {
            if (!is_file($path)) {
                continue;
            }
            try {
                $f = \FFI::cdef($cdef, $path);
                if (self::sizesMatch($f->atlas_less_cat1_public_key_bytes(), $f->atlas_less_cat1_signature_min_bytes(),
                    $f->atlas_less_cat1_signature_max_bytes())) {
                    self::$ffi = $f;
                    return self::$ffi;
                }
            } catch (\Throwable) {
                // try the next candidate
            }
        }
        return null;
    }

    /**
     * A library counts only if it reports the less-252-45 sizes (public key, minimum and maximum signature bytes).
     * @internal public for tests only
     */
    public static function sizesMatch(int $pk, int $sigMin, int $sigMax): bool
    {
        return $pk === self::PUBLIC_KEY_BYTES && $sigMin === self::SIGNATURE_MIN_BYTES && $sigMax === self::SIGNATURE_MAX_BYTES;
    }

    /** True iff a usable libatlas_less is loaded. */
    public static function available(): bool
    {
        return self::ffi() !== null;
    }

    public const SECRET_KEY_BYTES = 32;
    public const SEED_BYTES = 32;

    private static ?\FFI $signFfi = null;
    private static bool $signTried = false;

    /** The keygen / sign half of the library (loaded on its own so a verify-only build keeps verifying). */
    private static function signLib(): ?\FFI
    {
        if (self::$signTried) {
            return self::$signFfi;
        }
        self::$signTried = true;
        if (!extension_loaded('FFI') || self::ffi() === null) {
            return null;
        }
        $cdef = <<<'CDEF'
            size_t atlas_less_cat1_secret_key_bytes(void);
            int atlas_less_cat1_keygen(char* pk, size_t pk_cap, char* sk, size_t sk_cap, const char* seed, size_t seed_len);
            int atlas_less_cat1_sign(const char* sk, size_t sk_len, const char* msg, size_t msg_len, const char* seed, size_t seed_len,
                                     char* sig, size_t sig_cap, size_t* sig_len);
            CDEF;
        foreach (self::candidates() as $path) {
            if (!is_file($path)) {
                continue;
            }
            try {
                $f = \FFI::cdef($cdef, $path);
                if ($f->atlas_less_cat1_secret_key_bytes() === self::SECRET_KEY_BYTES) {
                    self::$signFfi = $f;
                    return $f;
                }
            } catch (\Throwable) {
                // try the next candidate
            }
        }
        return null;
    }

    /** Availability and the reason it is not (lessBackendStatus of the reference). Never throws. @return array{available:bool,reason?:string} */
    public static function status(): array
    {
        return self::available() ? ['available' => true]
            : ['available' => false, 'reason' => extension_loaded('FFI') ? 'libatlas_less was not found (set ATLAS_PCA_LIBLESS)' : 'the FFI extension is not loaded'];
    }

    /**
     * Deterministic keygen from a 32-byte seed.
     * @return array{publicKey:string,secretKey:string}
     * @throws \RuntimeException when the library is unavailable or refuses
     */
    public static function keygen(string $seed): array
    {
        if (strlen($seed) !== self::SEED_BYTES) {
            throw new \InvalidArgumentException('lessCat1Keygen: seed must be ' . self::SEED_BYTES . ' bytes');
        }
        $f = self::signLib() ?? throw new \RuntimeException('lessCat1Keygen: LESS suites are unsupported (' . (self::status()['reason'] ?? 'no keygen in the library') . ')');
        $pk = $f->new('char[' . self::PUBLIC_KEY_BYTES . ']');
        $sk = $f->new('char[' . self::SECRET_KEY_BYTES . ']');
        if ($f->atlas_less_cat1_keygen($pk, self::PUBLIC_KEY_BYTES, $sk, self::SECRET_KEY_BYTES, $seed, strlen($seed)) !== 1) {
            throw new \RuntimeException('lessCat1Keygen: the library refused the seed');
        }
        return ['publicKey' => \FFI::string($pk, self::PUBLIC_KEY_BYTES), 'secretKey' => \FFI::string($sk, self::SECRET_KEY_BYTES)];
    }

    /** Detached signature (1153..1329 bytes) with an explicit 32-byte RNG seed. @throws \RuntimeException when unavailable or refused */
    public static function sign(string $secretKey, string $msg, string $seed): string
    {
        if (strlen($seed) !== self::SEED_BYTES) {
            throw new \InvalidArgumentException('lessCat1Sign: seed must be ' . self::SEED_BYTES . ' bytes');
        }
        $f = self::signLib() ?? throw new \RuntimeException('lessCat1Sign: LESS suites are unsupported (' . (self::status()['reason'] ?? 'no sign in the library') . ')');
        $sig = $f->new('char[' . self::SIGNATURE_MAX_BYTES . ']');
        $len = $f->new('size_t');
        if ($f->atlas_less_cat1_sign($secretKey, strlen($secretKey), $msg, strlen($msg), $seed, strlen($seed), $sig, self::SIGNATURE_MAX_BYTES, \FFI::addr($len)) !== 1) {
            throw new \RuntimeException('lessCat1Sign: the library refused the key');
        }
        return \FFI::string($sig, (int)$len->cdata);
    }

    /** `$n` is a signature length the parameter set produces. */
    public static function sigLenOk(int $n): bool
    {
        return $n >= self::SIGNATURE_MIN_BYTES && $n <= self::SIGNATURE_MAX_BYTES
            && (self::SIGNATURE_MAX_BYTES - $n) % self::SIGNATURE_STEP_BYTES === 0;
    }

    /** The detached signature opens under `$pk` and yields exactly `$msg`. Never throws. */
    public static function verify(string $pk, string $msg, string $sig): bool
    {
        if (strlen($pk) !== self::PUBLIC_KEY_BYTES || !self::sigLenOk(strlen($sig))) {
            return false;
        }
        $f = self::ffi();
        if ($f === null) {
            return false;
        }
        try {
            return $f->atlas_less_cat1_verify($pk, strlen($pk), $msg, strlen($msg), $sig, strlen($sig)) === 1;
        } catch (\Throwable) {
            return false;
        }
    }
}
