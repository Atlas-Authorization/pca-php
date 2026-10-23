<?php
declare(strict_types=1);

namespace Atlas\Pca;

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
