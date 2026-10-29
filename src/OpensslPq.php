<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * B4 post-quantum primitives through OpenSSL >= 3.5 libcrypto (FFI): ML-DSA-65 / ML-DSA-87 (FIPS 204) and
 * SLH-DSA-SHA2-128f / SLH-DSA-SHA2-256s (FIPS 205) signature verification, raw public keys, the one-shot PURE EVP verify
 * with an EMPTY context (OpenSSL's defaults for these key types, = @noble/post-quantum in packages/pca/src/pq.ts).
 *
 * PHP's own `openssl_*` functions do not expose these key types, so libcrypto is bound through FFI. Every key type is
 * probed for real (the provider must build a raw public key of it; no version-number gate): a key type the loaded library
 * cannot build is reported unavailable, and the suite capability manifest (Pca::supportedSuites) leaves its suites out so
 * they fail closed with `unsupported_suite`. Never throws; a wrong length / unavailable library / malformed input
 * returns false.
 */
final class OpensslPq
{
    /** OpenSSL key type => [public key bytes, signature bytes]. */
    public const KEY_TYPES = [
        'ML-DSA-65' => [1952, 3309],
        'ML-DSA-87' => [2592, 4627],
        'SLH-DSA-SHA2-128f' => [32, 17088],
        'SLH-DSA-SHA2-256s' => [64, 29792],
    ];

    private static ?\FFI $ffi = null;
    private static bool $tried = false;
    /** @var array<string,bool> */
    private static array $probed = [];

    /**
     * Candidate libcrypto paths, tried in order: the explicit override first (ATLAS_PCA_LIBCRYPTO: one path, or several
     * separated by PATH_SEPARATOR; empty entries are ignored), then common OpenSSL >= 3.5 locations. The first one whose
     * provider can build an ML-DSA-65 key wins.
     * @internal public for tests only
     * @return list<string>
     */
    public static function candidates(): array
    {
        $env = getenv('ATLAS_PCA_LIBCRYPTO');
        $paths = is_string($env) ? array_values(array_filter(explode(PATH_SEPARATOR, $env), fn($p) => $p !== '')) : [];
        foreach ([
            '/opt/homebrew/opt/openssl@3/lib/libcrypto*.dylib',
            '/opt/homebrew/lib/libcrypto*.dylib',
            '/usr/local/opt/openssl@3/lib/libcrypto*.dylib',
            '/usr/lib/libcrypto.so.3',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
            '/usr/lib/aarch64-linux-gnu/libcrypto.so.3',
            '/lib/x86_64-linux-gnu/libcrypto.so.3',
        ] as $pat) {
            foreach (glob($pat) ?: [] as $m) {
                $paths[] = $m;
            }
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
            void* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const unsigned char* key, size_t keylen);
            void* EVP_MD_CTX_new(void);
            int EVP_DigestVerifyInit_ex(void* ctx, void** pctx, const char* mdname, void* libctx, const char* props, void* pkey, void* params);
            int EVP_DigestVerify(void* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen);
            void EVP_PKEY_free(void* pkey);
            void EVP_MD_CTX_free(void* ctx);
            void* EVP_PKEY_CTX_new_from_name(void* libctx, const char* name, const char* propq);
            int EVP_PKEY_keygen_init(void* ctx);
            int EVP_PKEY_generate(void* ctx, void** ppkey);
            void EVP_PKEY_CTX_free(void* ctx);
            int EVP_PKEY_get_raw_public_key(const void* pkey, unsigned char* pub, size_t* len);
            int EVP_DigestSignInit_ex(void* ctx, void** pctx, const char* mdname, void* libctx, const char* props, void* pkey, void* params);
            int EVP_DigestSign(void* ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs, size_t tbslen);
            CDEF;
        foreach (self::candidates() as $path) {
            try {
                $f = \FFI::cdef($cdef, $path);
                if (!self::builds($f, 'ML-DSA-65')) {
                    continue; // libcrypto < 3.5 (no ML-DSA): never report available
                }
                self::$ffi = $f;
                return self::$ffi;
            } catch (\Throwable) {
                // try the next candidate
            }
        }
        return null;
    }

    /**
     * Real capability probe: the provider can actually construct a raw public key of `$type` (OpenSSL < 3.5 cannot, and
     * returns NULL; a library without the _ex symbols fails FFI::cdef). This is the whole test: no version-number gate.
     */
    private static function builds(\FFI $f, string $type): bool
    {
        try {
            $n = self::KEY_TYPES[$type][0];
            $buf = $f->new('unsigned char[' . $n . ']');
            \FFI::memset($buf, 0, $n);
            $k = $f->EVP_PKEY_new_raw_public_key_ex(null, $type, null, $buf, $n);
            if ($k === null || \FFI::isNull($k)) {
                return false;
            }
            $f->EVP_PKEY_free($k);
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** True iff the loaded libcrypto can verify `$type` signatures (false for an unknown type or no usable library). */
    public static function available(string $type): bool
    {
        if (!isset(self::KEY_TYPES[$type])) {
            return false;
        }
        if (!array_key_exists($type, self::$probed)) {
            $f = self::ffi();
            self::$probed[$type] = $f !== null && self::builds($f, $type);
        }
        return self::$probed[$type];
    }

    /** Verify a `$type` signature over raw bytes (pure, empty context). Exact lengths; never throws. */
    public static function verify(string $type, string $pk, string $msg, string $sig): bool
    {
        if (!isset(self::KEY_TYPES[$type])) {
            return false;
        }
        [$pkLen, $sigLen] = self::KEY_TYPES[$type];
        if (strlen($pk) !== $pkLen || strlen($sig) !== $sigLen || !self::available($type)) {
            return false;
        }
        $ffi = self::ffi();
        if ($ffi === null) {
            return false;
        }
        try {
            $pkBuf = $ffi->new('unsigned char[' . strlen($pk) . ']');
            \FFI::memcpy($pkBuf, $pk, strlen($pk));
            $pkey = $ffi->EVP_PKEY_new_raw_public_key_ex(null, $type, null, $pkBuf, strlen($pk));
            if ($pkey === null || \FFI::isNull($pkey)) {
                return false;
            }
            try {
                $ctx = $ffi->EVP_MD_CTX_new();
                if ($ctx === null || \FFI::isNull($ctx)) {
                    return false;
                }
                try {
                    if ($ffi->EVP_DigestVerifyInit_ex($ctx, null, null, null, null, $pkey, null) !== 1) {
                        return false;
                    }
                    $sigBuf = $ffi->new('unsigned char[' . strlen($sig) . ']');
                    \FFI::memcpy($sigBuf, $sig, strlen($sig));
                    $mlen = strlen($msg);
                    $msgBuf = $ffi->new('unsigned char[' . max(1, $mlen) . ']');
                    if ($mlen > 0) {
                        \FFI::memcpy($msgBuf, $msg, $mlen);
                    }
                    return $ffi->EVP_DigestVerify($ctx, $sigBuf, strlen($sig), $msgBuf, $mlen) === 1;
                } finally {
                    $ffi->EVP_MD_CTX_free($ctx);
                }
            } finally {
                $ffi->EVP_PKEY_free($pkey);
            }
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * SIGNING (the producer side, see {@see Sign}): a fresh `$type` key pair through libcrypto. Returns `[pkey, publicKeyBytes]`
     * where `pkey` is an opaque FFI handle (free it with {@see free}); null when the loaded library cannot generate `$type`.
     * @return array{0:\FFI\CData,1:string}|null
     */
    public static function generate(string $type): ?array
    {
        if (!self::available($type)) {
            return null;
        }
        $ffi = self::ffi();
        try {
            $ctx = $ffi->EVP_PKEY_CTX_new_from_name(null, $type, null);
            if ($ctx === null || \FFI::isNull($ctx)) {
                return null;
            }
            try {
                $pp = $ffi->new('void*[1]');
                if ($ffi->EVP_PKEY_keygen_init($ctx) !== 1 || $ffi->EVP_PKEY_generate($ctx, \FFI::addr($pp[0])) !== 1 || \FFI::isNull($pp[0])) {
                    return null;
                }
            } finally {
                $ffi->EVP_PKEY_CTX_free($ctx);
            }
            $pkey = $pp[0];
            $n = self::KEY_TYPES[$type][0];
            $buf = $ffi->new('unsigned char[' . $n . ']');
            $len = $ffi->new('size_t[1]');
            $len[0] = $n;
            if ($ffi->EVP_PKEY_get_raw_public_key($pkey, $buf, \FFI::addr($len[0])) !== 1) {
                $ffi->EVP_PKEY_free($pkey);
                return null;
            }
            return [$pkey, \FFI::string($buf, $n)];
        } catch (\Throwable) {
            return null;
        }
    }

    public static function free(\FFI\CData $pkey): void
    {
        self::ffi()?->EVP_PKEY_free($pkey);
    }

    /** Sign `$msg` (pure, empty context; hedged by the provider's default) with a key from {@see generate}. Null on failure. */
    public static function sign(string $type, \FFI\CData $pkey, string $msg): ?string
    {
        $ffi = self::ffi();
        if ($ffi === null || !isset(self::KEY_TYPES[$type])) {
            return null;
        }
        try {
            $ctx = $ffi->EVP_MD_CTX_new();
            if ($ctx === null || \FFI::isNull($ctx)) {
                return null;
            }
            try {
                if ($ffi->EVP_DigestSignInit_ex($ctx, null, null, null, null, $pkey, null) !== 1) {
                    return null;
                }
                $mlen = strlen($msg);
                $msgBuf = $ffi->new('unsigned char[' . max(1, $mlen) . ']');
                if ($mlen > 0) {
                    \FFI::memcpy($msgBuf, $msg, $mlen);
                }
                $max = self::KEY_TYPES[$type][1];
                $sig = $ffi->new('unsigned char[' . $max . ']');
                $len = $ffi->new('size_t[1]');
                $len[0] = $max;
                if ($ffi->EVP_DigestSign($ctx, $sig, \FFI::addr($len[0]), $msgBuf, $mlen) !== 1) {
                    return null;
                }
                return \FFI::string($sig, (int)$len[0]);
            } finally {
                $ffi->EVP_MD_CTX_free($ctx);
            }
        } catch (\Throwable) {
            return null;
        }
    }
}
