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

    /** Seed bytes of a seeded key pair: the 32-byte FIPS 204 xi for ML-DSA, SK.seed || SK.prf || PK.seed (3n bytes) for SLH-DSA. */
    public const SEED_BYTES = ['ML-DSA-65' => 32, 'ML-DSA-87' => 32, 'SLH-DSA-SHA2-128f' => 48, 'SLH-DSA-SHA2-256s' => 96];

    /**
     * TEST SEAM: called with 'md_ctx_new' / 'verify_init' / 'keygen' / 'raw_public_key'; returning true makes that libcrypto step report
     * failure, so the tests can prove the fail-closed branches libcrypto never takes on its own. Always null in production.
     */
    public static ?\Closure $faultHook = null;

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
            typedef struct { const char* key; unsigned int data_type; void* data; size_t data_size; size_t return_size; } OSSL_PARAM;
            int EVP_PKEY_CTX_set_params(void* ctx, const OSSL_PARAM* params);
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
            $buf = $f->new('unsigned char[' . $n . ']'); // FFI::new zero-fills; every byte pattern is a valid raw public key
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
                $ctx = self::$faultHook?->__invoke('md_ctx_new') === true ? null : $ffi->EVP_MD_CTX_new();
                if ($ctx === null || \FFI::isNull($ctx)) {
                    return false;
                }
                try {
                    if ($ffi->EVP_DigestVerifyInit_ex($ctx, null, null, null, null, $pkey, null) !== 1 || self::$faultHook?->__invoke('verify_init') === true) {
                        return false;
                    }
                    $sigBuf = $ffi->new('unsigned char[' . strlen($sig) . ']');
                    \FFI::memcpy($sigBuf, $sig, strlen($sig));
                    $mlen = strlen($msg);
                    $msgBuf = $ffi->new('unsigned char[' . max(1, $mlen) . ']');
                    \FFI::memcpy($msgBuf, $msg, $mlen); // zero bytes for an empty message: a no-op
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
     * A one-entry OSSL_PARAM list (plus the end marker) over a copy of `$data`: an octet string, or a C int when `$data` is an
     * int. Returns [params, buffers]; the caller keeps the buffers alive for the call and wipes them after.
     * @return array{0:\FFI\CData,1:list<\FFI\CData>}
     */
    private static function param(\FFI $ffi, string $key, string|int $data): array
    {
        $k = $ffi->new('char[' . (strlen($key) + 1) . ']'); // zero-filled: NUL-terminated
        \FFI::memcpy($k, $key, strlen($key));
        if (is_int($data)) {
            $buf = $ffi->new('int[1]');
            $buf[0] = $data;
            [$type, $size] = [1, \FFI::sizeof($buf)]; // OSSL_PARAM_INTEGER
        } else {
            $buf = $ffi->new('unsigned char[' . strlen($data) . ']');
            \FFI::memcpy($buf, $data, strlen($data));
            [$type, $size] = [5, strlen($data)]; // OSSL_PARAM_OCTET_STRING
        }
        $p = $ffi->new('OSSL_PARAM[2]'); // the second entry stays zero: the end marker
        $p[0]->key = $ffi->cast('const char*', \FFI::addr($k[0]));
        $p[0]->data_type = $type;
        $p[0]->data = \FFI::addr($buf[0]);
        $p[0]->data_size = $size;
        return [$p, [$k, $buf]];
    }

    /**
     * SIGNING (the producer side, see {@see Sign}): a `$type` key pair through libcrypto, fresh, or derived from `$seed`
     * ({@see SEED_BYTES}: the same key the reference derives from that seed). Returns `[pkey, publicKeyBytes]` where `pkey` is an
     * opaque FFI handle (free it with {@see free}); null when the loaded library cannot generate `$type` or refuses the seed.
     * @return array{0:\FFI\CData,1:string}|null
     */
    public static function generate(string $type, ?string $seed = null): ?array
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
                if (self::$faultHook?->__invoke('keygen') === true) {
                    return null;
                }
                $pp = $ffi->new('void*[1]');
                if ($ffi->EVP_PKEY_keygen_init($ctx) !== 1) {
                    return null;
                }
                if ($seed !== null) { // libcrypto refuses a seed of the wrong length
                    [$params, $bufs] = self::param($ffi, 'seed', $seed);
                    try {
                        if ($ffi->EVP_PKEY_CTX_set_params($ctx, \FFI::addr($params[0])) !== 1) {
                            return null;
                        }
                    } finally {
                        \FFI::memset($bufs[1], 0, strlen($seed)); // the seed is the private key
                    }
                }
                if ($ffi->EVP_PKEY_generate($ctx, \FFI::addr($pp[0])) !== 1 || \FFI::isNull($pp[0])) {
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
            if ($ffi->EVP_PKEY_get_raw_public_key($pkey, $buf, \FFI::addr($len[0])) !== 1 || self::$faultHook?->__invoke('raw_public_key') === true) {
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

    /**
     * Sign `$msg` (pure, empty context) with a key from {@see generate}. DETERMINISTIC like the reference: ML-DSA with rnd = 0^32,
     * SLH-DSA with opt_rand = PK.seed, so a seeded key reproduces the reference's bytes. Null on failure.
     */
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
                [$params, $keep] = self::param($ffi, 'deterministic', 1); // $keep holds the buffers the list points into
                if ($ffi->EVP_DigestSignInit_ex($ctx, null, null, null, null, $pkey, \FFI::addr($params[0])) !== 1) {
                    return null;
                }
                $mlen = strlen($msg);
                $msgBuf = $ffi->new('unsigned char[' . max(1, $mlen) . ']');
                \FFI::memcpy($msgBuf, $msg, $mlen); // zero bytes for an empty message: a no-op
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
