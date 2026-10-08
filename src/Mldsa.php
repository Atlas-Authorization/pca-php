<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * B4 post-quantum primitive: ML-DSA-65 (FIPS-204, CRYSTALS-Dilithium category 3) signature verification.
 *
 * Mirrors `mlDsa65Verify` in packages/pca/src/pq.ts (which uses @noble/post-quantum's ml_dsa65). PHP's own
 * `openssl_*` functions do not expose ML-DSA, so this binds OpenSSL >= 3.5 libcrypto through FFI and calls
 * the one-shot pure EVP verify (empty context): raw public key 1952 bytes, signature 3309 bytes. Never
 * throws; a wrong length / unavailable library / malformed input returns false. If no usable libcrypto is
 * found, {@see available()} is false and verification returns false (fail-closed).
 */
final class Mldsa
{
    public const PUBLIC_KEY_BYTES = 1952;
    public const SIGNATURE_BYTES = 3309;

    private static ?\FFI $ffi = null;
    private static bool $tried = false;

    /** Candidate libcrypto paths: an explicit override first, then common OpenSSL >= 3.5 locations. */
    private static function candidates(): array
    {
        $env = getenv('ATLAS_PCA_LIBCRYPTO');
        $paths = $env !== false && $env !== '' ? [$env] : [];
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
            CDEF;
        foreach (self::candidates() as $path) {
            try {
                self::$ffi = \FFI::cdef($cdef, $path);
                return self::$ffi;
            } catch (\Throwable) {
                // try the next candidate
            }
        }
        return null;
    }

    public static function available(): bool
    {
        return self::ffi() !== null;
    }

    public static function verify(string $pk, string $msg, string $sig): bool
    {
        if (strlen($pk) !== self::PUBLIC_KEY_BYTES || strlen($sig) !== self::SIGNATURE_BYTES) {
            return false;
        }
        $ffi = self::ffi();
        if ($ffi === null) {
            return false;
        }
        try {
            $pkBuf = $ffi->new('unsigned char[' . strlen($pk) . ']');
            \FFI::memcpy($pkBuf, $pk, strlen($pk));
            $pkey = $ffi->EVP_PKEY_new_raw_public_key_ex(null, 'ML-DSA-65', null, $pkBuf, strlen($pk));
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
}
