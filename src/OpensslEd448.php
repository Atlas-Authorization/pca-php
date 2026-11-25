<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Ed448 (RFC 8032, pure, empty context) sign and verify through OpenSSL libcrypto over ext-ffi: libsodium has Ed25519 only and PHP's own
 * `openssl_*` functions do not expose raw Ed448 keys. Library paths come from OpensslPq::candidates() (ATLAS_PCA_LIBCRYPTO first). A
 * missing ext-ffi / library makes `available()` false and verify() return false (a signature is never accepted without a verifier); sign()
 * throws. A wrong key or signature length is refused before libcrypto is called.
 */
final class OpensslEd448
{
    public const NID_ED448 = 1088;
    public const KEY_BYTES = 57;
    public const SIG_BYTES = 114;

    private static ?\FFI $ffi = null;
    private static bool $tried = false;

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
            void* EVP_PKEY_new_raw_public_key(int type, void* e, const unsigned char* key, size_t keylen);
            void* EVP_PKEY_new_raw_private_key(int type, void* e, const unsigned char* key, size_t keylen);
            void EVP_PKEY_free(void* pkey);
            void* EVP_MD_CTX_new(void);
            void EVP_MD_CTX_free(void* ctx);
            int EVP_DigestVerifyInit(void* ctx, void** pctx, const void* type, void* e, void* pkey);
            int EVP_DigestVerify(void* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen);
            int EVP_DigestSignInit(void* ctx, void** pctx, const void* type, void* e, void* pkey);
            int EVP_DigestSign(void* ctx, unsigned char* sigret, size_t* siglen, const unsigned char* tbs, size_t tbslen);
            CDEF;
        foreach (self::candidates() as $path) {
            try {
                $f = \FFI::cdef($cdef, $path);
                $probe = $f->new('unsigned char[' . self::KEY_BYTES . ']');
                $k = $f->EVP_PKEY_new_raw_public_key(self::NID_ED448, null, $probe, self::KEY_BYTES);
                if ($k === null || \FFI::isNull($k)) {
                    continue;
                }
                $f->EVP_PKEY_free($k);
                return self::$ffi = $f;
            } catch (\Throwable) {
                // next candidate
            }
        }
        return null;
    }

    /**
     * The post-quantum loader's candidates, then the libcrypto PHP itself ships beside its binary on Windows: Ed448 needs only
     * OpenSSL 1.1.1 (the 3.5 floor is for ML-DSA), and no other copy is installed there by default.
     * @internal public for tests only
     * @return list<string>
     */
    public static function candidates(): array
    {
        $paths = OpensslPq::candidates();
        if (PHP_OS_FAMILY === 'Windows') {
            foreach (glob(dirname(PHP_BINARY) . DIRECTORY_SEPARATOR . 'libcrypto-*.dll') ?: [] as $m) {
                $paths[] = $m;
            }
        }
        return $paths;
    }

    public static function available(): bool
    {
        return self::ffi() !== null;
    }

    private static function buf(\FFI $f, string $s): \FFI\CData
    {
        $n = strlen($s);
        $b = $f->new('unsigned char[' . max(1, $n) . ']');
        \FFI::memcpy($b, $s, $n);
        return $b;
    }

    /** True iff `$sig` is a valid Ed448 signature of `$msg` under the 57-byte public key. Never throws. */
    public static function verify(string $pub, string $sig, string $msg): bool
    {
        if (strlen($pub) !== self::KEY_BYTES || strlen($sig) !== self::SIG_BYTES) {
            return false;
        }
        $f = self::ffi();
        if ($f === null) {
            return false;
        }
        $key = $ctx = null;
        try {
            $key = $f->EVP_PKEY_new_raw_public_key(self::NID_ED448, null, self::buf($f, $pub), self::KEY_BYTES);
            if ($key === null || \FFI::isNull($key)) {
                return false;
            }
            $ctx = $f->EVP_MD_CTX_new();
            if ($ctx === null || \FFI::isNull($ctx) || $f->EVP_DigestVerifyInit($ctx, null, null, null, $key) !== 1) {
                return false;
            }
            return $f->EVP_DigestVerify($ctx, self::buf($f, $sig), self::SIG_BYTES, self::buf($f, $msg), strlen($msg)) === 1;
        } catch (\Throwable) {
            return false;
        } finally {
            if ($ctx !== null && !\FFI::isNull($ctx)) {
                $f->EVP_MD_CTX_free($ctx);
            }
            if ($key !== null && !\FFI::isNull($key)) {
                $f->EVP_PKEY_free($key);
            }
        }
    }

    /** The 114-byte Ed448 signature of `$msg` under the 57-byte private key (RFC 8032 seed). */
    public static function sign(string $priv, string $msg): string
    {
        if (strlen($priv) !== self::KEY_BYTES) {
            throw new \InvalidArgumentException('an Ed448 private key is 57 bytes');
        }
        $f = self::ffi();
        if ($f === null) {
            throw new \RuntimeException('Ed448 needs ext-ffi and an OpenSSL libcrypto (set ATLAS_PCA_LIBCRYPTO)');
        }
        $key = $ctx = null;
        try {
            $key = $f->EVP_PKEY_new_raw_private_key(self::NID_ED448, null, self::buf($f, $priv), self::KEY_BYTES);
            if ($key === null || \FFI::isNull($key)) {
                throw new \RuntimeException('the Ed448 private key was refused');
            }
            $ctx = $f->EVP_MD_CTX_new();
            if ($ctx === null || \FFI::isNull($ctx) || $f->EVP_DigestSignInit($ctx, null, null, null, $key) !== 1) {
                throw new \RuntimeException('Ed448 signing could not start');
            }
            $out = $f->new('unsigned char[' . self::SIG_BYTES . ']');
            $len = $f->new('size_t[1]');
            $len[0] = self::SIG_BYTES;
            if ($f->EVP_DigestSign($ctx, $out, \FFI::addr($len[0]), self::buf($f, $msg), strlen($msg)) !== 1 || $len[0] !== self::SIG_BYTES) {
                throw new \RuntimeException('Ed448 signing failed');
            }
            return \FFI::string($out, self::SIG_BYTES);
        } finally {
            if ($ctx !== null && !\FFI::isNull($ctx)) {
                $f->EVP_MD_CTX_free($ctx);
            }
            if ($key !== null && !\FFI::isNull($key)) {
                $f->EVP_PKEY_free($key);
            }
        }
    }
}
