<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * SHAKE256 (FIPS 202) through OpenSSL libcrypto (ext-ffi, EVP_MD_fetch + EVP_DigestFinalXOF): PHP's hash extension has no SHAKE and
 * the permutation is not re-implemented here. Library paths come from OpensslPq::candidates() (ATLAS_PCA_LIBCRYPTO first); any
 * OpenSSL 3.x provides SHAKE256. A missing library or a failing libcrypto call throws (never returns a wrong digest).
 * shortcut: the whole message is held in memory (the OT challenges are a few kilobytes); stream it if inputs ever grow.
 */
final class MpcShake256
{
    private static ?\FFI $ffi = null;
    private static mixed $md = null;

    /** True iff ext-ffi plus a libcrypto exposing SHAKE256 is loadable. */
    public static function available(): bool
    {
        try {
            self::load();
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function load(): \FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        if (!extension_loaded('FFI')) {
            throw new \RuntimeException('SHAKE256 needs ext-ffi');
        }
        $cdef = <<<'CDEF'
            void* EVP_MD_fetch(void* libctx, const char* algorithm, const char* properties);
            void* EVP_MD_CTX_new(void);
            void EVP_MD_CTX_free(void* ctx);
            int EVP_DigestInit_ex(void* ctx, const void* type, void* impl);
            int EVP_DigestUpdate(void* ctx, const void* d, size_t cnt);
            int EVP_DigestFinalXOF(void* ctx, unsigned char* md, size_t len);
            CDEF;
        foreach (OpensslPq::candidates() as $path) {
            try {
                $f = \FFI::cdef($cdef, $path);
                $md = $f->EVP_MD_fetch(null, 'SHAKE256', null);
                if ($md !== null && !\FFI::isNull($md)) {
                    self::$md = $md;
                    return self::$ffi = $f;
                }
            } catch (\Throwable) {
                // next candidate
            }
        }
        throw new \RuntimeException('no libcrypto with SHAKE256 (set ATLAS_PCA_LIBCRYPTO)');
    }

    /** @return string $outLen bytes of SHAKE256($msg) */
    public static function hash(string $msg, int $outLen): string
    {
        if ($outLen < 1) {
            throw new \InvalidArgumentException('SHAKE256 output length must be positive');
        }
        $f = self::load();
        $ctx = $f->EVP_MD_CTX_new();
        if ($ctx === null || \FFI::isNull($ctx)) {
            throw new \RuntimeException('EVP_MD_CTX_new failed');
        }
        try {
            $n = strlen($msg);
            $in = $f->new('unsigned char[' . max(1, $n) . ']');
            \FFI::memcpy($in, $msg, $n);
            $out = $f->new('unsigned char[' . $outLen . ']');
            if ($f->EVP_DigestInit_ex($ctx, self::$md, null) !== 1
                || $f->EVP_DigestUpdate($ctx, $in, $n) !== 1
                || $f->EVP_DigestFinalXOF($ctx, $out, $outLen) !== 1) {
                throw new \RuntimeException('SHAKE256 failed');
            }
            return \FFI::string($out, $outLen);
        } finally {
            $f->EVP_MD_CTX_free($ctx);
        }
    }
}
