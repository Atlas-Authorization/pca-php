<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * ML-KEM-768 (FIPS 203) through OpenSSL >= 3.5 libcrypto (ext-ffi): key generation from a caller-supplied 64-byte seed (d || z) and
 * encapsulation from a caller-supplied 32-byte message (the "ikme" parameter), so the OT transcripts are reproducible from a seeded
 * stream. Library paths come from OpensslPq::candidates() (ATLAS_PCA_LIBCRYPTO first). available() is a real probe, no version gate;
 * every other call throws when libcrypto refuses (never returns a wrong secret).
 */
final class MpcMlKem768
{
    public const MSG_BYTES = 32;
    public const KEYGEN_SEED_BYTES = 64;
    public const PUBLIC_KEY_BYTES = 1184;
    public const CIPHERTEXT_BYTES = 1088;
    public const SECRET_BYTES = 32;

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
            typedef struct { const char* key; unsigned int data_type; void* data; size_t data_size; size_t return_size; } OSSL_PARAM;
            void* EVP_PKEY_CTX_new_from_name(void* libctx, const char* name, const char* propq);
            void* EVP_PKEY_CTX_new_from_pkey(void* libctx, void* pkey, const char* propq);
            int EVP_PKEY_CTX_set_params(void* ctx, const OSSL_PARAM* params);
            void EVP_PKEY_CTX_free(void* ctx);
            int EVP_PKEY_keygen_init(void* ctx);
            int EVP_PKEY_generate(void* ctx, void** ppkey);
            int EVP_PKEY_get_raw_public_key(const void* pkey, unsigned char* pub, size_t* len);
            void* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const unsigned char* key, size_t keylen);
            void EVP_PKEY_free(void* pkey);
            int EVP_PKEY_encapsulate_init(void* ctx, const OSSL_PARAM* params);
            int EVP_PKEY_encapsulate(void* ctx, unsigned char* wrapped, size_t* wrappedlen, unsigned char* genkey, size_t* genkeylen);
            int EVP_PKEY_decapsulate_init(void* ctx, const OSSL_PARAM* params);
            int EVP_PKEY_decapsulate(void* ctx, unsigned char* unwrapped, size_t* unwrappedlen, const unsigned char* wrapped, size_t wrappedlen);
            CDEF;
        foreach (OpensslPq::candidates() as $path) {
            try {
                $f = \FFI::cdef($cdef, $path);
                $r = self::probe($f);
                if ($r) {
                    return self::$ffi = $f;
                }
            } catch (\Throwable) {
                // next candidate
            }
        }
        return null;
    }

    private static function probe(\FFI $f): bool
    {
        try {
            $seed = str_repeat("\x01", self::KEYGEN_SEED_BYTES);
            $a = self::keygenWith($f, $seed);
            $e = self::encapsulateWith($f, $a['publicKey'], str_repeat("\x02", self::MSG_BYTES));
            $ss = self::decapsulateWith($f, $e['cipherText'], $a['pkey']);
            $f->EVP_PKEY_free($a['pkey']);
            return $ss === $e['sharedSecret'];
        } catch (\Throwable) {
            return false;
        }
    }

    /** True iff a libcrypto with ML-KEM-768 (seeded keygen, deterministic encapsulation) is loadable. */
    public static function available(): bool
    {
        return self::ffi() !== null;
    }

    private static function f(): \FFI
    {
        return self::ffi() ?? throw new \RuntimeException('ML-KEM-768 needs ext-ffi and OpenSSL >= 3.5 (set ATLAS_PCA_LIBCRYPTO)');
    }

    /** One octet-string OSSL_PARAM (plus end marker); returns [params, keep-alive buffers]. */
    private static function param(\FFI $f, string $key, string $data): array
    {
        $k = $f->new('char[' . (strlen($key) + 1) . ']');
        \FFI::memcpy($k, $key, strlen($key));
        $buf = $f->new('unsigned char[' . strlen($data) . ']');
        \FFI::memcpy($buf, $data, strlen($data));
        $p = $f->new('OSSL_PARAM[2]');
        $p[0]->key = $f->cast('const char*', \FFI::addr($k[0]));
        $p[0]->data_type = 5; // OSSL_PARAM_OCTET_STRING
        $p[0]->data = \FFI::addr($buf[0]);
        $p[0]->data_size = strlen($data);
        return [$p, [$k, $buf]];
    }

    private static function bytes(\FFI $f, string $s): \FFI\CData
    {
        $b = $f->new('unsigned char[' . max(1, strlen($s)) . ']');
        \FFI::memcpy($b, $s, strlen($s));
        return $b;
    }

    /** @return array{publicKey:string,pkey:\FFI\CData} */
    private static function keygenWith(\FFI $f, string $seed64): array
    {
        $ctx = $f->EVP_PKEY_CTX_new_from_name(null, 'ML-KEM-768', null);
        if ($ctx === null || \FFI::isNull($ctx)) {
            throw new \RuntimeException('ML-KEM-768 unavailable');
        }
        try {
            [$params, $keep] = self::param($f, 'seed', $seed64);
            if ($f->EVP_PKEY_keygen_init($ctx) !== 1 || $f->EVP_PKEY_CTX_set_params($ctx, \FFI::addr($params[0])) !== 1) {
                throw new \RuntimeException('ML-KEM-768 keygen refused the seed');
            }
            $pp = $f->new('void*[1]');
            if ($f->EVP_PKEY_generate($ctx, \FFI::addr($pp[0])) !== 1 || \FFI::isNull($pp[0])) {
                throw new \RuntimeException('ML-KEM-768 keygen failed');
            }
        } finally {
            $f->EVP_PKEY_CTX_free($ctx);
        }
        $pkey = $pp[0];
        $buf = $f->new('unsigned char[' . self::PUBLIC_KEY_BYTES . ']');
        $len = $f->new('size_t[1]');
        $len[0] = self::PUBLIC_KEY_BYTES;
        if ($f->EVP_PKEY_get_raw_public_key($pkey, $buf, \FFI::addr($len[0])) !== 1 || (int) $len[0] !== self::PUBLIC_KEY_BYTES) {
            $f->EVP_PKEY_free($pkey);
            throw new \RuntimeException('ML-KEM-768 public key export failed');
        }
        return ['publicKey' => \FFI::string($buf, self::PUBLIC_KEY_BYTES), 'pkey' => $pkey];
    }

    /** @return array{cipherText:string,sharedSecret:string} */
    private static function encapsulateWith(\FFI $f, string $publicKey, string $msg32): array
    {
        $pk = $f->EVP_PKEY_new_raw_public_key_ex(null, 'ML-KEM-768', null, self::bytes($f, $publicKey), strlen($publicKey));
        if ($pk === null || \FFI::isNull($pk)) {
            throw new \RuntimeException('ml-kem encapsulate: invalid public key');
        }
        try {
            $ctx = $f->EVP_PKEY_CTX_new_from_pkey(null, $pk, null);
            if ($ctx === null || \FFI::isNull($ctx)) {
                throw new \RuntimeException('ml-kem encapsulate: no context');
            }
            try {
                [$params, $keep] = self::param($f, 'ikme', $msg32);
                if ($f->EVP_PKEY_encapsulate_init($ctx, \FFI::addr($params[0])) !== 1) {
                    throw new \RuntimeException('ml-kem encapsulate: init refused');
                }
                $ct = $f->new('unsigned char[' . self::CIPHERTEXT_BYTES . ']');
                $ss = $f->new('unsigned char[' . self::SECRET_BYTES . ']');
                $cl = $f->new('size_t[1]');
                $sl = $f->new('size_t[1]');
                $cl[0] = self::CIPHERTEXT_BYTES;
                $sl[0] = self::SECRET_BYTES;
                if ($f->EVP_PKEY_encapsulate($ctx, $ct, \FFI::addr($cl[0]), $ss, \FFI::addr($sl[0])) !== 1
                    || (int) $cl[0] !== self::CIPHERTEXT_BYTES || (int) $sl[0] !== self::SECRET_BYTES) {
                    throw new \RuntimeException('ml-kem encapsulate failed');
                }
                return ['cipherText' => \FFI::string($ct, self::CIPHERTEXT_BYTES), 'sharedSecret' => \FFI::string($ss, self::SECRET_BYTES)];
            } finally {
                $f->EVP_PKEY_CTX_free($ctx);
            }
        } finally {
            $f->EVP_PKEY_free($pk);
        }
    }

    private static function decapsulateWith(\FFI $f, string $cipherText, \FFI\CData $pkey): string
    {
        if (strlen($cipherText) !== self::CIPHERTEXT_BYTES) {
            throw new \InvalidArgumentException('ml-kem decapsulate: ciphertext must be exactly ' . self::CIPHERTEXT_BYTES . ' bytes');
        }
        $ctx = $f->EVP_PKEY_CTX_new_from_pkey(null, $pkey, null);
        if ($ctx === null || \FFI::isNull($ctx)) {
            throw new \RuntimeException('ml-kem decapsulate: no context');
        }
        try {
            if ($f->EVP_PKEY_decapsulate_init($ctx, null) !== 1) {
                throw new \RuntimeException('ml-kem decapsulate: init refused');
            }
            $ss = $f->new('unsigned char[' . self::SECRET_BYTES . ']');
            $sl = $f->new('size_t[1]');
            $sl[0] = self::SECRET_BYTES;
            if ($f->EVP_PKEY_decapsulate($ctx, $ss, \FFI::addr($sl[0]), self::bytes($f, $cipherText), strlen($cipherText)) !== 1 || (int) $sl[0] !== self::SECRET_BYTES) {
                throw new \RuntimeException('ml-kem decapsulate failed');
            }
            return \FFI::string($ss, self::SECRET_BYTES);
        } finally {
            $f->EVP_PKEY_CTX_free($ctx);
        }
    }

    /**
     * @return array{publicKey:string,secretKey:\FFI\CData} the 1184-byte encapsulation key and an opaque handle (kept alive by the
     * array; freed with free() or at process end)
     */
    public static function keygen(string $seed64): array
    {
        if (strlen($seed64) !== self::KEYGEN_SEED_BYTES) {
            throw new \InvalidArgumentException('ml-kem keygen: seed must be exactly 64 bytes');
        }
        $k = self::keygenWith(self::f(), $seed64);
        return ['publicKey' => $k['publicKey'], 'secretKey' => $k['pkey']];
    }

    /** @return array{cipherText:string,sharedSecret:string} */
    public static function encapsulate(string $publicKey, string $msg32): array
    {
        if (strlen($msg32) !== self::MSG_BYTES) {
            throw new \InvalidArgumentException('ml-kem encapsulate: message must be exactly 32 bytes');
        }
        if (strlen($publicKey) !== self::PUBLIC_KEY_BYTES) {
            throw new \InvalidArgumentException('ml-kem encapsulate: public key must be exactly ' . self::PUBLIC_KEY_BYTES . ' bytes');
        }
        return self::encapsulateWith(self::f(), $publicKey, $msg32);
    }

    public static function decapsulate(string $cipherText, \FFI\CData $secretKey): string
    {
        return self::decapsulateWith(self::f(), $cipherText, $secretKey);
    }

    public static function free(\FFI\CData $secretKey): void
    {
        self::ffi()?->EVP_PKEY_free($secretKey);
    }
}
