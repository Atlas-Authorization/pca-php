<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/OpensslPq.php';

/**
 * ML-KEM-768 and ML-KEM-1024 (FIPS 203) through OpenSSL >= 3.5 libcrypto (ext-ffi) for the KEM module ({@see Kem}): seeded key
 * generation (d || z), derandomised encapsulation (the "ikme" parameter) and decapsulation from an EXPANDED decapsulation key
 * (FIPS 203 dk, the "priv" parameter). The expanded key is imported in a private library context whose default provider has the
 * pairwise consistency test switched off (the provider setting `ml-kem.import_pct_type` = none), so a damaged dk is answered with
 * the FIPS 203 implicit-rejection secret exactly as the algorithm defines, instead of being refused at import. Library paths come from OpensslPq::candidates() (ATLAS_PCA_LIBCRYPTO
 * first); available() is a real probe. Every failing libcrypto call throws; a wrong secret is never returned.
 */
final class OpensslMlKem
{
    public const MSG_BYTES = 32;
    public const SEED_BYTES = 64;
    public const SECRET_BYTES = 32;

    /** level => [OpenSSL name, k, encapsulation key bytes, ciphertext bytes, expanded decapsulation key bytes] */
    public const LEVELS = [
        768 => ['ML-KEM-768', 3, 1184, 1088, 2400],
        1024 => ['ML-KEM-1024', 4, 1568, 1568, 3168],
    ];

    private const SELECT_KEYPAIR = 0x87; // EVP_PKEY_KEYPAIR
    private const OCTETS = 5;            // OSSL_PARAM_OCTET_STRING

    private static ?\FFI $ffi = null;
    private static bool $tried = false;
    /** The private library context of the expanded-key import (kept for the life of the process). */
    private static ?\FFI\CData $importCtx = null;

    /**
     * A private OpenSSL library context whose default provider has `ml-kem.import_pct_type = none`. That switch is a PROVIDER
     * configuration parameter (a fromdata parameter of that name is ignored), so it is set on a context of our own and the
     * process-wide one keeps its default.
     */
    private static function importCtx(\FFI $f): \FFI\CData
    {
        if (self::$importCtx !== null) {
            return self::$importCtx;
        }
        $ctx = $f->OSSL_LIB_CTX_new();
        if ($ctx === null || \FFI::isNull($ctx)) {
            throw new \RuntimeException('ml-kem: no library context');
        }
        $prov = $f->OSSL_PROVIDER_load($ctx, 'default');
        if ($prov === null || \FFI::isNull($prov) || $f->OSSL_PROVIDER_add_conf_parameter($prov, 'ml-kem.import_pct_type', 'none') !== 1) {
            $f->OSSL_LIB_CTX_free($ctx);
            throw new \RuntimeException('ml-kem: the provider refused ml-kem.import_pct_type');
        }
        return self::$importCtx = $ctx;
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
            void* EVP_PKEY_CTX_new_from_name(void* libctx, const char* name, const char* propq);
            void* EVP_PKEY_CTX_new_from_pkey(void* libctx, void* pkey, const char* propq);
            int EVP_PKEY_CTX_set_params(void* ctx, const OSSL_PARAM* params);
            void EVP_PKEY_CTX_free(void* ctx);
            int EVP_PKEY_keygen_init(void* ctx);
            int EVP_PKEY_generate(void* ctx, void** ppkey);
            int EVP_PKEY_fromdata_init(void* ctx);
            int EVP_PKEY_fromdata(void* ctx, void** ppkey, int selection, OSSL_PARAM* params);
            int EVP_PKEY_get_raw_public_key(const void* pkey, unsigned char* pub, size_t* len);
            int EVP_PKEY_get_octet_string_param(const void* pkey, const char* key_name, unsigned char* buf, size_t max_buf_sz, size_t* out_len);
            void* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const unsigned char* key, size_t keylen);
            void EVP_PKEY_free(void* pkey);
            int EVP_PKEY_encapsulate_init(void* ctx, const OSSL_PARAM* params);
            int EVP_PKEY_encapsulate(void* ctx, unsigned char* wrapped, size_t* wrappedlen, unsigned char* genkey, size_t* genkeylen);
            int EVP_PKEY_decapsulate_init(void* ctx, const OSSL_PARAM* params);
            int EVP_PKEY_decapsulate(void* ctx, unsigned char* unwrapped, size_t* unwrappedlen, const unsigned char* wrapped, size_t wrappedlen);
            void* OSSL_LIB_CTX_new(void);
            void OSSL_LIB_CTX_free(void* ctx);
            void* OSSL_PROVIDER_load(void* libctx, const char* name);
            int OSSL_PROVIDER_add_conf_parameter(void* prov, const char* name, const char* value);
            CDEF;
        foreach (OpensslPq::candidates() as $path) {
            try {
                $f = \FFI::cdef($cdef, $path);
                self::$importCtx = null;
                if (self::probe($f)) {
                    return self::$ffi = $f;
                }
            } catch (\Throwable) {
                // next candidate
            }
        }
        return null;
    }

    /** A real round trip at both levels, including the expanded-dk import: a library without any of it is never reported available. */
    private static function probe(\FFI $f): bool
    {
        try {
            foreach (array_keys(self::LEVELS) as $level) {
                $k = self::keygenWith($f, $level, str_repeat("\x01", self::SEED_BYTES));
                $e = self::encapsulateWith($f, $level, $k['publicKey'], str_repeat("\x02", self::MSG_BYTES));
                if (self::decapsulateWith($f, $level, $e['cipherText'], $k['secretKey']) !== $e['sharedSecret']) {
                    return false;
                }
            }
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** True iff a libcrypto with ML-KEM-768 and -1024 (seeded keygen, deterministic encapsulation, expanded-dk import) is loadable. */
    public static function available(): bool
    {
        return self::ffi() !== null;
    }

    private static function f(): \FFI
    {
        return self::ffi() ?? throw new \RuntimeException('ML-KEM needs ext-ffi and OpenSSL >= 3.5 (set ATLAS_PCA_LIBCRYPTO)');
    }

    /**
     * An OSSL_PARAM list (plus the end marker) over copies of the values; returns [params, buffers the list points into].
     * @param list<array{0:string,1:int,2:string}> $items [name, OSSL_PARAM type, value]
     * @return array{0:\FFI\CData,1:list<\FFI\CData>}
     */
    private static function params(\FFI $f, array $items): array
    {
        $p = $f->new('OSSL_PARAM[' . (count($items) + 1) . ']'); // the last entry stays zero: the end marker
        $keep = [];
        foreach ($items as $i => [$name, $type, $value]) {
            $k = $f->new('char[' . (strlen($name) + 1) . ']');
            \FFI::memcpy($k, $name, strlen($name));
            $buf = $f->new('unsigned char[' . (strlen($value) + 1) . ']'); // zero-filled: a string value stays NUL-terminated
            \FFI::memcpy($buf, $value, strlen($value));
            $p[$i]->key = $f->cast('const char*', \FFI::addr($k[0]));
            $p[$i]->data_type = $type;
            $p[$i]->data = \FFI::addr($buf[0]);
            $p[$i]->data_size = strlen($value);
            $keep[] = $k;
            $keep[] = $buf;
        }
        return [$p, $keep];
    }

    private static function bytes(\FFI $f, string $s): \FFI\CData
    {
        $b = $f->new('unsigned char[' . max(1, strlen($s)) . ']');
        \FFI::memcpy($b, $s, strlen($s));
        return $b;
    }

    /** @return array{publicKey:string,secretKey:string} the encapsulation key and the expanded FIPS 203 decapsulation key */
    private static function keygenWith(\FFI $f, int $level, string $seed64): array
    {
        [$name, , $ekLen, , $dkLen] = self::LEVELS[$level];
        $ctx = $f->EVP_PKEY_CTX_new_from_name(null, $name, null);
        if ($ctx === null || \FFI::isNull($ctx)) {
            throw new \RuntimeException("$name unavailable");
        }
        $keep = [];
        try {
            [$params, $keep] = self::params($f, [['seed', self::OCTETS, $seed64]]);
            if ($f->EVP_PKEY_keygen_init($ctx) !== 1 || $f->EVP_PKEY_CTX_set_params($ctx, \FFI::addr($params[0])) !== 1) {
                throw new \RuntimeException("$name keygen refused the seed");
            }
            $pp = $f->new('void*[1]');
            if ($f->EVP_PKEY_generate($ctx, \FFI::addr($pp[0])) !== 1 || \FFI::isNull($pp[0])) {
                throw new \RuntimeException("$name keygen failed");
            }
        } finally {
            if (isset($keep[1])) {
                \FFI::memset($keep[1], 0, strlen($seed64)); // the seed is the private key
            }
            $f->EVP_PKEY_CTX_free($ctx);
        }
        $pkey = $pp[0];
        try {
            $pub = $f->new('unsigned char[' . $ekLen . ']');
            $len = $f->new('size_t[1]');
            $len[0] = $ekLen;
            if ($f->EVP_PKEY_get_raw_public_key($pkey, $pub, \FFI::addr($len[0])) !== 1 || (int) $len[0] !== $ekLen) {
                throw new \RuntimeException("$name public key export failed");
            }
            $dk = $f->new('unsigned char[' . $dkLen . ']');
            $dl = $f->new('size_t[1]');
            if ($f->EVP_PKEY_get_octet_string_param($pkey, 'priv', $dk, $dkLen, \FFI::addr($dl[0])) !== 1 || (int) $dl[0] !== $dkLen) {
                throw new \RuntimeException("$name decapsulation key export failed");
            }
            $out = ['publicKey' => \FFI::string($pub, $ekLen), 'secretKey' => \FFI::string($dk, $dkLen)];
            \FFI::memset($dk, 0, $dkLen);
            return $out;
        } finally {
            $f->EVP_PKEY_free($pkey);
        }
    }

    /** @return array{cipherText:string,sharedSecret:string} */
    private static function encapsulateWith(\FFI $f, int $level, string $ek, string $msg32): array
    {
        [$name, , $ekLen, $ctLen] = self::LEVELS[$level];
        $pk = $f->EVP_PKEY_new_raw_public_key_ex(null, $name, null, self::bytes($f, $ek), strlen($ek));
        if ($pk === null || \FFI::isNull($pk)) {
            throw new \RuntimeException('ml-kem encapsulate: invalid encapsulation key');
        }
        try {
            $ctx = $f->EVP_PKEY_CTX_new_from_pkey(null, $pk, null);
            if ($ctx === null || \FFI::isNull($ctx)) {
                throw new \RuntimeException('ml-kem encapsulate: no context');
            }
            try {
                [$params, $keep] = self::params($f, [['ikme', self::OCTETS, $msg32]]);
                if ($f->EVP_PKEY_encapsulate_init($ctx, \FFI::addr($params[0])) !== 1) {
                    throw new \RuntimeException('ml-kem encapsulate: init refused');
                }
                $ct = $f->new('unsigned char[' . $ctLen . ']');
                $ss = $f->new('unsigned char[' . self::SECRET_BYTES . ']');
                $cl = $f->new('size_t[1]');
                $sl = $f->new('size_t[1]');
                $cl[0] = $ctLen;
                $sl[0] = self::SECRET_BYTES;
                if ($f->EVP_PKEY_encapsulate($ctx, $ct, \FFI::addr($cl[0]), $ss, \FFI::addr($sl[0])) !== 1
                    || (int) $cl[0] !== $ctLen || (int) $sl[0] !== self::SECRET_BYTES) {
                    throw new \RuntimeException('ml-kem encapsulate failed');
                }
                return ['cipherText' => \FFI::string($ct, $ctLen), 'sharedSecret' => \FFI::string($ss, self::SECRET_BYTES)];
            } finally {
                $f->EVP_PKEY_CTX_free($ctx);
            }
        } finally {
            $f->EVP_PKEY_free($pk);
        }
    }

    /**
     * FIPS 203 ByteDecode_12 reduces each 12-bit coefficient of the decryption half (the first 384 * k bytes of the decapsulation key)
     * mod q = 3329, so a coefficient >= q names the same key as its residue. OpenSSL range-checks on import instead; the half is
     * re-encoded with reduced coefficients (the encapsulation key, its hash and z are left as they are).
     */
    public static function canonicalDkPke(string $dk, int $k): string
    {
        $n = 384 * $k;
        for ($i = 0; $i + 2 < $n; $i += 3) {
            $b0 = ord($dk[$i]);
            $b1 = ord($dk[$i + 1]);
            $b2 = ord($dk[$i + 2]);
            $c0 = (($b0 | (($b1 & 0x0F) << 8)) % 3329);
            $c1 = ((($b1 >> 4) | ($b2 << 4)) % 3329);
            $dk[$i] = chr($c0 & 0xFF);
            $dk[$i + 1] = chr((($c0 >> 8) & 0x0F) | (($c1 & 0x0F) << 4));
            $dk[$i + 2] = chr(($c1 >> 4) & 0xFF);
        }
        return $dk;
    }

    private static function decapsulateWith(\FFI $f, int $level, string $ct, string $dk): string
    {
        [$name, , , $ctLen, $dkLen] = self::LEVELS[$level];
        if (strlen($ct) !== $ctLen) {
            throw new \InvalidArgumentException("ml-kem decapsulate: ciphertext must be exactly $ctLen bytes");
        }
        if (strlen($dk) !== $dkLen) {
            throw new \InvalidArgumentException("ml-kem decapsulate: decapsulation key must be exactly $dkLen bytes");
        }
        $dk = self::canonicalDkPke($dk, self::LEVELS[$level][1]);
        $lib = self::importCtx($f);
        $ictx = $f->EVP_PKEY_CTX_new_from_name($lib, $name, null);
        if ($ictx === null || \FFI::isNull($ictx)) {
            throw new \RuntimeException("$name unavailable");
        }
        $pkey = null;
        $keep = [];
        try {
            // imported in the private context (pairwise consistency test off): a damaged dk gives the FIPS 203 rejection secret, not an import failure
            [$params, $keep] = self::params($f, [['priv', self::OCTETS, $dk]]);
            $pp = $f->new('void*[1]');
            if ($f->EVP_PKEY_fromdata_init($ictx) !== 1
                || $f->EVP_PKEY_fromdata($ictx, \FFI::addr($pp[0]), self::SELECT_KEYPAIR, \FFI::addr($params[0])) !== 1 || \FFI::isNull($pp[0])) {
                throw new \InvalidArgumentException('ml-kem decapsulate: invalid decapsulation key');
            }
            $pkey = $pp[0];
        } finally {
            if (isset($keep[1])) {
                \FFI::memset($keep[1], 0, strlen($dk)); // the decapsulation key is the private key
            }
            $f->EVP_PKEY_CTX_free($ictx);
        }
        try {
            $ctx = $f->EVP_PKEY_CTX_new_from_pkey($lib, $pkey, null);
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
                if ($f->EVP_PKEY_decapsulate($ctx, $ss, \FFI::addr($sl[0]), self::bytes($f, $ct), strlen($ct)) !== 1 || (int) $sl[0] !== self::SECRET_BYTES) {
                    throw new \RuntimeException('ml-kem decapsulate failed');
                }
                return \FFI::string($ss, self::SECRET_BYTES);
            } finally {
                $f->EVP_PKEY_CTX_free($ctx);
            }
        } finally {
            $f->EVP_PKEY_free($pkey);
        }
    }

    private static function level(int $level): void
    {
        if (!isset(self::LEVELS[$level])) {
            throw new \InvalidArgumentException("ML-KEM level must be 768 or 1024, got $level");
        }
    }

    /** @return array{publicKey:string,secretKey:string} the encapsulation key and the expanded decapsulation key of the 64-byte seed d || z */
    public static function keygen(int $level, string $seed64): array
    {
        self::level($level);
        if (strlen($seed64) !== self::SEED_BYTES) {
            throw new \InvalidArgumentException('ml-kem keygen: seed must be exactly 64 bytes');
        }
        return self::keygenWith(self::f(), $level, $seed64);
    }

    /** @return array{cipherText:string,sharedSecret:string} */
    public static function encapsulate(int $level, string $ek, string $msg32): array
    {
        self::level($level);
        if (strlen($msg32) !== self::MSG_BYTES) {
            throw new \InvalidArgumentException('ml-kem encapsulate: message must be exactly 32 bytes');
        }
        if (strlen($ek) !== self::LEVELS[$level][2]) {
            throw new \InvalidArgumentException('ml-kem encapsulate: encapsulation key must be exactly ' . self::LEVELS[$level][2] . ' bytes');
        }
        return self::encapsulateWith(self::f(), $level, $ek, $msg32);
    }

    /** The shared secret, or the implicit-rejection secret for a ciphertext that does not belong to `$dk` (never a failure for a well-sized input). */
    public static function decapsulate(int $level, string $ct, string $dk): string
    {
        self::level($level);
        return self::decapsulateWith(self::f(), $level, $ct, $dk);
    }
}
