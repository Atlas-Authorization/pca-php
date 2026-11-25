<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/**
 * The endemic OT's lattice core: Kyber-768 K-PKE keygen, CPA encrypt and decrypt, ring add and subtract, and the hash to a uniform ring vector.
 * Every operation is the audited pqc_kyber reference reached through the small C library liblweot (pca_lwe_ot.h, built from the flagship's crate
 * with cargo build --features capi) over ext-ffi; nothing lattice-related is implemented here. Point ATLAS_PCA_LIBLWEOT at it (needs
 * ffi.enable=true or preload). A wrong size is refused before the call and again by the library.
 */
final class MpcLweLattice
{
    public const PK_BYTES = 1184;
    public const SK_BYTES = 1152;
    public const CT_BYTES = 1088;
    public const TVEC_BYTES = 1152;
    public const SYM_BYTES = 32;
    public const HASHIN_CAP = 4096;

    private const CDEF = <<<'C'
        size_t lweot_len_pk(void); size_t lweot_len_sk(void); size_t lweot_len_ct(void); size_t lweot_len_tvec(void);
        size_t lweot_len_sym(void); size_t lweot_hashin_cap(void);
        int32_t lweot_kpke_keygen_fips203(const uint8_t *seed, size_t seed_len, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);
        int32_t lweot_kpke_keygen(const uint8_t *seed, size_t seed_len, uint8_t *pk, size_t pk_len, uint8_t *sk, size_t sk_len);
        int32_t lweot_kpke_enc(const uint8_t *pk, size_t pk_len, const uint8_t *msg, size_t msg_len, const uint8_t *coins, size_t coins_len, uint8_t *ct, size_t ct_len);
        int32_t lweot_kpke_dec(const uint8_t *sk, size_t sk_len, const uint8_t *ct, size_t ct_len, uint8_t *msg, size_t msg_len);
        int32_t lweot_ring_add(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out, size_t out_len);
        int32_t lweot_ring_sub(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len, uint8_t *out, size_t out_len);
        int32_t lweot_hash_to_ring(const uint8_t *input, size_t input_len, uint8_t *out, size_t out_len);
        C;

    private static ?\FFI $lib = null;

    /** True when ext-ffi and liblweot are usable. */
    public static function available(): bool
    {
        try {
            self::lib();
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    private static function lib(): \FFI
    {
        if (self::$lib === null) {
            if (!class_exists(\FFI::class)) {
                throw new \RuntimeException('the endemic LWE OT needs ext-ffi');
            }
            $path = getenv('ATLAS_PCA_LIBLWEOT');
            $lib = \FFI::cdef(self::CDEF, $path !== false && $path !== '' ? $path : (NativeDir::lib('lweot') ?? 'liblweot.so'));
            // the sizes this class hard-codes must be the ones the library was built with, or nothing is safe
            $got = [$lib->lweot_len_pk(), $lib->lweot_len_sk(), $lib->lweot_len_ct(), $lib->lweot_len_tvec(), $lib->lweot_len_sym(), $lib->lweot_hashin_cap()];
            if ($got !== [self::PK_BYTES, self::SK_BYTES, self::CT_BYTES, self::TVEC_BYTES, self::SYM_BYTES, self::HASHIN_CAP]) {
                throw new \RuntimeException('liblweot reports different Kyber-768 sizes');
            }
            self::$lib = $lib;
        }
        return self::$lib;
    }

    private static function need(string $b, int $len, string $what): void
    {
        if (strlen($b) !== $len) {
            throw new \InvalidArgumentException("lattice: $what must be exactly $len bytes");
        }
    }

    private static function in(string $b): \FFI\CData
    {
        $buf = self::lib()->new('uint8_t[' . max(strlen($b), 1) . ']');
        if ($b !== '') {
            \FFI::memcpy($buf, $b, strlen($b));
        }
        return $buf;
    }

    private static function out(int $n): \FFI\CData
    {
        return self::lib()->new("uint8_t[$n]");
    }

    private static function ok(int $rc, string $op): void
    {
        if ($rc !== 0) {
            throw new \RuntimeException("lattice: $op refused ($rc)");
        }
    }

    /** @return array{0:string,1:string} [public key, secret key] of Kyber-768 K-PKE, deterministic in the 32-byte seed */
    public static function keygen(string $seed): array
    {
        self::need($seed, self::SYM_BYTES, 'seed');
        $pk = self::out(self::PK_BYTES);
        $sk = self::out(self::SK_BYTES);
        self::ok(self::lib()->lweot_kpke_keygen(self::in($seed), self::SYM_BYTES, $pk, self::PK_BYTES, $sk, self::SK_BYTES), 'keygen');
        return [\FFI::string($pk, self::PK_BYTES), \FFI::string($sk, self::SK_BYTES)];
    }

    /** @return array{0:string,1:string} [public key, secret key] exactly as FIPS 203 Algorithm 13 derives K-PKE.KeyGen(d): the derivation the endemic receiver uses */
    public static function keygenFips203(string $seed): array
    {
        self::need($seed, self::SYM_BYTES, 'seed');
        $pk = self::out(self::PK_BYTES);
        $sk = self::out(self::SK_BYTES);
        self::ok(self::lib()->lweot_kpke_keygen_fips203(self::in($seed), self::SYM_BYTES, $pk, self::PK_BYTES, $sk, self::SK_BYTES), 'keygen (FIPS 203)');
        return [\FFI::string($pk, self::PK_BYTES), \FFI::string($sk, self::SK_BYTES)];
    }

    public static function enc(string $publicKey, string $message, string $coins): string
    {
        self::need($publicKey, self::PK_BYTES, 'public key');
        self::need($message, self::SYM_BYTES, 'message');
        self::need($coins, self::SYM_BYTES, 'coins');
        $ct = self::out(self::CT_BYTES);
        self::ok(self::lib()->lweot_kpke_enc(self::in($publicKey), self::PK_BYTES, self::in($message), self::SYM_BYTES, self::in($coins), self::SYM_BYTES, $ct, self::CT_BYTES), 'enc');
        return \FFI::string($ct, self::CT_BYTES);
    }

    public static function dec(string $secretKey, string $ciphertext): string
    {
        self::need($secretKey, self::SK_BYTES, 'secret key');
        self::need($ciphertext, self::CT_BYTES, 'ciphertext');
        $m = self::out(self::SYM_BYTES);
        self::ok(self::lib()->lweot_kpke_dec(self::in($secretKey), self::SK_BYTES, self::in($ciphertext), self::CT_BYTES, $m, self::SYM_BYTES), 'dec');
        return \FFI::string($m, self::SYM_BYTES);
    }

    public static function ringAdd(string $a, string $b): string
    {
        return self::ring(true, $a, $b);
    }

    public static function ringSub(string $a, string $b): string
    {
        return self::ring(false, $a, $b);
    }

    private static function ring(bool $add, string $a, string $b): string
    {
        self::need($a, self::TVEC_BYTES, 'a');
        self::need($b, self::TVEC_BYTES, 'b');
        $o = self::out(self::TVEC_BYTES);
        $l = self::lib();
        $rc = $add
            ? $l->lweot_ring_add(self::in($a), self::TVEC_BYTES, self::in($b), self::TVEC_BYTES, $o, self::TVEC_BYTES)
            : $l->lweot_ring_sub(self::in($a), self::TVEC_BYTES, self::in($b), self::TVEC_BYTES, $o, self::TVEC_BYTES);
        self::ok($rc, $add ? 'ring add' : 'ring sub');
        return \FFI::string($o, self::TVEC_BYTES);
    }

    /** SHAKE128 then the FIPS 203 SampleNTT sampler: a uniform ring vector. At most 4096 input bytes. */
    public static function hashToRing(string $input): string
    {
        if (strlen($input) > self::HASHIN_CAP) {
            throw new \InvalidArgumentException('lattice: hash input must be at most ' . self::HASHIN_CAP . ' bytes');
        }
        $o = self::out(self::TVEC_BYTES);
        self::ok(self::lib()->lweot_hash_to_ring(self::in($input), strlen($input), $o, self::TVEC_BYTES), 'hash to ring');
        return \FFI::string($o, self::TVEC_BYTES);
    }
}
