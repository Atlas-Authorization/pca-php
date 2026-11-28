<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/**
 * Thin helpers over supranational blst (through ext-ffi) shared by the pairing packages (bbs, abe): points as C-owned buffers
 * (G1 or G2, selected by the group argument 1 / 2), scalar arithmetic mod r on GMP integers, RFC 9380 expand_message_xmd (SHA-256),
 * strict canonical decoders and the GT group (a small shim over blst's public API, native/pca_gt.c). No pairing, field or curve
 * arithmetic is implemented here: every point and pairing operation is a blst call.
 *
 * The library is bound lazily; a missing one throws RuntimeException (never a "bad input" result). Point it at the shared library
 * with PCA_BLST_LIB (blst built together with the shim: see the pairing workflow), or put libblst on the loader path.
 *
 * shortcut: scalar-field add/mul/inverse is GMP arithmetic, which is not constant time. Point multiplication (the expensive,
 * key-dependent part) is blst's constant-time implementation; move to blst's scalar functions if a deployment needs the scalar
 * steps constant time as well.
 */
final class Bls12
{
    public const R_HEX = '73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001';
    public const GT_BYTES = 576;
    /** group => [blst prefix, Jacobian size, affine size, compressed size, name] */
    private const GROUPS = [
        1 => ['p1', 144, 96, 48, 'G1'],
        2 => ['p2', 288, 192, 96, 'G2'],
    ];

    private const CDEF = <<<'CDEF'
        void blst_scalar_from_bendian(void *out, const char *a);
        void blst_p1_mult(void *out, const void *a, const void *scalar, size_t nbits);
        void blst_p1_add_or_double(void *out, const void *a, const void *b);
        void blst_p1_cneg(void *p, bool cbit);
        void blst_p1_compress(void *out, const void *in);
        int blst_p1_uncompress(void *out, const char *in);
        void blst_p1_from_affine(void *out, const void *in);
        void blst_p1_to_affine(void *out, const void *in);
        bool blst_p1_is_inf(const void *a);
        bool blst_p1_affine_in_g1(const void *p);
        bool blst_p1_affine_on_curve(const void *p);
        void blst_hash_to_g1(void *out, const char *msg, size_t len, const char *dst, size_t dstlen, const char *aug, size_t auglen);
        const uint8_t *blst_p1_generator(void);
        void blst_p2_mult(void *out, const void *a, const void *scalar, size_t nbits);
        void blst_p2_add_or_double(void *out, const void *a, const void *b);
        void blst_p2_cneg(void *p, bool cbit);
        void blst_p2_compress(void *out, const void *in);
        int blst_p2_uncompress(void *out, const char *in);
        void blst_p2_from_affine(void *out, const void *in);
        void blst_p2_to_affine(void *out, const void *in);
        bool blst_p2_is_inf(const void *a);
        bool blst_p2_affine_in_g2(const void *p);
        bool blst_p2_affine_on_curve(const void *p);
        const uint8_t *blst_p2_generator(void);
        void blst_miller_loop(void *ret, const void *q, const void *p);
        bool blst_fp12_finalverify(const void *a, const void *b);
        CDEF;
    // the GT shim (native/pca_gt.c), present only in a library built with it
    private const GT_CDEF = <<<'CDEF'
        int pca_gt_mul(void *out, const char *a, const char *b);
        int pca_gt_pow(void *out, const char *a, const char *k);
        int pca_gt_is_element(const char *a);
        int pca_gt_pairing(void *out, const char *g1s, const char *g2s, size_t n);
        CDEF;

    private static ?\FFI $ffi = null;
    private static ?\FFI $gt = null;
    private static ?string $libPath = null;
    private static ?\GMP $r = null;

    private static function lib(): \FFI
    {
        if (self::$ffi !== null) {
            return self::$ffi;
        }
        if (!extension_loaded('FFI')) {
            throw new \RuntimeException('BLS12-381 needs the FFI extension and a built libblst');
        }
        $paths = [];
        $env = getenv('PCA_BLST_LIB');
        if (is_string($env) && $env !== '') {
            $paths[] = $env;
        }
        $packaged = NativeDir::lib('blst');
        if ($packaged !== null) {
            $paths[] = $packaged; // after the override, before the system names
        }
        array_push($paths, 'libblst.so', 'libblst.dylib', 'blst.dll');
        if (self::$pathsHook !== null) {
            $paths = (self::$pathsHook)($paths);
        }
        foreach ($paths as $p) {
            try {
                $f = \FFI::cdef(self::CDEF, $p);
            } catch (\Throwable) {
                continue;
            }
            self::$libPath = $p;
            return self::$ffi = $f;
        }
        throw new \RuntimeException('BLS12-381 needs a built libblst (supranational/blst shared library; abe also needs the GT shim, set PCA_BLST_LIB)');
    }

    private static function gtLib(): \FFI
    {
        if (self::$gt !== null) {
            return self::$gt;
        }
        self::lib();
        try {
            return self::$gt = \FFI::cdef(self::GT_CDEF, self::$libPath);
        } catch (\Throwable $e) {
            throw new \RuntimeException('abe needs the GT shim (native/pca_gt.c) built into the library: ' . $e->getMessage());
        }
    }

    /** A zeroed C-owned buffer (zeroed memory is the point at infinity). */
    public static function buf(int $n): \FFI\CData
    {
        return self::lib()->new("uint8_t[$n]");
    }

    public static function r(): \GMP
    {
        return self::$r ??= gmp_init(self::R_HEX, 16);
    }

    // ---- scalars (GMP) ----

    public static function mod(\GMP $x): \GMP
    {
        return gmp_mod($x, self::r());
    }

    public static function add(\GMP $a, \GMP $b): \GMP
    {
        return self::mod(gmp_add($a, $b));
    }

    public static function sub(\GMP $a, \GMP $b): \GMP
    {
        return self::mod(gmp_sub($a, $b));
    }

    public static function mul(\GMP $a, \GMP $b): \GMP
    {
        return self::mod(gmp_mul($a, $b));
    }

    /** Fermat inverse x^(r-2) mod r (fixed public exponent); throws on zero */
    public static function inv(\GMP $x): \GMP
    {
        $v = self::mod($x);
        if (gmp_sign($v) === 0) {
            throw new \DivisionByZeroError('inverse of zero');
        }
        return gmp_powm($v, gmp_sub(self::r(), 2), self::r());
    }

    /** I2OSP: non-negative integer to fixed-length big-endian octets; throws when it does not fit */
    public static function i2osp(\GMP|int $n, int $len): string
    {
        $n = $n instanceof \GMP ? $n : gmp_init($n);
        $h = gmp_strval($n, 16);
        if (gmp_sign($n) < 0 || strlen($h) > 2 * $len) {
            throw new \InvalidArgumentException("integer does not fit $len octets");
        }
        return (string) hex2bin(str_pad($h, 2 * $len, '0', STR_PAD_LEFT));
    }

    public static function os2ip(string $bytes): \GMP
    {
        return $bytes === '' ? gmp_init(0) : gmp_init(bin2hex($bytes), 16);
    }

    /** expand_message_xmd with SHA-256 (RFC 9380 5.3.1); the DST must be at most 255 octets */
    public static function expandMessageXmd(string $msg, string $dst, int $len): string
    {
        $ell = intdiv($len + 31, 32);
        if ($len < 0 || $ell > 255 || $len > 65535 || strlen($dst) > 255) {
            throw new \InvalidArgumentException('expand_message_xmd: invalid length or DST');
        }
        $dstPrime = $dst . chr(strlen($dst));
        $b0 = hash('sha256', str_repeat("\0", 64) . $msg . pack('n', $len) . "\0" . $dstPrime, true);
        $bi = hash('sha256', $b0 . "\x01" . $dstPrime, true);
        $out = $bi;
        for ($i = 2; $i <= $ell; $i++) {
            $bi = hash('sha256', ($b0 ^ $bi) . chr($i) . $dstPrime, true);
            $out .= $bi;
        }
        return substr($out, 0, $len);
    }

    /** blst_scalar (32 bytes) for a value reduced mod r */
    public static function scalar(\GMP $s): \FFI\CData
    {
        $p = self::buf(32);
        self::lib()->blst_scalar_from_bendian($p, self::i2osp(self::mod($s), 32));
        return $p;
    }

    // ---- points: C-owned Jacobian buffers; every operation returns a new one ----

    /** the group tuple, or throws */
    private static function grp(int $g): array
    {
        return self::GROUPS[$g] ?? throw new \InvalidArgumentException('group must be 1 or 2');
    }

    private static function call(int $g, string $name, mixed ...$args): mixed
    {
        $f = 'blst_' . self::grp($g)[0] . '_' . $name;
        return self::lib()->$f(...$args);
    }

    /** the point at infinity */
    public static function identity(int $g): \FFI\CData
    {
        return self::buf(self::grp($g)[1]);
    }

    public static function pAdd(int $g, \FFI\CData $a, \FFI\CData $b): \FFI\CData
    {
        $out = self::identity($g);
        self::call($g, 'add_or_double', $out, $a, $b);
        return $out;
    }

    public static function pDup(int $g, \FFI\CData $a): \FFI\CData
    {
        $out = self::identity($g);
        \FFI::memcpy($out, $a, self::grp($g)[1]);
        return $out;
    }

    public static function pNeg(int $g, \FFI\CData $a): \FFI\CData
    {
        $out = self::pDup($g, $a);
        self::call($g, 'cneg', $out, true);
        return $out;
    }

    public static function pSub(int $g, \FFI\CData $a, \FFI\CData $b): \FFI\CData
    {
        return self::pAdd($g, $a, self::pNeg($g, $b));
    }

    /** k * P, the identity when k is zero mod r */
    public static function pMul(int $g, \FFI\CData $a, \GMP $k): \FFI\CData
    {
        $v = self::mod($k);
        $out = self::identity($g);
        if (gmp_sign($v) === 0) {
            return $out;
        }
        self::call($g, 'mult', $out, $a, self::scalar($v), 255);
        return $out;
    }

    public static function isInf(int $g, \FFI\CData $a): bool
    {
        return (bool) self::call($g, 'is_inf', $a);
    }

    public static function compress(int $g, \FFI\CData $a): string
    {
        $n = self::grp($g)[3];
        $out = self::buf($n);
        self::call($g, 'compress', $out, $a);
        return \FFI::string($out, $n);
    }

    public static function affine(int $g, \FFI\CData $a): \FFI\CData
    {
        $out = self::buf(self::grp($g)[2]);
        self::call($g, 'to_affine', $out, $a);
        return $out;
    }

    public static function pEq(int $g, \FFI\CData $a, \FFI\CData $b): bool
    {
        return self::compress($g, $a) === self::compress($g, $b);
    }

    /**
     * Strict compressed decoding: compression flag set, canonical, on curve, in the prime-order subgroup. The identity is allowed
     * (check it separately). Throws InvalidArgumentException otherwise.
     */
    public static function decode(int $g, mixed $bytes): \FFI\CData
    {
        [, , $affLen, $comp, $name] = self::grp($g);
        if (!is_string($bytes) || strlen($bytes) !== $comp || (ord($bytes[0]) & 0x80) === 0) {
            throw new \InvalidArgumentException("not a $comp-byte compressed $name point");
        }
        $aff = self::buf($affLen);
        if (self::call($g, 'uncompress', $aff, $bytes) !== 0) {
            throw new \InvalidArgumentException("invalid $name encoding");
        }
        if (!self::call($g, 'affine_on_curve', $aff) || !self::call($g, "affine_in_g$g", $aff)) {
            throw new \InvalidArgumentException("invalid $name encoding");
        }
        $pt = self::identity($g);
        self::call($g, 'from_affine', $pt, $aff);
        if (self::compress($g, $pt) !== $bytes) {
            throw new \InvalidArgumentException("non-canonical $name encoding");
        }
        return $pt;
    }

    public static function generator(int $g): \FFI\CData
    {
        $out = self::identity($g);
        \FFI::memcpy($out, self::call($g, 'generator'), self::grp($g)[1]);
        return $out;
    }

    /** RFC 9380 hash_to_curve (SSWU_RO) into G1 */
    public static function hashToG1(string $msg, string $dst): \FFI\CData
    {
        $out = self::identity(1);
        self::lib()->blst_hash_to_g1($out, $msg, strlen($msg), $dst, strlen($dst), null, 0);
        return $out;
    }

    /** e(a, x) == e(b, y) for a, b in G1 and x, y in G2, by blst's pairing */
    public static function pairingEq(\FFI\CData $a, \FFI\CData $x, \FFI\CData $b, \FFI\CData $y): bool
    {
        $l = self::buf(self::GT_BYTES);
        $r = self::buf(self::GT_BYTES);
        self::lib()->blst_miller_loop($l, self::affine(2, $x), self::affine(1, $a));
        self::lib()->blst_miller_loop($r, self::affine(2, $y), self::affine(1, $b));
        return (bool) self::lib()->blst_fp12_finalverify($l, $r);
    }

    // ---- the pairing target group GT as 576-byte strings (12 Fp coordinates, 48-byte big-endian each), through the shim ----

    public static function gtMul(string $a, string $b): string
    {
        $out = self::buf(self::GT_BYTES);
        if (self::gtLib()->pca_gt_mul($out, $a, $b) === 0) {
            throw new \InvalidArgumentException('not a canonical GT encoding');
        }
        return \FFI::string($out, self::GT_BYTES);
    }

    /** a^(k mod r) */
    public static function gtPow(string $a, \GMP $k): string
    {
        $out = self::buf(self::GT_BYTES);
        if (self::gtLib()->pca_gt_pow($out, $a, self::i2osp(self::mod($k), 32)) === 0) {
            throw new \InvalidArgumentException('not a canonical GT encoding');
        }
        return \FFI::string($out, self::GT_BYTES);
    }

    /** canonical encoding of an element of the order-r subgroup other than the identity */
    public static function gtIsElement(mixed $a): bool
    {
        return is_string($a) && strlen($a) === self::GT_BYTES && self::gtLib()->pca_gt_is_element($a) === 1;
    }

    public static function gtPairing(\FFI\CData $p, \FFI\CData $q): string
    {
        return self::gtPairingProduct([$p], [$q]);
    }

    /**
     * prod e(g1[i], g2[i]) with one shared final exponentiation; throws on an identity point
     *
     * @param list<\FFI\CData> $g1
     * @param list<\FFI\CData> $g2
     */
    public static function gtPairingProduct(array $g1, array $g2): string
    {
        $n = count($g1);
        if ($n === 0 || $n !== count($g2)) {
            throw new \InvalidArgumentException('pairing product needs equal, non-empty point lists');
        }
        $a = '';
        $b = '';
        foreach ($g1 as $i => $p) {
            $q = $g2[$i];
            if (self::isInf(1, $p) || self::isInf(2, $q)) {
                throw new \InvalidArgumentException('pairing is not defined for the identity');
            }
            $a .= self::compress(1, $p);
            $b .= self::compress(2, $q);
        }
        $out = self::buf(self::GT_BYTES);
        if (self::gtLib()->pca_gt_pairing($out, $a, $b, $n) === 0) {
            throw new \InvalidArgumentException('invalid pairing input');
        }
        return \FFI::string($out, self::GT_BYTES);
    }

    /** @internal Test seam: when set, it gets the candidate libblst paths, in load order, and returns the list to try instead. */
    public static ?\Closure $pathsHook = null;
}
