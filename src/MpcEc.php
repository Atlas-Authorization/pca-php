<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Ed25519Core.php';

/**
 * A small prime-order group for the base oblivious transfer: Ed25519 (twisted Edwards, q = 2^255 - 19), used in its prime-order
 * subgroup (order L). The group law (add, subtract, scalar multiplication, subgroup test) is libsodium's, called through ext-sodium
 * on the compressed encoding; nothing of it is written out here. What remains in GMP is only the public coordinate codec (affine
 * normalisation, RFC 8032 x-recovery) and the on-curve predicate, which touch no secret. Every point received across the OT trust
 * boundary is validated (on curve, non-identity, [L]P = O).
 *
 * A point is ['X' => GMP, 'Y' => GMP, 'Z' => GMP, 'T' => GMP] in extended coordinates (x = X/Z, y = Y/Z, T = XY/Z).
 * A Schnorr proof is ['U' => point, 'z' => GMP]. Needs the Ed25519 core functions of ext-sodium (the same ones the FROST port uses).
 */
final class MpcEc
{
    private static ?\GMP $q = null;
    private static ?\GMP $l = null;
    private static ?\GMP $d = null;
    private static ?\GMP $sqrtM1 = null;

    public static function q(): \GMP
    {
        return self::$q ??= gmp_sub(gmp_pow(2, 255), 19);
    }

    /** The prime subgroup order. */
    public static function l(): \GMP
    {
        return self::$l ??= gmp_add(gmp_pow(2, 252), gmp_init('27742317777372353535851937790883648493'));
    }

    private static function d(): \GMP
    {
        return self::$d ??= self::modFq(gmp_mul(gmp_init(-121665), self::invFq(gmp_init(121666))));
    }

    private static function sqrtM1(): \GMP
    {
        return self::$sqrtM1 ??= self::powFq(gmp_init(2), gmp_div_q(gmp_sub(self::q(), 1), 4));
    }

    public static function modFq(\GMP $x): \GMP
    {
        return gmp_mod($x, self::q());
    }

    private static function invFq(\GMP $a): \GMP
    {
        return self::powFq(self::modFq($a), gmp_sub(self::q(), 2));
    }

    private static function powFq(\GMP $b, \GMP $e): \GMP
    {
        return gmp_powm(self::modFq($b), $e, self::q());
    }

    private static function mm(\GMP $a, \GMP $b): \GMP
    {
        return gmp_mod(gmp_mul($a, $b), self::q());
    }

    public static function fromAffine(\GMP $x, \GMP $y): array
    {
        $X = self::modFq($x);
        $Y = self::modFq($y);
        return ['X' => $X, 'Y' => $Y, 'Z' => gmp_init(1), 'T' => self::modFq(gmp_mul($X, $Y))];
    }

    public static function identity(): array
    {
        return ['X' => gmp_init(0), 'Y' => gmp_init(1), 'Z' => gmp_init(1), 'T' => gmp_init(0)];
    }

    public static function base(): array
    {
        return self::fromAffine(
            gmp_init('15112221349535400772501151409588531511454012693041857206046113283949847762202'),
            gmp_init('46316835694926478169428394003475163141307993866256225615783033603165251855960'),
        );
    }

    /** Little-endian bytes of the low $len bytes of a non-negative (or two's-complement) integer. */
    public static function le(\GMP $v, int $len): string
    {
        $m = gmp_and($v, gmp_sub(gmp_pow(2, 8 * $len), 1));
        return strrev((string) hex2bin(str_pad(gmp_strval($m, 16), 2 * $len, '0', STR_PAD_LEFT)));
    }

    private static function fromEnc(string $enc): array
    {
        return self::decompressPoint($enc);
    }

    private static function binary(bool $sub, array $p1, array $p2): array
    {
        try {
            $r = $sub ? Ed25519Core::sub(self::compressPoint($p1), self::compressPoint($p2))
                : Ed25519Core::add(self::compressPoint($p1), self::compressPoint($p2));
        } catch (\SodiumException) {
            throw new MpcPointError('point is not on the curve');
        }
        return self::fromEnc($r);
    }

    /** Public group addition P + Q (complete on the subgroup). */
    public static function addPoints(array $p1, array $p2): array
    {
        return self::binary(false, $p1, $p2);
    }

    public static function dbl(array $p): array
    {
        return self::addPoints($p, $p);
    }

    public static function sub(array $p1, array $p2): array
    {
        return self::binary(true, $p1, $p2);
    }

    public static function neg(array $p): array
    {
        return self::sub(self::identity(), $p);
    }

    /** [k]P with k reduced mod L (k = 0 or P = identity is the identity). P must lie in the prime-order subgroup (libsodium refuses torsion). */
    public static function mul(\GMP $k, array $p): array
    {
        $s = gmp_mod($k, self::l());
        if (gmp_sign($s) === 0 || self::isIdentity($p)) {
            return self::identity();
        }
        try {
            $r = Ed25519Core::mulNoclamp(self::le($s, 32), self::compressPoint($p));
        } catch (\SodiumException) {
            throw new MpcPointError('scalar multiplication refused: point not in the prime-order subgroup');
        }
        return self::fromEnc($r);
    }

    public static function mulBase(\GMP $k): array
    {
        $s = gmp_mod($k, self::l());
        if (gmp_sign($s) === 0) {
            return self::identity();
        }
        return self::fromEnc(Ed25519Core::mulBaseNoclamp(self::le($s, 32)));
    }

    /** Affine [x, y] of a point (identity is (0, 1)). @return array{0:\GMP,1:\GMP} */
    public static function toAffine(array $p): array
    {
        $zinv = self::invFq($p['Z']);
        return [self::modFq(gmp_mul($p['X'], $zinv)), self::modFq(gmp_mul($p['Y'], $zinv))];
    }

    public static function equal(array $a, array $b): bool
    {
        return gmp_cmp(self::modFq(gmp_mul($a['X'], $b['Z'])), self::modFq(gmp_mul($b['X'], $a['Z']))) === 0
            && gmp_cmp(self::modFq(gmp_mul($a['Y'], $b['Z'])), self::modFq(gmp_mul($b['Y'], $a['Z']))) === 0;
    }

    /** Canonical 64-byte affine encoding x || y (little-endian field elements), the OT key-derivation input. */
    public static function encodePoint(array $p): string
    {
        [$x, $y] = self::toAffine($p);
        return self::le(self::modFq($x), 32) . self::le(self::modFq($y), 32);
    }

    /** Canonical 32-byte compressed encoding (little-endian y, sign of x in bit 255). */
    public static function compressPoint(array $p): string
    {
        [$x, $y] = self::toAffine($p);
        $out = self::le(self::modFq($y), 32);
        $out[31] = chr((ord($out[31]) & 0xff) | ((gmp_testbit($x, 0) ? 1 : 0) << 7));
        return $out;
    }

    /** Decodes a canonical compressed encoding (RFC 8032 5.1.3 x-recovery). */
    public static function decompressPoint(string $bytes): array
    {
        if (strlen($bytes) !== 32) {
            throw new MpcPointError('decompressPoint: expected 32 bytes');
        }
        $sign = (ord($bytes[31]) >> 7) & 1;
        $y = gmp_init(bin2hex(strrev($bytes)), 16);
        gmp_clrbit($y, 255);
        if (gmp_cmp($y, self::q()) >= 0) {
            throw new MpcPointError('decompressPoint: non-canonical y (>= q)');
        }
        $y2 = self::mm($y, $y);
        $u = self::modFq(gmp_sub($y2, 1));
        $v = self::modFq(gmp_add(gmp_mul(self::d(), $y2), 1));
        $v3 = self::mm(self::mm($v, $v), $v);
        $v7 = self::mm(self::mm($v3, $v3), $v);
        $x = self::mm(self::mm($u, $v3), self::powFq(self::mm($u, $v7), gmp_div_q(gmp_sub(self::q(), 5), 8)));
        $vx2 = self::mm($v, self::mm($x, $x));
        if (gmp_cmp($vx2, self::modFq($u)) === 0) {
            // x is correct as-is
        } elseif (gmp_cmp($vx2, self::modFq(gmp_neg($u))) === 0) {
            $x = self::mm($x, self::sqrtM1());
        } else {
            throw new MpcPointError('decompressPoint: not on curve');
        }
        if (gmp_sign($x) === 0 && $sign === 1) {
            throw new MpcPointError('decompressPoint: non-canonical sign');
        }
        if ((gmp_testbit($x, 0) ? 1 : 0) !== $sign) {
            $x = self::modFq(gmp_sub(self::q(), $x));
        }
        return self::fromAffine($x, $y);
    }

    /** Whether the extended coordinates lie on the curve (projectively, no inversion). */
    public static function isOnCurve(array $p): bool
    {
        if (gmp_sign(self::modFq($p['Z'])) === 0) {
            return false;
        }
        if (gmp_cmp(self::modFq(gmp_mul($p['T'], $p['Z'])), self::modFq(gmp_mul($p['X'], $p['Y']))) !== 0) {
            return false;
        }
        $X2 = self::mm($p['X'], $p['X']);
        $Y2 = self::mm($p['Y'], $p['Y']);
        $Z2 = self::mm($p['Z'], $p['Z']);
        $lhs = self::modFq(gmp_mul(gmp_sub($Y2, $X2), $Z2));
        $Z4 = self::mm($Z2, $Z2);
        $dxy = self::mm(self::mm(self::d(), $X2), $Y2);
        return gmp_cmp($lhs, self::modFq(gmp_add($Z4, $dxy))) === 0;
    }

    public static function isIdentity(array $p): bool
    {
        return self::equal($p, self::identity());
    }

    /** The cofactor check [L]P = O (true for the identity too). */
    public static function hasPrimeOrder(array $p): bool
    {
        if (!self::isOnCurve($p)) {
            return false;
        }
        return self::isIdentity($p) || Ed25519Core::isValidPoint(self::compressPoint($p));
    }

    /** A valid non-identity point of the prime-order subgroup. */
    public static function isInSubgroup(array $p): bool
    {
        return self::isOnCurve($p) && !self::isIdentity($p) && self::hasPrimeOrder($p);
    }

    public static function assertInSubgroup(array $p, string $label = 'point'): void
    {
        if (!self::isOnCurve($p)) {
            throw new MpcPointError("$label: not on curve");
        }
        if (self::isIdentity($p)) {
            throw new MpcPointError("$label: identity element (forbidden here)");
        }
        if (!self::hasPrimeOrder($p)) {
            throw new MpcPointError("$label: not in the prime-order subgroup (small-order/cofactor)");
        }
    }

    private static function schnorrChallenge(array $S, array $U, string $ctx): \GMP
    {
        $h = hash('sha512', 'atlas-pca-mpc/schnorr-dlog' . pack('N', strlen($ctx)) . $ctx . self::encodePoint(self::base()) . self::encodePoint($S) . self::encodePoint($U), true);
        return gmp_mod(gmp_init(bin2hex($h), 16), self::l());
    }

    /**
     * Fiat-Shamir Schnorr proof of knowledge of y with S = y*B: commitment U = r*B and z = r + e*y. $rnd returns the nonce.
     *
     * @return array{U:array,z:\GMP}
     */
    public static function schnorrProve(\GMP $y, array $S, callable $rnd, string $ctx): array
    {
        if ($ctx === '') {
            throw new \InvalidArgumentException('schnorrProve: a non-empty session binding is required');
        }
        $r = gmp_mod($rnd(), self::l());
        if (gmp_sign($r) === 0) {
            throw new \RuntimeException('schnorrProve: nonce source returned 0 (RNG failure); refusing to produce a proof');
        }
        $U = self::mulBase($r);
        $e = self::schnorrChallenge($S, $U, $ctx);
        return ['U' => $U, 'z' => gmp_mod(gmp_add($r, gmp_mul($e, gmp_mod($y, self::l()))), self::l())];
    }

    public static function schnorrVerify(array $S, array $proof, string $ctx): bool
    {
        if ($ctx === '') {
            return false;
        }
        if (gmp_sign($proof['z']) < 0 || gmp_cmp($proof['z'], self::l()) >= 0) {
            return false;
        }
        if (!self::isInSubgroup($proof['U'])) {
            return false;
        }
        $e = self::schnorrChallenge($S, $proof['U'], $ctx);
        try {
            return self::equal(self::mulBase($proof['z']), self::addPoints($proof['U'], self::mul($e, $S)));
        } catch (MpcPointError) {
            return false;
        }
    }
}
