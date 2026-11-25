<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * DETERMINISTIC MATH (the rule every language follows). libm's log, exp, log2 and pow are not correctly rounded and differ in the last digit
 * between implementations, which moves a decision that sits on a boundary (the drift threshold, the next question, a map weight, an integer
 * cut point). The functions here use only integer arithmetic (ext-gmp): fixed point with 96 fractional bits (a value is an integer scaled by
 * 2^96), TRUNCATING division (toward zero), and one final conversion of the integer to a double with round-to-nearest-even followed by an
 * exact power-of-two scaling. Mirrors packages/pca-intent/src/detmath.ts.
 *
 *   detLn(x)   ln x for x > 0: x = m * 2^E, m = M / 2^52 in [1, 2) (M the 53-bit significand); ln x = E * LN2 + 2 * atanh((M - 2^52) / (M + 2^52)),
 *              atanh summed as z + z^3/3 + z^5/5 + ... (z fixed point, z2 = (z*z)/2^96 truncated) until a term is 0; LN2 = 2 * atanh(1/3).
 *   detLog2(x) log2 x: the same fixed value divided by LN2 in fixed point ((fixed * 2^96) / LN2, truncating): an exact power of two gives its
 *              integer exponent exactly.
 *   detLn(0) and detLog2(0) are -Infinity (also for -0), a negative x or NaN gives NaN; detExp(-Infinity) is 0.
 *   detExp(x)  e^x: X = trunc(x * 2^96); k = floor((X + LN2/2) / LN2); r = X - k * LN2; e^r = sum of r^n / n! with term_0 = 2^96,
 *              term_n = trunc(trunc(term_{n-1} * r / 2^96) / n), until a term is 0; result = double(sum) * 2^(k - 96). x > 709.78 gives
 *              +Infinity, x < -745.2 gives 0, NaN gives NaN.
 *   detPowInt(b, n) b^n for an integer n >= 0: 1 multiplied by b, n times, in sequence.
 */
final class DetMath
{
    private const FRAC = 96;

    private static ?\GMP $one = null;
    private static ?\GMP $ln2 = null;

    private static function one(): \GMP
    {
        return self::$one ??= gmp_pow(2, self::FRAC);
    }

    private static function ln2(): \GMP
    {
        return self::$ln2 ??= self::atanh2(gmp_init(1), gmp_init(3)); // ln 2 = 2 atanh(1/3)
    }

    /** Division truncating toward zero. */
    private static function tdiv(\GMP $a, \GMP $b): \GMP
    {
        return gmp_div_q($a, $b, GMP_ROUND_ZERO);
    }

    /** 2 * atanh(num / den) in fixed point (num >= 0, den > 0). */
    private static function atanh2(\GMP $num, \GMP $den): \GMP
    {
        $one = self::one();
        $z = self::tdiv(gmp_mul($num, $one), $den);
        $z2 = self::tdiv(gmp_mul($z, $z), $one);
        $term = $z;
        $sum = gmp_init(0);
        for ($i = 1; gmp_sign($term) !== 0; $i += 2) {
            $sum = gmp_add($sum, self::tdiv($term, gmp_init($i)));
            $term = self::tdiv(gmp_mul($term, $z2), $one);
        }
        return gmp_mul($sum, 2);
    }

    /** The integer `n` (any size) as the nearest double, ties to even. */
    private static function toDouble(\GMP $n): float
    {
        $s = gmp_sign($n);
        if ($s === 0) {
            return 0.0;
        }
        $a = gmp_abs($n);
        $bits = strlen(gmp_strval($a, 2));
        if ($bits <= 53) {
            $f = (float) gmp_intval($a);
            return $s < 0 ? -$f : $f;
        }
        $shift = $bits - 53;
        $unit = gmp_pow(2, $shift);
        $q = self::tdiv($a, $unit);
        $rem = gmp_sub($a, gmp_mul($q, $unit));
        $c = gmp_cmp($rem, gmp_pow(2, $shift - 1));
        if ($c > 0 || ($c === 0 && gmp_intval(gmp_and($q, 1)) === 1)) {
            $q = gmp_add($q, 1); // at most 2^53: still exact as a double
        }
        $f = (float) gmp_intval($q) * self::pow2($shift);
        return $s < 0 ? -$f : $f;
    }

    /** 2^n as a double, built from its bits (PHP has no ldexp; pow is not used): exact for every n a double can hold. */
    private static function pow2(int $n): float
    {
        if ($n > 1023) {
            return INF;
        }
        if ($n >= -1022) {
            return unpack('E', pack('J', ($n + 1023) << 52))[1];
        }
        if ($n >= -1074) { // subnormal
            return unpack('E', pack('J', 1 << ($n + 1074)))[1];
        }
        return 0.0;
    }

    /** The 64 bits of a double. */
    private static function bitsOf(float $x): int
    {
        return unpack('J', pack('E', $x))[1];
    }

    /** Fixed-point ln(x) (an integer scaled by 2^96) of a positive finite double, or null when x is not positive and finite. */
    private static function lnFixed(float $x): ?\GMP
    {
        if (!($x > 0) || $x === INF) {
            return null;
        }
        $scale = 0;
        $y = $x;
        if ($y < 2.2250738585072014e-308) { // 2^-1022: a subnormal is scaled by 2^64 first (exact)
            $y *= 18446744073709551616.0;
            $scale = 64;
        }
        $bits = self::bitsOf($y);
        $E = (($bits >> 52) & 0x7ff) - 1023 - $scale;
        $M = ($bits & ((1 << 52) - 1)) | (1 << 52);
        $two52 = 1 << 52;
        return gmp_add(gmp_mul(self::ln2(), $E), self::atanh2(gmp_init($M - $two52), gmp_init($M + $two52)));
    }

    public static function detLn(float $x): float
    {
        if ($x === 0.0) { // positive and negative zero: -Infinity, as Math.log gives
            return -INF;
        }
        if (!($x > 0)) { // negative or NaN
            return NAN;
        }
        if ($x === INF) {
            return $x;
        }
        if ($x === 1.0) {
            return 0.0;
        }
        return self::toDouble(self::lnFixed($x)) / self::pow2(self::FRAC);
    }

    public static function detLog2(float $x): float
    {
        if ($x === 0.0) { // positive and negative zero: -Infinity, as Math.log gives
            return -INF;
        }
        if (!($x > 0)) { // negative or NaN
            return NAN;
        }
        if ($x === INF) {
            return $x;
        }
        if ($x === 1.0) {
            return 0.0;
        }
        $l = self::lnFixed($x);
        return self::toDouble(self::tdiv(gmp_mul($l, self::one()), self::ln2())) / self::pow2(self::FRAC);
    }

    public static function detExp(float $x): float
    {
        if (is_nan($x)) {
            return $x;
        }
        if ($x > 709.782712893384) {
            return INF;
        }
        if ($x < -745.2) {
            return 0.0;
        }
        if ($x === 0.0) {
            return 1.0;
        }
        $bits = self::bitsOf(abs($x));
        $be = ($bits >> 52) & 0x7ff;
        $frac = $bits & ((1 << 52) - 1);
        $m = gmp_init($be === 0 ? $frac : ($frac | (1 << 52)));
        $sh = ($be === 0 ? 1 : $be) - 1075 + self::FRAC; // |x| * 2^96 = m * 2^sh
        $X = $sh >= 0 ? gmp_mul($m, gmp_pow(2, $sh)) : self::tdiv($m, gmp_pow(2, -$sh));
        if ($x < 0) {
            $X = gmp_neg($X);
        }
        $one = self::one();
        $ln2 = self::ln2();
        $k = gmp_div_q(gmp_add($X, self::tdiv($ln2, gmp_init(2))), $ln2, GMP_ROUND_MINUSINF); // floor division
        $r = gmp_sub($X, gmp_mul($k, $ln2));
        $term = $one;
        $sum = $one;
        for ($n = 1; gmp_sign($term) !== 0; $n++) {
            $term = self::tdiv(self::tdiv(gmp_mul($term, $r), $one), gmp_init($n));
            $sum = gmp_add($sum, $term);
        }
        $e = gmp_intval($k) - self::FRAC;
        $half = intdiv($e, 2);
        return self::toDouble($sum) * self::pow2($half) * self::pow2($e - $half);
    }

    /** b^n for an integer n >= 0 by sequential multiplication (1 * b * b ... n times). */
    public static function detPowInt(float $b, int|float $n): float
    {
        $r = 1.0;
        for ($i = 0; $i < $n; $i++) {
            $r *= $b;
        }
        return $r;
    }
}
