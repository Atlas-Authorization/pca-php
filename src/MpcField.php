<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Arithmetic in the prime field F_p (p = 2^61 - 1) used for additive secret sharing. Every element is a GMP value in [0, p);
 * the operations are exact big-integer arithmetic. The randomness sources are MpcFieldRng (a deterministic SplitMix64 behind an
 * explicit seed, for reproducible tests) and its CSPRNG mode (the default for protocol randomness).
 */
final class MpcField
{
    private static ?\GMP $p = null;

    public static function prime(): \GMP
    {
        return self::$p ??= gmp_sub(gmp_pow(2, 61), 1);
    }

    /** Canonical representative in [0, p). */
    public static function mod(\GMP $x): \GMP
    {
        return gmp_mod($x, self::prime());
    }

    public static function fadd(\GMP $a, \GMP $b): \GMP
    {
        return self::mod(gmp_add($a, $b));
    }

    public static function fsub(\GMP $a, \GMP $b): \GMP
    {
        return self::mod(gmp_sub($a, $b));
    }

    public static function fmul(\GMP $a, \GMP $b): \GMP
    {
        return self::mod(gmp_mul($a, $b));
    }

    public static function fneg(\GMP $a): \GMP
    {
        return self::mod(gmp_neg($a));
    }

    /** A CSPRNG-backed source by default, a reproducible seeded one only when a test seed is given. */
    public static function fieldRandom(?\GMP $testSeed = null): MpcFieldRng
    {
        return $testSeed === null ? MpcFieldRng::secure() : new MpcFieldRng($testSeed);
    }
}
