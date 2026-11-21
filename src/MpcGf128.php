<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * GF(2^128) arithmetic with the reduction polynomial x^128 + x^7 + x^2 + x + 1: the field of the KOS correlation check.
 * Elements are 128-bit non-negative GMP values (bit i = coefficient of x^i); addition is XOR. Not constant-time.
 */
final class MpcGf128
{
    private static function mask(): \GMP
    {
        return gmp_sub(gmp_pow(2, 128), 1);
    }

    public static function add(\GMP $a, \GMP $b): \GMP
    {
        return gmp_and(gmp_xor($a, $b), self::mask());
    }

    public static function mulX(\GMP $v): \GMP
    {
        $carry = gmp_testbit($v, 127);
        $r = gmp_and(gmp_mul($v, 2), self::mask());
        return $carry ? gmp_xor($r, gmp_init(0x87)) : $r;
    }

    public static function mulByXi(\GMP $v, int $i): \GMP
    {
        $r = gmp_and($v, self::mask());
        for ($k = 0; $k < $i; $k++) {
            $r = self::mulX($r);
        }
        return $r;
    }

    public static function mul(\GMP $a, \GMP $b): \GMP
    {
        $res = gmp_init(0);
        $v = gmp_and($a, self::mask());
        for ($i = 0; $i < 128; $i++) {
            if (gmp_testbit($b, $i)) {
                $res = gmp_xor($res, $v);
            }
            $v = self::mulX($v);
        }
        return gmp_and($res, self::mask());
    }
}
