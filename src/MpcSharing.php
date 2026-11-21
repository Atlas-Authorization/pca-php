<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Additive secret sharing over F_p for N parties: shares sum to the secret; reconstruction is all-or-nothing and fails closed on
 * an absent share. A shared value is a list of GMP values with x[i] held by party i.
 */
final class MpcSharing
{
    /** Largest party count accepted (bounds allocation). */
    public const MAX_PARTIES = 1024;

    /** @return list<\GMP> */
    public static function share(\GMP $secret, int $n, MpcFieldRng $rng): array
    {
        if ($n < 1 || $n > self::MAX_PARTIES) {
            throw new \InvalidArgumentException('share: n must be an integer in [1, ' . self::MAX_PARTIES . ']');
        }
        $out = [];
        $acc = gmp_init(0);
        for ($i = 0; $i < $n - 1; $i++) {
            $s = $rng->next();
            $out[] = $s;
            $acc = MpcField::fadd($acc, $s);
        }
        $out[] = MpcField::fadd(MpcField::mod($secret), MpcField::fneg($acc));
        return $out;
    }

    /** @param list<?\GMP> $shares */
    public static function reconstruct(array $shares): \GMP
    {
        if ($shares === []) {
            throw new \InvalidArgumentException('reconstruct: no shares (fail closed)');
        }
        $acc = gmp_init(0);
        foreach ($shares as $s) {
            if ($s === null) {
                throw new \InvalidArgumentException('reconstruct: missing share (fail closed)');
            }
            $acc = MpcField::fadd($acc, $s);
        }
        return $acc;
    }

    /** @return list<\GMP> */
    public static function shareConstant(\GMP $c, int $n): array
    {
        if ($n < 1 || $n > self::MAX_PARTIES) {
            throw new \InvalidArgumentException('shareConstant: n must be an integer in [1, ' . self::MAX_PARTIES . ']');
        }
        $out = array_fill(0, $n, gmp_init(0));
        $out[0] = MpcField::mod($c);
        return $out;
    }

    /** @param list<\GMP> $x @param list<\GMP> $y @return list<\GMP> */
    public static function addSV(array $x, array $y): array
    {
        self::same($x, $y);
        return array_map(static fn(\GMP $a, \GMP $b): \GMP => MpcField::fadd($a, $b), $x, $y);
    }

    /** @param list<\GMP> $x @param list<\GMP> $y @return list<\GMP> */
    public static function subSV(array $x, array $y): array
    {
        self::same($x, $y);
        return array_map(static fn(\GMP $a, \GMP $b): \GMP => MpcField::fadd($a, MpcField::fneg($b)), $x, $y);
    }

    /** @param list<\GMP> $x @return list<\GMP> */
    public static function negSV(array $x): array
    {
        return array_map(static fn(\GMP $a): \GMP => MpcField::fneg($a), $x);
    }

    /** @param list<\GMP> $x @return list<\GMP> */
    public static function scaleSV(array $x, \GMP $c): array
    {
        return array_map(static fn(\GMP $a): \GMP => MpcField::fmul($a, $c), $x);
    }

    /** @param list<\GMP> $x @return list<\GMP> */
    public static function addPublicSV(array $x, \GMP $c): array
    {
        $x[0] = MpcField::fadd($x[0], MpcField::mod($c));
        return $x;
    }

    /** @param list<\GMP> $b @return list<\GMP> */
    public static function notBitSV(array $b): array
    {
        return self::addPublicSV(self::negSV($b), gmp_init(1));
    }

    private static function same(array $x, array $y): void
    {
        if (count($x) !== count($y)) {
            throw new \InvalidArgumentException('shared values must have the same party count');
        }
    }
}
