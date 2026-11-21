<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FdLibmPow.php';

use Atlas\Pca\FdLibmPow;
use PHPUnit\Framework\TestCase;

/** FdLibmPow reproduces the reference's Math.pow: exact points, special values, and agreement with the C library within two units. */
final class FdLibmPowTest extends TestCase
{
    public function testExactPointsAndSpecialValues(): void
    {
        self::assertSame(1024.0, FdLibmPow::pow(2, 10));
        self::assertSame(9.5367431640625e-07, FdLibmPow::pow(2, -20));
        self::assertSame(5e-324, FdLibmPow::pow(2, -1074));
        self::assertSame(0.0, FdLibmPow::pow(2, -1076));
        self::assertSame(8.98846567431158e307, FdLibmPow::pow(2, 1023));
        self::assertSame(INF, FdLibmPow::pow(2, 1024));
        self::assertSame(0.125, FdLibmPow::pow(0.5, 3));
        self::assertSame(100.0, FdLibmPow::pow(10, 2));
        self::assertNan(FdLibmPow::pow(-8, 1.0 / 3.0));
        self::assertSame(-8.0, FdLibmPow::pow(-2, 3));
        self::assertSame(16.0, FdLibmPow::pow(-2, 4));
        self::assertSame(1.0, FdLibmPow::pow(7, 0));
        self::assertSame(1.0, FdLibmPow::pow(NAN, 0));
        self::assertNan(FdLibmPow::pow(1, INF)); // the reference language's rule, unlike C
        self::assertNan(FdLibmPow::pow(-1, -INF));
        self::assertNan(FdLibmPow::pow(2, NAN));
        self::assertSame(0.0, FdLibmPow::pow(0.5, INF));
        self::assertSame(INF, FdLibmPow::pow(0.5, -INF));
        self::assertSame(INF, FdLibmPow::pow(0, -1));
        self::assertSame('-0.0', var_export(FdLibmPow::pow(-0.0, 3), true));
        self::assertSame(2.0, FdLibmPow::pow(4, 0.5));
        self::assertSame(1 - 2 ** -20, 1 - FdLibmPow::pow(2.0, -20.0));
    }

    public function testAgreesWithTheCLibraryWithinTwoUnits(): void
    {
        mt_srand(20261117);
        for ($i = 0; $i < 20000; $i++) {
            $x = 0.001 + (50 - 0.001) * (mt_rand() / mt_getrandmax());
            $y = -40 + 80 * (mt_rand() / mt_getrandmax());
            $a = FdLibmPow::pow($x, $y);
            $b = \pow($x, $y);
            // two units in the last place of b: b * 2**-52 bounds one unit from above
            self::assertLessThanOrEqual(2 * abs($b) * 2.220446049250313e-16, abs($a - $b), "pow($x, $y)");
        }
    }
}
