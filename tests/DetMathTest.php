<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\DetMath;
use PHPUnit\Framework\TestCase;

/** Deterministic ln / log2 / exp / integer power: exact where the rule is exact, within a unit in the last place of libm elsewhere. */
final class DetMathTest extends TestCase
{
    public function testExactCases(): void
    {
        self::assertSame(0.0, DetMath::detLn(1.0));
        self::assertSame(0.0, DetMath::detLog2(1.0));
        self::assertSame(1.0, DetMath::detExp(0.0));
        foreach ([1, 2, 3, 10, 52, 1000, -1, -2, -10, -1000] as $k) {
            self::assertSame((float) $k, DetMath::detLog2(2.0 ** $k), "log2(2^$k)"); // an exact power of two gives its exponent exactly
        }
        self::assertSame(0.125, DetMath::detPowInt(0.5, 3));
        self::assertSame(1.0, DetMath::detPowInt(0.37, 0));
    }

    public function testSpecialValues(): void
    {
        self::assertSame(-INF, DetMath::detLn(0.0));
        self::assertSame(-INF, DetMath::detLn(-0.0));
        self::assertSame(-INF, DetMath::detLog2(0.0));
        self::assertSame(-INF, DetMath::detLog2(-0.0));
        self::assertSame(0.0, DetMath::detExp(-INF));
        self::assertNan(DetMath::detLog2(-1.0));
        self::assertNan(DetMath::detLn(-1.0));
        self::assertNan(DetMath::detLn(NAN));
        self::assertSame(INF, DetMath::detLn(INF));
        self::assertNan(DetMath::detLog2(-0.5));
        self::assertSame(INF, DetMath::detLog2(INF));
        self::assertNan(DetMath::detExp(NAN));
        self::assertSame(INF, DetMath::detExp(710.0));
        self::assertSame(0.0, DetMath::detExp(-746.0));
    }

    public function testAgreesWithLibmToTheLastDigits(): void
    {
        foreach ([0.001, 0.1, 0.5, 0.9999, 1.5, 2.0, 3.0, 10.0, 12345.678, 1e100, 5e-324, 1e-310] as $x) {
            self::assertEqualsWithDelta(log($x), DetMath::detLn($x), 4e-16 * max(1.0, abs(log($x))), "ln $x");
            self::assertEqualsWithDelta(log($x, 2), DetMath::detLog2($x), 4e-16 * max(1.0, abs(log($x, 2))), "log2 $x");
        }
        foreach ([-700.0, -20.5, -1.0, -0.001, 0.001, 0.5, 1.0, 2.5, 20.0, 700.0] as $x) {
            self::assertEqualsWithDelta(exp($x), DetMath::detExp($x), 4e-16 * exp($x), "exp $x");
        }
        self::assertEqualsWithDelta(M_LN2, DetMath::detLn(2.0), 1e-16);
    }

    public function testExpInvertsLn(): void
    {
        foreach ([0.3, 1.7, 42.0, 1e-5] as $x) {
            self::assertEqualsWithDelta($x, DetMath::detExp(DetMath::detLn($x)), 1e-15 * $x);
        }
    }
}
