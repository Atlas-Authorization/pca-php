<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\DetMath;
use PHPUnit\Framework\TestCase;

/**
 * Group 31 survivors of detmath.ts: the integer-to-double rounding, the power-of-two builder, the fixed-point ln guard and exact results the
 * reference (packages/pca-intent/src/detmath.ts) gives where one unit in the last fixed-point place shows.
 */
final class MathSurvivorKill31DetMathTest extends TestCase
{
    private static function call(string $fn, mixed $x): mixed
    {
        return (new \ReflectionMethod(DetMath::class, $fn))->invoke(null, $x);
    }

    private static function dbl(string $n): float
    {
        return self::call('toDouble', gmp_init($n));
    }

    /** The nearest double with ties to even, both signs; 53 bits go straight across, 0 is +0. */
    public function testToDoubleRounding(): void
    {
        self::assertSame(0.0, self::dbl('0'));
        self::assertSame([5.0, -5.0], [self::dbl('5'), self::dbl('-5')]);
        $p53 = 9007199254740992.0; // 2^53
        self::assertSame(4503599627370497.0, self::dbl('4503599627370497'), '2^52 + 1 has 53 bits');
        self::assertSame($p53, self::dbl('9007199254740993'), 'a tie on an even significand stays');
        self::assertSame($p53 + 4.0, self::dbl('9007199254740995'), 'a tie on an odd significand rounds up');
        self::assertSame(-($p53 + 4.0), self::dbl('-9007199254740995'));
        self::assertSame(2 * $p53 + 4.0, self::dbl('18014398509481987'), 'above the half rounds up');
    }

    /** 2^n: the largest finite, then infinity; the smallest subnormals, then 0. */
    public function testPow2Edges(): void
    {
        self::assertSame(8.98846567431158e307, self::call('pow2', 1023));
        self::assertSame(INF, self::call('pow2', 1024));
        self::assertSame(2.2250738585072014e-308, self::call('pow2', -1022));
        self::assertSame(1e-323, self::call('pow2', -1073));
        self::assertSame(5e-324, self::call('pow2', -1074));
        self::assertSame(0.0, self::call('pow2', -1075));
    }

    /** The fixed-point ln refuses zero, a negative number and infinity. */
    public function testLnFixedGuard(): void
    {
        foreach ([0.0, -1.0, INF] as $x) {
            self::assertNull(self::call('lnFixed', $x), "lnFixed($x)");
        }
    }

    /** Values of the reference where the last fixed-point unit of LN2 / atanh, or the range reduction, shows in the double. */
    public function testReferenceValues(): void
    {
        $x = 1.0000000000000002; // 1 + 2^-52
        self::assertSame(2.2204460492500606e-16, DetMath::detLn($x));
        self::assertSame(3.20342650381454e-16, DetMath::detLog2($x));
        self::assertSame(1.0, DetMath::detExp(1.1102230246251565e-16), 'e^(2^-53) is a tie at 1 + 2^-53 and stays 1');
        self::assertSame(1.00000000000001, DetMath::detExp(1e-14));
        self::assertSame(1.7976931348622732e308, DetMath::detExp(709.782712893384), 'the cut-off itself is still finite');
    }
}
