<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\DetMath;
use PHPUnit\Framework\TestCase;

/**
 * Group 38m survivors of detExp's range reduction k = floor((X + LN2/2) / LN2): two inputs whose exact result moves by one unit in the last
 * place when the reduction point is not LN2/2, with outputs taken from the reference (packages/pca-intent/src/detmath.ts).
 */
final class MathSurvivorKill38DetMathTest extends TestCase
{
    private static function hexOf(float $x): string
    {
        return bin2hex(pack('E', $x));
    }

    /** e^(2^-53): X = 2^43 reduces with k = 0, the sum is exactly the tie 2^96 + 2^43 and rounds to even, so the result is exactly 1.0. */
    public function testExpOfHalfUlpTiesToOne(): void
    {
        $x = 2 ** -53;
        self::assertSame('3ca0000000000000', self::hexOf($x));
        self::assertSame('3ff0000000000000', self::hexOf(DetMath::detExp($x)));
        self::assertSame(1.0, DetMath::detExp($x));
    }

    /** e^x for x = -8326519407960977 * 2^-55 (X/LN2 just below -1/3, a near-midpoint case): k = 0 gives significand ...201b. */
    public function testExpNearMidpointKeepsReferenceRounding(): void
    {
        $x = -8326519407960977 / 36028797018963968.0; // exact: a 53-bit integer over 2^55
        self::assertSame('bfcd94ecdf86e391', self::hexOf($x));
        self::assertSame('3fe9659da47c201b', self::hexOf(DetMath::detExp($x)));
        self::assertSame(0.7936542713732736, DetMath::detExp($x));
    }
}
