<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentOmega;
use PHPUnit\Framework\TestCase;

/** IntentOmega::jsMax / jsMin treat signed zeros as Math.max / Math.min do (max prefers +0, min prefers -0, in either order). */
final class IntentSurvivorKill32cOmegaTest extends TestCase
{
    /** The value and the sign of a zero (fdiv(1, -0.0) is -INF). @return array{0: int|float, 1: string} */
    private static function signed(int|float $v): array
    {
        return [$v, $v == 0 ? (fdiv(1, (float)$v) < 0 ? '-0' : '+0') : 'nz'];
    }

    /** Math.max(-0, 0) and Math.max(0, -0) are +0; Math.max(-0, -0) is -0; nonzero and int operands are unchanged. */
    public function testMaxOfSignedZeros(): void
    {
        $this->assertSame([0.0, '+0'], self::signed(IntentOmega::jsMax(-0.0, 0.0)));
        $this->assertSame([0.0, '+0'], self::signed(IntentOmega::jsMax(0.0, -0.0)));
        $this->assertSame([-0.0, '-0'], self::signed(IntentOmega::jsMax(-0.0, -0.0)));
        $this->assertSame([0, '+0'], self::signed(IntentOmega::jsMax(-0.0, 0)));
        $this->assertSame([1.0, 'nz'], self::signed(IntentOmega::jsMax(-0.0, 1.0)));
        $this->assertSame([-0.0, '-0'], self::signed(IntentOmega::jsMax(-1.0, -0.0)));
        $this->assertSame([0, '+0'], self::signed(IntentOmega::jsMax(0, 0)));
        $this->assertNan(IntentOmega::jsMax(-0.0, NAN));
    }

    /** Math.min(0, -0) and Math.min(-0, 0) are -0; Math.min(0, 0) is +0; nonzero and int operands are unchanged. */
    public function testMinOfSignedZeros(): void
    {
        $this->assertSame([-0.0, '-0'], self::signed(IntentOmega::jsMin(0.0, -0.0)));
        $this->assertSame([-0.0, '-0'], self::signed(IntentOmega::jsMin(-0.0, 0.0)));
        $this->assertSame([0.0, '+0'], self::signed(IntentOmega::jsMin(0.0, 0.0)));
        $this->assertSame([-0.0, '-0'], self::signed(IntentOmega::jsMin(0, -0.0)));
        $this->assertSame([-0.0, '-0'], self::signed(IntentOmega::jsMin(1.0, -0.0)));
        $this->assertSame([-1.0, 'nz'], self::signed(IntentOmega::jsMin(-0.0, -1.0)));
        $this->assertSame([0, '+0'], self::signed(IntentOmega::jsMin(0, 0)));
        $this->assertNan(IntentOmega::jsMin(NAN, -0.0));
    }
}
