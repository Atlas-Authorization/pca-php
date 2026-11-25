<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\BondSettlement;
use Atlas\Pca\Immune;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Sdjwt;
use PHPUnit\Framework\TestCase;

/** The immune decay uses only exactly reproducible operations; a non-number adaptation is a violation; an unrepresentable `now` is refused. */
final class ContractR14Test extends TestCase
{
    private static function decay(float $count, float $dt, float $half): float
    {
        return (new \ReflectionMethod(Immune::class, 'decay'))->invoke(null, $count, $dt, $half);
    }

    public function testDecayIsHalfLifeStepsByRepeatedMultiplication(): void
    {
        $half = 3600000.0;
        self::assertSame(1.0, self::decay(1.0, 0.0, $half));
        self::assertSame(0.5, self::decay(1.0, $half, $half));
        self::assertSame(0.25, self::decay(1.0, 2 * $half, $half));
        self::assertSame(0.9993233275026507, self::decay(1.0, $half / 1024, $half));
        $f = 1.0;
        for ($i = 0; $i < 512; $i++) {
            $f *= 0.9993233275026507;
        }
        self::assertSame(3.0 * $f, self::decay(3.0, $half / 2, $half)); // the quantized elapsed time, step by step, in this order
        // below one step nothing has decayed; far beyond the underflow bound the count is gone; NaN stays NaN
        self::assertSame(1.0, self::decay(1.0, $half / 2048, $half));
        self::assertSame(0.0, self::decay(1.0, 2000 * $half, $half));
        self::assertNan(self::decay(1.0, NAN, $half));
    }

    public function testNoWidenRefusesANonNumberKappaOrTheta(): void
    {
        $base = Obj::of(['kappa' => new Num('1'), 'theta1' => new Num('1'), 'theta2' => new Num('1'), 'lambda' => new Num('0'), 'rho' => new Num('0'), 'bMax' => new Num('1'),
            'weights' => Obj::of([])]);
        foreach (['kappa', 'theta1', 'theta2'] as $k) {
            foreach ([null, true, false, '1'] as $bad) {
                $a = $base->without();
                $a->set($k, $bad);
                self::assertSame('kappa and theta must be numbers', Immune::noWidenViolation($base, $a), "$k = " . var_export($bad, true));
            }
        }
    }

    public function testSdJwtRefusesAnUnrepresentableNow(): void
    {
        foreach ([1e300, -1e300, 8.64e15 + 1e3] as $now) {
            $r = Sdjwt::verifyPcaSdJwt('x', Obj::of(['now' => $now]));
            self::assertFalse($r->get('ok'));
            self::assertSame('now is not a representable time', $r->get('reason'));
        }
    }

    public function testPowerCurveUsesOnlyMultiplicationAndSqrt(): void
    {
        self::assertSame(8.0, BondSettlement::powEighths(2.0, 3.0));
        self::assertSame(8.0, BondSettlement::powEighths(4.0, 1.5));   // 4 * sqrt(4)
        self::assertSame(512.0, BondSettlement::powEighths(256.0, 1.125)); // 256 * sqrt(sqrt(sqrt(256)))
        self::assertSame(4.0, BondSettlement::powEighths(4.0, 1.0));
        self::assertSame(2.0 ** 64, BondSettlement::powEighths(2.0, 64.0));
        foreach ([1.3, 65.0, 64.5, NAN, INF, -INF, 1.0001] as $bad) {
            try {
                BondSettlement::powEighths(2.0, $bad);
                self::fail('gamma ' . $bad . ' is refused');
            } catch (\InvalidArgumentException $e) {
                self::assertSame('bondAmount: power curve gamma must be a multiple of 1/8 and at most 64', $e->getMessage());
            }
        }
    }
}
