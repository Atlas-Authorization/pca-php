<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalCrc.php';

use Atlas\Pca\GoalCrc;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/GoalCrc.php: JS-number output shape, alpha rounding, the calibration boundary and the report's number guard. */
final class RestSurvivorKill36cGoalCrcTest extends TestCase
{
    /** A whole alpha numerator comes back as an int (JS number 0 and 5000), not a float. */
    public function testAlphaNumeratorIsAnInteger(): void
    {
        $this->assertSame(0, GoalCrc::alphaOf(0)->get('a'));
        $this->assertSame(5000, GoalCrc::alphaOf(0.05)->get('a'));
        $this->assertSame(100000, GoalCrc::alphaOf(0.05)->get('b'));
    }

    /** A non-finite alpha keeps both members: a is the non-finite value, b stays 100000. */
    public function testNonFiniteAlphaKeepsNumerator(): void
    {
        $o = GoalCrc::alphaOf(INF);
        $this->assertTrue($o->has('a'));
        $this->assertSame(INF, $o->get('a'));
        $this->assertSame(100000, $o->get('b'));
    }

    /** x * 1e5 = 1.4999999999999998 rounds down to 1 (Math.round), never up by a pre-rounding round(). */
    public function testAlphaRoundsLikeMathRound(): void
    {
        $this->assertSame(1, GoalCrc::alphaOf(0.000014999999999999998)->get('a'));
        $this->assertSame(3, GoalCrc::alphaOf(0.000025)->get('a'), 'control: an exact half rounds up');
    }

    /** minN of exactly 2^53 is not a safe integer, so it stays a float. */
    public function testMinNAtTwoTo53StaysFloat(): void
    {
        $c = GoalCrc::calibrate([[0]], Obj::of(['a' => 1, 'b' => 9007199254740994]));
        $this->assertSame(9007199254740992.0, $c->get('minN'));
        $this->assertFalse($c->get('feasible'));
    }

    /** Corrected risk exactly equal to alpha ((k+1)*b == a*(n+1)) is feasible at that level. */
    public function testCalibrateBoundaryIsInclusive(): void
    {
        $c = GoalCrc::calibrate([[0], [0], [0]], Obj::of(['a' => 1, 'b' => 4]));
        $this->assertTrue($c->get('feasible'));
        $this->assertSame(0, $c->get('level'));
        $this->assertSame(3, $c->get('minN'));
        $d = GoalCrc::calibrate([[0], [0]], Obj::of(['a' => 1, 'b' => 4]));
        $this->assertFalse($d->get('feasible'), 'control: just above alpha is infeasible');
    }

    /** calibrate itself refuses a loss matrix that increases with the threshold. */
    public function testCalibrateChecksMonotone(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('loss is not nonincreasing in the threshold (case 0, level 1)');
        GoalCrc::calibrate([[0, 1]], Obj::of(['a' => 1, 'b' => 2]));
    }

    /** A negative trial count is refused by the bound, not answered with 1. */
    public function testCpUpperRefusesNegativeN(): void
    {
        $this->assertSame(1, GoalCrc::cpUpper95(0, 0), 'control');
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('clopperPearsonUpper: need integers 0 <= k <= n');
        GoalCrc::cpUpper95(0, -1);
    }

    /** A non-number rate in the report throws toFixed's TypeError instead of printing 0. */
    public function testReportRateMustBeANumber(): void
    {
        $r = Obj::of(['domain' => 'd', 'alpha' => 0.1, 'test' => Obj::of(['n' => 1, 'widening' => Obj::of(['k' => 0, 'rate' => 'x'])])]);
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('toFixed is not a function');
        GoalCrc::renderReportMarkdown([$r], Obj::of(['source' => 'fixture', 'modelSet' => 'm']));
    }
}
