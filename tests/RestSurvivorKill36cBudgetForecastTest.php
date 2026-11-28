<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/BudgetForecast.php';
require_once __DIR__ . '/../src/Facade.php';

use Atlas\Pca\BudgetForecast;
use Atlas\Pca\Facade;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/BudgetForecast.php: the default start time, PHP int inputs, the kappa / finiteness refusals, -0 and the 1e21 text switch. */
final class RestSurvivorKill36cBudgetForecastTest extends TestCase
{
    /** Without a start the forecast starts at 0: the budget leaked by a timed step is the one of start 0, not of -1 or 1. */
    public function testDefaultStartIsZero(): void
    {
        $policy = Facade::compilePolicy(['github' => ['read']], null, null, 'risk', ['lambda' => 0.5, 'bMax' => 3.0], 0);
        $plan = [Obj::of(['verb' => 'github.read', 'resource' => 'repo:x', 'at' => 1000])];
        $def = BudgetForecast::forecast($policy, $plan);
        $this->assertSame(BudgetForecast::forecast($policy, $plan, 0), $def);
        $b = $def['steps'][0]['budgetAfter'];
        $this->assertNotSame(BudgetForecast::forecast($policy, $plan, 1)['steps'][0]['budgetAfter'], $b, 'control: the start moves the leak');
        $this->assertNotSame(BudgetForecast::forecast($policy, $plan, -1)['steps'][0]['budgetAfter'], $b, 'control: the start moves the leak');
    }

    /** PHP ints are numbers: 10 actions of risk 0.5 with kappa 2. */
    public function testIntegerInputs(): void
    {
        $r = BudgetForecast::recommendPolicy(10, 0.5, 2);
        $this->assertSame(2.0, $r['kappa']);
        $this->assertSame(10.0, $r['bMax']);
        $this->assertSame(5.0, $r['autonomousBound']);
        $this->assertSame('Σr ≤ bMax/κ = 5.000 ≥ 10×0.500 actions before a human co-sign', $r['rationale']);
    }

    /** kappa 0 is not positive: refused with the kappa reason. */
    public function testZeroKappaRefused(): void
    {
        $this->expectException(\RangeException::class);
        $this->expectExceptionMessage('recommendPolicy: kappa must be a positive finite number');
        BudgetForecast::recommendPolicy(10, 0.5, 0);
    }

    /** A non-number target with a valid risk is refused with the finiteness reason. */
    public function testNonNumberTargetRefused(): void
    {
        $this->expectException(\RangeException::class);
        $this->expectExceptionMessage('recommendPolicy: targetActions and perActionRisk must be finite numbers');
        BudgetForecast::recommendPolicy('x', 0.5);
    }

    /** A -0 target counts as 0 actions: bMax is +0. */
    public function testNegativeZeroTargetGivesPositiveZero(): void
    {
        $r = BudgetForecast::recommendPolicy(-0.0, 0.5);
        $this->assertSame(INF, fdiv(1.0, $r['bMax']));
    }

    /** A bound of exactly 1e21 prints in exponent form, as JS toFixed does from 1e21 up. */
    public function testBoundAtE21UsesExponentForm(): void
    {
        $r = BudgetForecast::recommendPolicy(1e21, 1.0);
        $this->assertSame(1e21, $r['autonomousBound']);
        $this->assertStringStartsWith('Σr ≤ bMax/κ = 1e+21 ≥ ', $r['rationale']);
    }
}
