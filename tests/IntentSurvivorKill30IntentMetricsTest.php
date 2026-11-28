<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\HarmModel;
use Atlas\Pca\IntentLearner;
use Atlas\Pca\IntentMetrics;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentMetrics.php: Monte Carlo and exact grant measures, the Hoeffding width and the Wilson interval. */
final class IntentSurvivorKill30IntentMetricsTest extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function vs(array $dims = []): Obj
    {
        return Obj::of(['verb' => 'x.do', 'reversibility' => 'irreversible', 'weight' => 1, 'dims' => $dims]);
    }

    private static function omega(Obj $vs): Obj
    {
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => [$vs]]);
    }

    private static function grantAll(): array
    {
        return ['predicates' => [Obj::of(['verb' => 'x.do', 'resource' => '*'])], 'caveats' => []];
    }

    private static function harm(float $h): HarmModel
    {
        return new HarmModel(static fn($vs) => $h, static fn($d, $x) => 1.0);
    }

    /** The default Monte Carlo sample count. */
    public function testDefaultSamples(): void
    {
        $this->assertSame(20000, IntentMetrics::DEFAULT_SAMPLES);
    }

    /** Hoeffding: q = 0 gives width 0 (not NaN); otherwise r * sqrt(ln(2/delta) / 2M). */
    public function testHoeffding(): void
    {
        $this->assertSame(0.0, IntentMetrics::hoeffdingHalfWidth(1, 10, 2));
        $this->assertEqualsWithDelta(2 * sqrt(log(40) / 100), IntentMetrics::hoeffdingHalfWidth(2, 50), 1e-12);
    }

    /** measureGrant: every number from two samples of one irreversible cell (harm 10, acceptability 0.5). */
    public function testMeasureGrant(): void
    {
        $omega = self::omega(self::vs());
        $r = IntentMetrics::measureGrant($omega, self::grantAll(), static fn($vs, $o) => 0.5, ['samples' => 2]);
        $this->assertSame(['risk' => 5.0, 'burden' => 0.0, 'riskMax' => 5.0, 'fidelity' => 0.0, 'samples' => 2,
            'riskHalfWidth' => IntentMetrics::hoeffdingHalfWidth(10.0, 2)], $r);
        $c = IntentMetrics::measureGrant($omega, self::grantAll(), static fn($vs, $o) => 0.5, ['samples' => 2.5, 'harm' => self::harm(0.5)]);
        $this->assertSame(2, $c['samples']);
        $this->assertSame(0.25, $c['riskMax']);
        $this->assertSame(IntentMetrics::hoeffdingHalfWidth(0.5, 2), $c['riskHalfWidth']);
    }

    /** No risk at all (acceptability 1, or a boolean true): fidelity is exactly 1. */
    public function testMeasureGrantNoRisk(): void
    {
        $omega = self::omega(self::vs());
        foreach ([1, true] as $a) {
            $r = IntentMetrics::measureGrant($omega, self::grantAll(), static fn($vs, $o) => $a, ['samples' => 2]);
            $this->assertSame(0.0, $r['riskMax']);
            $this->assertSame(1.0, $r['fidelity']);
        }
        $e = IntentMetrics::measureGrantExact($omega, self::grantAll(), static fn($vs, $o) => 1);
        $this->assertSame(['risk' => 0.0, 'burden' => 0.0, 'riskMax' => 0.0, 'fidelity' => 1.0, 'meanHarm' => 10.0], $e);
    }

    /** measureGrantExact uses the given harm model. */
    public function testMeasureGrantExactHarm(): void
    {
        $e = IntentMetrics::measureGrantExact(self::omega(self::vs()), self::grantAll(), static fn($vs, $o) => 0.5, self::harm(3.0));
        $this->assertSame(['risk' => 1.5, 'burden' => 0.0, 'riskMax' => 1.5, 'fidelity' => 0.0, 'meanHarm' => 3.0], $e);
    }

    /** One cell, p in [tau, 1): every sample adds exactly (1 - p) * harm, so the estimate is that contribution. */
    public function testResidualRiskOneCell(): void
    {
        $vs = self::vs();
        $l = new IntentLearner(self::omega($vs), ['eta' => 0.1]);
        $o = IntentOmega::cellRep($vs, []);
        $l->observe($o, 1);
        $p = $l->acceptance($o);
        $this->assertTrue($p >= 0.95 && $p < 1.0, 'control');
        $this->assertSame((1 - $p) * 10.0, IntentMetrics::estimateResidualRiskMC($l, ['samples' => 2]));
        $this->assertSame((1 - $p) * 3.0, IntentMetrics::estimateResidualRiskMC($l, ['samples' => 2], self::harm(3.0)));
        $this->assertSame((1 - $p) * 10.0, IntentMetrics::estimateResidualRiskMC($l, ['samples' => 2.5]));
    }

    /** The default seed is 7: the same draws as seed 7, not seed 0, 6 or 8 (a two-cell learner, one cell in the grant). */
    public function testResidualRiskDefaultSeed(): void
    {
        $vs = self::vs([Obj::of(['kind' => 'cat', 'path' => 'action.params.s', 'values' => [
            Obj::of(['kind' => 'exact', 'value' => 'a']), Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER])]])]);
        $l = new IntentLearner(self::omega($vs), ['eta' => 0.1]);
        $l->observe(IntentOmega::cellRep($vs, [0]), 1);
        $l->observe(IntentOmega::cellRep($vs, [0]), 1);
        $l->observe(IntentOmega::cellRep($vs, [1]), 1);
        $d = IntentMetrics::estimateResidualRiskMC($l, ['samples' => 9]);
        // mulberry32(7): 5 of the 9 draws land on cell a (in the grant); cell other (p ~ 0.9 < tau) is outside it
        $o0 = IntentOmega::cellRep($vs, [0]);
        $h = IntentOmega::harmOf($vs, $o0, IntentOmega::defaultHarm());
        $c0 = (1 - $l->acceptance($o0)) * ($h instanceof Num ? $h->float() : (float)$h);
        $r = 0.0;
        for ($i = 0; $i < 5; $i++) {
            $r += $c0;
        }
        $this->assertSame($r / 9.0, $d);
        $this->assertSame(IntentMetrics::estimateResidualRiskMC($l, ['samples' => 9, 'seed' => 7]), $d);
    }

    /** Wilson: the empty-sample answer, and exact values at the clamps (lo clamps to the int 0, hi to the int 1). */
    public function testWilson(): void
    {
        $e = IntentMetrics::wilsonInterval(0, 0);
        $this->assertSame(['p', 'lo', 'hi'], array_keys($e));
        $this->assertNan($e['p']);
        $this->assertSame(0, $e['lo']);
        $this->assertSame(1, $e['hi']);
        $this->assertSame(['p' => 0.3, 'lo' => 0.10779126740630099, 'hi' => 0.6032218525388546], IntentMetrics::wilsonInterval(3, 10));
        $this->assertSame(['p' => 1.0, 'lo' => 0.20654931437723745, 'hi' => 1], IntentMetrics::wilsonInterval(1, 1));
        $this->assertSame(0, IntentMetrics::wilsonInterval(0, 21)['lo']);
        $this->assertSame(['p' => 0.0, 'lo' => 0, 'hi' => 0.2775327998628892], IntentMetrics::wilsonInterval(0, 10));
        $this->assertSame(['p' => 0.0, 'lo' => 0, 'hi' => 0.0], IntentMetrics::wilsonInterval(0, 10, 0));
    }
}
