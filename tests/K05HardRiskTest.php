<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Risk;
use PHPUnit\Framework\TestCase;

/** The risk functional, threshold map, trust budget and plan geodesic (risk.ts), at their boundaries. */
final class K05HardRiskTest extends TestCase
{
    private const W = ['alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05];
    private const NONE = ['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];

    public function testScore(): void
    {
        $this->assertSame(0.0, Risk::score(self::NONE, self::W));
        $this->assertSame(0.1, Risk::score(['semanticDistance' => 0.4] + self::NONE, self::W));
        $this->assertEqualsWithDelta(1.0, Risk::score([], self::W), 1e-12, 'every input missing is its worst case');
        $this->assertSame(1.0, Risk::score(['semanticDistance' => 5, 'blastRadius' => 5, 'taint' => 5, 'age' => 5, 'reversibility' => -3, 'confidence' => -3], self::W), 'clamped to [0,1]');
        $this->assertSame(0.0, Risk::score(['semanticDistance' => -4] + self::NONE, self::W));
        $this->assertEqualsWithDelta(0.25, Risk::score(['semanticDistance' => NAN] + self::NONE, self::W), 1e-12, 'NaN is the worst case of that input');
        $this->assertEqualsWithDelta(0.2, Risk::score(['reversibility' => 0] + self::NONE, self::W), 1e-12);
        $this->assertEqualsWithDelta(0.1, Risk::score(['confidence' => 0] + self::NONE, self::W), 1e-12);
        $this->assertEqualsWithDelta(0.2, Risk::score(['taint' => 1] + self::NONE, self::W), 1e-12);
        $this->assertEqualsWithDelta(0.2, Risk::score(['blastRadius' => 1] + self::NONE, self::W), 1e-12);
        $this->assertEqualsWithDelta(0.05, Risk::score(['age' => 1] + self::NONE, self::W), 1e-12);
        $neg = self::W;
        $neg['alpha'] = -5.0;
        $this->assertSame(0.0, Risk::score(['semanticDistance' => 1] + self::NONE, $neg), 'a negative weight counts as 0');
    }

    public function testRequiredThreshold(): void
    {
        $t = static fn(float $r, bool $irr = false): array => Risk::requiredThreshold($r, 0.25, 0.6, $irr);
        $this->assertSame(['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => true], $t(0.25));
        $this->assertSame(['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => false], $t(0.0, true));
        $this->assertSame(['t' => 2, 'proof' => 'standard', 'optimisticAllowed' => false], $t(0.2500001));
        $this->assertSame(2, $t(0.6)['t']);
        $this->assertSame(['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false], $t(0.6000001));
        $this->assertSame(3, $t(NAN)['t'], 'NaN is the worst case');
        $this->assertSame(3, $t(INF)['t']);
    }

    public function testEscalate(): void
    {
        $one = Risk::requiredThreshold(0.0, 0.25, 0.6);
        $this->assertSame($one, Risk::escalate($one, 1));
        $this->assertSame(['t' => 2, 'proof' => 'standard', 'optimisticAllowed' => false], Risk::escalate($one, 2));
        $this->assertSame(['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false], Risk::escalate($one, 3));
        $three = Risk::requiredThreshold(1.0, 0.25, 0.6);
        $this->assertSame($three, Risk::escalate($three, 1), 'never lowers');
        $this->assertSame($three, Risk::escalate($three, 2));
    }

    public function testCostLeakDebitAge(): void
    {
        $this->assertSame(0.5, Risk::cost(0.5, 1.0));
        $this->assertSame(1.0, Risk::cost(NAN, 1.0), 'a non-finite r costs as 1');
        $this->assertSame(0.0, Risk::cost(0.5, -1.0));
        $this->assertSame(2.0, Risk::cost(1.0, 2.0));
        $b = ['B' => 1.0, 'tau' => 0.0, 'asOf' => null];
        $this->assertSame(['B' => 0.5, 'tau' => 0.0, 'asOf' => 1000000.0], Risk::leak($b, 1000000.0, 0.0005));
        $this->assertSame(0.0, Risk::leak($b, 10000000.0, 0.0005)['B'], 'floors at 0');
        $this->assertSame(1.0, Risk::leak($b, -5.0, 0.0005)['B'], 'a time before the last update leaks nothing');
        $again = Risk::leak(Risk::leak($b, 1000000.0, 0.0005), 1000000.0, 0.0005);
        $this->assertSame(0.5, $again['B'], 'idempotent at one time');
        $this->assertSame(0.75, Risk::debit(['B' => 1.0, 'tau' => 0.0, 'asOf' => null], 0.25)['B']);
        $this->assertSame(0.0, Risk::debit(['B' => 0.1, 'tau' => 0.0, 'asOf' => null], 5.0)['B']);
        $this->assertSame(0.5, Risk::ageSinceTouch(['B' => 1.0, 'tau' => 0.0], 1800000.0));
        $this->assertSame(1.0, Risk::ageSinceTouch(['B' => 1.0, 'tau' => 0.0], 9e9));
        $this->assertSame(0.0, Risk::ageSinceTouch(['B' => 1.0, 'tau' => 5.0], 1.0), 'clamped below');
        $this->assertSame(1.0, Risk::ageSinceTouch(['B' => 1.0, 'tau' => NAN], 1.0));
        $this->assertSame(1.0, Risk::ageSinceTouch(['B' => 1.0, 'tau' => 0.0], 1.0, 0.0));
    }

    public function testAdmissionAndTheReleaseDecision(): void
    {
        $this->assertSame(['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true], Risk::admission(1, true));
        $this->assertSame(['admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false], Risk::admission(1, false));
        $this->assertSame(['admit' => false, 'needStepUp' => true, 't' => 2, 'metered' => true], Risk::admission(2, true));
        $this->assertSame(['admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false], Risk::admission(2, false));
        $this->assertSame(['admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false], Risk::admission(3, true));
        $rt = Risk::requiredThreshold(0.1, 0.25, 0.6);
        $d = Risk::decideCore(true, true, true, true, $rt, Risk::admission(1, true));
        $this->assertSame(['release' => true, 'admit' => true, 'needStepUp' => false, 'threshold' => $rt, 'debit' => true], $d);
        foreach ([[false, true, true, true], [true, false, true, true], [true, true, false, true], [true, true, true, false]] as $i => [$a, $b, $c, $e]) {
            $x = Risk::decideCore($a, $b, $c, $e, $rt, Risk::admission(1, true));
            $this->assertFalse($x['release'], "input $i");
            $this->assertFalse($x['admit']);
            $this->assertTrue($x['needStepUp']);
            $this->assertFalse($x['debit']);
        }
        $x = Risk::decideCore(true, true, true, true, $rt, Risk::admission(1, false));
        $this->assertSame([true, false, true, 3, false], [$x['release'], $x['admit'], $x['needStepUp'], $x['threshold']['t'], $x['debit']]);
        $x = Risk::decideCore(true, true, true, true, Risk::requiredThreshold(0.5, 0.25, 0.6), Risk::admission(2, true));
        $this->assertSame([true, false, true, 2, true], [$x['release'], $x['admit'], $x['needStepUp'], $x['threshold']['t'], $x['debit']], 't=2 is metered');
    }

    private static function nodes(array ...$ns): array
    {
        return array_map(static fn(array $n): Obj => Obj::of($n), $ns);
    }

    public function testPlanGeodesic(): void
    {
        $plain = self::nodes(['id' => 'a'], ['id' => 'b'], ['id' => 'c'], ['id' => 'd']);
        $this->assertSame(0.0, Risk::planGeodesic($plain, 'b', 'b'));
        $this->assertSame(1.0 / 3, Risk::planGeodesic($plain, 'a', 'b'), 'no edges: index distance over n - 1');
        $this->assertSame(1.0, Risk::planGeodesic($plain, 'a', 'd'));
        $this->assertSame(1.0, Risk::planGeodesic($plain, 'a', 'zzz'), 'an unknown id is 1');
        $this->assertSame(1.0, Risk::planGeodesic($plain, null, 'a'));
        $this->assertSame(1.0, Risk::planGeodesic(['x' => 1], 'a', 'b'));
        $edges = self::nodes(['id' => 'a'], ['id' => 'b', 'pre' => 'a'], ['id' => 'c', 'pre' => Obj::of(['after' => 'b'])], ['id' => 'd'], ['id' => 'e', 'post' => Obj::of(['then' => ['a']])]);
        $this->assertSame(0.25, Risk::planGeodesic($edges, 'a', 'b'));
        $this->assertSame(0.5, Risk::planGeodesic($edges, 'a', 'c'));
        $this->assertSame(0.25, Risk::planGeodesic($edges, 'e', 'a'), 'edges are undirected');
        $this->assertSame(0.75, Risk::planGeodesic($edges, 'e', 'c'));
        $this->assertSame(1.0, Risk::planGeodesic($edges, 'a', 'd'), 'unreachable is 1');
    }

    public function testInputsOf(): void
    {
        $this->assertSame(['semanticDistance' => 1.0, 'reversibility' => 0.0, 'blastRadius' => 1.0, 'taint' => 1.0, 'confidence' => 0.0, 'age' => 1.0], Risk::inputsOf([]));
        $this->assertSame(0.3, Risk::inputsOf(['taint' => 0.3, 'blastRadius' => NAN, 'age' => 'x'])['taint']);
        $this->assertSame(1.0, Risk::inputsOf(['blastRadius' => NAN])['blastRadius']);
        $this->assertTrue(Risk::fastPathClass('reversible') && Risk::fastPathClass('rate_limited') && Risk::fastPathClass('costly'));
        $this->assertFalse(Risk::fastPathClass('irreversible') || Risk::fastPathClass(null) || Risk::fastPathClass('weird'));
    }
}
