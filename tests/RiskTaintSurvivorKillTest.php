<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\InMemoryTaintRegistry;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Risk;
use Atlas\Pca\Taint;
use PHPUnit\Framework\TestCase;

/** Exact-value kills for the risk functional, the plan geodesic and the information-flow taint gate. */
final class RiskTaintSurvivorKillTest extends TestCase
{
    private static function label(string $kind, ?string $id = null): Obj
    {
        return $id === null ? Obj::of(['kind' => $kind]) : Obj::of(['kind' => $kind, 'id' => $id]);
    }

    private static function prov(array $refs): Obj
    {
        return Obj::of(['trusted_refs' => $refs]);
    }

    // ---- Risk ---------------------------------------------------------------------------------------------------------

    public function testNegativeZeroIsNotRewrittenByTheClamp(): void
    {
        // r = -0.0 passes through clamp01 unchanged (neither below 0 nor above 1); kappa * -0.0 is -0.0
        $this->assertSame(-INF, fdiv(1.0, Risk::cost(-0.0, 1.0)));
        $this->assertSame(INF, fdiv(1.0, Risk::cost(0.0, 1.0)));
    }

    public function testANegativeZeroWeightOrKappaCountsAsPositiveZero(): void
    {
        $w = ['alpha' => -0.0, 'beta' => -0.0, 'gamma' => -0.0, 'delta' => -0.0, 'epsilon' => -0.0, 'zeta' => -0.0];
        $in = ['semanticDistance' => 0.5, 'reversibility' => 0.5, 'blastRadius' => 0.5, 'taint' => 0.5, 'confidence' => 0.5, 'age' => 0.5];
        $this->assertSame(INF, fdiv(1.0, Risk::score($in, $w)));
        $this->assertSame(INF, fdiv(1.0, Risk::cost(0.5, -0.0)));
    }

    public function testAnInfiniteWeightIsDroppedNotApplied(): void
    {
        $w = ['alpha' => INF, 'beta' => 0.0, 'gamma' => 0.0, 'delta' => 0.0, 'epsilon' => 0.0, 'zeta' => 0.0];
        $in = ['semanticDistance' => 0.5, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];
        $this->assertSame(0.0, Risk::score($in, $w));
    }

    public function testPolicyOfReadsAnObjAndAPlainArray(): void
    {
        $expect = ['weights' => ['alpha' => 0.5, 'beta' => 2.0, 'gamma' => 0.0, 'delta' => 0.0, 'epsilon' => 0.0, 'zeta' => 0.0],
            'theta1' => 0.25, 'theta2' => 0.5, 'kappa' => 1.0, 'lambda' => 0.0, 'rho' => 0.5, 'bMax' => 0.0];
        $arr = ['weights' => ['alpha' => '0.5', 'beta' => 2], 'theta1' => '0.25', 'theta2' => 0.5, 'kappa' => 1, 'lambda' => '0', 'rho' => 0.5];
        $this->assertSame($expect, Risk::policyOf($arr));
        $obj = Obj::of(['weights' => Obj::of(['alpha' => new Num('0.5'), 'beta' => new Num('2')]), 'theta1' => new Num('0.25'),
            'theta2' => new Num('0.5'), 'kappa' => new Num('1'), 'lambda' => new Num('0'), 'rho' => new Num('0.5')]);
        $this->assertSame($expect, Risk::policyOf($obj));
    }

    public function testRequiredThresholdIsReversibleByDefault(): void
    {
        $this->assertSame(['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => true], Risk::requiredThreshold(0.1, 0.3, 0.6));
        $this->assertSame(['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => false], Risk::requiredThreshold(0.1, 0.3, 0.6, true));
    }

    public function testEscalateKeepsTheStrongerProofName(): void
    {
        $std = ['t' => 2, 'proof' => 'standard', 'optimisticAllowed' => false];
        $this->assertSame(['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false], Risk::escalate($std, 3));
        $this->assertSame($std, Risk::escalate($std, 1));
        $this->assertSame($std, Risk::escalate($std, 2));
        $claim = ['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => true];
        $this->assertSame(['t' => 2, 'proof' => 'standard', 'optimisticAllowed' => false], Risk::escalate($claim, 2));
        $this->assertSame($claim, Risk::escalate($claim, 1));
        $strong = ['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false];
        $this->assertSame($strong, Risk::escalate($strong, 2));
        $this->assertSame($strong, Risk::escalate($strong, 3));
    }

    public function testLeakWithAnInfiniteNowDrainsNothing(): void
    {
        $r = Risk::leak(['B' => 5.0, 'tau' => 0.0], INF, 1.0);
        $this->assertSame(5.0, $r['B']);
        $this->assertSame(0.0, $r['asOf']);
        $this->assertSame(4.0, Risk::leak(['B' => 5.0, 'tau' => 0.0], 1000.0, 1.0)['B']);
    }

    public function testInputsOfReturnsFloats(): void
    {
        $this->assertSame(['semanticDistance' => 1.0, 'reversibility' => 1.0, 'blastRadius' => 1.0, 'taint' => 0.0, 'confidence' => 0.0, 'age' => 1.0],
            Risk::inputsOf(['reversibility' => 1, 'taint' => 0]));
    }

    private static function node(string $id, ?array $pre = null, ?array $post = null): Obj
    {
        $o = Obj::of(['id' => $id]);
        if ($pre !== null) {
            $o->set('pre', Obj::of($pre));
        }
        if ($post !== null) {
            $o->set('post', Obj::of($post));
        }
        return $o;
    }

    public function testGeodesicIgnoresPlanEntriesThatAreNotObjects(): void
    {
        $plan = ['junk', self::node('a'), self::node('b')];
        $this->assertSame(0.5, Risk::planGeodesic($plan, 'a', 'b'));
    }

    public function testGeodesicWithoutEdgesIsTheIndexDistance(): void
    {
        $plan = [self::node('a'), self::node('b'), self::node('c')];
        $this->assertSame(0.5, Risk::planGeodesic($plan, 'b', 'c'));
        $this->assertSame(1.0, Risk::planGeodesic($plan, 'a', 'c'));
        $this->assertSame(0.0, Risk::planGeodesic($plan, 'b', 'b'));
    }

    public function testGeodesicFollowsABeforeReference(): void
    {
        $plan = [self::node('a', null, ['before' => 'c']), self::node('b'), self::node('c')];
        $this->assertSame(0.5, Risk::planGeodesic($plan, 'a', 'c'));
    }

    public function testGeodesicReadsEveryReferenceOfAList(): void
    {
        $plan = [self::node('a'), self::node('b'), self::node('c'), self::node('d', ['after' => ['a', 'b']])];
        $this->assertEqualsWithDelta(2 / 3, Risk::planGeodesic($plan, 'a', 'b'), 1e-12);
    }

    public function testGeodesicFromAnIsolatedNodeIsUnreachable(): void
    {
        $last = [self::node('a', null, ['next' => 'b']), self::node('b'), self::node('c')];
        $this->assertSame(1.0, Risk::planGeodesic($last, 'c', 'a'));
        $first = [self::node('x'), self::node('a', null, ['next' => 'b']), self::node('b')];
        $this->assertSame(1.0, Risk::planGeodesic($first, 'x', 'a'));
        $this->assertSame(0.5, Risk::planGeodesic($first, 'a', 'b'));
    }

    // ---- Taint --------------------------------------------------------------------------------------------------------

    public function testLabelRankAndTaintValue(): void
    {
        foreach (['trusted' => 0, 'first_party' => 1, 'tool' => 2, 'web' => 3, 'agent' => 4] as $kind => $rank) {
            $this->assertSame($rank, Taint::labelRank(self::label($kind)), $kind);
            $this->assertSame($rank / 4.0, Taint::taintValue(self::label($kind)), $kind);
        }
        $this->assertSame(4, Taint::labelRank(null));
        $this->assertSame(4, Taint::labelRank('trusted'));
        $this->assertSame(4, Taint::labelRank(Obj::of(['kind' => 5])));
        $this->assertSame(4, Taint::labelRank(Obj::of(['kind' => 'bogus'])));
        $this->assertSame(0.25, Taint::taintValue(self::label('first_party')));
    }

    public function testJoinLabel(): void
    {
        $a = self::label('tool', 'x');
        $b = self::label('tool', 'y');
        $j = Taint::joinLabel($a, $b);
        $this->assertSame(['kind'], $j->keys());
        $this->assertSame('tool', $j->get('kind'));
        $this->assertSame($a, Taint::joinLabel($a, self::label('tool', 'x')) === $a ? $a : null, 'equal ids keep the first label');
        $this->assertSame($a, Taint::joinLabel($a, $a));
        $hi = self::label('web');
        $this->assertSame($hi, Taint::joinLabel($a, $hi));
        $this->assertSame($hi, Taint::joinLabel($hi, $a));
        $this->assertSame($a, Taint::joinLabel($a, self::label('trusted')));
        $this->assertSame($a, Taint::joinLabel(self::label('trusted'), $a));
    }

    public function testJoinLabels(): void
    {
        $e = Taint::joinLabels([]);
        $this->assertSame(['kind'], $e->keys());
        $this->assertSame('agent', $e->get('kind'));
        $one = self::label('tool', 'x');
        $this->assertSame($one, Taint::joinLabels([$one]));
        $this->assertSame('web', Taint::joinLabels([self::label('trusted'), self::label('web'), self::label('tool')])->get('kind'));
    }

    public function testClassifyRef(): void
    {
        $reg = (new InMemoryTaintRegistry())->recordTrusted('r');
        foreach ([123, null, '', ['x']] as $bad) {
            $l = Taint::classifyRef($bad, $reg, null);
            $this->assertSame(['kind'], $l->keys());
            $this->assertSame('agent', $l->get('kind'));
        }
        $this->assertSame('trusted', Taint::classifyRef('r', $reg, null)->get('kind'));
        $g = new class { public function node(string $r): bool { return $r === 'n'; } };
        $this->assertSame('first_party', Taint::classifyRef('n', $reg, $g)->get('kind'));
        $this->assertSame('agent', Taint::classifyRef('other', $reg, $g)->get('kind'));
        $this->assertSame('agent', Taint::classifyRef('other', $reg, null)->get('kind'));
        $at = Taint::classifyRef(str_repeat('a', 128), $reg, null);
        $this->assertSame(['kind', 'id'], $at->keys());
        $this->assertSame('agent', $at->get('kind'));
        $this->assertSame(str_repeat('a', 128), $at->get('id'));
        $over = Taint::classifyRef(str_repeat('a', 129), $reg, null);
        $this->assertSame(['kind'], $over->keys());
        $this->assertSame('agent', $over->get('kind'));
    }

    public function testComputeTaintInvalidShapesFailClosedWithTheirReason(): void
    {
        $reg = (new InMemoryTaintRegistry())->recordTrusted('a');
        $check = function (array $r, string $reason): void {
            $this->assertSame(1.0, $r['taint']);
            $this->assertSame(['kind'], $r['label']->keys());
            $this->assertSame('agent', $r['label']->get('kind'));
            $this->assertSame([], $r['refs']);
            $this->assertFalse($r['valid']);
            $this->assertSame($reason, $r['reason']);
        };
        $check(Taint::computeTaint(null, $reg), 'taint: provenance is absent or malformed');
        $check(Taint::computeTaint('x', $reg), 'taint: provenance is absent or malformed');
        $check(Taint::computeTaint(self::prov(['a']), new \stdClass()), 'taint: no trusted-input registry');
        $check(Taint::computeTaint(self::prov(['a']), null), 'taint: no trusted-input registry');
        $check(Taint::computeTaint(Obj::of(['trusted_refs' => 'notalist']), null), 'taint: no trusted-input registry');
        $check(Taint::computeTaint(Obj::of(['trusted_refs' => 'str']), $reg), 'taint: trusted_refs must be an array');
        $check(Taint::computeTaint(Obj::of(['trusted_refs' => ['k' => 'a']]), $reg), 'taint: trusted_refs must be an array');
        $check(Taint::computeTaint(self::prov(['a', '']), $reg), 'taint: trusted_refs must be non-empty strings');
        $check(Taint::computeTaint(self::prov([5]), $reg), 'taint: trusted_refs must be non-empty strings');
    }

    public function testComputeTaintWithoutTrustedRefsIsValidAndWorstCase(): void
    {
        $r = Taint::computeTaint(Obj::of([]), new InMemoryTaintRegistry());
        $this->assertTrue($r['valid']);
        $this->assertSame(1.0, $r['taint']);
        $this->assertSame([], $r['refs']);
        $this->assertArrayNotHasKey('reason', $r);
    }

    public function testComputeTaintRecordsEachRefWithItsLabel(): void
    {
        $reg = (new InMemoryTaintRegistry())->recordTrusted('a')->recordTool('t', 'tool-1');
        $r = Taint::computeTaint(self::prov(['a', 't']), $reg);
        $this->assertTrue($r['valid']);
        $this->assertSame(0.5, $r['taint']);
        $this->assertCount(2, $r['refs']);
        $this->assertSame('a', $r['refs'][0]['ref']);
        $this->assertSame('trusted', $r['refs'][0]['label']->get('kind'));
        $this->assertSame('t', $r['refs'][1]['ref']);
        $this->assertSame('tool-1', $r['refs'][1]['label']->get('id'));
        $this->assertSame('tool', $r['label']->get('kind'));
    }

    public function testComputeTaintReportsAThrowingRegistry(): void
    {
        $reg = new class {
            public function lookup(string $d): ?Obj
            {
                throw new \RuntimeException('boom');
            }
        };
        $r = Taint::computeTaint(self::prov(['x']), $reg);
        $this->assertFalse($r['valid']);
        $this->assertSame('taint: evaluation error (fail closed): boom', $r['reason']);
    }

    public function testTaintGateReasonsAndBounds(): void
    {
        $reg = (new InMemoryTaintRegistry())->recordTrusted('a');
        $this->assertSame(['ok' => false, 'reason' => 'taint: provenance is absent or malformed'], Taint::taintGate(null, $reg, null, 1));
        $this->assertSame(['ok' => true], Taint::taintGate(self::prov(['a']), $reg, null, new Num('0.5')));
        $this->assertSame(['ok' => false, 'reason' => 'taint gate misconfigured: maxTaint must be a non-negative number (fail closed)'],
            Taint::taintGate(self::prov(['a']), $reg, null, new Num('-1')));
        // the worst label (rank 4, taint 1) passes only a bound of at least 1
        $this->assertSame(['ok' => true], Taint::taintGate(self::prov(['unknown']), $reg, null, 1.0));
        $this->assertSame(['ok' => true], Taint::taintGate(self::prov(['unknown']), $reg, null, 2));
        $this->assertSame(['ok' => false, 'reason' => 'information-flow taint 1 exceeds policy max 0.5'], Taint::taintGate(self::prov(['unknown']), $reg, null, 0.5));
        $this->assertSame(['ok' => false, 'reason' => 'information-flow taint 1 exceeds policy max 0'], Taint::taintGate(self::prov(['unknown']), $reg, null, 0));
        $this->assertSame(['ok' => true], Taint::taintGate(self::prov(['a']), $reg, null, 0.0));
        $this->assertFalse(Taint::taintGate(self::prov(['a']), $reg, null, NAN)['ok']);
        $this->assertFalse(Taint::taintGate(self::prov(['a']), $reg, null, INF)['ok']);
    }

    public function testTheRegistryStoresOnlyANonEmptyDigestWithARealLevel(): void
    {
        $reg = new InMemoryTaintRegistry();
        $this->assertSame(0, $reg->size());
        $reg->record('', self::label('trusted'));
        $reg->record('x', self::label('bogus'));
        $reg->record('y', Obj::of([]));
        $this->assertSame(0, $reg->size());
        $this->assertSame($reg, $reg->record('d', self::label('tool', 'i')));
        $this->assertSame(1, $reg->size());
        $reg->recordFirstParty('f');
        $this->assertSame(2, $reg->size());
        $this->assertSame('first_party', $reg->lookup('f')->get('kind'));
        $this->assertSame('tool', $reg->lookup('d')->get('kind'));
        $this->assertNull($reg->lookup('zzz'));
    }
}
