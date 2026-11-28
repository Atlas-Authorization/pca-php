<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentMultiAgg;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 32 mutation kills for src/IntentMultiAgg.php: input checks, the joint grant's caveat, per-principal orgs and fidelity, metric defaults, lifting and cross-org refusal. */
final class IntentSurvivorKill32IntentMultiAggTest extends TestCase
{
    private const C = 'action.params.c';

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

    private static function cat(?string $path, array $exacts): Obj
    {
        $d = Obj::of(['kind' => 'cat', 'values' => array_map(static fn(string $v): Obj => Obj::of(['kind' => 'exact', 'value' => $v]), $exacts)]);
        if ($path !== null) {
            $d->set('path', $path);
        }
        return $d;
    }

    private static function vs(string $verb = 'x.do', string $rev = 'reversible', array $dims = []): Obj
    {
        return Obj::of(['verb' => $verb, 'reversibility' => $rev, 'weight' => 1, 'dims' => $dims]);
    }

    private static function omega(Obj ...$verbs): Obj
    {
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => $verbs]);
    }

    /** A map over one dimensionless verb whose only cell the principal confirmed (y = 1), or left unobserved. */
    private static function map(string $ref, ?Obj $vs = null, bool $observe = true): Obj
    {
        $vs ??= self::vs();
        $l = IntentMapKit::createLearner(self::omega($vs));
        if ($observe) {
            $l->observe(IntentOmega::cellRep($vs, []), 1);
        }
        return IntentMapKit::emitIntentMap($l, $ref);
    }

    private static function thrown(\Closure $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'no throw';
    }

    /** Maps over different omegas are refused with the lifting hint. */
    public function testMapsMustShareTheOmega(): void
    {
        self::assertSame("InvalidArgumentException: aggregateIntentMaps: maps must share \u{03A9} (lift them with crossOrgAggregate)",
            self::thrown(static fn() => IntentMultiAgg::combineIntentMaps([self::map('p1', self::vs('a')), self::map('p2', self::vs('b'))])));
    }

    /** An input with an aggregation, or with two principals, is refused even when it carries a string intent_ref. */
    public function testOnlySinglePrincipalInputs(): void
    {
        $msg = 'InvalidArgumentException: aggregateIntentMaps: every input must be a single-principal map with an intent_ref';
        $agg = self::map('p1');
        $agg->set('aggregation', 'x');
        self::assertSame($msg, self::thrown(static fn() => IntentMultiAgg::combineIntentMaps([$agg])));
        $two = self::map('p1');
        $two->set('principals', ['p1', 'p2']);
        self::assertSame($msg, self::thrown(static fn() => IntentMultiAgg::combineIntentMaps([$two])));
    }

    /** The joint grant of a reversible verb carries the reversibility cap 'reversible'; a verb of unknown reversibility adds none. */
    public function testTheJointGrantCaveat(): void
    {
        $agg = IntentMultiAgg::combineIntentMaps([self::map('p1')]);
        self::assertSame('[{"type":"reversibility_max","class":"reversible"}]', Json::stringify($agg->get('grant')->get('caveats')));
        $odd = IntentMultiAgg::combineIntentMaps([self::map('p1', self::vs('x.do', 'odd'))]);
        self::assertSame('[]', Json::stringify($odd->get('grant')->get('caveats')));
    }

    /** A principal's org is recorded from opts.orgs; with nothing at risk the fidelity estimate is exactly 1. */
    public function testOrgAndFidelity(): void
    {
        $agg = IntentMultiAgg::combineIntentMaps([self::map('p1')], ['orgs' => ['p1' => 'OrgA']]);
        self::assertSame('OrgA', $agg->get('aggregation')->get('per_principal')[0]->get('org'));
        self::assertSame(1000000, $agg->get('metrics')->get('fidelity_est_ppm'));
        $plain = IntentMultiAgg::combineIntentMaps([self::map('p1')]);
        self::assertFalse($plain->get('aggregation')->get('per_principal')[0]->has('org'));
    }

    /** A metric a map does not report counts as 0. */
    public function testAMissingMetricCountsAsZero(): void
    {
        $m = self::map('p1');
        $m->set('metrics', $m->get('metrics')->without('questions'));
        self::assertSame(0, IntentMultiAgg::combineIntentMaps([$m])->get('metrics')->get('questions'));
    }

    /** The aggregate's observations are a list even when an input keyed them. */
    public function testObservationsAreAList(): void
    {
        $m = self::map('p1');
        $m->set('observations', ['k' => $m->get('observations')[0]]);
        $obs = IntentMultiAgg::combineIntentMaps([$m])->get('observations');
        self::assertTrue(is_array($obs) && array_is_list($obs));
        self::assertCount(1, $obs);
    }

    /** ruleOf needs the recorded vetoers. */
    public function testRuleOfNeedsVetoers(): void
    {
        self::assertSame("OutOfBoundsException: 'vetoers'", self::thrown(static fn() => IntentMultiAgg::ruleOf(['aggregation' => ['rule' => 'unanimity']])));
    }

    /** Lifting onto an omega without the observation's verb is refused, naming the verb. */
    public function testLiftRefusesAMissingVerb(): void
    {
        self::assertSame("InvalidArgumentException: liftIntentMap: verb x.do missing from \u{03A9}",
            self::thrown(static fn() => IntentMultiAgg::liftIntentMap(self::map('p1'), self::omega(self::vs('y.do')))));
    }

    /** An observation outside the map's own omega is refused (also when a target dimension has no path, read as ''). */
    public function testLiftRefusesAnObservationOutsideItsOmega(): void
    {
        $m = self::map('p1', self::vs('x.do', 'reversible', [self::cat(self::C, ['a'])]), false);
        $m->set('observations', [Obj::of(['verb' => 'x.do', 'values' => Obj::of([self::C => 'zzz']), 'y' => 1, 'source' => 'elicitation'])]);
        $msg = "InvalidArgumentException: liftIntentMap: an observation of x.do lies outside the map's own \u{03A9}";
        self::assertSame($msg, self::thrown(static fn() => IntentMultiAgg::liftIntentMap($m, self::omega(self::vs('x.do', 'reversible', [self::cat(self::C, ['a'])])))));
        self::assertSame($msg, self::thrown(static fn() => IntentMultiAgg::liftIntentMap($m, self::omega(self::vs('x.do', 'reversible', [self::cat(null, ['a'])])))));
    }

    /** A target dimension the observation does not name is filled with its first cell's representative, so the observation is kept. */
    public function testLiftFillsANewDimensionWithItsFirstCell(): void
    {
        $lifted = IntentMultiAgg::liftIntentMap(self::map('p1'), self::omega(self::vs('x.do', 'reversible', [self::cat(self::C, ['a', 'b'])])));
        $obs = $lifted->get('observations');
        self::assertCount(1, $obs);
        self::assertSame('{"action.params.c":"a"}', Json::stringify($obs[0]->get('values')));
        self::assertSame('elicitation', $obs[0]->get('source'));
    }

    /** An observation without a source lifts with the empty source. */
    public function testLiftOfAnObservationWithoutASource(): void
    {
        $m = self::map('p1');
        $m->set('observations', [Obj::of(['verb' => 'x.do', 'values' => new Obj(), 'y' => 1])]);
        $obs = IntentMultiAgg::liftIntentMap($m, self::omega(self::vs()))->get('observations');
        self::assertCount(1, $obs);
        self::assertSame('', $obs[0]->get('source'));
    }

    /** With a verb listed twice, the first listing is the one used, in the map's own omega and in the target. */
    public function testLiftUsesTheFirstListingOfAVerb(): void
    {
        $dup = self::omega(self::vs(), self::vs('x.do', 'reversible', [self::cat(self::C, ['a'])]));
        $m = self::map('p1');
        $m->set('omega', IntentMapKit::omegaToJSON($dup));
        self::assertCount(1, IntentMultiAgg::liftIntentMap($m, self::omega(self::vs()))->get('observations'), 'own omega: the dimensionless listing holds it');
        $obs = IntentMultiAgg::liftIntentMap(self::map('p1'), $dup)->get('observations');
        self::assertCount(1, $obs);
        self::assertSame([], $obs[0]->get('values')->keys(), 'target: the dimensionless listing adds no value');
    }

    /** A map that does not verify stops a cross-org aggregate, with its index and problems. */
    public function testCrossOrgAggregateRefusesAnUnverifiedMap(): void
    {
        $bad = self::map('p1');
        $bad->set('kind', 'x');
        self::assertSame('InvalidArgumentException: crossOrgAggregate: map 0 does not verify: not an intent map v1',
            self::thrown(static fn() => IntentMultiAgg::crossOrgAggregate([$bad], ['kind' => 'unanimity'])));
    }
}
