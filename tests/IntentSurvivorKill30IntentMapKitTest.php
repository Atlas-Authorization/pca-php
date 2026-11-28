<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentLearner;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentMapKit.php: rounding, the hash model, omega JSON, learner options and map verification. */
final class IntentSurvivorKill30IntentMapKitTest extends TestCase
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

    private static function vs(mixed $verb = 'x.do'): Obj
    {
        return Obj::of(['verb' => $verb, 'reversibility' => 'reversible', 'weight' => 1, 'dims' => []]);
    }

    private static function omega(mixed $verb = 'x.do'): Obj
    {
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => [self::vs($verb)]]);
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

    /** Math.round: ties toward +infinity, and the largest double below 0.5 rounds to 0. */
    public function testJsRoundAndPpm(): void
    {
        $this->assertSame(3, IntentMapKit::jsRound(2.5));
        $this->assertSame(-2, IntentMapKit::jsRound(-2.5));
        $this->assertSame(0, IntentMapKit::jsRound(0.49999999999999994));
        $this->assertSame(500000, IntentMapKit::ppm(0.5));
    }

    /** Numeric-looking keys become string members; an Obj is deep-copied with its nested assoc arrays converted. */
    public function testObjConversion(): void
    {
        $o = IntentMapKit::obj([1 => 'x']);
        $this->assertInstanceOf(Obj::class, $o);
        $this->assertSame(['1'], $o->keys());
        $in = Obj::of(['a' => ['b' => 1]]);
        $out = IntentMapKit::obj($in);
        $this->assertNotSame($in, $out);
        $this->assertInstanceOf(Obj::class, $out->get('a'));
        $this->assertSame(1, $out->get('a')->get('b'));
    }

    /** The hash model turns every float (inside objects and lists) into its JS number form, so 1e15 hashes like the integer. */
    public function testHashModelNumbers(): void
    {
        $this->assertSame(IntentMapKit::intentMapDigest(['x' => new Num('1000000000000000')]), IntentMapKit::intentMapDigest(['x' => 1e15]));
        $this->assertSame(IntentMapKit::intentMapDigest(['x' => [new Num('1000000000000000')]]), IntentMapKit::intentMapDigest(['x' => [1e15]]));
    }

    /** A non-finite number is refused by the hash model itself. */
    public function testHashModelRefusesNonFinite(): void
    {
        $this->assertSame('InvalidArgumentException: non-finite number', self::thrown(static fn() => IntentMapKit::intentMapDigest(['x' => INF])));
    }

    /** A non-list where a list is required is a TypeError with the fixed text. */
    public function testListRefusal(): void
    {
        $this->assertSame('TypeError: expected an array', self::thrown(static fn() => IntentMapKit::omegaToJSON(['verbs' => 'x'])));
    }

    /** omegaToJSON: unequal weights are ppm with a floor of 1; cuts, values and approximate come out as lists. */
    public function testOmegaToJSON(): void
    {
        $num = ['kind' => 'num', 'path' => 'action.params.n', 'lo' => 0, 'hi' => 10, 'cuts' => [1 => 5]];
        $cat = ['kind' => 'cat', 'path' => 'action.params.s', 'values' => [1 => ['kind' => 'other', 'value' => IntentOmega::OTHER]]];
        $o = ['verbs' => [['verb' => 'a', 'reversibility' => 'reversible', 'weight' => 0, 'dims' => [$num, $cat]],
            ['verb' => 'b', 'reversibility' => 'reversible', 'weight' => 1, 'dims' => []]], 'approximate' => [1 => 'z']];
        $j = IntentMapKit::omegaToJSON($o);
        $verbs = $j->get('verbs');
        $this->assertSame(1, $verbs[0]->get('w'));
        $this->assertSame(1000000, $verbs[1]->get('w'));
        $dims = $verbs[0]->get('dims');
        $this->assertSame([5], $dims[0]->get('cuts'));
        $this->assertTrue(array_is_list($dims[1]->get('values')));
        $this->assertSame(['z'], $j->get('approximate'));
    }

    /** omegaFromJSON: cuts and approximate come out as lists; a categorical dimension whose values are not a list is refused. */
    public function testOmegaFromJSON(): void
    {
        $j = ['verbs' => [['verb' => 'a', 'reversibility' => 'reversible', 'w' => 1, 'dims' => [['kind' => 'num', 'path' => 'action.params.n', 'lo' => 0, 'hi' => 10, 'cuts' => [1 => 5]]]]], 'approximate' => [1 => 'z']];
        $o = IntentMapKit::omegaFromJSON($j);
        $this->assertSame([5], $o->get('verbs')[0]->get('dims')[0]->get('cuts'));
        $this->assertSame(['z'], $o->get('approximate'));
        $bad = ['verbs' => [['verb' => 'a', 'w' => 1, 'dims' => [['kind' => 'cat', 'path' => 'action.params.s', 'values' => 'x']]]], 'approximate' => []];
        $this->assertSame("InvalidArgumentException: omegaFromJSON: categorical dimension 'action.params.s' has no values", self::thrown(static fn() => IntentMapKit::omegaFromJSON($bad)));
    }

    /** Every cell confirmed: the maximal risk is 0 and the fidelity estimate is exactly 1 (no division). */
    public function testFidelityWhenNothingIsAtRisk(): void
    {
        $l = IntentMapKit::createLearner(self::omega());
        $l->observe(IntentOmega::cellRep(self::vs(), []), 1);
        $this->assertSame(1000000, IntentMapKit::emitIntentMap($l, 'p1')->get('metrics')->get('fidelity_est_ppm'));
    }

    private static function prior(array $cells): array
    {
        return ['priorMix' => ['beta' => 0.5, 'cells' => $cells]];
    }

    /** priorMix cells: q may be exactly 0 or 1 and the cell index 2^53-1; q above 1 or a non-integer cell is refused. */
    public function testPriorMixCellBounds(): void
    {
        $msg = 'InvalidArgumentException: pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0';
        foreach ([[0, 0], [1, 0], [0.5, 9007199254740991]] as [$q, $cell]) {
            $this->assertInstanceOf(IntentLearner::class, IntentMapKit::createLearner(self::omega(), self::prior([['verb' => 'x.do', 'cell' => $cell, 'q' => $q]])));
        }
        $this->assertSame($msg, self::thrown(static fn() => IntentMapKit::createLearner(self::omega(), self::prior([['verb' => 'x.do', 'cell' => 0, 'q' => 2]]))));
        $this->assertSame($msg, self::thrown(static fn() => IntentMapKit::createLearner(self::omega(), self::prior([['verb' => 'x.do', 'cell' => 'x', 'q' => 0.5]]))));
    }

    /** The population weight sums the log terms of EVERY cell of the verb (here 0.9 in, 0.5 out of range: p = 0.4 + 0.45). */
    public function testPriorMixSumsEveryCell(): void
    {
        $l = IntentMapKit::createLearner(self::omega(), self::prior([['verb' => 'x.do', 'cell' => 0, 'q' => 0.9], ['verb' => 'x.do', 'cell' => 5, 'q' => 0.5]]));
        $this->assertEqualsWithDelta(0.85, $l->acceptance(IntentOmega::cellRep(self::vs(), [])), 1e-9);
    }

    /** A non-string verb (a float) keys its priorMix cells by its text. */
    public function testPriorMixFloatVerb(): void
    {
        $l = IntentMapKit::createLearner(self::omega(1.5), self::prior([['verb' => 1.5, 'cell' => 0, 'q' => 0.9]]));
        $this->assertEqualsWithDelta(0.85, $l->acceptance(IntentOmega::cellRep(self::vs(1.5), [])), 1e-9);
    }

    /** A non-string verb (an int) reads its own null mass and is written under its text. */
    public function testIntVerbNullMass(): void
    {
        $l = IntentMapKit::createLearner(self::omega(7), ['nullMass' => [7 => 0.5]]);
        $this->assertEqualsWithDelta(0.5, $l->acceptance(IntentOmega::cellRep(self::vs(7), [])), 1e-12);
        $this->assertSame(500000, IntentMapKit::emitIntentMap($l, 'p1')->get('learner')->get('null_mass_ppm')->get('7'));
    }

    /** A learner not built with createLearner has no serialisable parameters. */
    public function testLearnerOptionsOfRefusesAPlainLearner(): void
    {
        $this->assertSame('InvalidArgumentException: pca-intent: build the learner with createLearner() so its parameters are serialisable',
            self::thrown(static fn() => IntentMapKit::learnerOptionsOf(new IntentLearner(self::omega()))));
    }

    /** The emitted learner block: monotone paths as a list, and a noise block when only etaPos is set. */
    public function testEmitMonotoneAndNoise(): void
    {
        $l = IntentMapKit::createLearner(self::omega(), ['monotone' => ['paths' => [1 => 'action.params.n']], 'etaPos' => 0.1]);
        $lr = IntentMapKit::emitIntentMap($l, 'p1')->get('learner');
        $this->assertSame(['action.params.n'], $lr->get('monotone')->get('paths'));
        $this->assertSame(100000, $lr->get('noise')->get('eta_pos_ppm'));
        $this->assertSame(0, $lr->get('noise')->get('eta_neg_ppm'));
    }

    private static function lr(array $extra): Obj
    {
        return Obj::of(['learner' => Obj::of(['null_mass_ppm' => new Obj(), 'eta_ppm' => 0, 'tau_ppm' => 1000000, 'strategy' => 'disagreement'] + $extra)]);
    }

    /** mapLearnerOptions: the class defaults (union k 2, decision lists 2 rules, decay 0.25), no empty anchors, monotone paths as a list. */
    public function testMapLearnerOptionsDefaults(): void
    {
        $u = IntentMapKit::mapLearnerOptions(self::lr(['hypothesis_class' => 'per-verb-union/v1', 'anchors' => []]));
        $this->assertSame(['kind' => 'union', 'k' => 2, 'decay' => 0.25], $u['hypothesisClass']);
        $this->assertArrayNotHasKey('anchors', $u);
        $d = IntentMapKit::mapLearnerOptions(self::lr(['hypothesis_class' => 'per-verb-decision-list/v2']));
        $this->assertSame(['kind' => 'decision-list', 'maxRules' => 2, 'decay' => 0.25, 'conditions' => 'box'], $d['hypothesisClass']);
        $m = IntentMapKit::mapLearnerOptions(self::lr(['hypothesis_class' => 'per-verb-box/v1', 'monotone' => Obj::of(['paths' => [1 => 'p'], 'off_ppm' => 0])]));
        $this->assertSame(['paths' => ['p'], 'offMass' => 0.0], $m['monotone']);
    }

    private static function mapWithObservation(): Obj
    {
        $l = IntentMapKit::createLearner(self::omega());
        $l->observe(IntentOmega::cellRep(self::vs(), []), 1);
        return IntentMapKit::emitIntentMap($l, 'p1');
    }

    /** Rebuilding a learner from a map whose observation has no source reads the source as the empty text. */
    public function testLearnerFromMapWithoutSource(): void
    {
        $m = self::mapWithObservation();
        $m->set('observations', [$m->get('observations')[0]->without('source')]);
        $l = IntentMapKit::learnerFromMap($m);
        $this->assertCount(1, $l->observations);
        $this->assertSame('', $l->observations[0]['source']);
    }

    /** Only v === 1 is an intent map. */
    public function testVerifyRejectsVersionTwo(): void
    {
        $this->assertSame(['ok' => false, 'problems' => ['not an intent map v1']], IntentMapKit::verifyIntentMap(Obj::of(['v' => 2, 'kind' => 'pca-intent-map'])));
    }

    /** A map without intent_ref fails the replay with the member named. */
    public function testVerifyMissingIntentRef(): void
    {
        $m = self::mapWithObservation();
        $this->assertTrue(IntentMapKit::verifyIntentMap($m)['ok'], 'control');
        $this->assertSame(['ok' => false, 'problems' => ["replay failed: 'intent_ref'"]], IntentMapKit::verifyIntentMap($m->without('intent_ref')));
    }
}
