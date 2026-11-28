<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentTrajectory;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 32 mutation kills for src/IntentTrajectory.php: the augmented space, the lift of an action, the step rule and the default accumulators. */
final class IntentSurvivorKill32IntentTrajectoryTest extends TestCase
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

    private static function site(): Obj
    {
        return Obj::of(['kind' => 'site_local']);
    }

    private static function money(): Obj
    {
        return Obj::of(['type' => 'integer', 'semantic' => 'money.amount']);
    }

    /** @return list<string> */
    private static function ids(array $accs): array
    {
        return array_map(static fn(Obj $a) => $a->get('id'), $accs);
    }

    /**
     * Accumulator and monitor dimensions: cuts are kept when they are safe integers in [0, domain_max] (domain_max itself included), equal
     * cuts once with the first spelling (0 before -0), a non-number skipped, an integer id read as its text; a null domain_max reads as 0.
     */
    public function testAugmentedDimensions(): void
    {
        $omega = Obj::of(['approximate' => [1 => 'z'], 'verbs' => [Obj::of(['verb' => 'v', 'dims' => []])]]);
        $psi = Obj::of(['accumulators' => [Obj::of(['id' => 5, 'domain_max' => 10, 'holder' => self::site()]), Obj::of(['id' => 'n', 'domain_max' => null, 'holder' => self::site()])],
            'monitors' => [Obj::of(['id' => 7, 'kind' => 'never'])]]);
        $cuts = Obj::of(['5' => [10, 'x', 0, new Num('-0'), 11], 'n' => [0]]);
        $out = IntentTrajectory::augmentOmega($omega, $psi, ['cuts' => $cuts]);
        self::assertSame(['z'], $out->get('approximate'));
        $dims = $out->get('verbs')[0]->get('dims');
        self::assertSame(['env.acc.5.post', 'env.acc.n.post', 'env.mon.7.state'], array_map(static fn(Obj $d) => $d->get('path'), $dims));
        self::assertSame([0, 10], $dims[0]->get('cuts'));
        self::assertSame(10, $dims[0]->get('hi'));
        self::assertSame([0], $dims[1]->get('cuts'));
        self::assertNull($dims[1]->get('hi'));
        self::assertSame('[{"kind":"exact","value":"clean"},{"kind":"exact","value":"seen"}]', Json::stringify($dims[2]->get('values')));
    }

    /** Two safe-integer cuts that differ only past the 14th digit are two cuts (a float's text would merge them). */
    public function testLargeCutsStayDistinct(): void
    {
        $omega = Obj::of(['approximate' => [], 'verbs' => [Obj::of(['verb' => 'v', 'dims' => []])]]);
        $psi = Obj::of(['accumulators' => [Obj::of(['id' => 'a', 'domain_max' => 2000000000000000, 'holder' => self::site()])], 'monitors' => []]);
        $out = IntentTrajectory::augmentOmega($omega, $psi, ['cuts' => Obj::of(['a' => [1000000000000001, 1000000000000000]])]);
        self::assertSame([1000000000000000, 1000000000000001], $out->get('verbs')[0]->get('dims')[0]->get('cuts'));
    }

    /** A dimension without a path sorts as '' (whichever side of the comparison it is on). */
    public function testADimensionWithoutAPath(): void
    {
        $np = Obj::of(['kind' => 'num', 'lo' => 0, 'hi' => 1, 'cuts' => []]);
        $pa = Obj::of(['kind' => 'num', 'path' => 'action.params.a', 'lo' => 0, 'hi' => 1, 'cuts' => []]);
        $omega = Obj::of(['approximate' => [], 'verbs' => [Obj::of(['verb' => 'v1', 'dims' => [$np, $pa]]), Obj::of(['verb' => 'v2', 'dims' => [$pa, $np]])]]);
        $out = IntentTrajectory::augmentOmega($omega, Obj::of(['accumulators' => [], 'monitors' => []]));
        foreach ($out->get('verbs') as $vs) {
            self::assertSame([null, 'action.params.a'], array_map(static fn(Obj $d) => $d->get('path'), $vs->get('dims')));
        }
    }

    /** An accumulator dimension needs domain_max. */
    public function testAnAccumulatorWithoutDomainMaxIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("augmentOmega: accumulator 'q' needs domain_max (A_psi) to be a dimension of the augmented space");
        IntentTrajectory::augmentOmega(Obj::of(['approximate' => [], 'verbs' => [Obj::of(['verb' => 'v', 'dims' => []])]]),
            Obj::of(['accumulators' => [Obj::of(['id' => 'q', 'holder' => self::site()])], 'monitors' => []]));
    }

    /** scope 'selected' reads the first schema entry of the verb for accumulates_into. */
    public function testSelectionReadsTheFirstSchemaEntry(): void
    {
        $schema = Obj::of(['verbs' => [
            Obj::of(['verb' => 'v', 'params' => Obj::of(['action.params.x' => Obj::of(['type' => 'integer', 'accumulates_into' => ['u']])])]),
            Obj::of(['verb' => 'v', 'params' => new Obj()]),
        ]]);
        $psi = Obj::of(['accumulators' => [Obj::of(['id' => 'a', 'domain_max' => 10, 'sel' => Obj::of(['accumulates_into' => 'u']), 'holder' => self::site()])], 'monitors' => []]);
        $out = IntentTrajectory::augmentOmega(Obj::of(['approximate' => [], 'verbs' => [Obj::of(['verb' => 'v', 'dims' => []])]]), $psi, ['scope' => 'selected', 'schema' => $schema]);
        self::assertSame(['env.acc.a.post'], array_map(static fn(Obj $d) => $d->get('path'), $out->get('verbs')[0]->get('dims')));
    }

    /** The lift: numeric params copied, a pathless dimension skipped, the first accumulator and the first monitor of an id used. */
    public function testTheLift(): void
    {
        $vs = Obj::of(['verb' => 'v', 'dims' => [Obj::of(['kind' => 'num', 'path' => 'action.params.n']), Obj::of(['kind' => 'num']),
            Obj::of(['kind' => 'num', 'path' => 'env.acc.a.post']), Obj::of(['kind' => 'cat', 'path' => 'env.mon.m.state'])]]);
        $psi = Obj::of([
            'accumulators' => [Obj::of(['id' => 'a', 'agg' => 'count', 'key' => null, 'sel' => Obj::of(['event' => 'x']), 'win' => Obj::of(['kind' => 'task'])]),
                Obj::of(['id' => 'a', 'agg' => 'bogus'])],
            'monitors' => [Obj::of(['id' => 'm', 'kind' => 'never']), Obj::of(['id' => 'm', 'kind' => 'always'])],
        ]);
        $cand = Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['n' => 5]), 't' => 0]);
        $o = IntentTrajectory::liftAction(Obj::of(['verbs' => [$vs]]), $psi, [], $cand);
        self::assertSame('{"verb":"v","values":{"action.params.n":5,"env.acc.a.post":0,"env.mon.m.state":"clean"}}', Json::stringify($o));
    }

    /** An admitted step is a boolean and appends a reserved event to the re-indexed history. */
    public function testAStep(): void
    {
        $omega = Obj::of(['verbs' => [Obj::of(['verb' => 'v', 'dims' => []])]]);
        $cand = Obj::of(['id' => 'c', 'verb' => 'v', 'resource' => 'r', 'params' => new Obj(), 't' => 1]);
        $r = IntentTrajectory::stepTrajectory($omega, Obj::of(['accumulators' => [], 'monitors' => []]), [5 => Obj::of(['id' => 'e0'])], $cand, static fn($verb, $cell) => 1);
        self::assertTrue($r['admitted']);
        self::assertSame([0, 1], array_keys($r['history']));
        self::assertSame('reserved', $r['history'][1]->get('status'));
    }

    /**
     * Default accumulators: one per unit (sorted as text, a numeric unit kept as text, ids sanitised per UTF-16 unit and cut to 58), then
     * one per untagged money parameter sorted by verb + path, then the question counter.
     */
    public function testDefaultAccumulators(): void
    {
        $schema = Obj::of(['verbs' => [Obj::of(['verb' => 'v.x', 'params' => Obj::of([
            'action.params.zz' => self::money(),
            'action.params.aa' => self::money(),
            'action.params.u1' => Obj::of(['type' => 'integer', 'accumulates_into' => ["\u{20AC}x\u{1F600}", '5', 1.5, str_repeat('a', 60)]]),
        ])])]]);
        $accs = IntentTrajectory::defaultAccumulators($schema, []);
        self::assertSame(['spend_1_5', 'spend_5', 'spend_' . str_repeat('a', 58), 'spend__x__', 'spend_v_x_aa', 'spend_v_x_zz', 'questions'], self::ids($accs));
        self::assertSame('5', $accs[1]->get('unit'));
        $seven = Obj::of(['verbs' => [Obj::of(['verb' => 7, 'params' => Obj::of(['action.params.amount' => self::money()])])]]);
        self::assertSame(['spend_7_amount', 'questions'], self::ids(IntentTrajectory::defaultAccumulators($seven, [])));
        self::assertSame(6, Js::opt(IntentTrajectory::defaultAccumulators($seven, [])[1], 'cap'));
    }
}
