<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentOmega;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * The intent outcome space past the reference corpus: cell boundaries, the cell-index guards, categorical cells and representatives,
 * the default and custom harm models, the exact and quadrature interval harm, interval weights at the exact-span boundary, the
 * workload quantiles drawn with a scripted generator, and the derivation's dimension rules (cuts, domains, defaults, catalogs,
 * wildcards, grouping conditions).
 */
final class NetSurvivorKill16IntentOmegaTest extends TestCase
{
    private const CAT = ['kind' => 'cat', 'path' => 'p', 'values' => [['kind' => 'exact', 'value' => 'big'], ['kind' => 'other', 'value' => IntentOmega::OTHER]]];

    /** A scripted generator: each call returns the next value. */
    private static function seq(float ...$xs): \Closure
    {
        return static function () use (&$xs): float {
            return array_shift($xs);
        };
    }

    /** The value a one-verb, one-dimension workload draws for `$d` with the scripted dimension draw `$r`. */
    private static function draw(array $d, float $r): mixed
    {
        [, $o] = IntentOmega::sampleOutcome(['verbs' => [['verb' => 'v', 'weight' => 1, 'dims' => [$d]]]], self::seq(0.0, $r));
        return $o->get('values')->get($d['path']);
    }

    /** verb harm 2; dimension harm 5 for the string 'big', else 1. */
    private static function harm(): \Atlas\Pca\HarmModel
    {
        return IntentOmega::harmModel(static fn(mixed $vs): int => 2, static fn(mixed $d, mixed $x): int => $x === 'big' ? 5 : 1);
    }

    /** @return array{0: \Atlas\Pca\HarmModel, 1: \Closure(): list<int|float>} a harm model that records every point it is asked about (harm = x) */
    private static function recordingHarm(): array
    {
        $rec = [];
        $h = IntentOmega::harmModel(static fn(mixed $vs): int => 1, static function (mixed $d, mixed $x) use (&$rec): int|float {
            $rec[] = $x;
            return $x;
        });
        return [$h, static function () use (&$rec): array {
            return $rec;
        }];
    }

    public function testTheDefaultDomains(): void
    {
        $this->assertSame([
            'action.params.amount' => ['lo' => 0, 'hi' => 100000, 'dist' => 'loguniform'],
            'env.hour' => ['lo' => 0, 'hi' => 23, 'dist' => 'uniform'],
            'action.params.count' => ['lo' => 0, 'hi' => 1000, 'dist' => 'loguniform'],
        ], IntentOmega::defaultDomains());
    }

    // ---- cells ------------------------------------------------------------------------------------------------------------

    public function testCutsAtTheTopAndOutOfRange(): void
    {
        $cells = static fn(array $d): array => array_map(static fn(Obj $c): array => [$c->get('lo'), $c->get('hi')], IntentOmega::numCells($d));
        $this->assertSame([[0, 9], [10, 10]], $cells(['lo' => 0, 'hi' => 10, 'cuts' => [10]]));
        $this->assertSame([[0, 4], [5, 5], [6, 10]], $cells(['lo' => 0, 'hi' => 10, 'cuts' => [50, 5]]));
    }

    public function testCellIndexGuards(): void
    {
        $d = ['kind' => 'cat', 'values' => [['kind' => 'exact', 'value' => 'a'], ['kind' => 'exact', 'value' => 'b'], ['kind' => 'other', 'value' => IntentOmega::OTHER]]];
        $this->assertSame('b', IntentOmega::catRep($d, 1));
        foreach ([3, -1, 'x', 1.5] as $bad) {
            try {
                IntentOmega::catRep($d, $bad);
                $this->fail('accepted ' . var_export($bad, true));
            } catch (\OutOfRangeException $e) {
                $this->assertSame('cell index out of range', $e->getMessage());
            }
        }
    }

    /** A flat index that is no number decodes as 0. */
    public function testDecodeANonNumber(): void
    {
        $vs = ['dims' => [['kind' => 'cat', 'values' => [['kind' => 'other', 'value' => IntentOmega::OTHER], ['kind' => 'exact', 'value' => 'a']]]]];
        $this->assertSame([0], IntentOmega::decodeCell($vs, 'x'));
    }

    public function testCategoricalCells(): void
    {
        $other = ['kind' => 'other', 'value' => IntentOmega::OTHER];
        $this->assertSame(0, IntentOmega::catCellOf(['values' => [['kind' => 'prefix', 'value' => ''], $other]], 'abc'), 'the empty prefix matches');
        $this->assertSame(0, IntentOmega::catCellOf(['values' => [['kind' => 'prefix', 'value' => 'a'], ['kind' => 'prefix', 'value' => 'a'], $other]], 'ab'),
            'of equally long prefixes the first wins');
        $this->assertSame(-1, IntentOmega::catCellOf(['values' => [['kind' => 'exact', 'value' => 'x']]], 'y'));
    }

    /** The OTHER representative skips names an exact value takes; after 64 tries it falls back to the base name. */
    public function testOtherRepresentatives(): void
    {
        $other = ['kind' => 'other', 'value' => IntentOmega::OTHER];
        $this->assertSame('other1', IntentOmega::catRep(['values' => [['kind' => 'exact', 'value' => 'other'], $other]], 1));
        $values = [['kind' => 'exact', 'value' => 'other']];
        for ($k = 1; $k < 64; $k++) {
            $values[] = ['kind' => 'exact', 'value' => 'other' . $k];
        }
        $values[] = $other;
        $this->assertSame('other', IntentOmega::catRep(['values' => $values], 64));
    }

    // ---- harm ------------------------------------------------------------------------------------------------------------

    public function testTheDefaultHarm(): void
    {
        $h = IntentOmega::defaultHarm();
        $this->assertSame($h, IntentOmega::defaultHarm());
        $amount = ['kind' => 'num', 'path' => 'action.params.amount', 'lo' => -100, 'hi' => 100, 'dist' => 'uniform'];
        $this->assertSame(1, ($h->dim)($amount, -50), 'a negative amount is no harm');
        $this->assertSame(1.5, ($h->dim)($amount, 50));
        $this->assertSame(1, ($h->dim)(['kind' => 'num'], 5), 'a dimension without a path is no amount');
        $this->assertSame(1, ($h->dimMean)($amount, 0, 0));
        $this->assertSame(1, ($h->dimMean)($amount, -10, -5), 'a negative interval has a zero mean');
        $this->assertSame(1, ($h->dimMean)($amount, 5, 2), 'an empty interval has a zero mean');
        $this->assertEqualsWithDelta(1.02, ($h->dimMean)($amount, 0, 4), 1e-12);
        $this->assertEqualsWithDelta(1 + (10 / 15) / 100, ($h->dimMean)($amount, -10, 4), 1e-12);
    }

    public function testACustomHarmModelIsUsed(): void
    {
        $h = self::harm();
        $vs = ['verb' => 'v', 'weight' => 1, 'dims' => [self::CAT]];
        $this->assertSame(10, IntentOmega::harmMax(['verbs' => [$vs]], $h), 'the largest harm over the values, times the verb harm');
        $this->assertSame(['mass' => 0.5, 'harm' => 5], IntentOmega::dimCellStats(self::CAT, 0, $h));
        $this->assertSame(['mass' => 0.5, 'harm' => 10], IntentOmega::cellStats($vs, [0], $h));
        $this->assertSame(10, IntentOmega::harmOf($vs, ['values' => ['p' => 'big']], $h));
        $this->expectException(\ValueError::class);
        $this->expectExceptionMessage('max() arg is an empty sequence');
        IntentOmega::harmMax(['verbs' => [['verb' => 'v', 'dims' => [['kind' => 'cat', 'path' => 'p', 'values' => []]]]]], $h);
    }

    /** Up to EXACT_SPAN integers the interval harm sums every point. */
    public function testTheExactIntervalHarm(): void
    {
        [$h, $rec] = self::recordingHarm();
        $s = IntentOmega::dimCellStats(['kind' => 'num', 'path' => 'q', 'lo' => 1, 'hi' => 4096, 'cuts' => [], 'dist' => 'uniform'], 0, $h);
        $this->assertSame(['mass' => 1, 'harm' => 2048.5], $s);
        $this->assertSame(range(1, 4096), $rec());
    }

    /** Past EXACT_SPAN integers the interval harm is a 1024-piece midpoint quadrature. */
    public function testTheQuadratureIntervalHarm(): void
    {
        [$h, $rec] = self::recordingHarm();
        $s = IntentOmega::dimCellStats(['kind' => 'num', 'path' => 'q', 'lo' => 1, 'hi' => 10000, 'cuts' => [], 'dist' => 'uniform'], 0, $h);
        $this->assertSame(1, $s['mass']);
        $this->assertEqualsWithDelta(5000.892, $s['harm'], 1e-9);
        $r = $rec();
        $this->assertCount(IntentOmega::HARM_QUADRATURE_PIECES, $r);
        $this->assertSame([5.0, 15.0, 25.0], array_slice($r, 0, 3));
        $this->assertSame(9996.0, $r[1023]);
        $this->assertSame(5120400.0, array_sum($r));
    }

    // ---- interval weights --------------------------------------------------------------------------------------------------

    public function testLogUniformIntervalWeights(): void
    {
        $d = ['dist' => 'loguniform', 'lo' => 0];
        $this->assertSame(1.8333333333333333, IntentOmega::intervalWeight($d, 0, 2.5), 'the exact sum starts at the integer part of b');
        $this->assertSame(8.895103896966317, IntentOmega::intervalWeight($d, -1, 4095), 'one past EXACT_SPAN: H(b+1) - H(a), and H(4096) is summed exactly');
        $this->assertSame(8.894859756341317, IntentOmega::intervalWeight($d, -3, 4094.5), 'H of a fractional n sums 1/k from its integer part');
        $this->expectException(\DivisionByZeroError::class);
        IntentOmega::intervalWeight($d, -1, 4094); // exactly EXACT_SPAN integers: summed point by point, through x = -1
    }

    // ---- sampling ------------------------------------------------------------------------------------------------------------

    public function testQuantilesOfAUniformDimension(): void
    {
        $this->assertSame(5, self::draw(['kind' => 'num', 'path' => 'q', 'lo' => 0, 'hi' => 9, 'cuts' => [5], 'dist' => 'uniform'], 0.5),
            'a target on a cell boundary belongs to the next cell');
        $this->assertSame(1, self::draw(['kind' => 'num', 'path' => 'q', 'lo' => 0, 'hi' => 3, 'cuts' => [], 'dist' => 'uniform'], 0.25),
            'a remainder that reaches exactly 0 is still inside the point');
        $wide = ['kind' => 'num', 'path' => 'q', 'lo' => 0, 'hi' => 8191, 'cuts' => [], 'dist' => 'uniform'];
        $this->assertSame(2.0, self::draw($wide, 2.5 / 8192));
        $this->assertSame(8191, self::draw($wide, 1.5), 'a target past the total is capped at hi');
    }

    /** A log-uniform cell of EXACT_SPAN integers is walked point by point; one more is the closed form. */
    public function testQuantilesAtTheExactSpan(): void
    {
        $a = ['kind' => 'num', 'path' => 'q', 'lo' => 1, 'hi' => 4096, 'cuts' => [], 'dist' => 'loguniform'];
        $this->assertSame(3, self::draw($a, 1.0 / IntentOmega::intervalWeight(['dist' => 'loguniform', 'lo' => 1], 1, 4096)));
        $b = ['kind' => 'num', 'path' => 'q', 'lo' => 1, 'hi' => 4097, 'cuts' => [], 'dist' => 'loguniform'];
        $this->assertSame(4.0, self::draw($b, 1.0 / IntentOmega::intervalWeight(['dist' => 'loguniform', 'lo' => 1], 1, 4097)));
    }

    public function testCategoricalDrawAndVerbChoice(): void
    {
        $d = ['kind' => 'cat', 'path' => 'c', 'values' => [['kind' => 'exact', 'value' => 'a'], ['kind' => 'exact', 'value' => 'b'], ['kind' => 'other', 'value' => IntentOmega::OTHER]]];
        $this->assertSame('other', self::draw($d, 1.0), 'a draw of 1 is the last value');
        [, $o] = IntentOmega::sampleOutcome(['verbs' => [['verb' => 'A', 'weight' => 0.5, 'dims' => []], ['verb' => 'B', 'weight' => 0.5, 'dims' => []]]], self::seq(0.5));
        $this->assertSame('B', $o->get('verb'), 'a draw equal to a verb weight passes that verb');
    }

    // ---- derivation ------------------------------------------------------------------------------------------------------------

    /** @return array<string, list<mixed>> each dimension by path: num [lo, hi, cuts, dist], cat [[kind, value], ...] */
    private static function dims(Obj $verb): array
    {
        $out = [];
        foreach ($verb->get('dims') as $d) {
            $out[$d->get('path')] = $d->get('kind') === 'num' ? [$d->get('lo'), $d->get('hi'), $d->get('cuts'), $d->get('dist')]
                : array_map(static fn(Obj $v): array => [$v->get('kind'), $v->get('value')], $d->get('values'));
        }
        return $out;
    }

    public function testTheDerivedDimensions(): void
    {
        $o = Obj::of(['z' => 1]);
        $omega = IntentOmega::deriveOmega([
            'catalog' => [['connector' => 'c', 'verb' => 'c.v', 'reversibility' => new Num('3')]],
            'policies' => [],
            'extraVerbs' => ['c.v'],
            'domains' => ['env.hour' => ['dist' => 'uniform'], 'action.params.r' => ['lo' => 5, 'hi' => 50]],
            'slots' => ['constraints' => [
                ['path' => 'action.params.k', 'oneOf' => [new Num('7')]],
                ['path' => 'action.params.o', 'oneOf' => [$o]],
                ['path' => 'action.params.amount', 'oneOf' => ['x']],
                ['path' => 'action.params.count', 'prefixOneOf' => ['p']],
                ['path' => 'env.hour'],
                ['path' => 'action.params.n', 'max' => -5],
                ['path' => 'action.params.m', 'max' => 5],
                ['path' => 'action.params.g', 'max' => 20],
                ['path' => 'action.params.z', 'max' => 0.4],
                ['path' => 'action.params.big', 'max' => 1e19],
                ['path' => 'action.params.edge', 'max' => 9.2e18],
                ['path' => 'action.params.s', 'max' => 'abc'],
                ['path' => 'action.params.r', 'max' => 50, 'min' => 1],
                ['path' => 'action.params.r', 'max' => 5],
            ]],
        ]);
        $verbs = $omega->get('verbs');
        $this->assertCount(1, $verbs);
        $this->assertSame(['c.v', 3, 1], [$verbs[0]->get('verb'), $verbs[0]->get('reversibility'), $verbs[0]->get('weight')]);
        $x = IntentOmega::OTHER;
        $dims = self::dims($verbs[0]);
        $this->assertSame([['exact', 7], ['other', $x]], $dims['action.params.k']);
        $this->assertSame([['exact', $o], ['other', $x]], $dims['action.params.o']);
        $this->assertSame([['exact', 'x'], ['other', $x]], $dims['action.params.amount'], 'a default path with exact values stays categorical');
        $this->assertSame([['prefix', 'p'], ['other', $x]], $dims['action.params.count'], 'a default path with prefixes stays categorical');
        $this->assertSame([-1, 10, [], 'uniform'], $dims['env.hour'], 'a domain without bounds falls back to the cut-derived bounds');
        $this->assertSame([-6, 10, [-5], 'uniform'], $dims['action.params.n']);
        $this->assertSame([0, 15, [5], 'loguniform'], $dims['action.params.m']);
        $this->assertSame([0, 40, [20], 'loguniform'], $dims['action.params.g']);
        $this->assertSame([-1, 11, [0, 1], 'uniform'], $dims['action.params.z'], 'floor and ceil of 0.4, as integers');
        $this->assertSame([1.0E19], $dims['action.params.big'][2]);
        $this->assertSame([9.2E18], $dims['action.params.edge'][2]);
        $this->assertSame([['other', $x]], $dims['action.params.s'], 'a non-numeric bound adds no cut');
        $this->assertSame([5, 50, [5, 50], 'loguniform'], $dims['action.params.r'], 'cuts on the domain bounds are kept, outside ones dropped');
    }

    public function testCatalogsAndWildcards(): void
    {
        $wild = [['predicates' => [['verb' => '*']]]];
        $names = static fn(Obj $omega): array => array_map(static fn(Obj $v): mixed => $v->get('verb'), $omega->get('verbs'));
        $objCatalog = Obj::of(['a' => ['connector' => 'c', 'verb' => 'c.a'], 'b' => ['connector' => 'd', 'verb' => 'd.b']]);
        $this->assertSame(['c.a', 'd.b'], $names(IntentOmega::deriveOmega(['catalog' => $objCatalog, 'policies' => $wild])));
        $list = [['connector' => 'c', 'verb' => 'c.a'], ['connector' => 'd', 'verb' => 'd.b']];
        $this->assertSame(['c.a', 'c.x'], $names(IntentOmega::deriveOmega(['catalog' => $list, 'policies' => $wild, 'extraVerbs' => ['c.x']])),
            'a wildcard expands to the catalog verbs of the connectors in play');
        $this->assertSame(['c.a'], $names(IntentOmega::deriveOmega(['catalog' => $list, 'policies' => [['predicates' => [['verb' => ['c.a', 5]]]]]])),
            'a verb list keeps its strings only');
    }

    /** A grouping member that is not a list is skipped and the next grouping member is read. */
    public function testGroupingConditionsWithANonListMember(): void
    {
        $leaf = static fn(string $field, string $v): Obj => Obj::of(['field' => $field, 'op' => 'eq', 'value' => $v]);
        $omega = IntentOmega::deriveOmega(['catalog' => [['connector' => 'c', 'verb' => 'c.a']], 'policies' => [['predicates' => [['verb' => 'c.a', 'where' => [
            Obj::of(['all_of' => 5, 'any_of' => [$leaf('action.params.q', 'w')]]),
            Obj::of(['any_of' => 5, 'not' => $leaf('action.params.t', 'u')]),
        ]]]]]]);
        $dims = self::dims($omega->get('verbs')[0]);
        $this->assertSame([['exact', 'w'], ['other', IntentOmega::OTHER]], $dims['action.params.q'] ?? null);
        $this->assertSame([['exact', 'u'], ['other', IntentOmega::OTHER]], $dims['action.params.t'] ?? null);
    }

    // ---- JS Math ---------------------------------------------------------------------------------------------------------------

    public function testJsMaxAndMin(): void
    {
        $this->assertNan(IntentOmega::jsMax(1, NAN));
        $this->assertNan(IntentOmega::jsMin(1, NAN));
        $this->assertNan(IntentOmega::jsMin(NAN, 1));
        $this->assertSame(1, IntentOmega::jsMin(1, 2));
        $this->assertSame(1, IntentOmega::jsMin(2.5, 1));
    }
}
