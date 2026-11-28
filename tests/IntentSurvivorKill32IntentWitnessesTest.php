<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentWitnesses;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 32 mutation kills for src/IntentWitnesses.php: witness de-duplication, the boundary pair choice and the unconstrained witnesses. */
final class IntentSurvivorKill32IntentWitnessesTest extends TestCase
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

    private static function num(string $path, int $lo, int $hi, array $cuts): Obj
    {
        return Obj::of(['kind' => 'num', 'path' => $path, 'lo' => $lo, 'hi' => $hi, 'cuts' => $cuts, 'dist' => 'uniform']);
    }

    private static function cat(string $path, array $values): Obj
    {
        return Obj::of(['kind' => 'cat', 'path' => $path, 'values' => array_map(static fn(?string $v): Obj => $v === null
            ? Obj::of(['kind' => 'other', 'value' => 'other']) : Obj::of(['kind' => 'exact', 'value' => $v]), $values)]);
    }

    private static function vs(string $verb, int $weight, array $dims): Obj
    {
        return Obj::of(['verb' => $verb, 'reversibility' => 'reversible', 'weight' => $weight, 'dims' => $dims]);
    }

    private static function pred(string $verb, array $where): Obj
    {
        return Obj::of(['verb' => $verb, 'resource' => '*', 'where' => array_map(static fn(array $w): Obj => Obj::of(['field' => $w[0], 'op' => $w[1], 'value' => new Num((string)$w[2])]), $where)]);
    }

    /** @return list<array{0:string,1:string,2:list<int>,3:string}> [kind, side, cell, facet] */
    private static function shape(array $ws): array
    {
        return array_map(static fn(array $w): array => [$w['kind'], $w['side'], $w['cell'], $w['facet']], $ws);
    }

    /** Two verbs whose name + cell texts would run together ("v" cell [0], "v0" cell []) are still two witnesses. */
    public function testTheDedupKeySeparatesVerbFromCell(): void
    {
        $omega = Obj::of(['verbs' => [self::vs('v', 1, [self::cat('action.params.c', ['a'])]), self::vs('v0', 1, [])]]);
        $ws = IntentWitnesses::boundaryWitnesses(Obj::of(['predicates' => [], 'caveats' => []]), $omega);
        self::assertSame([['verb', 'outside', [0], 'v|verb'], ['verb', 'outside', [], 'v0|verb']], self::shape($ws));
    }

    /**
     * Per facet the inside cell that shares the typical action's other coordinates wins unless the other candidate outweighs it by
     * more than 10 in mass: with weight 240 the shared cell (1,0) wins (10 + 1.2 > 10.8), with weight 260 the heavier (1,1) wins
     * (10 + 1.3 < 11.7). Shown by the outside cell of facet x|1~2 ((1,1) itself was already asked under x|0~1).
     */
    public function testTheBoundaryPairPrefersSharedCoordinatesByTenMassUnits(): void
    {
        $dims = [self::num('action.params.x', 0, 19, [18]), self::num('action.params.y', 0, 9, [0])];
        $preds = [];
        foreach (['v240', 'v260'] as $v) {
            $preds[] = self::pred($v, [['action.params.x', 'lte', 17], ['action.params.y', 'lte', 0]]);
            $preds[] = self::pred($v, [['action.params.x', 'gte', 18], ['action.params.x', 'lte', 18]]);
        }
        $omega = Obj::of(['verbs' => [self::vs('v240', 240, $dims), self::vs('v260', 260, $dims)]]);
        $ws = IntentWitnesses::boundaryWitnesses(Obj::of(['predicates' => $preds, 'caveats' => []]), $omega);
        self::assertSame([
            ['verb', 'inside', [0, 0], 'v240|verb'],
            ['boundary', 'inside', [1, 1], 'v240|action.params.x|0~1'],
            ['boundary', 'outside', [0, 1], 'v240|action.params.x|0~1'],
            ['boundary', 'inside', [1, 0], 'v240|action.params.x|1~2'],
            ['boundary', 'outside', [2, 0], 'v240|action.params.x|1~2'],
            ['verb', 'inside', [0, 0], 'v260|verb'],
            ['boundary', 'inside', [1, 1], 'v260|action.params.x|0~1'],
            ['boundary', 'outside', [0, 1], 'v260|action.params.x|0~1'],
            ['boundary', 'outside', [2, 1], 'v260|action.params.x|1~2'],
        ], self::shape($ws));
    }

    /**
     * Two candidates with no shared coordinate whose masses (both 3/35) differ by one ulp in binary64: the later, heavier one wins on
     * its exact mass (an offset of the score would round the two together and keep the first).
     */
    public function testAOneUlpHeavierCandidateWins(): void
    {
        $dims = [self::num('action.params.x', 0, 6, [2]), self::num('action.params.y', 0, 6, [0, 4]), self::num('action.params.z', 0, 4, [1])];
        $preds = [];
        foreach ([[2, 0, 2], [2, 1, 0], [3, 4, 1]] as [$x, $y, $z]) {
            $preds[] = self::pred('v', [['action.params.x', 'eq', $x], ['action.params.y', 'eq', $y], ['action.params.z', 'eq', $z]]);
        }
        $ws = IntentWitnesses::boundaryWitnesses(Obj::of(['predicates' => $preds, 'caveats' => []]), Obj::of(['verbs' => [self::vs('v', 7, $dims)]]));
        self::assertSame([
            ['verb', 'inside', [2, 2, 1], 'v|verb'],
            ['boundary', 'inside', [1, 1, 0], 'v|action.params.x|0~1'],
            ['boundary', 'outside', [0, 1, 0], 'v|action.params.x|0~1'],
            ['boundary', 'outside', [1, 2, 1], 'v|action.params.x|1~2'],
            ['boundary', 'outside', [1, 0, 0], 'v|action.params.y|0~1'],
            ['boundary', 'outside', [2, 1, 1], 'v|action.params.y|1~2'],
            ['boundary', 'outside', [2, 3, 1], 'v|action.params.y|2~3'],
            ['boundary', 'outside', [2, 2, 0], 'v|action.params.z|0~1'],
            ['boundary', 'outside', [2, 2, 2], 'v|action.params.z|1~2'],
        ], self::shape($ws));
    }

    /**
     * A grant that ignores every dimension gets one unconstrained witness per dimension with at least two cells: a numeric one at
     * its top cell, a categorical one at its first OTHER value; a single-cell dimension before them is skipped, not a stop.
     */
    public function testUnconstrainedWitnesses(): void
    {
        $vs = self::vs('u', 1, [self::num('action.params.s', 0, 0, []), self::num('action.params.n', 0, 9, [5]), self::cat('action.params.c', ['a', null, null])]);
        $grant = Obj::of(['predicates' => [self::pred('u', [])], 'caveats' => []]);
        $ws = IntentWitnesses::boundaryWitnesses($grant, Obj::of(['verbs' => [$vs]]));
        self::assertSame([
            ['verb', 'inside', [0, 0, 0], 'u|verb'],
            ['unconstrained', 'inside', [0, 2, 0], 'u|action.params.n|unconstrained'],
            ['unconstrained', 'inside', [0, 0, 1], 'u|action.params.c|unconstrained'],
        ], self::shape($ws));
    }

    /** An unconstrained categorical dimension without an OTHER value has no cell to ask about: the representative lookup refuses (as the reference does). */
    public function testAnUnconstrainedCategoricalWithoutOtherIsRefused(): void
    {
        $vs = self::vs('w', 1, [self::cat('action.params.c', ['a', 'b'])]);
        $grant = Obj::of(['predicates' => [self::pred('w', [])], 'caveats' => []]);
        $this->expectException(\OutOfRangeException::class);
        $this->expectExceptionMessage('cell index out of range');
        IntentWitnesses::boundaryWitnesses($grant, Obj::of(['verbs' => [$vs]]));
    }
}
