<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentMapCommit.php';

use Atlas\Pca\IntentMapCommit;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/IntentMapCommit.php: numeric cell counting at the bounds, header cuts, cat values, cell order and the cell refusals. */
final class RestSurvivorKill36dIntentMapCommitTest extends TestCase
{
    private static function secret(): string
    {
        return hash('sha256', 'atlas-pca-conformance/map-commit-36d', true);
    }

    private static function num(int $lo, int $hi, array $cuts): Obj
    {
        return Obj::of(['kind' => 'num', 'path' => 'action.params.amount', 'lo' => $lo, 'hi' => $hi, 'cuts' => $cuts]);
    }

    /** @param list<list<int>|array<int,int>> $cells */
    private static function map(array $dims, array $cells, mixed $verb = 'pay'): Obj
    {
        $cs = [];
        foreach ($cells as $c) {
            $cs[] = Obj::of(['verb' => $verb, 'cell' => $c, 'p_ppm' => 0, 'in_grant' => true]);
        }
        return Obj::of([
            'omega' => Obj::of(['verbs' => [Obj::of(['verb' => $verb, 'dims' => $dims])]]),
            'cells' => $cs,
            'metrics' => Obj::of(array_fill_keys(IntentV2::MAP_METRIC_FIELDS, 0)),
            'learner' => Obj::of(['n' => 1]),
        ]);
    }

    /** @return array{0:Obj,1:list<mixed>} the header leaf and the cell values of the cell leaves, in leaf order */
    private static function commit(Obj $m): array
    {
        $leaves = IntentMapCommit::commitIntentMap($m, self::secret())['leaves'];
        self::assertSame('header', $leaves[0]->get('kind'));
        $cells = [];
        foreach ($leaves as $l) {
            if ($l->get('kind') === 'cell') {
                $cells[] = $l->get('leaf')->get('cell');
            }
        }
        return [$leaves[0]->get('leaf'), $cells];
    }

    private static function refusal(Obj $m): string
    {
        try {
            IntentMapCommit::commitIntentMap($m, self::secret());
        } catch (\InvalidArgumentException $e) {
            return $e->getMessage();
        }
        return 'committed';
    }

    /** A cut equal to lo is its own one-value cell: [lo, lo] and [lo+1, hi]. */
    public function testCutAtLo(): void
    {
        [$h, $cells] = self::commit(self::map([self::num(0, 10, [0])], [[0], [1]]));
        $this->assertSame(2, $h->get('cells'));
        $this->assertSame([0], $h->get('dims')[0]->get('cuts'));
        $this->assertSame([[0], [1]], $cells);
    }

    /** A cut equal to hi is its own one-value cell: [lo, hi-1] and [hi, hi]. */
    public function testCutAtHi(): void
    {
        [$h, $cells] = self::commit(self::map([self::num(0, 10, [10])], [[0], [1]]));
        $this->assertSame(2, $h->get('cells'));
        $this->assertSame([10], $h->get('dims')[0]->get('cuts'));
    }

    /** A cut outside [lo, hi] is skipped (later cuts still count) and left out of the header as a list. */
    public function testOutOfRangeCutIsSkipped(): void
    {
        [$h, $cells] = self::commit(self::map([self::num(0, 10, [-5, 5])], [[0], [1], [2]]));
        $this->assertSame(3, $h->get('cells'));
        $this->assertSame([5], $h->get('dims')[0]->get('cuts'));
        $this->assertSame([[0], [1], [2]], $cells);
    }

    /** A cut at hi-1 leaves the one-value tail cell [hi, hi]. */
    public function testCutJustBelowHi(): void
    {
        [$h] = self::commit(self::map([self::num(0, 6, [5])], [[0], [1], [2]]));
        $this->assertSame(3, $h->get('cells'));
    }

    /** A cat value is committed as exactly {kind, value}: extra members of the input are not carried into the header. */
    public function testCatValuesAreCopiedAsKindAndValue(): void
    {
        $cat = Obj::of(['kind' => 'cat', 'path' => 'action.resource', 'values' => [
            Obj::of(['kind' => 'exact', 'value' => 'a', 'note' => 'x']),
            Obj::of(['kind' => 'other', 'value' => IntentV2::MAP_OTHER]),
        ]]);
        [$h, $cells] = self::commit(self::map([$cat], [[0], [1]]));
        $v = $h->get('dims')[0]->get('values');
        $this->assertSame(['kind', 'value'], $v[0]->keys());
        $this->assertSame('a', $v[0]->get('value'));
        $this->assertSame([[0], [1]], $cells);
    }

    /** Cells listed out of order are committed in flat-index order. */
    public function testCellsAreCommittedInIndexOrder(): void
    {
        [, $cells] = self::commit(self::map([self::num(0, 10, [5])], [[2], [1], [0]]));
        $this->assertSame([[0], [1], [2]], $cells);
    }

    /** A cell index equal to the cell count, or negative, is out of range. */
    public function testCellIndexBounds(): void
    {
        $dims = [self::num(0, 10, [5])];
        $this->assertSame('commitIntentMap: cell index out of range for pay', self::refusal(self::map($dims, [[0], [1], [3]])));
        $this->assertSame('commitIntentMap: cell index out of range for pay', self::refusal(self::map($dims, [[-1], [0], [1], [2]])));
        $this->assertSame('committed', self::refusal(self::map($dims, [[0], [1], [2]])));
    }

    /** A map that leaves a cell out is refused. */
    public function testMissingCellIsRefused(): void
    {
        $this->assertSame('commitIntentMap: the map does not list every cell of pay', self::refusal(self::map([self::num(0, 10, [5])], [[0], [1]])));
    }

    /** A cell given as a keyed PHP array is committed as a JSON array (a list), in the given order. */
    public function testCellIsCommittedAsAList(): void
    {
        $other = static fn(string $path): Obj => Obj::of(['kind' => 'cat', 'path' => $path, 'values' => [Obj::of(['kind' => 'other', 'value' => IntentV2::MAP_OTHER])]]);
        [, $cells] = self::commit(self::map([$other('action.resource'), $other('action.params.x')], [[1 => 0, 0 => 0]]));
        $this->assertSame([[0, 0]], $cells);
    }

    /** A non-string verb reaches the map layer as its string key and is refused there by the string-typed member lookup. */
    public function testNonStringVerbIsRefusedByTheMapLayer(): void
    {
        try {
            IntentMapCommit::commitIntentMap(self::map([self::num(0, 10, [])], [[0]], 7), self::secret());
            $this->fail('no TypeError');
        } catch (\TypeError $e) {
            $this->assertStringStartsWith('Atlas\Pca\Obj::has(): Argument #1 ($k) must be of type string, int given', $e->getMessage());
        }
    }
}
