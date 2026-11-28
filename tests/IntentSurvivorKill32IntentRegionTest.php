<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentRegion;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 32 mutation kills for src/IntentRegion.php: cell regions, restriction, the covered cells of a dimension and of a verb space, value membership. */
final class IntentSurvivorKill32IntentRegionTest extends TestCase
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

    private static function num(): Obj
    {
        return Obj::of(['kind' => 'num', 'path' => 'action.params.x', 'lo' => 0, 'hi' => 9, 'cuts' => [5]]);
    }

    private static function values(): array
    {
        return [Obj::of(['kind' => 'exact', 'value' => 'a']), Obj::of(['kind' => 'exact', 'value' => 'b'])];
    }

    private static function cat(?string $path = 'action.params.c'): Obj
    {
        $d = Obj::of(['kind' => 'cat', 'values' => self::values()]);
        if ($path !== null) {
            $d->set('path', $path);
        }
        return $d;
    }

    /** A categorical cell region carries copies of the value list, not the verb space's own objects. */
    public function testACellRegionCopiesTheValueList(): void
    {
        $d = self::cat();
        $r = IntentRegion::regionOfCell(Obj::of(['verb' => 'v', 'dims' => [$d]]), [1]);
        $vals = $r->get('dims')->get('action.params.c')->get('values');
        self::assertSame(Json::stringify($d->get('values')), Json::stringify($vals));
        self::assertNotSame($d->get('values')[0], $vals[0]);
        $vals[0]->set('value', 'changed');
        self::assertSame('a', $d->get('values')[0]->get('value'), 'the verb space is untouched');
    }

    /** A numeric cell index past the last cell is refused. */
    public function testAnOutOfRangeNumericCellIsRefused(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('cell index out of range');
        IntentRegion::regionOfCell(Obj::of(['verb' => 'v', 'dims' => [self::num()]]), [5]);
    }

    /** A {lo, hi} part for a categorical dimension is refused, naming the path. */
    public function testARangePartForACategoricalDimensionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('restrictRegion: part does not match the kind of action.params.c');
        IntentRegion::restrictRegion(Obj::of(['verb' => 'v', 'dims' => new Obj()]), self::cat(), ['lo' => 1, 'hi' => 2]);
    }

    /** A {cells} part for a numeric dimension is refused. */
    public function testACellsPartForANumericDimensionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('restrictRegion: part does not match the kind of action.params.x');
        IntentRegion::restrictRegion(Obj::of(['verb' => 'v', 'dims' => new Obj()]), self::num(), ['cells' => [0]]);
    }

    /** dimCellsIn: no cells for an empty dimension, a re-indexed list for a numeric region (inner and outer) and for a categorical one (a dimension without a path too). */
    public function testDimCellsIn(): void
    {
        self::assertSame([], IntentRegion::dimCellsIn(Obj::of(['kind' => 'cat', 'path' => 'p', 'values' => []]), null, 'inner'));
        $rd = Obj::of(['kind' => 'num', 'lo' => 5, 'hi' => 9]);
        self::assertSame([1, 2], IntentRegion::dimCellsIn(self::num(), $rd, 'inner'));
        self::assertSame([0, 1], IntentRegion::dimCellsIn(self::num(), Obj::of(['kind' => 'num', 'lo' => 3, 'hi' => 5]), 'outer'));
        $rc = Obj::of(['kind' => 'cat', 'values' => self::values(), 'cells' => [1]]);
        self::assertSame([1], IntentRegion::dimCellsIn(self::cat(null), $rc, 'inner'));
    }

    /** A numeric dimension restricted by a categorical region dimension is refused. */
    public function testANumericDimensionWithACategoricalRegionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('region: action.params.x is numeric in Ω but categorical in the region');
        IntentRegion::dimCellsIn(self::num(), Obj::of(['kind' => 'cat', 'values' => self::values(), 'cells' => [0]]), 'inner');
    }

    /** A categorical dimension restricted by a numeric region dimension is refused. */
    public function testACategoricalDimensionWithANumericRegionIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('region: action.params.c is categorical in Ω but numeric in the region');
        IntentRegion::dimCellsIn(self::cat(), Obj::of(['kind' => 'num', 'lo' => 0, 'hi' => 1]), 'inner');
    }

    /** A region of another verb is refused, naming both verbs. */
    public function testARegionOfAnotherVerbIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('region: verb a does not match b');
        IntentRegion::regionCells(Obj::of(['verb' => 'b', 'dims' => []]), Obj::of(['verb' => 'a', 'dims' => new Obj()]), 'inner');
    }

    /** A region restricting a dimension the verb space lacks is refused (dropping it would widen a yes). */
    public function testARestrictionWithoutADimensionIsRefused(): void
    {
        $r = Obj::of(['verb' => 'v', 'dims' => Obj::of(['action.params.q' => Obj::of(['kind' => 'num', 'lo' => 0, 'hi' => 1])])]);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('region: restricts action.params.q, which Ω has no dimension for');
        IntentRegion::regionCells(Obj::of(['verb' => 'v', 'dims' => [self::num()]]), $r, 'inner');
    }

    /** The region dimension is looked up by the dimension's path as a string: a missing path reads as '' (the key of the region's '' dimension). */
    public function testRegionCellsLooksUpThePathAsAString(): void
    {
        $rc = Obj::of(['kind' => 'cat', 'values' => self::values(), 'cells' => [0]]);
        $vs = Obj::of(['verb' => 'v', 'dims' => [self::cat(''), self::cat(null)]]);
        self::assertSame([0], IntentRegion::regionCells($vs, Obj::of(['verb' => 'v', 'dims' => Obj::of(['' => $rc])]), 'inner'));
        self::assertSame([0, 1, 2, 3], IntentRegion::regionCells(Obj::of(['verb' => 'v', 'dims' => [self::cat(null), self::cat(null)]]), Obj::of(['verb' => 'v', 'dims' => new Obj()]), 'inner'));
    }

    /** valueInRegionDim: an inclusive numeric range for numbers only, and the listed cells for strings only. */
    public function testValueInRegionDim(): void
    {
        $rn = Obj::of(['kind' => 'num', 'lo' => 1, 'hi' => 3]);
        self::assertTrue(IntentRegion::valueInRegionDim('p', $rn, 1), 'lo is inside');
        self::assertTrue(IntentRegion::valueInRegionDim('p', $rn, 2));
        self::assertTrue(IntentRegion::valueInRegionDim('p', $rn, 3), 'hi is inside');
        self::assertFalse(IntentRegion::valueInRegionDim('p', $rn, 0));
        self::assertFalse(IntentRegion::valueInRegionDim('p', $rn, 4));
        self::assertFalse(IntentRegion::valueInRegionDim('p', $rn, '2'), 'a numeric string is not a number');
        self::assertFalse(IntentRegion::valueInRegionDim('p', Obj::of(['kind' => 'num', 'lo' => 0, 'hi' => 3]), 'x'), 'nor is any other string, from 0 up');
        $rc = Obj::of(['kind' => 'cat', 'values' => self::values(), 'cells' => [0]]);
        self::assertTrue(IntentRegion::valueInRegionDim('p', $rc, 'a'));
        self::assertFalse(IntentRegion::valueInRegionDim('p', $rc, 'b'));
    }
}
