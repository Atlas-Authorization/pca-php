<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use Atlas\Pca\Undef;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the JavaScript-semantics helpers. */
final class RestSurvivorKill35JsxTest extends TestCase
{
    /** An array is indexed by position whatever its keys; a string index at its length is undefined. */
    public function testGetByPosition(): void
    {
        $this->assertSame('q', Jsx::get(['x' => 'p', 'y' => 'q'], '1'));
        $this->assertSame('b', Jsx::get('ab', '1'));
        $this->assertInstanceOf(Undef::class, Jsx::get('ab', '2'));
    }

    /** Object.keys of an array is its positions, never its PHP keys. */
    public function testKeysOfAnArray(): void
    {
        $this->assertSame(['0', '1'], Jsx::keys(['x' => 1, 'y' => 2]));
        $this->assertSame(['0', '1'], Jsx::keys('ab'));
    }

    /** {...array} and {...string} give positional members (UTF-8 characters for a string). */
    public function testSpread(): void
    {
        $a = Jsx::spread(['x' => 'a', 'y' => 'b']);
        $this->assertSame(['0', '1'], $a->keys());
        $this->assertSame(['a', 'b'], [$a->get('0'), $a->get('1')]);
        $s = Jsx::spread("a\u{e9}");
        $this->assertSame(['0', '1'], $s->keys());
        $this->assertSame("\u{e9}", $s->get('1'));
    }

    /** Number(false) is 0. */
    public function testToNumFalse(): void
    {
        $this->assertSame(0.0, Jsx::toNum(false));
        $this->assertSame(1.0, Jsx::toNum(true));
    }

    /** An object compares as the string "[object Object]". */
    public function testObjectComparesAsItsString(): void
    {
        $this->assertTrue(Jsx::lt(new Obj(), 'x'));
        $this->assertFalse(Jsx::lt('x', new Obj()));
    }

    /** cmp is exactly -1 / 1 / 0. */
    public function testCmp(): void
    {
        $this->assertSame([-1, 1, 0], [Jsx::cmp(1, 2), Jsx::cmp(2, 1), Jsx::cmp(1, 1)]);
    }

    /** A value that is not a list or string is not iterable. */
    public function testIterRefusesOtherValues(): void
    {
        try {
            Jsx::iter(5);
            $this->fail('iterated');
        } catch (\TypeError $e) {
            $this->assertSame('not iterable', $e->getMessage());
        }
    }

    /** plain deep-copies objects and arrays, turning every -0 (and 0.0) into integer 0. */
    public function testPlain(): void
    {
        $o = Obj::of(['a' => -0.0]);
        $p = Jsx::plain($o);
        $this->assertNotSame($o, $p);
        $this->assertSame(0, $p->get('a'));
        $this->assertSame([0, 1.5], Jsx::plain([-0.0, 1.5]));
        $this->assertSame(0, Jsx::plain(-0.0));
        $this->assertSame(0, Jsx::plain(0.0));
    }

    /** sort refuses anything but a list, with the runtime's wording. */
    public function testSortRefusesNonLists(): void
    {
        foreach ([['a' => 1, 'b' => 2], 5] as $bad) {
            try {
                Jsx::sort($bad, static fn($a, $b): int => 0);
                $this->fail('sorted');
            } catch (\TypeError $e) {
                $this->assertSame('sort is not a function', $e->getMessage());
            }
        }
    }

    /** sort is stable: elements the comparator calls equal keep their order (short and long lists). */
    public function testSortIsStable(): void
    {
        $this->assertSame(['b', 'a'], Jsx::sort(['b', 'a'], static fn($a, $b): int => 0));
        $this->assertSame([3, 1, 2], Jsx::sort([3, 1, 2], static fn($a, $b): int => 0));
        $long = range(39, 0, -1);
        $this->assertSame($long, Jsx::sort($long, static fn($a, $b): float => 0.0));
        $this->assertSame([1, 2, 3], Jsx::sort([3, 1, 2], static fn($a, $b): float => ($a - $b) * 5.0));
    }
}
