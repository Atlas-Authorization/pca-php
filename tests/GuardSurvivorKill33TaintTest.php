<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Taint.php';

use Atlas\Pca\InMemoryTaintRegistry;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Taint;
use Atlas\Pca\Undef;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Taint.php: joinLabel's id comparison at equal rank, its refusal of an undefined label and the empty registry. */
final class GuardSurvivorKill33TaintTest extends TestCase
{
    private static function web(mixed ...$id): Obj
    {
        return Obj::of(['kind' => 'web'] + ($id === [] ? [] : ['id' => $id[0]]));
    }

    public function testEqualRankIdComparison(): void
    {
        $a = self::web(new Num('1'));
        $this->assertSame($a, Taint::joinLabel($a, self::web(1)), 'the same number id keeps the label');
        $this->assertSame($a, Taint::joinLabel($a, self::web(new Num('1.0'))));
        foreach ([[new Num('1'), new Num('2')], [new Num('0'), 'x'], ['x', new Num('0')], [null, 'n']] as [$x, $y]) {
            $r = Taint::joinLabel(self::web($x), self::web($y));
            $this->assertSame(['kind'], $r->keys(), 'different ids join to the generic label');
            $this->assertSame('web', $r->get('kind'));
        }
        // an absent id is not a null id
        $r = Taint::joinLabel(self::web(null), self::web());
        $this->assertSame(['kind'], $r->keys());
        // a label that is not an object (unknown rank) has no id: two of them are the same
        $this->assertSame('x', Taint::joinLabel('x', 'x'));
    }

    public function testAnUndefinedLabelThrowsAtEqualRank(): void
    {
        try {
            Taint::joinLabel(new Undef(), new Undef());
            $this->fail('an undefined label was joined');
        } catch (\TypeError $e) {
            $this->assertSame('Cannot convert undefined or null to object', $e->getMessage());
        }
    }

    /** In a fresh process nothing has set up the undefined marker yet: joinLabel does it itself. */
    #[RunInSeparateProcess]
    public function testJoinLabelInitialisesTheUndefinedMarker(): void
    {
        $a = self::web();
        $this->assertSame($a, Taint::joinLabel($a, self::web()));
    }

    public function testEmptyRegistry(): void
    {
        $this->assertSame(0, InMemoryTaintRegistry::empty()->size());
    }
}
