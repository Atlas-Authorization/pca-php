<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentFrames;
use Atlas\Pca\Js;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentFrames.php: snapshots, write sets and every checkFrame branch. */
final class IntentSurvivorKill30IntentFramesTest extends TestCase
{
    protected function setUp(): void
    {
        Jsx::init();
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function typeError(\Closure $f): string
    {
        try {
            $f();
        } catch (\TypeError $e) {
            return $e->getMessage();
        }
        return 'no type error';
    }

    private static function act(array $extra = []): Obj
    {
        return Obj::of(['verb' => 'x', 'resource' => 'r', 'params' => new Obj()] + $extra);
    }

    private static function leaf(string $field, mixed $value): Obj
    {
        return Obj::of(['field' => $field, 'op' => 'eq', 'value' => $value]);
    }

    private static function pc(array $extra): Obj
    {
        return Obj::of(['verb' => 'x', 'id' => 'p'] + $extra);
    }

    /** checkFrame with no monitored state and the given postconditions. */
    private static function post(array $pcs, ?Obj $action = null, ?Obj $pre = null, ?Obj $post = null, mixed $opts = null): Obj
    {
        return IntentFrames::checkFrame(Obj::of(['state' => [], 'writes' => new Obj(), 'post' => $pcs]), $action ?? self::act(),
            $pre ?? new Obj(), $post ?? new Obj(), $opts);
    }

    /** checkFrame over the monitored variables in $state, nothing written. */
    private static function frame(array $state, Obj $pre, Obj $post, mixed $opts = null): Obj
    {
        return IntentFrames::checkFrame(Obj::of(['state' => $state, 'writes' => new Obj()]), self::act(), $pre, $post, $opts);
    }

    private static function v(mixed $digest, mixed ...$value): Obj
    {
        $o = Obj::of(['digest' => $digest]);
        if ($value !== []) {
            $o->set('value', $value[0]);
        }
        return $o;
    }

    private function assertReport(string $status, array $missing, array $violated, Obj $r): void
    {
        $this->assertSame($status, $r->get('status'));
        $this->assertSame($missing, $r->get('missing'));
        $this->assertSame($violated, $r->get('postViolated'));
    }

    /** Snapshots keep values by default; captureState is public, reads every reader and sorts the names. */
    public function testSnapshotsKeepValuesAndSort(): void
    {
        $this->assertSame(['digest', 'value'], IntentFrames::snapshotState(['a' => 1])->get('a')->keys());
        $s = IntentFrames::captureState(['b' => static fn() => 2, 'a' => static fn() => 1]);
        $this->assertSame(['a', 'b'], $s->keys());
        $this->assertSame(1, $s->get('a')->get('value'));
        $this->assertSame(2, $s->get('b')->get('value'));
        $this->assertSame(['digest'], IntentFrames::captureState(['a' => static fn() => 1], false)->get('a')->keys());
        $n = IntentFrames::captureState([5 => static fn() => 1, 'b' => static fn() => 2]);
        $this->assertSame(['5', 'b'], $n->keys());
        $this->assertSame(1, $n->get('5')->get('value'));
    }

    /** writeSetOf: refusals, a non-object writes map, a verb that is not a string, and the parameter-selected list. */
    public function testWriteSetOf(): void
    {
        $this->assertSame('Cannot convert undefined or null to object', self::typeError(static fn() => IntentFrames::writeSetOf(new Obj(), self::act())));
        $this->assertSame([], IntentFrames::writeSetOf(Obj::of(['writes' => []]), self::act()));
        $this->assertSame([], IntentFrames::writeSetOf(Obj::of(['writes' => Obj::of(['x' => ['a']])]), new Obj()));
        $spec = static fn(Obj $d) => Obj::of(['writes' => Obj::of(['x' => $d])]);
        $this->assertSame('d.param.startsWith is not a function', self::typeError(static fn() => IntentFrames::writeSetOf($spec(new Obj()), self::act())));
        // a string has no members on the path ('length' is not read through it)
        $this->assertSame(['d'], IntentFrames::writeSetOf($spec(Obj::of(['param' => 'action.params.x.length', 'map' => Obj::of(['3' => ['m']]), 'default' => ['d']])),
            self::act(['params' => Obj::of(['x' => 'abc'])])));
        // an absent parameter selects nothing (it is not the key "[object Object]")
        $this->assertSame(['d'], IntentFrames::writeSetOf($spec(Obj::of(['param' => 'action.params.x', 'map' => Obj::of(['[object Object]' => ['m']]), 'default' => ['d']])), self::act()));
        // no map: the default
        $this->assertSame(['d'], IntentFrames::writeSetOf($spec(Obj::of(['param' => 'action.params.x', 'default' => ['d']])), self::act(['params' => Obj::of(['x' => 'v'])])));
    }

    /** Digest comparison: two absent digests are equal, one absent is a change, 5 equals 5.0. */
    public function testDigestEquality(): void
    {
        $this->assertSame('ok', self::frame(['v'], Obj::of(['v' => new Obj()]), Obj::of(['v' => new Obj()]))->get('status'));
        $this->assertSame(['v'], self::frame(['v'], Obj::of(['v' => new Obj()]), Obj::of(['v' => self::v('x')]))->get('outOfFrame'));
        $this->assertSame('ok', self::frame(['v'], Obj::of(['v' => self::v(5)]), Obj::of(['v' => self::v(5.0)]))->get('status'));
        $this->assertSame('ok', self::frame(['v'], Obj::of(['v' => self::v(5)]), Obj::of(['v' => self::v(5)]))->get('status'));
    }

    /** The monitored variables are checked in sorted order; a non-string entry is refused with its own reason. */
    public function testStateOrderAndEntries(): void
    {
        $pre = Obj::of(['b' => self::v('1'), 'a' => self::v('1')]);
        $post = Obj::of(['b' => self::v('2'), 'a' => self::v('2')]);
        $this->assertSame(['a', 'b'], self::frame(['b', 'a'], $pre, $post)->get('outOfFrame'));
        $this->assertReport('pending', ['error: state entry is not a string'], [], self::frame([5], new Obj(), new Obj()));
    }

    /** attributions explicitly undefined: no attribution, the change is out of frame. */
    public function testUndefinedAttributions(): void
    {
        $r = self::frame(['v'], Obj::of(['v' => self::v('1')]), Obj::of(['v' => self::v('2')]), Obj::of(['attributions' => Jsx::$U]));
        $this->assertSame(['v'], $r->get('outOfFrame'));
        $this->assertSame([], $r->get('missing'));
    }

    /** nest: a non-object entry is refused with the reference's message; an array entry has no value; an entry without one is skipped. */
    public function testNest(): void
    {
        $this->assertReport('pending', ["error: Cannot use 'in' operator to search for 'value' in 5"], [], self::post([], null, Obj::of(['x' => 5])));
        $this->assertReport('ok', [], [], self::post([], null, Obj::of(['x' => []]), Obj::of(['x' => []])));
        $pre = Obj::of(['a' => self::v('d'), 'b' => self::v('d1', 1)]);
        $post = Obj::of(['a' => self::v('d'), 'b' => self::v('d2', 2)]);
        $this->assertReport('ok', [], [], self::post([self::pc(['deltas' => [Obj::of(['path' => 'b', 'by' => 1])]])], null, $pre, $post));
    }

    /** env.effect is {} when the option is absent or undefined; action.params is {} when absent, else the params. */
    public function testEffectAndParams(): void
    {
        $pc = [self::pc(['where' => [self::leaf('env.effect', new Obj())]])];
        $this->assertReport('ok', [], [], self::post($pc));
        $this->assertReport('ok', [], [], self::post($pc, null, null, null, Obj::of(['effect' => Jsx::$U])));
        $noParams = Obj::of(['verb' => 'x', 'resource' => 'r']);
        $this->assertReport('ok', [], [], self::post([self::pc(['where' => [self::leaf('action.params', new Obj())]])], $noParams));
        $this->assertReport('ok', [], [], self::post([self::pc(['where' => [self::leaf('action.params.n', 5)]])], self::act(['params' => Obj::of(['n' => 5])])));
    }

    /** Deltas: a non-string path is refused; a missing side is pending (never a violation, the where is not evaluated). */
    public function testDeltas(): void
    {
        $this->assertReport('pending', ['error: path.split is not a function'], [], self::post([self::pc(['deltas' => [Obj::of(['path' => 5, 'by' => 1])]])]));
        $pre = Obj::of(['b' => self::v('d1', 1)]);
        $post = Obj::of(['b' => self::v('d2')]);
        $this->assertReport('pending', ['p:b'], [], self::post([self::pc(['deltas' => [Obj::of(['path' => 'b', 'by' => 1])]])], null, $pre, $post));
        $this->assertReport('pending', ['p:zz'], [], self::post([self::pc(['deltas' => [Obj::of(['path' => 'zz', 'by' => 1])], 'where' => [self::leaf('action.verb', 'other')]])]));
    }

    /** A violated delta stops that postcondition: no later delta and no where read is reported. */
    public function testViolatedDeltaStops(): void
    {
        $pre = Obj::of(['b' => self::v('d1', 1)]);
        $post = Obj::of(['b' => self::v('d2', 2)]);
        $pc = self::pc(['deltas' => [Obj::of(['path' => 'b', 'by' => 5]), Obj::of(['path' => 'zz', 'by' => 1])], 'where' => [self::leaf('env.post.zz', 1)]]);
        $this->assertReport('violated', [], ['p'], self::post([$pc], null, $pre, $post));
    }

    /** A truthy non-array where is refused; an empty where is never evaluated (an action without a resource still passes). */
    public function testWhereShapes(): void
    {
        $this->assertReport('pending', ['error: (pc.where ?? []).forEach is not a function'], [], self::post([self::pc(['where' => 'x'])]));
        $this->assertReport('ok', [], [], self::post([self::pc(['where' => []])], Obj::of(['verb' => 'x'])));
    }

    /** Violated ids: undefined is "undefined", a number its text, duplicates once. */
    public function testViolatedIds(): void
    {
        $bad = ['where' => [self::leaf('action.verb', 'other')]];
        $this->assertReport('violated', [], ['undefined'], self::post([Obj::of(['verb' => 'x'] + $bad)]));
        $this->assertReport('violated', [], ['5'], self::post([Obj::of(['verb' => 'x', 'id' => 5] + $bad)]));
        $this->assertReport('violated', [], ['p'], self::post([self::pc($bad), self::pc($bad)]));
    }

    /** env reads inside all_of are found; a non-array all_of / any_of is no group to walk (and no error). */
    public function testEnvReadsInGroups(): void
    {
        $this->assertReport('pending', ['p:env.post.zz'], [], self::post([self::pc(['where' => [Obj::of(['all_of' => [self::leaf('env.post.zz', 1)]])]])]));
        foreach (['all_of', 'any_of'] as $g) {
            $this->assertSame([], self::post([self::pc(['where' => [Obj::of([$g => 'x'])]])])->get('missing'), $g);
        }
    }
}
