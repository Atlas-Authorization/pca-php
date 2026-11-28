<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalJs.php';
require_once __DIR__ . '/../src/GoalDriftMonitor.php';

use Atlas\Pca\GoalDriftMonitor;
use Atlas\Pca\GoalJs;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** JS string semantics of the goal package (UTF-16 units both ways, keys, toLowerCase) and the stateful drift monitor. */
final class GoalSurvivorKill20JsDriftTest extends TestCase
{
    /** WTF-8 decodes to UTF-16 units: each lead-byte range, every payload bit, surrogate pairs and the cursor step. */
    public function testUnits(): void
    {
        self::assertSame([1], GoalJs::units("\x80A"));
        self::assertSame([0x800], GoalJs::units("\xE0\xA0\x80"));
        self::assertSame([0x1041], GoalJs::units("\xE1\x81\x81"));
        self::assertSame([0x7F, 0x41], GoalJs::units("\x7FA"));
        self::assertSame([0xD83D, 0xDE00], GoalJs::units("\xF0\x9F\x98\x80"));
        self::assertSame([0xD8ED, 0xDF67], GoalJs::units("\xF1\x8B\x9D\xA7"));
        self::assertSame([0x5A, 0xD8ED, 0xDF67, 0x59], GoalJs::units("Z\xF1\x8B\x9D\xA7Y"));
        self::assertSame([0xD8ED, 0xDF67, 0x41, 0x42], GoalJs::units("\xF1\x8B\x9D\xA7AB"));
        self::assertSame([0xDBFF, 0xDFFF], GoalJs::units("\xF4\x8F\xBF\xBF"));
    }

    /** UTF-16 units encode back: only a high+low pair joins, every other unit (a lone surrogate too) is its own WTF-8 sequence. */
    public function testFromUnits(): void
    {
        $cases = [
            ["\xF0\x90\x80\x80", [0xD800, 0xDC00]],
            ["\xF4\x8F\xBF\xBF", [0xDBFF, 0xDFFF]],
            ["\xED\xA0\x80\xEE\x80\x80", [0xD800, 0xE000]],
            ["\xF0\x90\x80\x80\xEE\x80\x80", [0xD800, 0xDC00, 0xE000]],
            ["\xF0\x90\x80\x80A", [0xD800, 0xDC00, 0x41]],
            ["A\xED\xB0\x80", [0x41, 0xDC00]],
            ["A\xF0\x90\x80\x80", [0x41, 0xD800, 0xDC00]],
            ["\xEE\x80\x80\xF0\x90\x80\x80", [0xE000, 0xD800, 0xDC00]],
            ["A\xF0\x9F\x98\x80B", [0x41, 0xD83D, 0xDE00, 0x42]],
            ["\xF1\x8B\x9D\xA7", [0xD8ED, 0xDF67]],
            ["\xF0\x9F\x98\x80", [0xD83D, 0xDE00]],
            ["\x7F", [0x7F]],
            ["\xC2\x80", [0x80]],
            ["\xE0\xA0\x80", [0x800]],
            ["\xE1\x81\x81", [0x1041]],
            ["\xED\xA0\x80", [0xD800]],
        ];
        foreach ($cases as [$want, $u]) {
            self::assertSame(bin2hex($want), bin2hex(GoalJs::fromUnits($u)), json_encode($u));
        }
    }

    /** length, equality, Object.keys and o[k] over strings and arrays. */
    public function testKeysAndReads(): void
    {
        self::assertSame(2, GoalJs::ulen("\xF0\x9F\x98\x80"));
        self::assertTrue(GoalJs::strEq('a', 'a'));
        self::assertFalse(GoalJs::strEq('a', 'b'));
        self::assertSame(['0', '1'], GoalJs::okeys(['x', 'y']));
        self::assertSame('b', GoalJs::kget('ab', '1'));
        self::assertSame("\xED\xB8\x80", GoalJs::kget("\xF0\x9F\x98\x80", '1'));
    }

    /** toLowerCase lowers every valid run (non-ASCII too) and leaves each lone surrogate byte-for-byte in place. */
    public function testLower(): void
    {
        self::assertSame("\u{E0}b", GoalJs::lower("\u{C0}B"));
        self::assertSame("\xED\xA0\x80a", GoalJs::lower("\xED\xA0\x80A"));
        self::assertSame("\u{E0}b\xED\xA0\x80cd\xED\xB0\x80ef", GoalJs::lower("\u{C0}B\xED\xA0\x80CD\xED\xB0\x80EF"));
    }

    private static function goal(): Obj
    {
        return Obj::of(['grants' => [Obj::of(['verb' => 'pay', 'res' => Obj::of(['k' => 'any'])])]]);
    }

    private static function act(mixed $amount, string $verb = 'pay', ?Obj $params = null): Obj
    {
        return Obj::of(['verb' => $verb, 'res' => 'r', 'params' => $params ?? Obj::of(['amount' => Obj::of(['k' => 'q', 'q' => Obj::of(['n' => $amount])])])]);
    }

    /** Options come from an Obj or an associative array (numeric keys too); a list or nothing keeps the defaults. */
    public function testOptions(): void
    {
        $defaults = ['windowMs', 'maxPerWindow', 'maxNovel', 'magnitudeFactor', 'warmup', 'lockdown'];
        foreach ([Obj::of(['maxPerWindow' => 1]), ['maxPerWindow' => 1]] as $opts) {
            $m = new GoalDriftMonitor(self::goal(), $opts);
            self::assertSame([], $m->observe(self::act(1), 1)->get('reasons'));
            self::assertSame(['rate above the profile'], $m->observe(self::act(1), 2)->get('reasons'));
        }
        $m = new GoalDriftMonitor(self::goal());
        self::assertSame($defaults, $m->o->keys());
        $m->observe(self::act(1), 1);
        self::assertSame([], $m->observe(self::act(1), 2)->get('reasons'));
        self::assertSame($defaults, (new GoalDriftMonitor(self::goal(), [99]))->o->keys());
        $n = new GoalDriftMonitor(self::goal(), [7 => 'x']);
        self::assertSame('x', $n->o->get('7'));
    }

    /** The magnitude check compares with factor x the running mean of the history, never fires on a zero mean, and skips non-quantities. */
    public function testMagnitude(): void
    {
        $o = ['warmup' => 1, 'magnitudeFactor' => 2];
        $m = new GoalDriftMonitor(self::goal(), $o);
        $m->observe(self::act(10), 1);
        self::assertSame(['amount magnitude 2x above the running mean'], $m->observe(self::act(21), 2)->get('reasons'));
        $m = new GoalDriftMonitor(self::goal(), $o);
        $m->observe(self::act(10), 1);
        self::assertSame([], $m->observe(self::act(20), 2)->get('reasons'), 'control: exactly factor x mean is not above');
        $m = new GoalDriftMonitor(self::goal(), $o);
        $m->observe(self::act(0), 1);
        self::assertSame([], $m->observe(self::act(5), 2)->get('reasons'));
        $m = new GoalDriftMonitor(self::goal());
        $m->observe(self::act(0, 'pay', Obj::of(['note' => Obj::of(['k' => 's']), 'amount' => Obj::of(['k' => 'q', 'q' => Obj::of(['n' => 10])])])), 1);
        self::assertSame([10], $m->state()->get('seen')->get('amount'));
    }

    /** The per-parameter history keeps exactly the last 50 values. */
    public function testHistoryWindow(): void
    {
        $m = new GoalDriftMonitor(self::goal(), ['maxPerWindow' => 1000, 'warmup' => 1000]);
        for ($i = 1; $i <= 51; $i++) {
            $m->observe(self::act($i), $i);
        }
        self::assertSame(range(2, 51), $m->state()->get('seen')->get('amount'));
    }

    /** Strikes count up by one as an integer while integral and safe, and stay a float otherwise. */
    public function testStrikeArithmetic(): void
    {
        $m = new GoalDriftMonitor(self::goal());
        self::assertSame(1, $m->observe(self::act(1, 'evil'), 1)->get('strikes'));
        $m->st->set('strikes', 0.5);
        $s = $m->observe(self::act(1, 'evil'), 2);
        self::assertSame(1.5, $s->get('strikes'));
        self::assertFalse($s->get('lockdown'));
        $m->st->set('strikes', 9007199254740991);
        $s = $m->observe(self::act(1, 'evil'), 3);
        self::assertSame(9007199254740992.0, $s->get('strikes'));
        self::assertTrue($s->get('lockdown'));
    }
}
