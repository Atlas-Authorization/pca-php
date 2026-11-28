<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentHistory;
use Atlas\Pca\MemoryIntentSessionStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/IntentHistory.php';

/** Group 32 mutation kills for src/IntentHistory.php: window arithmetic (JS ToNumber of the members), monitor steps, the verifier context and admission. */
final class IntentSurvivorKill32IntentHistoryTest extends TestCase
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

    private static function sliding(mixed $ms): Obj
    {
        return Obj::of(['kind' => 'sliding', 'ms' => $ms]);
    }

    /** A window that is not an object has no kind: undefined (null), never a member read. */
    public function testANonObjectWindowHasNoKind(): void
    {
        self::assertNull(IntentHistory::inWindow('x', 1, 2));
    }

    /** Sliding windows coerce ms as `t - ms` does: numbers, booleans, null, strings by Number() and lists by their text; absent is NaN. */
    public function testSlidingMemberCoercion(): void
    {
        // ti = t = 5: inside exactly when ms > 0
        self::assertTrue(IntentHistory::inWindow(self::sliding(10), 5, 5));
        self::assertTrue(IntentHistory::inWindow(self::sliding(new Num('1')), 5, 5));
        self::assertTrue(IntentHistory::inWindow(self::sliding(0.5), 5, 5));
        self::assertTrue(IntentHistory::inWindow(self::sliding(true), 5, 5), 'true is 1');
        self::assertFalse(IntentHistory::inWindow(self::sliding(false), 5, 5), 'false is 0');
        self::assertFalse(IntentHistory::inWindow(self::sliding(null), 5, 5), 'null is 0');
        self::assertFalse(IntentHistory::inWindow(Obj::of(['kind' => 'sliding']), 5, 5), 'absent is NaN');
        self::assertTrue(IntentHistory::inWindow(self::sliding(' 0x10 '), 5, 5), 'Number(" 0x10 ") is 16');
        self::assertTrue(IntentHistory::inWindow(self::sliding('Infinity'), 5, 5));
        self::assertFalse(IntentHistory::inWindow(self::sliding("1\0"), 5, 5), 'NUL is not white space: NaN');
        self::assertFalse(IntentHistory::inWindow(self::sliding('1x'), 5, 5));
        self::assertTrue(IntentHistory::inWindow(self::sliding([10]), 5, 5), '[10] is 10');
        self::assertFalse(IntentHistory::inWindow(self::sliding([]), 5, 5), '[] is 0');
        self::assertFalse(IntentHistory::inWindow(self::sliding(Obj::of(['a' => 1])), 5, 5), 'an object is NaN');
    }

    /** Period windows: t0 null or blank is 0, so stamps 0 and 5 share the period [0, 10); t0 = 1 would split them. */
    public function testPeriodMemberCoercion(): void
    {
        foreach ([null, ' ', '', 0] as $t0) {
            self::assertTrue(IntentHistory::inWindow(Obj::of(['kind' => 'period', 'ms' => 10, 't0' => $t0]), 0, 5), 't0 ' . var_export($t0, true));
        }
        self::assertFalse(IntentHistory::inWindow(Obj::of(['kind' => 'period', 'ms' => 10, 't0' => 1]), 0, 5));
        self::assertFalse(IntentHistory::inWindow(Obj::of(['kind' => 'period', 'ms' => 10]), 0, 5), 'absent t0 is NaN');
    }

    /** responds_within reads `within` as a number (a numeric string too): a matching trigger starts the countdown at it. */
    public function testRespondsWithinReadsWithin(): void
    {
        $m = Obj::of(['kind' => 'responds_within', 'within' => '3', 'p' => Obj::of(['verb' => 'v']), 'q' => Obj::of(['verb' => 'zz'])]);
        $e = Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => new Obj(), 'status' => 'committed']);
        self::assertSame('pending:3', IntentHistory::monitorStep($m, 'idle', $e));
    }

    /** The context: only site-local holders (a non-object holder skipped), a missing key skips that accumulator only, ids as text. */
    public function testTheVerifierContext(): void
    {
        $site = Obj::of(['kind' => 'site_local']);
        $win = Obj::of(['kind' => 'task']);
        $root = Obj::of([
            'accumulators' => [
                Obj::of(['id' => 'h', 'key' => null, 'agg' => 'count', 'win' => $win, 'holder' => 'x']),
                Obj::of(['id' => 'a', 'key' => 'action.params.k', 'agg' => 'count', 'win' => $win, 'holder' => $site]),
                Obj::of(['id' => 5, 'key' => null, 'agg' => 'count', 'win' => $win, 'holder' => $site]),
            ],
            'monitors' => [Obj::of(['id' => 7, 'kind' => 'never', 'p' => Obj::of(['verb' => 'v'])])],
        ]);
        $ctx = IntentHistory::accContextFor($root, [], Obj::of(['params' => new Obj(), 't' => 0]));
        self::assertSame(['5'], $ctx['state']->keys());
        self::assertSame('0', $ctx['state']->get('5')->get('count')->lexeme);
        self::assertSame(['7'], $ctx['monitors']->keys());
        self::assertSame('clean', $ctx['monitors']->get('7'));
    }

    /** Admission appends the event exactly when the verdict allows: an array needs allow, an object needs allow === true. */
    public function testAdmissionFollowsTheVerdict(): void
    {
        $cases = [
            'array without allow' => [[], 0],
            'array allow' => [['allow' => true], 1],
            'object allow true' => [Obj::of(['allow' => true]), 1],
            'object allow false' => [Obj::of(['allow' => false]), 0],
            'object allow 1' => [Obj::of(['allow' => 1]), 0],
            'null' => [null, 0],
        ];
        foreach ($cases as $name => [$verdict, $n]) {
            $store = new MemoryIntentSessionStore();
            $r = IntentHistory::admitIntentAction($store, [
                'session' => 's', 'root' => Obj::of(['accumulators' => [], 'monitors' => []]),
                'event' => Obj::of(['id' => 'e1', 'verb' => 'v', 'resource' => 'r', 'params' => new Obj(), 't' => 0, 'status' => 'x']),
                'verify' => static fn(array $acc) => $verdict, 'requireDurable' => false,
            ]);
            self::assertSame($verdict, $r, $name);
            $log = $store->snapshot('s');
            self::assertCount($n, $log, $name);
            if ($n === 1) {
                self::assertSame('reserved', $log[0]->get('status'));
            }
        }
    }
}
