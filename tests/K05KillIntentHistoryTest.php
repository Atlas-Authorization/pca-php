<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentHistory.php';

use Atlas\Pca\HistoryError;
use Atlas\Pca\IntentHistory;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Exact-outcome kill tests of the session-history helpers (intent-history.ts): windows, error texts, empty pre-states, monitor arithmetic. */
final class K05KillIntentHistoryTest extends TestCase
{
    private static function j(string $t): mixed
    {
        return Json::parseLax($t);
    }

    private static function throwsMsg(string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            self::assertInstanceOf(HistoryError::class, $e);
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("no HistoryError: $msg");
    }

    private static function ev(string $verb, mixed $t, ?Obj $params = null): Obj
    {
        return Obj::of(['id' => 'e1', 'verb' => $verb, 'resource' => 'r', 'params' => $params ?? new Obj(), 'status' => 'committed', 't' => $t]);
    }

    public function testInWindowEdges(): void
    {
        $this->assertTrue(IntentHistory::inWindow(self::j('{"kind":"task"}'), 1, 2)); // native ints are times too
        $this->assertTrue(IntentHistory::inWindow(Obj::of(['kind' => 'sliding', 'ms' => '100']), new Num('901'), new Num('1000')));
        $this->assertFalse(IntentHistory::inWindow(self::j('{"kind":"other"}'), new Num('5'), new Num('5'))); // equal time is not "after t"
        $this->assertFalse(IntentHistory::inWindow(null, new Num('1'), new Num('2')));
        $this->assertNull(IntentHistory::accKeyOf(Obj::of(['key' => 5]), new Obj()));
    }

    public function testAccPreStateErrorTextsAndSafeSum(): void
    {
        $sum = self::j('{"id":"s","agg":"sum","val":"action.params.x","unit":"u","sel":{"verbs":["buy"]},"win":{"kind":"task"},"key":null,"holder":{"kind":"site_local"}}');
        $keyed = self::j('{"id":"s","agg":"sum","val":"action.params.x","unit":"u","sel":{"verbs":["buy"]},"win":{"kind":"task"},"key":"action.params.k","holder":{"kind":"site_local"}}');
        self::throwsMsg('the key parameter action.params.k is missing', static fn() => IntentHistory::accPreState($keyed, [], new Obj(), new Num('1')));
        self::throwsMsg('event e1: the time is not a safe integer', static fn() => IntentHistory::accPreState($sum, [self::ev('buy', new Num('1.5'))], new Obj(), new Num('3')));
        self::throwsMsg('event e1: action.params.x must be a non-negative safe integer',
            static fn() => IntentHistory::accPreState($sum, [self::ev('buy', new Num('1'))], new Obj(), new Num('3')));
        $max = self::ev('buy', new Num('1'), Obj::of(['x' => new Num('9007199254740991')]));
        $this->assertSame('{"sum":9007199254740991}', Json::canonicalizeStrict(IntentHistory::accPreState($sum, [$max], new Obj(), new Num('3'))));
    }

    public function testAccPostWithAMissingKeyStartsEmpty(): void
    {
        $distinct = self::j('{"id":"s","agg":"distinct","val":"action.params.v","sel":{"verbs":["buy"]},"win":{"kind":"task"},"key":"action.params.k"}');
        $this->assertSame(0, IntentHistory::accPost($distinct, [], 'sell', new Obj(), new Num('1')));
        $this->assertSame(1, IntentHistory::accPost($distinct, [], 'buy', Obj::of(['v' => 'x']), new Num('1')));
        foreach (['sum' => 7, 'count' => 1, 'max' => 7] as $agg => $post) {
            $a = self::j('{"id":"s","agg":"' . $agg . '","val":"action.params.x","unit":"u","sel":{"verbs":["buy"]},"win":{"kind":"task"},"key":"action.params.k","holder":{"kind":"site_local"}}');
            $this->assertSame(0, IntentHistory::accPost($a, [], 'sell', Obj::of(['x' => new Num('7')]), new Num('1')));
            $this->assertSame($post, IntentHistory::accPost($a, [], 'buy', Obj::of(['x' => new Num('7')]), new Num('1')));
        }
    }

    public function testRespondsWithinArithmetic(): void
    {
        $m = self::j('{"id":"m","kind":"responds_within","p":{"verb":"a"},"q":{"verb":"b"},"within":2}');
        $c = self::ev('c', new Num('1'));
        $this->assertSame('pending:4', IntentHistory::monitorStep($m, 'pending:5', $c));
        // the pending count is a JS number: 2^53+1 reads as 2^53
        $this->assertSame('pending:9007199254740991', IntentHistory::monitorStep($m, 'pending:9007199254740993', $c));
        $nanW = $m->without();
        $nanW->set('within', NAN);
        $this->assertSame('pending:NaN', IntentHistory::monitorStep($nanW, 'pending:5', self::ev('a', new Num('1'))));
    }

    public function testPendingStateIsReadWithJsNumber(): void
    {
        // intent-history.ts: Number(q.slice('pending:'.length))
        $m = self::j('{"id":"m","kind":"responds_within","p":{"verb":"a"},"q":{"verb":"b"},"within":2}');
        $c = self::ev('c', new Num('1'));
        $this->assertSame('missed', IntentHistory::monitorStep($m, 'pending:', $c)); // Number("") is 0
        $this->assertSame('pending:4', IntentHistory::monitorStep($m, 'pending:0x5', $c));
        $this->assertSame('pending:4', IntentHistory::monitorStep($m, 'pending: 5 ', $c));
        $this->assertSame('pending:9', IntentHistory::monitorStep($m, 'pending:1e1', $c));
        $this->assertSame('pending:NaN', IntentHistory::monitorStep($m, 'pending:abc', $c));
    }

    public function testAccPostRefusesAnAggOutsideTheFourFirst(): void
    {
        // intent-history.ts accPost (80ad8c7ff): an unknown agg throws before any key / pre-state work, selected or not, keyed or not
        foreach (['"SUM"', '"tVm"', '""', '"avg"', 'null', '1', null] as $agg) {
            $bad = self::j('{"id":"s",' . ($agg === null ? '' : '"agg":' . $agg . ',') . '"val":"action.params.total","unit":"u","sel":{"verbs":["pay"]},"win":{"kind":"task"},"key":null,"holder":{"kind":"site_local"}}');
            foreach (['pay', 'look'] as $verb) {
                self::throwsMsg('accPost: unknown agg', static fn() => IntentHistory::accPost($bad, [], $verb, Obj::of(['total' => new Num('5')]), new Num('1')));
            }
            $keyed = $bad->without();
            $keyed->set('key', 'action.params.k'); // the key parameter is missing: the refusal still comes first
            self::throwsMsg('accPost: unknown agg', static fn() => IntentHistory::accPost($keyed, [], 'pay', Obj::of(['total' => new Num('5')]), new Num('1')));
        }
        // the four known aggs pass the gate
        foreach (['sum', 'count', 'max', 'distinct'] as $agg) {
            $ok = self::j('{"id":"s","agg":"' . $agg . '","val":"action.params.total","unit":"u","sel":{"verbs":["pay"]},"win":{"kind":"task"},"key":null,"holder":{"kind":"site_local"}}');
            $this->assertSame(0, IntentHistory::accPost($ok, [], 'look', new Obj(), new Num('1')));
        }
    }

    public function testAccPostRefusesAnAggThatOnlyStringifiesToSum(): void
    {
        // an agg that only STRINGIFIES to 'sum' is no known agg (intent-history.ts: ACC_AGGS.includes is strict)
        $agg = new class {
            public function __toString(): string
            {
                return 'sum';
            }
        };
        $a = Obj::of(['agg' => $agg, 'key' => 'action.params.k', 'sel' => Obj::of(['verbs' => ['buy']])]);
        self::throwsMsg('accPost: unknown agg', static fn() => IntentHistory::accPost($a, [], 'sell', new Obj(), new Num('1')));
    }
}
