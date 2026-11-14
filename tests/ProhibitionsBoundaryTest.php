<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Prohibitions;
use PHPUnit\Framework\TestCase;

/** Limits and error paths of the prohibition plane, each asserted at n-1, n and n+1 against packages/pca/src/prohibitions.ts. */
final class ProhibitionsBoundaryTest extends TestCase
{
    private const NOW = 2000000;

    private static function n(int|float|string $v): Num
    {
        return new Num((string) $v);
    }

    private static function state(array $ledger = [], array $latched = [], ?array $deadlines = null, int $seq = 0, ?string $parent = null): Obj
    {
        $s = Obj::of(['now' => self::n(self::NOW), 'seq' => self::n($seq), 'parent' => $parent, 'ledger' => Obj::of($ledger), 'latched' => Obj::of($latched)]);
        if ($deadlines !== null) {
            $s->set('deadlines', Obj::of($deadlines));
        }
        return $s;
    }

    private static function entries(int $count, int $amount = 1): array
    {
        $l = [];
        for ($i = 0; $i < $count; $i++) {
            $l[] = Obj::of(['t' => self::n(1000 + $i), 'amount' => self::n($amount)]);
        }
        return $l;
    }

    private static function when(): Obj
    {
        return Obj::of(['verb' => 'pay']);
    }

    private static function constitution(array $invariants): Obj
    {
        return Obj::of(['version' => self::n(1), 'principal' => 'p', 'invariants' => $invariants]);
    }

    private static function action(int $amount = 5): Obj
    {
        return Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => '/r', 'params' => Obj::of(['amount' => self::n($amount)])])]);
    }

    private static function cap(string $id = 'c', mixed $window = null): Obj
    {
        $o = Obj::of(['id' => $id, 'kind' => 'cap', 'when' => self::when(), 'amount' => 'action.params.amount', 'max' => self::n(100000000)]);
        if ($window !== null) {
            $o->set('window_secs', $window);
        }
        return $o;
    }

    public function testSignConstitutionJoinsEveryProblem(): void
    {
        $bad = Obj::of(['version' => self::n(2), 'principal' => '', 'invariants' => []]);
        try {
            Prohibitions::signConstitution($bad, KeyPair::generate());
            $this->fail('a malformed constitution is not signed');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('signConstitution: unsupported version 2; principal missing', $e->getMessage());
        }
    }

    public function testVerifyConstitutionReportsTheFirstProblemAndAPinOfAnyKind(): void
    {
        $r = Prohibitions::verifyConstitution(Obj::of(['version' => self::n(2), 'principal' => '', 'invariants' => []]));
        $this->assertSame(['ok' => false, 'reason' => 'unsupported version 2'], $r);
        $kp = KeyPair::generate();
        $sc = Prohibitions::signConstitution(Obj::of(['version' => self::n(1), 'principal' => $kp->public, 'invariants' => []]), $kp);
        $this->assertSame(['ok' => true], Prohibitions::verifyConstitution($sc));
        foreach ([null, 5, true, ['x'], ''] as $pin) {
            $this->assertSame(['ok' => false, 'reason' => 'principal mismatch'], Prohibitions::verifyConstitution($sc, $pin));
        }
        $this->assertSame(['ok' => true], Prohibitions::verifyConstitution($sc, $kp->public));
    }

    public function testInvariantAndConstitutionLimits(): void
    {
        $never = static fn(string $id): Obj => Obj::of(['id' => $id, 'kind' => 'never', 'when' => self::when()]);
        $this->assertSame([], Prohibitions::validateInvariant($never(str_repeat('a', 128))));
        $this->assertSame([str_repeat('a', 129) . ': id too long'], Prohibitions::validateInvariant($never(str_repeat('a', 129))));
        // 128 UTF-16 units made of 64 astral characters pass, 65 do not
        $this->assertSame([], Prohibitions::validateInvariant($never(str_repeat("\u{1F600}", 64))));
        $this->assertSame(1, count(Prohibitions::validateInvariant($never(str_repeat("\u{1F600}", 65)))));
        $many = static fn(int $c): Obj => self::constitution(array_map(static fn(int $i): Obj => $never("i$i"), range(1, $c)));
        $this->assertSame([], Prohibitions::validateConstitution($many(256)));
        $this->assertSame(['too many invariants'], Prohibitions::validateConstitution($many(257)));
        $dup = self::constitution([$never('a'), $never('a')]);
        $this->assertSame(['a: duplicate id'], Prohibitions::validateConstitution($dup));
        $this->assertSame(['invariants not an array'], Prohibitions::validateConstitution(Obj::of(['version' => self::n(1), 'principal' => 'p', 'invariants' => Obj::of([])])));
        $this->assertSame(['unsupported version 2', 'principal missing', 'invariants not an array'],
            Prohibitions::validateConstitution(Obj::of(['version' => self::n(2), 'principal' => 5])));
    }

    public function testNumericInvariantFieldBounds(): void
    {
        $rate = static fn(mixed $max, mixed $w): Obj => Obj::of(['id' => 'r', 'kind' => 'rate', 'when' => self::when(), 'max' => $max, 'window_secs' => $w]);
        $this->assertSame([], Prohibitions::validateInvariant($rate(self::n(0), self::n(1))));
        $this->assertSame([], Prohibitions::validateInvariant($rate(self::n(10000), self::n('0.5'))));
        foreach ([self::n(10001), self::n(-1), self::n('1.5'), self::n('-0'), '5', true] as $m) {
            $this->assertSame(['r: max must be an integer in [0,10000]'], Prohibitions::validateInvariant($rate($m, self::n(1))));
        }
        foreach ([self::n(0), self::n(-1), '1', null, true] as $w) {
            $this->assertSame(['r: window_secs must be > 0'], Prohibitions::validateInvariant($rate(self::n(1), $w)));
        }
        $cap = static fn(mixed $max, ?array $extra = null): Obj => Obj::of(['id' => 'c', 'kind' => 'cap', 'when' => self::when(), 'amount' => 'action.x', 'max' => $max] + ($extra ?? []));
        $this->assertSame([], Prohibitions::validateInvariant($cap(self::n(0))));
        $this->assertSame(['c: max must be a finite number >= 0'], Prohibitions::validateInvariant($cap(self::n(-1))));
        $this->assertSame(['c: max must be a finite number >= 0'], Prohibitions::validateInvariant($cap('1')));
        $this->assertSame([], Prohibitions::validateInvariant($cap(self::n(1), ['window_secs' => self::n('0.001')])));
        foreach ([self::n(0), self::n(-1), null, '1'] as $w) {
            $this->assertSame(['c: bad window_secs'], Prohibitions::validateInvariant($cap(self::n(1), ['window_secs' => $w])));
        }
        $this->assertSame(['c: amount must be an action.* path'], Prohibitions::validateInvariant(Obj::of(['id' => 'c', 'kind' => 'cap', 'when' => self::when(), 'amount' => 'actio.x', 'max' => self::n(1)])));
        $appr = static fn(mixed $thr, mixed $cs): Obj => Obj::of(['id' => 'a', 'kind' => 'require_approval_over', 'when' => self::when(), 'amount' => 'action.x', 'threshold' => $thr, 'approved' => $cs]);
        $cond = [Obj::of(['field' => 'action.verb', 'op' => 'eq', 'value' => 'x'])];
        $this->assertSame([], Prohibitions::validateInvariant($appr(self::n(0), $cond)));
        $this->assertSame(['a: threshold must be a finite number >= 0'], Prohibitions::validateInvariant($appr(self::n(-1), $cond)));
        $this->assertSame(['a: approved must be a non-empty array'], Prohibitions::validateInvariant($appr(self::n(1), [])));
        $this->assertSame(['a: approved must be a non-empty array'], Prohibitions::validateInvariant($appr(self::n(1), Obj::of([]))));
        $nu = Obj::of(['id' => 'u', 'kind' => 'never_unless', 'when' => self::when(), 'unless' => []]);
        $this->assertSame(['u: unless must be a non-empty array'], Prohibitions::validateInvariant($nu));
        $this->assertSame(['u: unknown invariant kind undefined'], Prohibitions::validateInvariant(Obj::of(['id' => 'u'])));
        $this->assertSame(['u: unknown invariant kind null'], Prohibitions::validateInvariant(Obj::of(['id' => 'u', 'kind' => null])));
        $this->assertSame(['unsupported version undefined', 'principal missing', 'invariants not an array'], Prohibitions::validateConstitution(new Obj()));
    }

    public function testStateLimits(): void
    {
        $shared = self::entries(10000);
        $ten = [];
        for ($i = 0; $i < 10; $i++) {
            $ten["k$i"] = $shared;
        }
        $this->assertNull(Prohibitions::stateProblem(self::state($ten)));
        $this->assertSame('malformed monitor state: too many entries', Prohibitions::stateProblem(self::state($ten + ['extra' => self::entries(1)])));
        $this->assertSame('malformed monitor state: bad ledger', Prohibitions::stateProblem(self::state(['k' => self::entries(10001)])));
        $this->assertSame('malformed monitor state: bad ledger', Prohibitions::stateProblem(self::state(['k' => Obj::of([])])));

        $keys = static fn(int $c, mixed $v): array => array_combine(array_map(static fn(int $i): string => "k$i", range(1, $c)), array_fill(0, $c, $v));
        $this->assertNull(Prohibitions::stateProblem(self::state($keys(1024, []))));
        $this->assertSame('malformed monitor state: too many keys', Prohibitions::stateProblem(self::state($keys(1025, []))));
        $this->assertNull(Prohibitions::stateProblem(self::state([], $keys(1024, self::n(5)))));
        $this->assertSame('malformed monitor state: too many keys', Prohibitions::stateProblem(self::state([], $keys(1025, self::n(5)))));
        $this->assertNull(Prohibitions::stateProblem(self::state([], [], $keys(1024, self::n(1)))));
        $this->assertSame('malformed monitor state: too many deadline keys', Prohibitions::stateProblem(self::state([], [], $keys(1025, self::n(1)))));

        $k128 = str_repeat('k', 128);
        $k129 = str_repeat('k', 129);
        $this->assertNull(Prohibitions::stateProblem(self::state([$k128 => []])));
        $this->assertSame('malformed monitor state: bad ledger key', Prohibitions::stateProblem(self::state([$k129 => []])));
        $this->assertSame('malformed monitor state: bad ledger key', Prohibitions::stateProblem(self::state(['constructor' => []])));
        $this->assertNull(Prohibitions::stateProblem(self::state([], [$k128 => self::n(5)])));
        $this->assertSame('malformed monitor state: bad latch key', Prohibitions::stateProblem(self::state([], [$k129 => self::n(5)])));
        $this->assertSame('malformed monitor state: bad latch key', Prohibitions::stateProblem(self::state([], ['__proto__' => self::n(5)])));
        $this->assertNull(Prohibitions::stateProblem(self::state([], [], [$k128 => self::n(1)])));
        $this->assertSame('malformed monitor state: bad deadline key', Prohibitions::stateProblem(self::state([], [], [$k129 => self::n(1)])));
        $this->assertSame('malformed monitor state: bad deadline key', Prohibitions::stateProblem(self::state([], [], ['prototype' => self::n(1)])));

        $this->assertNull(Prohibitions::stateProblem(self::state([], [], ['d' => self::n(1000000)])));
        foreach ([self::n(1000001), self::n(0), self::n('1.5'), '5', null] as $d) {
            $this->assertSame('malformed monitor state: bad deadline', Prohibitions::stateProblem(self::state([], [], ['d' => $d])));
        }
        $this->assertSame('malformed monitor state: deadlines', Prohibitions::stateProblem(self::withDeadlines(null)));
        $this->assertSame('malformed monitor state: deadlines', Prohibitions::stateProblem(self::withDeadlines('x')));

        $this->assertSame('malformed monitor state: bad latch', Prohibitions::stateProblem(self::state([], ['x' => self::n(self::NOW + 1)])));
        $this->assertNull(Prohibitions::stateProblem(self::state([], ['x' => self::n(self::NOW)])));
        $this->assertSame('malformed monitor state: bad latch', Prohibitions::stateProblem(self::state([], ['x' => '5'])));
        $this->assertSame('malformed monitor state: bad ledger entry', Prohibitions::stateProblem(self::state(['k' => [Obj::of(['t' => self::n(1), 'amount' => self::n(-1)])]])));
        $this->assertNull(Prohibitions::stateProblem(self::state(['k' => [Obj::of(['t' => self::n(1), 'amount' => self::n(0)])]])));
        $this->assertSame('malformed monitor state: bad ledger entry', Prohibitions::stateProblem(self::state(['k' => [5]])));
        $this->assertSame('malformed monitor state: bad ledger entry', Prohibitions::stateProblem(self::state(['k' => [Obj::of(['t' => '1', 'amount' => self::n(1)])]])));
        $this->assertSame('malformed monitor state: bad ledger entry', Prohibitions::stateProblem(self::state(['k' => [Obj::of(['t' => self::n(1), 'amount' => null])]])));
        $this->assertSame('malformed monitor state: ledger entry after now (clock regression)', Prohibitions::stateProblem(self::state(['k' => [Obj::of(['t' => self::n(self::NOW + 1), 'amount' => self::n(1)])]])));
        $this->assertNull(Prohibitions::stateProblem(self::state(['k' => [Obj::of(['t' => self::n(self::NOW), 'amount' => self::n(1)])]])));
        $this->assertSame('malformed monitor state: parent', Prohibitions::stateProblem(self::withParent(5, 0)));
        $this->assertSame('malformed monitor state: genesis has a parent', Prohibitions::stateProblem(self::state([], [], null, 0, 'p')));
        $this->assertSame('malformed monitor state: missing chain link', Prohibitions::stateProblem(self::state([], [], null, 1, null)));
        $this->assertNull(Prohibitions::stateProblem(self::state([], [], null, 1, 'p')));
        foreach ([self::n(-1), self::n('-0'), self::n('1.5'), '1', null] as $seq) {
            $s = self::state();
            $s->set('seq', $seq);
            $this->assertSame('malformed monitor state: seq', Prohibitions::stateProblem($s));
        }
        $this->assertSame('malformed monitor state', Prohibitions::stateProblem(self::state()->without('latched')));
        $this->assertSame('malformed monitor state', Prohibitions::stateProblem(self::state()->without('ledger')));
        $this->assertSame('malformed monitor state', Prohibitions::stateProblem(self::state()->without('now')));
    }

    private static function withDeadlines(mixed $d): Obj
    {
        $s = self::state();
        $s->set('deadlines', $d);
        return $s;
    }

    private static function withParent(mixed $p, int $seq): Obj
    {
        $s = self::state([], [], null, $seq);
        $s->set('parent', $p);
        return $s;
    }

    public function testCanonicalStateSortsDropsAndRefusesMalformed(): void
    {
        $st = self::state(['b' => [Obj::of(['t' => self::n(5), 'amount' => self::n(2)]), Obj::of(['t' => self::n(5), 'amount' => self::n(1)]), Obj::of(['t' => self::n(3), 'amount' => self::n(9), 'junk' => 1])], 'e' => []],
            ['z' => self::n(7)], ['d' => self::n(4)]);
        $c = Prohibitions::canonicalState($st);
        $this->assertSame('{"d":"atlas-pca/monitor-state/v1","deadlines":{"d":4},"latched":{"z":7},"ledger":{"b":[{"amount":9,"t":3},{"amount":1,"t":5},{"amount":2,"t":5}]},"now":2000000,"parent":null,"seq":0}',
            \Atlas\Pca\Json::canonicalizeStrict($c));
        $this->assertFalse(Prohibitions::canonicalState(self::state([], [], []))->has('deadlines'));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('malformed monitor state: seq');
        $bad = self::state();
        $bad->set('seq', self::n(-1));
        Prohibitions::canonicalState($bad);
    }

    public function testTickState(): void
    {
        $st = self::state();
        $this->assertSame(['ok' => false, 'reason' => 'malformed monitor state'], Prohibitions::tickState(null, self::n(5)));
        $this->assertSame(['ok' => false, 'reason' => 'clock regression'], Prohibitions::tickState($st, self::n(self::NOW - 1)));
        $this->assertSame(['ok' => false, 'reason' => 'clock regression'], Prohibitions::tickState($st, '5000000'));
        $this->assertSame(['ok' => false, 'reason' => 'clock regression'], Prohibitions::tickState($st, null));
        $r = Prohibitions::tickState($st, self::n(self::NOW));
        $this->assertTrue($r['ok']);
        $this->assertSame(2000000.0, Prohibitions::fin($r['state']->get('now')));
        $r = Prohibitions::tickState($st, self::n(self::NOW + 7));
        $this->assertSame(2000007.0, Prohibitions::fin($r['state']->get('now')));
        $this->assertSame($st->get('latched'), $r['state']->get('latched'));
    }

    public function testRateLedgerOverflowIsRefusedAndACapLedgerMergesTheOldestTwo(): void
    {
        $rate = Obj::of(['id' => 'r', 'kind' => 'rate', 'when' => self::when(), 'max' => self::n(10000), 'window_secs' => self::n(100000)]);
        $c = self::constitution([$rate]);
        $this->assertSame(['ok' => false, 'reason' => 'r: rate ledger overflow'], Prohibitions::advanceStrict(self::action(), $c, self::state(['r' => self::entries(10000)])));
        $ok = Prohibitions::advanceStrict(self::action(), $c, self::state(['r' => self::entries(9999)]));
        $this->assertTrue($ok['ok']);
        $this->assertCount(10000, $ok['state']->get('ledger')->get('r'));

        $cap = self::constitution([self::cap()]);
        $r = Prohibitions::advanceStrict(self::action(5), $cap, self::state(['c' => self::entries(10000)]));
        $this->assertTrue($r['ok']);
        $l = $r['state']->get('ledger')->get('c');
        $this->assertCount(10000, $l);
        $this->assertSame([1001.0, 2.0], [Prohibitions::fin($l[0]->get('t')), Prohibitions::fin($l[0]->get('amount'))]);
        $this->assertSame([1002.0, 1.0], [Prohibitions::fin($l[1]->get('t')), Prohibitions::fin($l[1]->get('amount'))]);
        $this->assertSame([(float) self::NOW, 5.0], [Prohibitions::fin($l[9999]->get('t')), Prohibitions::fin($l[9999]->get('amount'))]);
        $under = Prohibitions::advanceStrict(self::action(5), $cap, self::state(['c' => self::entries(9999)]));
        $this->assertCount(10000, $under['state']->get('ledger')->get('c'));
        $this->assertSame(1000.0, Prohibitions::fin($under['state']->get('ledger')->get('c')[0]->get('t')));
    }

    public function testAdvanceWindowPrunesAtTheEdgeAndSortsByTimeThenAmount(): void
    {
        $c = self::constitution([self::cap('c', self::n(10))]);
        // window 10s => entries at t <= now - 10000 are pruned, t = now - 9999 stays
        $st = self::state(['c' => [
            Obj::of(['t' => self::n(self::NOW - 10000), 'amount' => self::n(3)]),
            Obj::of(['t' => self::n(self::NOW - 9999), 'amount' => self::n(4)]),
        ]]);
        $r = Prohibitions::advanceStrict(self::action(5), $c, $st);
        $l = $r['state']->get('ledger')->get('c');
        $this->assertSame([[self::NOW - 9999.0, 4.0], [(float) self::NOW, 5.0]], array_map(static fn(Obj $e): array => [Prohibitions::fin($e->get('t')), Prohibitions::fin($e->get('amount'))], $l));
        $this->assertSame(1.0, Prohibitions::fin($r['state']->get('seq')));
        $this->assertNull(Prohibitions::stateProblem($r['state']));
        // a later explicit now moves the clock; an earlier one, an absent-clock null and a non-number are refused
        $later = Prohibitions::advanceStrict(self::action(5), $c, $st, self::n(self::NOW + 5));
        $this->assertSame(2000005.0, Prohibitions::fin($later['state']->get('now')));
        foreach ([self::n(self::NOW - 1), null, 'x', true] as $bad) {
            $this->assertSame(['ok' => false, 'reason' => 'clock regression'], Prohibitions::advanceStrict(self::action(5), $c, $st, $bad));
        }
        $this->assertSame(['ok' => false, 'reason' => 'malformed action'], Prohibitions::advanceStrict(Obj::of(['action' => Obj::of(['verb' => 'pay'])]), $c, $st));
        $this->assertSame(['ok' => false, 'reason' => 'malformed monitor state'], Prohibitions::advanceStrict(self::action(), $c, null));
        $this->assertSame(['ok' => false, 'reason' => 'unsupported version undefined'], Prohibitions::advanceStrict(self::action(), new Obj(), $st));
        $this->assertSame(['ok' => false, 'reason' => 'c: amount unresolvable'], Prohibitions::advanceStrict(Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => '/r'])]), $c, $st));
        $this->assertSame(['ok' => false, 'reason' => 'c: amount unresolvable'], Prohibitions::advanceStrict(self::action(-1), $c, $st));
        // advance returns the input state on every refusal
        $this->assertSame($st, Prohibitions::advance(self::action(-1), $c, $st));
        $this->assertSame(1.0, Prohibitions::fin(Prohibitions::advance(self::action(5), $c, $st)->get('seq')));
    }

    public function testCapAndRateReasonsAndWindowEdges(): void
    {
        $capC = self::constitution([Obj::of(['id' => 'c', 'kind' => 'cap', 'when' => self::when(), 'amount' => 'action.params.amount', 'max' => self::n(10), 'window_secs' => self::n(10)])]);
        $st = self::state(['c' => [Obj::of(['t' => self::n(self::NOW - 10000), 'amount' => self::n(100)]), Obj::of(['t' => self::n(self::NOW - 9999), 'amount' => self::n(4)])]]);
        $this->assertTrue(Prohibitions::check(self::action(6), $capC, $st)['ok']);
        $r = Prohibitions::check(self::action(7), $capC, $st);
        $this->assertSame(['c: cap exceeded: 4 + 7 > 10'], $r['reasons']);
        $this->assertSame(['c'], $r['violated']);
        $this->assertSame('violated', $r['evaluated'][0]->get('result'));
        $this->assertSame('cap exceeded: 4 + 7 > 10', $r['evaluated'][0]->get('reason'));
        $this->assertSame('amount unresolvable (fail closed)', Prohibitions::check(self::action(-1), $capC, $st)['evaluated'][0]->get('reason'));

        $rateC = self::constitution([Obj::of(['id' => 'r', 'kind' => 'rate', 'when' => self::when(), 'max' => self::n(2), 'window_secs' => self::n(10)])]);
        $two = self::state(['r' => [Obj::of(['t' => self::n(self::NOW - 10000), 'amount' => self::n(1)]), Obj::of(['t' => self::n(self::NOW - 1), 'amount' => self::n(1)])]]);
        $this->assertTrue(Prohibitions::check(self::action(), $rateC, $two)['ok']);
        $three = self::state(['r' => [Obj::of(['t' => self::n(self::NOW - 9999), 'amount' => self::n(1)]), Obj::of(['t' => self::n(self::NOW), 'amount' => self::n(1)])]]);
        $this->assertSame(['r: rate exceeded: 3 > 2 per 10s'], Prohibitions::check(self::action(), $rateC, $three)['reasons']);
    }

    public function testApprovalOverThresholdAndLatches(): void
    {
        $cond = [Obj::of(['field' => 'action.params.approved', 'op' => 'eq', 'value' => true])];
        $c = self::constitution([Obj::of(['id' => 'a', 'kind' => 'require_approval_over', 'when' => self::when(), 'amount' => 'action.params.amount', 'threshold' => self::n(10), 'approved' => $cond])]);
        $st = self::state();
        $this->assertTrue(Prohibitions::check(self::action(10), $c, $st)['ok']);
        $r = Prohibitions::check(self::action(11), $c, $st);
        $this->assertSame(['a: approval required over 10'], $r['reasons']);
        $this->assertFalse(Prohibitions::check(self::action(-1), $c, $st)['ok']);
        $this->assertFalse(Prohibitions::check(Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => '/r'])]), $c, $st)['ok']);

        $nu = self::constitution([Obj::of(['id' => 'n', 'kind' => 'never_after', 'after' => Obj::of(['verb' => 'pay']), 'forbid' => Obj::of(['verb' => 'pay'])]),
            Obj::of(['id' => 'q', 'kind' => 'require_prior', 'when' => Obj::of(['verb' => 'pay']), 'prior' => Obj::of(['verb' => 'pay'])])]);
        $a = Prohibitions::advanceStrict(self::action(), $nu, $st);
        $this->assertSame(['n', 'q'], $a['state']->get('latched')->keys());
        // the earliest latch is kept
        $b = Prohibitions::advanceStrict(self::action(), $nu, $a['state'], self::n(self::NOW + 9));
        $this->assertSame(2000000.0, Prohibitions::fin($b['state']->get('latched')->get('n')));
        $this->assertSame(2000009.0, Prohibitions::fin($b['state']->get('now')));
        // an unlatched require_prior refuses; a latched never_after refuses
        $this->assertSame(['q: required prior action not admitted'], Prohibitions::check(self::action(), self::constitution([Obj::of(['id' => 'q', 'kind' => 'require_prior', 'when' => self::when(), 'prior' => self::when()])]), $st)['reasons']);
        $this->assertSame(['n: forbidden after trigger'], Prohibitions::check(self::action(), $nu, $a['state'])['reasons']);
    }

    public function testEvidenceAndCompositionSurface(): void
    {
        $kp = KeyPair::generate();
        $c = self::constitution([Obj::of(['id' => 'n', 'kind' => 'never', 'when' => Obj::of(['verb' => 'wire']), 'description' => 'no wires'])]);
        $st = self::state();
        $act = self::action();
        $r = Prohibitions::check($act, $c, $st);
        $ev = Prohibitions::evidenceFrom($r, $act, $c, $st);
        $this->assertSame(Prohibitions::evidenceDigest($ev), \Atlas\Pca\Pca::hashCanonical($ev));
        $this->assertSame(['allow' => true, 'decidedBy' => 'none', 'permitted' => true, 'prohibition' => $r], Prohibitions::composeFrom(true, $r));
        $this->assertSame('permission', Prohibitions::composeFrom(false, $r)['decidedBy']);
        $this->assertFalse(Prohibitions::composeFrom('yes', $r)['permitted']);
        $deny = Prohibitions::composeAuthority(true, Obj::of(['action' => Obj::of(['verb' => 'wire', 'resource' => '/r'])]), $c, $st);
        $this->assertSame(['allow' => false, 'decidedBy' => 'prohibition', 'permitted' => true], ['allow' => $deny['allow'], 'decidedBy' => $deny['decidedBy'], 'permitted' => $deny['permitted']]);
        $this->assertSame('prohibition', Prohibitions::composeFrom(false, $deny['prohibition'])['decidedBy']);

        // an undigestable constitution / action / state is named in `violated`, once, after the structural row
        $bad = Prohibitions::evidenceFrom(['ok' => true, 'violated' => ['<action>'], 'reasons' => [], 'evaluated' => []], Obj::of(['x' => self::n('-0')]), $c, null);
        $this->assertFalse($bad->get('ok'));
        $this->assertSame(0.0, Prohibitions::fin($bad->get('now')));
        $this->assertSame('<unhashable>', $bad->get('action_digest'));
        $this->assertSame('<unhashable>', $bad->get('state_digest'));
        $this->assertSame(['<action>', '<state>'], $bad->get('violated'));

        $signed = Prohibitions::signSafetyEvidence($ev, $kp);
        $exp = ['signer' => $kp->public, 'action' => $act, 'constitution' => $c, 'state' => $st];
        $this->assertSame(['ok' => true], Prohibitions::verifySignedSafetyEvidence($signed, $exp));
        $this->assertSame(['ok' => false, 'reason' => 'malformed input'], Prohibitions::verifySignedSafetyEvidence($signed, 5));
        $this->assertSame(['ok' => false, 'reason' => 'malformed input'], Prohibitions::verifySignedSafetyEvidence($signed, ['x']));
        $this->assertSame(['ok' => false, 'reason' => 'no pinned signer'], Prohibitions::verifySignedSafetyEvidence($signed, []));
        $this->assertSame(['ok' => false, 'reason' => 'malformed input'], Prohibitions::verifySignedSafetyEvidence(Obj::of(['evidence' => 5]), $exp));
        $this->assertSame(['ok' => false, 'reason' => 'malformed input'], Prohibitions::verifySignedSafetyEvidence(Obj::of([]), $exp));
        $this->assertSame(['ok' => false, 'reason' => 'no pinned signer'], Prohibitions::verifySignedSafetyEvidence($signed, ['signer' => ''] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'no pinned signer'], Prohibitions::verifySignedSafetyEvidence($signed, ['signer' => []] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'no pinned signer'], Prohibitions::verifySignedSafetyEvidence($signed, ['signer' => [$kp->public, 5]] + $exp));
        $this->assertSame(['ok' => true], Prohibitions::verifySignedSafetyEvidence($signed, ['signer' => ['x', $kp->public]] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'signer not trusted'], Prohibitions::verifySignedSafetyEvidence($signed, ['signer' => ['x']] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'unbound: action not specified'], Prohibitions::verifySignedSafetyEvidence($signed, array_diff_key($exp, ['action' => 1])));
        $this->assertSame(['ok' => false, 'reason' => 'unbound: constitution not specified'], Prohibitions::verifySignedSafetyEvidence($signed, array_diff_key($exp, ['constitution' => 1])));
        $this->assertSame(['ok' => false, 'reason' => 'unbound: state not specified'], Prohibitions::verifySignedSafetyEvidence($signed, array_diff_key($exp, ['state' => 1])));
        // digests alone bind as well; a disagreeing digest beside the object is refused
        $dg = ['signer' => $kp->public, 'actionDigest' => $ev->get('action_digest'), 'constitutionId' => $ev->get('constitution'), 'stateDigest' => $ev->get('state_digest')];
        $this->assertSame(['ok' => true], Prohibitions::verifySignedSafetyEvidence($signed, $dg));
        $this->assertSame(['ok' => false, 'reason' => 'expected action and digest disagree'], Prohibitions::verifySignedSafetyEvidence($signed, ['actionDigest' => 'x'] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'expected constitution and id disagree'], Prohibitions::verifySignedSafetyEvidence($signed, ['constitutionId' => 'x'] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'expected state and digest disagree'], Prohibitions::verifySignedSafetyEvidence($signed, ['stateDigest' => null] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'principal pin requires a signed constitution'], Prohibitions::verifySignedSafetyEvidence($signed, ['principal' => $kp->public] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'principal pin requires a signed constitution'], Prohibitions::verifySignedSafetyEvidence($signed, ['principal' => null] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'constitution mismatch (evidence bound to another constitution)'], Prohibitions::verifySignedSafetyEvidence($signed, ['constitutionId' => 'x'] + array_diff_key($exp, ['constitution' => 1])));
        $this->assertSame(['ok' => false, 'reason' => 'state digest mismatch (evidence bound to another state)'], Prohibitions::verifySignedSafetyEvidence($signed, ['stateDigest' => 'x'] + array_diff_key($exp, ['state' => 1])));
        $this->assertSame(['ok' => false, 'reason' => 'action digest mismatch (evidence bound to another action)'], Prohibitions::verifySignedSafetyEvidence($signed, ['actionDigest' => 'x'] + array_diff_key($exp, ['action' => 1])));

        // a signature by another key under the right id, a tampered id, and a non-string id / sig
        $this->assertSame(['ok' => false, 'reason' => 'binding id mismatch'], Prohibitions::verifySignedSafetyEvidence(self::with($signed, 'id', 'x'), $exp));
        $this->assertSame(['ok' => false, 'reason' => 'binding id mismatch'], Prohibitions::verifySignedSafetyEvidence(self::with($signed, 'id', 5), $exp));
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], Prohibitions::verifySignedSafetyEvidence(self::with($signed, 'sig', 5), $exp));
        $this->assertSame(['ok' => false, 'reason' => 'bad signature'], Prohibitions::verifySignedSafetyEvidence(self::with($signed, 'sig', \Atlas\Pca\Pca::b64u(str_repeat("\1", 64))), $exp));
        $this->assertSame(['ok' => false, 'reason' => 'unsupported evidence version'], Prohibitions::verifySignedSafetyEvidence(self::with($signed, 'evidence', self::with($ev, 'v', true)), $exp));

        // signing refuses unsupported / unbound evidence with the reference's messages
        foreach ([[self::with($ev, 'v', self::n(2)), 'signSafetyEvidence: unsupported evidence'], [null, 'signSafetyEvidence: unsupported evidence'], [self::with($ev, 'v', '1'), 'signSafetyEvidence: unsupported evidence'],
            [self::with($ev, 'constitution', ''), 'signSafetyEvidence: unbound evidence'], [self::with($ev, 'action_digest', '<unhashable>'), 'signSafetyEvidence: unbound evidence'],
            [self::with($ev, 'state_digest', 5), 'signSafetyEvidence: unbound evidence']] as [$e, $msg]) {
            try {
                Prohibitions::signSafetyEvidence($e, $kp);
                $this->fail("signing must refuse: $msg");
            } catch (\InvalidArgumentException $x) {
                $this->assertSame($msg, $x->getMessage());
            }
        }
        // binding id: a missing bound member is refused, an explicit null is hashed
        foreach (['constitution', 'action_digest', 'state_digest'] as $k) {
            try {
                Prohibitions::safetyBindingId($ev->without($k), $kp->public);
                $this->fail("a missing $k is refused");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
            $this->assertIsString(Prohibitions::safetyBindingId(self::with($ev, $k, null), $kp->public));
        }
        $this->assertSame(['ok' => false, 'reason' => 'verification error (fail closed)'], Prohibitions::verifySignedSafetyEvidence(self::with($signed, 'evidence', $ev->without('state_digest')), $exp));
    }

    private static function with(mixed $o, string $k, mixed $v): mixed
    {
        if (!($o instanceof Obj)) {
            return $o;
        }
        $c = new Obj();
        foreach ($o->keys() as $key) {
            $c->set($key, $o->get($key));
        }
        $c->set($k, $v);
        return $c;
    }

    public function testCheckAndAdvanceGuardsTheHeadStrictly(): void
    {
        $c = self::constitution([self::cap()]);
        $st = self::state([], [], null, 1, 'p');
        $act = self::action();
        foreach ([[self::n(2)], [self::n('1.5')], [true], ['1'], [null], [[1]], [Obj::of([])]] as [$seq]) {
            $r = Prohibitions::checkAndAdvance(true, $act, $c, $st, ['expectedSeq' => $seq]);
            $this->assertFalse($r['allow'], 'expectedSeq ' . var_export($seq, true));
            $this->assertSame(['state', 'stale state head (seq)'], [$r['decidedBy'], $r['reason']]);
            $this->assertSame($st, $r['next']);
        }
        $ok = Prohibitions::checkAndAdvance(true, $act, $c, $st, ['expectedSeq' => self::n(1)]);
        $this->assertTrue($ok['allow']);
        $this->assertSame(2.0, Prohibitions::fin($ok['next']->get('seq')));
        $this->assertFalse(Prohibitions::checkAndAdvance(true, $act, $c, null, ['expectedSeq' => self::n(1)])['allow']);
        foreach ([null, 5, 'x'] as $dg) {
            $r = Prohibitions::checkAndAdvance(true, $act, $c, $st, ['expectedStateDigest' => $dg]);
            $this->assertSame('stale state head (digest)', $r['reason']);
        }
        $this->assertTrue(Prohibitions::checkAndAdvance(true, $act, $c, $st, ['expectedStateDigest' => Prohibitions::stateDigest($st)])['allow']);
        // not permitted: the permission layer decided; a violation: the prohibition did; neither is given a reason
        $np = Prohibitions::checkAndAdvance(false, $act, $c, $st);
        $this->assertSame('permission', $np['decidedBy']);
        $this->assertArrayNotHasKey('reason', $np);
        $this->assertSame($st, $np['next']);
        $veto = Prohibitions::checkAndAdvance(true, self::action(200000000), $c, $st);
        $this->assertSame('prohibition', $veto['decidedBy']);
        $this->assertArrayNotHasKey('reason', $veto);
        $malformed = Prohibitions::checkAndAdvance(true, $act, $c, 5);
        $this->assertFalse($malformed['allow']);
        $this->assertSame('prohibition', $malformed['decidedBy']);
    }

    public function testVerifySafetyEvidenceReasons(): void
    {
        $c = self::constitution([Obj::of(['id' => 'n', 'kind' => 'never', 'when' => Obj::of(['verb' => 'wire'])])]);
        $st = self::state();
        $act = self::action();
        $ev = Prohibitions::proveSafety($act, $c, $st);
        $this->assertSame(['ok' => true], Prohibitions::verifySafetyEvidence($ev, $act, $c, $st));
        foreach ([null, 5, Obj::of([]), self::with($ev, 'v', true), self::with($ev, 'v', '1')] as $bad) {
            $this->assertSame(['ok' => false, 'reason' => 'unsupported evidence version'], Prohibitions::verifySafetyEvidence($bad, $act, $c, $st));
        }
        $this->assertSame('constitution mismatch', Prohibitions::verifySafetyEvidence(self::with($ev, 'constitution', 'x'), $act, $c, $st)['reason']);
        $this->assertSame('action digest mismatch', Prohibitions::verifySafetyEvidence(self::with($ev, 'action_digest', 'x'), $act, $c, $st)['reason']);
        $this->assertSame('state digest mismatch', Prohibitions::verifySafetyEvidence(self::with($ev, 'state_digest', 'x'), $act, $c, $st)['reason']);
        $this->assertSame('evidence does not reproduce', Prohibitions::verifySafetyEvidence(self::with($ev, 'now', self::n(1)), $act, $c, $st)['reason']);
        $wire = Obj::of(['action' => Obj::of(['verb' => 'wire', 'resource' => '/r'])]);
        $evw = Prohibitions::proveSafety($wire, $c, $st);
        $this->assertSame(['ok' => false, 'reason' => 'prohibition violated: n'], Prohibitions::verifySafetyEvidence($evw, $wire, $c, $st));
        $this->assertSame(['ok' => false, 'reason' => 'verification error (fail closed)'], Prohibitions::verifySafetyEvidence(self::with($ev, 'now', self::n('-0')), $act, $c, $st));
    }
}
