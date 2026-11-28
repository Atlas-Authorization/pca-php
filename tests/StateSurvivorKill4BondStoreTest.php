<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/BondStore.php';

use Atlas\Pca\BondStoreDoc;
use Atlas\Pca\BondStoreError;
use Atlas\Pca\Json;
use Atlas\Pca\KvBondStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Bond settlement book: caps, replays and compare-and-swap of the pure transition, and the stored document's shape checks. */
final class StateSurvivorKill4BondStoreTest extends TestCase
{
    private static function record(string $claimId, string $action = 'open'): Obj
    {
        return Obj::of(['claimId' => $claimId, 'action' => $action, 'amount' => new Num('5')]);
    }

    /** @param array<string,mixed>|null $window */
    private static function openPlan(mixed $claimId, string $depositor, float|int $amount, float|int $maxAmount, Obj $record, ?array $window = null): array
    {
        $open = ['depositor' => $depositor, 'amount' => $amount, 'maxOpenClaims' => 10, 'maxOpenAmount' => $maxAmount];
        if ($window !== null) {
            $open['window'] = $window;
        }
        return ['claimId' => $claimId, 'expect' => 'none', 'next' => 'open', 'open' => $open, 'moves' => [], 'record' => $record];
    }

    /** @return array<string,mixed> */
    private static function openRow(string $claimId, float $amount, string $status, Obj $record): array
    {
        return ['claimId' => $claimId, 'amount' => $amount, 'depositor' => 'd', 'status' => $status, 'records' => [$record]];
    }

    /** The empty book, and the store type check. */
    public function testEmptyDocAndStoreCheck(): void
    {
        self::assertSame(['balances' => [], 'bonds' => [], 'highWater' => 0], BondStoreDoc::emptyBondDoc());
        self::assertTrue(BondStoreDoc::isBondStore(new KvBondStore(new MemoryAtomicKv())));
        self::assertFalse(BondStoreDoc::isBondStore(new \stdClass()));
    }

    /** sameSettlement compares array records member by member: a different claim is a different settlement. */
    public function testSameSettlementOverArrays(): void
    {
        $a = ['claimId' => 'c1', 'action' => 'open', 'amount' => 5];
        self::assertTrue(BondStoreDoc::sameSettlement($a, ['claimId' => 'c1', 'action' => 'open', 'amount' => 5.0]));
        self::assertFalse(BondStoreDoc::sameSettlement($a, ['claimId' => 'c2', 'action' => 'open', 'amount' => 5]));
        self::assertFalse(BondStoreDoc::sameSettlement($a, ['claimId' => 'c1', 'action' => 'slash', 'amount' => 5]));
    }

    /** planOf reads an array plan as is; an Obj plan keeps a non-Obj window and other Obj members unconverted, and unwraps numbers. */
    public function testPlanOf(): void
    {
        $moves = [['account' => 'a', 'op' => 'credit', 'amount' => 1]];
        $p = BondStoreDoc::planOf(['claimId' => 'c', 'expect' => 'none', 'next' => 'open', 'open' => null, 'moves' => $moves, 'record' => 'r']);
        self::assertSame(['claimId' => 'c', 'expect' => 'none', 'next' => 'open', 'open' => null, 'moves' => $moves, 'record' => 'r'], $p);
        self::assertSame([['junk']], BondStoreDoc::planOf(['moves' => ['junk']])['moves']);
        $o = BondStoreDoc::planOf(Json::parseLax('{"open":{"window":[1],"extra":{"a":1},"amount":2}}'))['open'];
        self::assertInstanceOf(Num::class, $o['window'][0]);
        self::assertInstanceOf(Obj::class, $o['extra']);
        self::assertSame(2, $o['amount']);
    }

    /** The aggregate open-amount cap admits a total of exactly the cap and refuses one above it (summing every open bond). */
    public function testAggregateOpenAmountCap(): void
    {
        $doc = BondStoreDoc::emptyBondDoc();
        self::assertSame('committed', BondStoreDoc::commitBondPlan($doc, self::openPlan('c1', 'd', 5, 10, self::record('c1')), 1)['outcome']);
        self::assertSame('committed', BondStoreDoc::commitBondPlan($doc, self::openPlan('c2', 'd', 5, 10, self::record('c2')), 2)['outcome']);
        $over = ['outcome' => 'conflict', 'reason' => 'depositor aggregate open-bond cap exceeded', 'current' => 'none'];
        self::assertSame($over, BondStoreDoc::commitBondPlan($doc, self::openPlan('c3', 'd', 5, 12, self::record('c3')), 3));
        self::assertArrayNotHasKey('c3', $doc['bonds']);
    }

    /** An aggregate that overflows to infinity is refused even under an infinite cap. */
    public function testAnOverflowingAggregateIsRefused(): void
    {
        $doc = BondStoreDoc::emptyBondDoc();
        $doc['bonds']['x'] = self::openRow('x', 1e308, 'open', self::record('x'));
        self::assertSame(['outcome' => 'conflict', 'reason' => 'depositor aggregate open-bond cap exceeded', 'current' => 'none'],
            BondStoreDoc::commitBondPlan($doc, self::openPlan('y', 'd', 1e308, INF, self::record('y')), 1));
    }

    /** Re-opening a bond is a replay only for the same depositor, amount, window and record; otherwise the bond already exists. */
    public function testReopenReplayNeedsTheSameBond(): void
    {
        $doc = BondStoreDoc::emptyBondDoc();
        $r = self::record('c1');
        self::assertSame('committed', BondStoreDoc::commitBondPlan($doc, self::openPlan('c1', 'd', 5, 100, $r), 1)['outcome']);
        self::assertSame(['outcome' => 'replayed', 'record' => $r], BondStoreDoc::commitBondPlan($doc, self::openPlan('c1', 'd', 5, 100, $r), 2));
        $exists = ['outcome' => 'conflict', 'reason' => 'bond c1 already exists', 'current' => 'open'];
        self::assertSame($exists, BondStoreDoc::commitBondPlan($doc, self::openPlan('c1', 'e', 5, 100, $r), 2), 'another depositor');
        self::assertSame($exists, BondStoreDoc::commitBondPlan($doc, self::openPlan('c1', 'd', 5, 100, $r, ['registeredAt' => 5]), 2), 'a window the bond lacks');
    }

    /** A bond already in another final phase is a conflict even when its last record matches the plan's. */
    public function testATransitionToAnotherPhaseIsNotAReplay(): void
    {
        $doc = BondStoreDoc::emptyBondDoc();
        $r = self::record('c1', 'release');
        $doc['bonds']['c1'] = self::openRow('c1', 5.0, 'released', $r);
        $plan = ['claimId' => 'c1', 'expect' => 'open', 'next' => 'slashed', 'open' => null, 'moves' => [], 'record' => $r];
        self::assertSame(['outcome' => 'conflict', 'reason' => 'bond c1 is already released', 'current' => 'released'], BondStoreDoc::commitBondPlan($doc, $plan, 1));
        $plan['next'] = 'released';
        self::assertSame(['outcome' => 'replayed', 'record' => $r], BondStoreDoc::commitBondPlan($doc, $plan, 1), 'control: the same transition is a replay');
    }

    /** A non-numeric observation time counts as time 0 for the high-water mark. */
    public function testANonNumericObservationTimeIsZero(): void
    {
        $doc = BondStoreDoc::emptyBondDoc();
        BondStoreDoc::commitBondPlan($doc, self::openPlan('c1', 'd', 5, 100, self::record('c1')), null);
        self::assertSame(0, $doc['highWater']);
        $doc['highWater'] = -5;
        BondStoreDoc::commitBondPlan($doc, self::openPlan('c2', 'd', 5, 100, self::record('c2')), 'later');
        self::assertSame(0, $doc['highWater']);
    }

    /** A numeric claim id and a numeric account name are stored as strings, so the book still decodes. */
    public function testNumericIdsRoundTripAsStrings(): void
    {
        $s = new KvBondStore(new MemoryAtomicKv());
        self::assertSame('committed', $s->commit(self::openPlan(7, 'd', 5, 100, self::record('7')), 1)['outcome']);
        self::assertSame('7', $s->read('7')['bond']['claimId']);
        $s->deposit('5', 10);
        self::assertSame([['5', 10.0]], $s->read('7', '5')['balances']);
    }

    private static function decodeError(string $raw): string
    {
        try {
            BondStoreDoc::decodeDoc($raw);
        } catch (BondStoreError $e) {
            return $e->getMessage();
        }
        return 'accepted';
    }

    /** Each malformed stored book is refused as store_corrupt with its exact reason. */
    public function testDecodeRefusesMalformedBooks(): void
    {
        $shape = 'store_corrupt: bond document has the wrong shape';
        self::assertSame($shape, self::decodeError('[]'));
        self::assertSame($shape, self::decodeError('{"v":2,"balances":[],"bonds":[],"highWater":0}'));
        self::assertSame($shape, self::decodeError('{"v":1,"balances":[],"bonds":[],"highWater":"0"}'));
        $row = 'store_corrupt: malformed bond row';
        self::assertSame($row, self::decodeError('{"v":1,"balances":[],"bonds":[5],"highWater":0}'));
        self::assertSame($row, self::decodeError('{"v":1,"balances":[],"bonds":[{"claimId":5,"depositor":"d","amount":1,"status":"open","records":[{}]}],"highWater":0}'));
        $ok = '{"claimId":"c","depositor":"d","amount":1,"status":"open","records":[{}]}';
        self::assertSame('accepted', self::decodeError('{"v":1,"balances":[],"bonds":[' . $ok . '],"highWater":0}'), 'control: one good row');
        self::assertSame('store_corrupt: duplicate bond row', self::decodeError('{"v":1,"balances":[],"bonds":[' . $ok . ',' . $ok . '],"highWater":0}'));
    }
}
