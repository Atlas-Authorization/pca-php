<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/KvStateStore.php';
require_once __DIR__ . '/../src/UndoStore.php';
require_once __DIR__ . '/../src/IntentSessionStore.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\BudgetStateStore;
use Atlas\Pca\ClaimResult;
use Atlas\Pca\Json;
use Atlas\Pca\KvStateStore;
use Atlas\Pca\KvUndoStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryIntentSessionStore;
use Atlas\Pca\MemoryUndoStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PcaStateStores;
use Atlas\Pca\PinStateStore;
use Atlas\Pca\SessionTx;
use Atlas\Pca\StateStore;
use Atlas\Pca\UndoError;
use Atlas\Pca\UndoStore;
use PHPUnit\Framework\TestCase;

/** The durable replay / budget / pin / consume-once store, the undo ledger stores and the intent session store: exact state transitions. */
final class StateSurvivorKill4KvStoresTest extends TestCase
{
    private static function put(AtomicKv $kv, string $key, string $raw): void
    {
        $kv->update($key, static fn(?string $prev): string => $raw);
    }

    /** Runs $f with every PHP warning or notice turned into an exception, so a code path that only warns is caught. */
    private static function noWarnings(\Closure $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    // ---- KvStateStore ------------------------------------------------------------------------------------------------------

    /** A scope other than 'process' or 'shared' is refused at construction. */
    public function testAnUnknownScopeIsRefused(): void
    {
        try {
            new KvStateStore(new MemoryAtomicKv(), 'p:', 'global');
            self::fail('an unknown scope was accepted');
        } catch (\InvalidArgumentException $e) {
            self::assertSame("KvStateStore: scope is 'process' or 'shared'", $e->getMessage());
        }
        self::assertSame('shared', (new KvStateStore(new MemoryAtomicKv(), 'p:', 'shared'))->scope());
    }

    /** A stored value that is not a JSON object (here a bare number) reads as no state and is replaced by the next claim. */
    public function testANonObjectDocumentReadsAsEmpty(): void
    {
        $kv = new MemoryAtomicKv();
        self::put($kv, 'pca-state:k', '7');
        $s = new KvStateStore($kv);
        self::assertNull($s->last('k'));
        self::assertTrue($s->claim('k', 1)->ok);
        self::assertSame(1, $s->last('k'));
    }

    /** The stored document keeps float budgets with their fraction, and a budget that cannot be encoded fails loudly (nothing stored). */
    public function testTheDocumentEncodingKeepsFloatsAndThrowsOnNaN(): void
    {
        $kv = new MemoryAtomicKv();
        $s = new KvStateStore($kv);
        self::assertTrue($s->claimWithBudget('k', 1, null, ['B' => 10.0, 'tau' => 2.0, 'asOf' => 100.0])->ok);
        self::assertSame('{"lastCounter":1,"budget":{"B":10.0,"tau":2.0,"asOf":100.0}}', $kv->get('pca-state:k'));
        try {
            $s->claimWithBudget('n', 1, null, ['B' => NAN, 'tau' => 2.0]);
            self::fail('a NaN budget was stored');
        } catch (\JsonException) {
            self::assertNull($kv->get('pca-state:n'));
        }
    }

    /** A budget written with integer members (by another process) reads back as floats and compares equal to the float budget. */
    public function testAnIntegerBudgetDocumentReadsAsFloats(): void
    {
        $kv = new MemoryAtomicKv();
        self::put($kv, 'pca-state:k', '{"budget":{"B":10,"tau":2,"asOf":100}}');
        $s = new KvStateStore($kv);
        $b = ['B' => 10.0, 'tau' => 2.0, 'asOf' => 100.0];
        self::assertSame($b, $s->budget('k'));
        $r = $s->claimWithBudget('k', 1, $b, null);
        self::assertTrue($r->ok, 'the stored integer budget is the one the caller read');
        self::assertFalse($r->conflict);
    }

    /** A budget member set without tau is no budget. */
    public function testAnIncompleteBudgetIsNull(): void
    {
        $kv = new MemoryAtomicKv();
        self::put($kv, 'pca-state:k', '{"budget":{"B":1}}');
        self::assertNull((new KvStateStore($kv))->budget('k'));
    }

    /** The beacon-sequence pin is stored in the document and only rises. */
    public function testTheBeaconSequencePinIsStoredAndOnlyRises(): void
    {
        $kv = new MemoryAtomicKv();
        $s = new KvStateStore($kv);
        $s->raiseBeaconSeq('k', 4);
        self::assertSame(4, json_decode((string)$kv->get('pca-state:k'), true)['lastBeaconSeq'] ?? null);
        $s->raiseBeaconSeq('k', 3);
        self::assertSame(4, json_decode((string)$kv->get('pca-state:k'), true)['lastBeaconSeq'] ?? null);
        self::assertNull($s->pin('k'), 'the beacon pin is not the epoch pin');
    }

    /** Raising a pin to its current (or a lower) value writes nothing. */
    public function testRaisingAPinToItsValueWritesNothing(): void
    {
        $kv = new StateKill4Kv();
        $s = new KvStateStore($kv);
        $s->raisePin('k', 5);
        self::assertSame(1, $kv->writes);
        $s->raisePin('k', 5);
        $s->raisePin('k', 4);
        self::assertSame(1, $kv->writes);
        $s->raisePin('k', 6);
        self::assertSame(2, $kv->writes);
        self::assertSame(6, $s->pin('k'));
    }

    /** A plain claim never compares budgets: it is admitted over a stored budget. */
    public function testAPlainClaimIgnoresTheStoredBudget(): void
    {
        $s = new KvStateStore(new MemoryAtomicKv());
        self::assertTrue($s->claimWithBudget('k', 1, null, ['B' => 1.0, 'tau' => 1.0, 'asOf' => null])->ok);
        $r = $s->claim('k', 2);
        self::assertTrue($r->ok);
        self::assertFalse($r->conflict);
        self::assertSame(2, $s->last('k'));
    }

    /** If the kv never runs the update, no claim is reported admitted (a budget claim reports a conflict to retry) and no slot is won. */
    public function testAKvThatNeverRunsTheUpdateAdmitsNothing(): void
    {
        $kv = new StateKill4Kv();
        $kv->noop = true;
        $s = new KvStateStore($kv);
        foreach ([$s->claimWithBudget('k', 1, null, null), $s->claim('k', 1)] as $r) {
            self::assertFalse($r->ok);
            self::assertTrue($r->conflict);
            self::assertNull($r->lastCounter);
        }
        self::assertFalse($s->consumeOnce('slot', 2000, 1000));
    }

    /** consume-once slots live under `<prefix>once:<key>`, one slot per key, never in the claim document of the same key. */
    public function testConsumeOnceSlotLayout(): void
    {
        $kv = new MemoryAtomicKv();
        $s = new KvStateStore($kv);
        self::assertTrue($s->claim('x', 5)->ok);
        self::assertTrue($s->consumeOnce('x', 2000, 1000));
        self::assertSame('2000', $kv->get('pca-state:once:x'));
        self::assertSame(5, $s->last('x'), 'the slot did not overwrite the claim document');
        self::assertTrue($s->consumeOnce('y', 2000, 1000), 'another key is another slot');
    }

    /** A slot is held through its horizon inclusive, the horizon never shrinks, and a stored horizon is rewritten in plain decimal. */
    public function testConsumeOnceHorizon(): void
    {
        $s = new KvStateStore(new MemoryAtomicKv());
        self::assertTrue($s->consumeOnce('s', 2000, 1000));
        self::assertFalse($s->consumeOnce('s', 2000, 2000), 'still live at exactly its horizon');
        self::assertTrue($s->consumeOnce('s', 3000, 2001));

        $t = new KvStateStore(new MemoryAtomicKv());
        self::assertTrue($t->consumeOnce('s', 5000, 1000));
        self::assertFalse($t->consumeOnce('s', 2000, 1500));
        self::assertFalse($t->consumeOnce('s', 6000, 3000), 'a shorter repeat did not shrink the horizon');

        $kv = new MemoryAtomicKv();
        $u = new KvStateStore($kv);
        self::put($kv, 'pca-state:once:p', '0002000');
        self::assertFalse($u->consumeOnce('p', 1500, 1000));
        self::assertSame('2000', $kv->get('pca-state:once:p'));
        self::put($kv, 'pca-state:once:j', 'junk');
        self::assertTrue($u->consumeOnce('j', 10, 0), 'an unreadable record is no live record');
        self::assertTrue($u->consumeOnce('n', -5, -10));
        self::assertSame('0', $kv->get('pca-state:once:n'), 'a negative horizon is stored as 0');
    }

    /** isAtomic needs all three sides: claim, budget claim and pins. */
    public function testIsAtomicNeedsClaimBudgetAndPins(): void
    {
        $claim = new class implements StateStore {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }
        };
        $claimBudget = new class implements StateStore, BudgetStateStore {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }

            public function budget(string $key): ?array
            {
                return null;
            }

            public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after): ClaimResult
            {
                return new ClaimResult(true);
            }
        };
        $claimPin = new class implements StateStore, PinStateStore {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(true);
            }

            public function pin(string $key): ?int
            {
                return null;
            }

            public function raisePin(string $key, int $value): void
            {
            }
        };
        $budgetPin = new class implements BudgetStateStore, PinStateStore {
            public function budget(string $key): ?array
            {
                return null;
            }

            public function claimWithBudget(string $key, int $counter, ?array $before, ?array $after): ClaimResult
            {
                return new ClaimResult(true);
            }

            public function pin(string $key): ?int
            {
                return null;
            }

            public function raisePin(string $key, int $value): void
            {
            }
        };
        $pinOnly = new class implements PinStateStore {
            public function pin(string $key): ?int
            {
                return null;
            }

            public function raisePin(string $key, int $value): void
            {
            }
        };
        foreach ([$claim, $claimBudget, $claimPin, $budgetPin, $pinOnly] as $i => $store) {
            self::assertFalse(PcaStateStores::isAtomic($store), "store $i lacks a side");
        }
        self::assertTrue(PcaStateStores::isAtomic(new KvStateStore(new MemoryAtomicKv())));
    }

    // ---- UndoStore -------------------------------------------------------------------------------------------------------

    /** @return list<UndoStore> */
    private static function undoStores(): array
    {
        return [new MemoryUndoStore(), new KvUndoStore(new MemoryAtomicKv(), true)];
    }

    private static function undoRec(string $id, int $windowEnd, string $bond): Obj
    {
        return Json::parseLax('{"v":1,"id":"' . $id . '","state":"open","ver":0,"window_end":' . $windowEnd . ',"grant_ref":"g","bond_ref":"' . $bond . '","receipts":[]}');
    }

    /** list: windowEndedBy includes a window ending exactly then, bondRef filters, and a fractional limit counts whole records. */
    public function testUndoListFilters(): void
    {
        foreach (self::undoStores() as $s) {
            $s->create(self::undoRec('a', 1000, 'b1'));
            $s->create(self::undoRec('b', 1001, 'b2'));
            $s->create(self::undoRec('c', 500, 'b2'));
            $ids = static fn(array $rs): array => array_map(static fn(Obj $r): string => $r->get('id'), $rs);
            self::assertSame(['a', 'c'], $ids($s->list(['state' => 'open', 'windowEndedBy' => 1000])), get_class($s));
            self::assertSame(['b', 'c'], $ids($s->list(['state' => 'open', 'bondRef' => 'b2'])), get_class($s));
            self::assertSame(['a'], $ids($s->list(['state' => 'open', 'limit' => 1.5])), get_class($s));
        }
    }

    /** replace never changes a record's id, on either store. */
    public function testUndoReplaceRefusesAnIdChange(): void
    {
        foreach (self::undoStores() as $s) {
            $s->create(self::undoRec('a', 1000, 'b1'));
            try {
                $s->replace('a', 0, self::undoRec('z', 1000, 'b1'));
                self::fail('the id changed');
            } catch (UndoError $e) {
                self::assertSame('invalid', $e->errorCode);
                self::assertSame('invalid: replace: the record id cannot change', $e->getMessage());
            }
            self::assertSame('a', $s->get('a')->get('id'));
            self::assertNull($s->get('z'));
        }
    }

    /** A kv that never runs the update does not make a replace look done. */
    public function testUndoReplaceIsNotDoneWhenTheKvDidNotRun(): void
    {
        $kv = new StateKill4Kv();
        $s = new KvUndoStore($kv, true);
        self::assertTrue($s->create(self::undoRec('a', 1000, 'b1'))['created']);
        $kv->noop = true;
        self::assertFalse($s->replace('a', 0, self::undoRec('a', 1000, 'b1')));
    }

    private static function corrupt(string $raw): string
    {
        $kv = new MemoryAtomicKv();
        self::put($kv, 'pca-undo/v1/x', $raw);
        try {
            self::noWarnings(static fn() => (new KvUndoStore($kv, true))->get('x'));
        } catch (UndoError $e) {
            return $e->getMessage();
        }
        return 'accepted';
    }

    /** Each corrupt stored record is refused as store_corrupt, with no PHP warning on the way. */
    public function testUndoCorruptRecords(): void
    {
        self::assertSame('store_corrupt: an undo record is not JSON', self::corrupt('not json'));
        self::assertSame('store_corrupt: an undo record has the wrong shape', self::corrupt('[1]'));
        self::assertSame('store_corrupt: an undo record has the wrong shape', self::corrupt('{"v":2,"id":"x","state":"open","ver":0,"receipts":[]}'));
        self::assertSame('store_corrupt: an undo record has the wrong shape', self::corrupt('{"v":"1","id":"x","state":"open","ver":0,"receipts":[]}'));
        self::assertSame('accepted', self::corrupt('{"v":1,"id":"x","state":"open","ver":0,"receipts":[]}'), 'control: a well-formed record');
    }

    // ---- IntentSessionStore ----------------------------------------------------------------------------------------------

    private static function event(string $id): Obj
    {
        return Obj::of(['id' => $id, 'verb' => 'v', 'resource' => 'r', 'params' => new Obj(), 't' => new Num('1'), 'status' => 'reserved']);
    }

    /** The memory session store is volatile, keeps each session's history across transactions, refuses duplicate ids and hands out copies. */
    public function testMemorySessionStore(): void
    {
        $s = new MemoryIntentSessionStore();
        self::assertFalse($s->durable());
        self::assertSame([], $s->snapshot('s1'));
        self::assertSame('done', $s->withSession('s1', static function (SessionTx $tx): string {
            $tx->append(self::event('e1'));
            $tx->append(self::event('e2'));
            return 'done';
        }));
        $s->withSession('s1', static function (SessionTx $tx): void {
            $events = $tx->events();
            self::assertSame(['e1', 'e2'], array_map(static fn(Obj $e): string => $e->get('id'), $events));
            $events[0]->set('status', 'tampered');
            try {
                $tx->append(self::event('e1'));
                self::fail('a duplicate event id was appended');
            } catch (\RuntimeException $e) {
                self::assertSame('duplicate event id', $e->getMessage());
            }
            self::assertTrue($tx->setStatus('e2', 'committed'));
            self::assertFalse($tx->setStatus('e9', 'committed'));
        });
        $snap = $s->snapshot('s1');
        self::assertSame([['e1', 'reserved'], ['e2', 'committed']], array_map(static fn(Obj $e): array => [$e->get('id'), $e->get('status')], $snap));
        $snap[1]->set('status', 'tampered');
        self::assertSame('committed', $s->snapshot('s1')[1]->get('status'), 'a snapshot is a copy');
        self::assertSame([], $s->snapshot('s2'), 'sessions are independent');
    }
}

/** An atomic kv over memory that counts the writes it applies; with `noop` it never runs the update function. */
final class StateKill4Kv implements AtomicKv
{
    public int $writes = 0;
    public bool $noop = false;
    private MemoryAtomicKv $m;

    public function __construct()
    {
        $this->m = new MemoryAtomicKv();
    }

    public function get(string $key): ?string
    {
        return $this->m->get($key);
    }

    public function update(string $key, callable $fn): void
    {
        if ($this->noop) {
            return;
        }
        $this->m->update($key, function (?string $prev) use ($fn): ?string {
            $next = $fn($prev);
            if ($next !== null) {
                $this->writes++;
            }
            return $next;
        });
    }
}
