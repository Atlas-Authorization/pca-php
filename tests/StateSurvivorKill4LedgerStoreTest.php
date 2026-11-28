<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/LedgerStore.php';
require_once __DIR__ . '/../src/LedgerLog.php';

use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvLedgerStore;
use Atlas\Pca\Ledger;
use Atlas\Pca\LedgerDoc;
use Atlas\Pca\LedgerStore;
use Atlas\Pca\LedgerStoreError;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\StoredLedger;
use Atlas\Pca\TransparencyLedger;
use PHPUnit\Framework\TestCase;

/** The durable transparency ledger: the store's pure transitions, the stored ledger's fail-closed open / append / checkpoint, and the in-memory log. */
final class StateSurvivorKill4LedgerStoreTest extends TestCase
{
    protected function tearDown(): void
    {
        Ledger::$faultHook = null;
        Pca::$faultHook = null;
    }

    private static function key(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/state-kill-4-guardian', true));
    }

    private static function open(LedgerStore $s, ?callable $clock = null, bool $systemClock = false): StoredLedger
    {
        return StoredLedger::open($s, self::key(), 'inst', 'pr', $systemClock ? null : ($clock ?? static fn(): int => 1_800_000_000_000));
    }

    private static function setDoc(MemoryAtomicKv $kv, string $raw): void
    {
        $kv->update(KvLedgerStore::DOC_KEY, static fn(?string $prev): string => $raw);
    }

    /** The message of the LedgerStoreError `$f` throws, or 'no error'. */
    private static function err(\Closure $f): string
    {
        try {
            $f();
        } catch (LedgerStoreError $e) {
            return $e->getMessage();
        }
        return 'no error';
    }

    // ---- LedgerDoc ---------------------------------------------------------------------------------------------------------

    /** A checkpoint whose size is negative zero (float or lexeme) or that is not an object is malformed; +0 is a valid size. */
    public function testCheckpointSizeNegativeZeroIsMalformed(): void
    {
        $cp = static fn(mixed $size): Obj => Obj::of(['sth' => Obj::of(['size' => $size, 'root' => 'r'])]);
        $malformed = ['outcome' => 'conflict', 'count' => 0, 'reason' => 'malformed checkpoint'];
        $doc = LedgerDoc::emptyLedgerDoc();
        self::assertSame($malformed, LedgerDoc::checkpointToLedgerDoc($doc, 0, $cp(-0.0)));
        self::assertSame($malformed, LedgerDoc::checkpointToLedgerDoc($doc, 0, $cp(new Num('-0'))));
        self::assertSame($malformed, LedgerDoc::checkpointToLedgerDoc($doc, 0, null));
        self::assertSame(['outcome' => 'appended', 'count' => 1], LedgerDoc::checkpointToLedgerDoc($doc, 0, $cp(0.0)));
        $doc2 = LedgerDoc::emptyLedgerDoc();
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            $r = LedgerDoc::checkpointToLedgerDoc($doc2, 0, $cp(0));
        } finally {
            restore_error_handler();
        }
        self::assertSame(['outcome' => 'appended', 'count' => 1], $r, 'a native int size is checked without a warning');
    }

    /** expectedSize: a float zero and the largest safe integer are sizes, a non-number is refused with the exact reason. */
    public function testAppendExpectedSizeParsing(): void
    {
        $doc = LedgerDoc::emptyLedgerDoc();
        self::assertSame(['outcome' => 'appended', 'size' => 1], LedgerDoc::appendToLedgerDoc($doc, 0.0, ['c1']));
        self::assertSame(['outcome' => 'conflict', 'size' => 1], LedgerDoc::appendToLedgerDoc($doc, 9007199254740991, ['c2']));
        try {
            LedgerDoc::appendToLedgerDoc($doc, 'x', ['c2']);
            self::fail('a string size was accepted');
        } catch (\RangeException $e) {
            self::assertSame('append: expectedSize must be a non-negative safe integer', $e->getMessage());
        }
        self::assertSame(['c1'], $doc['commits']);
    }

    /** checkpoints() with no argument lists from the start. */
    public function testCheckpointsDefaultsToTheStart(): void
    {
        self::assertSame([], (new KvLedgerStore(new MemoryAtomicKv()))->checkpoints());
    }

    // ---- StoredLedger::open ------------------------------------------------------------------------------------------------

    /** open refuses a missing store, a missing guardian key, and a PQ or unknown suite without a pin, each with its exact reason. */
    public function testOpenGuards(): void
    {
        $s = new KvLedgerStore(new MemoryAtomicKv());
        $k = self::key();
        self::assertSame('store_missing: a LedgerStore is required (there is no in-memory default)',
            self::err(static fn() => StoredLedger::open(null, $k, 'inst', 'pr')));
        self::assertSame('guardian_key_missing: a guardian secret key is required', self::err(static fn() => StoredLedger::open($s, 'k', 'inst', 'pr')));
        $pin = 'pin_missing: a post-quantum or hybrid checkpoint suite needs a PQ pin for the guardian (and a known suite name)';
        self::assertSame($pin, self::err(static fn() => StoredLedger::open($s, $k, 'inst', 'pr', null, 'no-such-suite', null, ['x' => 'y'])));
        self::assertSame($pin, self::err(static fn() => StoredLedger::open($s, $k, 'inst', 'pr', null, 'ml-dsa-65')));
        self::assertSame(0, StoredLedger::open($s, $k, 'inst', 'pr', null, 'ed25519')->size());
        self::assertSame(0, StoredLedger::open($s, $k, 'inst', 'pr', null, 'ml-dsa-65', null, [$k->public => 'pq'])->size());
    }

    /** A store failure surfaces as store_unavailable with the store's own message. */
    public function testOpenKeepsTheStoreFailureMessage(): void
    {
        $s = new StateKill4LedgerStore(new KvLedgerStore(new MemoryAtomicKv()));
        $s->o['size'] = static function (): int {
            throw new \RuntimeException('disk gone');
        };
        self::assertSame('store_unavailable: disk gone', self::err(static fn() => self::open($s)));
    }

    /** A checkpoint attesting more entries than the log holds is a rollback, its size printed as an integer. */
    public function testOpenRefusesARollbackBelowACheckpoint(): void
    {
        $kv = new MemoryAtomicKv();
        self::setDoc($kv, '{"v":1,"commits":[],"checkpoints":[{"sth":{"size":1000000000000000}}]}');
        self::assertSame('rollback: the log has 0 entries but a checkpoint attests 1000000000000000', self::err(static fn() => self::open(new KvLedgerStore($kv))));
    }

    /** A checkpoint with an unreadable size attests nothing (no rollback) and is then refused as belonging to another log. */
    public function testAnUnreadableCheckpointSizeAttestsNothing(): void
    {
        $kv = new MemoryAtomicKv();
        self::setDoc($kv, '{"v":1,"commits":[],"checkpoints":[{"sth":{"size":"x"}}]}');
        self::assertSame('forged_checkpoint: checkpoint 0 belongs to another log', self::err(static fn() => self::open(new KvLedgerStore($kv))));
    }

    /** Entries that do not reproduce a checkpoint's root are tamper, naming the checkpoint and its size. */
    public function testOpenRefusesEntriesThatDoNotReproduceTheRoot(): void
    {
        $kv = new MemoryAtomicKv();
        self::setDoc($kv, '{"v":1,"commits":["c1"],"checkpoints":[{"sth":{"instance_id":"inst","principal":"pr","size":1,"root":"bogus"}}]}');
        self::assertSame('tamper: the stored entries do not reproduce the root of checkpoint 0 (size 1)', self::err(static fn() => self::open(new KvLedgerStore($kv))));
    }

    /** A later checkpoint with an empty proof is a missing proof; one with a proof that is not an object is inconsistent. */
    public function testOpenRefusesAMissingOrMalformedProof(): void
    {
        $kv = new MemoryAtomicKv();
        $h = self::open(new KvLedgerStore($kv));
        $h->append('c1');
        $h->checkpoint();
        $h->append('c2');
        $h->checkpoint();
        $good = (string)$kv->get(KvLedgerStore::DOC_KEY);
        self::assertSame(2, self::open(new KvLedgerStore($kv))->size(), 'control: the untouched log opens');
        $withProof = static function (mixed $proof) use ($kv, $good): void {
            $d = Json::parseLax($good);
            $d->get('checkpoints')[1]->set('proof', $proof);
            self::setDoc($kv, Json::canonicalizeLenient($d));
        };
        $withProof(new Obj());
        self::assertSame('forged_checkpoint: checkpoint 1: proof_missing', self::err(static fn() => self::open(new KvLedgerStore($kv))));
        $withProof('x');
        self::assertSame('inconsistent: checkpoint 1: inconsistent', self::err(static fn() => self::open(new KvLedgerStore($kv))));
    }

    // ---- append / catchUp --------------------------------------------------------------------------------------------------

    /** append retries exactly 16 times when another writer keeps taking the tail, then gives up with a conflict. */
    public function testAppendGivesUpAfterSixteenConflicts(): void
    {
        $s = new StateKill4LedgerStore(new KvLedgerStore(new MemoryAtomicKv()));
        $h = self::open($s);
        $s->o['append'] = static fn(mixed $size, mixed $commits): array => ['outcome' => 'conflict', 'size' => 0];
        self::assertSame('conflict: the log kept moving; could not append', self::err(static fn() => $h->append('c1')));
        self::assertSame(16, $s->appendCalls);
        self::assertSame(0, $h->size());
    }

    /** A store that fails during append surfaces as store_unavailable with its message. */
    public function testAppendStoreFailure(): void
    {
        $s = new StateKill4LedgerStore(new KvLedgerStore(new MemoryAtomicKv()));
        $h = self::open($s);
        $s->o['append'] = static function (mixed $size, mixed $commits): array {
            throw new \RuntimeException('disk');
        };
        self::assertSame('store_unavailable: disk', self::err(static fn() => $h->append('c1')));
        self::assertSame(1, $s->appendCalls);
    }

    /** catchUp refuses a store that lost entries this handle already holds. */
    public function testCatchUpRefusesAShrunkStore(): void
    {
        $kv = new MemoryAtomicKv();
        $h = self::open(new KvLedgerStore($kv));
        $h->append('c1');
        self::setDoc($kv, '{"v":1,"commits":[],"checkpoints":[]}');
        self::assertSame('rollback: the store shrank from 1 to 0 entries', self::err(static fn() => $h->catchUp()));
    }

    /** catchUp verifies the checkpoints other writers added. */
    public function testCatchUpVerifiesNewCheckpoints(): void
    {
        $kv = new MemoryAtomicKv();
        $h = self::open(new KvLedgerStore($kv));
        $h->append('c1');
        self::setDoc($kv, '{"v":1,"commits":["c1"],"checkpoints":[{"sth":{"size":5}}]}');
        self::assertSame('rollback: the log has 1 entries but a checkpoint attests 5', self::err(static fn() => $h->catchUp()));
    }

    // ---- checkpoint --------------------------------------------------------------------------------------------------------

    /** checkpoint refuses to sign when the stored entries cannot be re-read (store_unavailable, the store's message). */
    public function testCheckpointRefusesWhenTheEntriesCannotBeRead(): void
    {
        $inner = new KvLedgerStore(new MemoryAtomicKv());
        $s = new StateKill4LedgerStore($inner);
        $h = self::open($s);
        $h->append('c1');
        $s->o['read'] = static function (mixed $from, mixed $to) use ($inner): array {
            if ($from === 0 && $to > 0) {
                throw new \RuntimeException('read broke');
            }
            return $inner->read($from, $to);
        };
        self::assertSame('store_unavailable: read broke', self::err(static fn() => $h->checkpoint()));
        self::assertSame(0, $inner->checkpointCount());
    }

    /** checkpoint refuses to sign over entries rewritten under this handle. */
    public function testCheckpointRefusesRewrittenEntries(): void
    {
        $kv = new MemoryAtomicKv();
        $store = new KvLedgerStore($kv);
        $h = self::open($store);
        $h->append('c1');
        self::setDoc($kv, '{"v":1,"commits":["zz"],"checkpoints":[]}');
        self::assertSame('tamper: the stored entries no longer match this handle; refusing to sign a checkpoint over them', self::err(static fn() => $h->checkpoint()));
        self::assertSame(0, $store->checkpointCount());
    }

    /** Without a clock the timestamp is the system time in milliseconds. */
    public function testCheckpointUsesTheSystemClockInMilliseconds(): void
    {
        $h = self::open(new KvLedgerStore(new MemoryAtomicKv()), null, true);
        $h->append('c1');
        $before = (int)floor(microtime(true) * 1000);
        $sth = $h->checkpoint();
        $after = (int)floor(microtime(true) * 1000) + 1;
        $t = $sth->get('timestamp')->int();
        self::assertGreaterThanOrEqual($before, $t);
        self::assertLessThanOrEqual($after, $t);
    }

    /** A clock returning a non-number or a non-finite number is refused before anything is signed. */
    public function testCheckpointRefusesAnInvalidClock(): void
    {
        foreach (['x', INF] as $bad) {
            $store = new KvLedgerStore(new MemoryAtomicKv());
            $h = self::open($store, static fn() => $bad);
            $h->append('c1');
            self::assertSame('clock_invalid: the clock returned a non-finite time', self::err(static fn() => $h->checkpoint()));
            self::assertSame(0, $store->checkpointCount());
        }
    }

    /** A float clock is floored to whole milliseconds and written as an integer, also beyond 1e15. */
    public function testCheckpointTimestampIsTheFlooredInteger(): void
    {
        foreach ([[1800000000000.7, '1800000000000'], [2.0e15, '2000000000000000']] as [$clock, $want]) {
            $h = self::open(new KvLedgerStore(new MemoryAtomicKv()), static fn(): float => $clock);
            $h->append('c1');
            self::assertSame($want, $h->checkpoint()->get('timestamp')->lexeme);
        }
    }

    /** A new head the chain check finds inconsistent with the previous checkpoint is refused and not stored. */
    public function testCheckpointRefusesAnInconsistentNewHead(): void
    {
        $store = new KvLedgerStore(new MemoryAtomicKv());
        $h = self::open($store);
        $h->append('c1');
        $h->checkpoint();
        $h->append('c2');
        Ledger::$faultHook = static function (string $fn): void {
            if ($fn === 'verifyHeadConsistency') {
                throw new \RuntimeException('fault');
            }
        };
        self::assertSame('inconsistent: the new head is not consistent with checkpoint 0', self::err(static fn() => $h->checkpoint()));
        self::assertSame(1, $store->checkpointCount());
    }

    /** A new head that does not verify under the pinned guardian identity is refused as forged and not stored. */
    public function testCheckpointRefusesANewHeadThatDoesNotVerify(): void
    {
        $store = new KvLedgerStore(new MemoryAtomicKv());
        $h = self::open($store);
        $h->append('c1');
        Pca::$faultHook = static function (string $what): void {
            if ($what === 'pinned_suite') {
                throw new \RuntimeException('fault');
            }
        };
        self::assertSame('forged_checkpoint: the new checkpoint does not verify under the pinned guardian identity (check the guardian key and the PQ pin)',
            self::err(static fn() => $h->checkpoint()));
        self::assertSame(0, $store->checkpointCount());
    }

    /** A failed or refused checkpoint write is reported with the store's message or reason (default 'conflict'). */
    public function testCheckpointWriteFailureAndConflict(): void
    {
        $s = new StateKill4LedgerStore(new KvLedgerStore(new MemoryAtomicKv()));
        $h = self::open($s);
        $h->append('c1');
        $s->o['appendCheckpoint'] = static function (mixed $n, mixed $cp): array {
            throw new \RuntimeException('cp disk');
        };
        self::assertSame('store_unavailable: cp disk', self::err(static fn() => $h->checkpoint()));
        foreach ([['taken', 'conflict: taken'], [5, 'conflict: 5'], [null, 'conflict: conflict']] as [$reason, $want]) {
            $s->o['appendCheckpoint'] = static fn(mixed $n, mixed $cp): array => ['outcome' => 'conflict', 'count' => 0] + ($reason === null ? [] : ['reason' => $reason]);
            self::assertSame($want, self::err(static fn() => $h->checkpoint()));
        }
        self::assertNull($h->latestCheckpoint());
    }

    // ---- TransparencyLedger ------------------------------------------------------------------------------------------------

    /** append returns the index and the salted commit; a drawn salt is 16 random bytes; a fresh log audits clean. */
    public function testLogAppend(): void
    {
        $l = new TransparencyLedger('pr');
        $p0 = Obj::of(['act' => 'a0']);
        self::assertSame(['index' => 0, 'commit' => TransparencyLedger::entryCommit('salt-0', $p0)], $l->append($p0, 'salt-0'));
        self::assertSame(1, $l->append(Obj::of(['act' => 'a1']))['index']);
        $salt = (new \ReflectionProperty(TransparencyLedger::class, 'openings'))->getValue($l)[1]['salt'];
        self::assertSame(22, strlen($salt), '16 bytes in unpadded base64url');
        self::assertSame([], $l->auditOpenings());
    }

    /** auditOpenings lists every index whose stored opening no longer matches, and skips opaque or shredded leaves. */
    public function testAuditOpeningsListsEveryTamperedIndex(): void
    {
        $l = new TransparencyLedger();
        $p0 = Obj::of(['act' => 'a0']);
        $p1 = Obj::of(['act' => 'a1']);
        $p3 = Obj::of(['act' => 'a3']);
        $l->append($p0, 's0');
        $l->append($p1, 's1');
        $l->appendCommitment('opaque');
        $l->append($p3, 's3');
        self::assertSame([], $l->auditOpenings());
        $p0->set('act', 'changed');
        $p3->set('act', 'changed');
        self::assertSame([0, 3], $l->auditOpenings());
    }

    /** verifyOpening reads an array opening as well as an Obj one. */
    public function testVerifyOpeningAcceptsAnArray(): void
    {
        $p = Obj::of(['act' => 'a']);
        $c = TransparencyLedger::entryCommit('s', $p);
        self::assertTrue(TransparencyLedger::verifyOpening($c, ['salt' => 's', 'pcactn' => $p]));
        self::assertTrue(TransparencyLedger::verifyOpening($c, Obj::of(['salt' => 's', 'pcactn' => $p])));
        self::assertFalse(TransparencyLedger::verifyOpening($c, ['salt' => 't', 'pcactn' => $p]));
    }

    /** An empty commitment is refused and nothing is appended. */
    public function testAppendCommitmentRefusesAnEmptyCommit(): void
    {
        $l = new TransparencyLedger();
        try {
            $l->appendCommitment('');
            self::fail('an empty commit was appended');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('appendCommitment: commit must be a non-empty string', $e->getMessage());
        }
        self::assertSame(0, $l->size());
    }

    /** rootAt takes an integral number (float or int) in [0, size]; anything else is out of range. */
    public function testRootAtSizes(): void
    {
        $l = TransparencyLedger::fromCommits(['c1', 'c2', 'c3']);
        self::assertSame(TransparencyLedger::rootOf(['c1', 'c2']), $l->rootAt(2.0));
        self::assertSame(TransparencyLedger::rootOf(['c1', 'c2']), $l->rootAt(2));
        self::assertSame(Ledger::emptyTreeRoot(), $l->rootAt(0));
        foreach ([1.5, '1', null, -1, 4] as $bad) {
            try {
                $l->rootAt($bad);
                self::fail('rootAt accepted ' . var_export($bad, true));
            } catch (\RangeException $e) {
                self::assertSame('rootAt: size out of range', $e->getMessage());
            }
        }
    }

    /** shred removes an opening once (true, then false), refuses an index outside [0, size), and keeps the commit. */
    public function testShred(): void
    {
        $l = new TransparencyLedger();
        $l->append(Obj::of(['a' => 'x']), 's');
        $l->appendCommitment('c');
        self::assertTrue($l->shred(0));
        self::assertFalse($l->shred(0));
        self::assertFalse($l->shred(1));
        foreach ([-1, 2] as $bad) {
            try {
                $l->shred($bad);
                self::fail("shred accepted $bad");
            } catch (\RangeException $e) {
                self::assertSame('shred: index out of range', $e->getMessage());
            }
        }
        self::assertSame(2, $l->size());
        self::assertSame([], $l->auditOpenings());
    }

    /** consistencyProof: the new size defaults to the log size, a proof covers only the first newSize entries, bad sizes are refused. */
    public function testConsistencyProof(): void
    {
        $l = TransparencyLedger::fromCommits(['c1', 'c2', 'c3']);
        self::assertSame('3', $l->consistencyProof(1)->get('newSize')->lexeme);
        $two = TransparencyLedger::fromCommits(['c1', 'c2'])->consistencyProof(1, 2)->get('path');
        self::assertNotSame([], $two);
        self::assertSame($two, $l->consistencyProof(1, 2)->get('path'));
        try {
            $l->consistencyProof('x', 1);
            self::fail('a string old size was accepted');
        } catch (\RangeException $e) {
            self::assertSame('consistencyProof: invalid sizes', $e->getMessage());
        }
    }
}

/** A {@see LedgerStore} that delegates to another one, with per-method overrides and an append counter. */
final class StateKill4LedgerStore implements LedgerStore
{
    /** @var array<string,\Closure> */
    public array $o = [];
    public int $appendCalls = 0;

    public function __construct(private readonly LedgerStore $inner)
    {
    }

    public function size(): int
    {
        return isset($this->o['size']) ? ($this->o['size'])() : $this->inner->size();
    }

    public function read(mixed $from, mixed $to): array
    {
        return isset($this->o['read']) ? ($this->o['read'])($from, $to) : $this->inner->read($from, $to);
    }

    public function append(mixed $expectedSize, mixed $commits): array
    {
        $this->appendCalls++;
        return isset($this->o['append']) ? ($this->o['append'])($expectedSize, $commits) : $this->inner->append($expectedSize, $commits);
    }

    public function checkpointCount(): int
    {
        return $this->inner->checkpointCount();
    }

    public function checkpoints(mixed $from = 0): array
    {
        return $this->inner->checkpoints($from);
    }

    public function appendCheckpoint(mixed $expectedCount, mixed $cp): array
    {
        return isset($this->o['appendCheckpoint']) ? ($this->o['appendCheckpoint'])($expectedCount, $cp) : $this->inner->appendCheckpoint($expectedCount, $cp);
    }
}
