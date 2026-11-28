<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/BudgetLedger.php';

use Atlas\Pca\BudgetLedger;
use Atlas\Pca\BudgetLedgerDoc;
use Atlas\Pca\BudgetLedgerError;
use Atlas\Pca\BudgetRelease;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvBudgetLedger;
use Atlas\Pca\LedgerDoc;
use Atlas\Pca\LedgerStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24) for src/BudgetLedger.php: event validation, the cap, replay identity, releases, aggregate admission and the durable store. */
final class PolicySurvivorKill24BudgetLedgerTest extends TestCase
{
    /** @var list<string> */
    private array $tmp = [];

    protected function tearDown(): void
    {
        foreach (array_reverse($this->tmp) as $p) {
            if (is_dir($p)) {
                @rmdir($p);
            } elseif (file_exists($p)) {
                @unlink($p);
            }
        }
    }

    private static function acc(string $id, int $max, string $scope = 'principal', string $verb = 'pay'): Obj
    {
        return Json::parseLax('{"id":"' . $id . '","agg":"sum","val":"action.params.amount","sel":{"verbs":["' . $verb . '"]},"win":{"kind":"task"},"key":null,'
            . '"domain_max":' . $max . ',"holder":{"kind":"site_local"},"scope":"' . $scope . '"}');
    }

    private static function ev(string $id, int $amount = 10, string $verb = 'pay', string $res = 'r', int $t = 1000): Obj
    {
        return Obj::of(['id' => $id, 'verb' => $verb, 'resource' => $res, 'params' => Obj::of(['amount' => $amount]), 't' => $t]);
    }

    private static function ledger(): KvBudgetLedger
    {
        return new KvBudgetLedger(new MemoryAtomicKv(), true);
    }

    private static function admit(BudgetLedger $l, array $accs, Obj $e, mixed $verdict = ['allow' => true], mixed $exp = null, mixed $max = null,
        array $ids = ['principal' => 'alice', 'org' => 'acme']): array
    {
        return BudgetRelease::admitAggregateAction($l, $ids, $accs, null, $e, static fn($s) => $verdict, $exp, $max);
    }

    private function assertMalformed(mixed $req, string $msg = 'reserve: a malformed event'): void
    {
        try {
            BudgetLedgerDoc::reserveInDoc(BudgetLedgerDoc::emptyBudgetDoc(), $req);
            $this->fail('accepted: ' . $msg);
        } catch (\RangeException $e) {
            $this->assertSame($msg, $e->getMessage());
        }
    }

    /** Every malformed event field is refused on its own; Obj and list params are both accepted. */
    public function testEventValidation(): void
    {
        $this->assertSame('reserved', BudgetLedgerDoc::reserveInDoc(BudgetLedgerDoc::emptyBudgetDoc(), ['event' => self::ev('a'), 'accumulators' => []])['outcome']);
        $ok = self::ev('a');
        $ok->set('params', [1]);
        $this->assertSame('reserved', BudgetLedgerDoc::reserveInDoc(BudgetLedgerDoc::emptyBudgetDoc(), ['event' => $ok, 'accumulators' => []])['outcome']);
        $this->assertMalformed('x');
        $this->assertMalformed(['event' => ['id' => 'a'], 'accumulators' => []]);
        foreach ([['id', ''], ['verb', 5], ['resource', null], ['t', 1.5], ['params', 'x'], ['params', ['a' => 1]]] as [$k, $v]) {
            $e = self::ev('a');
            $e->set($k, $v);
            $this->assertMalformed(['event' => $e, 'accumulators' => []]);
        }
        $this->assertMalformed(['event' => self::ev('a'), 'accumulators' => [], 'expiresAt' => 1.5], 'reserve: expiresAt must be a safe integer');
    }

    /** A re-reservation with the same id is a replay only when verb, resource, params and t all match. */
    public function testReplayIdentity(): void
    {
        $doc = BudgetLedgerDoc::emptyBudgetDoc();
        $this->assertSame('reserved', BudgetLedgerDoc::reserveInDoc($doc, ['event' => self::ev('a', 1, 'pay', 'a'), 'accumulators' => []])['outcome']);
        $this->assertSame(['outcome' => 'replayed', 'version' => 1, 'status' => 'reserved'],
            BudgetLedgerDoc::reserveInDoc($doc, ['event' => self::ev('a', 1, 'pay', 'a'), 'accumulators' => []]));
        foreach ([self::ev('a', 1, 'paz', 'a'), self::ev('a', 1, 'pay', 'b'), self::ev('a', 1, 'pay', 'a', 2000)] as $e) {
            $this->assertSame(['outcome' => 'id_conflict', 'version' => 1], BudgetLedgerDoc::reserveInDoc($doc, ['event' => $e, 'accumulators' => []]));
        }
    }

    /** The cap: a missing domain_max is an exact error, a non-selecting accumulator is skipped (not a stop), a broken history is store_corrupt with its reason. */
    public function testCapAndAccumulators(): void
    {
        $this->assertMalformed(['event' => self::ev('a'), 'accumulators' => [self::acc('spend', 5)->without('domain_max')]],
            'reserve: accumulator spend has no domain_max (the cap)');
        $r = BudgetLedgerDoc::reserveInDoc(BudgetLedgerDoc::emptyBudgetDoc(), ['event' => self::ev('a', 10), 'accumulators' => [self::acc('x', 1000, 'principal', 'other'), self::acc('b', 5)]]);
        $this->assertSame(['over_cap', 'b', 10], [$r['outcome'], $r['acc'], $r['post']]);
        $bad = self::acc('c', 100);
        $bad->set('agg', 'bogus');
        try {
            BudgetLedgerDoc::reserveInDoc(BudgetLedgerDoc::emptyBudgetDoc(), ['event' => self::ev('a'), 'accumulators' => [$bad]]);
            $this->fail('accepted an unknown agg');
        } catch (BudgetLedgerError $e) {
            $this->assertSame('store_corrupt: accPost: unknown agg', $e->getMessage());
        }
        $int = self::acc('d', 100);
        $int->set('id', 5);
        $r = BudgetLedgerDoc::reserveInDoc(BudgetLedgerDoc::emptyBudgetDoc(), ['event' => self::ev('a', 10), 'accumulators' => [$int]]);
        $this->assertSame('reserved', $r['outcome']);
        $this->assertSame(['5'], $r['post']->keys());
    }

    /** A stored document of the wrong shape is store_corrupt, never an internal error. */
    public function testDecodeShape(): void
    {
        foreach (['[]', '5', '{"v":1,"ver":0,"events":[5]}'] as $raw) {
            try {
                BudgetLedgerDoc::decode($raw);
                $this->fail("decoded $raw");
            } catch (BudgetLedgerError $e) {
                $this->assertSame('store_corrupt: budget document has the wrong shape', $e->getMessage());
            }
        }
    }

    /** The ledger needs an atomic kv and an explicit durability flag. */
    public function testLedgerConstruction(): void
    {
        foreach ([['x', true, 'store_missing: KvBudgetLedger needs an atomic kv'], [new MemoryAtomicKv(), 'yes', 'invalid: say whether the kv is durable (true or false)']] as [$kv, $d, $msg]) {
            try {
                new KvBudgetLedger($kv, $d);
                $this->fail($msg);
            } catch (BudgetLedgerError $e) {
                $this->assertSame($msg, $e->getMessage());
            }
        }
    }

    /** openDurable creates nested directories and the owner-only database file, and is durable and usable. */
    public function testOpenDurable(): void
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-bl24-' . bin2hex(random_bytes(6));
        $dir = $base . DIRECTORY_SEPARATOR . 'a';
        $this->tmp = [$base, $dir, $dir . DIRECTORY_SEPARATOR . 'budget-ledger.db'];
        $l = KvBudgetLedger::openDurable($dir);
        $this->assertTrue($l->durable());
        $this->assertFileExists($dir . DIRECTORY_SEPARATOR . 'budget-ledger.db');
        $this->assertSame('reserved', $l->reserve('k', ['event' => self::ev('a'), 'accumulators' => []])['outcome']);
        $this->assertSame(1, $l->snapshot('k')['version']);
    }

    /** A directory that cannot be created, or a database path that is a directory, are store_missing with their own reason. */
    public function testOpenDurableFailures(): void
    {
        $base = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-bl24f-' . bin2hex(random_bytes(6));
        $file = $base . DIRECTORY_SEPARATOR . 'f';
        $dbDir = $base . DIRECTORY_SEPARATOR . 'd';
        $this->tmp = [$base, $file, $dbDir, $dbDir . DIRECTORY_SEPARATOR . 'budget-ledger.db'];
        mkdir($base, 0700);
        file_put_contents($file, 'x');
        mkdir($dbDir . DIRECTORY_SEPARATOR . 'budget-ledger.db', 0700, true);
        foreach ([[$file . DIRECTORY_SEPARATOR . 'sub', 'store_missing: cannot create the ledger directory'], [$dbDir, 'store_missing: cannot create the ledger database file']] as [$d, $msg]) {
            try {
                KvBudgetLedger::openDurable($d);
                $this->fail($msg);
            } catch (BudgetLedgerError $e) {
                $this->assertSame($msg, $e->getMessage());
            }
        }
    }

    private static function key(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/budget-release-24', true));
    }

    /** A release with v = 2, validly signed over that content, is still refused; a lone surrogate in its key is refused, not an error. */
    public function testVerifyReleaseShape(): void
    {
        $kp = self::key();
        $this->assertTrue(BudgetRelease::verifyRelease(BudgetRelease::signRelease('k', 'i', 'rollback', 5, $kp), $kp->public), 'control');
        $r = Obj::of(['v' => BudgetLedgerDoc::num(2), 'key' => 'k', 'id' => 'i', 'reason' => 'rollback', 'at' => Sign::n(5), 'signer' => $kp->public]);
        $msg = (new \ReflectionMethod(BudgetRelease::class, 'message'))->invoke(null, $r);
        $r->set('sig', Pca::b64u($kp->sign($msg)));
        $this->assertFalse(BudgetRelease::verifyRelease($r, $kp->public));
        $s = Obj::of(['v' => BudgetLedgerDoc::num(1), 'key' => "k\xED\xA0\x80", 'id' => 'i', 'reason' => 'rollback', 'at' => Sign::n(5), 'signer' => $kp->public,
            'sig' => Pca::b64u(str_repeat("\1", 64))]);
        $this->assertFalse(BudgetRelease::verifyRelease($s, $kp->public));
    }

    private static function log(\Closure $append): LedgerStore
    {
        return new class($append) implements LedgerStore {
            public int $calls = 0;

            public function __construct(private readonly \Closure $f)
            {
            }

            public function size(): int
            {
                return 7;
            }

            public function read(mixed $from, mixed $to): array
            {
                return [];
            }

            public function append(mixed $expectedSize, mixed $commits): array
            {
                $this->calls++;
                return ($this->f)($this->calls);
            }

            public function checkpointCount(): int
            {
                return 0;
            }

            public function checkpoints(mixed $from = 0): array
            {
                return [];
            }

            public function appendCheckpoint(mixed $expectedCount, mixed $cp): array
            {
                return [];
            }
        };
    }

    /** Anchoring retries exactly 64 times on conflicts, then fails conflict_exhausted; a replayed append is anchored. */
    public function testAnchorRetries(): void
    {
        $r = BudgetRelease::signRelease('k', 'i', 'rollback', 5, self::key());
        $this->assertSame(7, BudgetRelease::anchorRelease(self::log(static fn(int $n): array => ['outcome' => 'replayed']), $r));
        $log = self::log(static fn(int $n): array => $n > 64 ? throw new \LogicException('a 65th attempt') : ['outcome' => 'conflict']);
        try {
            BudgetRelease::anchorRelease($log, $r);
            $this->fail('anchored under conflicts');
        } catch (BudgetLedgerError $e) {
            $this->assertSame('conflict_exhausted', $e->codeName);
        }
        $this->assertSame(64, $log->calls);
    }

    /** The ledger key of a scope: Obj and array id maps, a numeric scope keeps its text. */
    public function testAggregateKeyOf(): void
    {
        $this->assertSame('principal/alice', BudgetRelease::aggregateKeyOf(Obj::of(['scope' => 'principal', 'id' => 'x']), ['principal' => 'alice']));
        $this->assertSame('5/alice', BudgetRelease::aggregateKeyOf(Obj::of(['scope' => 5, 'id' => 'x']), Obj::of(['5' => 'alice'])));
        $this->assertSame('1.5/alice', BudgetRelease::aggregateKeyOf(Obj::of(['scope' => 1.5, 'id' => 'x']), ['1.5' => 'alice']));
        $this->assertNull(BudgetRelease::aggregateKeyOf(Obj::of(['scope' => 'session']), []));
    }

    /** The verifier's verdict: an Obj or array with allow === true admits; anything else denies. */
    public function testVerdictShapes(): void
    {
        foreach ([[Obj::of(['allow' => true]), true], [['allow' => true], true], [Obj::of(['allow' => false]), false], ['yes', false], [['x' => 1], false]] as [$v, $want]) {
            $r = self::admit(self::ledger(), [], self::ev('a'), $v);
            $this->assertSame($want, $r['admitted']);
            if (!$want) {
                $this->assertSame('verifier denied', $r['reason']);
            }
        }
    }

    /** expiresAt reaches the reservation; a committed event admitted again is "already committed"; a reserved one is a replay. */
    public function testAdmitExpiryAndReplay(): void
    {
        $l = self::ledger();
        $r = self::admit($l, [self::acc('s', 100)], self::ev('a'), ['allow' => true], 5000);
        $this->assertTrue($r['admitted']);
        $this->assertSame(5000.0, LedgerDoc::num($l->snapshot('principal/alice')['events'][0]->get('exp')));
        $this->assertTrue(self::admit($l, [self::acc('s', 100)], self::ev('a'))['admitted']);
        BudgetRelease::settleAggregate($l, $r['reservations'], 'committed');
        $again = self::admit($l, [self::acc('s', 100)], self::ev('a'));
        $this->assertSame([false, 'aggregate: already committed'], [$again['admitted'], $again['reason']]);
    }

    /** A key over its cap denies with the exact reason and releases what an earlier key reserved. */
    public function testOverCapReleasesEarlierKeys(): void
    {
        $l = self::ledger();
        $r = self::admit($l, [self::acc('p', 5, 'principal'), self::acc('o', 1000, 'org')], self::ev('a', 10));
        $this->assertSame([false, 'aggregate: over_cap: p would reach 10 (cap 5)'], [$r['admitted'], $r['reason']]);
        $this->assertSame('released', $l->snapshot('org/acme')['events'][0]->get('status'));
    }

    /** An invalid scope id is an error, not a denial. */
    public function testInvalidScopeIdThrows(): void
    {
        $this->expectException(BudgetLedgerError::class);
        $this->expectExceptionMessage('invalid: a scope id is a non-empty string');
        self::admit(self::ledger(), [self::acc('s', 100)], self::ev('a'), ['allow' => true], null, null, ['principal' => '']);
    }

    /** @param \Closure(int, string): array $reserve */
    private static function stub(\Closure $reserve): object
    {
        return new class($reserve) implements BudgetLedger {
            /** @var list<string> */
            public array $log = [];

            public function __construct(private readonly \Closure $f)
            {
            }

            public function durable(): bool
            {
                return true;
            }

            public function snapshot(mixed $key): array
            {
                return ['version' => 0, 'events' => []];
            }

            public function reserve(mixed $key, mixed $req): array
            {
                $this->log[] = $key;
                return ($this->f)(count($this->log), $key);
            }

            public function start(mixed $key, mixed $id): array
            {
                return [];
            }

            public function commit(mixed $key, mixed $id): array
            {
                return [];
            }

            public function release(mixed $key, mixed $id, mixed $evidence = null): array
            {
                return [];
            }

            public function expire(mixed $key, mixed $now): array
            {
                return ['released' => [], 'version' => 0];
            }
        };
    }

    /** A ledger that keeps moving is retried exactly 256 times (or maxAttempts, truncated), then conflict_exhausted. */
    public function testAttemptLimit(): void
    {
        foreach ([[null, 256], [2.5, 2]] as [$max, $want]) {
            $s = self::stub(static fn(int $n, string $k): array => $n > 256 ? throw new \LogicException('too many') : ['outcome' => 'conflict']);
            try {
                self::admit($s, [self::acc('s', 100)], self::ev('a'), ['allow' => true], null, $max);
                $this->fail('admitted under conflicts');
            } catch (BudgetLedgerError $e) {
                $this->assertSame('conflict_exhausted', $e->codeName);
            }
            $this->assertCount($want, $s->log);
        }
    }

    /** A moved key restarts the whole admission from its first key. */
    public function testAMovedKeyRestarts(): void
    {
        $s = self::stub(static fn(int $n, string $k): array => $n === 1 ? ['outcome' => 'conflict'] : ['outcome' => 'reserved']);
        $r = self::admit($s, [self::acc('p', 100, 'principal'), self::acc('o', 100, 'org')], self::ev('a'));
        $this->assertTrue($r['admitted']);
        $this->assertSame(['org/acme', 'org/acme', 'principal/alice'], $s->log);
        $this->assertCount(2, $r['reservations']);
    }

    /** start: settled and replayed pass, a released reservation stops the effect; settle commits or releases every reservation. */
    public function testStartAndSettle(): void
    {
        $l = self::ledger();
        $r = self::admit($l, [self::acc('p', 100, 'principal'), self::acc('o', 100, 'org')], self::ev('a'));
        $this->assertTrue(BudgetRelease::startAggregate($l, $r['reservations']));
        $this->assertTrue(BudgetRelease::startAggregate($l, $r['reservations']));
        $out = BudgetRelease::settleAggregate($l, $r['reservations'], 'committed');
        $this->assertCount(2, $out);
        $this->assertSame('committed', $l->snapshot('org/acme')['events'][0]->get('status'));
        $r2 = self::admit($l, [self::acc('p', 100, 'principal'), self::acc('o', 100, 'org')], self::ev('b'));
        BudgetRelease::settleAggregate($l, $r2['reservations'], 'released');
        $this->assertSame('released', $l->snapshot('principal/alice')['events'][1]->get('status'));
        $this->assertFalse(BudgetRelease::startAggregate($l, $r2['reservations']));
    }
}
