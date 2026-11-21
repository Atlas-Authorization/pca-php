<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ClaimResult;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\PdoOperationStore;
use Atlas\Pca\PdoStateStore;
use Atlas\Pca\StoreConformance;
use PHPUnit\Framework\TestCase;

/** The reusable store-conformance helper: real stores pass, and negative controls (stores that break each invariant) fail the right check. */
final class StoreConformanceTest extends TestCase
{
    public function testMemoryStatePassesAndDurabilityIsSkippedNotPassed(): void
    {
        $st = new MemoryStateStore();
        $r = StoreConformance::runStateStore(['durable' => false, 'name' => 'memory', 'open' => fn () => $st, 'shared' => true]);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame(['pass', 'pass', 'pass', 'skip', 'skip'], [$r->status('claim-burst'), $r->status('claim-concurrent'),
            $r->status('retry-after-timeout'), $r->status('claim-durability'), $r->status('crash-after-claim')]);
        $this->assertTrue(StoreConformance::runStateStore(['name' => 'memory', 'open' => fn () => $st, 'shared' => true, 'durable' => true])->ok());
    }

    public function testPdoStatePassesAcrossProcesses(): void
    {
        $db = tempnam(sys_get_temp_dir(), 'pcaconf');
        $open = function () use ($db): PdoStateStore {
            $pdo = new \PDO('sqlite:' . $db);
            $pdo->exec('PRAGMA busy_timeout = 10000');
            $s = new PdoStateStore($pdo);
            $s->createTable();
            return $s;
        };
        $r = StoreConformance::runStateStore(['name' => 'sqlite', 'open' => $open, 'shared' => true, 'durable' => true, 'processes' => true, 'rounds' => 4]);
        @unlink($db);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame('pass', $r->status('claim-durability'));
        $this->assertSame('pass', $r->status('crash-after-claim'));
    }

    public function testCatchesAStoreThatAdmitsOlderCounters(): void
    {
        $lax = new class {
            public function claim(string $k, int $n): ClaimResult
            {
                return new ClaimResult(true); // never refuses: replays and older counters are admitted
            }
        };
        $r = StoreConformance::runStateStore(['durable' => false, 'name' => 'lax', 'open' => fn () => $lax, 'shared' => true]);
        $this->assertFalse($r->ok());
        $this->assertSame('fail', $r->status('claim-burst'));
        $this->assertSame('fail', $r->status('claim-concurrent'));
        $this->assertStringContainsString('FAIL', (string)$r);
    }

    public function testCatchesAStoreThatForgets(): void
    {
        // every open() is a fresh empty store, yet it claims durability and sharing
        $r = StoreConformance::runStateStore(['name' => 'forgetful', 'open' => fn () => new MemoryStateStore(), 'shared' => true, 'durable' => true]);
        foreach (['claim-durability', 'crash-after-claim', 'retry-after-timeout'] as $check) {
            $this->assertSame('fail', $r->status($check), "$check\n$r");
        }
        $this->assertFalse(StoreConformance::runStateStore(['name' => 'no open'])->ok());
    }

    /** A check-then-write claim is correct one at a time and wrong under a race: forked processes must see it. */
    public function testCatchesANonAtomicClaimAcrossProcesses(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl not available');
        }
        $db = tempnam(sys_get_temp_dir(), 'pcaracy');
        $owner = getmypid();
        // The racers (forked processes) meet between their read and their write: every racer reads, then waits until a partner on the same
        // key has read too (racers pair off in arrival order through a ticket in the shared database: the kit's retry race has two racers
        // and its bursts eight, so a barrier of a fixed size would not fit both), and only then do the two write, so a pair always loses
        // an update whatever the scheduler or the machine speed does (a 20 ms sleep let a late racer run alone). The process that built
        // the double (serial setup) never waits. A racer left without a partner for 30 s records a row in rvbroken and throws; the test
        // asserts the table is empty.
        $open = function () use ($db, $owner): object {
            $pdo = new \PDO('sqlite:' . $db);
            $pdo->exec('PRAGMA busy_timeout = 10000');
            $pdo->exec('CREATE TABLE IF NOT EXISTS racy (k TEXT PRIMARY KEY, n INTEGER NOT NULL)');
            $pdo->exec('CREATE TABLE IF NOT EXISTS rv (k TEXT PRIMARY KEY, n INTEGER NOT NULL)');
            $pdo->exec('CREATE TABLE IF NOT EXISTS rvbroken (msg TEXT NOT NULL)');
            return new class($pdo, $owner) {
                public function __construct(private readonly \PDO $pdo, private readonly int $owner)
                {
                }

                public function claim(string $k, int $n): ClaimResult
                {
                    $q = $this->pdo->prepare('SELECT n FROM racy WHERE k = ?');
                    $q->execute([$k]);
                    $last = $q->fetchColumn();
                    if (getmypid() !== $this->owner) {
                        $this->meet($k);
                    }
                    if ($last !== false && $n <= (int)$last) {
                        return new ClaimResult(false, (int)$last);
                    }
                    $this->pdo->prepare('INSERT INTO racy (k, n) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET n = excluded.n')->execute([$k, $n]);
                    return new ClaimResult(true);
                }

                private function meet(string $k): void
                {
                    $this->pdo->exec('BEGIN IMMEDIATE');
                    $this->pdo->prepare('INSERT INTO rv (k, n) VALUES (?, 1) ON CONFLICT (k) DO UPDATE SET n = n + 1')->execute([$k]);
                    $q = $this->pdo->prepare('SELECT n FROM rv WHERE k = ?');
                    $q->execute([$k]);
                    $ticket = (int)$q->fetchColumn();
                    $this->pdo->exec('COMMIT');
                    $target = intdiv($ticket + 1, 2) * 2;
                    $deadline = microtime(true) + 30;
                    while (true) {
                        $q = $this->pdo->prepare('SELECT n FROM rv WHERE k = ?');
                        $q->execute([$k]);
                        if ((int)$q->fetchColumn() >= $target) {
                            return;
                        }
                        if (microtime(true) > $deadline) {
                            $this->pdo->prepare('INSERT INTO rvbroken (msg) VALUES (?)')->execute(["no partner reached the rendezvous on $k"]);
                            throw new \RuntimeException("no partner reached the rendezvous on $k");
                        }
                        usleep(1000); // waiting for the partner's ticket, not a window that provokes the race
                    }
                }
            };
        };
        $r = StoreConformance::runStateStore(['durable' => false, 'name' => 'racy', 'open' => $open, 'shared' => true, 'processes' => true, 'rounds' => 2, 'copies' => 8]);
        $check = new \PDO('sqlite:' . $db);
        $broken = (int)$check->query('SELECT COUNT(*) FROM rvbroken')->fetchColumn();
        $check = null;
        @unlink($db);
        $this->assertSame(0, $broken, 'the racers did not all reach the rendezvous');
        $this->assertSame('pass', $r->status('claim-burst'), (string)$r);
        $this->assertSame('fail', $r->status('claim-concurrent'), (string)$r);
    }

    public function testOperationStores(): void
    {
        $mem = new MemoryOperationStore();
        $this->assertTrue(StoreConformance::runOperationStore(['name' => 'memory', 'open' => fn () => $mem, 'shared' => true, 'durable' => true])->ok());
        $db = tempnam(sys_get_temp_dir(), 'pcaopconf');
        $open = function () use ($db): PdoOperationStore {
            $pdo = new \PDO('sqlite:' . $db);
            $pdo->exec('PRAGMA busy_timeout = 10000');
            $s = new PdoOperationStore($pdo);
            $s->createTable();
            return $s;
        };
        $r = StoreConformance::runOperationStore(['name' => 'sqlite', 'open' => $open, 'shared' => true, 'durable' => true, 'processes' => true]);
        @unlink($db);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame('pass', $r->status('create-once'));
    }

    public function testOperationStoreNegativeControls(): void
    {
        // a store that forgets between handles fails the shared and durability checks
        $r = StoreConformance::runOperationStore(['name' => 'forgetful', 'open' => fn () => new MemoryOperationStore(), 'shared' => true, 'durable' => true]);
        $this->assertSame('fail', $r->status('shared'));
        $this->assertSame('fail', $r->status('durability'));
        // a transition that ignores the expected state fails wrong-state
        $loose = new class implements \Atlas\Pca\OperationStore {
            private array $m = [];
            public function create(OperationRecord $rec): array
            {
                if (isset($this->m[$rec->id])) {
                    return [false, $this->m[$rec->id]];
                }
                $this->m[$rec->id] = $rec;
                return [true, null];
            }
            public function get(string $id): ?OperationRecord { return $this->m[$id] ?? null; }
            public function transition(string $id, string $from, OperationRecord $next): bool
            {
                $this->m[$id] = $next;
                return true;
            }
        };
        $r = StoreConformance::runOperationStore(['durable' => false, 'name' => 'loose', 'open' => fn () => $loose, 'shared' => true]);
        $this->assertSame('fail', $r->status('wrong-state'));
        $this->assertSame('fail', $r->status('transition-once'));
        $this->assertFalse(StoreConformance::runOperationStore(['name' => 'x'])->ok());
    }
}
