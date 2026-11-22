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

    /**
     * Runs the state-store kit against a check-then-write claim whose racers (forked processes) meet between their read and their
     * write, and returns [report, whether a racer gave up waiting, what every racer that threw reported].
     *
     * The meeting is sized from the racers that really exist, never from an assumed count. The process that forks them registers every
     * racer (a token made before the fork, written while the gate is still shut, so all are registered before any runs). Each racer
     * takes an exclusive lock on its own `alive` file the moment it is forked and keeps it until its process ends: the kernel releases
     * it however the process ends (exit, crash, kill), which a shutdown function cannot promise. A racer that has read waits until every
     * registered racer has read the same key or is dead (it had started and its lock is free), then all of them write, so whoever is
     * alive always loses an update whatever the scheduler or the machine speed does, for an even or an odd number of racers, and one
     * that dies before it claims never strands the others. The process that built the double (serial setup) never waits. A racer left
     * waiting for 30 s writes a `broken` marker naming each racer it still waits for and the last step that one reported, and throws. The
     * markers live outside the database so that polling never holds a lock on it.
     *
     * @return array{0: \Atlas\Pca\ConformanceReport, 1: bool, 2: string}
     */
    private function runRacy(bool $firstRacerDies): array
    {
        $db = tempnam(sys_get_temp_dir(), 'pcaracy');
        $rv = $db . '.rv';
        mkdir($rv);
        $racer = new \stdClass();
        $racer->token = null; // set in a forked racer only
        $racer->alive = null; // the open lock file of a forked racer
        // Every step a racer takes is noted in its `phase` file; one that throws also writes the step, the exception class and its
        // message to an `error.*` file: the harness reports a throwing copy only as a code, and a racer that dies early is a defect to
        // see, not to absorb.
        $note = static function (string $step, ?\Throwable $e = null) use ($rv, $racer): void {
            if ($racer->token === null) {
                return;
            }
            file_put_contents($rv . '/' . $racer->token . '.phase', $step);
            if ($e !== null) {
                file_put_contents($rv . '/error.' . $racer->token . '.' . $step, $step . ': ' . $e::class . ': ' . $e->getMessage() . "\n");
            }
        };
        $open = function () use ($db, $rv, $racer, $firstRacerDies, $note): object {
            $note('open');
            try {
                if ($firstRacerDies && $racer->token !== null && @fopen($rv . '/died', 'x') !== false) {
                    throw new \RuntimeException('this racer dies before it claims');
                }
                $pdo = new \PDO('sqlite:' . $db);
                $pdo->exec('PRAGMA busy_timeout = 10000');
                $pdo->exec('CREATE TABLE IF NOT EXISTS racy (k TEXT PRIMARY KEY, n INTEGER NOT NULL)');
            } catch (\Throwable $e) {
                $note('open', $e);
                throw $e;
            }
            return new class($pdo, $racer, $rv, $note) {
                public function __construct(private readonly \PDO $pdo, private readonly \stdClass $racer, private readonly string $rv, private readonly \Closure $note)
                {
                }

                public function claim(string $k, int $n): ClaimResult
                {
                    $step = 'select';
                    try {
                        ($this->note)($step);
                        $q = $this->pdo->prepare('SELECT n FROM racy WHERE k = ?');
                        $q->execute([$k]);
                        $last = $q->fetchColumn();
                        $q->closeCursor();
                        if ($this->racer->token !== null) {
                            $step = 'meet';
                            ($this->note)($step);
                            $this->meet($k, $this->racer->token);
                        }
                        if ($last !== false && $n <= (int)$last) {
                            return new ClaimResult(false, (int)$last);
                        }
                        $step = 'insert';
                        ($this->note)($step);
                        $this->pdo->prepare('INSERT INTO racy (k, n) VALUES (?, ?) ON CONFLICT (k) DO UPDATE SET n = excluded.n')->execute([$k, $n]);
                        return new ClaimResult(true);
                    } catch (\Throwable $e) {
                        ($this->note)($step, $e);
                        throw $e;
                    }
                }

                private function meet(string $k, string $me): void
                {
                    $h = md5($k);
                    touch($this->rv . '/' . $h . '.' . $me);
                    $deadline = microtime(true) + 30;
                    while (($absent = $this->absent($h)) !== []) {
                        if (microtime(true) > $deadline) {
                            $why = "a registered racer never reached the rendezvous on $k; still waiting for: " . implode('; ', $absent);
                            file_put_contents($this->rv . '/broken', $why . "\n", FILE_APPEND);
                            throw new \RuntimeException($why);
                        }
                        usleep(1000); // waiting for the others' markers, not a window that provokes the race
                    }
                    $this->gateReleased($me);
                }

                /**
                 * Every racer has started by now, so none may still hold the harness's start gate: it lets go of it as soon as its copy
                 * starts, since a racer that kept it would hold up the racers still queued behind it (and these racers wait for each other).
                 * Probes from racers that meet at the same moment collide, so a refusal is retried for a while before it counts.
                 */
                private function gateReleased(string $me): void
                {
                    $path = (string)@file_get_contents($this->rv . '/' . $me . '.gate');
                    $f = $path === '' ? false : @fopen($path, 'r');
                    if ($f === false) {
                        return;
                    }
                    for ($i = 0; $i < 300; $i++) {
                        if (flock($f, LOCK_EX | LOCK_NB)) {
                            fclose($f);
                            return;
                        }
                        usleep(10000);
                    }
                    fclose($f);
                    throw new \RuntimeException('a racer still holds the start gate: the harness kept it while the racer ran');
                }

                /** @return list<string> the registered racers that have neither read this key nor died, with what is known of each */
                private function absent(string $h): array
                {
                    $out = [];
                    foreach (glob($this->rv . '/*.expected') ?: [] as $e) {
                        $t = basename($e, '.expected');
                        if (file_exists($this->rv . '/' . $h . '.' . $t)) {
                            continue;
                        }
                        $started = file_exists($this->rv . '/' . $t . '.started');
                        if ($started && $this->dead($t)) {
                            continue;
                        }
                        $phase = @file_get_contents($this->rv . '/' . $t . '.phase');
                        $out[] = $t . ' started=' . ($started ? 'yes' : 'no') . ' phase=' . ($phase === false ? 'none' : $phase);
                    }
                    return $out;
                }

                /** A started racer holds its lock for as long as it lives, so a free lock means the process is gone. */
                private function dead(string $t): bool
                {
                    $f = @fopen($this->rv . '/' . $t . '.alive', 'r');
                    if ($f === false) {
                        return false;
                    }
                    $free = flock($f, LOCK_SH | LOCK_NB);
                    fclose($f); // the probe's own lock goes with it
                    return $free;
                }
            };
        };
        StoreConformance::$forkHook = static function () use ($rv, $racer): int {
            $token = bin2hex(random_bytes(6));
            $pid = pcntl_fork();
            if ($pid > 0) {
                touch($rv . '/' . $token . '.expected'); // the gate is still shut: registered before any racer runs
                $gates = glob(sys_get_temp_dir() . '/pcagate*') ?: []; // the harness made its gate just before it forked: the newest
                usort($gates, static fn (string $x, string $y): int => filemtime($y) <=> filemtime($x));
                file_put_contents($rv . '/' . $token . '.gate', $gates[0] ?? '');
            } elseif ($pid === 0) {
                $racer->token = $token;
                file_put_contents($rv . '/' . $token . '.phase', 'forked'); // still there when the racer never got past the gate
                $racer->alive = fopen($rv . '/' . $token . '.alive', 'c');
                flock($racer->alive, LOCK_EX); // never released by this code: the process ending releases it
                touch($rv . '/' . $token . '.started');
            }
            return $pid;
        };
        try {
            $r = StoreConformance::runStateStore(['durable' => false, 'name' => 'racy', 'open' => $open, 'shared' => true, 'processes' => true, 'rounds' => 2, 'copies' => 8]);
        } finally {
            StoreConformance::$forkHook = null;
        }
        $broken = file_exists($rv . '/broken');
        $errors = '';
        foreach (glob($rv . '/error.*') ?: [] as $f) {
            $errors .= (string)file_get_contents($f);
        }
        if ($broken) {
            $errors .= (string)file_get_contents($rv . '/broken');
        }
        foreach (glob($rv . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($rv);
        @unlink($db);
        return [$r, $broken, $errors];
    }

    /** A check-then-write claim is correct one at a time and wrong under a race: forked processes must see it. */
    public function testCatchesANonAtomicClaimAcrossProcesses(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl not available');
        }
        [$r, $broken, $errors] = $this->runRacy(false);
        $this->assertSame('', $errors, "a racer threw:\n" . $errors);
        $this->assertFalse($broken, 'the racers did not all reach the rendezvous');
        $this->assertSame('pass', $r->status('claim-burst'), (string)$r);
        $this->assertSame('fail', $r->status('claim-concurrent'), (string)$r);
    }

    /** A racer that dies before it claims leaves an odd number of live racers: the rest must still meet (not wait out the limit) and the race still be caught. */
    public function testARacerThatDiesBeforeClaimingDoesNotStrandTheOthers(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl not available');
        }
        [$r, $broken, $errors] = $this->runRacy(true); // the injected death is the point: its own error file is not asserted away
        $this->assertFalse($broken, 'a dead racer stranded the others at the rendezvous: ' . $errors);
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
