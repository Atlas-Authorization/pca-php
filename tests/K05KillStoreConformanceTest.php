<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/StoreConformance.php';

use Atlas\Pca\ClaimResult;
use Atlas\Pca\ConformanceReport;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\StoreConformance;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for StoreConformance: every run goes through a recording store (a file-backed backend, so forked copies
 * share it) and pins the exact report, the exact sequence of store calls (handles, keys, counters, answers) and the key format;
 * deliberately broken stores pin each failure note; the forked path is pinned through the fork seam (the gate holds every copy
 * until all are forked, a failed fork fails the check) and the per-copy body through child() in-process.
 */
final class K05KillStoreConformanceTest extends TestCase
{
    /** @var list<string> */
    private array $files = [];

    protected function tearDown(): void
    {
        StoreConformance::$forkHook = null;
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    private function backend(?\Closure $tweak = null): K05ScBackend
    {
        $b = new K05ScBackend($tweak);
        $this->files[] = $b->path;
        return $b;
    }

    /** @return list<array{string,string,string}> */
    private static function checks(ConformanceReport $r): array
    {
        return array_map(static fn($c): array => [$c->name, $c->status, $c->note], $r->checks);
    }

    /** @return list<string> "h$h $prefix $n T|F" for counters $from..$to (step +1 or -1) */
    private static function claims(int $h, string $p, int $from, int $to, string $ans): array
    {
        return array_map(static fn(int $n): string => "h$h $p $n $ans", range($from, $to));
    }

    private static function canFork(): bool
    {
        return function_exists('pcntl_fork') && function_exists('pcntl_waitpid');
    }

    private const NOT_DURABLE = 'durable is false (state dies with the process)';

    public function testStateStoreExactCallSequenceReportAndKeys(): void
    {
        $b = $this->backend();
        $r = StoreConformance::runStateStore(['name' => 'rec', 'open' => $b->opener(), 'restart' => $b->restarter(), 'shared' => true,
            'durable' => true, 'rounds' => 2, 'copies' => 3, 'handles' => 2]);
        $this->assertSame('rec', $r->name);
        $this->assertSame([
            ['claim-burst', 'pass', ''],
            ['claim-concurrent', 'pass', '2 rounds x 3 copies over 2 handle(s), sequential interleavings'],
            ['claim-durability', 'pass', ''],
            ['crash-after-claim', 'pass', ''],
            ['retry-after-timeout', 'pass', ''],
        ], self::checks($r));
        $st = $b->state();
        $this->assertSame(array_merge(
            ['open h1'], self::claims(1, 'burst', 1, 25, 'T'), self::claims(1, 'burst', 25, 1, 'F'), ['h1 burst 26 T', 'h1 burst-other 1 T'],
            ['open h2', 'open h3',
                'h2 concurrent 1 T', 'h3 concurrent 1 F', 'h2 concurrent 1 F',
                'h2 concurrent 2 T', 'h3 concurrent 2 F', 'h2 concurrent 2 F',
                'h2 concurrent-distinct 3 T', 'h3 concurrent-distinct 4 T', 'h2 concurrent-distinct 5 T',
                'h2 concurrent-distinct 3 F', 'h2 concurrent-distinct 4 F', 'h2 concurrent-distinct 5 F'],
            ['open h4', 'h4 durability 1 T', 'h4 durability 2 T', 'h4 durability 3 T', 'restart', 'open h5', 'h5 durability 3 F', 'h5 durability 4 T'],
            ['open h6', 'h6 crash 1 T', 'restart', 'open h7', 'h7 crash 1 F', 'h7 crash 2 T'],
            ['open h8', 'open h9', 'h8 retry 1 T', 'h9 retry 1 F', 'h9 retry 2 T'],
        ), $st['log']);
        // conf:<pid>:<seq>:<prefix>:<8 hex>, one fresh sequence number per key
        $seqs = [];
        foreach (['burst', 'burst-other', 'concurrent', 'concurrent-distinct', 'durability', 'crash', 'retry'] as $i => $p) {
            $this->assertMatchesRegularExpression('/^conf:' . getmypid() . ':(\d+):' . $p . ':[0-9a-f]{8}$/', $st['keys'][$i]);
            $seqs[] = (int)explode(':', $st['keys'][$i])[2];
        }
        $this->assertCount(7, $st['keys']);
        $this->assertSame(range($seqs[0], $seqs[0] + 6), $seqs);
        $line = static fn(string $s, string $n, string $note = ''): string => '  [' . $s . '] ' . str_pad($n, 20) . ' ' . $note . "\n";
        $this->assertSame('store conformance: rec -> PASS' . "\n" . $line('PASS', 'claim-burst')
            . $line('PASS', 'claim-concurrent', '2 rounds x 3 copies over 2 handle(s), sequential interleavings')
            . $line('PASS', 'claim-durability') . $line('PASS', 'crash-after-claim') . $line('PASS', 'retry-after-timeout'), (string)$r);
    }

    /** Unshared: one handle for the race, and the retry goes through the same (lossy) instance, which loses one answer only. */
    public function testStateStoreUnsharedRetriesThroughTheSameInstance(): void
    {
        $b = $this->backend();
        $r = StoreConformance::runStateStore(['shared' => false, 'durable' => false, 'open' => $b->opener(), 'rounds' => 1, 'copies' => 2]);
        $this->assertSame('state store', $r->name);
        $this->assertSame([
            ['claim-burst', 'pass', ''],
            ['claim-concurrent', 'pass', '1 rounds x 2 copies over 1 handle(s), sequential interleavings'],
            ['claim-durability', 'skip', self::NOT_DURABLE],
            ['crash-after-claim', 'skip', self::NOT_DURABLE],
            ['retry-after-timeout', 'pass', ''],
        ], self::checks($r));
        $this->assertSame(['open h2', 'h2 concurrent 1 T', 'h2 concurrent 1 F', 'h2 concurrent-distinct 2 T', 'h2 concurrent-distinct 3 T',
            'h2 concurrent-distinct 2 F', 'h2 concurrent-distinct 3 F', 'open h3', 'h3 retry 1 T', 'h3 retry 1 F', 'h3 retry 2 T'],
            array_slice($b->state()['log'], 53));
    }

    /** Undeclared capabilities are required, as the reference (pca-state.ts: durable and shared default true): skipped only when declared false. */
    public function testUndeclaredCapabilitiesAreChecked(): void
    {
        $mem = new MemoryStateStore();
        $this->assertSame([
            ['claim-burst', 'pass', ''],
            ['claim-concurrent', 'pass', '10 rounds x 16 copies over 4 handle(s), sequential interleavings'],
            ['claim-durability', 'pass', ''],
            ['crash-after-claim', 'pass', ''],
            ['retry-after-timeout', 'pass', ''],
        ], self::checks(StoreConformance::runStateStore(['open' => fn() => $mem])));
        $ops = new MemoryOperationStore();
        $this->assertSame([['create-once', 'pass', ''], ['transition-once', 'pass', ''], ['wrong-state', 'pass', ''], ['get-missing', 'pass', ''],
            ['shared', 'pass', ''], ['durability', 'pass', '']], self::checks(StoreConformance::runOperationStore(['open' => fn() => $ops])));
    }

    public function testStateStoreDefaults(): void
    {
        $mem = new MemoryStateStore();
        $r = StoreConformance::runStateStore(['shared' => false, 'durable' => false, 'open' => fn() => $mem]);
        $want = [
            ['claim-burst', 'pass', ''],
            ['claim-concurrent', 'pass', '10 rounds x 16 copies over 1 handle(s), sequential interleavings'],
            ['claim-durability', 'skip', self::NOT_DURABLE],
            ['crash-after-claim', 'skip', self::NOT_DURABLE],
            ['retry-after-timeout', 'pass', ''],
        ];
        $this->assertSame($want, self::checks($r));
        $line = static fn(string $s, string $n, string $note = ''): string => '  [' . $s . '] ' . str_pad($n, 20) . ' ' . $note . "\n";
        $this->assertSame('store conformance: state store -> PASS' . "\n" . $line('PASS', 'claim-burst')
            . $line('PASS', 'claim-concurrent', '10 rounds x 16 copies over 1 handle(s), sequential interleavings')
            . $line('SKIP', 'claim-durability', self::NOT_DURABLE) . $line('SKIP', 'crash-after-claim', self::NOT_DURABLE)
            . $line('PASS', 'retry-after-timeout'), (string)$r);
        $mem2 = new MemoryStateStore();
        $r = StoreConformance::runStateStore(['open' => fn() => $mem2, 'shared' => true, 'durable' => false, 'rounds' => 1]);
        $this->assertTrue($r->ok(), (string)$r);
        $this->assertSame('1 rounds x 16 copies over 4 handle(s), sequential interleavings', $r->checks[1]->note);
        $this->assertSame('42', StoreConformance::runStateStore(['name' => 42])->name);
        $this->assertSame('42', StoreConformance::runOperationStore(['name' => 42])->name);
        $this->assertSame('x', StoreConformance::runOperationStore(['name' => 'x', 'open' => 1])->name);
        $this->assertSame('operation store', StoreConformance::runOperationStore([])->name);
    }

    /** A thrown error becomes "<class>: <message>" in place of the note, and the report reads FAIL. */
    public function testThrowingOpenFailsEveryCheckWithTheClassAndMessage(): void
    {
        $open = static fn(): object => throw new \RuntimeException('boom');
        $boom = 'RuntimeException: boom';
        $r = StoreConformance::runStateStore(['name' => 'b', 'open' => $open, 'shared' => true, 'durable' => true]);
        $this->assertSame([['claim-burst', 'fail', $boom], ['claim-concurrent', 'fail', $boom], ['claim-durability', 'fail', $boom],
            ['crash-after-claim', 'fail', $boom], ['retry-after-timeout', 'fail', $boom]], self::checks($r));
        $line = static fn(string $n): string => '  [FAIL] ' . str_pad($n, 20) . ' ' . $boom . "\n";
        $this->assertSame('store conformance: b -> FAIL' . "\n" . $line('claim-burst') . $line('claim-concurrent') . $line('claim-durability')
            . $line('crash-after-claim') . $line('retry-after-timeout'), (string)$r);
        $r = StoreConformance::runOperationStore(['open' => $open, 'shared' => true, 'durable' => true]);
        $this->assertSame([['create-once', 'fail', $boom], ['transition-once', 'fail', $boom], ['wrong-state', 'fail', $boom],
            ['get-missing', 'fail', $boom], ['shared', 'fail', $boom], ['durability', 'fail', $boom]], self::checks($r));
    }

    /** Wins, refusals and errors are told apart: 2 admitted, 1 thrown, 2 refused out of 5 copies. */
    public function testConcurrentRoundNoteCountsWinsAndErrors(): void
    {
        $b = $this->backend(static fn(string $op, string $p, int $n, int $call, mixed $d): mixed => $p !== 'concurrent' ? $d
            : match ($call) { 1 => new ClaimResult(true), 2 => throw new \RuntimeException('lost'), default => $d });
        $r = StoreConformance::runStateStore(['durable' => false, 'open' => $b->opener(), 'shared' => true, 'handles' => 2, 'rounds' => 2, 'copies' => 5]);
        $this->assertSame(['claim-concurrent', 'fail', 'round 1: 2 of 5 copies of one counter were admitted (want exactly 1; 1 errors)'],
            self::checks($r)[1]);
        $this->assertSame(['h2 concurrent 1 T', 'h3 concurrent 1 T', 'h2 concurrent 1 E', 'h3 concurrent 1 F', 'h2 concurrent 1 F'],
            array_values(array_filter($b->state()['log'], static fn(string $e): bool => str_contains($e, ' concurrent '))));
    }

    public function testConcurrentDistinctHighestMustBeAdmitted(): void
    {
        $b = $this->backend(static fn(string $op, string $p, int $n, int $call, mixed $d): mixed
            => $p === 'concurrent-distinct' && $call === 2 ? new ClaimResult(false) : $d);
        $r = StoreConformance::runStateStore(['shared' => false, 'durable' => false, 'open' => $b->opener(), 'rounds' => 1, 'copies' => 3]);
        $this->assertSame(['claim-concurrent', 'fail', 'the highest of 3 racing counters was not admitted'], self::checks($r)[1]);
    }

    public function testConcurrentDistinctReadmissionAfterTheRace(): void
    {
        $b = $this->backend(static fn(string $op, string $p, int $n, int $call, mixed $d): mixed
            => $p === 'concurrent-distinct' && $call === 5 ? new ClaimResult(true) : $d);
        $r = StoreConformance::runStateStore(['shared' => false, 'durable' => false, 'open' => $b->opener(), 'rounds' => 1, 'copies' => 3]);
        $this->assertSame(['claim-concurrent', 'fail', 'counter 4 is admitted again after the race'], self::checks($r)[1]);
    }

    /** Only a bool or a ClaimResult is an answer; anything else (even with an `ok` property) is an error. */
    public function testClaimNormalisesTheAnswer(): void
    {
        $claim = new \ReflectionMethod(StoreConformance::class, 'claim');
        $store = static fn(mixed $answer): object => new class($answer) {
            public function __construct(private readonly mixed $answer)
            {
            }

            public function claim(string $k, int $n): mixed
            {
                return $this->answer;
            }
        };
        $this->assertNull($claim->invoke(null, $store((object)['ok' => true]), 'k', 1));
        $this->assertTrue($claim->invoke(null, $store(true), 'k', 1));
        $this->assertFalse($claim->invoke(null, $store(new ClaimResult(false)), 'k', 1));
    }

    /** The per-copy body, in-process: it waits at the gate, passes its index, and maps a throw to 12. */
    public function testChildWaitsAtTheGateAndMapsAThrowTo12(): void
    {
        $child = new \ReflectionMethod(StoreConformance::class, 'child');
        $gate = (string)tempnam(sys_get_temp_dir(), 'k05gate');
        $this->files[] = $gate;
        $this->assertSame(10, $child->invoke(null, $gate, static fn(int $i): int => $i + 7, 3));
        $this->assertSame(12, $child->invoke(null, $gate, static fn(int $i): int => throw new \LogicException('x'), 0));
        // another process holds the gate shut for 2 s: the copy must wait for it
        $p = proc_open([PHP_BINARY, '-r', '$h = fopen($argv[1], "c"); flock($h, LOCK_EX); echo "L\n"; fflush(STDOUT); usleep(2000000);', $gate],
            [1 => ['pipe', 'w']], $pipes);
        $this->assertIsResource($p);
        $this->assertSame("L\n", fgets($pipes[1]));
        $t = microtime(true);
        $this->assertSame(11, $child->invoke(null, $gate, static fn(int $i): int => 11, 0));
        $waited = microtime(true) - $t;
        fclose($pipes[1]);
        proc_close($p);
        $this->assertGreaterThan(1.0, $waited);
    }

    /** Forked copies on a backend shared between processes: each copy opens its own handle, and none reaches the store before the
     *  parent has forked them all (the gate). */
    public function testForkedRaceExactCopiesBehindTheGate(): void
    {
        if (!self::canFork()) {
            $this->markTestSkipped('pcntl not available');
        }
        $b = $this->backend();
        $probe = null;
        StoreConformance::$forkHook = static function () use ($b, &$probe): int {
            $before = $b->opens();
            $pid = pcntl_fork();
            if ($pid === 0 || $probe !== null) {
                return $pid;
            }
            // the first copy is forked: with the gate shut it cannot reach the store, however long we wait
            $until = microtime(true) + 1.5;
            while (microtime(true) < $until && $b->opens() === $before) {
                usleep(10000);
            }
            $probe = $b->opens() - $before;
            return $pid;
        };
        $r = StoreConformance::runStateStore(['open' => $b->opener(), 'restart' => $b->restarter(), 'shared' => true, 'durable' => true,
            'processes' => true, 'rounds' => 2, 'copies' => 3, 'handles' => 2]);
        $this->assertSame(0, $probe);
        $this->assertSame([
            ['claim-burst', 'pass', ''],
            ['claim-concurrent', 'pass', '2 rounds x 3 copies over 2 handle(s), forked processes'],
            ['claim-durability', 'pass', ''],
            ['crash-after-claim', 'pass', ''],
            ['retry-after-timeout', 'pass', ''],
        ], self::checks($r), (string)$r);
        $log = $b->state()['log'];
        $strip = static fn(string $e): string => (string)preg_replace('/^h\d+ /', '', $e);
        $conc = array_map($strip, array_values(array_filter($log, static fn(string $e): bool => preg_match('/^h\d+ concurrent \d/', $e) === 1)));
        sort($conc);
        $this->assertSame(['concurrent 1 F', 'concurrent 1 F', 'concurrent 1 T', 'concurrent 2 F', 'concurrent 2 F', 'concurrent 2 T'], $conc);
        $dist = array_values(array_filter($log, static fn(string $e): bool => preg_match('/^h\d+ concurrent-distinct /', $e) === 1));
        $this->assertSame(['h2 concurrent-distinct 3 F', 'h2 concurrent-distinct 4 F', 'h2 concurrent-distinct 5 F'], array_slice($dist, 3));
        $raced = array_map(static fn(string $e): string => substr($strip($e), 0, -2), array_slice($dist, 0, 3));
        sort($raced);
        $this->assertSame(['concurrent-distinct 3', 'concurrent-distinct 4', 'concurrent-distinct 5'], $raced);
        $this->assertContains('concurrent-distinct 5 T', array_map($strip, $dist));
        // burst 1 + race handles 2 + one handle per copy (2 x 3 + 3) + durability 2 + crash 2 + retry 2
        $this->assertSame(18, $b->opens());
    }

    public function testForkFailureFailsTheCheck(): void
    {
        if (!self::canFork()) {
            $this->markTestSkipped('pcntl not available');
        }
        StoreConformance::$forkHook = static fn(): int => -1;
        $mem = new MemoryStateStore();
        $r = StoreConformance::runStateStore(['shared' => false, 'durable' => false, 'open' => fn() => $mem, 'processes' => true, 'rounds' => 1, 'copies' => 2]);
        $this->assertSame(['claim-concurrent', 'fail', 'RuntimeException: conformance: fork failed'], self::checks($r)[1]);
        $this->assertSame('pass', $r->status('claim-burst'));
    }

    public function testOperationStoreExactCallSequence(): void
    {
        $b = $this->backend();
        $r = StoreConformance::runOperationStore(['name' => 'ops', 'open' => $b->opener(), 'restart' => $b->restarter(), 'shared' => true,
            'durable' => true, 'copies' => 3]);
        $this->assertSame('ops', $r->name);
        $this->assertSame([['create-once', 'pass', ''], ['transition-once', 'pass', ''], ['wrong-state', 'pass', ''], ['get-missing', 'pass', ''],
            ['shared', 'pass', ''], ['durability', 'pass', '']], self::checks($r));
        $this->assertSame([
            'open h1', 'open h2', 'h1 create create pending 1 T', 'h2 create create pending 1 F', 'h1 create create pending 1 F',
            'open h3', 'open h4', 'h3 create transition pending 1 T', 'h3 transition transition pending>executing 1 T',
            'h4 transition transition pending>executing 1 F', 'h3 transition transition pending>executing 1 F',
            'open h5', 'h5 create wrong pending 1 T', 'h5 transition wrong executing>committed 1 F', 'h5 get wrong',
            'h5 transition missing pending>committed 1 F',
            'open h6', 'h6 get never',
            'open h7', 'open h8', 'h7 create shared pending 1 T', 'h8 get shared',
            'open h9', 'h9 create durable pending 1 T', 'restart', 'open h10', 'h10 get durable',
        ], $b->state()['log']);
    }

    public function testOperationStoreDefaults(): void
    {
        $b = $this->backend();
        $r = StoreConformance::runOperationStore(['shared' => false, 'durable' => false, 'open' => $b->opener()]);
        $this->assertSame([['create-once', 'pass', ''], ['transition-once', 'pass', ''], ['wrong-state', 'pass', ''], ['get-missing', 'pass', ''],
            ['shared', 'skip', 'shared is false'], ['durability', 'skip', 'durable is false']], self::checks($r));
        $this->assertSame(array_merge(
            ['open h1', 'h1 create create pending 1 T'], array_fill(0, 15, 'h1 create create pending 1 F'),
            ['open h2', 'h2 create transition pending 1 T', 'h2 transition transition pending>executing 1 T'],
            array_fill(0, 15, 'h2 transition transition pending>executing 1 F'),
            ['open h3', 'h3 create wrong pending 1 T', 'h3 transition wrong executing>committed 1 F', 'h3 get wrong',
                'h3 transition missing pending>committed 1 F', 'open h4', 'h4 get never'],
        ), $b->state()['log']);
    }

    /** A loser that is not handed the existing record fails create-once even when exactly one create won. */
    public function testCreateOnceLoserWithoutTheRecord(): void
    {
        $b = $this->backend(static fn(string $op, string $p, int $n, int $call, mixed $d): mixed
            => $op === 'create' && $p === 'create' && $call > 0 ? [false, null] : $d);
        $r = StoreConformance::runOperationStore(['durable' => false, 'open' => $b->opener(), 'shared' => true, 'copies' => 3]);
        $this->assertSame(['create-once', 'fail',
            '1 concurrent creates of one id reported created (want exactly 1; a loser must be handed the existing record)'], self::checks($r)[0]);
    }

    /** A refused transition that changes the record anyway fails wrong-state. */
    public function testWrongStateRecordChangedByARefusedTransition(): void
    {
        $lying = new class {
            /** @var array<string,OperationRecord> */
            private array $m = [];

            public function create(OperationRecord $rec): array
            {
                if (isset($this->m[$rec->id])) {
                    return [false, $this->m[$rec->id]];
                }
                $this->m[$rec->id] = $rec;
                return [true, null];
            }

            public function get(string $id): ?OperationRecord
            {
                return $this->m[$id] ?? null;
            }

            public function transition(string $id, string $from, OperationRecord $next): bool
            {
                $this->m[$id] = $next;
                return false;
            }
        };
        $r = StoreConformance::runOperationStore(['shared' => false, 'durable' => false, 'open' => fn() => $lying]);
        $this->assertSame(['wrong-state', 'fail', 'the record changed after a refused transition'], self::checks($r)[2]);
    }
}

/** A correct replay + operation store whose state lives in a file (shared by forked copies), recording every call. */
final class K05ScBackend
{
    public readonly string $path;

    /** @param ?\Closure(string, string, int, int, mixed): mixed $tweak (op, key prefix, counter, call index on that key, the correct answer) -> the answer; may throw */
    public function __construct(private readonly ?\Closure $tweak = null)
    {
        $this->path = (string)tempnam(sys_get_temp_dir(), 'k05sc');
        file_put_contents($this->path, serialize(['h' => 0, 'last' => [], 'calls' => [], 'ops' => [], 'log' => [], 'keys' => []]));
    }

    /** @return array{h:int, last:array<string,int>, calls:array<string,int>, ops:array<string,OperationRecord>, log:list<string>, keys:list<string>} */
    public function state(): array
    {
        return $this->locked(static fn(array &$st): array => $st);
    }

    public function opens(): int
    {
        return $this->state()['h'];
    }

    public function opener(): \Closure
    {
        return fn(): K05ScHandle => new K05ScHandle($this, $this->locked(static function (array &$st): int {
            $st['log'][] = 'open h' . ++$st['h'];
            return $st['h'];
        }));
    }

    public function restarter(): \Closure
    {
        return fn() => $this->locked(static function (array &$st): void {
            $st['log'][] = 'restart';
        });
    }

    private function locked(\Closure $f): mixed
    {
        $h = fopen($this->path, 'c+');
        flock($h, LOCK_EX);
        $st = unserialize((string)stream_get_contents($h));
        $out = $f($st);
        ftruncate($h, 0);
        rewind($h);
        fwrite($h, serialize($st));
        fflush($h);
        flock($h, LOCK_UN);
        fclose($h);
        return $out;
    }

    /** Runs $f(&$st, $prefix, $call) -> [correct answer, log line without the answer], then the tweak, under the lock; rethrows. */
    private function call(string $op, string $key, int $n, \Closure $f, \Closure $flag): mixed
    {
        [$r, $e] = $this->locked(function (array &$st) use ($op, $key, $n, $f, $flag): array {
            $p = explode(':', $key)[3] ?? '?';
            if (!in_array($key, $st['keys'], true)) {
                $st['keys'][] = $key;
            }
            $call = $st['calls']["$op $key"] = ($st['calls']["$op $key"] ?? -1) + 1;
            [$d, $line] = $f($st, $p);
            $e = null;
            try {
                $r = $this->tweak !== null ? ($this->tweak)($op, $p, $n, $call, $d) : $d;
            } catch (\Throwable $e) {
                $r = null;
            }
            $st['log'][] = $line . ($e !== null ? 'E' : $flag($r));
            return [$r, $e];
        });
        if ($e !== null) {
            throw $e;
        }
        return $r;
    }

    public function claim(int $h, string $k, int $n): mixed
    {
        return $this->call('claim', $k, $n, static function (array &$st, string $p) use ($h, $k, $n): array {
            $ok = !isset($st['last'][$k]) || $n > $st['last'][$k];
            if ($ok) {
                $st['last'][$k] = $n;
            }
            return [new ClaimResult($ok), "h$h $p $n "];
        }, static fn(mixed $r): string => ($r instanceof ClaimResult ? $r->ok : $r === true) ? 'T' : 'F');
    }

    public function create(int $h, OperationRecord $rec): array
    {
        return $this->call('create', $rec->id, 0, static function (array &$st, string $p) use ($h, $rec): array {
            $ex = $st['ops'][$rec->id] ?? null;
            if ($ex === null) {
                $st['ops'][$rec->id] = $rec;
            }
            return [$ex === null ? [true, null] : [false, $ex], "h$h create $p {$rec->state} {$rec->startedAt} "];
        }, static fn(mixed $r): string => $r[0] ? 'T' : 'F');
    }

    public function get(int $h, string $id): ?OperationRecord
    {
        return $this->call('get', $id, 0, static function (array &$st, string $p) use ($h, $id): array {
            return [$st['ops'][$id] ?? null, "h$h get $p"];
        }, static fn(mixed $r): string => '');
    }

    public function transition(int $h, string $id, string $from, OperationRecord $next): bool
    {
        return $this->call('transition', $id, 0, static function (array &$st, string $p) use ($h, $id, $from, $next): array {
            $ok = isset($st['ops'][$id]) && $st['ops'][$id]->state === $from;
            if ($ok) {
                $st['ops'][$id] = $next;
            }
            return [$ok, "h$h transition $p $from>{$next->state} {$next->startedAt} "];
        }, static fn(mixed $r): string => $r ? 'T' : 'F');
    }
}

/** One handle (one "connection") onto a {@see K05ScBackend}. */
final class K05ScHandle
{
    public function __construct(private readonly K05ScBackend $b, public readonly int $id)
    {
    }

    public function claim(string $k, int $n): mixed
    {
        return $this->b->claim($this->id, $k, $n);
    }

    public function create(OperationRecord $rec): array
    {
        return $this->b->create($this->id, $rec);
    }

    public function get(string $id): ?OperationRecord
    {
        return $this->b->get($this->id, $id);
    }

    public function transition(string $id, string $from, OperationRecord $next): bool
    {
        return $this->b->transition($this->id, $id, $from, $next);
    }
}
