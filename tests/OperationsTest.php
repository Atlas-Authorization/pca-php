<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\ExecuteOptions;
use Atlas\Pca\ExecutionHandle;
use Atlas\Pca\Executor;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\Operations;
use Atlas\Pca\Pca;
use Atlas\Pca\PdoOperationStore;
use Atlas\Pca\RecheckResult;
use PHPUnit\Framework\TestCase;

/**
 * Operation records (T3): replays operation-vectors.json scenario by scenario (memory store and PDO store), then
 * "N workers claim one id" over a shared database, a store that fails, and the executor. A missing vector file fails the test.
 */
final class OperationsTest extends TestCase
{
    public function testVectorsMemoryStore(): void
    {
        [$n, $fails] = NativeParityVectors::operations();
        $this->assertSame([], $fails);
        $this->assertSame(49, $n);
    }

    public function testVectorsPdoStore(): void
    {
        [$n, $fails] = NativeParityVectors::operations(static function (): PdoOperationStore {
            $s = new PdoOperationStore(new \PDO('sqlite::memory:'));
            $s->createTable();
            return $s;
        });
        $this->assertSame([], $fails);
        $this->assertSame(49, $n);
    }

    private static function allowed(string $id, string $class = 'reversible'): AuthorizeResult
    {
        return new AuthorizeResult(true, 200, pcactn: Obj::of(['action' => Obj::of(['reversibility_class' => $class])]), verdict: ['allow' => true],
            operation: new AuthorizedOperation('v', '/r', Pca::paramsDigest(), $id));
    }

    public function testSequentialExecutionsRunOnce(): void
    {
        foreach ([new MemoryOperationStore(), $this->pdoStore()] as $store) {
            $calls = 0;
            $firsts = 0;
            for ($i = 0; $i < 32; $i++) {
                $o = Operations::executeAuthorized(self::allowed('op-s'), function () use (&$calls) {
                    $calls++;
                    return 'done';
                }, new ExecuteOptions($store));
                $firsts += $o->status === 'committed' && !$o->replayed ? 1 : 0;
                $this->assertSame('committed', $o->status);
            }
            $this->assertSame([1, 1], [$calls, $firsts]);
        }
    }

    private function pdoStore(?string $file = null): PdoOperationStore
    {
        $pdo = new \PDO('sqlite:' . ($file ?? ':memory:'));
        $pdo->exec('PRAGMA busy_timeout = 10000');
        $s = new PdoOperationStore($pdo);
        $s->createTable();
        return $s;
    }

    /** Of N processes sharing one database exactly one creates the record and runs the function. */
    public function testConcurrentProcessesRunOnce(): void
    {
        if (!function_exists('pcntl_fork')) {
            $this->markTestSkipped('pcntl not available');
        }
        $db = tempnam(sys_get_temp_dir(), 'pcaop');
        $log = tempnam(sys_get_temp_dir(), 'pcalog');
        $this->pdoStore($db);
        $pids = [];
        for ($i = 0; $i < 16; $i++) {
            $pid = pcntl_fork();
            if ($pid === 0) {
                $o = Operations::executeAuthorized(self::allowed('op-c'), static function () use ($log) {
                    file_put_contents($log, "x\n", FILE_APPEND | LOCK_EX);
                    usleep(20000);
                    return 'done';
                }, new ExecuteOptions($this->pdoStore($db)));
                exit($o->status === 'refused' ? 12 : ($o->status === 'committed' && !$o->replayed ? 10 : 11));
            }
            $pids[] = $pid;
        }
        $codes = [];
        foreach ($pids as $pid) {
            pcntl_waitpid($pid, $status);
            $codes[] = pcntl_wexitstatus($status);
        }
        $ran = substr_count((string)file_get_contents($log), "x\n");
        @unlink($db);
        @unlink($log);
        $this->assertSame(1, $ran, 'fn ran exactly once');
        $this->assertSame(1, count(array_filter($codes, fn ($c) => $c === 10)), 'one first execution');
        $this->assertSame(0, count(array_filter($codes, fn ($c) => $c === 12)), 'no refusal');
    }

    public function testStoreThatThrowsRefusesFailClosed(): void
    {
        $broken = new class implements \Atlas\Pca\OperationStore {
            public function create(OperationRecord $rec): array { throw new \RuntimeException('locked'); }
            public function get(string $id): ?OperationRecord { return null; }
            public function transition(string $id, string $from, OperationRecord $next): bool { return false; }
        };
        $ran = false;
        $o = Operations::executeAuthorized(self::allowed('op-b'), function () use (&$ran) {
            $ran = true;
            return 1;
        }, new ExecuteOptions($broken));
        $this->assertSame('refused', $o->status);
        $this->assertStringContainsString('the operation store failed (fail closed): locked', $o->reason);
        $this->assertFalse($ran);
    }

    public function testRecoverNeedsAListingStore(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Operations::recoverOperations(new class implements \Atlas\Pca\OperationStore {
            public function create(OperationRecord $rec): array { return [true, null]; }
            public function get(string $id): ?OperationRecord { return null; }
            public function transition(string $id, string $from, OperationRecord $next): bool { return false; }
        });
    }

    public function testIrreversibleWithoutRecheckIsRefusedAndRecordsNothing(): void
    {
        $store = new MemoryOperationStore();
        $o = Operations::executeAuthorized(self::allowed('op-i', 'irreversible'), fn () => 1, new ExecuteOptions($store));
        $this->assertSame('refused', $o->status);
        $this->assertNull($store->get('op-i'));
        // a PHP array result is stored as the JSON object it is
        $o = Operations::executeAuthorized(self::allowed('op-j'), fn () => ['a' => 1, 'b' => [true, null]], new ExecuteOptions($store));
        $this->assertSame('{"a":1,"b":[true,null]}', Json::canonicalizeLenient($store->get('op-j')->result));
    }

    // ---- executor

    private function executor(MemoryOperationStore $ops, array $over = []): array
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $c = $fix->get('cases')[0]; // signed class irreversible
        $s = $c->get('steps')[0];
        $now = $fix->get('now')->int();
        $revoked = false;
        $ex = new Executor($ops, $over + ['audience' => $fix->get('audience'), 'resolveGrant' => fn ($r) => $c->get('grant'),
            'stateStore' => new MemoryStateStore(), 'isRevoked' => function () use (&$revoked) { return $revoked; }, 'plan' => 'single-step'],
            now: fn () => $now);
        return [$ex, $s->get('pcactn'), $s->get('operation'), function (bool $v) use (&$revoked): void { $revoked = $v; }];
    }

    public function testExecutorRunsOnceAndAnswersARetryFromTheRecord(): void
    {
        $ops = new MemoryOperationStore();
        [$ex, $pcactn, $op] = $this->executor($ops);
        $calls = 0;
        $fn = function (ExecutionHandle $h) use (&$calls) {
            $calls++;
            return $h->idempotencyKey;
        };
        $first = $ex->run($pcactn, $op, $fn);
        $this->assertSame(['committed', false], [$first->status, $first->replayed]);
        $this->assertSame(Pca::hashCanonical($pcactn), $first->operationId);
        $again = $ex->run($pcactn, $op, $fn);
        $this->assertSame(['committed', true, $first->operationId], [$again->status, $again->replayed, $again->result]);
        $this->assertSame(1, $calls);
    }

    public function testExecutorDeniedWithoutARecordKeepsTheDenial(): void
    {
        $ops = new MemoryOperationStore();
        [$ex, $pcactn, $op] = $this->executor($ops);
        $other = Obj::of(['verb' => 'other.verb', 'resource' => $op->get('resource'), 'params' => $op->get('params')]);
        $o = $ex->run($pcactn, $other, fn () => 1);
        $this->assertSame('denied', $o->status);
        $this->assertFalse($o->authorization->allow);
        // a replay whose operation differs from the recorded one is also a denial, not the record
        $ex->run($pcactn, $op, fn () => 1);
        $o = $ex->run($pcactn, $other, fn () => 1);
        $this->assertSame('denied', $o->status);
    }

    public function testExecutorRecheckAbortsARevokedGrantBeforeFnRuns(): void
    {
        $ops = new MemoryOperationStore();
        // the grant is revoked after authorization but before the function starts: the re-check runs after the first isRevoked
        $calls = 0;
        $answers = [false, true]; // authorize sees "not revoked", the pre-execution re-check sees "revoked"
        [$ex, $pcactn, $op] = $this->executor($ops, ['isRevoked' => function () use (&$answers) { return array_shift($answers) ?? true; }]);
        $o = $ex->run($pcactn, $op, function () use (&$calls) { $calls++; return 1; });
        $this->assertSame('aborted', $o->status);
        $this->assertSame('recheck: the grant has been revoked', $o->reason);
        $this->assertSame(0, $calls);
        $this->assertSame('aborted', $ops->get($o->operationId)->state);
    }

    public function testExecutorWithoutAStoreWouldNotCompile(): void
    {
        // the store is a required constructor argument: a missing one is a type error, never a silent in-memory default
        $this->expectException(\TypeError::class);
        new Executor(null, []);
    }
}
