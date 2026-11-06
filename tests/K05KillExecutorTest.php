<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\ExecutionHandle;
use Atlas\Pca\Executor;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\OperationStore;
use Atlas\Pca\Pca;
use Atlas\Pca\PlanRegistry;
use Atlas\Pca\RecheckResult;
use PHPUnit\Framework\TestCase;

/** k05 survivor kills for Executor.php: the clock, the replay path and the executor's own pre-execution re-check. */
final class K05KillExecutorTest extends TestCase
{
    /** authorize-fixtures.json case 0 (signed class irreversible): [executor, pcactn, operation, setRevoked, fixture now]. */
    private function fixture(OperationStore $ops, array $over = [], ?callable $classOf = null, ?int $timeout = null, ?callable $now = null): array
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $c = $fix->get('cases')[0];
        $s = $c->get('steps')[0];
        $fixNow = $fix->get('now')->int();
        $revoked = false;
        $ex = new Executor($ops, $over + ['audience' => $fix->get('audience'), 'resolveGrant' => fn ($r) => $c->get('grant'),
            'stateStore' => new MemoryStateStore(), 'isRevoked' => function () use (&$revoked) { return $revoked; }, 'plan' => 'single-step']
            + ProvHarness::options(),
            reversibilityClassOf: $classOf, pendingTimeoutMs: $timeout, now: $now ?? fn () => $fixNow);
        return [$ex, $s->get('pcactn'), $s->get('operation'), function (bool $v) use (&$revoked): void { $revoked = $v; }, $fixNow];
    }

    public function testClock(): void
    {
        $clock = new \ReflectionMethod(Executor::class, 'clock');
        $this->assertSame(1234, $clock->invoke(new Executor(new MemoryOperationStore(), [], now: fn () => 1234.0)));
        $this->assertLessThan(60000, abs($clock->invoke(new Executor(new MemoryOperationStore(), [])) - (int)(microtime(true) * 1000)));
    }

    public function testAuthorizeNowWinsOverTheExecutorClock(): void
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $fixNow = $fix->get('now')->int();
        // authorization at the fixture time is allowed; the executor clock (far later) only drives the record and the re-check
        [$ex, $pcactn, $op] = $this->fixture(new MemoryOperationStore(), ['now' => $fixNow], now: fn () => $fixNow + 10 ** 12);
        $o = $ex->run($pcactn, $op, fn () => 1);
        $this->assertSame('aborted', $o->status);
        $this->assertStringStartsWith('recheck: the PCActn expired at ', $o->reason);
    }

    public function testReversibilityClassOfIsConsulted(): void
    {
        $seen = [];
        [$ex, $pcactn, $op] = $this->fixture(new MemoryOperationStore(), classOf: function ($o) use (&$seen) {
            $seen[] = $o;
            return 5; // not a string: ignored
        });
        $o = $ex->run($pcactn, $op, fn () => 1);
        $this->assertSame('committed', $o->status);
        $this->assertCount(1, $seen);
        $this->assertSame($op, $seen[0]);
    }

    public function testReplayOfARevokedGrantIsDenied(): void
    {
        $ops = new MemoryOperationStore();
        [$ex, $pcactn, $op, $setRevoked] = $this->fixture($ops);
        $this->assertSame('committed', $ex->run($pcactn, $op, fn () => 1)->status);
        $setRevoked(true);
        $this->assertSame('denied', $ex->run($pcactn, $op, fn () => 1)->status);
    }

    public function testReplayWhoseRecordHasAnotherVerbIsDenied(): void
    {
        $ops = new MemoryOperationStore();
        [$ex, $pcactn, $op] = $this->fixture($ops);
        $first = $ex->run($pcactn, $op, fn () => 1);
        $this->assertSame('committed', $first->status);
        $rec = $ops->get($first->operationId);
        $this->assertTrue($ops->transition($rec->id, 'committed', $rec->with(['verb' => 'zzz'])));
        $this->assertSame('denied', $ex->run($pcactn, $op, fn () => 1)->status);
        // restored, the replay is answered from the record again
        $this->assertTrue($ops->transition($rec->id, 'committed', $rec));
        $again = $ex->run($pcactn, $op, fn () => 1);
        $this->assertSame(['committed', true], [$again->status, $again->replayed]);
    }

    public function testReplayIsSettledWithTheExecutorTimeout(): void
    {
        $ops = new MemoryOperationStore();
        [$ex, $pcactn, $op, , $fixNow] = $this->fixture($ops, timeout: 1000);
        $first = $ex->run($pcactn, $op, fn () => 1);
        $rec = $ops->get($first->operationId);
        $this->assertTrue($ops->transition($rec->id, 'committed', $rec->with(['state' => 'pending', 'startedAt' => $fixNow - 10000])));
        $o = $ex->run($pcactn, $op, fn () => 1);
        $this->assertSame(['aborted', 'not started within 1000 ms of the claim: the side effect never ran', true], [$o->status, $o->reason, $o->replayed]);
    }

    public function testReplayWithAFailingStoreIsRefused(): void
    {
        $ops = new class implements OperationStore {
            public bool $fail = false;
            private MemoryOperationStore $m;

            public function __construct() { $this->m = new MemoryOperationStore(); }
            public function create(OperationRecord $rec): array { return $this->m->create($rec); }

            public function get(string $id): ?OperationRecord
            {
                if ($this->fail) {
                    throw new \RuntimeException('boom');
                }
                return $this->m->get($id);
            }

            public function transition(string $id, string $from, OperationRecord $next): bool { return $this->m->transition($id, $from, $next); }
        };
        [$ex, $pcactn, $op] = $this->fixture($ops);
        $this->assertSame('committed', $ex->run($pcactn, $op, fn () => 1)->status);
        $ops->fail = true;
        $o = $ex->run($pcactn, $op, fn () => 1);
        $this->assertSame(['refused', 'executor: the operation store failed (fail closed): boom'], [$o->status, $o->reason]);
    }

    // ---- the executor's own re-check (private recheckOf: reached here with handcrafted handles)

    private static function recheck(array $cfg, int $now): \Closure
    {
        $ex = new Executor(new MemoryOperationStore(), $cfg, now: fn () => $now);
        return (new \ReflectionMethod(Executor::class, 'recheckOf'))->invoke($ex);
    }

    private static function handle(Obj $pcactn): ExecutionHandle
    {
        return new ExecutionHandle('id', new AuthorizedOperation('v', '/r', Pca::paramsDigest(), 'id'), $pcactn);
    }

    private static function plan(PlanRegistry $reg, bool $authorize): string
    {
        $root = $reg->draft('g', [['id' => 'n1', 'verb' => 'orders.read', 'resource' => '/orders/1']])['record']->get('root');
        $reg->validate('g', $root);
        $reg->commit('g', $root);
        if ($authorize) {
            $reg->authorize('g', $root, ['by' => 'p', 'expiresAt' => 3000]);
        }
        return $root;
    }

    public function testRecheckGrantAndPlan(): void
    {
        $grant = Obj::of(['id' => 'g']);
        $base = ['resolveGrant' => fn ($r) => $grant, 'isRevoked' => fn () => false];
        $ok = fn (RecheckResult $r): array => [$r->ok, $r->reason];

        // no string grant_ref: the grant is unknown even though resolveGrant would answer
        $this->assertSame([false, 'the grant is no longer known'], $ok(self::recheck($base, 2000)(self::handle(Obj::of([])))));
        $this->assertSame([false, 'the grant is no longer known'],
            $ok(self::recheck(['resolveGrant' => fn ($r) => null] + $base, 2000)(self::handle(Obj::of(['grant_ref' => 'g'])))));
        // no plan registry, no plan member
        $this->assertSame([true, ''], $ok(self::recheck($base, 2000)(self::handle(Obj::of(['grant_ref' => 'g'])))));

        $committed = new PlanRegistry(null, 'pca-plan:', fn () => 1000);
        $croot = self::plan($committed, false);
        $rc = self::recheck(['plans' => $committed] + $base, 2000);
        $this->assertSame([true, ''], $ok($rc(self::handle(Obj::of(['grant_ref' => 'g'])))));
        // a root the registry does not know is not checked here (authorize decided it)
        $this->assertSame([true, ''], $ok($rc(self::handle(Obj::of(['grant_ref' => 'g', 'plan' => Obj::of(['root' => 'unregistered'])])))));
        $this->assertSame([false, "plan $croot is committed but not authorized by the principal"],
            $ok($rc(self::handle(Obj::of(['grant_ref' => 'g', 'plan' => Obj::of(['root' => $croot])])))));

        $authorized = new PlanRegistry(null, 'pca-plan:', fn () => 1000);
        $aroot = self::plan($authorized, true);
        $at = fn (int $now, string $node): array => $ok(self::recheck(['plans' => $authorized] + $base, $now)(self::handle(
            Obj::of(['grant_ref' => 'g', 'plan' => Obj::of(['root' => $aroot, 'node_id' => $node])]))));
        $this->assertSame([true, ''], $at(2000, 'n1'));
        $this->assertSame([false, "plan $aroot has no node 'nX'"], $at(2000, 'nX'));
        // the executor's clock (not the registry's) decides the approval expiry
        $expired = $at(5000, 'n1');
        $this->assertFalse($expired[0]);
        $this->assertStringStartsWith("plan $aroot: the principal's approval expired at ", $expired[1]);
    }
}
