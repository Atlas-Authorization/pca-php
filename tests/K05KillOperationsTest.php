<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\ExecuteOptions;
use Atlas\Pca\ExecuteOutcome;
use Atlas\Pca\ExecutionHandle;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\Operations;
use Atlas\Pca\OperationStore;
use Atlas\Pca\Pca;
use Atlas\Pca\PdoOperationStore;
use Atlas\Pca\RecheckResult;
use PHPUnit\Framework\TestCase;

/** k05 survivor kills for Operations.php (records, stores, executeAuthorized, recover/resolve). */
final class K05KillOperationsTest extends TestCase
{
    private static function allowed(string $id, string $class = 'reversible', ?Obj $pcactn = null): AuthorizeResult
    {
        return new AuthorizeResult(true, 200, pcactn: $pcactn ?? Obj::of(['action' => Obj::of(['reversibility_class' => $class])]),
            verdict: ['allow' => true], operation: new AuthorizedOperation('v', '/r', Pca::paramsDigest(), $id));
    }

    private static function rec(string $id, string $state, int $startedAt = 1000, ?string $error = null): OperationRecord
    {
        return new OperationRecord($id, $state, 'v', '/r', 'd', 'reversible', $startedAt, error: $error);
    }

    private static function wallMs(): int
    {
        return (int)(microtime(true) * 1000);
    }

    /** A PDO whose INSERTs change nothing (an UPDATE with the same placeholders that matches no row); counts them. */
    private static function swallowingPdo(): \PDO
    {
        $pdo = new class ('sqlite::memory:') extends \PDO {
            public int $inserts = 0;

            public function prepare(string $query, array $options = []): \PDOStatement|false
            {
                if (str_starts_with($query, 'INSERT')) {
                    if (++$this->inserts > 100) {
                        throw new \LogicException('runaway insert loop');
                    }
                    return parent::prepare('UPDATE swallow SET a = a WHERE 0' . str_repeat(' AND ? IS NOT NULL', substr_count($query, '?')), $options);
                }
                return parent::prepare($query, $options);
            }
        };
        $pdo->exec('CREATE TABLE swallow (a INTEGER)');
        return $pdo;
    }

    public function testRecordObjAndFromObj(): void
    {
        $o = self::rec('a', 'pending', 5)->toObj();
        $this->assertSame('a', $o->get('id'));
        $this->assertSame('5', $o->get('startedAt')->lexeme);
        $this->assertFalse($o->has('executingAt'));

        $this->assertNull(OperationRecord::fromObj('x'));
        $this->assertNull(OperationRecord::fromObj(null));
        $this->assertNull(OperationRecord::fromObj(Obj::of(['state' => 'pending'])));
        $this->assertNull(OperationRecord::fromObj(Obj::of(['id' => 'a'])));
        $r = OperationRecord::fromObj(Obj::of(['id' => 'a', 'state' => 'pending']));
        $this->assertSame(['a', 'pending', '', 0, null], [$r->id, $r->state, $r->verb, $r->startedAt, $r->executingAt]);
    }

    public function testMemoryStoreTransitionKeepsIdAndListOpenIsSortedOpenOnly(): void
    {
        $s = new MemoryOperationStore();
        $s->create(self::rec('b', 'pending'));
        $s->create(self::rec('a', 'executing'));
        $s->create(self::rec('c', 'committed'));
        $this->assertSame(['a', 'b'], array_map(fn (OperationRecord $r): string => $r->id, $s->listOpen()));
        $this->assertTrue($s->transition('b', 'pending', self::rec('zz', 'executing')));
        $this->assertSame('b', $s->get('b')->id);
        $this->assertSame('executing', $s->get('b')->state);
    }

    public function testPdoStore(): void
    {
        $s = new PdoOperationStore(new \PDO('sqlite::memory:'));
        $s->createTable();
        $s->create(self::rec('b', 'pending'));
        $s->create(self::rec('a', 'executing'));
        $s->create(self::rec('c', 'committed'));
        $this->assertSame(['a', 'b'], array_map(fn (OperationRecord $r): string => $r->id, $s->listOpen()));
        $this->assertTrue($s->transition('b', 'pending', self::rec('zz', 'executing')));
        $this->assertSame('b', $s->get('b')->id);

        $pdo = new \PDO('sqlite::memory:', null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_SILENT]);
        new PdoOperationStore($pdo);
        $this->assertSame(\PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(\PDO::ATTR_ERRMODE));
    }

    public function testPdoStoreRejectsABadTableName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoOperationStore(new \PDO('sqlite::memory:'), 'bad-name');
    }

    public function testPdoCreateGivesUpAfterThreeAttempts(): void
    {
        $pdo = self::swallowingPdo();
        $s = new PdoOperationStore($pdo);
        $s->createTable();
        try {
            $s->create(self::rec('x', 'pending'));
            $this->fail('expected a RuntimeException');
        } catch (\RuntimeException $e) {
            $this->assertSame('PdoOperationStore: the record could neither be created nor read', $e->getMessage());
        }
        $this->assertSame(3, $pdo->inserts);
    }

    public function testOptionsClockAndOutcomeDefaults(): void
    {
        $this->assertSame(1234, (new ExecuteOptions(now: fn () => 1234.0))->clock());
        $this->assertLessThan(60000, abs((new ExecuteOptions())->clock() - self::wallMs()));
        $o = new ExecuteOutcome('committed');
        $this->assertFalse($o->replayed);
        $this->assertFalse($o->recorded);
    }

    public function testJsonValue(): void
    {
        $n = Operations::jsonValue(1.5);
        $this->assertInstanceOf(Num::class, $n);
        $this->assertSame('1.5', $n->lexeme);
        $this->assertSame(INF, Operations::jsonValue(INF));
        $o = Operations::jsonValue([5 => 'a']);
        $this->assertInstanceOf(Obj::class, $o);
        $this->assertSame(['5'], $o->keys());
        $in = Obj::of(['a' => 3]);
        $out = Operations::jsonValue($in);
        $this->assertNotSame($in, $out);
        $this->assertInstanceOf(Num::class, $out->get('a'));
        $this->assertSame('3', $out->get('a')->lexeme);
    }

    public function testSettleStaleAnswersWhatIsStoredNow(): void
    {
        // the settling transition loses to a concurrent writer: the stored record (committed) wins over the computed one
        $store = new class implements OperationStore {
            public int $gets = 0;

            public function create(OperationRecord $rec): array { return [true, null]; }

            public function get(string $id): ?OperationRecord
            {
                return ++$this->gets === 1 ? new OperationRecord($id, 'pending', 'v', '/r', 'd', 'reversible', 0)
                    : new OperationRecord($id, 'committed', 'v', '/r', 'd', 'reversible', 0);
            }

            public function transition(string $id, string $from, OperationRecord $next): bool { return false; }
        };
        $r = Operations::recoverOperation($store, 'x', 1000, fn () => 100000);
        $this->assertSame('committed', $r->state);
    }

    public function testAnswerFromRecordEveryState(): void
    {
        $s = new MemoryOperationStore();
        $a = fn (OperationRecord $r): ExecuteOutcome => Operations::answerFromRecord($s, $r, 1000, 5000);
        $o = $a(self::rec('c', 'committed')->with(['result' => 'R']));
        $this->assertSame(['committed', 'R', true, true], [$o->status, $o->result, $o->replayed, $o->recorded]);
        $this->assertSame(['failed', 'e', true], [$a(self::rec('f', 'failed', error: 'e'))->status, $a(self::rec('f', 'failed', error: 'e'))->error, $a(self::rec('f', 'failed'))->replayed]);
        $this->assertSame('failed', $a(self::rec('f', 'failed'))->error);
        $this->assertSame(['aborted', 'aborted'], [$a(self::rec('x', 'aborted'))->status, $a(self::rec('x', 'aborted'))->reason]);
        $this->assertSame(['uncertain', 'outcome unknown'], [$a(self::rec('u', 'uncertain'))->status, $a(self::rec('u', 'uncertain'))->reason]);
        $this->assertSame(['pending', true], [$a(self::rec('p', 'pending'))->status, $a(self::rec('p', 'pending'))->replayed]);
        $this->assertSame('pending', $a(self::rec('e', 'executing'))->status);
        $o = $a(self::rec('w', 'weird'));
        $this->assertSame(['uncertain', "unknown record state 'weird'", true], [$o->status, $o->reason, $o->replayed]);
    }

    public function testFinishLeavesUncertainWhenRecoverySettledTheExecution(): void
    {
        $s = new MemoryOperationStore();
        $o = Operations::executeAuthorized(self::allowed('op-f'), function (ExecutionHandle $h) use ($s) {
            // a recovery run settles the executing record as uncertain while $fn is still running
            Operations::recoverOperation($s, $h->idempotencyKey, 0, fn () => 5000);
            return 'ok';
        }, new ExecuteOptions($s, now: fn () => 1000));
        $this->assertSame(['committed', true, 'ok'], [$o->status, $o->recorded, $o->result]);
        $this->assertSame('committed', $s->get('op-f')->state);
        $this->assertSame('ok', $s->get('op-f')->result);
    }

    public function testCreateRefusedWithoutAnExistingRecordAnswersTheCurrentOne(): void
    {
        $present = new class implements OperationStore {
            public function create(OperationRecord $rec): array { return [false, null]; }
            public function get(string $id): ?OperationRecord { return (new OperationRecord($id, 'committed', 'v', '/r', 'd', 'reversible', 1000))->with(['result' => 'R']); }
            public function transition(string $id, string $from, OperationRecord $next): bool { return false; }
        };
        $o = Operations::executeAuthorized(self::allowed('op-a'), fn () => 1, new ExecuteOptions($present, now: fn () => 1000));
        $this->assertSame(['committed', true, 'R'], [$o->status, $o->replayed, $o->result]);

        $gone = new class implements OperationStore {
            public function create(OperationRecord $rec): array { return [false, null]; }
            public function get(string $id): ?OperationRecord { return null; }
            public function transition(string $id, string $from, OperationRecord $next): bool { return false; }
        };
        $o = Operations::executeAuthorized(self::allowed('op-b'), fn () => 1, new ExecuteOptions($gone, now: fn () => 1000));
        $this->assertSame(['uncertain', 'op-b', 'the operation record disappeared', true], [$o->status, $o->operationId, $o->reason, $o->replayed]);
    }

    public function testExecuteAuthorizedBranches(): void
    {
        // an authorization for another operation is refused
        $o = Operations::executeAuthorized(self::allowed('op-o'), fn () => 1, new ExecuteOptions(new MemoryOperationStore(),
            operation: ['verb' => 'other', 'resource' => '/r', 'params' => Obj::of([])]));
        $this->assertSame(['refused', 'executeAuthorized: the authorization is not for this operation (verb, resource or params differ)'], [$o->status, $o->reason]);

        // no signed action at all: irreversible, so the re-check runs and the call commits
        $o = Operations::executeAuthorized(self::allowed('op-n', pcactn: Obj::of([])), fn () => 'y',
            new ExecuteOptions(new MemoryOperationStore(), recheck: fn () => RecheckResult::ok(), now: fn () => 1000));
        $this->assertSame(['committed', 'y'], [$o->status, $o->result]);

        // a re-check answer that is not a RecheckResult is a refusal whatever it carries
        $s = new MemoryOperationStore();
        $o = Operations::executeAuthorized(self::allowed('op-r'), fn () => 1, new ExecuteOptions($s,
            recheck: fn () => new class {
                public bool $ok = true;
                public string $reason = 'sneaky';
            }, recheckFor: 'always', now: fn () => 1000));
        $this->assertSame(['aborted', 'recheck: refused'], [$o->status, $o->reason]);
        $this->assertSame('aborted', $s->get('op-r')->state);

        // the record is `executing` (with its start time) while $fn runs
        $s = new MemoryOperationStore();
        $seen = null;
        Operations::executeAuthorized(self::allowed('op-e'), function (ExecutionHandle $h) use ($s, &$seen) {
            $r = $s->get($h->idempotencyKey);
            $seen = [$r->state, $r->executingAt];
            return 1;
        }, new ExecuteOptions($s, now: fn () => 1000));
        $this->assertSame(['executing', 1000], $seen);

        // the final record cannot be written: committed, recorded false
        $inner = new MemoryOperationStore();
        $flaky = new class ($inner) implements OperationStore {
            public function __construct(private readonly MemoryOperationStore $m) {}
            public function create(OperationRecord $rec): array { return $this->m->create($rec); }
            public function get(string $id): ?OperationRecord { return $this->m->get($id); }

            public function transition(string $id, string $from, OperationRecord $next): bool
            {
                if ($next->state === 'committed') {
                    throw new \RuntimeException('down');
                }
                return $this->m->transition($id, $from, $next);
            }
        };
        $o = Operations::executeAuthorized(self::allowed('op-w'), fn () => 'x', new ExecuteOptions($flaky, now: fn () => 1000));
        $this->assertSame(['committed', 'x', false], [$o->status, $o->result, $o->recorded]);
    }

    public function testRecoverOperationClock(): void
    {
        $wall = self::wallMs();
        $s = new MemoryOperationStore();
        $s->create(self::rec('fresh', 'pending', $wall));
        $s->create(self::rec('old', 'pending', $wall - 600000));
        $s->create(self::rec('f', 'pending', 1000));
        $this->assertSame('pending', Operations::recoverOperation($s, 'fresh', 60000)->state);
        $this->assertSame('aborted', Operations::recoverOperation($s, 'old', 60000)->state);
        $r = Operations::recoverOperation($s, 'f', 1000, fn () => 5000.0);
        $this->assertSame(['aborted', 5000], [$r->state, $r->finishedAt]);
    }

    public function testResolveOperation(): void
    {
        $wall = self::wallMs();
        $s = new MemoryOperationStore();
        foreach (['u1', 'u2', 'u3'] as $id) {
            $s->create(self::rec($id, 'uncertain'));
        }
        $this->assertTrue(Operations::resolveOperation($s, 'u1', ['state' => 'committed', 'result' => 1]));
        $r = $s->get('u1');
        $this->assertSame('committed', $r->state);
        $this->assertSame('1', $r->result->lexeme);
        $this->assertLessThan(60000, abs($r->finishedAt - $wall));
        $this->assertTrue(Operations::resolveOperation($s, 'u2', ['state' => 'failed', 'error' => 5], fn () => 777.0));
        $this->assertSame(['failed', '5', 777], [$s->get('u2')->state, $s->get('u2')->error, $s->get('u2')->finishedAt]);
        $this->assertFalse(Operations::resolveOperation($s, 'u1', ['state' => 'failed']));
    }

    public function testResolveOperationRejectsAnUnknownState(): void
    {
        $s = new MemoryOperationStore();
        $s->create(self::rec('u', 'uncertain'));
        $this->expectException(\InvalidArgumentException::class);
        Operations::resolveOperation($s, 'u', ['state' => 'bogus']);
    }
}
