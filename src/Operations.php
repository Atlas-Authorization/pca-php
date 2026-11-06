<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/RevocationStaleness.php';

/**
 * Operation records (T3): execute an authorized operation at most once, with a durable record of what happened.
 *
 * {@see Authorize::authorize} decides and consumes the PCActn's replay counter. Between that decision and the end of the side
 * effect the process can crash, the client can time out and retry, or two workers can pick up the same authorization. A record
 * per operation id (`AuthorizedOperation::$id`, the digest of the presented PCActn) closes that gap:
 *
 *  1. {@see Operations::executeAuthorized} creates the record in state `pending` BEFORE anything runs (one atomic
 *     create-if-absent: of N concurrent executions of one authorization exactly one gets to run `$fn`);
 *  2. for an irreversible operation it re-checks revocation, expiry and approval immediately before `$fn` (`recheck` is
 *     required, fail closed); a failed re-check records `aborted` and `$fn` never runs;
 *  3. it moves the record to `executing` and only then calls `$fn`, with the operation id as the idempotency key;
 *  4. the record becomes `committed` (with `$fn`'s result) or `failed` (with its message) afterwards.
 *
 * A second execution of the same id never runs `$fn` again: it is answered from the record. Once `pendingTimeoutMs` has passed,
 * a record still `pending` is settled `aborted` (the side effect never started) and one still `executing` `uncertain` (it may or
 * may not have happened: reconcile it with {@see Operations::resolveOperation} using the idempotency key). Mirrors the reference
 * operation-record module; the shared operation-vectors.json corpus pins the state machine and every message.
 */
final class OperationRecord
{
    public const PENDING = 'pending';
    public const EXECUTING = 'executing';
    public const COMMITTED = 'committed';
    public const FAILED = 'failed';
    public const ABORTED = 'aborted';
    public const UNCERTAIN = 'uncertain';

    /**
     * @param mixed $result what `$fn` returned when committed (keep it JSON-serialisable for a durable store: Obj, list, scalars)
     */
    public function __construct(
        public readonly string $id,
        public readonly string $state,
        public readonly string $verb,
        public readonly string $resource,
        public readonly string $paramsDigest,
        public readonly string $reversibility,
        public readonly int $startedAt,
        public readonly ?int $executingAt = null,
        public readonly ?int $finishedAt = null,
        public readonly mixed $result = null,
        public readonly ?string $error = null,
    ) {
    }

    /** A copy with the named properties replaced. @param array<string,mixed> $changes */
    public function with(array $changes): self
    {
        return new self(...array_merge(get_object_vars($this), $changes));
    }

    /** The JSON form (the reference's field names; absent members are omitted). */
    public function toObj(): Obj
    {
        $n = static fn(int $i): Num => new Num((string)$i);
        $o = Obj::of(['id' => $this->id, 'state' => $this->state, 'verb' => $this->verb, 'resource' => $this->resource,
            'params_digest' => $this->paramsDigest, 'reversibility' => $this->reversibility, 'startedAt' => $n($this->startedAt)]);
        if ($this->executingAt !== null) {
            $o->set('executingAt', $n($this->executingAt));
        }
        if ($this->finishedAt !== null) {
            $o->set('finishedAt', $n($this->finishedAt));
        }
        if ($this->result !== null) {
            $o->set('result', $this->result);
        }
        if ($this->error !== null) {
            $o->set('error', $this->error);
        }
        return $o;
    }

    public static function fromObj(mixed $v): ?self
    {
        if (!($v instanceof Obj) || !is_string($v->get('id')) || !is_string($v->get('state'))) {
            return null;
        }
        $int = static fn(mixed $x): ?int => $x instanceof Num && $x->isInt() ? $x->int() : null;
        $str = static fn(mixed $x): string => is_string($x) ? $x : '';
        return new self($v->get('id'), $v->get('state'), $str($v->get('verb')), $str($v->get('resource')), $str($v->get('params_digest')),
            $str($v->get('reversibility')), $int($v->get('startedAt')) ?? 0, $int($v->get('executingAt')), $int($v->get('finishedAt')),
            $v->get('result'), is_string($v->get('error')) ? $v->get('error') : null);
    }
}

/**
 * Durable, shared storage of operation records. `create` and `transition` MUST be atomic across every process and node that
 * shares the store (a unique-key insert and a conditional UPDATE, a Redis script, ...). A call that cannot decide MUST throw:
 * the executor then refuses or reports the outcome as unknown.
 */
interface OperationStore
{
    /** Atomically insert `$rec` if no record with its id exists. @return array{0:bool, 1:?OperationRecord} [created, the existing record when not] */
    public function create(OperationRecord $rec): array;

    public function get(string $id): ?OperationRecord;

    /** Atomically replace the record with `$next` only if its current state is `$from`. Returns whether it did. */
    public function transition(string $id, string $from, OperationRecord $next): bool;
}

/** The optional capability {@see Operations::recoverOperations} needs: the records still `pending` or `executing`. */
interface OpenListingStore extends OperationStore
{
    /** @return list<OperationRecord> */
    public function listOpen(): array;
}

/** In-process {@see OperationStore} (tests, one worker): PHP shares nothing between requests, so under FPM it lives for one request. */
final class MemoryOperationStore implements OpenListingStore
{
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
        if (!isset($this->m[$id]) || $this->m[$id]->state !== $from) {
            return false;
        }
        $this->m[$id] = $next->with(['id' => $id]);
        return true;
    }

    public function listOpen(): array
    {
        $out = array_values(array_filter($this->m, static fn(OperationRecord $r): bool => $r->state === OperationRecord::PENDING
            || $r->state === OperationRecord::EXECUTING));
        usort($out, static fn(OperationRecord $a, OperationRecord $b): int => strcmp($a->id, $b->id));
        return $out;
    }
}

/**
 * Durable {@see OperationStore} on PDO (SQLite 3.24+ or PostgreSQL 9.5+): one row per operation id (the PRIMARY KEY). `create`
 * is a unique-key `INSERT ... ON CONFLICT DO NOTHING` (its row count says whether this call created the record) and
 * `transition` a conditional `UPDATE ... WHERE id = ? AND state = <from>`, so the database serializes concurrent processes on
 * the row: of N workers claiming one id exactly one creates it, and exactly one moves it out of a given state. The connection
 * must be in autocommit mode (no open transaction).
 */
final class PdoOperationStore implements OpenListingStore
{
    public const DEFAULT_TABLE = 'pca_operations';

    private readonly string $table;

    public function __construct(private readonly \PDO $pdo, string $table = self::DEFAULT_TABLE)
    {
        if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]{0,62}\z/D', $table) !== 1) {
            throw new \InvalidArgumentException('PdoOperationStore: invalid table name');
        }
        $this->table = $table;
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    /** Create the table when it does not exist (idempotent). Run it once at deployment, or at start-up. */
    public function createTable(): void
    {
        $this->pdo->exec('CREATE TABLE IF NOT EXISTS ' . $this->table
            . ' (id TEXT NOT NULL PRIMARY KEY, state TEXT NOT NULL, record TEXT NOT NULL)');
    }

    public function create(OperationRecord $rec): array
    {
        for ($i = 0; $i < 3; $i++) {
            $st = $this->pdo->prepare('INSERT INTO ' . $this->table . ' (id, state, record) VALUES (?, ?, ?) ON CONFLICT (id) DO NOTHING');
            $st->execute([$rec->id, $rec->state, Json::canonicalizeLenient($rec->toObj())]);
            if ($st->rowCount() === 1) {
                return [true, null];
            }
            if (($existing = $this->get($rec->id)) !== null) {
                return [false, $existing];
            }
        }
        throw new \RuntimeException('PdoOperationStore: the record could neither be created nor read');
    }

    public function get(string $id): ?OperationRecord
    {
        $q = $this->pdo->prepare('SELECT record FROM ' . $this->table . ' WHERE id = ?');
        $q->execute([$id]);
        $v = $q->fetchColumn();
        return is_string($v) ? OperationRecord::fromObj(Json::parseLax($v)) : null;
    }

    public function transition(string $id, string $from, OperationRecord $next): bool
    {
        $next = $next->with(['id' => $id]);
        $st = $this->pdo->prepare('UPDATE ' . $this->table . ' SET state = ?, record = ? WHERE id = ? AND state = ?');
        $st->execute([$next->state, Json::canonicalizeLenient($next->toObj()), $id, $from]);
        return $st->rowCount() === 1;
    }

    public function listOpen(): array
    {
        $q = $this->pdo->query('SELECT record FROM ' . $this->table . " WHERE state IN ('pending', 'executing') ORDER BY id");
        $out = [];
        foreach ($q->fetchAll(\PDO::FETCH_COLUMN) as $v) {
            $r = is_string($v) ? OperationRecord::fromObj(Json::parseLax($v)) : null;
            if ($r !== null) {
                $out[] = $r;
            }
        }
        return $out;
    }
}

/** What a pre-execution re-check answered. */
final class RecheckResult
{
    private function __construct(public readonly bool $ok, public readonly string $reason = '')
    {
    }

    public static function ok(): self
    {
        return new self(true);
    }

    public static function refuse(string $reason): self
    {
        return new self(false, $reason);
    }
}

/** What the executed function receives. `idempotencyKey` is the operation id: pass it as the idempotency key of the downstream call. */
final class ExecutionHandle
{
    public function __construct(public readonly string $idempotencyKey, public readonly AuthorizedOperation $operation, public readonly Obj $pcactn)
    {
    }
}

/** Options of {@see Operations::executeAuthorized}. */
final class ExecuteOptions
{
    /** @var \Closure|null */
    public readonly ?\Closure $recheck;
    /** @var \Closure|null */
    public readonly ?\Closure $now;

    /**
     * @param OperationStore|null $store  REQUIRED (shared and durable in production)
     * @param mixed $operation  when set (`['verb' =>, 'resource' =>, 'params' => Obj]`), the authorization must be for exactly it
     * @param callable|null $recheck `(ExecutionHandle): RecheckResult` re-checks, immediately before `$fn`, that the authorization
     *        still stands (grant not revoked, approval not expired or withdrawn). REQUIRED for an irreversible operation (fail
     *        closed), and for the others with `recheckFor: 'always'`. The PCActn's own `exp` is always checked with it. A throw is a refusal
     * @param string $recheckFor  `'irreversible'` (default) or `'always'`
     * @param string|null $reversibilityClass the server's authoritative class; the stricter of it and the signed class applies (missing or unknown = irreversible)
     * @param int|null $pendingTimeoutMs an open record older than this is settled (default 5 minutes)
     * @param callable|null $now  `(): int` epoch milliseconds (default: the wall clock)
     */
    public function __construct(
        public readonly ?OperationStore $store = null,
        public readonly mixed $operation = null,
        ?callable $recheck = null,
        public readonly string $recheckFor = 'irreversible',
        public readonly ?string $reversibilityClass = null,
        public readonly ?int $pendingTimeoutMs = null,
        ?callable $now = null,
    ) {
        $this->recheck = $recheck === null ? null : \Closure::fromCallable($recheck);
        $this->now = $now === null ? null : \Closure::fromCallable($now);
    }

    public function clock(): int
    {
        return $this->now !== null ? (int)($this->now)() : (int)(microtime(true) * 1000);
    }

    public function timeout(): int
    {
        return $this->pendingTimeoutMs ?? Operations::PENDING_TIMEOUT_MS;
    }
}

/**
 * The outcome of an execution attempt. `replayed` means it was answered from an existing record.
 *
 * `status`: `committed` (`result`; `recorded` false means `$fn` ran but the record could not be written), `failed` (`error`),
 * `aborted` (`reason`), `pending` (another execution of this id is in flight; `$fn` did not run here), `uncertain` (`reason`: the
 * earlier outcome is unknown; `$fn` did not run here), `refused` (`reason`: nothing ran and nothing was recorded) or, from the
 * {@see Executor}, `denied` (`authorization` is the denial; nothing ran).
 */
final class ExecuteOutcome
{
    public function __construct(
        public readonly string $status,
        public readonly string $operationId = '',
        public readonly mixed $result = null,
        public readonly string $error = '',
        public readonly string $reason = '',
        public readonly bool $replayed = false,
        public readonly bool $recorded = false,
        public readonly ?AuthorizeResult $authorization = null,
    ) {
    }

    public static function refused(string $reason): self
    {
        return new self('refused', reason: $reason);
    }

    /** The reference's JSON shape of the outcome. */
    public function toObj(): Obj
    {
        $o = Obj::of(['status' => $this->status]);
        switch ($this->status) {
            case 'committed':
                $o->set('operationId', $this->operationId);
                if ($this->result !== null) {
                    $o->set('result', $this->result);
                }
                $o->set('replayed', $this->replayed);
                $o->set('recorded', $this->recorded);
                break;
            case 'failed':
                $o->set('operationId', $this->operationId);
                $o->set('error', $this->error);
                $o->set('replayed', $this->replayed);
                break;
            case 'aborted':
            case 'uncertain':
                $o->set('operationId', $this->operationId);
                $o->set('reason', $this->reason);
                $o->set('replayed', $this->replayed);
                break;
            case 'pending':
                $o->set('operationId', $this->operationId);
                $o->set('replayed', $this->replayed);
                break;
            default:
                $o->set('reason', $this->reason);
        }
        return $o;
    }
}

final class Operations
{
    public const PENDING_TIMEOUT_MS = 300000;

    /** Native PHP values become JSON values, recursively: numbers a Num, an associative array an Obj (a result is then storable and comparable). */
    public static function jsonValue(mixed $v): mixed
    {
        if (is_int($v)) {
            return new Num((string)$v);
        }
        if (is_float($v)) {
            return is_finite($v) ? new Num(IntentV2::jsNumStr($v)) : $v;
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map([self::class, 'jsonValue'], $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set((string)$k, self::jsonValue($x));
            }
            return $o;
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::jsonValue($v->get($k)));
            }
            return $o;
        }
        return $v;
    }

    /** Settle an open record older than `$timeoutMs`: pending -> aborted (never started), executing -> uncertain. */
    private static function settleStale(OperationStore $store, OperationRecord $rec, int $now, int $timeoutMs): OperationRecord
    {
        if ($rec->state !== OperationRecord::PENDING && $rec->state !== OperationRecord::EXECUTING) {
            return $rec;
        }
        // `executing` is aged from the moment `$fn` was started (a slow re-check does not count against it)
        $start = $rec->state === OperationRecord::EXECUTING ? ($rec->executingAt ?? $rec->startedAt) : $rec->startedAt;
        if (!($now - $start > $timeoutMs)) {
            return $rec;
        }
        $next = $rec->state === OperationRecord::PENDING
            ? $rec->with(['state' => OperationRecord::ABORTED, 'finishedAt' => $now,
                'error' => "not started within $timeoutMs ms of the claim: the side effect never ran"])
            : $rec->with(['state' => OperationRecord::UNCERTAIN, 'finishedAt' => $now,
                'error' => "no outcome recorded within $timeoutMs ms of the start: the side effect may or may not have happened"]);
        $store->transition($rec->id, $rec->state, $next);
        // whatever is stored now (the original execution may have finished in between)
        return $store->get($rec->id) ?? $next;
    }

    /** Answer an execution attempt from an existing record (never runs anything). */
    private static function fromRecord(OperationStore $store, OperationRecord $rec0, int $now, int $timeoutMs): ExecuteOutcome
    {
        $rec = self::settleStale($store, $rec0, $now, $timeoutMs);
        $id = $rec->id;
        $or = static fn(?string $s, string $d): string => $s === null || $s === '' ? $d : $s;
        return match ($rec->state) {
            OperationRecord::COMMITTED => new ExecuteOutcome('committed', $id, $rec->result, replayed: true, recorded: true),
            OperationRecord::FAILED => new ExecuteOutcome('failed', $id, error: $or($rec->error, 'failed'), replayed: true),
            OperationRecord::ABORTED => new ExecuteOutcome('aborted', $id, reason: $or($rec->error, 'aborted'), replayed: true),
            OperationRecord::UNCERTAIN => new ExecuteOutcome('uncertain', $id, reason: $or($rec->error, 'outcome unknown'), replayed: true),
            OperationRecord::PENDING, OperationRecord::EXECUTING => new ExecuteOutcome('pending', $id, replayed: true),
            default => new ExecuteOutcome('uncertain', $id, reason: "unknown record state '{$rec->state}'", replayed: true),
        };
    }

    /** Answer an execution attempt from an existing record (never runs anything); used by the {@see Executor} for a replay. */
    public static function answerFromRecord(OperationStore $store, OperationRecord $rec, int $now, int $timeoutMs): ExecuteOutcome
    {
        return self::fromRecord($store, $rec, $now, $timeoutMs);
    }

    /** Leave `executing` (or `uncertain`, when recovery settled a slow execution) for the final state. */
    private static function finish(OperationStore $store, OperationRecord $rec, array $changes): bool
    {
        $out = $rec->with($changes);
        if ($store->transition($rec->id, $rec->state, $out)) {
            return true;
        }
        return $rec->state === OperationRecord::EXECUTING && $store->transition($rec->id, OperationRecord::UNCERTAIN, $out);
    }

    /** Answer from the record as it is stored now (a concurrent recovery or execution changed it). */
    private static function answerCurrent(OperationStore $store, string $id, int $now, int $timeoutMs): ExecuteOutcome
    {
        $cur = $store->get($id);
        return $cur === null
            ? new ExecuteOutcome('uncertain', $id, reason: 'the operation record disappeared', replayed: true)
            : self::fromRecord($store, $cur, $now, $timeoutMs);
    }

    /**
     * Execute an allowed {@see Authorize::authorize} result at most once, with a durable record (see {@see OperationRecord}).
     * `$fn` runs only if this call created the `pending` record and the re-check (when required) passed; every other outcome is
     * answered from the record. A throw from `$fn` is recorded as `failed` and returned, not re-thrown. A store that throws makes
     * the call a `refused` outcome (fail closed).
     *
     * @param callable(ExecutionHandle):mixed $fn
     */
    public static function executeAuthorized(AuthorizeResult $authorization, callable $fn, ExecuteOptions $opts): ExecuteOutcome
    {
        try {
            return self::execute($authorization, $fn, $opts);
        } catch (\Throwable $e) {
            return ExecuteOutcome::refused('executeAuthorized: the operation store failed (fail closed): ' . $e->getMessage());
        }
    }

    private static function execute(AuthorizeResult $az, callable $fn, ExecuteOptions $opts): ExecuteOutcome
    {
        $store = $opts->store;
        if ($store === null) {
            return ExecuteOutcome::refused('executeAuthorized: missing required component: store (fail closed)');
        }
        $op = $az->operation;
        $pcactn = $az->pcactn;
        if (!$az->allow || $op === null || $op->id === '' || $pcactn === null) {
            return ExecuteOutcome::refused('executeAuthorized: the authorization did not allow an operation');
        }
        if ($opts->operation !== null && !Authorize::isAuthorizedFor($az, $opts->operation)) {
            return ExecuteOutcome::refused('executeAuthorized: the authorization is not for this operation (verb, resource or params differ)');
        }
        $timeoutMs = $opts->timeout();
        $action = $pcactn->get('action');
        $reversibility = RevocationStaleness::effectiveReversibility($opts->reversibilityClass,
            $action instanceof Obj ? $action->get('reversibility_class') : null);
        $mustRecheck = $reversibility === 'irreversible' || $opts->recheckFor === 'always';
        if ($mustRecheck && $opts->recheck === null) {
            return ExecuteOutcome::refused("executeAuthorized: a $reversibility operation needs a recheck (revocation, expiry, approval) before it runs (fail closed)");
        }

        $handle = new ExecutionHandle($op->id, $op, $pcactn);
        $rec = new OperationRecord($op->id, OperationRecord::PENDING, $op->verb, $op->resource, $op->paramsDigest, $reversibility, $opts->clock());
        [$created, $existing] = $store->create($rec);
        if (!$created) {
            return $existing === null ? self::answerCurrent($store, $op->id, $opts->clock(), $timeoutMs)
                : self::fromRecord($store, $existing, $opts->clock(), $timeoutMs);
        }

        if ($mustRecheck) {
            $exp = $pcactn->get('exp');
            $expMs = $exp instanceof Num ? $exp->float() : null;
            if ($expMs !== null && (float)$opts->clock() > $expMs) {
                $rc = RecheckResult::refuse('the PCActn expired at ' . IntentV2::jsNumStr($expMs));
            } else {
                try {
                    $rc = ($opts->recheck)($handle);
                } catch (\Throwable $e) {
                    $rc = RecheckResult::refuse('recheck error (fail closed): ' . $e->getMessage());
                }
            }
            if (!($rc instanceof RecheckResult) || !$rc->ok) {
                $why = $rc instanceof RecheckResult ? ($rc->reason === '' ? 'refused' : $rc->reason) : 'refused';
                $reason = "recheck: $why";
                if (self::finish($store, $rec, ['state' => OperationRecord::ABORTED, 'error' => $reason, 'finishedAt' => $opts->clock()])) {
                    return new ExecuteOutcome('aborted', $rec->id, reason: $reason);
                }
                return self::answerCurrent($store, $rec->id, $opts->clock(), $timeoutMs);
            }
        }

        // the marker that separates "never started" from "maybe happened"; a recovery that settled the claim meanwhile wins
        $running = $rec->with(['state' => OperationRecord::EXECUTING, 'executingAt' => $opts->clock()]);
        if (!$store->transition($rec->id, OperationRecord::PENDING, $running)) {
            return self::answerCurrent($store, $rec->id, $opts->clock(), $timeoutMs);
        }

        try {
            $result = self::jsonValue($fn($handle));
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            try {
                self::finish($store, $running, ['state' => OperationRecord::FAILED, 'error' => $msg, 'finishedAt' => $opts->clock()]);
            } catch (\Throwable) {
                // the record stays executing and settles as uncertain: the outcome below is what the caller sees
            }
            return new ExecuteOutcome('failed', $rec->id, error: $msg);
        }
        try {
            $recorded = self::finish($store, $running, ['state' => OperationRecord::COMMITTED, 'result' => $result, 'finishedAt' => $opts->clock()]);
        } catch (\Throwable) {
            $recorded = false;
        }
        return new ExecuteOutcome('committed', $rec->id, $result, recorded: $recorded);
    }

    /**
     * Settle every open record older than `$olderThanMs` (run it at startup and periodically): pending -> aborted (the side
     * effect never started), executing -> uncertain. Returns the records it settled. Needs a store that is an
     * {@see OpenListingStore}. Nothing is re-run: reconcile each uncertain one with {@see resolveOperation}.
     *
     * @param callable|null $now `(): int` epoch milliseconds
     * @return list<OperationRecord>
     */
    public static function recoverOperations(OperationStore $store, ?int $olderThanMs = null, ?callable $now = null): array
    {
        if (!($store instanceof OpenListingStore)) {
            throw new \InvalidArgumentException('recoverOperations: the store has no listOpen (recover by id with recoverOperation)');
        }
        $out = [];
        foreach ($store->listOpen() as $r) {
            $u = self::recoverOperation($store, $r->id, $olderThanMs, $now);
            if ($u !== null && $u->state !== $r->state) {
                $out[] = $u;
            }
        }
        return $out;
    }

    /** {@see recoverOperations} for one id. Returns the record as it now stands (null: no record, the operation never started). */
    public static function recoverOperation(OperationStore $store, string $id, ?int $olderThanMs = null, ?callable $now = null): ?OperationRecord
    {
        $r = $store->get($id);
        return $r === null ? null : self::settleStale($store, $r, $now !== null ? (int)$now() : (int)(microtime(true) * 1000),
            $olderThanMs ?? self::PENDING_TIMEOUT_MS);
    }

    /**
     * Settle an `uncertain` record after reconciling with the downstream system (look the idempotency key up there):
     * `['state' => 'committed', 'result' => ...]` or `['state' => 'failed', 'error' => '...']`. Returns false when the record is
     * not uncertain (or unknown).
     *
     * @param array{state:string, result?:mixed, error?:string} $outcome
     * @param callable|null $now `(): int` epoch milliseconds
     */
    public static function resolveOperation(OperationStore $store, string $id, array $outcome, ?callable $now = null): bool
    {
        $r = $store->get($id);
        if ($r === null || $r->state !== OperationRecord::UNCERTAIN) {
            return false;
        }
        $at = $now !== null ? (int)$now() : (int)(microtime(true) * 1000);
        $next = match ($outcome['state'] ?? null) {
            OperationRecord::COMMITTED => $r->with(['state' => OperationRecord::COMMITTED, 'result' => self::jsonValue($outcome['result'] ?? null), 'finishedAt' => $at]),
            OperationRecord::FAILED => $r->with(['state' => OperationRecord::FAILED, 'error' => (string)($outcome['error'] ?? ''), 'finishedAt' => $at]),
            default => throw new \InvalidArgumentException('resolveOperation: the outcome state must be committed or failed'),
        };
        return $store->transition($id, OperationRecord::UNCERTAIN, $next);
    }
}
