<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Operations.php';
require_once __DIR__ . '/PlanLifecycle.php';

/**
 * The operation-record settings of the guarded handler ({@see AuthorizeOptions}'s `executor`): the store and the re-check policy
 * the {@see Executor} runs with. See {@see Executor::__construct} for the members.
 */
final class ExecutorOptions
{
    public function __construct(
        public readonly OperationStore $operations,
        public readonly mixed $recheck = null,
        public readonly string $recheckFor = 'irreversible',
        public readonly mixed $reversibilityClassOf = null,
        public readonly ?int $pendingTimeoutMs = null,
    ) {
    }
}

/**
 * Executor: {@see Authorize::authorize} + {@see Operations::executeAuthorized} in one call, with retries answered from the record.
 * A second presentation of the same PCActn is refused by `authorize` as a replay; if that replay is the ONLY failing check (the
 * proof, binding, policy and revocation all still pass now) and a record exists for its operation id and this operation, the
 * record's outcome is returned (`replayed: true`) instead of the bare denial. No record means the first attempt never reached
 * execution: the denial stands (the authorization was consumed; the agent signs a fresh PCActn).
 *
 * Before an irreversible operation the executor re-runs `isRevoked` against the grant from `resolveGrant`, checks the PCActn's
 * expiry, and (with `plans` in the authorize configuration) that the registered plan is still executable for the node.
 */
final class Executor
{
    /** @var \Closure|null */
    private readonly ?\Closure $recheck;
    /** @var \Closure|null */
    private readonly ?\Closure $classOf;
    /** @var \Closure|null */
    private readonly ?\Closure $now;

    /**
     * @param OperationStore $operations REQUIRED: the operation record store
     * @param array<string,mixed> $authorize the named arguments of {@see Authorize::authorize} (`audience`, `resolveGrant`,
     *        `stateStore`, `isRevoked`, `plans`, `context`, ...) except `pcactn` and `operation`, which are per call
     * @param callable|null $recheck extra re-check before an irreversible operation (for example a step-up approval still
     *        stands): `(ExecutionHandle): RecheckResult`
     * @param string $recheckFor `'irreversible'` (default) or `'always'`
     * @param callable|null $reversibilityClassOf `(array|Obj $operation): ?string` the server's class for an operation (catalog)
     * @param int|null $pendingTimeoutMs an open record older than this is settled (default 5 minutes)
     * @param callable|null $now `(): int` epoch milliseconds (default: the wall clock; `authorize['now']`, when set, wins for the authorization)
     */
    public function __construct(
        private readonly OperationStore $operations,
        private readonly array $authorize,
        ?callable $recheck = null,
        private readonly string $recheckFor = 'irreversible',
        ?callable $reversibilityClassOf = null,
        private readonly ?int $pendingTimeoutMs = null,
        ?callable $now = null,
    ) {
        $this->recheck = $recheck === null ? null : \Closure::fromCallable($recheck);
        $this->classOf = $reversibilityClassOf === null ? null : \Closure::fromCallable($reversibilityClassOf);
        $this->now = $now === null ? null : \Closure::fromCallable($now);
    }

    private function clock(): int
    {
        return $this->now !== null ? (int)($this->now)() : (int)(microtime(true) * 1000);
    }

    /** The executor's own re-check: the grant is still known and not revoked, a registered plan is still executable, then the caller's extra re-check. */
    private function recheckOf(): \Closure
    {
        $cfg = $this->authorize;
        return function (ExecutionHandle $h) use ($cfg): RecheckResult {
            $ref = $h->pcactn->get('grant_ref');
            try {
                $grant = is_string($ref) && is_callable($cfg['resolveGrant'] ?? null) ? $cfg['resolveGrant']($ref) : null;
            } catch (\Throwable) {
                $grant = null;
            }
            if (!($grant instanceof Obj)) {
                return RecheckResult::refuse('the grant is no longer known');
            }
            try {
                $revoked = is_callable($cfg['isRevoked'] ?? null) ? $cfg['isRevoked']($h->pcactn, $grant) : null;
            } catch (\Throwable) {
                $revoked = null;
            }
            if ($revoked !== false) {
                return RecheckResult::refuse($revoked === true ? 'the grant has been revoked' : 'revocation could not be checked');
            }
            // a registered plan must still be executable: not revoked, the principal's approval not expired
            $plans = $cfg['plans'] ?? null;
            $pl = $h->pcactn->get('plan');
            $root = $pl instanceof Obj ? $pl->get('root') : null;
            if ($plans instanceof PlanRegistry && is_string($root) && $plans->get($ref, $root) !== null) {
                $ps = $plans->check($ref, $root, ['nodeId' => is_string($pl->get('node_id')) ? $pl->get('node_id') : null, 'now' => $this->clock()]);
                if (!$ps['executable']) {
                    return RecheckResult::refuse($ps['reason'] ?? 'plan is ' . $ps['state']);
                }
            }
            return $this->recheck !== null ? ($this->recheck)($h) : RecheckResult::ok();
        };
    }

    /**
     * Authorize `$pcactn` for `$operation` and, when allowed, execute `$fn` at most once. Status `denied` carries the
     * authorization denial (`authorization`) and nothing ran. A missing store is a refusal.
     *
     * @param Obj|string|null $pcactn
     * @param callable(ExecutionHandle):mixed $fn
     */
    public function run(mixed $pcactn, mixed $operation, callable $fn): ExecuteOutcome
    {
        $cfg = $this->authorize;
        $cfg['now'] ??= $this->clock();
        $r = Authorize::authorize(...$cfg, pcactn: $pcactn, operation: $operation);
        $cls = $operation !== null && $this->classOf !== null ? ($this->classOf)($operation) : null;
        $opts = new ExecuteOptions($this->operations, $operation, $this->recheckOf(), $this->recheckFor, is_string($cls) ? $cls : null,
            $this->pendingTimeoutMs, fn(): int => $this->clock());
        if ($r->allow) {
            return Operations::executeAuthorized($r, $fn, $opts);
        }
        $denied = new ExecuteOutcome('denied', authorization: $r);
        $failed = array_keys(array_filter($r->checks, static fn(string $s): bool => $s === 'fail'));
        if ($r->status !== 403 || $failed !== ['replay'] || $r->pcactn === null || !Authorize::validOperationShape($operation)) {
            return $denied;
        }
        // a replay of a proof that is otherwise still valid now: answer from the record, if the first attempt made one
        try {
            $rec = $this->operations->get(Pca::hashCanonical($r->pcactn));
            if ($rec === null || $rec->verb !== Authorize::operationMember($operation, 'verb') || $rec->resource !== Authorize::operationMember($operation, 'resource')
                || $rec->paramsDigest !== Authorize::operationParamsDigest($operation)) {
                return $denied;
            }
            return Operations::answerFromRecord($this->operations, $rec, $this->clock(), $this->pendingTimeoutMs ?? Operations::PENDING_TIMEOUT_MS);
        } catch (\Throwable $e) {
            return ExecuteOutcome::refused('executor: the operation store failed (fail closed): ' . $e->getMessage());
        }
    }
}
