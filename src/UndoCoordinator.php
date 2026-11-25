<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Decide.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Operations.php';
require_once __DIR__ . '/Undo.php';
require_once __DIR__ . '/UndoServer.php';
require_once __DIR__ . '/UndoStore.php';

/**
 * The undo-window coordinator: admission, the durable ledger, the human surface and the real rollback.
 *
 *   admit      ELIGIBILITY. An action gets a veto window only when the policy does not turn windows off, its signed reversibility class is
 *              `reversible`, the `engine` (the verifier's own CONFIRMED action definitions) returns a plan, and the compensating action is
 *              AUTHORIZED under the original grant (the policy VM releases it over the original PCActn's verified chain).
 *   open       writes the record DURABLY before the effect may run (a store that is not durable is refused), signs the `opened` receipt,
 *              mints the one-click undo token and notifies the principal. A window nobody was told about is no window: a failed notification
 *              aborts the record and raises an alert.
 *   veto       a valid token (or an operator, a fraud proof, a revocation policy) inside the window moves `open -> vetoed` exactly once and
 *              starts the compensation.
 *   compensate re-decides the compensating action under the grant AS IT STOOD AT ADMISSION, then runs it at most once per attempt through
 *              the `operations` store and the `compensate` executor. Success: `compensated` and the budget reservation released.
 *              Anything else: `compensation_failed`, the reservation kept and an alert raised (never silent).
 *   finalizeDue closes the windows whose time is up (`open -> finalized`) and commits their budget reservations.
 *
 * Synchronous: every injected callable is a plain callable. The budget ledger (`commit(key, id)` and `release(key, id, evidence)` returning
 * `['outcome' => 'settled' | 'replayed' | ...]`, e.g. a {@see KvBudgetLedger}) and the bond ledger (`slashBond(params)`, e.g. a {@see StoreBondLedger}) are duck-typed objects.
 * A budget release carries NO evidence unless the `budget` option is `['ledger' => ..., 'evidence' => fn(Obj $reservation, string $reason)]` (for example a release signed with {@see BudgetRelease::signRelease}): there is no default release signing.
 */
final class UndoCoordinatorFactory
{
    /**
     * Build the coordinator. Options: store, engine (a closure `(Obj $op, array $ctx): ?Obj` or an object with `plan`), signerSecret (32 bytes), audience,
     * resolveGrant `(string $ref, Obj $pcactn): ?Obj`, compensate `(array $call): mixed` (throws on failure), operations, notifier, alert `(array): void`,
     * and optionally policy, window, resolveTarget, budget, pqPins, effectTimeoutMs, now, relay, insecureVolatileStore, bonds. Throws UndoError `config`
     * for a missing component and `not_durable` for a volatile store (fail closed).
     *
     * @param array<string,mixed> $o
     */
    public static function create(array $o): UndoCoordinator
    {
        $et = $o['effectTimeoutMs'] ?? 0;
        if (!((is_int($et) || is_float($et)) && $et >= 0)) { // NaN and a negative or non-numeric timeout refuse; +INF is the never-time-out cap
            throw new UndoError('config', 'undo coordinator: effectTimeoutMs must be a non-negative number');
        }
        $missing = UndoServer::missingUndoComponents(self::asEngineObject($o));
        if ($missing) {
            throw new UndoError('config', 'undo coordinator: missing required component(s): ' . implode(', ', $missing));
        }
        if ($o['store']->durable() !== true && ($o['insecureVolatileStore'] ?? false) !== true) {
            throw new UndoError('not_durable', 'an undo ledger must be durable: a restart would lose every open window and its compensation');
        }
        return new UndoCoordinator($o);
    }

    /** @param array<string,mixed> $o @return array<string,mixed> */
    private static function asEngineObject(array $o): array
    {
        if (($o['engine'] ?? null) instanceof \Closure) {
            $f = $o['engine'];
            $o['engine'] = new class ($f) {
                public function __construct(private readonly \Closure $f)
                {
                }

                public function plan(Obj $op, array $ctx = []): ?Obj
                {
                    return ($this->f)($op, $ctx);
                }
            };
        }
        return $o;
    }

    /** @internal */
    public static function engineOf(array $o): object
    {
        return self::asEngineObject($o)['engine'];
    }
}

final class UndoCoordinator
{
    private const MAX_CAS = 64;
    public const RELAY_GRACE_MS = UndoServer::UNDO_RELAY_GRACE_MS;

    public readonly string $signerPublic;
    private readonly string $secret;
    private readonly UndoStore $store;
    private readonly object $engine;
    private readonly ?\Closure $clock;
    /** @var array{ledger:object,evidence?:callable}|null */
    private readonly ?array $budget;

    /** @param array<string,mixed> $o */
    public function __construct(private readonly array $o)
    {
        $this->store = $o['store'];
        $this->secret = $o['signerSecret'] instanceof KeyPair ? throw new UndoError('config', 'signerSecret is the 32-byte seed') : $o['signerSecret'];
        $this->engine = UndoCoordinatorFactory::engineOf($o);
        $this->clock = isset($o['now']) ? \Closure::fromCallable($o['now']) : null;
        $b = $o['budget'] ?? null;
        $this->budget = $b === null ? null : (is_array($b) && isset($b['ledger']) ? $b : ['ledger' => $b]);
        $this->signerPublic = UndoServer::undoSignerPublic($this->secret);
    }

    // ---- plumbing ----

    private function now(): int
    {
        $t = $this->clock ? ($this->clock)() : microtime(true) * 1000;
        if (!is_int($t) && (!is_float($t) || !is_finite($t))) {
            throw new UndoError('invalid', 'the clock returned a non-finite time');
        }
        return (int)floor($t);
    }

    private static function n(int $i): Num
    {
        return new Num((string)$i);
    }

    private static function int(mixed $x): int
    {
        return (int)Js::num($x);
    }

    /** @param array<string,mixed> $a */
    private function alert(array $a): void
    {
        try {
            ($this->o['alert'])($a);
        } catch (\Throwable) { // an alert sink that throws is itself a failure the operator must see
            fwrite(STDERR, 'pca undo alert (' . $a['code'] . ') for ' . $a['record'] . ': ' . $a['reason'] . "\n");
        }
    }

    /** @param array<string,mixed> $n @return array{delivered:bool,reason?:string} */
    private function notify(array $n): array
    {
        try {
            $r = $this->o['notifier']->notify($n);
            return is_array($r) && ($r['delivered'] ?? null) === true ? ['delivered' => true]
                : ['delivered' => false, 'reason' => is_array($r) && !empty($r['reason']) ? $r['reason'] : 'no channel delivered the notice'];
        } catch (\Throwable $e) {
            return ['delivered' => false, 'reason' => $e->getMessage() ?: 'notifier error'];
        }
    }

    /** @param array<string,mixed> $ev @return array<string,mixed> */
    private function apply(string $id, Obj $ev, ?int $checkAt = null): array
    {
        for ($i = 0; $i < self::MAX_CAS; $i++) {
            $cur = $this->store->get($id);
            if ($cur === null) {
                return ['refused' => 'unknown', 'reason' => "no undo record $id"];
            }
            $t = $this->now();
            $tr = Undo::transition($cur, $ev, $checkAt ?? $t); // a relayed veto is judged as of when the principal made it
            if ($tr['outcome'] === 'refused') {
                return ['refused' => $tr['code'], 'reason' => $tr['reason']];
            }
            if ($tr['outcome'] === 'replayed') {
                return ['record' => $tr['record'], 'applied' => false];
            }
            $nxt = Undo::withReceipt($tr['record'], $tr['receipt'], $t, $this->secret);
            if ($this->store->replace($id, self::int($cur->get('ver')), $nxt)) {
                return ['record' => $nxt, 'applied' => true];
            }
        }
        throw new UndoError('conflict_exhausted', "undo record $id kept changing");
    }

    /** @return array<string,mixed> */
    private function must(string $id, Obj $ev): array
    {
        $r = $this->apply($id, $ev);
        if (isset($r['refused'])) {
            throw new UndoError('invalid', $r['refused'] . ': ' . $r['reason']);
        }
        return $r;
    }

    private function settleBudget(Obj $rec, string $how): void
    {
        $b = $this->budget;
        if (!$b || !$rec->get('budget')) {
            return;
        }
        foreach ($rec->get('budget') as $r) {
            try {
                if ($how === 'commit') {
                    $o = $b['ledger']->commit($r->get('key'), $r->get('id'));
                } else {
                    $ev = isset($b['evidence']) && is_callable($b['evidence']) ? ($b['evidence'])($r, $how) : null; // no evidence unless the caller supplies it
                    $o = $b['ledger']->release($r->get('key'), $r->get('id'), $ev);
                }
                $outcome = is_array($o) ? ($o['outcome'] ?? null) : null;
                if (!in_array($outcome, ['settled', 'replayed'], true)) {
                    $this->alert(['level' => 'warning', 'code' => 'budget_settle_failed', 'record' => $rec->get('id'),
                        'reason' => "$how of " . $r->get('key') . '/' . $r->get('id') . ': ' . IntentWb::jsStr($outcome)]);
                }
            } catch (\Throwable $e) {
                $this->alert(['level' => 'warning', 'code' => 'budget_settle_failed', 'record' => $rec->get('id'),
                    'reason' => "$how of " . $r->get('key') . '/' . $r->get('id') . ': ' . ($e->getMessage() ?: 'error')]);
            }
        }
    }

    /** @return array<string,mixed> */
    private function policyOf(Obj $op, Obj $grant): array
    {
        $p = isset($this->o['policy']) ? ($this->o['policy'])($op, $grant) : null;
        return $p instanceof Obj ? self::asArray($p) : (is_array($p) ? $p : []);
    }

    /** @return array<string,mixed> */
    private static function asArray(Obj $o): array
    {
        $out = [];
        foreach ($o->keys() as $k) {
            $out[$k] = $o->get($k);
        }
        return $out;
    }

    /** @return array{ok:bool,reason:string} */
    private function compensationAllowed(Obj $pc, Obj $grant, Obj $op, int $at): array
    {
        $in = Obj::of(['grant' => $grant, 'trustedRoot' => $grant, 'chain' => $pc->get('cap_chain'),
            'action' => Obj::of(['action' => Obj::of(['verb' => $op->get('verb'), 'resource' => $op->get('resource'), 'params' => $op->get('params') ?? new Obj()])]),
            'risk' => new Obj(), 'budget' => Obj::of(['B' => self::n(0), 'tau' => self::n($at)]), 'now' => self::n($at)]);
        if (($this->o['pqPins'] ?? null) !== null) {
            $in->set('pqPins', $this->o['pqPins']);
        }
        $d = Decide::decide($in);
        if ($d['releaseGuardianShare']) {
            return ['ok' => true, 'reason' => ''];
        }
        foreach ($d['reasons'] as $r) {
            if (!str_starts_with($r, 'risk input')) {
                return ['ok' => false, 'reason' => $r];
            }
        }
        return ['ok' => false, 'reason' => 'the grant does not authorize the compensating action'];
    }

    private static function classRank(mixed $c): int
    {
        return is_string($c) ? (['reversible' => 0, 'rate_limited' => 1, 'costly' => 1, 'irreversible' => 2][$c] ?? 2) : 2;
    }

    private static function strip(Obj $r): Obj
    {
        return $r->without('pcactn', 'receipts');
    }

    // ---- the API ----

    /**
     * ELIGIBILITY: an admission array, or `['refused' => reason]`. Never throws.
     *
     * @return array<string,mixed>
     */
    public function admit(Obj $pcactn, Obj $operation, bool $converted, ?Obj $grant = null): array
    {
        try {
            if (!is_string($operation->get('verb')) || !is_string($operation->get('resource'))) {
                return ['refused' => 'no operation'];
            }
            $g = $grant ?? ($this->o['resolveGrant'])($pcactn->get('grant_ref'), $pcactn);
            if (!$g) {
                return ['refused' => 'unknown grant'];
            }
            $pol = $this->policyOf($operation, $g);
            $mode = $pol['mode'] ?? 'always';
            if ($mode === 'off') {
                return ['refused' => 'policy: undo windows are off'];
            }
            if ($mode === 'escalations' && !$converted) {
                return ['refused' => 'policy: windows only replace approvals'];
            }
            $class = $pcactn->get('action') instanceof Obj ? $pcactn->get('action')->get('reversibility_class') : null;
            if (self::classRank($class) !== 0) { // the stricter of the signed class and the definition applies
                return ['refused' => 'the signed class is ' . IntentWb::jsStr($class)];
            }
            $id = IntentV2::hashCanonical($pcactn);
            $plan = $this->engine->plan($operation, ['operationId' => $id]);
            if (!$plan) {
                return ['refused' => 'not confirmed reversible, or no confirmed compensating action'];
            }
            $pc = $plan->get('compensation');
            $comp = Obj::of(['verb' => $pc->get('verb'), 'resource' => $operation->get('resource'), 'params' => $pc->get('params'), 'undo_of' => $id, 'def_digest' => $pc->get('def_digest')]);
            if ($pc->get('target_param') !== null) {
                $comp->set('target_param', $pc->get('target_param'));
            }
            $t = $this->now();
            $allowed = $this->compensationAllowed($pcactn, $g, Obj::of(['verb' => $comp->get('verb'), 'resource' => $comp->get('resource'), 'params' => $comp->get('params')]), $t);
            if (!$allowed['ok']) {
                return ['refused' => 'the compensating action is not authorized under the grant: ' . $allowed['reason']];
            }
            $windowMs = Undo::resolveWindow($pol['windowMs'] ?? null, $this->o['window'] ?? null);
            return ['id' => $id, 'opened_at' => $t, 'window_end' => $t + $windowMs, 'converted' => $converted, 'plan' => $plan, 'compensation' => $comp, 'pcactn' => $pcactn,
                'grant' => $g, 'operation' => Obj::of(['verb' => $operation->get('verb'), 'resource' => $operation->get('resource'), 'params' => $operation->get('params') ?? new Obj()])];
        } catch (\Throwable $e) {
            return ['refused' => 'undo admission error (fail closed): ' . ($e->getMessage() ?: 'unknown')];
        }
    }

    /** @return array<string,mixed> */
    private function infoOf(Obj $rec): array
    {
        return ['id' => $rec->get('id'), 'window_end' => $rec->get('window_end'), 'converted' => $rec->get('converted'),
            'compensation' => ['verb' => $rec->get('compensation')->get('verb'), 'resource' => $rec->get('compensation')->get('resource')],
            'token' => Undo::encodeToken(Undo::signToken($rec, new KeyPair($this->secret))),
            'obligation' => ['kind' => 'undo_window', 'params' => Obj::of(['id' => $rec->get('id'), 'window_end' => $rec->get('window_end')]), 'due' => $rec->get('window_end')]];
    }

    /**
     * Write the record durably, sign the `opened` receipt, mint the one-click token and tell the principal. $bond: `['ref', 'challengeEndsAt']`.
     *
     * @param array<string,mixed> $adm an admit() result
     * @param array{ref:string,challengeEndsAt:int|float}|null $bond
     * @return array<string,mixed>
     */
    public function open(array $adm, ?array $bond = null): array
    {
        $pc = $adm['pcactn'];
        $chain = $pc->get('cap_chain');
        $windowEnd = $bond ? max($adm['window_end'], (int)floor($bond['challengeEndsAt'])) : $adm['window_end'];
        $cdig = Undo::compensationDigest($adm['compensation']);
        $base = Obj::of(['v' => new Num('1'), 'id' => $adm['id'], 'aud' => $this->o['audience'], 'grant_ref' => $pc->get('grant_ref'), 'holder' => $chain[count($chain) - 1]->get('holder'),
            'principal' => $adm['grant']->get('issuer'),
            'action' => Obj::of(['verb' => $adm['operation']->get('verb'), 'resource' => $adm['operation']->get('resource'), 'params_digest' => $pc->get('action')->get('params_digest'),
                'def_digest' => $adm['plan']->get('def_digest')]),
            'compensation' => $adm['compensation'], 'compensation_digest' => $cdig]);
        if ($adm['plan']->get('render_digest') !== null) {
            $base->set('render_digest', $adm['plan']->get('render_digest'));
        }
        foreach (['opened_at' => self::n($adm['opened_at']), 'window_end' => self::n($windowEnd), 'converted' => $adm['converted'], 'state' => 'open', 'ver' => self::n(0),
            'pcactn' => IntentV2::canonicalize($pc)] as $k => $v) {
            $base->set($k, $v);
        }
        if ($bond) {
            $base->set('bond_ref', $bond['ref']);
        }
        $base->set('attempt', self::n(0));
        $base->set('receipts', []);
        $rec = Undo::withReceipt($base, ['event' => 'opened', 'note' => $adm['converted'] ? 'converted' : ''], $adm['opened_at'], $this->secret);
        $c = $this->store->create($rec);
        if (!$c['created']) {
            // a retry of the same admission returns the same window; anything else is a different action under the same id
            if ($c['record']->get('compensation_digest') !== $cdig || $c['record']->get('state') !== 'open') {
                throw new UndoError('invalid', 'undo record ' . $adm['id'] . ' already exists with other terms or state ' . $c['record']->get('state'));
            }
            return $this->infoOf($c['record']);
        }
        $info = $this->infoOf($rec);
        $notice = ['kind' => 'opened', 'record' => self::strip($rec), 'token' => $info['token']];
        if ($adm['plan']->get('render')) {
            $notice['render'] = $adm['plan']->get('render');
        }
        $n = $this->notify($notice);
        if (!$n['delivered']) {
            $this->apply($rec->get('id'), Obj::of(['kind' => 'abort', 'reason' => 'notify_failed']));
            $this->alert(['level' => 'critical', 'code' => 'notify_failed', 'record' => $rec->get('id'),
                'reason' => 'the principal could not be told about the undo window: ' . ($n['reason'] ?? 'not delivered')]);
            throw new UndoError('invalid', 'notify_failed: the undo window could not be announced (' . ($n['reason'] ?? 'not delivered') . ')');
        }
        return $info;
    }

    public function get(string $id): ?Obj
    {
        return $this->store->get($id);
    }

    /** Hold aggregate budget reservations `[{key, id}]` until the window closes. @param list<array{key:string,id:string}> $reservations */
    public function holdBudget(string $id, array $reservations): Obj
    {
        for ($i = 0; $i < self::MAX_CAS; $i++) {
            $cur = $this->store->get($id);
            if ($cur === null) {
                throw new UndoError('invalid', "no undo record $id");
            }
            if (!in_array($cur->get('state'), ['open', 'vetoed'], true)) {
                throw new UndoError('invalid', 'a ' . $cur->get('state') . ' record holds no budget');
            }
            $nxt = $cur->without();
            $nxt->set('budget', array_merge($cur->get('budget') ?? [], array_map(static fn(array $r): Obj => Obj::of(['key' => $r['key'], 'id' => $r['id']]), $reservations)));
            $nxt->set('ver', self::n(self::int($cur->get('ver')) + 1));
            if ($this->store->replace($id, self::int($cur->get('ver')), $nxt)) {
                return $nxt;
            }
        }
        throw new UndoError('conflict_exhausted', "undo record $id kept changing");
    }

    /** Report the original effect (its result names the compensation target). A veto that arrived while it ran is acted on now. */
    public function recordEffect(string $id, mixed $result = null, bool $hasResult = false): Obj
    {
        $ev = Obj::of(['kind' => 'effect']);
        if ($hasResult || $result !== null) {
            $ev->set('result', $result);
        }
        $r = $this->must($id, $ev);
        return $r['record']->get('state') === 'vetoed' ? $this->runCompensation($r['record']) : $r['record'];
    }

    public function abort(string $id, string $reason): Obj
    {
        $r = $this->must($id, Obj::of(['kind' => 'abort', 'reason' => $reason]));
        if ($r['applied']) {
            $this->settleBudget($r['record'], 'effect_not_run');
        }
        return $r['record'];
    }

    private function finishCompensated(Obj $rec): Obj
    {
        if ($rec->get('state') === 'compensated') {
            $this->settleBudget($rec, 'rollback');
            $this->notify(['kind' => 'compensated', 'record' => self::strip($rec)]);
        }
        return $rec;
    }

    private function runCompensation(Obj $rec0): Obj
    {
        $rec = $rec0;
        if ($rec->get('state') !== 'vetoed') {
            return $rec;
        }
        $t = $this->now();
        $effectTimeout = $this->o['effectTimeoutMs'] ?? 300000; // +INF stays infinite (an (int) cast would make it 0)
        $veto = $rec->get('veto');
        if ($rec->get('effect') === null && $t - ($veto instanceof Obj && $veto->get('at') !== null ? self::int($veto->get('at')) : $t) < $effectTimeout) {
            return $rec; // wait for the effect report (recordEffect resumes)
        }
        $pc = Json::parseStrict($rec->get('pcactn'));
        $grant = ($this->o['resolveGrant'])($rec->get('grant_ref'), $pc);
        $fail = function (string $reason, string $code = 'compensation_failed') use ($rec): Obj {
            $r = $this->apply($rec->get('id'), Obj::of(['kind' => 'compensation_failed', 'reason' => $reason]));
            $out = isset($r['refused']) ? ($this->store->get($rec->get('id')) ?? $rec) : $r['record'];
            if (!isset($r['refused']) && $r['applied']) {
                $this->alert(['level' => 'critical', 'code' => $code, 'record' => $rec->get('id'), 'reason' => $reason]);
                $this->notify(['kind' => 'compensation_failed', 'record' => self::strip($out)]);
            }
            return $out;
        };
        if (!$grant) {
            return $fail('the grant is no longer known: the compensation cannot be authorized', 'compensation_denied');
        }
        $comp = $rec->get('compensation');
        $params = $comp->get('params')->without();
        $tp = $comp->get('target_param');
        if ($tp !== null) {
            if (isset($this->o['resolveTarget'])) {
                $target = ($this->o['resolveTarget'])($rec);
            } else {
                $res = $rec->get('effect') instanceof Obj ? $rec->get('effect')->get('result') : null;
                $target = $res instanceof Obj && is_string($res->get('id')) && $res->get('id') !== '' ? $res->get('id') : null;
            }
            if ($target === null) {
                return $fail("the target '$tp' of the compensation is unknown (no effect result names it)");
            }
            $params->set($tp, $target);
        }
        $op = Obj::of(['verb' => $comp->get('verb'), 'resource' => $comp->get('resource'), 'params' => $params]);
        $dec = $this->compensationAllowed($pc, $grant, $op, self::int($rec->get('opened_at')));
        if (!$dec['ok']) {
            return $fail('the compensating action is not authorized under the grant: ' . $dec['reason'], 'compensation_denied');
        }
        $ops = $this->o['operations'];
        // at most once per attempt: the operation record is created before the compensator runs
        $opId = IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/undo-compensation-op/v1', 'record' => $rec->get('id'), 'attempt' => $rec->get('attempt')]));
        $orec = new OperationRecord($opId, 'pending', $op->get('verb'), $op->get('resource'), IntentV2::hashCanonical($params), 'irreversible', $t);
        [$created, $prev] = $ops->create($orec);
        if (!$created) {
            if ($prev->state === 'committed') {
                $ev = Obj::of(['kind' => 'compensated']);
                if ($prev->result !== null) {
                    $ev->set('result', $prev->result);
                }
                $r = $this->apply($rec->get('id'), $ev);
                return $this->finishCompensated(isset($r['refused']) ? $rec : $r['record']);
            }
            if (in_array($prev->state, ['failed', 'uncertain'], true)) {
                return $fail('compensation attempt ' . self::int($rec->get('attempt')) . ' ' . $prev->state . ': ' . ($prev->error ?? ''));
            }
            if ($prev->state === 'aborted') {
                $r = $this->apply($rec->get('id'), Obj::of(['kind' => 'compensation_failed', 'reason' => 'attempt never started']));
                if (isset($r['refused'])) {
                    return $rec;
                }
                $again = $this->apply($rec->get('id'), Obj::of(['kind' => 'retry']));
                return isset($again['refused']) ? $r['record'] : $this->runCompensation($again['record']);
            }
            // pending / executing: another worker holds it, or a crash; stale ones are settled here
            if ($t - ($prev->executingAt ?? $prev->startedAt) > $effectTimeout) {
                $settled = $prev->state === 'pending' ? $prev->with(['state' => 'aborted', 'error' => 'never started', 'finishedAt' => $t])
                    : $prev->with(['state' => 'uncertain', 'error' => 'no outcome recorded: the compensation may or may not have run', 'finishedAt' => $t]);
                $ops->transition($prev->id, $prev->state, $settled);
                return $this->runCompensation($this->store->get($rec->get('id')) ?? $rec);
            }
            return $rec;
        }
        // re-read under the record: a concurrent retry or resolution wins
        $cur = $this->store->get($rec->get('id'));
        if ($cur === null || $cur->get('state') !== 'vetoed' || self::int($cur->get('attempt')) !== self::int($rec->get('attempt'))) {
            $ops->transition($opId, 'pending', $orec->with(['state' => 'aborted', 'error' => 'the undo record moved on', 'finishedAt' => $this->now()]));
            return $cur ?? $rec;
        }
        $running = $orec->with(['state' => 'executing', 'executingAt' => $this->now()]);
        if (!$ops->transition($opId, 'pending', $running)) {
            return $this->store->get($rec->get('id')) ?? $rec;
        }
        $call = ['operation' => $op, 'idempotencyKey' => $opId, 'undoOf' => $rec->get('id'), 'record' => $cur->without('pcactn')];
        $eff = $rec->get('effect');
        if ($eff instanceof Obj && $eff->get('result') !== null) {
            $call['originalResult'] = $eff->get('result');
        }
        try {
            $result = ($this->o['compensate'])($call);
        } catch (\Throwable $e) {
            $error = $e->getMessage();
            try {
                $ops->transition($opId, 'executing', $running->with(['state' => 'failed', 'error' => $error, 'finishedAt' => $this->now()]));
            } catch (\Throwable) {
            }
            return $fail("the compensating action failed: $error");
        }
        try {
            $ops->transition($opId, 'executing', $running->with(['state' => 'committed', 'result' => $result, 'finishedAt' => $this->now()]));
        } catch (\Throwable) {
        }
        $ev = Obj::of(['kind' => 'compensated']);
        if ($result !== null) {
            $ev->set('result', $result);
        }
        $r = $this->apply($rec->get('id'), $ev);
        if (isset($r['refused'])) {
            return $this->store->get($rec->get('id')) ?? $rec;
        }
        return $this->finishCompensated($r['record']);
    }

    /**
     * Veto with the one-click $token (the principal; $at is the relayed veto time), as an authenticated $operator of this server, or with a prepared
     * $veto (revocation, fraud proof). `['ok' => true, 'record', 'replayed']` or `['ok' => false, 'code', 'reason']`.
     *
     * @return array<string,mixed>
     */
    public function veto(string $id, mixed $token = null, ?int $at = null, ?string $operator = null, ?Obj $veto = null): array
    {
        try {
            $cur = $this->store->get($id);
            if ($cur === null) {
                return ['ok' => false, 'code' => 'unknown', 'reason' => "no undo record $id"];
            }
            $t = $this->now();
            $checkAt = null;
            if ($token !== null) {
                if ($at !== null) {
                    if ($at > $t || $at < self::int($cur->get('opened_at'))) {
                        return ['ok' => false, 'code' => 'malformed', 'reason' => 'a relayed veto time must lie between the opening of the window and now'];
                    }
                    $t = $checkAt = $at;
                }
                $tok = is_string($token) ? Undo::decodeToken($token) : $token;
                $chk = Undo::tokenCheck($tok, $this->signerPublic, $cur, $t);
                if ($chk !== 'ok') {
                    return ['ok' => false, 'code' => $chk, 'reason' => "the undo token was refused ($chk)"];
                }
                $v = Obj::of(['at' => self::n($t), 'via' => 'token', 'by' => $cur->get('principal'), 'evidence' => Undo::tokenDigest($tok)]);
            } elseif ($operator !== null) {
                if ($operator === '') {
                    return ['ok' => false, 'code' => 'malformed', 'reason' => 'an operator veto names the operator'];
                }
                $v = Obj::of(['at' => self::n($t), 'via' => 'operator', 'by' => $operator]);
            } else {
                $v = ($veto ?? new Obj())->without();
                $v->set('at', self::n($t));
            }
            $r = $this->apply($id, Obj::of(['kind' => 'veto', 'veto' => $v]), $checkAt);
            if (isset($r['refused'])) {
                return ['ok' => false, 'code' => $r['refused'], 'reason' => $r['reason']];
            }
            if ($r['applied']) {
                $this->notify(['kind' => 'vetoed', 'record' => self::strip($r['record'])]);
            }
            return ['ok' => true, 'record' => $this->runCompensation($r['record']), 'replayed' => !$r['applied']];
        } catch (\Throwable $e) {
            return ['ok' => false, 'code' => 'malformed', 'reason' => 'veto error (fail closed): ' . ($e->getMessage() ?: 'unknown')];
        }
    }

    /** Apply the relay's pending vetoes now (also done by every finalizeDue). Throws when the relay cannot be read. @return list<array<string,mixed>> */
    public function syncRelay(): array
    {
        $relay = $this->o['relay'] ?? null;
        if (!$relay) {
            return [];
        }
        $lst = $relay->pending();
        if (!is_array($lst) || !array_is_list($lst)) {
            throw new UndoError('invalid', 'the veto relay returned no list');
        }
        $out = [];
        foreach ($lst as $x) {
            if (is_array($x) && isset($x['id']) && is_string($x['id'])) {
                $out[] = $this->veto($x['id'], $x['token'], $x['at']);
            }
        }
        return $out;
    }

    public function compensate(string $id): Obj
    {
        $cur = $this->store->get($id);
        if ($cur === null) {
            throw new UndoError('invalid', "no undo record $id");
        }
        return $this->runCompensation($cur);
    }

    public function retry(string $id): Obj
    {
        return $this->runCompensation($this->must($id, Obj::of(['kind' => 'retry']))['record']);
    }

    /** Close the windows whose time is up (`open -> finalized`) and commit their budget reservations. @return list<string> */
    public function finalizeDue(): array
    {
        $out = [];
        try {
            $this->syncRelay();
        } catch (\Throwable $e) {
            // a veto may be waiting at the relay: closing any window now could finalize an action the principal undid
            $this->alert(['level' => 'critical', 'code' => 'veto_relay_failed', 'record' => '*', 'reason' => 'the veto relay could not be read; no window was finalized: ' . ($e->getMessage() ?: 'error')]);
            return $out;
        }
        foreach ($this->store->list(['state' => 'open', 'windowEndedBy' => $this->now() - 1 - (($this->o['relay'] ?? null) ? self::RELAY_GRACE_MS : 0)]) as $rec) {
            $r = $this->apply($rec->get('id'), Obj::of(['kind' => 'finalize']));
            if (isset($r['refused']) || !$r['applied']) {
                continue;
            }
            $out[] = $rec->get('id');
            if ($r['record']->get('effect') === null) {
                $this->alert(['level' => 'warning', 'code' => 'effect_unknown', 'record' => $rec->get('id'), 'reason' => 'the window closed without an effect report: reconcile the original operation']);
            }
            $this->settleBudget($r['record'], 'commit');
            $this->notify(['kind' => 'finalized', 'record' => self::strip($r['record'])]);
        }
        return $out;
    }

    /** After a restart: resume every vetoed record's compensation, then finalize what is due. @return list<string> */
    public function recover(): array
    {
        $out = [];
        foreach ($this->store->list(['state' => 'vetoed']) as $rec) {
            if ($this->runCompensation($rec)->get('state') !== 'vetoed') {
                $out[] = $rec->get('id');
            }
        }
        return array_merge($out, $this->finalizeDue());
    }

    /** A grant was revoked: veto its open windows when the policy says so, else alert and tell the principal. @return list<string> */
    public function onRevocation(string $grantRef): array
    {
        $out = [];
        foreach ($this->store->list(['state' => 'open', 'grantRef' => $grantRef]) as $rec) {
            $pc = Json::parseStrict($rec->get('pcactn'));
            $grant = ($this->o['resolveGrant'])($rec->get('grant_ref'), $pc);
            $pol = $grant ? $this->policyOf(Obj::of(['verb' => $rec->get('action')->get('verb'), 'resource' => $rec->get('action')->get('resource')]), $grant) : [];
            if (($pol['onRevocation'] ?? 'keep') === 'veto') {
                if ($this->veto($rec->get('id'), null, null, null, Obj::of(['at' => self::n(0), 'via' => 'revocation', 'by' => $grantRef]))['ok']) {
                    $out[] = $rec->get('id');
                }
            } else {
                $this->alert(['level' => 'warning', 'code' => 'revoked_open_window', 'record' => $rec->get('id'),
                    'reason' => "grant $grantRef was revoked while this window is open; the principal can still undo it"]);
                $this->notify(['kind' => 'revoked', 'record' => self::strip($rec)]);
            }
        }
        return $out;
    }

    /**
     * Slash a bond (the bond ledger re-verifies the fraud proof itself and refuses outside the challenge window), then undo the record.
     *
     * @param array<string,mixed> $params the bond ledger's slash parameters, with `claimId`
     * @return array<string,mixed>
     */
    public function rollbackOnSlash(array $params, ?object $bonds = null): array
    {
        $bonds ??= $this->o['bonds'] ?? null;
        if ($bonds === null) {
            throw new UndoError('config', 'rollbackOnSlash needs a bond ledger (pass bonds to the coordinator or to this call)');
        }
        $settlement = $bonds->slashBond($params);
        $evidence = IntentV2::hashCanonical(Obj::of(['d' => 'atlas-pca/undo-slash-ref/v1', 'settlement' => $settlement]));
        $recs = $this->store->list(['state' => 'open', 'bondRef' => $params['claimId']]);
        $target = $recs[0] ?? $this->store->get($params['claimId']);
        if ($target === null) {
            return ['settlement' => $settlement, 'veto' => ['ok' => false, 'code' => 'unknown', 'reason' => 'no undo record for bond ' . $params['claimId']]];
        }
        $v = $this->veto($target->get('id'), null, null, null, Obj::of(['at' => self::n(0), 'via' => 'fraud_proof', 'by' => $params['claimId'], 'evidence' => $evidence]));
        if (!$v['ok']) {
            $this->alert(['level' => 'critical', 'code' => 'slash_after_window', 'record' => $target->get('id'), 'reason' => 'the bond was slashed but the effect could not be rolled back: ' . $v['reason']]);
        }
        return ['settlement' => $settlement, 'veto' => $v];
    }
}
