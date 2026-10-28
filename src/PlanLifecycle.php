<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/AtomicKv.php';
require_once __DIR__ . '/Operations.php';

/**
 * Plan lifecycle (T10): explicit states around the plan commitment (the Merkle root an agent signs into every PCActn) and the
 * principal's plan authorization.
 *
 *     draft --validate--> validated --commit--> committed --authorize--> authorized
 *       '---------------------'-----------------------'-----------revoke----'--> revoked
 *
 *  - draft: the nodes are recorded; the root is computed from them (never taken from the caller).
 *  - validated: the nodes are well-formed (unique ids, verb and resource, a known reversibility class) and passed the server's
 *    own validator (for example every node inside the grant's predicates).
 *  - committed: the root is fixed. A committed plan is NOT executable: it still needs the principal.
 *  - authorized: the principal approved this root for this grant, optionally until `expiresAt`.
 *  - revoked: terminal; every later action against the root is denied.
 *
 * "Executable" is not stored: it is evaluated at the moment of use. A plan is executable when it is authorized, the approval has
 * not expired, and its stored nodes still hash to the root. {@see check} adds the per-action staleness rules a server applies
 * immediately before execution: the node exists and the operation's verb, resource and params still match what the principal
 * approved. The registry only feeds the plan into {@see Authorize::authorize} (`plans`) and names the state on a denial; the wire
 * formats are unchanged. Mirrors the reference plan registry; plan-vectors.json pins it.
 *
 * A plan record is an Obj `{grantRef, root, nodes, state, createdAt, validatedAt?, committedAt?, authorizedAt?, approval?,
 * revokedAt?, revokedReason?}`. A transition answers `['ok' => true, 'record' => Obj]` or `['ok' => false, 'state' => string,
 * 'reason' => string]`; a status `['state', 'executable', 'reason'?, 'record'?]`.
 */
final class PlanRegistry
{
    private const KNOWN_CLASSES = ['reversible', 'rate_limited', 'costly', 'irreversible'];

    private readonly AtomicKv $kv;
    /** @var \Closure():int */
    private readonly \Closure $clock;
    /** @var \Closure|null */
    private readonly ?\Closure $validator;

    /**
     * @param AtomicKv|null $kv      where the records live (default: in memory, one process; {@see PdoAtomicKv} for a database)
     * @param string        $prefix  key prefix in the store
     * @param callable|null $now     `(): int` epoch milliseconds (default: the wall clock)
     * @param callable|null $validator `(Obj $record): array{ok:bool, reason?:string}` the server's validation, run by {@see validate}
     *                               after the structural checks. A throw refuses
     */
    public function __construct(?AtomicKv $kv = null, private readonly string $prefix = 'pca-plan:', ?callable $now = null, ?callable $validator = null)
    {
        $this->kv = $kv ?? new MemoryAtomicKv();
        $this->clock = $now !== null ? \Closure::fromCallable($now) : static fn(): int => (int)(microtime(true) * 1000);
        $this->validator = $validator === null ? null : \Closure::fromCallable($validator);
    }

    private function key(string $grantRef, string $root): string
    {
        return $this->prefix . rawurlencode($grantRef) . ':' . $root;
    }

    private function now(): int
    {
        return (int)($this->clock)();
    }

    private static function num(int $i): Num
    {
        return new Num((string)$i);
    }

    private static function decode(?string $s): ?Obj
    {
        if ($s === null) {
            return null;
        }
        try {
            $r = Json::parseLax($s);
        } catch (\Throwable) {
            return null;
        }
        return $r instanceof Obj && is_string($r->get('root')) && is_array($r->get('nodes')) && is_string($r->get('state')) ? $r : null;
    }

    private static function with(Obj $r, array $set): Obj
    {
        $o = new Obj();
        foreach ($r->keys() as $k) {
            $o->set($k, $r->get($k));
        }
        foreach ($set as $k => $v) {
            $o->set((string)$k, $v);
        }
        return $o;
    }

    /** The stored plan (null: none for this grant). */
    public function get(string $grantRef, string $root): ?Obj
    {
        return self::decode($this->kv->get($this->key($grantRef, $root)));
    }

    private static function refuse(string $state, string $reason): array
    {
        return ['ok' => false, 'state' => $state, 'reason' => $reason];
    }

    private static function unknown(string $root): array
    {
        return self::refuse('unknown', "plan $root is unknown for this grant");
    }

    /** The Merkle root of the plan-node leaves. @param list<Obj> $nodes @throws \InvalidArgumentException */
    private static function rootOf(array $nodes): string
    {
        if ($nodes === []) {
            throw new \InvalidArgumentException('merkleRoot: empty leaf set');
        }
        $leaves = [];
        foreach ($nodes as $n) {
            if (!($n instanceof Obj)) {
                throw new \InvalidArgumentException('a plan node cannot be hashed');
            }
            $leaves[] = Pca::planLeaf($n->get('id'), $n, Pca::conditionsDigest($n->get('pre'), $n->get('post')));
        }
        return Pca::merkleRoot($leaves);
    }

    private static function show(mixed $v): string
    {
        return match (true) {
            is_string($v) => $v,
            $v === null => 'null',
            is_bool($v) => $v ? 'true' : 'false',
            $v instanceof Num => $v->lexeme,
            default => '[object Object]',
        };
    }

    /** The reason a plan's nodes are not well-formed (null when valid). */
    private static function structuralProblem(mixed $nodes): ?string
    {
        if (!is_array($nodes) || !array_is_list($nodes) || $nodes === []) {
            return 'a plan needs at least one node';
        }
        $ids = [];
        foreach ($nodes as $n) {
            $id = $n instanceof Obj ? $n->get('id') : null;
            if (!is_string($id) || $id === '') {
                return 'every node needs an id';
            }
            if (isset($ids[$id])) {
                return "duplicate node id '$id'";
            }
            $ids[$id] = true;
            foreach (['verb', 'resource'] as $k) {
                if (!is_string($n->get($k)) || $n->get($k) === '') {
                    return "node '$id' needs a verb and a resource";
                }
            }
            if ($n->has('reversibility_class') && !in_array($n->get('reversibility_class'), self::KNOWN_CLASSES, true)) {
                return "node '$id' has an unknown reversibility class '" . self::show($n->get('reversibility_class')) . "'";
            }
        }
        return null;
    }

    /** Atomically move a plan from one of `$from` to the state `$to` (`$next` computes the new record from the current one). */
    private function move(string $grantRef, string $root, array $from, string $to, callable $next): array
    {
        $out = self::unknown($root);
        try {
            $this->kv->update($this->key($grantRef, $root), function (?string $prev) use (&$out, $root, $from, $to, $next): ?string {
                $cur = self::decode($prev);
                if ($cur === null) {
                    $out = self::unknown($root);
                    return null;
                }
                if (!in_array($cur->get('state'), $from, true)) {
                    $out = self::refuse($cur->get('state'), "plan $root is " . $cur->get('state') . ": cannot $to");
                    return null;
                }
                $rec = $next($cur);
                $out = ['ok' => true, 'record' => $rec];
                return Json::canonicalizeLenient($rec);
            });
        } catch (\Throwable $e) {
            return self::refuse('unknown', 'the plan store failed (fail closed): ' . $e->getMessage());
        }
        return $out;
    }

    /**
     * Record a draft plan for a grant. The root is computed from `$nodes` (Obj nodes, or PHP arrays). Re-drafting an existing
     * root is refused. @param list<Obj|array<string,mixed>> $nodes
     */
    public function draft(string $grantRef, array $nodes): array
    {
        if ($grantRef === '') {
            return self::refuse('unknown', 'a plan needs a grant');
        }
        // structural problems are reported by `validate` (a draft can be inspected first); an unhashable plan has no root
        try {
            $nodes = Operations::jsonValue(array_values($nodes));
            $root = self::rootOf($nodes);
        } catch (\Throwable $e) {
            return self::refuse('unknown', 'the plan cannot be committed: ' . $e->getMessage());
        }
        $rec = Obj::of(['grantRef' => $grantRef, 'root' => $root, 'nodes' => $nodes, 'state' => 'draft', 'createdAt' => self::num($this->now())]);
        $out = ['ok' => true, 'record' => $rec];
        try {
            $this->kv->update($this->key($grantRef, $root), function (?string $prev) use (&$out, $rec, $root): ?string {
                if (($cur = self::decode($prev)) !== null) {
                    $out = self::refuse($cur->get('state'), "plan $root already exists (" . $cur->get('state') . ')');
                    return null;
                }
                $out = ['ok' => true, 'record' => $rec];
                return Json::canonicalizeLenient($rec);
            });
        } catch (\Throwable $e) {
            return self::refuse('unknown', 'the plan store failed (fail closed): ' . $e->getMessage());
        }
        return $out;
    }

    /** draft -> validated (structural checks, then the server's validator). */
    public function validate(string $grantRef, string $root): array
    {
        try {
            $cur = $this->get($grantRef, $root);
        } catch (\Throwable $e) {
            return self::refuse('unknown', 'the plan store failed (fail closed): ' . $e->getMessage());
        }
        if ($cur === null) {
            return self::unknown($root);
        }
        if ($cur->get('state') !== 'draft') {
            return self::refuse($cur->get('state'), "plan $root is " . $cur->get('state') . ': cannot validate');
        }
        $problem = self::structuralProblem($cur->get('nodes'));
        if ($problem === null) {
            try {
                if (self::rootOf($cur->get('nodes')) !== $root) {
                    $problem = 'the stored nodes no longer hash to the root';
                }
            } catch (\Throwable) {
                $problem = 'the stored nodes no longer hash to the root';
            }
        }
        if ($problem !== null) {
            return self::refuse('draft', "plan $root is invalid: $problem");
        }
        if ($this->validator !== null) {
            try {
                $v = ($this->validator)($cur);
                $ok = is_array($v) && ($v['ok'] ?? false) === true;
                $why = is_array($v) && is_string($v['reason'] ?? null) && $v['reason'] !== '' ? $v['reason'] : 'refused by the validator';
            } catch (\Throwable $e) {
                $ok = false;
                $why = 'validator error (fail closed): ' . $e->getMessage();
            }
            if (!$ok) {
                return self::refuse('draft', "plan $root is invalid: $why");
            }
        }
        return $this->move($grantRef, $root, ['draft'], 'validate', fn(Obj $r): Obj => self::with($r, ['state' => 'validated', 'validatedAt' => self::num($this->now())]));
    }

    /** validated -> committed: the root is fixed; it still needs the principal's authorization to execute. */
    public function commit(string $grantRef, string $root): array
    {
        return $this->move($grantRef, $root, ['validated'], 'commit', fn(Obj $r): Obj => self::with($r, ['state' => 'committed', 'committedAt' => self::num($this->now())]));
    }

    /**
     * committed -> authorized: the principal's approval (call it only after verifying the principal's consent).
     * @param Obj|array<string,mixed>|null $approval `{by: string (required), expiresAt?: number (epoch ms)}`
     */
    public function authorize(string $grantRef, string $root, mixed $approval): array
    {
        $ap = $approval instanceof Obj ? $approval : (is_array($approval) && !array_is_list($approval) ? Operations::jsonValue($approval) : null);
        $stateOf = function () use ($grantRef, $root): string {
            try {
                return $this->get($grantRef, $root)?->get('state') ?? 'unknown';
            } catch (\Throwable) {
                return 'unknown';
            }
        };
        if (!($ap instanceof Obj) || !is_string($ap->get('by')) || $ap->get('by') === '') {
            return self::refuse($stateOf(), 'an approval names who approved (`by`)');
        }
        if ($ap->has('expiresAt')) {
            $e = $ap->get('expiresAt');
            if (!($e instanceof Num) || !is_finite($e->float())) {
                return self::refuse($stateOf(), 'approval.expiresAt must be a time (epoch ms)');
            }
        }
        return $this->move($grantRef, $root, ['committed'], 'authorize', fn(Obj $r): Obj => self::with($r, ['state' => 'authorized',
            'authorizedAt' => self::num($this->now()), 'approval' => self::with($ap, [])]));
    }

    /** Any state except revoked -> revoked (terminal). */
    public function revoke(string $grantRef, string $root, string $reason): array
    {
        return $this->move($grantRef, $root, ['draft', 'validated', 'committed', 'authorized'], 'revoke',
            fn(Obj $r): Obj => self::with($r, ['state' => 'revoked', 'revokedAt' => self::num($this->now()), 'revokedReason' => $reason]));
    }

    /**
     * The state now and whether the plan is executable (authorized, approval unexpired, nodes still hash to the root). A store
     * error is reported as not executable.
     * @return array{state:string, executable:bool, reason?:string, record?:Obj}
     */
    public function status(string $grantRef, string $root, ?int $now = null): array
    {
        $now ??= $this->now();
        try {
            $rec = $this->get($grantRef, $root);
        } catch (\Throwable $e) {
            return ['state' => 'unknown', 'executable' => false, 'reason' => 'the plan store failed (fail closed): ' . $e->getMessage()];
        }
        if ($rec === null) {
            return ['state' => 'unknown', 'executable' => false, 'reason' => "plan $root is unknown for this grant"];
        }
        $state = $rec->get('state');
        if ($state !== 'authorized') {
            $why = match ($state) {
                'committed' => 'committed but not authorized by the principal',
                'revoked' => 'revoked (' . (($r = $rec->get('revokedReason')) === null || $r === '' ? 'no reason given' : $r) . ')',
                default => "$state, not authorized",
            };
            return ['state' => $state, 'executable' => false, 'reason' => "plan $root is $why", 'record' => $rec];
        }
        $ap = $rec->get('approval');
        $exp = $ap instanceof Obj && $ap->get('expiresAt') instanceof Num ? $ap->get('expiresAt')->float() : null;
        if ($exp !== null && !((float)$now < $exp)) {
            return ['state' => $state, 'executable' => false, 'record' => $rec,
                'reason' => "plan $root: the principal's approval expired at " . IntentV2::jsNumStr($exp)];
        }
        try {
            $hashed = self::rootOf($rec->get('nodes')) === $root;
        } catch (\Throwable) {
            $hashed = false;
        }
        if (!$hashed) {
            return ['state' => $state, 'executable' => false, 'record' => $rec, 'reason' => "plan $root: the stored nodes no longer hash to the root"];
        }
        return ['state' => $state, 'executable' => true, 'record' => $rec];
    }

    /**
     * {@see status} plus the per-action staleness rules (the node exists, the operation matches it). Run it immediately before
     * execution.
     *
     * @param array{nodeId?:?string, operation?:mixed, now?:?int} $o `operation`: `['verb' =>, 'resource' =>, 'params' =>?]` (or an Obj) about to execute
     * @return array{state:string, executable:bool, reason?:string, record?:Obj}
     */
    public function check(string $grantRef, string $root, array $o = []): array
    {
        $s = $this->status($grantRef, $root, $o['now'] ?? null);
        $nodeId = $o['nodeId'] ?? null;
        $op = $o['operation'] ?? null;
        if (!$s['executable'] || !isset($s['record']) || ($nodeId === null && $op === null)) {
            return $s;
        }
        $nodes = $s['record']->get('nodes');
        $node = null;
        if ($nodeId !== null) {
            foreach ($nodes as $n) {
                if ($n instanceof Obj && $n->get('id') === $nodeId) {
                    $node = $n;
                    break;
                }
            }
            if ($node === null) {
                return ['executable' => false, 'reason' => "plan $root has no node '$nodeId'"] + $s;
            }
        }
        if ($op !== null) {
            $get = static fn(string $k): mixed => $op instanceof Obj ? $op->get($k) : (is_array($op) ? ($op[$k] ?? null) : null);
            try {
                $digest = Pca::paramsDigest(Operations::jsonValue($get('params')));
            } catch (\Throwable) {
                return ['executable' => false, 'reason' => "plan $root: the operation's params cannot be hashed"] + $s;
            }
            $same = false;
            foreach ($node !== null ? [$node] : $nodes as $n) {
                if (!($n instanceof Obj)) {
                    continue;
                }
                $nd = $n->get('params_digest') ?? Pca::paramsDigest();
                if ($n->get('verb') === $get('verb') && $n->get('resource') === $get('resource') && $nd === $digest) {
                    $same = true;
                }
            }
            if (!$same) {
                return ['executable' => false, 'reason' => "plan $root: the operation (" . self::show($get('verb')) . ' on '
                    . self::show($get('resource')) . ' with these params) is not what the principal approved'] + $s;
            }
        }
        return $s;
    }

    /** True only when the plan is executable now (fail closed on any error). */
    public function isPlanAuthorized(string $grantRef, string $planRoot): bool
    {
        try {
            return $this->status($grantRef, $planRoot)['executable'];
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * The verifier context for an action against `$root`: the stored plan, and `planAuthorized` = executable. null: the root is
     * unknown for this grant.
     * @return array{plan:list<Obj>, planAuthorized:bool, status:array}|null
     */
    public function context(string $grantRef, string $root, ?int $now = null): ?array
    {
        $s = $this->status($grantRef, $root, $now);
        return isset($s['record']) ? ['plan' => $s['record']->get('nodes'), 'planAuthorized' => $s['executable'], 'status' => $s] : null;
    }
}
