<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Bounded safety-LTL behavioural contracts (PCA frontier B2, v1) and their durable enforcer (packages/pca/src/contracts.ts and
 * contract-enforcer.ts are authoritative). A contract is an optional embedded prohibition constitution PLUS a set of temporal clauses, run
 * against one shared, hash-chained monitor state: `always P` (affirmative), `never P` (conservative), `precedes` / `requires_prior`,
 * bounded `responds_within N`, and `and`. A contract with no clauses is exactly the prohibition monitor. Total pure functions:
 * everything malformed, unknown or unresolvable FAILS CLOSED as the prohibition monitor does.
 */
final class Contracts
{
    public const CONTRACT_VERSION = 1;
    public const CONTRACT_SIG_DOMAIN = "atlas-pca/contract/v1\0";
    public const CONTRACT_RESET_DOMAIN = "atlas-pca/contract-reset/v1\0";
    public const DOC_VERSION = 1;
    public const MAX_CLAUSES = 256;
    public const MAX_CLAUSE_DEPTH = 16;
    public const MAX_ID_LEN = 128;
    private const FORBIDDEN_IDS = ['__proto__', 'constructor', 'prototype'];

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    // ---- validation -------------------------------------------------------------------------------------------------

    /**
     * Structural problems with a clause (empty = well-formed). Collects every id into `$seen` (global uniqueness); `$depth` bounds nesting.
     *
     * @param array<string, true> $seen
     * @return list<string>
     */
    public static function validateClause(mixed $cl, array &$seen, int $depth): array
    {
        if ($depth > self::MAX_CLAUSE_DEPTH) {
            return ['clause nesting too deep'];
        }
        if (!($cl instanceof Obj)) {
            return ['clause not an object'];
        }
        $id = $cl->get('id');
        if (!is_string($id) || $id === '') {
            return ['<no id>: missing clause id'];
        }
        $err = static fn(string $m): array => ["$id: $m"];
        if (SafeRegex::utf16Len($id) > self::MAX_ID_LEN) {
            return $err('id too long');
        }
        if (in_array($id, self::FORBIDDEN_IDS, true)) {
            return $err('forbidden id');
        }
        if (isset($seen['k' . $id])) {
            return $err('duplicate id');
        }
        $seen['k' . $id] = true;
        $when = static fn(string $k): ?string => ForbidCertificate::whenError($cl->get($k), $k);
        switch ($cl->get('kind')) {
            case 'always':
            case 'never':
                $e = $when('p');
                return $e !== null ? $err($e) : [];
            case 'precedes':
            case 'requires_prior':
                $e = $when('p') ?? $when('q');
                return $e !== null ? $err($e) : [];
            case 'responds_within':
                if (($e = $when('p') ?? $when('q')) !== null) {
                    return $err($e);
                }
                $w = Prohibitions::int($cl->get('within'));
                if ($w === null || $w < 1 || $w > Prohibitions::MAX_DEADLINE) {
                    return $err('within must be an integer in [1, MAX_DEADLINE]');
                }
                return [];
            case 'and':
                $subs = $cl->get('clauses');
                if (!self::isList($subs) || $subs === []) {
                    return $err('and.clauses must be a non-empty array');
                }
                $out = [];
                foreach ($subs as $sub) {
                    $out = array_merge($out, self::validateClause($sub, $seen, $depth + 1));
                }
                return $out;
            default:
                return $err('unknown clause kind ' . IntentWb::jsStr($cl->get('kind')));
        }
    }

    /** Count clauses (including nested). An absurdly deep nest is "too many" at once, never a stack overflow. */
    public static function countClauses(array $cls, int $depth = 1): int
    {
        if ($depth > self::MAX_CLAUSE_DEPTH + 1) {
            return self::MAX_CLAUSES + 1;
        }
        $n = 0;
        foreach ($cls as $cl) {
            $n++;
            if ($cl instanceof Obj && $cl->get('kind') === 'and' && self::isList($cl->get('clauses'))) {
                $n += self::countClauses($cl->get('clauses'), $depth + 1);
            }
        }
        return $n;
    }

    /** Structural problems with a contract (empty = well-formed). Total; never throws. @return list<string> */
    public static function validateContract(mixed $c): array
    {
        if (!($c instanceof Obj)) {
            return ['contract not an object'];
        }
        $out = [];
        if (Prohibitions::fin($c->get('version')) !== 1.0 || !($c->get('version') instanceof Num)) {
            $out[] = 'unsupported version ' . IntentWb::jsStr($c->get('version') instanceof Num ? $c->get('version')->float() : $c->get('version'));
        }
        if (!is_string($c->get('principal')) || $c->get('principal') === '') {
            $out[] = 'principal missing';
        }
        /** @var array<string, true> $ids */
        $ids = [];
        if ($c->has('invariants')) {
            $invariants = $c->get('invariants');
            if (!self::isList($invariants)) {
                return array_merge($out, ['invariants not an array']);
            }
            if (count($invariants) > Prohibitions::MAX_INVARIANTS) {
                $out[] = 'too many invariants';
            }
            foreach ($invariants as $inv) {
                $out = array_merge($out, Prohibitions::validateInvariant($inv));
                $id = $inv instanceof Obj ? $inv->get('id') : null;
                if (!is_string($id)) {
                    continue;
                }
                if (isset($ids['k' . $id])) {
                    $out[] = "$id: duplicate id";
                }
                $ids['k' . $id] = true;
            }
        }
        if ($c->has('clauses')) {
            $clauses = $c->get('clauses');
            if (!self::isList($clauses)) {
                return array_merge($out, ['clauses not an array']);
            }
            if (self::countClauses($clauses) > self::MAX_CLAUSES) {
                $out[] = 'too many clauses';
            }
            // clause ids must be globally unique AND disjoint from the constitution invariant ids (shared state keys)
            foreach ($clauses as $cl) {
                $out = array_merge($out, self::validateClause($cl, $ids, 1));
            }
        }
        return $out;
    }

    // ---- contract commitment ----------------------------------------------------------------------------------------

    /** Content address of a contract body. Throws only on non-canonicalizable input (authoring time). */
    public static function contractId(Obj $c): string
    {
        return Pca::hashCanonical($c->without('id', 'sig'));
    }

    /** The principal signs the contract. Refuses a malformed one. */
    public static function signContract(Obj $c, KeyPair $key): Obj
    {
        $problems = self::validateContract($c);
        if ($problems !== []) {
            throw new \InvalidArgumentException('signContract: ' . implode('; ', $problems));
        }
        $id = self::contractId($c);
        $out = $c->without('id', 'sig');
        $out->set('id', $id);
        $out->set('sig', Pca::b64u($key->sign(self::domainMessage(self::CONTRACT_SIG_DOMAIN, $id))));
        return $out;
    }

    private static function domainMessage(string $domain, string $id): string
    {
        return $domain . hash('sha256', $id, true);
    }

    /** Well-formed, id matches content, signature by `$expectedPrincipal` (or the embedded one). Never throws. @return array{ok: bool, reason?: string} */
    public static function verifyContract(mixed $sc, ?string $expectedPrincipal = null): array
    {
        try {
            $problems = self::validateContract($sc);
            if ($problems !== []) {
                return ['ok' => false, 'reason' => $problems[0]];
            }
            if ($expectedPrincipal !== null && $sc->get('principal') !== $expectedPrincipal) {
                return ['ok' => false, 'reason' => 'principal mismatch'];
            }
            if (!is_string($sc->get('id')) || $sc->get('id') !== self::contractId($sc)) {
                return ['ok' => false, 'reason' => 'id does not match content'];
            }
            if (!is_string($sc->get('sig')) || !Pca::verifyEd25519B64u($sc->get('principal'), self::domainMessage(self::CONTRACT_SIG_DOMAIN, $sc->get('id')), $sc->get('sig'))) {
                return ['ok' => false, 'reason' => 'bad signature'];
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return ['ok' => false, 'reason' => 'verification error (fail closed)'];
        }
    }

    /** The embedded prohibition constitution of a contract (empty when `invariants` is omitted). */
    public static function embeddedConstitution(Obj $c): Obj
    {
        return Obj::of(['version' => Prohibitions::num(1), 'principal' => $c->get('principal'),
            'invariants' => self::isList($c->get('invariants')) ? $c->get('invariants') : []]);
    }

    /** Lift a plain prohibition constitution into the degenerate contract (no temporal clauses). */
    public static function contractFromConstitution(Obj $c): Obj
    {
        return Obj::of(['version' => Prohibitions::num(self::CONTRACT_VERSION), 'principal' => $c->get('principal'), 'invariants' => $c->get('invariants'), 'clauses' => []]);
    }

    // ---- clause evaluation (per-action transition) ------------------------------------------------------------------

    private static function row(Obj $cl, bool $ok, ?string $reason): Obj
    {
        $r = Obj::of(['id' => $cl->get('id'), 'kind' => $cl->get('kind'), 'result' => $ok ? 'pass' : 'violated']);
        if ($reason !== null && $reason !== '') {
            $r->set('reason', $reason);
        }
        return $r;
    }

    /** @return array{ok: bool, reason: ?string, rows: list<Obj>, latch_set: array<string, float>, deadline_set: array<string, ?float>} */
    private static function base(Obj $cl, bool $ok, ?string $reason = null): array
    {
        return ['ok' => $ok, 'reason' => $reason, 'rows' => [self::row($cl, $ok, $reason)], 'latch_set' => [], 'deadline_set' => []];
    }

    private static function desc(Obj $cl, string $default): string
    {
        $d = $cl->get('description');
        return is_string($d) ? $d : $default;
    }

    /**
     * Per-clause transition against ONE action and the pre-state: the verdict plus the intended state updates (`latch_set`: precedence
     * latches to set now; `deadline_set`: new bounded-liveness budget, or null to clear an open obligation). The updates are applied to the
     * next state ONLY if the whole contract is ok.
     */
    private static function evalClause(Obj $cl, Obj $ctx, Obj $state, float $now): array
    {
        try {
            $latched = $state->get('latched');
            $deadlines = $state->get('deadlines') instanceof Obj ? $state->get('deadlines') : new Obj();
            switch ($cl->get('kind')) {
                case 'always':
                    return Prohibitions::whenAffirmative($cl->get('p'), $ctx) ? self::base($cl, true)
                        : self::base($cl, false, self::desc($cl, 'always-invariant violated (action does not satisfy p)'));
                case 'never':
                    return Prohibitions::whenMatches($cl->get('p'), $ctx) ? self::base($cl, false, self::desc($cl, 'never-invariant violated (forbidden action)')) : self::base($cl, true);
                case 'precedes':
                case 'requires_prior':
                    $isQ = Prohibitions::whenMatches($cl->get('q'), $ctx); // the guarded action, conservative
                    $held = !$isQ || $latched->has($cl->get('id'));
                    $t = self::base($cl, $held, $held ? null : self::desc($cl, 'precedence violated (prerequisite p not yet admitted before q)'));
                    if (!$latched->has($cl->get('id')) && Prohibitions::whenAffirmative($cl->get('p'), $ctx)) {
                        $t['latch_set'][$cl->get('id')] = $now; // an ambiguous prerequisite must not count
                    }
                    return $t;
                case 'responds_within':
                    $violated = false;
                    $carried = null;
                    if ($deadlines->has($cl->get('id'))) {
                        $cur = Prohibitions::fin($deadlines->get($cl->get('id')));
                        if (Prohibitions::whenAffirmative($cl->get('q'), $ctx)) {
                            $carried = null; // any response discharges all open obligations
                        } else {
                            $r = $cur - 1;
                            if ($r <= 0) {
                                $violated = true; // window exhausted with no response => violation at this action
                            } else {
                                $carried = $r;
                            }
                        }
                    }
                    $within = Prohibitions::fin($cl->get('within'));
                    $reason = $violated ? self::desc($cl, 'bounded-liveness deadline missed (no q within ' . IntentV2::jsNumStr($within) . ' actions of p)') : null;
                    $rows = [self::row($cl, !$violated, $reason)];
                    if ($violated) {
                        return ['ok' => false, 'reason' => $reason, 'rows' => $rows, 'latch_set' => [], 'deadline_set' => []];
                    }
                    $nxt = $carried;
                    if (Prohibitions::whenMatches($cl->get('p'), $ctx)) { // a conservative stimulus opens a fresh obligation; the binding deadline is the MOST URGENT
                        $nxt = $nxt === null ? $within : min($nxt, $within);
                    }
                    return ['ok' => true, 'reason' => null, 'rows' => $rows, 'latch_set' => [], 'deadline_set' => [$cl->get('id') => $nxt]];
                case 'and':
                    $rows = [];
                    $latchSet = [];
                    $deadlineSet = [];
                    $ok = true;
                    $reason = null;
                    foreach ($cl->get('clauses') as $sub) {
                        $r = self::evalClause($sub, $ctx, $state, $now);
                        $rows = array_merge($rows, $r['rows']);
                        foreach ($r['latch_set'] as $k => $v) {
                            $latchSet[$k] = $v;
                        }
                        foreach ($r['deadline_set'] as $k => $v) {
                            $deadlineSet[$k] = $v;
                        }
                        if (!$r['ok'] && $ok) {
                            $ok = false;
                            $reason = $r['reason'];
                        }
                    }
                    // the `and` itself emits no row: its children's rows carry the detail (ok rolls up)
                    return ['ok' => $ok, 'reason' => $reason, 'rows' => $rows, 'latch_set' => $latchSet, 'deadline_set' => $deadlineSet];
                default:
                    return self::base($cl, false, 'unknown clause kind (fail closed)');
            }
        } catch (\Throwable) {
            return self::base($cl, false, 'clause evaluation error (fail closed)');
        }
    }

    // ---- the contract monitor ---------------------------------------------------------------------------------------

    private static function fail(string $id, string $reason): array
    {
        return ['ok' => false, 'violated' => [$id], 'reasons' => ["$id: $reason"],
            'evaluated' => [Obj::of(['id' => $id, 'kind' => 'structural', 'result' => 'violated', 'reason' => $reason])]];
    }

    /**
     * Evaluate a whole contract (embedded constitution + temporal clauses) against one action and the running state, WITHOUT advancing.
     * Pure, total, fail-closed; every invariant and clause is evaluated (no short-circuit); the whole contract is one regex-budget document.
     *
     * @return array{ok: bool, violated: list<string>, reasons: list<string>, evaluated: list<Obj>}
     */
    public static function check(mixed $action, mixed $contract, mixed $state): array
    {
        try {
            return SafeRegex::withBudget(fn(): array => self::checkInner($action, $contract, $state));
        } catch (\Throwable) {
            return self::fail('<monitor>', 'monitor error (fail closed)');
        }
    }

    private static function checkInner(mixed $action, mixed $contract, mixed $state): array
    {
        $cp = self::validateContract($contract);
        if ($cp !== []) {
            return self::fail('<contract>', $cp[0]);
        }
        $a = $action instanceof Obj ? $action->get('action') : null;
        if (!($a instanceof Obj) || !is_string($a->get('verb')) || !is_string($a->get('resource'))) {
            return self::fail('<action>', 'malformed action');
        }
        if (($sp = Prohibitions::stateProblem($state)) !== null) {
            return self::fail('<state>', $sp);
        }
        $evaluated = [];
        $constitution = self::embeddedConstitution($contract);
        if ($constitution->get('invariants') !== []) {
            $evaluated = array_merge($evaluated, Prohibitions::check($action, $constitution, $state)['evaluated']);
        }
        $now = Prohibitions::fin($state->get('now'));
        foreach ($contract->has('clauses') ? $contract->get('clauses') : [] as $cl) {
            try {
                $t = self::evalClause($cl, $action, $state, $now);
            } catch (\Throwable) {
                $t = ['rows' => [self::row(Obj::of(['id' => $cl->get('id'), 'kind' => $cl->get('kind') ?? 'clause']), false, 'clause evaluation error (fail closed)')]];
            }
            $evaluated = array_merge($evaluated, $t['rows']);
        }
        $bad = array_values(array_filter($evaluated, static fn(Obj $e): bool => $e->get('result') === 'violated'));
        return ['ok' => $bad === [], 'violated' => array_map(static fn(Obj $e): string => $e->get('id'), $bad),
            'reasons' => array_map(static fn(Obj $e): string => $e->get('id') . ': ' . ($e->get('reason') ?? 'violated'), $bad), 'evaluated' => $evaluated];
    }

    /**
     * Check the whole contract against one action and, iff it holds, advance the hash-chained monitor state exactly like the prohibition
     * monitor, overlaying the clauses' precedence latches and bounded-liveness deadline counters. Fail-closed on anything unresolvable or on
     * a stale chain head; `next` is then the input state, unchanged. `$opts`: `expectedSeq`, `expectedStateDigest`, `now`. Never throws.
     *
     * @return array{ok: bool, violated: list<string>, reasons: list<string>, evaluated: list<Obj>, next: mixed, decidedBy: string}
     */
    public static function advance(mixed $state, mixed $action, mixed $contract, array $opts = []): array
    {
        $refuse = function (string $decidedBy, ?array $r = null, ?string $reason = null) use ($state, $action, $contract): array {
            $base = $r ?? self::check($action, $contract, $state);
            return ['ok' => false,
                'violated' => $reason !== null ? array_merge(array_values(array_filter($base['violated'], static fn(string $v): bool => $v !== '<state>')), ['<state>']) : $base['violated'],
                'reasons' => $reason !== null ? array_merge($base['reasons'], ["<state>: $reason"]) : $base['reasons'],
                'evaluated' => $base['evaluated'], 'next' => $state, 'decidedBy' => $decidedBy];
        };
        try {
            $now = ($opts['now'] ?? null) === null ? ($state instanceof Obj ? $state->get('now') : null) : $opts['now'];
            if (($opts['expectedSeq'] ?? null) !== null && (!($state instanceof Obj) || Prohibitions::fin($state->get('seq')) !== (float)$opts['expectedSeq'])) {
                return $refuse('state', null, 'stale state head (seq)'); // CAS on the chain head FIRST
            }
            if (($opts['expectedStateDigest'] ?? null) !== null) {
                try {
                    $d = Prohibitions::stateDigest($state);
                } catch (\Throwable) {
                    $d = Prohibitions::UNHASHABLE;
                }
                if ($d !== $opts['expectedStateDigest']) {
                    return $refuse('state', null, 'stale state head (digest)');
                }
            }
            $verdict = self::check($action, $contract, $state);
            if (!$verdict['ok']) {
                $structural = false;
                foreach ($verdict['violated'] as $v) {
                    $structural = $structural || (str_starts_with($v, '<') && str_ends_with($v, '>'));
                }
                return $verdict + ['next' => $state, 'decidedBy' => $structural ? 'state' : 'contract'];
            }
            $constitution = self::embeddedConstitution($contract);
            $adv = Prohibitions::advanceStrict($action, $constitution, $state, $now);
            if (!$adv['ok']) {
                return $refuse('state', $verdict, 'advance failed: ' . $adv['reason']);
            }
            // overlay the temporal clauses' state, recomputed against the PRE-state (the same transitions the verdict used)
            $latched = Obj::of([]);
            foreach ($adv['state']->get('latched')->keys() as $k) {
                $latched->set($k, $adv['state']->get('latched')->get($k));
            }
            $deadlines = new Obj();
            if ($state->get('deadlines') instanceof Obj) {
                foreach ($state->get('deadlines')->keys() as $k) {
                    $deadlines->set($k, $state->get('deadlines')->get($k));
                }
            }
            $nowF = Prohibitions::fin($now);
            SafeRegex::withBudget(function () use ($contract, $action, $state, $nowF, $latched, &$deadlines): void { // a second pass of the same clauses: its own document budget
                foreach ($contract->has('clauses') ? $contract->get('clauses') : [] as $cl) {
                    $t = self::evalClause($cl, $action, $state, $nowF);
                    foreach ($t['latch_set'] as $k => $v) {
                        if (!$latched->has((string)$k)) {
                            $latched->set((string)$k, Prohibitions::num($v));
                        }
                    }
                    foreach ($t['deadline_set'] as $k => $v) {
                        if ($v === null) {
                            $deadlines = $deadlines->without((string)$k);
                        } else {
                            $deadlines->set((string)$k, Prohibitions::num($v));
                        }
                    }
                }
            });
            $nxt = new Obj();
            foreach ($adv['state']->keys() as $k) {
                $nxt->set($k, $k === 'latched' ? $latched : $adv['state']->get($k));
            }
            if ($deadlines->keys() !== []) {
                $nxt->set('deadlines', $deadlines);
            }
            if (($sp = Prohibitions::stateProblem($nxt)) !== null) {
                return $refuse('state', $verdict, "resulting state invalid: $sp");
            }
            return $verdict + ['next' => $nxt, 'decidedBy' => 'none'];
        } catch (\Throwable) {
            return $refuse('state', null, 'advance error (fail closed)');
        }
    }

    /**
     * allow = permitted AND contract.ok, and on allow the state advances. The permission verdict is an INPUT that can only be ANDed; the
     * contract monitor runs unconditionally so denial reasons are complete.
     */
    public static function checkAndAdvance(mixed $permitted, mixed $state, mixed $action, mixed $contract, array $opts = []): array
    {
        $adv = self::advance($state, $action, $contract, $opts);
        $p = $permitted === true;
        if (!$adv['ok']) {
            return ['allow' => false, 'permitted' => $p] + $adv;
        }
        if (!$p) {
            return ['ok' => false, 'violated' => $adv['violated'], 'reasons' => array_merge($adv['reasons'], ['<permission>: not permitted']), 'evaluated' => $adv['evaluated'],
                'next' => $state, 'decidedBy' => 'contract', 'allow' => false, 'permitted' => $p];
        }
        return ['allow' => true, 'permitted' => $p] + $adv;
    }

    // ---- durable enforcement ----------------------------------------------------------------------------------------

    private static function resetMessage(string $id, int|string $seq): string
    {
        return self::CONTRACT_RESET_DOMAIN . hash('sha256', "$id:$seq", true);
    }

    /** The principal's authorisation to un-latch `$contractId` at sequence `$seq` (binds both, so it cannot be replayed later). */
    public static function signContractReset(KeyPair $key, string $contractId, int $seq): string
    {
        return Pca::b64u($key->sign(self::resetMessage($contractId, $seq)));
    }

    /** @internal */
    public static function resetMessageFor(string $id, int|string $seq): string
    {
        return self::resetMessage($id, $seq);
    }

    /** @internal */
    public static function enforcerDoc(mixed $d, string $id): bool
    {
        if (!($d instanceof Obj)) {
            return false;
        }
        if (Prohibitions::fin($d->get('v')) !== 1.0 || $d->get('contract_id') !== $id || Prohibitions::stateProblem($d->get('state')) !== null) {
            return false;
        }
        if (!$d->has('latched')) {
            return true;
        }
        $l = $d->get('latched');
        if (!($l instanceof Obj) || Prohibitions::int($l->get('seq')) === null || Prohibitions::int($l->get('seq')) < 0 || !is_array($l->get('violated')) || !array_is_list($l->get('violated'))) {
            return false;
        }
        foreach ($l->get('violated') as $v) {
            if (!is_string($v)) {
                return false;
            }
        }
        return !($l->get('seq') instanceof Num && str_starts_with($l->get('seq')->lexeme, '-'));
    }
}

final class ContractEnforcerError extends \RuntimeException
{
    public function __construct(string $message)
    {
        parent::__construct("ContractEnforcer: $message");
    }
}

/**
 * Durable enforcement of a signed contract: the monitor state is one document in an {@see AtomicKv}, and the whole read-check-advance runs
 * inside the kv's atomic update, so concurrent callers are serialised and a stale or rolled-back state can never be advanced. Only a contract
 * signed by the PINNED principal is loaded; a real violation LATCHES the enforcer (default) until the principal signs a reset. Every malformed,
 * corrupt or unreadable state denies. Results: `['allow' => bool, 'reason' => 'ok'|'violated'|'latched'|'permission'|'state-error'|'store-error',
 * 'violated' => list<string>, 'reasons' => list<string>, 'seq' => int]`.
 */
final class ContractEnforcer
{
    /** @var callable */
    private $now;

    private function __construct(private readonly AtomicKv $kv, private readonly Obj $contract, private readonly string $key, callable $now, private readonly bool $latch)
    {
        $this->now = $now;
    }

    /** Throws ContractEnforcerError unless the contract verifies under the pinned principal. */
    public static function open(AtomicKv $kv, Obj $contract, string $principal, ?string $key = null, ?callable $now = null, bool $latchOnViolation = true): self
    {
        if ($principal === '') {
            throw new ContractEnforcerError('a pinned principal is required');
        }
        $v = Contracts::verifyContract($contract, $principal);
        if (!$v['ok']) {
            throw new ContractEnforcerError('contract refused: ' . $v['reason']);
        }
        return new self($kv, $contract, $key ?? ('contract/' . Contracts::contractId($contract)), $now ?? static fn(): float => floor(microtime(true) * 1000), $latchOnViolation);
    }

    private static function result(bool $allow, string $reason, array $violated, array $reasons, mixed $seq): array
    {
        return ['allow' => $allow, 'reason' => $reason, 'violated' => $violated, 'reasons' => $reasons, 'seq' => (int)(is_float($seq) ? $seq : (Prohibitions::fin($seq) ?? 0))];
    }

    private function doc(?string $raw): ?Obj
    {
        return KvDoc::dec($raw);
    }

    /** Check one action against the permission verdict AND the contract, advancing the durable state iff both allow. Never throws. */
    public function check(Obj $action, bool $permitted = true): array
    {
        $id = (string)$this->contract->get('id');
        $out = self::result(false, 'store-error', [], ['store unavailable'], 0);
        try {
            $wallRaw = ($this->now)();
            $wall = Prohibitions::fin($wallRaw);
            $this->kv->update($this->key, function (?string $raw) use (&$out, $id, $wall, $action, $permitted): ?string {
                $prev = $this->doc($raw);
                if ($raw !== null && !Contracts::enforcerDoc($prev, $id)) {
                    $out = self::result(false, 'state-error', [], ['<state>: stored state is corrupt or belongs to another contract'], 0);
                    return null;
                }
                if ($prev !== null && $wall === null) {
                    $out = self::result(false, 'state-error', [], ['<state>: clock is not finite'], $prev->get('state')->get('seq'));
                    return null;
                }
                $doc = $prev ?? Obj::of(['v' => Prohibitions::num(Contracts::DOC_VERSION), 'contract_id' => $id, 'state' => Prohibitions::emptyState($wall ?? 0.0)]);
                if ($doc->has('latched')) {
                    $l = $doc->get('latched');
                    $out = self::result(false, 'latched', $l->get('violated'), ['<latched>: contract violated at seq ' . IntentV2::jsNumStr((float)Prohibitions::fin($l->get('seq')))], $doc->get('state')->get('seq'));
                    return null;
                }
                $stateNow = Prohibitions::fin($doc->get('state')->get('now'));
                $r = Contracts::checkAndAdvance($permitted, $doc->get('state'), $action, $this->contract,
                    ['now' => ($wall === null || is_nan($wall)) ? NAN : max($wall, $stateNow), 'expectedSeq' => Prohibitions::fin($doc->get('state')->get('seq'))]);
                if ($r['allow']) {
                    $out = self::result(true, 'ok', [], [], $r['next']->get('seq'));
                    $doc->set('state', $r['next']);
                    return KvDoc::enc($doc);
                }
                $structural = $r['decidedBy'] === 'state';
                $real = !$structural && $r['violated'] !== [];
                $out = self::result(false, $structural ? 'state-error' : ($real ? 'violated' : 'permission'), $real ? $r['violated'] : [], $r['reasons'], $doc->get('state')->get('seq'));
                if ($real && $this->latch) {
                    $doc->set('latched', Obj::of(['seq' => $doc->get('state')->get('seq'), 'violated' => $r['violated']]));
                    return KvDoc::enc($doc);
                }
                return null;
            });
        } catch (\Throwable) {
            $out = self::result(false, 'store-error', [], ['store error (fail closed)'], 0);
        }
        return $out;
    }

    /**
     * Read-only evaluation against the stored state: nothing is advanced or latched. Used to refuse BEFORE a replay counter is spent; `check`
     * then commits once the action is actually admitted. Never throws.
     */
    public function peek(Obj $action): array
    {
        try {
            $raw = $this->kv->get($this->key);
            $prev = $this->doc($raw);
            $id = (string)$this->contract->get('id');
            if ($raw !== null && !Contracts::enforcerDoc($prev, $id)) {
                return self::result(false, 'state-error', [], ['<state>: stored state is corrupt or belongs to another contract'], 0);
            }
            if ($prev !== null && $prev->has('latched')) {
                $l = $prev->get('latched');
                return self::result(false, 'latched', $l->get('violated'), ['<latched>: contract violated at seq ' . IntentV2::jsNumStr((float)Prohibitions::fin($l->get('seq')))], $prev->get('state')->get('seq'));
            }
            $wall = Prohibitions::fin(($this->now)());
            $r = Contracts::check($action, $this->contract, $prev !== null ? $prev->get('state') : Prohibitions::emptyState($wall ?? 0.0));
            $seq = $prev !== null ? $prev->get('state')->get('seq') : 0;
            return $r['ok'] ? self::result(true, 'ok', [], [], $seq) : self::result(false, 'violated', $r['violated'], $r['reasons'], $seq);
        } catch (\Throwable) {
            return self::result(false, 'store-error', [], ['store error (fail closed)'], 0);
        }
    }

    /** The current stored state (`['state' => Obj, 'latched' => bool]`), or null when nothing was admitted yet. Throws ContractEnforcerError on a corrupt document. */
    public function state(): ?array
    {
        $raw = $this->kv->get($this->key);
        if ($raw === null) {
            return null;
        }
        $d = $this->doc($raw);
        if (!Contracts::enforcerDoc($d, (string)$this->contract->get('id'))) {
            throw new ContractEnforcerError('stored state is corrupt or belongs to another contract');
        }
        return ['state' => $d->get('state'), 'latched' => $d->has('latched')];
    }

    /** Un-latch with the principal's signature (see {@see Contracts::signContractReset}) at the latched sequence. Returns whether it cleared. */
    public function reset(mixed $sig): bool
    {
        $cleared = false;
        try {
            $id = (string)$this->contract->get('id');
            $this->kv->update($this->key, function (?string $raw) use (&$cleared, $id, $sig): ?string {
                $prev = $this->doc($raw);
                if (!Contracts::enforcerDoc($prev, $id) || !$prev->has('latched')) {
                    return null;
                }
                $seq = IntentV2::jsNumStr((float)Prohibitions::fin($prev->get('latched')->get('seq')));
                if (!is_string($sig) || !Pca::verifyEd25519B64u((string)$this->contract->get('principal'), Contracts::resetMessageFor($id, $seq), $sig)) {
                    return null;
                }
                $cleared = true;
                return KvDoc::enc($prev->without('latched'));
            });
        } catch (\Throwable) {
            return false;
        }
        return $cleared;
    }
}
