<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Facade.php';
require_once __DIR__ . '/Approval.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/Agent.php';

/**
 * The approval and step-up model (approvals.ts): the HEADLESS core an approval inbox renders. Given an intended action it decides whether it
 * auto-admits, is a hard deny or needs a human, and if so produces a step-up request carrying goal lineage, the risk tier and a stable id;
 * plus batching, "approve this class for N hours" standing approvals and the human co-sign budget recharge.
 *
 * Pure and offline: it composes the agent handle's non-authoritative {@see AgentHandle::dryRun} and the budget algebra. It signs nothing
 * except where a grant is time-boxed ({@see timeBox}). The resource server stays the authority at run time. Records are PHP arrays with the
 * reference's member names (`goalCommit`, `requestedAt`, `renderDigest`, ...); params may be an Obj or an assoc array.
 */
final class Approvals
{
    private static function fmtNum(int|float $n): string
    {
        return IntentWb::jsNumStr((float)$n);
    }

    /** @param array{amount:int|float,unit:string,periodMs?:int|float} $limit */
    private static function formatLimit(array $limit): string
    {
        $base = ($limit['unit'] ?? null) === 'usd' ? '$' . self::fmtNum($limit['amount']) : self::fmtNum($limit['amount']);
        if (!isset($limit['periodMs'])) {
            return $base;
        }
        $hours = $limit['periodMs'] / 3600000;
        if (fmod((float)$hours, 24.0) === 0.0 && $hours >= 24) {
            $period = self::fmtNum($hours / 24) . 'd';
        } elseif ($hours >= 1) {
            $period = self::fmtNum($hours) . 'h';
        } else {
            $period = self::fmtNum(floor($limit['periodMs'] / 60000 + 0.5)) . 'm';
        }
        return "$base/$period";
    }

    private static function show(mixed $v): string
    {
        return is_array($v) || $v instanceof Obj || $v === null ? Js::stringify(Sign::n($v)) : Js::str($v);
    }

    private static function summarizeParams(mixed $params, ?string $amountField): ?string
    {
        if ($params === null) {
            return null;
        }
        $map = $params instanceof Obj ? array_combine($params->keys(), array_map(fn($k) => $params->get($k), $params->keys())) : (is_array($params) ? $params : []);
        if ($amountField !== null && ($map[$amountField] ?? null) !== null) {
            return $amountField . '=' . Js::str($map[$amountField]);
        }
        if ($map === []) {
            return null;
        }
        $out = [];
        foreach (array_slice($map, 0, 4, true) as $k => $v) {
            $out[] = $k . '=' . self::show($v);
        }
        return implode(', ', $out);
    }

    /** @return array<string,mixed>|null the compiled spec of `$verb` */
    private static function specOf(AgentHandle $agent, string $verb): ?array
    {
        foreach ($agent->policy['actions'] as $s) {
            if (($s['verb'] ?? null) === $verb) {
                return $s;
            }
        }
        return null;
    }

    /**
     * The goal lineage of one intended action ("you approved X because you asked to Y"), derived from the grant envelope's `goal_commit`, the
     * compiled policy and the optional revealed goal, which is checked against the commitment with the agent's goal salt (`goalVerified`).
     * Pure; signs nothing.
     * @return array<string,mixed> `goal?`, `goalCommit`, `goalVerified`, `chain` (three nodes: goal, authority, action) and `because`
     */
    public static function buildGoalLineage(AgentHandle $agent, string $verb, string $resource, mixed $params = null, ?string $goal = null): array
    {
        $env = Authorize::readEnvelope($agent->grant);
        $gc = $env?->get('goal_commit');
        $goalCommit = is_string($gc) ? $gc : '';
        $salt = $agent->goalSalt;
        $verified = $goal !== null && $goalCommit !== '' && $salt !== '' && Sign::verifyGoalCommit($goalCommit, $goal, $salt);
        $spec = self::specOf($agent, $verb);
        $limit = ($agent->policy['limits'] ?? [])[$verb] ?? null;
        $goalLabel = $goal !== null ? "Pursue the goal: “{$goal}”" : 'Pursue the grant’s committed goal';
        $goalDetail = $goal !== null
            ? ($verified ? 'verified: this goal opens the signed grant commitment' : 'unverified: the revealed goal does not open the grant commitment')
            : ($goalCommit !== '' ? "committed as $goalCommit" : null);
        $authority = "Delegated authority to $verb" . ($limit ? ' (up to ' . self::formatLimit($limit) . ')' : '');
        $actionDetail = self::summarizeParams($params, $spec['amountField'] ?? null);
        $g = ['kind' => 'goal', 'label' => $goalLabel];
        if ($goalDetail !== null) {
            $g['detail'] = $goalDetail;
        }
        $a = ['kind' => 'authority', 'label' => $authority];
        if ($spec !== null && !empty($spec['description'])) {
            $a['detail'] = $spec['description'];
        }
        $c = ['kind' => 'action', 'label' => "$verb $resource"];
        if ($actionDetail !== null) {
            $c['detail'] = $actionDetail;
        }
        $because = $goal !== null ? "Approving $verb on $resource because you asked to “{$goal}”."
            : "Approving $verb on $resource, authorized under the grant’s committed goal.";
        $out = [];
        if ($goal !== null) {
            $out['goal'] = $goal;
        }
        return $out + ['goalCommit' => $goalCommit, 'goalVerified' => $verified, 'chain' => [$g, $a, $c], 'because' => $because];
    }

    /** Flatten a lineage to plain text lines (SMS, plain email, Slack fallback). @param array<string,mixed> $lineage @return list<string> */
    public static function describeGoalLineage(array $lineage): array
    {
        $chain = $lineage['chain'] ?? null;
        if (!is_array($chain)) { // lineage.chain.map(...) in the reference: an engine TypeError on a lineage without a chain
            throw new \TypeError($chain === null ? "Cannot read properties of undefined (reading 'map')" : 'lineage.chain.map is not a function');
        }
        // a node without a label reads as undefined (null), as in the reference
        return array_map(static fn(mixed $n): mixed => !is_array($n) ? throw new \TypeError("Cannot read properties of " . ($n === null ? 'null' : 'a non-object') . " (reading 'detail')") : (!empty($n['detail']) ? ($n['label'] ?? 'undefined') . ' — ' . $n['detail'] : ($n['label'] ?? null)), $chain);
    }

    private static function riskForReview(AgentHandle $agent, string $verb, mixed $params): float
    {
        $spec = self::specOf($agent, $verb);
        if (($agent->policy['budgetModel'] ?? null) === 'dollars' && $spec !== null && isset($spec['amountField'])) {
            $raw = Js::opt($params, $spec['amountField']);
            $amt = $raw instanceof Num ? $raw->float() : (is_int($raw) || is_float($raw) ? (float)$raw : (is_string($raw) && is_numeric($raw) ? (float)$raw : NAN));
            $kappa = (float)$agent->policy['riskPolicy']['kappa'];
            if (is_finite($amt) && $kappa > 0) {
                return max(0.0, min(1.0, $amt / $kappa));
            }
        }
        return max(0.0, min(1.0, (float)($spec['blastRadius'] ?? 0.8)));
    }

    /**
     * Review an intended action against the agent's grant: `['kind' => 'auto']` (no human needed), `['kind' => 'deny', 'reason']` (the grant
     * forbids it; no approval fixes that offline) or `['kind' => 'step_up', 'request']` (admissible but needs a tier-2/3 co-sign, unless a
     * standing class approval covers it).
     *
     * A step-up request is created only together with its canonical approval render (`$renderer(verb, resource, params)`, e.g. from the
     * pinned action definitions): what the approver sees is what is signed. Without a renderer the review is a `deny` unless
     * `$insecureUnboundApproval` is true (a DOCUMENTED INSECURE opt-out). A renderer that throws makes the review a `deny`: an action that cannot
     * be shown completely is never put to a human.
     * @param list<array<string,mixed>>|null $standing
     * @return array<string,mixed>
     */
    public static function reviewAction(AgentHandle $agent, string $verb, string $resource, mixed $params = null, ?int $now = null, ?string $goal = null,
                                        ?array $standing = null, ?callable $renderer = null, bool $insecureUnboundApproval = false): array
    {
        $at = $now ?? (int)(self::clock() * 1000);
        $dr = $agent->dryRun($verb, $resource, $params, $at);
        if (($dr['allowed'] ?? false) !== true) {
            return ['kind' => 'deny', 'reason' => ($dr['reason'] ?? '') !== '' ? $dr['reason'] : 'denied by policy'];
        }
        $t = $dr['t'] ?? null;
        if ($t === 1 || $t === null) {
            return ['kind' => 'auto'];
        }
        if ($standing && self::coveredByAny($standing, $verb, $resource, $at)) {
            return ['kind' => 'auto'];
        }
        $render = $digest = null;
        if ($renderer === null && $insecureUnboundApproval !== true) {
            return ['kind' => 'deny', 'reason' => 'approval render required: pass a renderer (renderersFromDefs from the pinned action definitions), or insecureUnboundApproval: true'];
        }
        if ($renderer !== null) {
            try {
                $render = $renderer($verb, $resource, $params);
                $digest = Approval::renderDigest($render);
            } catch (\Throwable $err) {
                return ['kind' => 'deny', 'reason' => 'approval render failed (fail closed): ' . ($err->getMessage() !== '' ? $err->getMessage() : 'unknown')];
            }
        }
        $gc = Authorize::readEnvelope($agent->grant)?->get('goal_commit');
        $request = [
            'id' => Pca::hashCanonical(Sign::n(['d' => 'atlas-pca/stepup/v1', 'verb' => $verb, 'resource' => $resource, 'params' => $params, 'at' => $at])),
            'verb' => $verb, 'resource' => $resource,
        ];
        if ($params !== null) {
            $request['params'] = $params;
        }
        $request += ['tier' => $t, 'reason' => ($dr['reason'] ?? '') !== '' ? $dr['reason'] : "requires tier $t co-sign", 'goalCommit' => is_string($gc) ? $gc : ''];
        if ($goal !== null) {
            $request['goal'] = $goal;
        }
        $request += ['lineage' => self::buildGoalLineage($agent, $verb, $resource, $params, $goal), 'r' => self::riskForReview($agent, $verb, $params), 'requestedAt' => $at];
        if ($render !== null && $digest !== null) {
            $request += ['render' => $render, 'renderDigest' => $digest];
        }
        return ['kind' => 'step_up', 'request' => $request];
    }

    /**
     * Review a batch of intended actions `['verb', 'resource', 'params'?]` (the inbox's "N actions waiting"). `$opts`: now, goal, standing, renderer,
     * insecureUnboundApproval.
     * @param list<array<string,mixed>> $calls
     * @param array<string,mixed> $opts
     * @return list<array<string,mixed>>
     */
    public static function batchReview(AgentHandle $agent, array $calls, array $opts = []): array
    {
        return array_map(static fn(array $c): array => self::reviewAction($agent, $c['verb'], $c['resource'], $c['params'] ?? null, ...$opts), $calls);
    }

    /** Just the step-up requests from a batch of reviews (what the approver actually sees). @param list<array<string,mixed>> $reviews @return list<array<string,mixed>> */
    public static function pendingRequests(array $reviews): array
    {
        return array_values(array_map(static fn(array $r): array => $r['request'], array_filter($reviews, static fn(array $r): bool => $r['kind'] === 'step_up')));
    }

    /**
     * Mint a standing class approval ("approve stripe.refund + gmail.send for the next 4 hours").
     * @param list<string> $verbs
     * @return array<string,mixed>
     */
    public static function approveClass(array $verbs, int $ttlMs, string $by, ?int $now = null, ?string $resource = null): array
    {
        $granted = $now ?? (int)(self::clock() * 1000);
        $sorted = $verbs;
        usort($sorted, static fn(string $a, string $b): int => IntentV2::compareUtf8($a, $b));
        $out = ['id' => Pca::hashCanonical(Sign::n(['d' => 'atlas-pca/class-approval/v1', 'verbs' => $sorted, 'resource' => $resource, 'grantedAt' => $granted, 'by' => $by])),
            'verbs' => array_values($verbs)];
        if ($resource !== null) {
            $out['resource'] = $resource;
        }
        return $out + ['grantedAt' => $granted, 'ttlMs' => $ttlMs, 'by' => $by];
    }

    private static function resourceMatches(?string $pattern, string $resource): bool
    {
        if ($pattern === null || $pattern === '*') {
            return true;
        }
        return str_ends_with($pattern, '*') ? str_starts_with($resource, substr($pattern, 0, -1)) : $pattern === $resource;
    }

    /** Does this standing approval still cover (verb, resource) at `$now`? @param array<string,mixed> $a */
    public static function classApprovalCovers(array $a, string $verb, string $resource, int $now): bool
    {
        if (!($now >= $a['grantedAt']) || !($now < $a['grantedAt'] + $a['ttlMs'])) {
            return false;
        }
        return in_array($verb, $a['verbs'], true) && self::resourceMatches($a['resource'] ?? null, $resource);
    }

    /** Is (verb, resource) covered by ANY active standing approval? @param list<array<string,mixed>> $approvals */
    public static function coveredByAny(array $approvals, string $verb, string $resource, int $now): bool
    {
        foreach ($approvals as $a) {
            if (self::classApprovalCovers($a, $verb, $resource, $now)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Record a human's decision (`approve` | `deny`) on a request (pure data for the audit trail).
     * @param array<string,mixed> $request
     * @return array{requestId:string,decision:string,by:string,at:int}
     */
    public static function recordDecision(array $request, string $decision, string $by, ?int $at = null): array
    {
        return ['requestId' => $request['id'], 'decision' => $decision, 'by' => $by, 'at' => $at ?? (int)(self::clock() * 1000)];
    }

    /**
     * Apply a human co-sign to the trust budget: a partial recharge (rho per co-sign), or a full recharge to bMax with `$full`. The ONLY thing that
     * raises the budget, so the safety bound holds between two co-signs.
     * @param array{B:float,tau:float,asOf?:?float} $budget
     * @param array<string,mixed> $policy the risk policy (`rho`, `bMax`)
     * @return array{B:float,tau:float,asOf:float}
     */
    public static function applyCosign(array $budget, array $policy, int $now, bool $full = false): array
    {
        return $full ? Risk::rechargeFull($budget, (float)$policy['bMax'], (float)$now) : Risk::recharge($budget, (float)$policy['rho'], (float)$policy['bMax'], (float)$now);
    }

    /**
     * Narrow a capability to expire `$ttlMs` from `$now` by appending an `expires` caveat signed by the holder: a delegation to the same
     * holder with one more caveat. Caveats are conjunctive and append-only, so this only ever restricts.
     */
    public static function timeBox(Obj $parent, KeyPair $holder, int|float $ttlMs, int|float|null $now = null): Obj
    {
        $at = $now ?? (int)(self::clock() * 1000); // fractional milliseconds are kept, as the reference does
        return Sign::delegate($parent, $holder, null, [['type' => 'expires', 'at' => $at + $ttlMs]]);
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
