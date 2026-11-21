<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/Facade.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/Risk.php';

/**
 * Policy simulation and static lints (the TypeScript reference policy-sim.ts is authoritative): replay hypothetical actions against
 * a compiled policy ({@see Facade::compilePolicy}) to see, per action, whether it runs on its own, needs a human step-up or is
 * denied, with the budget trace; and flag the classic authoring mistakes. Nothing here authorizes anything.
 */
final class PolicySim
{
    private const REVERSIBILITY_ORDER = ['reversible', 'rate_limited', 'irreversible'];

    /** The double of a finite JSON or PHP number, else null (a string is not a number). */
    private static function fin(mixed $x): ?float
    {
        $v = $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : null);
        return $v !== null && is_finite($v) ? $v : null;
    }

    /**
     * Replay `$actions` (`{verb, resource, params?, at?}`, Obj or arrays) in time order. `$start` is the start TIME: an action
     * without `at` occurs at `$start` + its index; the budget always starts at the policy's `bMax`. An action whose time is not a
     * finite number is denied. A verb the catalog does not know is treated as irreversible (it never falls back to another catalog).
     *
     * @param array<string,mixed> $policy a compiled policy
     * @return array{results: list<array<string,mixed>>, auto: int, stepUp: int, deny: int, endBudget: float, peakRisk: float, autonomousRisk: float}
     */
    public static function simulate(array $policy, array $actions, ?Catalog $catalog = null, int|float $start = 0): array
    {
        $catalog ??= Catalog::defaultCatalog();
        $rp = $policy['riskPolicy'];
        $budget = ['B' => (float)$rp['bMax'], 'tau' => (float)$start, 'asOf' => (float)$start];
        $results = $ordered = [];
        foreach (array_values($actions) as $i => $a) {
            $at = Js::opt($a, 'at') ?? $start + $i;
            if (self::fin($at) === null) {
                $results[] = ['action' => $a, 'outcome' => 'deny', 'r' => 1, 'reason' => 'action has no finite time', 'budgetAfter' => $budget['B']];
            } else {
                $ordered[] = [$a, (float)self::fin($at)];
            }
        }
        usort($ordered, static fn(array $x, array $y): int => $x[1] <=> $y[1]); // stable: equal times keep the given order
        $predicates = Sign::n($policy['predicates']);
        $caveats = Sign::n($policy['caveats']);
        $recent = [];
        $peak = $autonomous = 0.0;
        foreach ($ordered as [$a, $at]) {
            $verb = Js::opt($a, 'verb');
            $spec = is_string($verb) ? $catalog->get($verb) : null;
            $class = $spec['reversibility'] ?? 'irreversible';
            $params = Js::opt($a, 'params');
            $r = (float)Facade::riskFor($policy, $spec ?? ['blastRadius' => 0.8], $params);
            $peak = max($peak, $r);
            $pred = Predicates::evaluatePredicates($predicates, Obj::of(['action' => Obj::of(['verb' => $verb, 'resource' => Js::opt($a, 'resource'),
                'params' => $params === null ? new Obj() : Sign::n($params), 'reversibility_class' => $class])]));
            $cav = $pred['allowed'] === true
                ? Pca::evaluateCaveats($caveats, Sign::n(['now' => $at, 'blast_radius' => $spec['blastRadius'] ?? 1, 'reversibility_class' => $class, 'recent_action_times' => $recent]))
                : ['ok' => false, 'failed' => []];
            $budget = Risk::leak($budget, $at, (float)$rp['lambda']);
            if ($pred['allowed'] !== true) {
                $results[] = ['action' => $a, 'outcome' => 'deny', 'r' => $r, 'reason' => $pred['reason'] ?? 'no predicate permits this action', 'budgetAfter' => $budget['B']];
                continue;
            }
            if (!$cav['ok']) {
                $results[] = ['action' => $a, 'outcome' => 'deny', 'r' => $r, 'reason' => 'caveat(s) failed: ' . implode(', ', $cav['failed']), 'budgetAfter' => $budget['B']];
                continue;
            }
            $cost = Risk::cost($r, (float)$rp['kappa']);
            $adm = Risk::admission(Risk::requiredThreshold($r, (float)$rp['theta1'], (float)$rp['theta2'])['t'], is_finite((float)$budget['B']) && $budget['B'] >= $cost);
            if ($adm['t'] === 1 && $adm['admit']) {
                $budget['B'] -= $cost;
                $autonomous += $r;
                $recent[] = $at;
                $results[] = ['action' => $a, 'outcome' => 'auto', 't' => 1, 'r' => $r, 'budgetAfter' => $budget['B']];
            } else {
                $results[] = ['action' => $a, 'outcome' => 'step_up', 't' => $adm['t'], 'r' => $r] + ($adm['needStepUp'] ? ['reason' => 'requires tier ' . $adm['t']] : []) + ['budgetAfter' => $budget['B']];
            }
        }
        $count = static fn(string $o): int => count(array_filter($results, static fn(array $x): bool => $x['outcome'] === $o));
        return ['results' => $results, 'auto' => $count('auto'), 'stepUp' => $count('step_up'), 'deny' => $count('deny'), 'endBudget' => $budget['B'],
            'peakRisk' => $peak, 'autonomousRisk' => $autonomous];
    }

    private static function sev(mixed $c): int
    {
        $i = array_search($c, self::REVERSIBILITY_ORDER, true);
        return $i === false ? -1 : $i;
    }

    /**
     * Static checks of a compiled policy: a limit that matches no granted action (error), a money action without a per-call limit,
     * a risky action on any resource, an uncatalogued verb, no step-up band, a very large autonomous bound.
     *
     * @param array<string,mixed> $policy a compiled policy
     * @return list<array{level: string, code: string, message: string}>
     */
    public static function lintPolicy(array $policy, ?Catalog $catalog = null): array
    {
        $catalog ??= Catalog::defaultCatalog();
        $lints = [];
        $granted = [];
        foreach ($policy['actions'] as $s) {
            foreach ([$s['verb'], $s['action'], ...($s['aliases'] ?? [])] as $name) {
                $granted["k$name"] = true;
            }
        }
        foreach (array_keys($policy['inputLimits']) as $key) {
            if (!isset($granted["k$key"])) {
                $lints[] = ['level' => 'error', 'code' => 'limit-unmatched', 'message' => "limit for '$key' matches no granted action"];
            }
        }
        foreach ($policy['actions'] as $spec) {
            $verb = $spec['verb'];
            $resource = null;
            foreach ($policy['predicates'] as $p) {
                if (($p['verb'] ?? null) === $verb) {
                    $resource = $p['resource'] ?? null;
                    break;
                }
            }
            if (($spec['amountField'] ?? '') !== '' && !isset($policy['limits'][$verb])) {
                $lints[] = ['level' => 'warn', 'code' => 'money-unbounded', 'message' => "money action '$verb' has no per-call limit — spend is bounded only by the trust budget"];
            }
            if (($resource === null || $resource === '' || $resource === '*') && self::sev($spec['reversibility']) >= 1) {
                $lints[] = ['level' => 'warn', 'code' => 'broad-resource', 'message' => "'$verb' ({$spec['reversibility']}) matches ANY resource — consider a resource prefix"];
            }
            if ($catalog->get($verb) === null) {
                $lints[] = ['level' => 'info', 'code' => 'uncatalogued', 'message' => "'$verb' is not in the catalog — treated conservatively (irreversible, high blast radius)"];
            }
        }
        $rp = $policy['riskPolicy'];
        if ($rp['theta2'] >= 1) {
            $irrev = in_array('irreversible', array_column($policy['actions'], 'reversibility'), true);
            $lints[] = ['level' => $irrev ? 'warn' : 'info', 'code' => 'no-step-up-band',
                'message' => 'theta2 ≥ 1: no action triggers a human step-up until the budget is exhausted' . ($irrev ? ' — including irreversible actions' : '')];
        }
        if ($rp['kappa'] > 0 && $rp['bMax'] / $rp['kappa'] > 100) {
            $lints[] = ['level' => 'warn', 'code' => 'large-autonomy',
                'message' => 'autonomous bound is ' . IntentWb::jsNumStr(floor($rp['bMax'] / $rp['kappa'] + 0.5)) . '× a max-risk action between human co-signs'];
        }
        return $lints;
    }
}
