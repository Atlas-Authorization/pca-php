<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/PolicySim.php';

/**
 * Budget forecasting (the TypeScript reference budget-forecast.ts is authoritative): how the trust budget drains over a planned
 * action sequence under a compiled policy, and, inversely, the `kappa` / `bMax` that give a target autonomy.
 */
final class BudgetForecast
{
    /** The double of a JSON or PHP number (NaN and the infinities included), else null. */
    private static function d(mixed $x): ?float
    {
        return $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : null);
    }

    /**
     * Forecast a plan (`[{verb, resource, params?, at?}]`): the per-step outcome and budget, the index of the first forced co-sign,
     * the autonomous risk taken, how many co-signs the plan needs and the budget left. `$start` is the start time (see {@see PolicySim::simulate}).
     *
     * @param array<string,mixed> $policy a compiled policy
     * @return array{steps: list<array<string,mixed>>, firstStepUpAt?: int, autonomousRisk: float, forcesCosign: bool, cosignsNeeded: int, endBudget: float}
     */
    public static function forecast(array $policy, array $plan, int|float $start = 0, ?Catalog $catalog = null): array
    {
        $rep = PolicySim::simulate($policy, $plan, $catalog, $start);
        $steps = array_map(static fn(array $r): array => ['verb' => Js::opt($r['action'], 'verb'), 'resource' => Js::opt($r['action'], 'resource'), 'outcome' => $r['outcome'],
            'r' => $r['r'], 'budgetAfter' => $r['budgetAfter']], $rep['results']);
        $out = ['steps' => $steps];
        foreach ($steps as $i => $s) {
            if ($s['outcome'] === 'step_up') {
                $out['firstStepUpAt'] = $i;
                break;
            }
        }
        return $out + ['autonomousRisk' => $rep['autonomousRisk'], 'forcesCosign' => $rep['stepUp'] > 0, 'cosignsNeeded' => $rep['stepUp'], 'endBudget' => $rep['endBudget']];
    }

    /**
     * The `kappa` and `bMax` under which about `$targetActions` actions of risk `$perActionRisk` run between two human co-signs.
     * Throws unless the two are finite numbers and `$kappa` (default 1) is a positive finite number.
     *
     * @return array{kappa: float, bMax: float, autonomousBound: float, rationale: string}
     */
    public static function recommendPolicy(mixed $targetActions, mixed $perActionRisk, mixed $kappa = null): array
    {
        $k = $kappa === null ? 1.0 : self::d($kappa);
        if ($k === null || !is_finite($k) || $k <= 0) {
            throw new \RangeException('recommendPolicy: kappa must be a positive finite number');
        }
        $t = self::d($targetActions);
        $p = self::d($perActionRisk);
        if ($t === null || $p === null || !is_finite($t) || !is_finite($p)) {
            throw new \RangeException('recommendPolicy: targetActions and perActionRisk must be finite numbers');
        }
        $r = max(1e-6, min(1.0, $p));
        $n = $t > 0 ? $t : 0.0;
        $bMax = $n * $r * $k;
        $bound = $bMax / $k;
        $fixed = static fn(float $x): string => abs($x) >= 1e21 ? IntentWb::jsNumStr($x) : AnalyzerJs::toFixed($x, 3);
        return ['kappa' => $k, 'bMax' => $bMax, 'autonomousBound' => $bound,
            'rationale' => 'Σr ≤ bMax/κ = ' . $fixed($bound) . ' ≥ ' . IntentWb::jsNumStr($n) . '×' . $fixed($r) . ' actions before a human co-sign'];
    }

    /** The most risk the agent can take between two human co-signs under `{bMax, kappa}`: `bMax / kappa` (0 when kappa is not above 0). */
    public static function autonomyBoundOf(mixed $p): float
    {
        $kappa = self::d(Js::opt($p, 'kappa'));
        if ($kappa === null || !($kappa > 0)) {
            return 0.0;
        }
        $bMax = self::d(Js::opt($p, 'bMax'));
        return fdiv($bMax === null || is_nan($bMax) ? NAN : max(0.0, $bMax), $kappa);
    }
}
