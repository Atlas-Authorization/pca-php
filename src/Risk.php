<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Risk functional, threshold map and decaying trust budget (reference: packages/pca/src/risk.ts and the Policy VM's release decision,
 * packages/pca/src/policy-vm.ts steps 3 to 5; the decision kernels are the ones the Dafny model PolicyVm.dfy proves). Pure and
 * deterministic. Time is epoch milliseconds, `lambda` is budget drained PER SECOND, a non-finite input fails closed (worst case).
 * A policy is `['weights' => [alpha, beta, gamma, delta, epsilon, zeta], theta1, theta2, kappa, lambda, rho, bMax]` (floats); a budget is
 * `['B' => float, 'tau' => float, 'asOf' => ?float]`; the inputs are the six unit values `semanticDistance, reversibility,
 * blastRadius, taint, confidence, age`.
 */
final class Risk
{
    public const INPUTS = ['semanticDistance', 'reversibility', 'blastRadius', 'taint', 'confidence', 'age'];
    /** The worst case of each input (risk-increasing inputs 1, reversibility and confidence 0, age 1). */
    private const WORST = ['semanticDistance' => 1.0, 'reversibility' => 0.0, 'blastRadius' => 1.0, 'taint' => 1.0, 'confidence' => 0.0, 'age' => 1.0];
    public const DEFAULT_HORIZON_MS = 3600000.0;
    /** Classes that may take the optimistic fast path; every other (or missing) class counts as irreversible. */
    private const FAST_PATH = ['reversible', 'rate_limited', 'costly'];

    private static function finite(mixed $x): bool
    {
        return (is_int($x) || is_float($x)) && is_finite((float)$x);
    }

    private static function clamp01(float $x): float
    {
        return $x < 0 ? 0.0 : ($x > 1 ? 1.0 : $x);
    }

    /** Non-finite is the worst case; else clamped to [0, 1]. */
    private static function unit(mixed $x, float $worst): float
    {
        return self::finite($x) ? self::clamp01((float)$x) : $worst;
    }

    /** A weight: finite and positive, else 0. */
    private static function wt(mixed $x): float
    {
        return self::finite($x) && $x > 0 ? (float)$x : 0.0;
    }

    private static function nz(mixed $x): float
    {
        return self::finite($x) && $x > 0 ? (float)$x : 0.0;
    }

    /** The policy of an envelope's `risk_policy` (an Obj or array already validated by the envelope reader) as floats. @return array<string,mixed> */
    public static function policyOf(mixed $rp): array
    {
        $g = static fn(mixed $o, string $k): mixed => $o instanceof Obj ? $o->get($k) : (is_array($o) ? ($o[$k] ?? null) : null);
        $num = static fn(mixed $v): float => $v instanceof Num ? $v->float() : (float)$v;
        $w = $g($rp, 'weights');
        $weights = [];
        foreach (['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'] as $k) {
            $weights[$k] = $num($g($w, $k));
        }
        $p = ['weights' => $weights];
        foreach (['theta1', 'theta2', 'kappa', 'lambda', 'rho', 'bMax'] as $k) {
            $p[$k] = $num($g($rp, $k));
        }
        return $p;
    }

    /**
     * r = clamp(alpha*d + beta*(1-rev) + gamma*bl + delta*taint + epsilon*(1-conf) + zeta*age, 0, 1). Monotone in every input (weights
     * are clamped to >= 0), and a non-finite input counts as its worst case.
     * @param array<string,mixed> $i @param array<string,float> $w
     */
    public static function score(array $i, array $w): float
    {
        $r = self::wt($w['alpha']) * self::unit($i['semanticDistance'] ?? null, 1.0)
            + self::wt($w['beta']) * (1 - self::unit($i['reversibility'] ?? null, 0.0))
            + self::wt($w['gamma']) * self::unit($i['blastRadius'] ?? null, 1.0)
            + self::wt($w['delta']) * self::unit($i['taint'] ?? null, 1.0)
            + self::wt($w['epsilon']) * (1 - self::unit($i['confidence'] ?? null, 0.0))
            + self::wt($w['zeta']) * self::unit($i['age'] ?? null, 1.0);
        return self::clamp01($r);
    }

    /**
     * The piecewise threshold map: r <= theta1 -> t=1 (claim; optimistic only for a reversible action), theta1 < r <= theta2 -> t=2
     * (standard), above -> t=3 (strong). A non-finite r is the worst case. @return array{t:int, proof:string, optimisticAllowed:bool}
     */
    public static function requiredThreshold(float $r, float $theta1, float $theta2, bool $irreversible = false): array
    {
        $x = is_finite($r) ? $r : 1.0;
        if ($x <= $theta1) {
            return ['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => !$irreversible];
        }
        if ($x <= $theta2) {
            return ['t' => 2, 'proof' => 'standard', 'optimisticAllowed' => false];
        }
        return ['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false];
    }

    /** Raise a threshold to at least `$minT` and keep it coherent (never lowers anything). @param array{t:int, proof:string, optimisticAllowed:bool} $rt */
    public static function escalate(array $rt, int $minT): array
    {
        $rank = ['claim' => 0, 'standard' => 1, 'strong' => 2];
        $names = [1 => 'claim', 2 => 'standard', 3 => 'strong'];
        $t = max($minT, $rt['t']);
        $floor = $names[$t];
        return ['t' => $t, 'proof' => $rank[$rt['proof']] >= $rank[$floor] ? $rt['proof'] : $floor, 'optimisticAllowed' => $t > 1 ? false : $rt['optimisticAllowed']];
    }

    /** c(A) = kappa * r(A); a non-finite r costs as r = 1. */
    public static function cost(float $r, float $kappa): float
    {
        return self::nz($kappa) * self::clamp01(is_finite($r) ? $r : 1.0);
    }

    /** Passive leak dB/dt = -lambda since the last update (idempotent for repeated calls at one `now`). @param array{B:float,tau:float,asOf?:?float} $b */
    public static function leak(array $b, float $now, float $lambda): array
    {
        $from = $b['asOf'] ?? $b['tau'];
        $dt = is_finite($now) && is_finite($from) ? max(0.0, $now - $from) : 0.0;
        return ['B' => max(0.0, $b['B'] - self::nz($lambda) * ($dt / 1000)), 'tau' => $b['tau'], 'asOf' => is_finite($now) ? max($now, $from) : $from];
    }

    /** B <- max(0, B - cost). The caller checks B >= cost first. @param array{B:float,tau:float,asOf?:?float} $b */
    public static function debit(array $b, float $c): array
    {
        return ['B' => max(0.0, $b['B'] - self::nz($c)), 'tau' => $b['tau'], 'asOf' => $b['asOf'] ?? null];
    }

    /** Normalised age since the last human touch: clamp((now - tau) / horizon, 0, 1); non-finite or a bad horizon is the worst case (1). */
    public static function ageSinceTouch(array $b, float $now, float $horizonMs = self::DEFAULT_HORIZON_MS): float
    {
        if (!is_finite($now) || !is_finite($b['tau']) || !($horizonMs > 0)) {
            return 1.0;
        }
        return self::clamp01(($now - $b['tau']) / $horizonMs);
    }

    /**
     * The admission of an action whose threshold band is `$t` (requiredThreshold(r).t) and whose cost the budget does (or does not) cover.
     * The machine-only band is t=1 AND t=2 (the guardian auto-cosigns at t=2): both are metered, and an action that the budget cannot
     * cover escalates to t=3 (a human step-up; only t=3 is unmetered). @return array{admit:bool, needStepUp:bool, t:int, metered:bool}
     */
    public static function admission(int $t, bool $budgetCoversCost): array
    {
        if ($t < 3 && !$budgetCoversCost) {
            return ['admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false];
        }
        if ($t === 1) {
            return ['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true];
        }
        if ($t === 2) {
            return ['admit' => false, 'needStepUp' => true, 't' => 2, 'metered' => true];
        }
        return ['admit' => false, 'needStepUp' => true, 't' => 3, 'metered' => false];
    }

    /**
     * The release decision (DecideCore): the guardian share is released only when the envelope predicates, the caveats, the delegated
     * caveats and the chain all hold; the threshold is raised to the admission's band; the budget is debited only for a released,
     * metered action. @param array{t:int, proof:string, optimisticAllowed:bool} $rt @param array{admit:bool, needStepUp:bool, t:int, metered:bool} $adm
     * @return array{release:bool, admit:bool, needStepUp:bool, threshold:array<string,mixed>, debit:bool}
     */
    public static function decideCore(bool $policyOk, bool $caveatsOk, bool $delegatedOk, bool $chainOk, array $rt, array $adm): array
    {
        $release = $policyOk && $caveatsOk && $delegatedOk && $chainOk;
        return ['release' => $release, 'admit' => $release && $adm['admit'], 'needStepUp' => $release ? $adm['needStepUp'] : true,
            'threshold' => self::escalate($rt, $adm['t']), 'debit' => $release && $adm['metered']];
    }

    /**
     * Normalised geodesic distance in the committed plan DAG, in [0, 1]: edges come from the node references (`pre` / `post`), the distance is
     * the BFS hop count over the UNDIRECTED graph divided by (n - 1); no edges at all falls back to |i - j| / (n - 1); an unknown id or an
     * unreachable node is 1 (fail closed); the same node is 0. @param list<mixed> $plan
     */
    public static function planGeodesic(array $plan, ?string $from, ?string $to): float
    {
        if (!array_is_list($plan)) {
            return 1.0;
        }
        $idx = [];
        foreach ($plan as $i => $n) {
            $id = $n instanceof Obj ? $n->get('id') : null;
            if (is_string($id)) {
                $idx['k' . $id] = $i; // the reference's Map: a later node with the same id wins
            }
        }
        $a = $from === null ? null : ($idx['k' . $from] ?? null);
        $b = $to === null ? null : ($idx['k' . $to] ?? null);
        if ($a === null || $b === null) {
            return 1.0;
        }
        if ($a === $b) {
            return 0.0;
        }
        $n = count($plan);
        $adj = array_fill(0, $n, []);
        $edges = 0;
        $link = static function (int $i, int $j) use (&$adj, &$edges): void {
            if ($i === $j) {
                return;
            }
            if (!isset($adj[$i][$j])) {
                $edges++;
            }
            $adj[$i][$j] = true;
            $adj[$j][$i] = true;
        };
        foreach ($plan as $i => $node) {
            $pre = $node instanceof Obj ? $node->get('pre') : null;
            $post = $node instanceof Obj ? $node->get('post') : null;
            foreach (self::refs($pre, ['after', 'depends_on', 'requires', 'nodes']) as $id) {
                if (isset($idx['k' . $id])) {
                    $link($idx['k' . $id], $i);
                }
            }
            foreach (self::refs($post, ['before', 'enables', 'then', 'next']) as $id) {
                if (isset($idx['k' . $id])) {
                    $link($i, $idx['k' . $id]);
                }
            }
        }
        if ($edges === 0) {
            return self::clamp01(abs($a - $b) / ($n - 1));
        }
        $dist = array_fill(0, $n, -1);
        $dist[$a] = 0;
        $q = [$a];
        for ($h = 0; $h < count($q); $h++) {
            $u = $q[$h];
            $nb = array_keys($adj[$u]);
            sort($nb);
            foreach ($nb as $v) {
                if ($dist[$v] === -1) {
                    $dist[$v] = $dist[$u] + 1;
                    $q[] = $v;
                }
            }
        }
        return $dist[$b] < 0 ? 1.0 : self::clamp01($dist[$b] / ($n - 1));
    }

    /** @param list<string> $keys @return list<string> */
    private static function refs(mixed $x, array $keys): array
    {
        $out = [];
        $add = static function (mixed $v) use (&$out): void {
            if (is_string($v)) {
                $out[] = $v;
            } elseif (is_array($v) && array_is_list($v)) {
                foreach ($v as $s) {
                    if (is_string($s)) {
                        $out[] = $s;
                    }
                }
            }
        };
        $add($x);
        if ($x instanceof Obj) {
            foreach ($keys as $k) {
                $add($x->get($k));
            }
        }
        return $out;
    }

    /** The inputs the Policy VM scores: the worst case overlaid with the finite server values. @param array<string,mixed> $risk @return array<string,float> */
    public static function inputsOf(array $risk): array
    {
        $out = self::WORST;
        foreach (self::INPUTS as $k) {
            if (isset($risk[$k]) && self::finite($risk[$k])) {
                $out[$k] = (float)$risk[$k];
            }
        }
        return $out;
    }

    public static function fastPathClass(mixed $c): bool
    {
        return is_string($c) && in_array($c, self::FAST_PATH, true);
    }
}
