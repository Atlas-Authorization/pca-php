<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/IntentPolicy.php';
require_once __DIR__ . '/IntentLearner.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * Measuring a grant against an intent (metrics.ts): Monte Carlo and exact risk / burden / fidelity, the Hoeffding half-width and the
 * Wilson interval. An acceptability is a Closure(vs, outcome): int|float; the harm model is the {@see HarmModel} of IntentOmega
 * (default IntentOmega::defaultHarm()). Metrics are assoc arrays of floats (NaN where the reference yields NaN).
 */
final class IntentMetrics
{
    /** The Monte Carlo sample count when `samples` is not given (measureGrant, estimateResidualRiskMC). */
    public const DEFAULT_SAMPLES = 20000;

    private static function div(float $a, float $b): float
    {
        return fdiv($a, $b);
    }

    private static function num(mixed $x): float
    {
        return $x instanceof Num ? $x->float() : (float)$x;
    }

    /** The 0/1 acceptability of a policy: 1 when it admits the outcome. */
    public static function acceptabilityOf(mixed $policy): \Closure
    {
        $a = IntentPolicy::admitter($policy);
        return static fn($vs, $o): int => $a->admits($vs, $o) ? 1 : 0;
    }

    public static function hoeffdingHalfWidth(int|float|Num $range, int|float|Num $samples, int|float|Num $deltaPrime = 0.05): float
    {
        $r = self::num($range);
        $logv = log(self::div(2.0, self::num($deltaPrime)));
        $q = self::div($logv, 2 * self::num($samples));
        return $r * ($q < 0 || is_nan($q) ? NAN : sqrt($q));
    }

    /**
     * Monte Carlo risk R, burden B, R_max and fidelity F of a grant over the workload. Options: `samples` (20000), `seed` (1), `harm`
     * (a HarmModel), `hMax`.
     * @return array{risk:float,burden:float,riskMax:float,fidelity:float,samples:int,riskHalfWidth:float}
     */
    public static function measureGrant(mixed $omega, mixed $grant, \Closure $acceptability, mixed $opts = null): array
    {
        $samples = Js::opt($opts, 'samples');
        $M = $samples === null ? self::DEFAULT_SAMPLES : (int)self::num($samples);
        $harm = Js::opt($opts, 'harm') ?? IntentOmega::defaultHarm();
        $seed = Js::opt($opts, 'seed');
        $rand = IntentOmega::rng($seed === null ? 1 : WalletOmega::plain($seed));
        $g = IntentPolicy::admitter($grant);
        $R = 0.0;
        $B = 0.0;
        $Rm = 0.0;
        $hMax = 0.0;
        for ($i = 0; $i < $M; $i++) {
            [$vs, $o] = IntentOmega::sampleOutcome($omega, $rand);
            $a = self::num($acceptability($vs, $o));
            $h = self::num(IntentOmega::harmOf($vs, $o, $harm));
            $hMax = IntentOmega::jsMax($hMax, $h);
            if ($g->admits($vs, $o)) {
                $R += (1 - $a) * $h;
            } else {
                $B += $a;
            }
            $Rm += (1 - $a) * $h;
        }
        $R = self::div($R, (float)$M);
        $B = self::div($B, (float)$M);
        $Rm = self::div($Rm, (float)$M);
        $hm = Js::opt($opts, 'hMax');
        return ['risk' => $R, 'burden' => $B, 'riskMax' => $Rm, 'fidelity' => $Rm > 0 ? 1 - $R / $Rm : 1.0, 'samples' => $M,
            'riskHalfWidth' => self::hoeffdingHalfWidth($hm ?? $hMax, $M)];
    }

    /**
     * The Monte Carlo form of the learner's residual-risk estimate, for the cross-check (options `samples` 20000, `seed` 7). The learner's
     * harm model is not readable from IntentLearner: pass it as `$harm` when it is not the default.
     */
    public static function estimateResidualRiskMC(IntentLearner $learner, mixed $opts = null, ?HarmModel $harm = null): float
    {
        $samples = Js::opt($opts, 'samples');
        $M = $samples === null ? self::DEFAULT_SAMPLES : (int)self::num($samples);
        $rand = IntentOmega::rng(($s = Js::opt($opts, 'seed')) === null ? 7 : WalletOmega::plain($s));
        $harm ??= IntentOmega::defaultHarm();
        $g = IntentPolicy::admitter($learner->synthesize());
        $R = 0.0;
        for ($i = 0; $i < $M; $i++) {
            [$vs, $o] = IntentOmega::sampleOutcome($learner->omega, $rand);
            if ($g->admits($vs, $o)) {
                $R += (1 - $learner->acceptance($o)) * self::num(IntentOmega::harmOf($vs, $o, $harm));
            }
        }
        return self::div($R, (float)$M);
    }

    /**
     * Exact R, B, R_max, F by summing over the cells (no sampling error).
     * @return array{risk:float,burden:float,riskMax:float,fidelity:float,meanHarm:float}
     */
    public static function measureGrantExact(mixed $omega, mixed $grant, \Closure $acceptability, ?HarmModel $harm = null): array
    {
        $harm ??= IntentOmega::defaultHarm();
        $g = IntentPolicy::admitter($grant);
        $R = 0.0;
        $B = 0.0;
        $Rm = 0.0;
        $Eh = 0.0;
        foreach (Js::opt($omega, 'verbs') as $vs) {
            $n = IntentOmega::verbCellCount($vs);
            for ($c = 0; $c < $n; $c++) {
                $idx = IntentOmega::decodeCell($vs, $c);
                $o = IntentOmega::cellRep($vs, $idx);
                $st = IntentOmega::cellStats($vs, $idx, $harm);
                $mass = self::num($st['mass']);
                $h = self::num($st['harm']);
                $a = self::num($acceptability($vs, $o));
                $Eh += $mass * $h;
                $Rm += $mass * (1 - $a) * $h;
                if ($g->admits($vs, $o)) {
                    $R += $mass * (1 - $a) * $h;
                } else {
                    $B += $mass * $a;
                }
            }
        }
        return ['risk' => $R, 'burden' => $B, 'riskMax' => $Rm, 'fidelity' => $Rm > 0 ? 1 - $R / $Rm : 1.0, 'meanHarm' => $Eh];
    }

    /** Wilson score interval for a binomial proportion k/n (default 95%). @return array{p:float,lo:float|int,hi:float|int} */
    public static function wilsonInterval(int|float|Num $k, int|float|Num $n, int|float|Num $z = 1.959963984540054): array
    {
        $k = self::num($k);
        $n = self::num($n);
        $z = self::num($z);
        if (!($n > 0)) {
            return ['p' => NAN, 'lo' => 0, 'hi' => 1];
        }
        $p = $k / $n;
        $z2 = $z * $z;
        $den = 1 + $z2 / $n;
        $centre = ($p + $z2 / (2 * $n)) / $den;
        $rad = ($p * (1 - $p)) / $n + $z2 / (4 * $n * $n);
        $half = ($z * ($rad < 0 || is_nan($rad) ? NAN : sqrt($rad))) / $den;
        return ['p' => $p, 'lo' => IntentOmega::jsMax(0, $centre - $half), 'hi' => IntentOmega::jsMin(1, $centre + $half)];
    }
}
