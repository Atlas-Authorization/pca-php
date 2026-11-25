<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';

/**
 * Provenance on the wallet side and within-grant regret (provenance.ts): the fixed banner for a tainted value, the provenance
 * friction floor and the regret report. A regret case is an assoc array `['feasible' => list, 'chosen' => outcome,
 * 'admits' => Closure(outcome): bool, 'utility' => Closure(outcome): float|Num]`.
 */
final class IntentProvenance
{
    private const FRICTION_ORDER = ['tap', 'hold', 'typed', 'device'];

    /** The fixed banner for a tainted value (null for trusted / first-party values). */
    public static function provenanceBanner(mixed $level, string $what = 'value'): ?string
    {
        return match ($level) {
            'web' => "This $what was suggested by content on the page, not by you.",
            'agent' => "This $what came from your agent, not from you or the site.",
            'tool' => "This $what came from another service, not from you or this site.",
            default => null,
        };
    }

    public static function isTainted(mixed $level): bool
    {
        return $level === 'tool' || $level === 'web' || $level === 'agent';
    }

    /** A tainted critical value is at least `typed`, a tainted material value at least `hold`; provenance only raises friction. */
    public static function provenanceFriction(mixed $base, mixed $sensitivity, mixed $level): string
    {
        $floor = !self::isTainted($level) ? 'tap' : ($sensitivity === 'critical' ? 'typed' : 'hold');
        $ib = is_string($base) ? array_search($base, self::FRICTION_ORDER, true) : false;
        return self::FRICTION_ORDER[max($ib === false ? -1 : $ib, (int)array_search($floor, self::FRICTION_ORDER, true))];
    }

    private static function u(mixed $f, mixed $o): float
    {
        $r = $f($o);
        return $r instanceof Num ? $r->float() : (float)$r;
    }

    /**
     * Only options inside the effective grant compete; a chosen option outside it is denied (risk, not regret).
     * @return array{regret:float|int,best:mixed,admitted:bool}
     */
    public static function withinGrantRegret(mixed $c): array
    {
        $admits = Js::opt($c, 'admits');
        $utility = Js::opt($c, 'utility');
        $chosen = Js::opt($c, 'chosen');
        $admitted = (bool)$admits($chosen);
        $best = null;
        $bestU = -INF;
        foreach (Js::opt($c, 'feasible') as $o) {
            if (!$admits($o)) {
                continue;
            }
            $u = self::u($utility, $o);
            if ($u > $bestU) {
                $bestU = $u;
                $best = $o;
            }
        }
        if (!$admitted || $best === null) {
            return ['regret' => 0, 'best' => $best, 'admitted' => $admitted];
        }
        $d = $bestU - self::u($utility, $chosen);
        return ['regret' => is_nan($d) ? NAN : max(0.0, $d), 'best' => $best, 'admitted' => $admitted];
    }

    /** @return array<string,int|float> */
    public static function regretReport(array $cases, float|Num $scale = 1): array
    {
        $scale = $scale instanceof Num ? $scale->float() : $scale;
        $admitted = 0;
        $positive = 0;
        $sum = 0.0;
        $max = 0.0;
        foreach ($cases as $c) {
            $r = self::withinGrantRegret($c);
            if (!$r['admitted']) {
                continue;
            }
            $admitted++;
            $sum += $r['regret'];
            if ($r['regret'] > 0) {
                $positive++;
            }
            if ($r['regret'] > $max) {
                $max = (float)$r['regret'];
            }
        }
        $mean = $admitted ? $sum / $admitted : 0.0;
        $ppm = floor(($mean / ($scale > 0 ? $scale : 1)) * 1000000 + 0.5);
        return ['cases' => count($cases), 'admitted' => $admitted, 'positive' => $positive, 'mean' => $mean, 'max' => $max, 'regret_est_ppm' => $ppm];
    }
}
