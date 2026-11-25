<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentOmega.php';
require_once __DIR__ . '/WalletOmega.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentMapKit.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Classifier error folded into the residual-risk estimate: the confusion calibration (exact Clopper-Pearson upper bounds per entry), the
 * risk on explicit arrays, the label-sound bound, the classifier-aware residual risk of a learner and the gamma-max JIT gate. A "learner"
 * exposes ->omega and ->cells() -> [{verb, cell, p, mass, harm, inGrant}] (IntentLearner). Calibrations are Obj or assoc arrays
 * {labels, counts, gamma, gammaBar, delta_ppm}; numbers plain.
 */
final class IntentClassifier
{
    private static function g(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    private static function f(mixed $x): float
    {
        return Js::num($x) ?? NAN;
    }

    /** Calibrate a classifier on labelled examples. Labels outside the label set are refused. @return array<string,mixed> */
    public static function calibrateConfusion(array $samples, array $labels, mixed $deltaGamma = 0.05): array
    {
        $L = array_values(array_unique($labels));
        usort($L, static fn($a, $b) => IntentV2::compareUtf8($a, $b));
        if (count($L) === 0) {
            throw new \InvalidArgumentException('calibrateConfusion: empty label set');
        }
        $delta = self::f($deltaGamma);
        if (!(0 < $delta && $delta < 1)) {
            throw new \InvalidArgumentException('calibrateConfusion: delta must be in (0, 1)');
        }
        $ix = array_flip($L);
        $counts = array_fill(0, count($L), array_fill(0, count($L), 0));
        foreach ($samples as $s) {
            $tr = self::g($s, 'truth');
            $pr = self::g($s, 'predicted');
            $t = is_string($tr) ? ($ix[$tr] ?? null) : null;
            $p = is_string($pr) ? ($ix[$pr] ?? null) : null;
            if ($t === null || $p === null) {
                throw new \InvalidArgumentException('calibrateConfusion: label outside L (' . Js::str($tr) . ' / ' . Js::str($pr) . ')');
            }
            $counts[$t][$p]++;
        }
        $alpha = $delta / (count($L) * count($L));
        $gamma = [];
        $gammaBar = [];
        foreach ($counts as $row) {
            $n = array_sum($row);
            $gamma[] = array_map(static fn($c) => $n ? $c / $n : 0, $row);
            $gammaBar[] = array_map(static fn($c) => WalletOmega::clopperPearsonUpper($c, $n, $alpha), $row);
        }
        return ['labels' => $L, 'counts' => $counts, 'gamma' => $gamma, 'gammaBar' => $gammaBar, 'delta_ppm' => (int)floor($delta * 1000000 + 0.5)];
    }

    public static function confusionDigest(mixed $c): string
    {
        return Pca::hashCanonical(self::model(['d' => 'atlas-pca/intent-classifier-calibration/v1', 'labels' => self::g($c, 'labels'),
            'counts' => self::g($c, 'counts'), 'delta_ppm' => self::g($c, 'delta_ppm')]));
    }

    /** Numbers as Num, assoc arrays as Obj (the canonical-hash model). */
    private static function model(mixed $v): mixed
    {
        $v = IntentMapKit::obj($v);
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::model($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::model(...), $v);
        }
        if (is_int($v)) {
            return new Num((string)$v);
        }
        if (is_float($v)) {
            if (!is_finite($v)) {
                throw new \InvalidArgumentException('non-finite number');
            }
            return new Num($v == 0.0 ? '0' : IntentWb::jsStr($v));
        }
        return $v;
    }

    /** Max over true labels of the capped upper bound of any other label. */
    public static function publishedErrorRate(mixed $c): float
    {
        $worst = 0.0;
        foreach (self::g($c, 'gammaBar') as $t => $row) {
            $s = 0.0;
            foreach ($row as $p => $g) {
                if ($p !== $t) {
                    $s += self::f($g);
                }
            }
            $e = min(1.0, $s);
            if ($e > $worst) {
                $worst = $e;
            }
        }
        return $worst;
    }

    public static function classifierCardNote(string $id, mixed $c): string
    {
        return '"' . $id . '" is decided by an attested classifier, not by a person. Published error rate: up to ' . AnalyzerJs::toFixed(self::publishedErrorRate($c) * 100, 1) . '%.';
    }

    private static function gammaOfSet(array $g, array $A, int $t): float
    {
        $s = 0.0;
        foreach ($A as $p) {
            $s += self::f($g[$p][$t]);
        }
        return min(1.0, $s);
    }

    /** @return list<int> */
    private static function members(mixed $row): array
    {
        $A = [];
        foreach ($row as $p => $b) {
            if (Js::truthy($b)) {
                $A[] = $p;
            }
        }
        return $A;
    }

    /** R_kappa(G) = sum mu (1 - a) h Gamma(A_G(x) | l), with Gamma(A | l) capped at 1. */
    public static function classifierRisk(mixed $m): float
    {
        $r = 0.0;
        $a = self::g($m, 'a');
        $h = self::g($m, 'h');
        foreach (self::g($m, 'mu') as $x => $row) {
            $A = self::members(self::g($m, 'inG')[$x]);
            foreach ($row as $t => $mu) {
                $r += self::f($mu) * (1 - self::f($a[$x][$t])) * self::f($h[$x][$t]) * self::gammaOfSet(self::g($m, 'g'), $A, $t);
            }
        }
        return $r;
    }

    public static function labelSound(mixed $m): bool
    {
        $a = self::g($m, 'a');
        foreach (self::g($m, 'inG') as $x => $row) {
            foreach ($row as $p => $b) {
                if (Js::truthy($b) && self::f($a[$x][$p]) != 1) {
                    return false;
                }
            }
        }
        return true;
    }

    public static function labelSoundBound(mixed $m, mixed $hMax): float
    {
        $s = 0.0;
        $a = self::g($m, 'a');
        foreach (self::g($m, 'mu') as $x => $row) {
            $A = self::members(self::g($m, 'inG')[$x]);
            foreach ($row as $t => $mu) {
                if (self::f($a[$x][$t]) == 0) {
                    $s += self::f($mu) * self::gammaOfSet(self::g($m, 'g'), $A, $t);
                }
            }
        }
        return self::f($hMax) * $s;
    }

    /** @return array{0:mixed,1:int,2:array<int,array<int,array<string,mixed>>>} dim, k, groups */
    private static function groupsOf(mixed $l, mixed $spec): array
    {
        $vs = null;
        foreach (self::g($l->omega, 'verbs') as $v) {
            if (self::g($v, 'verb') === self::g($spec, 'verb')) {
                $vs = $v;
                break;
            }
        }
        if ($vs === null) {
            throw new \InvalidArgumentException('classifier: no verb ' . Js::str(self::g($spec, 'verb')) . " in \u{03A9}");
        }
        $k = -1;
        foreach (self::g($vs, 'dims') as $i => $d) {
            if (self::g($d, 'path') === self::g($spec, 'path')) {
                $k = $i;
                break;
            }
        }
        $dim = $k >= 0 ? self::g($vs, 'dims')[$k] : null;
        if ($k < 0 || $dim === null || self::g($dim, 'kind') !== 'cat') {
            throw new \InvalidArgumentException('classifier: ' . Js::str(self::g($spec, 'verb')) . ' has no categorical dimension ' . Js::str(self::g($spec, 'path')));
        }
        $groups = [];
        foreach ($l->cells() as $c) {
            if ($c['verb'] !== self::g($spec, 'verb')) {
                continue;
            }
            $parts = [];
            foreach ($c['cell'] as $i => $x) {
                if ($i !== $k) {
                    $parts[] = (string)$x;
                }
            }
            $groups['k' . implode(',', $parts)][$c['cell'][$k]] = ['cell' => $c['cell'], 'p' => $c['p'], 'mass' => $c['mass'], 'harm' => $c['harm'], 'inGrant' => $c['inGrant']];
        }
        return [$dim, $k, $groups];
    }

    private static function gbar(mixed $spec, mixed $dim, int $pred, int $truth): float
    {
        $values = self::g($dim, 'values');
        $pv = $values[$pred];
        $tv = $values[$truth];
        if (self::g($pv, 'kind') !== 'exact') {
            return 0.0;
        }
        $labels = self::g(self::g($spec, 'cal'), 'labels');
        $pi = array_search(self::g($pv, 'value'), $labels, true);
        if ($pi === false) {
            return 0.0;
        }
        $ti = self::g($tv, 'kind') === 'exact' ? array_search(self::g($tv, 'value'), $labels, true) : false;
        if ($ti === false) {
            return 1.0;
        }
        return self::f(self::g(self::g($spec, 'cal'), 'gammaBar')[$ti][$pi]);
    }

    private static function sumGbar(mixed $spec, mixed $dim, array $A, int $t): float
    {
        $s = 0.0;
        foreach ($A as $p) {
            $s += self::gbar($spec, $dim, $p, $t);
        }
        return $s;
    }

    /**
     * R-hat of the learner's grant with classifier error folded in; other verbs contribute the ordinary sum.
     * @return array{total:int|float,perVerb:Obj}
     */
    public static function classifierAwareResidualRisk(mixed $l, array $specs): array
    {
        $per = new Obj();
        $specVerbs = array_map(static fn($s) => self::g($s, 'verb'), $specs);
        foreach ($l->cells() as $c) {
            if (in_array($c['verb'], $specVerbs, true)) {
                continue;
            }
            $prev = $per->has($c['verb']) ? $per->get($c['verb']) : 0;
            $per->set($c['verb'], $c['inGrant'] ? $prev + $c['mass'] * (1 - $c['p']) * $c['harm'] : $prev);
        }
        foreach ($specs as $spec) {
            [$dim, , $groups] = self::groupsOf($l, $spec);
            $r = 0.0;
            foreach ($groups as $g) {
                $A = [];
                foreach ($g as $i => $m) {
                    if ($m['inGrant']) {
                        $A[] = $i;
                    }
                }
                foreach ($g as $t => $m) {
                    $r += $m['mass'] * (1 - $m['p']) * $m['harm'] * min(1.0, self::sumGbar($spec, $dim, $A, $t));
                }
            }
            $per->set(self::g($spec, 'verb'), $r);
        }
        $total = 0;
        foreach ($per->keys() as $k) {
            $total += $per->get($k);
        }
        return ['total' => $total, 'perVerb' => $per];
    }

    /**
     * Cells admitted on a classifier label that go to JIT consent: some true label the grant does not admit at the same x has an
     * upper-bounded mislabel rate above gamma_max.
     * @return list<array{verb:mixed,cell:list<int>,flat:int}>
     */
    public static function classifierJitCells(mixed $l, mixed $spec, mixed $gammaMax): array
    {
        [$dim, , $groups] = self::groupsOf($l, $spec);
        $vs = null;
        foreach (self::g($l->omega, 'verbs') as $v) {
            if (self::g($v, 'verb') === self::g($spec, 'verb')) {
                $vs = $v;
                break;
            }
        }
        $gm = self::f($gammaMax);
        $out = [];
        foreach ($groups as $g) {
            $A = [];
            foreach ($g as $i => $m) {
                if ($m['inGrant']) {
                    $A[] = $i;
                }
            }
            if (count($A) === 0) {
                continue;
            }
            $worst = 0.0;
            foreach ($g as $t => $m) {
                if (!$m['inGrant'] && self::g(self::g($dim, 'values')[$t], 'kind') === 'exact') {
                    $worst = max($worst, min(1.0, self::sumGbar($spec, $dim, $A, $t)));
                }
            }
            if ($worst > $gm) {
                foreach ($A as $p) {
                    $cell = $g[$p]['cell'];
                    $out[] = ['verb' => self::g($spec, 'verb'), 'cell' => $cell, 'flat' => IntentOmega::encodeCell($vs, $cell)];
                }
            }
        }
        usort($out, static fn($a, $b) => $a['flat'] <=> $b['flat']);
        return $out;
    }
}
