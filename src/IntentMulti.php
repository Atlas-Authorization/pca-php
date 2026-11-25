<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/IntentMapKit.php';

/**
 * Multi-principal intent: aggregation rules (unanimity, quorum, weighted, vetoers), the exact joint-acceptance DP and the common
 * refinement of several outcome spaces. Rules are Obj / assoc arrays with the reference's names; a rule in normal form is the assoc array
 * {weights, threshold, veto}. Error messages are the reference's.
 */
final class IntentMulti
{
    public const PPM = 1000000;
    private const SEV = ['reversible', 'rate_limited', 'irreversible'];

    public static function ppm(float $x): int
    {
        return (int)floor($x * self::PPM + 0.5);
    }

    /** o.k with the reference's TypeError on null / undefined. */
    private static function member(mixed $o, string $k): mixed
    {
        if ($o === null) {
            throw new \TypeError("Cannot read properties of null (reading '$k')");
        }
        return Js::opt($o, $k);
    }

    private static function isInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    /**
     * A rule in normal form.
     * @param list<string> $refs
     * @return array{weights:list<int>,threshold:int,veto:list<bool>}
     */
    public static function normalizeRule(mixed $rule, array $refs): array
    {
        $vs = self::member($rule, 'vetoers');
        if ($vs === null) {
            $vetoers = [];
        } elseif (is_array($vs) && array_is_list($vs)) {
            $vetoers = $vs;
        } elseif (is_string($vs)) {
            $vetoers = mb_str_split($vs);
        } else {
            throw new \TypeError('rule.vetoers is not iterable');
        }
        foreach ($vetoers as $v) {
            if (!in_array($v, $refs, true)) {
                throw new \InvalidArgumentException('aggregateIntentMaps: vetoer ' . Js::str($v) . ' is not one of the maps');
            }
        }
        $veto = array_map(static fn($r) => in_array($r, $vetoers, true), $refs);
        $kind = self::member($rule, 'kind');
        if ($kind === 'unanimity') {
            return ['weights' => array_fill(0, count($refs), 1), 'threshold' => count($refs), 'veto' => $veto];
        }
        if ($kind === 'quorum') {
            $k = self::member($rule, 'k');
            if (!(self::isInt($k) && Js::num($k) >= 1 && Js::num($k) <= count($refs))) {
                throw new \InvalidArgumentException('aggregateIntentMaps: quorum k must be an integer in [1, ' . count($refs) . ']');
            }
            return ['weights' => array_fill(0, count($refs), 1), 'threshold' => (int)Js::num($k), 'veto' => $veto];
        }
        $wmap = self::member($rule, 'weights');
        $wAbsent = $wmap === null && !Js::has($rule, 'weights'); // an absent member reads as undefined, an explicit null as null
        $weights = [];
        foreach ($refs as $r) {
            if ($wAbsent) {
                throw new \TypeError("Cannot read properties of undefined (reading '" . Js::str($r) . "')");
            }
            $weights[] = self::member($wmap, $r);
        }
        foreach ($weights as $w) {
            if (!(self::isInt($w) && Js::num($w) >= 0)) {
                throw new \InvalidArgumentException('aggregateIntentMaps: every principal needs a non-negative integer weight');
            }
        }
        $weights = array_map(static fn($w) => (int)Js::num($w), $weights);
        $W = array_sum($weights);
        $th = self::member($rule, 'threshold');
        if (!(self::isInt($th) && Js::num($th) >= 1 && Js::num($th) <= $W)) {
            throw new \InvalidArgumentException("aggregateIntentMaps: threshold must be an integer in [1, $W]");
        }
        return ['weights' => $weights, 'threshold' => (int)Js::num($th), 'veto' => $veto];
    }

    /** Principals that bound the joint grant: explicit vetoers plus implicit ones (T > W - w_i). @return list<string> */
    public static function effectiveVetoers(mixed $rule, array $refs): array
    {
        $n = self::normalizeRule($rule, $refs);
        $W = array_sum($n['weights']);
        $out = [];
        foreach ($refs as $i => $r) {
            if ($n['veto'][$i] || $n['threshold'] > $W - $n['weights'][$i]) {
                $out[] = $r;
            }
        }
        return $out;
    }

    /** Vetoers must admit; the admitting weight must reach the threshold. @param list<bool> $ins */
    public static function ruleAdmits(array $n, array $ins): bool
    {
        $s = 0;
        foreach ($ins as $i => $in) {
            if ($n['veto'][$i] && !$in) {
                return false;
            }
            if ($in) {
                $s += $n['weights'][$i];
            }
        }
        return $s >= $n['threshold'];
    }

    /** P(rule admits) with independent Bernoulli(p_i) acceptances: DP over the (capped) admitting weight. @param list<float> $ps */
    public static function jointAcceptance(array $n, array $ps): float
    {
        $th = $n['threshold'];
        $dist = array_fill(0, $th + 1, 0.0);
        $dist[0] = 1.0;
        foreach ($ps as $i => $p) {
            $nxt = array_fill(0, $th + 1, 0.0);
            $w = $n['weights'][$i];
            for ($s = 0; $s <= $th; $s++) {
                $m = $dist[$s];
                if ($m == 0) {
                    continue;
                }
                $t = min($th, $s + $w);
                $nxt[$t] = $nxt[$t] + $m * $p;
                if (!$n['veto'][$i]) {
                    $nxt[$s] = $nxt[$s] + $m * (1 - $p);
                }
            }
            $dist = $nxt;
        }
        return $dist[$th];
    }

    // ---- cross-org: common refinement ----------------------------------------------------------------------------------------

    private static function sev(mixed $r): int
    {
        $i = array_search($r, self::SEV, true);
        return $i === false ? -1 : $i;
    }

    private static function numEq(mixed $a, mixed $b): bool
    {
        return Js::num($a) === Js::num($b);
    }

    private static function mergeDim(mixed $a, mixed $b): array
    {
        $path = Js::opt($a, 'path');
        if (Js::opt($a, 'kind') !== Js::opt($b, 'kind')) {
            throw new \InvalidArgumentException('commonRefinement: ' . Js::str($path) . ' is numeric in one ' . "\u{03A9}" . ' and categorical in another');
        }
        if (Js::opt($a, 'kind') === 'num') {
            if (!self::numEq(Js::opt($a, 'lo'), Js::opt($b, 'lo')) || !self::numEq(Js::opt($a, 'hi'), Js::opt($b, 'hi'))) {
                throw new \InvalidArgumentException('commonRefinement: ' . Js::str($path) . ' has different domains ([' . Js::str(Js::opt($a, 'lo')) . ', ' . Js::str(Js::opt($a, 'hi'))
                    . '] vs [' . Js::str(Js::opt($b, 'lo')) . ', ' . Js::str(Js::opt($b, 'hi')) . '])');
            }
            $cuts = [];
            foreach ([...Js::opt($a, 'cuts'), ...Js::opt($b, 'cuts')] as $c) {
                $seen = false;
                foreach ($cuts as $x) {
                    if (self::numEq($x, $c)) {
                        $seen = true;
                        break;
                    }
                }
                if (!$seen) {
                    $cuts[] = $c;
                }
            }
            usort($cuts, static fn($x, $y) => Js::num($x) <=> Js::num($y));
            $out = ['kind' => 'num', 'path' => $path, 'lo' => Js::opt($a, 'lo'), 'hi' => Js::opt($a, 'hi')];
            if (Js::opt($a, 'dist') !== null) {
                $out['dist'] = Js::opt($a, 'dist');
            }
            $out['cuts'] = $cuts;
            return $out;
        }
        $ex = [];
        $pre = [];
        foreach ([...Js::opt($a, 'values'), ...Js::opt($b, 'values')] as $v) {
            $val = Js::opt($v, 'value');
            if (Js::opt($v, 'kind') === 'exact' && !in_array($val, $ex, true)) {
                $ex[] = $val;
            } elseif (Js::opt($v, 'kind') === 'prefix' && !in_array($val, $pre, true)) {
                $pre[] = $val;
            }
        }
        $key = static fn(string $s): string => AnalyzerJs::u16key($s);
        usort($ex, static fn($x, $y) => strcmp($key($x), $key($y)));
        usort($pre, static fn($x, $y) => strcmp($key($x), $key($y)));
        $values = [];
        foreach ($ex as $v) {
            $values[] = ['kind' => 'exact', 'value' => $v];
        }
        foreach ($pre as $v) {
            $values[] = ['kind' => 'prefix', 'value' => $v];
        }
        $values[] = ['kind' => 'other', 'value' => "\u{22A5}"];
        return ['kind' => 'cat', 'path' => $path, 'values' => $values];
    }

    /**
     * The union of the verbs; per verb the union of dimensions; per numeric dimension the union of cuts (domains must agree); per
     * categorical dimension the union of the named values.
     * @param list<mixed> $omegas
     */
    public static function commonRefinement(array $omegas): Obj
    {
        $byVerb = [];
        $approx = [];
        foreach ($omegas as $o) {
            foreach (Js::opt($o, 'approximate') as $x) {
                if (!in_array($x, $approx, true)) {
                    $approx[] = $x;
                }
            }
            foreach (Js::opt($o, 'verbs') as $vs) {
                $k = 'k' . Js::opt($vs, 'verb');
                if (!isset($byVerb[$k])) {
                    $byVerb[$k] = ['verb' => Js::opt($vs, 'verb'), 'reversibility' => Js::opt($vs, 'reversibility'), 'weight' => 0,
                        'dims' => array_map(static fn($d) => WalletOmega::plain($d), Js::opt($vs, 'dims'))];
                    continue;
                }
                $cur = &$byVerb[$k];
                if (self::sev(Js::opt($vs, 'reversibility')) > self::sev($cur['reversibility'])) {
                    $cur['reversibility'] = Js::opt($vs, 'reversibility');
                }
                foreach (Js::opt($vs, 'dims') as $d) {
                    $i = -1;
                    foreach ($cur['dims'] as $j => $x) {
                        if (Js::opt($x, 'path') === Js::opt($d, 'path')) {
                            $i = $j;
                            break;
                        }
                    }
                    if ($i < 0) {
                        $cur['dims'][] = WalletOmega::plain($d);
                    } else {
                        $cur['dims'][$i] = self::mergeDim($cur['dims'][$i], $d);
                    }
                }
                unset($cur);
            }
        }
        $verbs = array_values($byVerb);
        usort($verbs, static fn($a, $b) => strcmp(AnalyzerJs::u16key($a['verb']), AnalyzerJs::u16key($b['verb'])));
        foreach ($verbs as &$v) {
            usort($v['dims'], static fn($a, $b) => strcmp(AnalyzerJs::u16key(Js::opt($a, 'path')), AnalyzerJs::u16key(Js::opt($b, 'path'))));
            $v['weight'] = 1 / count($verbs);
        }
        unset($v);
        usort($approx, static fn($a, $b) => strcmp(AnalyzerJs::u16key($a), AnalyzerJs::u16key($b)));
        return IntentMapKit::obj(['v' => 1, 'verbs' => $verbs, 'approximate' => $approx]);
    }
}
