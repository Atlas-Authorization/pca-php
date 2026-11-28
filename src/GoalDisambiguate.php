<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalExamples.php';
require_once __DIR__ . '/GoalFmt.php';
require_once __DIR__ . '/GoalNversion.php';

/**
 * Questions over the symmetric difference of competing readings and active disambiguation by version-space halving. A reading is
 * `{id, family, deterministic, goal, notes}`; the question options are `{ont, riskOf?, massOf?, budget?}` (an Obj or an assoc array;
 * `riskOf` and `massOf` are callables over an action). The answering function `ask(question)` returns 'allow' or 'deny'.
 */
final class GoalDisambiguate
{
    public const DEFAULT_RISK = ['read' => 1, 'reversible' => 2, 'external_send' => 8, 'irreversible' => 10];

    private static function j(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    /**
     * Math.log2 as the reference's engine computes it (the FreeBSD e_log2.c algorithm): a different library log2 can differ in the last
     * digit, which shows in the question scores. Defined for finite x > 0.
     */
    private static function log2(float $x): float
    {
        $ivln2hi = 1.44269504072144627571e+00;
        $ivln2lo = 1.67517131648865118353e-10;
        $wd = unpack('N2', pack('E', $x));
        $hx = $wd[1];
        $lx = $wd[2];
        $k = 0;
        if ($hx < 0x00100000) { // subnormal: scale up by 2^54
            $x *= 18014398509481984.0;
            $k -= 54;
            $wd = unpack('N2', pack('E', $x));
            $hx = $wd[1];
            $lx = $wd[2];
        }
        if ($hx === 0x3ff00000 && $lx === 0) {
            return 0.0;
        }
        $k += ($hx >> 20) - 1023;
        $hx &= 0x000fffff;
        $i = ($hx + 0x95f64) & 0x100000;
        $x = unpack('E', pack('N2', $hx | ($i ^ 0x3ff00000), $lx))[1]; // normalize x or x/2
        $k += $i >> 20;
        $y = (float)$k;
        $f = $x - 1.0;
        $hfsq = 0.5 * $f * $f;
        // k_log1p(f)
        $s = $f / (2.0 + $f);
        $z = $s * $s;
        $w = $z * $z;
        $t1 = $w * (3.999999999940941908e-01 + $w * (2.222219843214978396e-01 + $w * 1.531383769920937332e-01));
        $t2 = $z * (6.666666666666735130e-01 + $w * (2.857142874366239149e-01 + $w * (1.818357216161805012e-01 + $w * 1.479819860511658591e-01)));
        $r = $s * ($hfsq + ($t2 + $t1));
        $hi = $f - $hfsq;
        $hi = unpack('E', pack('N2', unpack('N', substr(pack('E', $hi), 0, 4))[1], 0))[1]; // low word to zero
        $lo = ($f - $hi) - $hfsq + $r;
        $valHi = $hi * $ivln2hi;
        $valLo = ($lo + $hi) * $ivln2lo + $lo * $ivln2hi;
        $w = $y + $valHi;
        $valLo += ($y - $w) + $valHi;
        $valHi = $w;
        return $valLo + $valHi;
    }

    private static function h2(float $p): float
    {
        return $p <= 0 || $p >= 1 ? 0.0 : -(($p * self::log2($p)) + ((1 - $p) * self::log2(1 - $p)));
    }

    /** Whether goal `$g` allows the witness `{act, prior, rels}` after replaying its prior actions. */
    public static function allowsWitness(mixed $g, mixed $ont, mixed $w): bool
    {
        $hist = GoalExamples::replay($g, $ont, self::j($w, 'prior'), self::j($w, 'rels'));
        return GoalExamples::decideCase($g, $ont, Obj::of(['act' => self::j($w, 'act'), 'hist' => $hist, 'rels' => self::j($w, 'rels')]))->get('decision') === 'allow';
    }

    /** Candidate witness actions: decision-cell representatives of the joint space plus every reading's cap sequences. @return list<Obj> */
    private static function witnesses(array $readings, mixed $ont): array
    {
        $goals = array_map(static fn($r) => self::j($r, 'goal'), $readings);
        $out = [];
        foreach (GoalExamples::cells(GoalExamples::buildSpace($goals))->get('cases') as $c) {
            $out[] = Obj::of(['act' => $c->get('act'), 'prior' => [], 'rels' => $c->get('rels')]);
        }
        foreach ($readings as $r) {
            foreach (GoalExamples::boundaryExamples(self::j($r, 'goal'), Obj::of(['ont' => $ont, 'extra' => $goals]))->get('examples') as $e) {
                if ($e->get('kind') === 'cap_sequence') {
                    $out[] = Obj::of(['act' => $e->get('act'), 'prior' => array_map(static fn($a) => $a->get('act'), $e->get('hist')->get('adms')), 'rels' => $e->get('rels')]);
                }
            }
        }
        return $out;
    }

    /** Questions ranked by H2(vote) x risk x mass (best first). @return list<Obj> */
    public static function questions(mixed $readings, mixed $opts): array
    {
        $readings = AnalyzerJs::reqList($readings);
        $ont = Js::opt($opts, 'ont');
        $k = count($readings);
        $cls = [];
        foreach (AnalyzerJs::reqList(self::j($ont, 'verbs')) as $v) {
            $cls['k' . AnalyzerJs::jsStr(self::j($v, 'verb'))] = self::j($v, 'cls');
        }
        $riskOf = Js::opt($opts, 'riskOf') ?? static function (mixed $a) use ($cls): float {
            $c = $cls['k' . AnalyzerJs::jsStr(self::j($a, 'verb'))] ?? '';
            return (float)(is_string($c) ? (self::DEFAULT_RISK[$c] ?? 10) : 10);
        };
        $massOf = Js::opt($opts, 'massOf');
        $out = [];
        $seen = [];
        foreach (self::witnesses($readings, $ont) as $w) {
            $yes = [];
            foreach ($readings as $r) {
                if (self::allowsWitness(self::j($r, 'goal'), $ont, $w)) {
                    $yes[] = self::j($r, 'id');
                }
            }
            if ($yes === [] || count($yes) === $k) {
                continue;
            }
            $n = count($w->get('prior'));
            $qid = Js::stringify([$w->get('act'), $n]);
            if (isset($seen['k' . $qid])) {
                continue;
            }
            $seen['k' . $qid] = true;
            $notAllow = [];
            foreach ($readings as $r) {
                if (!AnalyzerJs::includes($yes, self::j($r, 'id'))) {
                    $notAllow[] = self::j($r, 'id');
                }
            }
            $act = $w->get('act');
            $mass = $massOf === null ? 1 : (float)Js::num($massOf($act));
            $risk = $riskOf($act);
            $out[] = Obj::of(['id' => $qid, 'act' => $act, 'prior' => $w->get('prior'), 'rels' => $w->get('rels'), 'allow' => $yes, 'notAllow' => $notAllow,
                'text' => 'Should this be allowed: ' . GoalFmt::fmtAct($act) . ($n > 0 ? " (after $n earlier identical action(s))" : '') . '?',
                'score' => self::h2(count($yes) / $k) * (Js::isNum($risk) ? (float)Js::num($risk) : (float)$risk) * $mass]);
        }
        return GoalJs::stableSort($out, static function (Obj $a, Obj $b): int {
            $d = $b->get('score') - $a->get('score');
            if ($d != 0.0 && !is_nan($d)) {
                return $d < 0 ? -1 : 1;
            }
            return AnalyzerJs::u16cmp($a->get('id'), $b->get('id')) < 0 ? -1 : 1;
        });
    }

    /** Fraction of witness cells on which the readings do not all agree on Allow. */
    public static function disagreementMass(mixed $readings, mixed $ont): int|float
    {
        $readings = AnalyzerJs::reqList($readings);
        $w = self::witnesses($readings, $ont);
        if ($w === []) {
            return 0;
        }
        $split = 0;
        foreach ($w as $x) {
            $n = 0;
            foreach ($readings as $r) {
                if (self::allowsWitness(self::j($r, 'goal'), $ont, $x)) {
                    $n++;
                }
            }
            if ($n > 0 && $n < count($readings)) {
                $split++;
            }
        }
        return $split / count($w);
    }

    /**
     * Active disambiguation by version-space halving over the finite class of readings: every question strictly shrinks the class, so at
     * most k-1 questions. Realizability (assumption): the principal's intent is one of the readings.
     */
    public static function disambiguate(mixed $readings, callable $ask, mixed $opts): Obj
    {
        $readings = AnalyzerJs::reqList($readings);
        $ont = Js::opt($opts, 'ont');
        $budget = Js::opt($opts, 'budget');
        $budget = $budget === null ? count($readings) : Js::num($budget);
        $active = $readings;
        $asked = [];
        while (count($active) > 1 && count($asked) < $budget) {
            $qs = self::questions($active, $opts);
            if ($qs === []) {
                break; // the survivors agree on every witness cell
            }
            $q = $qs[0];
            $asked[] = $q;
            $ans = $ask($q);
            $next = [];
            foreach ($active as $r) {
                if (self::allowsWitness(self::j($r, 'goal'), $ont, $q) === ($ans === 'allow')) {
                    $next[] = $r;
                }
            }
            $active = $next;
        }
        $mass = self::disagreementMass($active, $ont);
        $g = GoalNversion::meet(array_map(static fn($r) => self::j($r, 'goal'), $active));
        $ids = array_map(static fn($r) => self::j($r, 'id'), $active);
        if ($mass > 0) {
            $hole = Obj::of(['hid' => 'budget', 'q' => 'Question budget exhausted with disagreement left.', 'domain' => [], 'affects' => [], 'global' => true]);
            $holes = GoalJs::stableSort([...AnalyzerJs::reqList(self::j($g, 'holes')), $hole], static fn($a, $b) => AnalyzerJs::u16cmp(self::j($a, 'hid'), self::j($b, 'hid')));
            $g2 = AnalyzerJs::copy($g);
            $g2->set('holes', $holes);
            return Obj::of(['status' => 'budget_exhausted', 'goal' => $g2, 'asked' => $asked, 'residualMass' => $mass, 'remaining' => $ids]);
        }
        return Obj::of(['status' => 'resolved', 'goal' => $g, 'asked' => $asked, 'residualMass' => 0, 'remaining' => $ids]);
    }
}
