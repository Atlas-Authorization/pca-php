<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/WalletOmega.php';
require_once __DIR__ . '/IntentPolicy.php';
require_once __DIR__ . '/IntentRegion.php';

/** The per-verb model of the learner: hypothesis tables, prior / posterior weights and per-cell state. */
final class IntentLearnerVerbModel
{
    public mixed $vs;
    /** @var list<int> */
    public array $nChoice = [];
    /** @var list<string> byte tables (one per dimension) */
    public array $contains = [];
    /** @var list<int> */
    public array $nCellsD = [];
    public int $nh = 0;
    /** @var list<int> */
    public array $choice = [];
    /** @var list<string>|null hypothesis masks (index 0 = the empty hypothesis) */
    public ?array $member = null;
    /** @var list<int>|null */
    public ?array $complexity = null;
    /** @var list<float> */
    public array $prior = [];
    /** @var list<float> */
    public array $w = [];
    /** @var list<int> */
    public array $err = [];
    public int $nCells = 0;
    /** @var list<int> */
    public array $cellIdx = [];
    /** @var list<float> */
    public array $mass = [];
    /** @var list<float> */
    public array $harm = [];
    /** @var list<float> */
    public array $p = [];
    /** @var list<int> */
    public array $veto = [];
    /** @var list<int> */
    public array $seen = [];
    public bool $dirty = true;
}

/**
 * Elicitation as learning: the exact Bayesian posterior over a per-verb hypothesis class (boxes, unions of boxes, decision lists),
 * the conservative grant it implies, the next question, the audit round and the synthesis of the grant as predicates. Omegas,
 * verb spaces, options, observations and questions are Obj / assoc arrays with the reference's field names (numbers as plain
 * ints / floats: WalletOmega::plain); results are assoc arrays. The posterior arithmetic keeps the reference's operation order
 * (log2 is log(x) / ln 2, so entropies can differ from Math.log2 in the last ulp). Needs IntentPolicy::admitter(policy)->admits(vs, outcome)
 * and IntentRegion::regionCells(vs, region, mode).
 */
final class IntentLearner
{
    private const ORDER = ['reversible', 'rate_limited', 'irreversible'];

    public mixed $omega;
    public float $eta;
    public float $etaPos;
    public float $etaNeg;
    public float $tau;
    public string $strategy;
    public mixed $hypothesisClass;
    public ?float $agnosticSlack = null;
    /** The serialisable parameters an Intent Map builder attached (IntentMapKit::createLearner). */
    public mixed $mapParams = null;
    /** @var list<array<string,mixed>> */
    public array $observations = [];
    private bool $noisy;
    private mixed $opts;
    private ?HarmModel $harmModel;
    /** @var list<IntentLearnerVerbModel> */
    private array $models = [];

    // ---- helpers -------------------------------------------------------------------------------------------------------------

    private static function g(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    /** JS `o.k ?? d`. */
    private static function dflt(mixed $o, string $k, mixed $d): mixed
    {
        $v = Js::opt($o, $k);
        return $v === null ? $d : $v;
    }

    private static function f(mixed $x): float
    {
        $v = Js::num($x);
        return $v ?? NAN;
    }

    private static function isInteger(mixed $x): bool
    {
        $v = Js::num($x);
        return $v !== null && is_finite($v) && $v == floor($v);
    }

    /** JS `x || 1` over a number. */
    private static function or1(float $x): float
    {
        return ($x == $x && $x != 0) ? $x : 1.0;
    }

    private static function log2(float $x): float
    {
        return log($x) / M_LN2;
    }

    public static function hypothesisClassName(mixed $h): string
    {
        $k = self::g($h, 'kind');
        if ($k === 'box') {
            return 'per-verb-box/v1';
        }
        if ($k === 'union') {
            return 'per-verb-union/v1';
        }
        return self::dflt($h, 'conditions', 'box') === 'atomic' ? 'per-verb-decision-list/v1' : 'per-verb-decision-list/v2';
    }

    private static function binEnt(float $p): float
    {
        if ($p <= 0 || $p >= 1) {
            return 0.0;
        }
        return -($p * self::log2($p) + (1 - $p) * self::log2(1 - $p));
    }

    // ---- hypothesis enumeration --------------------------------------------------------------------------------------------

    /** @return array{0:list<string>,1:list<int>} */
    private static function buildBoxTables(mixed $vs, array $nCellsD): array
    {
        $contains = [];
        $nChoice = [];
        foreach (self::g($vs, 'dims') as $k => $d) {
            $n = $nCellsD[$k];
            if (self::g($d, 'kind') === 'num') {
                $ch = [];
                for ($i = 0; $i < $n; $i++) {
                    for ($j = $i; $j < $n; $j++) {
                        $ch[] = [$i, $j];
                    }
                }
                $t = str_repeat("\0", count($ch) * $n);
                foreach ($ch as $c => [$i, $j]) {
                    for ($x = $i; $x <= $j; $x++) {
                        $t[$c * $n + $x] = "\1";
                    }
                }
                $contains[] = $t;
                $nChoice[] = count($ch);
            } else {
                if ($n > 20) {
                    throw new \InvalidArgumentException('pca-intent: categorical dimension ' . Js::str(self::g($d, 'path')) . " has $n values (max 20 for exact enumeration)");
                }
                $m = (1 << $n) - 1;
                $t = str_repeat("\0", $m * $n);
                for ($mask = 1; $mask <= $m; $mask++) {
                    for ($x = 0; $x < $n; $x++) {
                        if ($mask & (1 << $x)) {
                            $t[($mask - 1) * $n + $x] = "\1";
                        }
                    }
                }
                $contains[] = $t;
                $nChoice[] = $m;
            }
        }
        return [$contains, $nChoice];
    }

    /** @return list<string> */
    private static function boxMasks(mixed $vs, int $nCells, array $cellIdx, array $nCellsD, array $contains, array $nChoice, float $cap): array
    {
        $D = count(self::g($vs, 'dims'));
        $boxes = 1;
        foreach ($nChoice as $c) {
            $boxes *= $c;
        }
        if (!($boxes <= $cap)) {
            throw new \InvalidArgumentException("pca-intent: $boxes boxes for " . Js::str(self::g($vs, 'verb')) . ' exceed the enumeration cap; coarsen the cuts');
        }
        $out = [];
        $cur = array_fill(0, $D, 0);
        for ($b = 0; $b < $boxes; $b++) {
            $mask = str_repeat("\0", $nCells);
            for ($c = 0; $c < $nCells; $c++) {
                $inside = true;
                for ($d = 0; $d < $D && $inside; $d++) {
                    if ($contains[$d][$cur[$d] * $nCellsD[$d] + $cellIdx[$c * $D + $d]] === "\0") {
                        $inside = false;
                    }
                }
                if ($inside) {
                    $mask[$c] = "\1";
                }
            }
            $out[] = $mask;
            for ($d = $D - 1; $d >= 0; $d--) {
                $cur[$d]++;
                if ($cur[$d] < $nChoice[$d]) {
                    break;
                }
                $cur[$d] = 0;
            }
        }
        return $out;
    }

    /** @return array{0:list<string>,1:list<int>} */
    private static function enumerateUnions(array $boxes, int $k, float $cap, mixed $verb): array
    {
        $seen = [];
        $sets = [];
        $complexity = [];
        $frontier = [];
        foreach ($boxes as $b) {
            if (isset($seen[$b])) {
                continue;
            }
            $seen[$b] = count($sets);
            $sets[] = $b;
            $complexity[] = 1;
            $frontier[] = $b;
        }
        $work = 0;
        for ($level = 2; $level <= $k; $level++) {
            $nxt = [];
            foreach ($frontier as $s) {
                foreach ($boxes as $b) {
                    $work++;
                    if (!($work <= $cap)) {
                        throw new \InvalidArgumentException("pca-intent: the union-of-$k-boxes class for " . Js::str($verb) . ' exceeds the enumeration cap; coarsen the cuts or lower k');
                    }
                    $u = $s | $b;
                    if (isset($seen[$u])) {
                        continue;
                    }
                    $seen[$u] = count($sets);
                    $sets[] = $u;
                    $complexity[] = $level;
                    $nxt[] = $u;
                }
            }
            $frontier = $nxt;
        }
        return [$sets, $complexity];
    }

    /** @return list<string> */
    private static function atomicTests(mixed $vs, int $nCells, array $cellIdx, array $nCellsD): array
    {
        $D = count(self::g($vs, 'dims'));
        $tests = [];
        $add = static function (int $k, \Closure $pred) use (&$tests, $nCells, $cellIdx, $D): void {
            $m = str_repeat("\0", $nCells);
            $any = false;
            $all = true;
            for ($c = 0; $c < $nCells; $c++) {
                if ($pred($cellIdx[$c * $D + $k])) {
                    $m[$c] = "\1";
                    $any = true;
                } else {
                    $all = false;
                }
            }
            if ($any && !$all) {
                $tests[] = $m;
            }
        };
        foreach (self::g($vs, 'dims') as $k => $d) {
            $n = $nCellsD[$k];
            if (self::g($d, 'kind') === 'num') {
                for ($i = 0; $i < $n - 1; $i++) {
                    $add($k, static fn($x) => $x <= $i);
                }
                for ($i = 1; $i < $n; $i++) {
                    $add($k, static fn($x) => $x >= $i);
                }
                if ($n > 2) {
                    for ($i = 1; $i < $n - 1; $i++) {
                        $add($k, static fn($x) => $x === $i);
                    }
                }
            } else {
                for ($i = 0; $i < $n; $i++) {
                    $add($k, static fn($x) => $x === $i);
                }
            }
        }
        return self::dedupMasks($tests);
    }

    /** @return list<string> */
    private static function dedupMasks(array $masks): array
    {
        $seen = [];
        $out = [];
        foreach ($masks as $t) {
            if (isset($seen[$t])) {
                continue;
            }
            $seen[$t] = true;
            $out[] = $t;
        }
        return $out;
    }

    /** @return array{0:list<string>,1:list<int>} */
    private static function enumerateDecisionLists(array $tests, int $nCells, int $L, float $cap, mixed $verb): array
    {
        $seen = [];
        $sets = [];
        $complexity = [];
        $emit = static function (string $acc, string $decided, int $rules) use (&$seen, &$sets, &$complexity, $nCells): void {
            foreach ([0, 1] as $dflt) {
                $s = str_repeat("\0", $nCells);
                $any = false;
                for ($c = 0; $c < $nCells; $c++) {
                    $v = $decided[$c] !== "\0" ? $acc[$c] : ($dflt === 1 ? "\1" : "\0");
                    $s[$c] = $v;
                    if ($v !== "\0") {
                        $any = true;
                    }
                }
                if (!$any || isset($seen[$s])) {
                    continue;
                }
                $seen[$s] = count($sets);
                $sets[] = $s;
                $complexity[] = max(1, $rules);
            }
        };
        $zero = str_repeat("\0", $nCells);
        $frontier = [[$zero, $zero]]; // (decided, acc)
        $emit($zero, $zero, 0);
        $work = 0;
        for ($depth = 1; $depth <= $L; $depth++) {
            $states = [];
            foreach ($frontier as [$stDecided, $stAcc]) {
                foreach ($tests as $t) {
                    foreach ([0, 1] as $label) {
                        $work++;
                        if (!($work <= $cap)) {
                            throw new \InvalidArgumentException("pca-intent: the decision-list class (\u{2264} $L rules) for " . Js::str($verb) . ' exceeds the enumeration cap');
                        }
                        $decided = str_repeat("\0", $nCells);
                        $acc = str_repeat("\0", $nCells);
                        $fresh = false;
                        for ($c = 0; $c < $nCells; $c++) {
                            if ($stDecided[$c] !== "\0") {
                                $decided[$c] = "\1";
                                $acc[$c] = $stAcc[$c];
                            } elseif ($t[$c] !== "\0") {
                                $decided[$c] = "\1";
                                $acc[$c] = $label === 1 ? "\1" : "\0";
                                $fresh = true;
                            }
                        }
                        if (!$fresh) {
                            continue;
                        }
                        $key = $decided . $acc;
                        if (!isset($states[$key])) {
                            $states[$key] = [$decided, $acc];
                        }
                    }
                }
            }
            $frontier = array_values($states);
            foreach ($frontier as [$decided, $acc]) {
                $emit($acc, $decided, $depth);
            }
        }
        return [$sets, $complexity];
    }

    private static function buildVerbModel(mixed $vs, mixed $opts, ?HarmModel $harm): IntentLearnerVerbModel
    {
        $dims = self::g($vs, 'dims');
        $D = count($dims);
        $nCellsD = [];
        foreach ($dims as $d) {
            $nCellsD[] = WalletOmega::cellCount($d);
        }
        [$contains, $nChoice] = self::buildBoxTables($vs, $nCellsD);
        $nCells = WalletOmega::verbCellCount($vs);
        $cellIdx = array_fill(0, $nCells * $D, 0);
        $mass = array_fill(0, $nCells, 0.0);
        $hm = array_fill(0, $nCells, 0.0);
        for ($c = 0; $c < $nCells; $c++) {
            $idx = WalletOmega::decodeCell($vs, $c);
            for ($d = 0; $d < $D; $d++) {
                $cellIdx[$c * $D + $d] = $idx[$d];
            }
            $s = WalletOmega::cellStats($vs, $idx, $harm);
            $mass[$c] = (float)$s['mass'];
            $hm[$c] = (float)$s['harm'];
        }
        $hc = self::dflt($opts, 'hypothesisClass', ['kind' => 'box']);
        $maxH = self::f(self::g($opts, 'maxHypotheses'));
        $maxE = self::f(self::g($opts, 'maxEnumeration'));
        $choice = [0];
        $member = null;
        $complexity = null;
        $kind = self::g($hc, 'kind');
        if ($kind === 'box') {
            $boxes = 1;
            foreach ($nChoice as $c) {
                $boxes *= $c;
            }
            if (!($boxes + 1 <= $maxH)) {
                throw new \InvalidArgumentException('pca-intent: |\u{0398}_' . Js::str(self::g($vs, 'verb')) . '| = ' . ($boxes + 1) . ' exceeds maxHypotheses ' . Js::str(self::g($opts, 'maxHypotheses')) . '; coarsen the cuts');
            }
            $nh = $boxes + 1;
            $choice = array_fill(0, max(1, $boxes * $D), 0);
            $cur = array_fill(0, $D, 0);
            for ($h = 0; $h < $boxes; $h++) {
                for ($d = 0; $d < $D; $d++) {
                    $choice[$h * $D + $d] = $cur[$d];
                }
                for ($d = $D - 1; $d >= 0; $d--) {
                    $cur[$d]++;
                    if ($cur[$d] < $nChoice[$d]) {
                        break;
                    }
                    $cur[$d] = 0;
                }
            }
        } else {
            if ($kind === 'union') {
                $k = self::g($hc, 'k');
                if (!(self::isInteger($k) && self::f($k) >= 1)) {
                    throw new \InvalidArgumentException('pca-intent: union class needs an integer k >= 1');
                }
                $boxM = self::boxMasks($vs, $nCells, $cellIdx, $nCellsD, $contains, $nChoice, $maxE);
                [$sets, $cx] = self::enumerateUnions($boxM, (int)self::f($k), $maxE, self::g($vs, 'verb'));
            } else {
                $mr = self::g($hc, 'maxRules');
                if (!(self::isInteger($mr) && self::f($mr) >= 1)) {
                    throw new \InvalidArgumentException('pca-intent: decision-list class needs an integer maxRules >= 1');
                }
                $cond = self::dflt($hc, 'conditions', 'box');
                if ($cond !== 'box' && $cond !== 'atomic') {
                    throw new \InvalidArgumentException("pca-intent: decision-list conditions must be 'box' or 'atomic'");
                }
                $tests = $cond === 'atomic'
                    ? self::atomicTests($vs, $nCells, $cellIdx, $nCellsD)
                    : self::dedupMasks(self::boxMasks($vs, $nCells, $cellIdx, $nCellsD, $contains, $nChoice, $maxE));
                [$sets, $cx] = self::enumerateDecisionLists($tests, $nCells, (int)self::f($mr), $maxE, self::g($vs, 'verb'));
            }
            if (!(count($sets) + 1 <= $maxH)) {
                throw new \InvalidArgumentException('pca-intent: |\u{0398}_' . Js::str(self::g($vs, 'verb')) . '| = ' . (count($sets) + 1) . ' exceeds maxHypotheses ' . Js::str(self::g($opts, 'maxHypotheses')) . '; coarsen the cuts');
            }
            $nh = count($sets) + 1;
            $member = [str_repeat("\0", $nCells), ...$sets];
            $complexity = [0, ...$cx];
        }
        $m = new IntentLearnerVerbModel();
        $m->vs = $vs;
        $m->nChoice = $nChoice;
        $m->contains = $contains;
        $m->nCellsD = $nCellsD;
        $m->nh = $nh;
        $m->choice = $choice;
        $m->member = $member;
        $m->complexity = $complexity;
        $m->prior = array_fill(0, $nh, 0.0);
        $m->w = array_fill(0, $nh, 0.0);
        $m->err = array_fill(0, $nh, 0);
        $m->nCells = $nCells;
        $m->cellIdx = $cellIdx;
        $m->mass = $mass;
        $m->harm = $hm;
        $m->p = array_fill(0, $nCells, 0.0);
        $m->veto = array_fill(0, $nCells, 0);
        $m->seen = array_fill(0, $nCells, 0);
        $m->dirty = true;
        return $m;
    }

    /** Does hypothesis h (>= 1) contain flat cell c? */
    private static function holds(IntentLearnerVerbModel $m, int $h, int $c): bool
    {
        if ($m->member !== null) {
            return $m->member[$h][$c] === "\1";
        }
        $D = count(self::g($m->vs, 'dims'));
        $base = ($h - 1) * $D;
        for ($d = 0; $d < $D; $d++) {
            $n = $m->nCellsD[$d];
            if ($m->contains[$d][$m->choice[$base + $d] * $n + $m->cellIdx[$c * $D + $d]] === "\0") {
                return false;
            }
        }
        return true;
    }

    /**
     * The non-empty hypotheses of Theta_v for a class as cell masks over the verb's flat cells (lists of 0 / 1), each with its Occam complexity.
     * @return array{sets:list<list<int>>,complexity:list<int>}
     */
    public static function hypothesisCellSets(mixed $vs, mixed $hypothesisClass = null, mixed $caps = null): array
    {
        $o = ['maxHypotheses' => 400000, 'maxEnumeration' => 4000000];
        foreach (['maxHypotheses', 'maxEnumeration'] as $k) {
            $v = self::g($caps, $k);
            if ($v !== null) {
                $o[$k] = $v;
            }
        }
        $o['hypothesisClass'] = $hypothesisClass ?? ['kind' => 'box'];
        $m = self::buildVerbModel($vs, $o, WalletOmega::defaultHarm());
        $sets = [];
        $complexity = [];
        for ($h = 1; $h < $m->nh; $h++) {
            $s = [];
            for ($c = 0; $c < $m->nCells; $c++) {
                $s[] = self::holds($m, $h, $c) ? 1 : 0;
            }
            $sets[] = $s;
            $complexity[] = $m->complexity !== null ? $m->complexity[$h] : 1;
        }
        return ['sets' => $sets, 'complexity' => $complexity];
    }

    private static function applyMonotonePrior(IntentLearnerVerbModel $m, mixed $mono): void
    {
        $off = self::f(self::dflt($mono, 'offMass', 0));
        if (!($off >= 0 && $off <= 1)) {
            throw new \InvalidArgumentException('pca-intent: monotone.offMass must be in [0, 1]');
        }
        $dims = self::g($m->vs, 'dims');
        $D = count($dims);
        $paths = self::g($mono, 'paths');
        $ks = [];
        foreach ($dims as $k => $d) {
            if (self::g($d, 'kind') === 'num' && in_array(self::g($d, 'path'), $paths, true)) {
                $ks[] = $k;
            }
        }
        if ($ks === []) {
            return;
        }
        $stride = [];
        foreach ($ks as $k) {
            $s = 1;
            for ($i = $k + 1; $i < count($m->nCellsD); $i++) {
                $s *= $m->nCellsD[$i];
            }
            $stride[] = $s;
        }
        for ($h = 1; $h < $m->nh; $h++) {
            $isMono = true;
            for ($c = 0; $c < $m->nCells && $isMono; $c++) {
                if (self::holds($m, $h, $c)) {
                    foreach ($ks as $i => $k) {
                        if ($m->cellIdx[$c * $D + $k] > 0 && !self::holds($m, $h, $c - $stride[$i])) {
                            $isMono = false;
                            break;
                        }
                    }
                }
            }
            if (!$isMono) {
                $m->w[$h] = $m->w[$h] * $off;
            }
        }
    }

    /** @param list<int> $cells */
    private static function holdsAll(IntentLearnerVerbModel $m, int $h, array $cells): bool
    {
        if ($h === 0) {
            return false;
        }
        foreach ($cells as $c) {
            if (!self::holds($m, $h, $c)) {
                return false;
            }
        }
        return true;
    }

    /** @param list<float> $w */
    private static function normalize(array &$w): void
    {
        $s = 0.0;
        foreach ($w as $x) {
            $s += $x;
        }
        if ($s > 0) {
            foreach ($w as $i => $x) {
                $w[$i] = $x / $s;
            }
        }
    }

    private static function mixPrior(IntentLearnerVerbModel $m, mixed $mix): void
    {
        $beta = self::f(self::g($mix, 'beta'));
        if (!($beta >= 0 && $beta < 1)) {
            throw new \InvalidArgumentException('pca-intent: priorMix.beta must be in [0, 1)');
        }
        $weight = self::g($mix, 'weight');
        $pop = array_fill(0, $m->nh, 0.0);
        $z = 0.0;
        for ($h = 0; $h < $m->nh; $h++) {
            $contains = static fn(mixed $c): bool => $h !== 0 && self::isInteger($c) && self::f($c) >= 0 && self::f($c) < $m->nCells && self::holds($m, $h, (int)self::f($c));
            $x = $weight($m->vs, $contains);
            $xf = Js::num($x);
            if ($xf === null || !is_finite($xf) || !($xf >= 0)) {
                throw new \InvalidArgumentException('pca-intent: priorMix.weight must be finite and >= 0');
            }
            $pop[$h] = $xf;
            $z += $xf;
        }
        if (!($z > 0)) {
            return;
        }
        for ($h = 0; $h < $m->nh; $h++) {
            $m->w[$h] = (1 - $beta) * $m->w[$h] + ($beta * $pop[$h]) / $z;
        }
    }

    // ---- the learner ---------------------------------------------------------------------------------------------------------

    public function __construct(mixed $omega, mixed $opts = null)
    {
        $this->omega = $omega;
        $this->opts = $opts;
        $this->eta = self::f(self::dflt($opts, 'eta', 0));
        if (!($this->eta >= 0 && $this->eta < 0.5)) {
            throw new \InvalidArgumentException('pca-intent: eta must be in [0, 0.5)');
        }
        $this->etaPos = self::f(self::dflt($opts, 'etaPos', $this->eta));
        $this->etaNeg = self::f(self::dflt($opts, 'etaNeg', $this->eta));
        if (!($this->etaPos >= 0 && $this->etaPos < 0.5 && $this->etaNeg >= 0 && $this->etaNeg < 0.5)) {
            throw new \InvalidArgumentException('pca-intent: etaPos and etaNeg must be in [0, 0.5)');
        }
        $this->noisy = $this->etaPos != 0 || $this->etaNeg != 0;
        $this->tau = self::f(self::dflt($opts, 'tau', $this->noisy ? 0.95 : 1));
        $this->strategy = (string)self::dflt($opts, 'strategy', 'disagreement');
        $h = self::g($opts, 'harm');
        $this->harmModel = $h instanceof HarmModel ? $h : WalletOmega::defaultHarm();
        $this->hypothesisClass = self::dflt($opts, 'hypothesisClass', ['kind' => 'box']);
        $slack = self::g($opts, 'agnosticSlack');
        if ($slack !== null) {
            if (!(self::isInteger($slack) && self::f($slack) >= 0)) {
                throw new \InvalidArgumentException('pca-intent: agnosticSlack must be a non-negative integer');
            }
            if ($this->noisy) {
                throw new \InvalidArgumentException('pca-intent: agnostic selection replaces the noise model; use eta = 0');
            }
            $this->agnosticSlack = self::f($slack);
        }
        $full = ['maxHypotheses' => 400000, 'maxEnumeration' => 4000000, 'hypothesisClass' => $this->hypothesisClass];
        foreach (['maxHypotheses', 'maxEnumeration'] as $k) {
            $v = self::g($opts, $k);
            if ($v !== null) {
                $full[$k] = $v;
            }
        }
        foreach (self::g($omega, 'verbs') as $vs) {
            $this->models[] = self::buildVerbModel($vs, $full, $this->harmModel);
        }
        $this->initPrior();
    }

    private function initPrior(): void
    {
        $opts = $this->opts;
        $anchors = [];
        $a1 = self::g($opts, 'anchor');
        if (Js::truthy($a1)) {
            $anchors[] = $a1;
        }
        $as = self::g($opts, 'anchors');
        if (Js::truthy($as)) {
            foreach ($as as $a) {
                $anchors[] = $a;
            }
        }
        $admitters = [];
        foreach ($anchors as $a) {
            $lam = self::f(self::g($a, 'lambda'));
            if ($lam > 0) {
                $admitters[] = [IntentPolicy::admitter(self::g($a, 'policy')), $lam];
            }
        }
        $decay = self::g($this->hypothesisClass, 'kind') === 'box' ? 1.0 : self::f(self::dflt($this->hypothesisClass, 'decay', 0.25));
        if (!($decay > 0 && $decay <= 1)) {
            throw new \InvalidArgumentException('pca-intent: decay must be in (0, 1]');
        }
        foreach ($this->models as $m) {
            $nmo = self::g($opts, 'nullMass');
            $nm = $nmo instanceof \Closure ? self::f($nmo($m->vs)) : self::f($nmo === null ? 0.2 : $nmo);
            if (!($nm >= 0 && $nm <= 1)) {
                throw new \InvalidArgumentException('pca-intent: nullMass must be in [0, 1]');
            }
            $m->w[0] = $nm;
            $z = 0.0;
            for ($h = 1; $h < $m->nh; $h++) {
                $raw = $m->complexity !== null ? pow($decay, (float)($m->complexity[$h] - 1)) : 1.0;
                $m->w[$h] = $raw;
                $z += $raw;
            }
            for ($h = 1; $h < $m->nh; $h++) {
                $m->w[$h] = ((1 - $nm) * $m->w[$h]) / self::or1($z);
            }
            $mono = self::g($opts, 'monotone');
            if (Js::truthy($mono)) {
                self::applyMonotonePrior($m, $mono);
            }
            if ($admitters !== []) {
                $tot = 0.0;
                for ($c = 0; $c < $m->nCells; $c++) {
                    $tot += $m->mass[$c];
                }
                $accs = [];
                foreach ($admitters as [$adm]) {
                    $acc = [];
                    for ($c = 0; $c < $m->nCells; $c++) {
                        $acc[] = $adm->admits($m->vs, WalletOmega::cellRep($m->vs, WalletOmega::decodeCell($m->vs, $c))) ? 1 : 0;
                    }
                    $accs[] = $acc;
                }
                for ($h = 0; $h < $m->nh; $h++) {
                    $mix = 0.0;
                    foreach ($accs as $i => $acc) {
                        $dist = 0.0;
                        for ($c = 0; $c < $m->nCells; $c++) {
                            $inH = $h === 0 ? 0 : (self::holds($m, $h, $c) ? 1 : 0);
                            if ($inH !== $acc[$c]) {
                                $dist += $m->mass[$c];
                            }
                        }
                        $mix += exp((-$admitters[$i][1] * $dist) / self::or1($tot));
                    }
                    $m->w[$h] = $m->w[$h] * ($mix / count($accs));
                }
            }
            self::normalize($m->w);
            $pm = self::g($opts, 'priorMix');
            if (Js::truthy($pm)) {
                self::mixPrior($m, $pm);
            }
            $m->prior = $m->w;
            $m->dirty = true;
        }
    }

    private function inGrant(IntentLearnerVerbModel $m, int $c): bool
    {
        return $m->veto[$c] === 0 && $m->p[$c] >= $this->tau - 1e-12;
    }

    private function model(mixed $verb): ?IntentLearnerVerbModel
    {
        foreach ($this->models as $m) {
            if (self::g($m->vs, 'verb') === $verb) {
                return $m;
            }
        }
        return null;
    }

    private function refresh(IntentLearnerVerbModel $m): void
    {
        if (!$m->dirty) {
            return;
        }
        $m->p = array_fill(0, $m->nCells, 0.0);
        // certainty is decided combinatorially (p = 1 iff every live hypothesis holds the cell), not by the float sum
        $anyIn = array_fill(0, $m->nCells, 0);
        $anyOut = array_fill(0, $m->nCells, 0);
        $live = false;
        for ($h = 0; $h < $m->nh; $h++) {
            $w = $m->w[$h];
            if ($w == 0) {
                continue;
            }
            $live = true;
            for ($c = 0; $c < $m->nCells; $c++) {
                if ($h > 0 && self::holds($m, $h, $c)) {
                    $m->p[$c] = $m->p[$c] + $w;
                    $anyIn[$c] = 1;
                } else {
                    $anyOut[$c] = 1;
                }
            }
        }
        for ($c = 0; $c < $m->nCells; $c++) {
            $m->p[$c] = (!$live || $anyIn[$c] === 0) ? 0.0 : ($anyOut[$c] === 0 ? 1.0 : min(1.0, max(0.0, $m->p[$c])));
        }
        $m->dirty = false;
    }

    private static function flat(IntentLearnerVerbModel $m, array $idx): int
    {
        $f = 0;
        foreach ($idx as $d => $i) {
            $f = $f * $m->nCellsD[$d] + $i;
        }
        return $f;
    }

    /** p_n(omega) for a concrete outcome (0 outside Omega: the conservative reading). */
    public function acceptance(mixed $o): float
    {
        $m = $this->model(self::g($o, 'verb'));
        if ($m === null) {
            return 0.0;
        }
        $idx = WalletOmega::cellOf($m->vs, $o);
        if ($idx === null) {
            return 0.0;
        }
        $this->refresh($m);
        return $m->p[self::flat($m, $idx)];
    }

    public function admitsOutcome(mixed $o): bool
    {
        $m = $this->model(self::g($o, 'verb'));
        if ($m === null) {
            return false;
        }
        $idx = WalletOmega::cellOf($m->vs, $o);
        if ($idx === null) {
            return false;
        }
        $this->refresh($m);
        return $this->inGrant($m, self::flat($m, $idx));
    }

    public function isVetoed(mixed $o): bool
    {
        $m = $this->model(self::g($o, 'verb'));
        $idx = $m !== null ? WalletOmega::cellOf($m->vs, $o) : null;
        return $m !== null && $idx !== null && $m->veto[self::flat($m, $idx)] === 1;
    }

    /** @return list<string> */
    public function vetoedCells(): array
    {
        $out = [];
        foreach ($this->models as $m) {
            for ($c = 0; $c < $m->nCells; $c++) {
                if ($m->veto[$c] !== 0) {
                    $out[] = Js::str(self::g($m->vs, 'verb')) . '|' . $c;
                }
            }
        }
        return $out;
    }

    /**
     * Record the principal's answer y to "should omega be allowed?" (with a region: "should EVERY outcome in it be allowed?") and update
     * the posterior. Null when the outcome is outside Omega or the region covers no cell.
     * @return array<string,mixed>|null
     */
    public function observe(mixed $o, int $y, string $source = 'elicitation', mixed $region = null): ?array
    {
        $m = $this->model(self::g($o, 'verb'));
        if ($m === null) {
            return null;
        }
        $idx = WalletOmega::cellOf($m->vs, $o);
        if ($idx === null) {
            return null;
        }
        $cells = $region !== null ? IntentRegion::regionCells($m->vs, $region, $y === 1 ? 'inner' : 'outer') : [self::flat($m, $idx)];
        if (count($cells) === 0) {
            return null;
        }
        $this->refresh($m);
        $vals = new Obj();
        $v0 = self::g($o, 'values');
        if ($v0 instanceof Obj) {
            foreach ($v0->keys() as $k) {
                $vals->set($k, $v0->get($k));
            }
        } elseif (is_array($v0) && !array_is_list($v0)) {
            foreach ($v0 as $k => $x) {
                $vals->set((string)$k, $x);
            }
        }
        $obs = ['verb' => self::g($o, 'verb'), 'values' => $vals, 'cell' => $idx, 'y' => $y, 'source' => $source];
        if ($region !== null) {
            $obs['region'] = $region;
        }
        // a "no" about a region every live hypothesis contains contradicts the whole class (the CONFLICT of spec 4.2c)
        $regionP = 0.0;
        for ($h = 1; $h < $m->nh; $h++) {
            if ($m->w[$h] > 0 && self::holdsAll($m, $h, $cells)) {
                $regionP += $m->w[$h];
            }
        }
        $contradictsAll = $y === 0 ? $regionP >= 1 - 1e-12 : $regionP <= 1e-12;
        if ($source === 'runtime' && $y === 0) {
            foreach ($cells as $c) {
                $m->veto[$c] = 1;
            }
        }
        foreach ($cells as $c) {
            $m->seen[$c] = 1;
        }
        if ($this->agnosticSlack !== null) {
            for ($h = 0; $h < $m->nh; $h++) {
                if ((self::holdsAll($m, $h, $cells) ? 1 : 0) !== $y) {
                    $m->err[$h]++;
                }
            }
            $minErr = INF;
            for ($h = 0; $h < $m->nh; $h++) {
                if ($m->prior[$h] > 0) {
                    $minErr = min($minErr, $m->err[$h]);
                }
            }
            for ($h = 0; $h < $m->nh; $h++) {
                $m->w[$h] = $m->err[$h] <= $minErr + $this->agnosticSlack ? $m->prior[$h] : 0.0;
            }
            self::normalize($m->w);
            if ($contradictsAll) {
                $obs['conflict'] = true;
                if ($y === 0) {
                    foreach ($cells as $c) {
                        $m->veto[$c] = 1;
                    }
                }
            }
        } else {
            $prev = ($this->etaPos == 0 || $this->etaNeg == 0) ? $m->w : null;
            $etaPos = $this->etaPos;
            $etaNeg = $this->etaNeg;
            $total = 0.0;
            for ($h = 0; $h < $m->nh; $h++) {
                $in = self::holdsAll($m, $h, $cells);
                $lik = $in ? ($y === 1 ? 1 - $etaNeg : $etaNeg) : ($y === 1 ? $etaPos : 1 - $etaPos);
                $m->w[$h] = $m->w[$h] * $lik;
                $total += $m->w[$h];
            }
            if ($total == 0 && $prev !== null) {
                $m->w = $prev; // every hypothesis contradicted: the truth is outside Theta; keep VS, flag the conflict
                $obs['conflict'] = true;
                if ($y === 0) {
                    foreach ($cells as $c) {
                        $m->veto[$c] = 1;
                    }
                }
            } else {
                self::normalize($m->w);
            }
        }
        $m->dirty = true;
        $this->observations[] = $obs;
        return $obs;
    }

    /** @return list<array<string,mixed>> */
    public function cells(): array
    {
        $out = [];
        foreach ($this->models as $m) {
            $this->refresh($m);
            for ($c = 0; $c < $m->nCells; $c++) {
                $out[] = ['verb' => self::g($m->vs, 'verb'), 'cell' => WalletOmega::decodeCell($m->vs, $c), 'p' => $m->p[$c], 'mass' => $m->mass[$c],
                    'harm' => $m->harm[$c], 'inGrant' => $this->inGrant($m, $c), 'vetoed' => $m->veto[$c] === 1];
            }
        }
        return $out;
    }

    /** @return array<string,mixed> */
    public function metrics(): array
    {
        $R = $B = $U = $H = $vsBits = $dis = $meanHarm = 0.0;
        foreach ($this->models as $m) {
            $this->refresh($m);
            for ($c = 0; $c < $m->nCells; $c++) {
                $p = $m->p[$c];
                $mu = $m->mass[$c];
                $meanHarm += $mu * $m->harm[$c];
                if ($this->inGrant($m, $c)) {
                    $R += $mu * (1 - $p) * $m->harm[$c];
                } else {
                    $B += $mu * $p;
                }
                $U += $mu * min($p, 1 - $p);
                if ($p > 1e-12 && $p < 1 - 1e-12) {
                    $dis += $mu;
                }
            }
            $alive = 0;
            for ($h = 0; $h < $m->nh; $h++) {
                $w = $m->w[$h];
                if ($w > 0) {
                    $alive++;
                    $H -= $w * self::log2($w);
                }
            }
            $vsBits += self::log2((float)max(1, $alive));
        }
        $q = 0;
        $cf = 0;
        foreach ($this->observations as $o) {
            if ($o['source'] === 'elicitation') {
                $q++;
            }
            if (!empty($o['conflict'])) {
                $cf++;
            }
        }
        return ['residualRisk' => $R, 'burden' => $B, 'uncertainty' => $U, 'entropyBits' => $H,
            'log2VersionSpace' => $this->noisy ? null : $vsBits, 'disagreementMass' => $dis, 'meanHarm' => $meanHarm,
            'questions' => $q, 'conflicts' => $cf];
    }

    /** The next question: argmax expected information (x mu*h for the risk strategy). Null when nothing is uncertain. */
    public function nextQuestion(): ?array
    {
        $best = null;
        $hPos = self::binEnt($this->etaPos);
        $hNeg = self::binEnt($this->etaNeg);
        foreach ($this->models as $m) {
            $this->refresh($m);
            for ($c = 0; $c < $m->nCells; $c++) {
                if ($m->veto[$c] !== 0) {
                    continue;
                }
                $p = $m->p[$c];
                if ($p <= 1e-9 || $p >= 1 - 1e-9) {
                    continue;
                }
                $pe = $p * (1 - $this->etaNeg) + (1 - $p) * $this->etaPos;
                $score = self::binEnt($pe) - ($this->etaPos == $this->etaNeg ? $hPos : $p * $hNeg + (1 - $p) * $hPos);
                if ($this->strategy === 'risk') {
                    $score *= $m->mass[$c] * $m->harm[$c];
                }
                if ($score <= 1e-15) {
                    continue;
                }
                if ($best === null || $score > $best['score'] + 1e-12) {
                    $cell = WalletOmega::decodeCell($m->vs, $c);
                    $best = ['verb' => self::g($m->vs, 'verb'), 'cell' => $cell, 'outcome' => WalletOmega::cellRep($m->vs, $cell), 'p' => $p, 'score' => $score];
                }
            }
        }
        return $best;
    }

    /** Grant cells INFERRED but never directly observed, most consequential first. @return list<array<string,mixed>> */
    public function unconfirmedGrantCells(): array
    {
        $out = [];
        foreach ($this->models as $m) {
            $this->refresh($m);
            for ($c = 0; $c < $m->nCells; $c++) {
                if ($m->seen[$c] !== 0 || !$this->inGrant($m, $c)) {
                    continue;
                }
                $out[] = ['verb' => self::g($m->vs, 'verb'), 'cell' => WalletOmega::decodeCell($m->vs, $c), 'weight' => $m->mass[$c] * $m->harm[$c]];
            }
        }
        usort($out, static fn($a, $b) => $b['weight'] <=> $a['weight']); // stable (PHP 8), like the reference's sort
        return $out;
    }

    /** The conservative grant G_tau as a real PCA policy: allow only cells with p_n >= tau. */
    public function synthesize(): array
    {
        $predicates = [];
        $worst = -1;
        foreach ($this->models as $m) {
            $this->refresh($m);
            $allowed = [];
            $any = false;
            for ($c = 0; $c < $m->nCells; $c++) {
                $a = $this->inGrant($m, $c);
                $allowed[] = $a ? 1 : 0;
                $any = $any || $a;
            }
            if (!$any) {
                continue;
            }
            $rv = self::g($m->vs, 'reversibility');
            $ix = in_array($rv, self::ORDER, true) ? array_search($rv, self::ORDER, true) : -1;
            $worst = max($worst, $ix);
            foreach (self::boxesToPredicates($m->vs, $allowed) as $p) {
                $predicates[] = $p;
            }
        }
        return ['predicates' => $predicates, 'caveats' => $worst >= 0 ? [['type' => 'reversibility_max', 'class' => self::ORDER[$worst]]] : []];
    }

    /** Replay observations onto a fresh learner (used to verify an Intent Map). */
    public static function replay(mixed $omega, mixed $opts, array $observations): self
    {
        $l = new self($omega, $opts);
        foreach ($observations as $o) {
            $l->observe(['verb' => self::g($o, 'verb'), 'values' => self::g($o, 'values')], (int)self::f(self::g($o, 'y')), (string)self::g($o, 'source'), self::g($o, 'region'));
        }
        return $l;
    }

    // ---- synthesis: allowed cells -> union of boxes -> predicates -----------------------------------------------------------

    /** @param list<int> $idx */
    private static function encode(mixed $vs, array $idx): int
    {
        $f = 0;
        foreach (self::g($vs, 'dims') as $i => $d) {
            $f = $f * WalletOmega::cellCount($d) + $idx[$i];
        }
        return $f;
    }

    /**
     * Ranges: [lo, hi] for a numeric dimension, a set (int => true, insertion ordered) for a categorical one.
     * @return \Generator<int,list<int>>
     */
    private static function boxCells(array $ranges, array $isNum, int $k = 0, array $pre = []): \Generator
    {
        if ($k === count($ranges)) {
            yield $pre;
            return;
        }
        $vals = $isNum[$k] ? range($ranges[$k][0], $ranges[$k][1]) : (static function (array $s): array { $ks = array_keys($s); sort($ks); return $ks; })($ranges[$k]);
        foreach ($vals as $v) {
            yield from self::boxCells($ranges, $isNum, $k + 1, [...$pre, $v]);
        }
    }

    private static function catCondition(mixed $d, array $S): ?array
    {
        $values = self::g($d, 'values');
        $path = self::g($d, 'path');
        if (count($S) === count($values)) {
            return null;
        }
        $exacts = [];
        $prefixes = [];
        foreach ($values as $v) {
            if (self::g($v, 'kind') === 'exact') {
                $exacts[] = self::g($v, 'value');
            } elseif (self::g($v, 'kind') === 'prefix') {
                $prefixes[] = self::g($v, 'value');
            }
        }
        $alts = [];
        $allowedExacts = [];
        foreach (array_keys($S) as $i) {
            if (self::g($values[$i], 'kind') === 'exact') {
                $allowedExacts[] = self::g($values[$i], 'value');
            }
        }
        if (count($allowedExacts) === 1) {
            $alts[] = ['field' => $path, 'op' => 'eq', 'value' => $allowedExacts[0]];
        } elseif (count($allowedExacts) > 1) {
            $alts[] = ['field' => $path, 'op' => 'in', 'value' => $allowedExacts];
        }
        $sorted = array_keys($S);
        sort($sorted);
        foreach ($sorted as $i) {
            $v = $values[$i];
            if (self::g($v, 'kind') === 'exact') {
                continue;
            }
            $parts = [];
            if (self::g($v, 'kind') === 'prefix') {
                $pv = self::g($v, 'value');
                $parts[] = ['field' => $path, 'op' => 'prefix', 'value' => $pv];
                $under = array_values(array_filter($exacts, static fn($e) => str_starts_with($e, $pv)));
                if ($under !== []) {
                    $parts[] = ['field' => $path, 'op' => 'nin', 'value' => $under];
                }
                foreach ($prefixes as $q) {
                    if ($q !== $pv && str_starts_with($q, $pv)) {
                        $parts[] = ['not' => ['field' => $path, 'op' => 'prefix', 'value' => $q]];
                    }
                }
            } else {
                if ($exacts !== []) {
                    $parts[] = ['field' => $path, 'op' => 'nin', 'value' => $exacts];
                }
                foreach ($prefixes as $q) {
                    $parts[] = ['not' => ['field' => $path, 'op' => 'prefix', 'value' => $q]];
                }
            }
            if (count($parts) === 1) {
                $alts[] = $parts[0];
            } elseif (count($parts) > 1) {
                $alts[] = ['all_of' => $parts];
            }
        }
        if ($alts === []) {
            return null;
        }
        return count($alts) === 1 ? $alts[0] : ['any_of' => $alts];
    }

    private static function boxToPredicate(mixed $vs, array $ranges, array $isNum): array
    {
        $where = [];
        foreach (self::g($vs, 'dims') as $k => $d) {
            $r = $ranges[$k];
            if ($isNum[$k]) {
                $cells = WalletOmega::numCells($d);
                $where[] = ['field' => self::g($d, 'path'), 'op' => 'gte', 'value' => $cells[$r[0]]['lo']];
                $where[] = ['field' => self::g($d, 'path'), 'op' => 'lte', 'value' => $cells[$r[1]]['hi']];
            } else {
                $c = self::catCondition($d, $r);
                if ($c !== null) {
                    $where[] = $c;
                }
            }
        }
        $out = ['verb' => self::g($vs, 'verb'), 'resource' => '*'];
        if ($where !== []) {
            $out['where'] = $where;
        }
        return $out;
    }

    /**
     * Cover the allowed cell set (a list / string of 0 and 1 per flat cell) exactly with greedily grown maximal boxes; one predicate per box.
     * @return list<array<string,mixed>>
     */
    public static function boxesToPredicates(mixed $vs, mixed $allowed): array
    {
        if (is_string($allowed)) {
            $allowed = array_map('ord', str_split($allowed));
        }
        $allowed = array_map(static fn($x) => ($x === true || (is_numeric($x) && $x == 1) || $x instanceof Num && $x->float() == 1.0) ? 1 : 0, $allowed);
        $dims = self::g($vs, 'dims');
        $isNum = [];
        foreach ($dims as $d) {
            $isNum[] = self::g($d, 'kind') === 'num';
        }
        $covered = array_fill(0, count($allowed), 0);
        $out = [];
        $all = static function (array $ranges) use ($vs, $allowed, $isNum): bool {
            foreach (self::boxCells($ranges, $isNum) as $idx) {
                if ($allowed[self::encode($vs, $idx)] !== 1) {
                    return false;
                }
            }
            return true;
        };
        for ($c = 0; $c < count($allowed); $c++) {
            if ($allowed[$c] === 0 || $covered[$c] === 1) {
                continue;
            }
            $idx = WalletOmega::decodeCell($vs, $c);
            $ranges = [];
            foreach ($dims as $k => $d) {
                $ranges[] = $isNum[$k] ? [$idx[$k], $idx[$k]] : [$idx[$k] => true];
            }
            foreach ($dims as $k => $d) {
                if ($isNum[$k]) {
                    $n = WalletOmega::cellCount($d);
                    while ($ranges[$k][1] + 1 < $n) {
                        $ranges[$k][1]++;
                        if (!$all($ranges)) {
                            $ranges[$k][1]--;
                            break;
                        }
                    }
                    while ($ranges[$k][0] > 0) {
                        $ranges[$k][0]--;
                        if (!$all($ranges)) {
                            $ranges[$k][0]++;
                            break;
                        }
                    }
                } else {
                    for ($v = 0, $nv = count(self::g($d, 'values')); $v < $nv; $v++) {
                        if (isset($ranges[$k][$v])) {
                            continue;
                        }
                        $ranges[$k][$v] = true;
                        if (!$all($ranges)) {
                            unset($ranges[$k][$v]);
                        }
                    }
                }
            }
            foreach (self::boxCells($ranges, $isNum) as $bi) {
                $covered[self::encode($vs, $bi)] = 1;
            }
            $out[] = self::boxToPredicate($vs, $ranges, $isNum);
        }
        return $out;
    }

    // ---- the stop rule -------------------------------------------------------------------------------------------------------

    private static function seedQuestion(self $learner, mixed $s): ?array
    {
        $vs = null;
        foreach (self::g($learner->omega, 'verbs') as $v) {
            if (self::g($v, 'verb') === self::g($s, 'verb')) {
                $vs = $v;
                break;
            }
        }
        $cell = self::g($s, 'cell');
        if ($vs === null || count($cell) !== count(self::g($vs, 'dims'))) {
            return null;
        }
        $outcome = WalletOmega::cellRep($vs, $cell);
        $p = $learner->acceptance($outcome);
        if ($p <= 1e-9 || $p >= 1 - 1e-9 || $learner->isVetoed($outcome)) {
            return null;
        }
        return ['verb' => self::g($s, 'verb'), 'cell' => $cell, 'outcome' => $outcome, 'p' => $p, 'score' => 0];
    }

    /**
     * Ask questions until the stop rule of spec 2.5 holds. `$answer` is a Closure(question): int (0 / 1).
     * @return array<string,mixed>
     */
    public static function elicit(self $learner, \Closure $answer, mixed $o): array
    {
        $epsRisk = self::f(self::g($o, 'epsRisk'));
        $epsBurden = self::f(self::g($o, 'epsBurden'));
        $maxQ = self::f(self::g($o, 'maxQuestions'));
        $asked = [];
        $seedQuestions = 0;
        $seeds = self::g($o, 'seed');
        foreach (Js::truthy($seeds) ? $seeds : [] as $s) {
            if (!(count($asked) < $maxQ)) {
                break;
            }
            $m = $learner->metrics();
            if ($m['residualRisk'] <= $epsRisk && $m['burden'] <= $epsBurden) {
                break;
            }
            $q = self::seedQuestion($learner, $s);
            if ($q === null) {
                continue;
            }
            $learner->observe($q['outcome'], (int)$answer($q), 'elicitation');
            $asked[] = $q;
            $seedQuestions++;
        }
        $stop = null;
        while ($stop === null) {
            $m = $learner->metrics();
            if ($m['residualRisk'] <= $epsRisk && $m['burden'] <= $epsBurden) {
                $stop = 'converged';
            } elseif (!(count($asked) < $maxQ)) {
                $stop = 'budget';
            } else {
                $q = $learner->nextQuestion();
                if ($q === null) {
                    $stop = 'no-disagreement';
                } else {
                    $learner->observe($q['outcome'], (int)$answer($q), 'elicitation');
                    $asked[] = $q;
                }
            }
        }
        $audit = self::auditRound($learner, $answer, $o, $asked);
        if ($audit['exhausted']) {
            $stop = 'budget';
        }
        return ['stop' => $stop, 'questions' => count($asked), 'auditQuestions' => $audit['asked'], 'seedQuestions' => $seedQuestions, 'asked' => $asked];
    }

    /**
     * The audit round on its own (spec 4.2c): the questions asked, and whether the budget ran out. Appends to `$asked`.
     * @return array{asked:int,exhausted:bool}
     */
    public static function auditRound(self $learner, \Closure $answer, mixed $o, array &$asked): array
    {
        $n = 0;
        if (!Js::truthy(self::g($o, 'audit'))) {
            return ['asked' => 0, 'exhausted' => false];
        }
        $epsRisk = self::f(self::g($o, 'epsRisk'));
        $maxQ = self::f(self::g($o, 'maxQuestions'));
        while (true) {
            $pending = $learner->unconfirmedGrantCells();
            $mass = 0.0;
            foreach ($pending as $x) {
                $mass += $x['weight'];
            }
            if (count($pending) === 0 || $mass <= $epsRisk) {
                return ['asked' => $n, 'exhausted' => false];
            }
            if (!(count($asked) < $maxQ)) {
                return ['asked' => $n, 'exhausted' => true];
            }
            $top = $pending[0];
            $vs = null;
            foreach (self::g($learner->omega, 'verbs') as $v) {
                if (self::g($v, 'verb') === $top['verb']) {
                    $vs = $v;
                    break;
                }
            }
            $outcome = WalletOmega::cellRep($vs, $top['cell']);
            $q = ['verb' => $top['verb'], 'cell' => $top['cell'], 'outcome' => $outcome, 'p' => $learner->acceptance(WalletOmega::cellRep($vs, $top['cell'])), 'score' => $top['weight']];
            $learner->observe($q['outcome'], (int)$answer($q), 'elicitation');
            $asked[] = $q;
            $n++;
        }
    }
}
