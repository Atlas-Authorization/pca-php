<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/DetMath.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/Catalog.php';
require_once __DIR__ . '/ControlEvals.php';
require_once __DIR__ . '/WalletOmega.php';

/**
 * The intent outcome space (omega): typed dimensions derived from the grant vocabulary, cells, representatives, the workload and harm
 * measures, a seeded generator and the derivation from policies + slots. Dimensions, verb spaces and omegas are the parsed-JSON model
 * (an Obj, or an assoc array keyed by the reference's names); numbers may be Num / int / float. Results hold plain PHP ints / floats.
 *
 * deriveOmega calls IntentPolicy::normalizePolicy (the policy module of the intent package).
 */
final class IntentOmega
{
    public const OTHER = "\u{22A5}";
    public const EXACT_SPAN = 4096;
    public const HARM_QUADRATURE_PIECES = 1024;
    private const EULER_GAMMA = 0.5772156649015329;

    private static ?HarmModel $defaultHarm = null;

    public static function defaultDomains(): array
    {
        return [
            'action.params.amount' => ['lo' => 0, 'hi' => 100000, 'dist' => 'loguniform'],
            'env.hour' => ['lo' => 0, 'hi' => 23, 'dist' => 'uniform'],
            'action.params.count' => ['lo' => 0, 'hi' => 1000, 'dist' => 'loguniform'],
        ];
    }

    private static function p(mixed $x): mixed
    {
        return WalletOmega::plain($x);
    }

    /** A member with JSON numbers as plain PHP numbers (a Num scalar, or the Num items of a list); other values are returned as they are. */
    private static function m(mixed $o, string $k): mixed
    {
        $v = Js::opt($o, $k);
        if ($v instanceof Num) {
            return self::p($v);
        }
        return is_array($v) ? array_map(static fn(mixed $e): mixed => $e instanceof Num ? self::p($e) : $e, $v) : $v;
    }

    private static function jsRound(int|float $x): int|float
    {
        return floor($x + 0.5);
    }

    // ---- cells -------------------------------------------------------------------------------------------------------

    /** @return list<array{0:int|float,1:int|float}> the inclusive integer ranges of a numeric dimension (empty cells dropped; plain d) */
    private static function cellsOf(mixed $d): array
    {
        $out = [];
        $lo = self::p(self::m($d, 'lo'));
        $hi = self::p(self::m($d, 'hi'));
        $cur = $lo;
        foreach (self::p(self::m($d, 'cuts')) as $c) {
            if ($c < $lo || $c > $hi) {
                continue;
            }
            if ($cur <= $c - 1) {
                $out[] = [$cur, $c - 1];
            }
            $out[] = [$c, $c];
            $cur = $c + 1;
        }
        if ($cur <= $hi) {
            $out[] = [$cur, $hi];
        }
        return $out;
    }

    /** seq[i] with the reference's out-of-range failure (a negative index must not wrap around). */
    private static function at(array $seq, mixed $i): mixed
    {
        if (!is_int($i) || $i < 0 || $i >= count($seq)) {
            throw new \OutOfRangeException('cell index out of range');
        }
        return $seq[$i];
    }

    private static function idx(mixed $i): int
    {
        $f = Js::num($i);
        if ($f === null || $f != floor($f) || !is_finite($f)) {
            throw new \OutOfRangeException('cell index out of range');
        }
        return (int)$f;
    }

    /** The ordered cells of a numeric dimension as [{lo, hi}]. */
    public static function numCells(mixed $d): array
    {
        $d = self::p($d);
        return array_map(static fn(array $c): Obj => Obj::of(['lo' => $c[0], 'hi' => $c[1]]), self::cellsOf($d));
    }

    public static function cellCount(mixed $d): int
    {
        $d = self::p($d);
        return self::cc($d);
    }

    private static function cc(mixed $d): int
    {
        return self::m($d, 'kind') === 'num' ? count(self::cellsOf($d)) : count(self::m($d, 'values'));
    }

    public static function verbCellCount(mixed $vs): int
    {
        $vs = self::p($vs);
        $n = 1;
        foreach (self::m($vs, 'dims') as $d) {
            $n *= self::cc($d);
        }
        return $n;
    }

    /** @return list<int> */
    public static function decodeCell(mixed $vs, mixed $flat): array
    {
        $vs = self::p($vs);
        $dims = self::m($vs, 'dims');
        $idx = array_fill(0, count($dims), 0);
        $flat = (float)Js::num($flat);
        for ($i = count($dims) - 1; $i >= 0; $i--) {
            $n = self::cc($dims[$i]);
            $idx[$i] = (int)fmod($flat, (float)$n);
            $flat = floor($flat / $n);
        }
        return $idx;
    }

    public static function encodeCell(mixed $vs, mixed $idx): int
    {
        $vs = self::p($vs);
        $idx = self::p($idx);
        $flat = 0;
        foreach (self::m($vs, 'dims') as $i => $d) {
            $flat = $flat * self::cc($d) + $idx[$i];
        }
        return $flat;
    }

    /** Which cell of a categorical dimension a concrete string falls in (exact > longest prefix > OTHER). */
    public static function catCellOf(mixed $d, string $s): int
    {
        return self::catCell(self::p($d), $s);
    }

    private static function catCell(mixed $d, string $s): int
    {
        $best = -1;
        $bestLen = -1;
        $values = self::m($d, 'values');
        foreach ($values as $i => $v) {
            $kind = self::m($v, 'kind');
            $val = self::m($v, 'value');
            if ($kind === 'exact' && $val === $s) {
                return $i;
            }
            if ($kind === 'prefix' && str_starts_with($s, $val) && Js::len($val) > $bestLen) {
                $best = $i;
                $bestLen = Js::len($val);
            }
        }
        if ($best >= 0) {
            return $best;
        }
        foreach ($values as $i => $v) {
            if (self::m($v, 'kind') === 'other') {
                return $i;
            }
        }
        return -1;
    }

    /** The cell a concrete value falls in, or -1 outside the dimension's domain or type. */
    public static function cellOfValue(mixed $d, mixed $x): int
    {
        return self::cov(self::p($d), self::p($x));
    }

    private static function cov(mixed $d, mixed $x): int
    {
        if (self::m($d, 'kind') === 'num') {
            if (!Js::isNum($x) || !is_finite((float)Js::num($x))) {
                return -1;
            }
            foreach (self::cellsOf($d) as $i => [$lo, $hi]) {
                if ($x >= $lo && $x <= $hi) {
                    return $i;
                }
            }
            return -1;
        }
        return is_string($x) ? self::catCell($d, $x) : -1;
    }

    /** @return list<int>|null */
    public static function cellOf(mixed $vs, mixed $o): ?array
    {
        $vs = self::p($vs);
        $o = self::p($o);
        $values = self::m($o, 'values');
        $idx = [];
        foreach (self::m($vs, 'dims') as $d) {
            $i = self::cov($d, Js::isObj($values) ? self::m($values, self::m($d, 'path')) : null);
            if ($i < 0) {
                return null;
            }
            $idx[] = $i;
        }
        return $idx;
    }

    public static function catRep(mixed $d, mixed $i): string
    {
        return self::cr(self::p($d), self::idx($i));
    }

    private static function cr(mixed $d, int $i): string
    {
        $v = self::at(self::m($d, 'values'), $i);
        $val = self::m($v, 'value');
        if (self::m($v, 'kind') === 'exact') {
            return $val;
        }
        $base = self::m($v, 'kind') === 'prefix' ? $val . 'x' : 'other';
        for ($k = 0; $k < 64; $k++) {
            $s = $base . ($k === 0 ? '' : (string)$k);
            if (self::catCell($d, $s) === $i) {
                return $s;
            }
        }
        return $base;
    }

    public static function numRep(mixed $d, mixed $i): int|float
    {
        return self::nr(self::p($d), self::idx($i));
    }

    private static function nr(mixed $d, int $i): int|float
    {
        [$lo, $hi] = self::at(self::cellsOf($d), $i);
        return $i > 0 ? $lo : $hi;
    }

    public static function repValue(mixed $d, mixed $i): mixed
    {
        $d = self::p($d);
        $i = self::idx($i);
        return self::m($d, 'kind') === 'num' ? self::nr($d, $i) : self::cr($d, $i);
    }

    public static function cellRep(mixed $vs, mixed $idx): Obj
    {
        $vs = self::p($vs);
        $idx = self::p($idx);
        $values = new Obj();
        foreach (self::m($vs, 'dims') as $i => $d) {
            $values->set(self::m($d, 'path'), self::m($d, 'kind') === 'num' ? self::nr($d, self::idx($idx[$i])) : self::cr($d, self::idx($idx[$i])));
        }
        return Obj::of(['verb' => self::m($vs, 'verb'), 'values' => $values]);
    }

    // ---- workload and harm -------------------------------------------------------------------------------------------

    private static function logu(mixed $d): bool
    {
        return self::m($d, 'dist') === 'loguniform' && self::m($d, 'lo') >= 0;
    }

    private static function pointWeight(mixed $d, int|float $x): int|float
    {
        return self::logu($d) ? 1 / ($x + 1) : 1;
    }

    private static function linearAmount(mixed $d): bool
    {
        return self::m($d, 'kind') === 'num' && preg_match('/(^|\.)amount\z/', (string)self::m($d, 'path')) === 1;
    }

    public static function defaultHarm(): HarmModel
    {
        return self::$defaultHarm ??= new HarmModel(
            static function (mixed $vs): int|float {
                $r = Js::opt($vs, 'reversibility');
                return $r === 'irreversible' ? 10 : ($r === 'rate_limited' ? 3 : 1);
            },
            static fn(mixed $d, mixed $x): int|float => self::linearAmount($d) && Js::isNum($x) ? 1 + max(0, Js::num($x)) / 100 : 1,
            static fn(mixed $d, mixed $lo, mixed $hi): int|float => self::linearAmount($d)
                ? 1 + max(0, self::intervalMeanX($d, max($lo, 0), $hi, $lo)) / 100 : 1,
        );
    }

    /** A harm model from verb / dim / (optional) dimMean closures taking plain values. */
    public static function harmModel(\Closure $verb, \Closure $dim, ?\Closure $dimMean = null): HarmModel
    {
        return new HarmModel($verb, $dim, $dimMean);
    }

    public static function harmMax(mixed $omega, ?HarmModel $harm = null): int|float
    {
        $omega = self::p($omega);
        $harm ??= self::defaultHarm();
        $m = 0;
        foreach (self::m($omega, 'verbs') as $vs) {
            $f = ($harm->verb)($vs);
            foreach (self::m($vs, 'dims') as $d) {
                if (self::m($d, 'kind') === 'num') {
                    $f *= max(($harm->dim)($d, self::m($d, 'lo')), ($harm->dim)($d, self::m($d, 'hi')));
                } else {
                    $mx = null;
                    for ($i = 0, $n = count(self::m($d, 'values')); $i < $n; $i++) {
                        $h = ($harm->dim)($d, self::cr($d, $i));
                        $mx = $mx === null ? $h : max($mx, $h);
                    }
                    $f *= $mx ?? throw new \ValueError('max() arg is an empty sequence');
                }
            }
            $m = max($m, $f);
        }
        return $m;
    }

    private static function harmonic(int|float $n): int|float
    {
        if ($n <= 0) {
            return 0;
        }
        if ($n <= self::EXACT_SPAN) {
            $s = 0.0;
            for ($k = (int)$n; $k > 0; $k--) {
                $s += 1 / $k;
            }
            return $s;
        }
        $n = (float)$n;
        $n2 = $n * $n;
        return DetMath::detLn($n) + self::EULER_GAMMA + 1 / (2 * $n) - 1 / (12 * $n2) + 1 / (120 * $n2 * $n2) - 1 / (252 * $n2 * $n2 * $n2);
    }

    /** Sum of the dimension's law over the integers a..b (0 for an empty interval). */
    public static function intervalWeight(mixed $d, mixed $a, mixed $b): int|float
    {
        return self::iw(self::p($d), self::p($a), self::p($b));
    }

    private static function iw(mixed $d, int|float $a, int|float $b): int|float
    {
        if ($b < $a) {
            return 0;
        }
        if (!self::logu($d)) {
            return $b - $a + 1;
        }
        if ($b - $a + 1 <= self::EXACT_SPAN) {
            $s = 0.0;
            for ($x = (int)$b; $x >= $a; $x--) {
                $s += 1 / ($x + 1);
            }
            return $s;
        }
        return self::harmonic((float)$b + 1) - self::harmonic($a);
    }

    private static function firstMoment(mixed $d, int|float $a, int|float $b): int|float
    {
        if ($b < $a) {
            return 0;
        }
        $a = (float)$a;
        $b = (float)$b;
        if (!self::logu($d)) {
            return (($a + $b) * ($b - $a + 1)) / 2;
        }
        return $b - $a + 1 - self::iw($d, $a, $b);
    }

    private static function intervalMeanX(mixed $d, int|float $a, int|float $b, int|float $cellLo): int|float
    {
        $whole = self::iw($d, $cellLo, $b);
        return $whole > 0 ? self::firstMoment($d, $a, $b) / $whole : 0;
    }

    private static function intervalHarm(mixed $d, int|float $a, int|float $b, HarmModel $harm): int|float
    {
        if ($harm->dimMean !== null) {
            return ($harm->dimMean)($d, $a, $b);
        }
        $n = (float)$b - (float)$a + 1;
        $wTot = self::iw($d, $a, $b);
        if (!($wTot > 0)) {
            return ($harm->dim)($d, $a);
        }
        if ($n <= self::EXACT_SPAN) {
            $s = 0.0;
            for ($x = $a; $x <= $b; $x++) {
                $s += self::pointWeight($d, $x) * ($harm->dim)($d, $x);
            }
            return $s / $wTot;
        }
        $s = 0.0;
        $fa = (float)$a;
        for ($i = 0; $i < self::HARM_QUADRATURE_PIECES; $i++) {
            $pa = $fa + floor((float)$i * $n / self::HARM_QUADRATURE_PIECES);
            $pb = $fa + floor((float)($i + 1) * $n / self::HARM_QUADRATURE_PIECES) - 1;
            if ($pb < $pa) {
                continue;
            }
            $s += self::iw($d, $pa, $pb) * ($harm->dim)($d, self::jsRound(($pa + $pb) / 2));
        }
        return $s / $wTot;
    }

    private static function dimTotal(mixed $d): int|float
    {
        return self::iw(Obj::of(['dist' => self::m($d, 'dist'), 'lo' => self::m($d, 'lo')]), self::m($d, 'lo'), self::m($d, 'hi'));
    }

    /** mu_d(cell) and E[g_d | cell] for one dimension cell. Categorical values are uniform. @return array{mass:int|float,harm:int|float} */
    public static function dimCellStats(mixed $d, mixed $i, ?HarmModel $harm = null): array
    {
        return self::dcs(self::p($d), self::idx($i), $harm ?? self::defaultHarm());
    }

    private static function dcs(mixed $d, int $i, HarmModel $harm): array
    {
        if (self::m($d, 'kind') === 'cat') {
            return ['mass' => 1 / count(self::m($d, 'values')), 'harm' => ($harm->dim)($d, self::cr($d, $i))];
        }
        [$lo, $hi] = self::at(self::cellsOf($d), $i);
        $wm = self::iw($d, $lo, $hi);
        return ['mass' => $wm / self::dimTotal($d), 'harm' => $wm > 0 ? self::intervalHarm($d, $lo, $hi, $harm) : ($harm->dim)($d, $lo)];
    }

    /** @return int|float the value at the target quantile of the dimension's law */
    private static function quantileValue(mixed $d, int|float $target): int|float
    {
        $acc = 0.0;
        $cells = self::cellsOf($d);
        foreach ($cells as $ci => [$lo, $hi]) {
            $w = self::iw($d, $lo, $hi);
            if ($target < $acc + $w || $ci === count($cells) - 1) {
                $r = $target - $acc;
                if ($hi - $lo + 1 <= self::EXACT_SPAN) {
                    for ($x = $lo; $x < $hi; $x++) {
                        $r -= self::pointWeight($d, $x);
                        if ($r < 0) {
                            return $x;
                        }
                    }
                    return $hi;
                }
                if (!self::logu($d)) {
                    return min($hi, $lo + floor($r));
                }
                $x = floor(((float)$lo + 1) * DetMath::detExp($r) - 1);
                return max($lo, min($hi, $x));
            }
            $acc += $w;
        }
        return self::m($d, 'hi');
    }

    /** Exact mu(cell) and E[h | cell] for a whole cell (product measure, separable harm). @return array{mass:int|float,harm:int|float} */
    public static function cellStats(mixed $vs, mixed $idx, ?HarmModel $harm = null): array
    {
        $vs = self::p($vs);
        $idx = self::p($idx);
        $harm ??= self::defaultHarm();
        $mass = self::m($vs, 'weight');
        $h = ($harm->verb)($vs);
        foreach (self::m($vs, 'dims') as $k => $d) {
            $s = self::dcs($d, self::idx($idx[$k]), $harm);
            $mass *= $s['mass'];
            $h *= $s['harm'];
        }
        return ['mass' => $mass, 'harm' => $h];
    }

    public static function harmOf(mixed $vs, mixed $o, ?HarmModel $harm = null): int|float
    {
        $vs = self::p($vs);
        $o = self::p($o);
        $harm ??= self::defaultHarm();
        $h = ($harm->verb)($vs);
        $values = self::m($o, 'values');
        foreach (self::m($vs, 'dims') as $d) {
            $h *= ($harm->dim)($d, Js::isObj($values) ? self::m($values, self::m($d, 'path')) : null);
        }
        return $h;
    }

    /** A small seeded PRNG (mulberry32), bit-identical to the reference. */
    public static function rng(mixed $seed): \Closure
    {
        return ControlEvals::mulberry32($seed);
    }

    /** Draw an outcome from the workload. @return array{0:mixed,1:Obj} the verb space and the outcome */
    public static function sampleOutcome(mixed $omega, \Closure $rand): array
    {
        $omega = self::p($omega);
        $u = $rand();
        $verbs = self::m($omega, 'verbs');
        if (!is_array($verbs) || $verbs === []) { // no verb to draw from: the outcome has nothing to be an outcome of (never a verb-less one)
            throw new \TypeError("Cannot read properties of undefined (reading 'dims')");
        }
        $vs = $verbs[count($verbs) - 1];
        foreach ($verbs as $v) {
            if ($u < self::m($v, 'weight')) {
                $vs = $v;
                break;
            }
            $u -= self::m($v, 'weight');
        }
        $values = new Obj();
        foreach (self::m($vs, 'dims') as $d) {
            if (self::m($d, 'kind') === 'cat') {
                $n = count(self::m($d, 'values'));
                $values->set(self::m($d, 'path'), self::cr($d, min($n - 1, (int)floor($rand() * $n))));
                continue;
            }
            $values->set(self::m($d, 'path'), self::quantileValue($d, $rand() * self::dimTotal($d)));
        }
        return [$vs, Obj::of(['verb' => self::m($vs, 'verb'), 'values' => $values])];
    }

    public static function verbSpace(mixed $omega, string $verb): mixed
    {
        $omega = self::p($omega);
        foreach (self::m($omega, 'verbs') as $v) {
            if (self::m($v, 'verb') === $verb) {
                return $v;
            }
        }
        return null;
    }

    // ---- derivation from policies + slots ---------------------------------------------------------------------------

    /** @param list<array{0:string,1:array}> $m [path, lits] in first-seen order; lits = ['nums'=>list,'exacts'=>list,'prefixes'=>list] */
    private static function &lits(array &$m, string $path): array
    {
        foreach ($m as $i => $e) {
            if ($e[0] === $path) {
                return $m[$i][1];
            }
        }
        $m[] = [$path, ['nums' => [], 'exacts' => [], 'prefixes' => []]];
        return $m[count($m) - 1][1];
    }

    private static function addUnique(array &$xs, mixed $v): void
    {
        if (!in_array($v, $xs, true)) {
            $xs[] = $v;
        }
    }

    private static function intIfIntegral(int|float $x): int|float
    {
        return is_float($x) && $x == floor($x) && abs($x) < 9.2e18 ? (int)$x : $x;
    }

    private static function addNum(array &$f, mixed $x): void
    {
        if (!Js::isNum($x) || !is_finite((float)Js::num($x))) {
            return;
        }
        $x = self::p($x);
        self::addUnique($f['nums'], self::intIfIntegral(floor($x)));
        self::addUnique($f['nums'], self::intIfIntegral(ceil($x)));
    }

    private static function collectCond(mixed $c, array &$m, array &$approx): void
    {
        if (!($c instanceof Obj)) {
            return;
        }
        if (Predicates::isGroupCondition($c)) {
            if ($c->has('all_of') && is_array($c->get('all_of'))) {
                foreach ($c->get('all_of') as $x) {
                    self::collectCond($x, $m, $approx);
                }
            } elseif ($c->has('any_of') && is_array($c->get('any_of'))) {
                foreach ($c->get('any_of') as $x) {
                    self::collectCond($x, $m, $approx);
                }
            } elseif ($c->has('not')) {
                self::collectCond($c->get('not'), $m, $approx);
            }
            return;
        }
        if (!Predicates::isLeafCondition($c)) {
            return;
        }
        $field = $c->get('field');
        $op = $c->get('op');
        if ($c->get('ref') !== null) {
            self::addUnique($approx, 'cross-field ref on ' . $field);
        }
        if (in_array($op, ['like', 'matches', 'is_a', 'member_of'], true)) {
            self::addUnique($approx, $op . ' on ' . $field);
        }
        $f = &self::lits($m, $field);
        if ($op === 'exists') {
            return;
        }
        $value = $c->get('value');
        foreach (is_array($value) && array_is_list($value) ? $value : [$value] as $v) {
            if (Js::isNum($v)) {
                self::addNum($f, $v);
            } elseif (is_string($v)) {
                self::addUnique($f[$op === 'prefix' ? 'prefixes' : 'exacts'], $v);
            }
        }
    }

    private static function addResource(mixed $r, array &$m, array &$approx): void
    {
        if (!is_string($r) || $r === '*') {
            return;
        }
        if (str_starts_with($r, 're:')) {
            self::addUnique($approx, 're: resource matcher');
            return;
        }
        $f = &self::lits($m, 'action.resource');
        if (str_ends_with($r, '*')) {
            self::addUnique($f['prefixes'], substr($r, 0, -1));
        } else {
            self::addUnique($f['exacts'], $r);
        }
    }

    /** @return '*'|list<string> */
    private static function verbsOf(mixed $p): string|array
    {
        $v = Js::isObj($p) ? self::m($p, 'verb') : null;
        if (is_string($v)) {
            return $v === '*' ? '*' : [$v];
        }
        if (is_array($v)) {
            return in_array('*', $v, true) ? '*' : array_values(array_filter($v, 'is_string'));
        }
        return [];
    }

    private static function sortU16(array $xs): array
    {
        usort($xs, static fn($a, $b) => Jsx::cmp($a, $b));
        return $xs;
    }

    /** @return list<array> the catalog action specs (null: the built-in catalog) */
    private static function catalogAll(mixed $catalog): array
    {
        $catalog ??= Catalog::BUILTIN_ACTIONS;
        if ($catalog instanceof Obj) {
            return array_map(static fn(string $k) => $catalog->get($k), $catalog->keys());
        }
        $by = [];
        foreach ($catalog as $s) {
            $by['v' . self::m($s, 'verb')] = $s;
        }
        return array_values($by);
    }

    /**
     * Derive the outcome space from the vocabulary of the policies and the intent slots. Wildcard verbs expand to the catalog verbs of
     * every connector that appears anywhere (or the whole catalog when none does).
     */
    public static function deriveOmega(mixed $opts): Obj
    {
        require_once __DIR__ . '/IntentPolicy.php';
        $poolAll = self::catalogAll(self::m($opts, 'catalog'));
        $catByVerb = [];
        foreach ($poolAll as $s) {
            $catByVerb['v' . self::m($s, 'verb')] = $s;
        }
        $approx = [];
        $preds = [];
        foreach (self::m($opts, 'policies') as $pol) {
            foreach (self::m(IntentPolicy::normalizePolicy($pol), 'predicates') as $pr) {
                $preds[] = $pr;
            }
        }
        $slots = self::m($opts, 'slots');
        $slotsObj = Js::isObj($slots);
        $explicit = [];
        foreach (self::m($opts, 'extraVerbs') ?? [] as $v) {
            self::addUnique($explicit, $v);
        }
        $wildcard = false;
        foreach ($preds as $pr) {
            $vs = self::verbsOf($pr);
            if ($vs === '*') {
                $wildcard = true;
            } else {
                foreach ($vs as $v) {
                    self::addUnique($explicit, $v);
                }
            }
        }
        foreach (($slotsObj ? self::m($slots, 'verbs') : null) ?? [] as $v) {
            self::addUnique($explicit, $v);
        }
        if ($wildcard) {
            $connectors = [];
            foreach ($explicit as $v) {
                self::addUnique($connectors, explode('.', $v)[0]);
            }
            $pool = $connectors ? array_values(array_filter($poolAll, static fn($s) => in_array(self::m($s, 'connector'), $connectors, true))) : $poolAll;
            foreach ($pool as $s) {
                self::addUnique($explicit, self::m($s, 'verb'));
            }
        }
        $domains = self::p(self::m($opts, 'domains')) ?? null;
        $defaults = self::defaultDomains();
        $out = [];
        foreach (self::sortU16($explicit) as $verb) {
            $m = [];
            foreach ($preds as $pr) {
                $pv = self::verbsOf($pr);
                if ($pv !== '*' && !in_array($verb, $pv, true)) {
                    continue;
                }
                self::addResource(is_string(self::m($pr, 'resource')) ? self::m($pr, 'resource') : null, $m, $approx);
                if (is_array(self::m($pr, 'where'))) {
                    foreach (self::m($pr, 'where') as $c) {
                        self::collectCond($c, $m, $approx);
                    }
                }
            }
            foreach (($slotsObj ? self::m($slots, 'constraints') : null) ?? [] as $sc) {
                if (self::m($sc, 'verb') !== null && self::m($sc, 'verb') !== $verb) {
                    continue;
                }
                $f = &self::lits($m, self::m($sc, 'path'));
                if (self::m($sc, 'max') !== null) {
                    self::addNum($f, self::m($sc, 'max'));
                }
                if (self::m($sc, 'min') !== null) {
                    self::addNum($f, self::m($sc, 'min'));
                }
                foreach (self::m($sc, 'oneOf') ?? [] as $x) {
                    self::addUnique($f['exacts'], $x);
                }
                foreach (self::m($sc, 'noneOf') ?? [] as $x) {
                    self::addUnique($f['exacts'], $x);
                }
                foreach (self::m($sc, 'prefixOneOf') ?? [] as $x) {
                    self::addUnique($f['prefixes'], $x);
                }
                unset($f);
            }
            $paths = self::sortU16(array_map(static fn($e) => $e[0], $m));
            $dims = [];
            foreach ($paths as $path) {
                $f = &self::lits($m, $path);
                $dom = self::m($domains, $path) ?? ($defaults[$path] ?? null);
                if (count($f['nums']) > 0 || (!$f['exacts'] && !$f['prefixes'] && isset($defaults[$path]))) {
                    $cuts = $f['nums'];
                    sort($cuts);
                    $maxCut = $cuts ? $cuts[count($cuts) - 1] : 0;
                    $minCut = $cuts ? $cuts[0] : 0;
                    $lo = $dom !== null && self::m($dom, 'lo') !== null ? self::m($dom, 'lo') : min(0, $minCut - 1);
                    $hi = $dom !== null && self::m($dom, 'hi') !== null ? self::m($dom, 'hi') : max(10, 2 * $maxCut, $maxCut + 10);
                    $dist = $dom !== null && self::m($dom, 'dist') !== null ? self::m($dom, 'dist') : ($lo >= 0 ? 'loguniform' : 'uniform');
                    $dims[] = Obj::of(['kind' => 'num', 'path' => $path, 'lo' => $lo, 'hi' => $hi,
                        'cuts' => array_values(array_filter($cuts, static fn($c) => $lo <= $c && $c <= $hi)), 'dist' => $dist]);
                } else {
                    $values = [];
                    foreach (self::sortU16($f['exacts']) as $v) {
                        $values[] = Obj::of(['kind' => 'exact', 'value' => $v]);
                    }
                    foreach (self::sortU16($f['prefixes']) as $v) {
                        $values[] = Obj::of(['kind' => 'prefix', 'value' => $v]);
                    }
                    $values[] = Obj::of(['kind' => 'other', 'value' => self::OTHER]);
                    $dims[] = Obj::of(['kind' => 'cat', 'path' => $path, 'values' => $values]);
                }
                unset($f);
            }
            $spec = $catByVerb['v' . $verb] ?? null;
            $out[] = Obj::of(['verb' => $verb, 'reversibility' => ($spec !== null ? self::m($spec, 'reversibility') : null) ?? 'irreversible',
                'weight' => 0, 'dims' => $dims]);
        }
        foreach ($out as $v) {
            $v->set('weight', 1 / count($out));
        }
        return Obj::of(['v' => 1, 'verbs' => $out, 'approximate' => self::sortU16($approx)]);
    }

    // ---- IEEE-754 behaviour of the JS Math functions ----------------------------------------------------------------

    public static function jsMax(int|float $a, int|float $b): int|float
    {
        return is_nan((float)$a) || is_nan((float)$b) ? NAN : max($a, $b);
    }

    public static function jsMin(int|float $a, int|float $b): int|float
    {
        return is_nan((float)$a) || is_nan((float)$b) ? NAN : min($a, $b);
    }
}
