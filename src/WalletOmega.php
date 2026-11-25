<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/DetMath.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/K3Sig.php';

/** The separable harm model: h_v (verb factor), g_d (dimension factor at a concrete value) and the optional closed-form mean over an interval. */
final class HarmModel
{
    /** @param \Closure(mixed):float $verb @param \Closure(mixed,mixed):float $dim @param (\Closure(mixed,int,int):float)|null $dimMean */
    public function __construct(public readonly \Closure $verb, public readonly \Closure $dim, public readonly ?\Closure $dimMean = null)
    {
    }
}

/**
 * The outcome space the wallet resolves question cells against (the Omega of the intent layer), the separable harm model and the exact
 * Clopper-Pearson bound, as the wallet needs them. Private to the wallet port. Floats follow the reference operation by operation
 * (IEEE-754 doubles). Outcome spaces are objects (an Obj or an assoc array) whose numbers are plain PHP ints / floats (see
 * {@see WalletOmega::plain}); the exact Clopper-Pearson bound needs ext-gmp.
 */
final class WalletOmega
{
    public const OTHER = "\u{22A5}"; // "any value not named"
    public const EXACT_SPAN = 4096;
    private const EULER_GAMMA = 0.5772156649015329;
    private const MAX_SAFE = 9007199254740991;
    private const GRID_BITS = 52;
    private const TOL_UNITS = 256; // 1 << (GRID_BITS - 44)

    private static ?HarmModel $defaultHarm = null;

    // ---- JavaScript value helpers shared by the wallet modules --------------------------------------------------------------

    /** Deep copy of a JSON value with every number a plain PHP int (safe integers) or float. */
    public static function plain(mixed $v): mixed
    {
        if ($v instanceof Num) {
            $f = $v->float();
            return $f == floor($f) && abs($f) <= self::MAX_SAFE && !($f == 0.0 && fdiv(1.0, $f) < 0) ? (int)$f : $f;
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::plain($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::plain(...), $v);
        }
        return $v;
    }

    public static function isNumber(mixed $v): bool
    {
        return Js::isNum($v);
    }

    public static function isFiniteNumber(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f);
    }

    /** Number.isSafeInteger (accepts -0). */
    public static function isSafeInt(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= self::MAX_SAFE;
    }

    /** A safe integer that is not -0 (the wire `isInt`). */
    public static function isInt(mixed $v): bool
    {
        if (!self::isSafeInt($v)) {
            return false;
        }
        $f = Js::num($v);
        return !($f === 0.0 && fdiv(1.0, $f) < 0);
    }

    /** JavaScript String.length (UTF-16 code units). */
    public static function u16len(string $s): int
    {
        return Js::len($s);
    }

    /** The characters of a (WTF-8) string. @return list<string> */
    private static function chars(string $s): array
    {
        preg_match_all('/\xED[\xA0-\xBF][\x80-\xBF]|[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF4][\x80-\xBF]{3}|[\x80-\xFF]/', $s, $m);
        return $m[0];
    }

    private static function surrogate(string $c, bool $high): string
    {
        $cp = mb_ord($c, 'UTF-8') - 0x10000;
        $u = $high ? 0xD800 + ($cp >> 10) : 0xDC00 + ($cp & 0x3FF);
        return chr(0xE0 | ($u >> 12)) . chr(0x80 | (($u >> 6) & 0x3F)) . chr(0x80 | ($u & 0x3F));
    }

    /** `s.slice(start, end)` by UTF-16 code units (a cut surrogate pair leaves its lone half). */
    public static function u16slice(string $s, int $start, ?int $end = null): string
    {
        $units = [];
        foreach (self::chars($s) as $c) {
            if (strlen($c) === 4) {
                $units[] = self::surrogate($c, true);
                $units[] = self::surrogate($c, false);
            } else {
                $units[] = $c;
            }
        }
        $n = count($units);
        $end ??= $n;
        if ($start < 0) {
            $start = max(0, $n + $start);
        }
        $end = min($end, $n);
        $out = '';
        for ($i = $start; $i < $end; $i++) {
            // a high surrogate followed by its low half re-joins into the four-byte character
            if ($i + 1 < $end && strlen($units[$i]) === 3 && ord($units[$i][0]) === 0xED && (ord($units[$i][1]) & 0xF0) === 0xA0
                && strlen($units[$i + 1]) === 3 && ord($units[$i + 1][0]) === 0xED && (ord($units[$i + 1][1]) & 0xF0) >= 0xB0) {
                $hi = 0xD000 | ((ord($units[$i][1]) & 0x3F) << 6) | (ord($units[$i][2]) & 0x3F);
                $lo = 0xD000 | ((ord($units[$i + 1][1]) & 0x3F) << 6) | (ord($units[$i + 1][2]) & 0x3F);
                $out .= mb_chr(0x10000 + (($hi - 0xD800) << 10) + ($lo - 0xDC00), 'UTF-8');
                $i++;
                continue;
            }
            $out .= $units[$i];
        }
        return $out;
    }

    private static function m(mixed $o, string $k): mixed
    {
        return Js::opt($o, $k);
    }

    // ---- cells --------------------------------------------------------------------------------------------------------------

    /** @return list<array{lo:int|float,hi:int|float}> */
    public static function numCells(mixed $d): array
    {
        $out = [];
        $lo = self::m($d, 'lo');
        $hi = self::m($d, 'hi');
        $cur = $lo;
        foreach (self::m($d, 'cuts') as $c) {
            if ($c < $lo || $c > $hi) {
                continue;
            }
            if ($cur <= $c - 1) {
                $out[] = ['lo' => $cur, 'hi' => $c - 1];
            }
            $out[] = ['lo' => $c, 'hi' => $c];
            $cur = $c + 1;
        }
        if ($cur <= $hi) {
            $out[] = ['lo' => $cur, 'hi' => $hi];
        }
        return $out;
    }

    public static function cellCount(mixed $d): int
    {
        return self::m($d, 'kind') === 'num' ? count(self::numCells($d)) : count(self::m($d, 'values'));
    }

    public static function verbCellCount(mixed $vs): int
    {
        $n = 1;
        foreach (self::m($vs, 'dims') as $d) {
            $n *= self::cellCount($d);
        }
        return $n;
    }

    /** @return list<int> */
    public static function decodeCell(mixed $vs, mixed $flat): array
    {
        $dims = self::m($vs, 'dims');
        $idx = array_fill(0, count($dims), 0);
        $flat = (int)Js::num($flat);
        for ($i = count($dims) - 1; $i >= 0; $i--) {
            $n = self::cellCount($dims[$i]);
            $idx[$i] = $flat % $n;
            $flat = intdiv($flat, $n);
        }
        return $idx;
    }

    public static function catCellOf(mixed $d, string $s): int
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
        if (self::m($d, 'kind') === 'num') {
            if (!self::isFiniteNumber($x)) {
                return -1;
            }
            $f = Js::num($x);
            foreach (self::numCells($d) as $i => $c) {
                if ($f >= $c['lo'] && $f <= $c['hi']) {
                    return $i;
                }
            }
            return -1;
        }
        if (!is_string($x)) {
            return -1;
        }
        return self::catCellOf($d, $x);
    }

    /** @return list<int>|null */
    public static function cellOf(mixed $vs, mixed $o): ?array
    {
        $idx = [];
        $values = self::m($o, 'values');
        foreach (self::m($vs, 'dims') as $d) {
            $i = self::cellOfValue($d, Js::isObj($values) ? self::m($values, self::m($d, 'path')) : null);
            if ($i < 0) {
                return null;
            }
            $idx[] = $i;
        }
        return $idx;
    }

    public static function catRep(mixed $d, int $i): string
    {
        $v = self::m($d, 'values')[$i];
        $val = self::m($v, 'value');
        if (self::m($v, 'kind') === 'exact') {
            return $val;
        }
        $base = self::m($v, 'kind') === 'prefix' ? $val . 'x' : 'other';
        for ($k = 0; $k < 64; $k++) {
            $s = $base . ($k === 0 ? '' : (string)$k);
            if (self::catCellOf($d, $s) === $i) {
                return $s;
            }
        }
        return $base;
    }

    public static function numRep(mixed $d, int $i): int|float
    {
        $c = self::numCells($d)[$i];
        return $i > 0 ? $c['lo'] : $c['hi'];
    }

    public static function repValue(mixed $d, int $i): mixed
    {
        return self::m($d, 'kind') === 'num' ? self::numRep($d, $i) : self::catRep($d, $i);
    }

    /** @param list<int> $idx */
    public static function cellRep(mixed $vs, array $idx): Obj
    {
        $values = new Obj();
        foreach (self::m($vs, 'dims') as $i => $d) {
            $values->set(self::m($d, 'path'), self::repValue($d, $idx[$i]));
        }
        return Obj::of(['verb' => self::m($vs, 'verb'), 'values' => $values]);
    }

    public static function labelOf(string $path): string
    {
        if ($path === 'action.resource') {
            return 'resource';
        }
        $parts = explode('.', $path);
        return str_replace('_', ' ', $parts[count($parts) - 1]);
    }

    // ---- workload and harm --------------------------------------------------------------------------------------------------

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

    private static function loguniform(mixed $d): bool
    {
        return self::m($d, 'dist') === 'loguniform' && self::m($d, 'lo') >= 0;
    }

    public static function intervalWeight(mixed $d, int|float $a, int|float $b): int|float
    {
        if ($b < $a) {
            return 0;
        }
        if (!self::loguniform($d)) {
            return $b - $a + 1;
        }
        if ($b - $a + 1 <= self::EXACT_SPAN) {
            $s = 0.0;
            for ($x = (int)$b; $x >= $a; $x--) {
                $s += 1 / ($x + 1);
            }
            return $s;
        }
        return self::harmonic($b + 1) - self::harmonic($a);
    }

    private static function firstMoment(mixed $d, int|float $a, int|float $b): int|float
    {
        if ($b < $a) {
            return 0;
        }
        if (!self::loguniform($d)) {
            return (((float)($a + $b)) * ((float)($b - $a + 1))) / 2;
        }
        return ($b - $a + 1) - self::intervalWeight($d, $a, $b);
    }

    private static function intervalMeanX(mixed $d, int|float $a, int|float $b, int|float $cellLo): int|float
    {
        $whole = self::intervalWeight($d, $cellLo, $b);
        return $whole > 0 ? self::firstMoment($d, $a, $b) / $whole : 0;
    }

    private static function linearAmount(mixed $d): bool
    {
        return self::m($d, 'kind') === 'num' && preg_match('/(^|\.)amount\z/', (string)self::m($d, 'path')) === 1;
    }

    public static function defaultHarm(): HarmModel
    {
        return self::$defaultHarm ??= new HarmModel(
            static function (mixed $vs): float {
                $r = Js::opt($vs, 'reversibility');
                return $r === 'irreversible' ? 10 : ($r === 'rate_limited' ? 3 : 1);
            },
            static fn(mixed $d, mixed $x): float => self::linearAmount($d) && Js::isNum($x) ? 1 + max(0, Js::num($x)) / 100 : 1,
            static fn(mixed $d, int $lo, int $hi): float => self::linearAmount($d) ? 1 + max(0, self::intervalMeanX($d, max($lo, 0), $hi, $lo)) / 100 : 1,
        );
    }

    private static function pointWeight(mixed $d, int $x): float
    {
        return self::loguniform($d) ? 1 / ($x + 1) : 1;
    }

    private static function intervalHarm(mixed $d, int $a, int $b, HarmModel $harm): float
    {
        if ($harm->dimMean !== null) {
            return ($harm->dimMean)($d, $a, $b);
        }
        $n = $b - $a + 1;
        $wTot = self::intervalWeight($d, $a, $b);
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
        for ($i = 0; $i < 1024; $i++) {
            $pa = $a + intdiv($i * $n, 1024);
            $pb = $a + intdiv(($i + 1) * $n, 1024) - 1;
            if ($pb < $pa) {
                continue;
            }
            $w = self::intervalWeight($d, $pa, $pb);
            $s += $w * ($harm->dim)($d, (int)floor(($pa + $pb) / 2 + 0.5));
        }
        return $s / $wTot;
    }

    /** @return array{mass:float,harm:float} */
    public static function dimCellStats(mixed $d, int $i, ?HarmModel $harm = null): array
    {
        $harm ??= self::defaultHarm();
        if (self::m($d, 'kind') === 'cat') {
            return ['mass' => 1 / count(self::m($d, 'values')), 'harm' => ($harm->dim)($d, self::catRep($d, $i))];
        }
        $c = self::numCells($d)[$i];
        $wm = self::intervalWeight($d, $c['lo'], $c['hi']);
        $total = self::intervalWeight($d, self::m($d, 'lo'), self::m($d, 'hi'));
        return ['mass' => $wm / $total, 'harm' => $wm > 0 ? self::intervalHarm($d, $c['lo'], $c['hi'], $harm) : ($harm->dim)($d, $c['lo'])];
    }

    /**
     * Exact mu(cell) and E[h | cell] for a whole cell (product measure, separable harm).
     * @param list<int> $idx
     * @return array{mass:float,harm:float}
     */
    public static function cellStats(mixed $vs, array $idx, ?HarmModel $harm = null): array
    {
        $harm ??= self::defaultHarm();
        $mass = self::m($vs, 'weight');
        $h = ($harm->verb)($vs);
        foreach (self::m($vs, 'dims') as $k => $d) {
            $s = self::dimCellStats($d, $idx[$k], $harm);
            $mass *= $s['mass'];
            $h *= $s['harm'];
        }
        return ['mass' => $mass, 'harm' => $h];
    }

    // ---- exact Clopper-Pearson upper bound ----------------------------------------------------------------------------------

    /** @return list<float> */
    private static function logFactorials(int $n): array
    {
        $lf = array_fill(0, $n + 1, 0.0);
        for ($i = 1; $i <= $n; $i++) {
            $lf[$i] = $lf[$i - 1] + log($i);
        }
        return $lf;
    }

    /** @param list<float> $lf */
    private static function binomialCdf(int $k, int $n, float $p, array $lf): float
    {
        if ($k >= $n) {
            return 1;
        }
        if ($k < 0) {
            return 0;
        }
        if ($p <= 0) {
            return 1;
        }
        if ($p >= 1) {
            return 0;
        }
        $lp = log($p);
        $lq = log1p(-$p);
        $s = 0.0;
        for ($i = 0; $i <= $k; $i++) {
            $s += exp($lf[$n] - $lf[$i] - $lf[$n - $i] + $i * $lp + ($n - $i) * $lq);
        }
        return min(1, $s);
    }

    private static function cdfRecNumerator(int $n, int $k, int $a): \GMP
    {
        $A = 1 << self::GRID_BITS;
        $b = $A - $a;
        $kk = min($k, $n);
        $row = array_fill(0, $kk + 1, gmp_init(1));
        $pw = gmp_init(1);
        for ($m = 0; $m < $n; $m++) {
            $nxt = [];
            $pwNext = gmp_mul($pw, $A);
            for ($j = 0; $j <= $kk; $j++) {
                if ($j >= $m + 1) {
                    $nxt[$j] = $pwNext;
                } else {
                    $left = $j === 0 ? gmp_init(0) : $row[$j - 1];
                    $nxt[$j] = gmp_add(gmp_mul($a, $left), gmp_mul($b, $row[$j]));
                }
            }
            $row = $nxt;
            $pw = $pwNext;
        }
        return $row[$kk];
    }

    /** @param array{0:int,1:int} $alpha numerator and the power of two of the denominator */
    private static function cdfExceeds(int $n, int $k, int $a, array $alpha): bool
    {
        [$num, $exp] = $alpha;
        $A = 1 << self::GRID_BITS;
        return gmp_cmp(gmp_mul(self::cdfRecNumerator($n, $k, $a), gmp_pow(2, $exp)), gmp_mul($num, gmp_pow($A, $n))) > 0;
    }

    private static function floatGuess(int $k, int $n, float $alpha): float
    {
        $lf = self::logFactorials($n);
        $lo = $k / $n;
        $hi = 1.0;
        for ($it = 0; $it < 200 && $hi - $lo > 1e-13; $it++) {
            $mid = ($lo + $hi) / 2;
            if (self::binomialCdf($k, $n, $mid, $lf) > $alpha) {
                $lo = $mid;
            } else {
                $hi = $mid;
            }
        }
        return $hi;
    }

    private static function clamp(int $a): int
    {
        $A = 1 << self::GRID_BITS;
        return $a < 0 ? 0 : ($a > $A ? $A : $a);
    }

    private static function certifyBracket(int $start, \Closure $exceeds): int
    {
        $hi = $start;
        $step = self::TOL_UNITS;
        while ($exceeds($hi)) {
            $hi = self::clamp($hi + $step);
            $step *= 2;
        }
        $lo = self::clamp($hi - self::TOL_UNITS);
        $step = self::TOL_UNITS;
        while ($lo > 0 && !$exceeds($lo)) {
            $hi = $lo;
            $lo = self::clamp($lo - $step);
            $step *= 2;
        }
        if ($lo === 0 && !$exceeds(0)) {
            throw new \InvalidArgumentException('clopperPearsonUpper: unreachable (cdfRec(0) = 1)');
        }
        while ($hi - $lo > self::TOL_UNITS) {
            $mid = intdiv($lo + $hi, 2);
            if ($exceeds($mid)) {
                $lo = $mid;
            } else {
                $hi = $mid;
            }
        }
        return $hi;
    }

    /** @return array{0:int,1:int} the exact ratio of a float in (0, 1): numerator and the exponent of the power-of-two denominator */
    private static function ratio(float $x): array
    {
        $bits = (int)unpack('J', pack('E', $x))[1];
        $e = ($bits >> 52) & 0x7FF;
        $mant = $bits & ((1 << 52) - 1);
        if ($e !== 0) {
            $mant |= 1 << 52;
        } else {
            $e = 1;
        }
        $exp = 1075 - $e; // x = mant / 2^exp
        while ($exp > 0 && ($mant & 1) === 0) {
            $mant >>= 1;
            $exp--;
        }
        return [$mant, $exp];
    }

    /** One-sided Clopper-Pearson upper bound after k successes in n, rounded outward on the 2^-52 grid (exact integer arithmetic). */
    public static function clopperPearsonUpper(mixed $k, mixed $n, mixed $alpha): float
    {
        $fk = Js::num($k);
        $fn = Js::num($n);
        if ($fk === null || $fn === null || $fk != floor($fk) || $fn != floor($fn) || is_infinite($fk) || is_infinite($fn) || !($fk >= 0) || !($fn >= 0) || !($fk <= $fn)) {
            throw new \InvalidArgumentException('clopperPearsonUpper: need integers 0 <= k <= n');
        }
        $fa = Js::num($alpha);
        if ($fa === null || !($fa > 0 && $fa < 1)) {
            throw new \InvalidArgumentException('clopperPearsonUpper: alpha must be in (0, 1)');
        }
        $k = (int)$fk;
        $n = (int)$fn;
        if ($n === 0 || $k === $n) {
            return 1.0;
        }
        $al = self::ratio($fa);
        $start = self::clamp((int)ceil(self::floatGuess($k, $n, $fa) * 4503599627370496.0) + self::TOL_UNITS);
        $hi = self::certifyBracket($start, static fn(int $a): bool => self::cdfExceeds($n, $k, $a, $al));
        return $hi / 4503599627370496.0;
    }
}
