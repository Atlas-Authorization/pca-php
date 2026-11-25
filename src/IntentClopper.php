<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';

/**
 * Exact Clopper-Pearson upper bounds in integer arithmetic (ext-gmp) at the dyadic points a / 2^52, as the formal definition is stated;
 * a floating-point bisection only supplies the starting guess. Bigints are GMP values.
 */
final class IntentClopper
{
    public const CP_GRID_BITS = 52;
    /** The certified tolerance of the Clopper-Pearson bound (CP_TOLERANCE): 2^-44, that is 2^(52 - 44) units of the 2^-52 grid. */
    public const CP_TOLERANCE = 5.684341886080802e-14;
    private const TOL_UNITS = 256; // 2^(52 - 44)

    private static function grid(): \GMP
    {
        return gmp_pow(2, self::CP_GRID_BITS);
    }

    /** @return list<float> */
    private static function logFactorials(int $n): array
    {
        $lf = array_fill(0, $n + 1, 0.0);
        for ($i = 1; $i <= $n; $i++) {
            $lf[$i] = $lf[$i - 1] + log($i);
        }
        return $lf;
    }

    /** P(X <= k) for X ~ Binomial(n, p) in floating point (guesses and diagnostics, never decisions). @param list<float>|null $lf */
    public static function binomialCdf(int|float $k, int|float $n, int|float $p, ?array $lf = null): int|float
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
        $lf ??= self::logFactorials((int)$n);
        $lp = log($p);
        $lq = log1p(-$p);
        $s = 0.0;
        for ($i = 0, $e = (int)floor($k); $i <= $e; $i++) {
            $s += exp($lf[(int)$n] - $lf[$i] - $lf[(int)$n - $i] + $i * $lp + ($n - $i) * $lq);
        }
        return min(1, $s);
    }

    /** The exact binary fraction of a double x in (0, 1): x = num / 2^exp. @return array{num:\GMP,exp:int} */
    public static function doubleToDyadic(mixed $x): array
    {
        $f = Js::num($x);
        if ($f === null || !is_finite($f) || !($f > 0 && $f < 1)) {
            throw new \InvalidArgumentException('doubleToDyadic: need 0 < x < 1');
        }
        $e = 0;
        $y = $f;
        while ($y != floor($y)) {
            $y *= 2;
            $e++;
            if ($e > 1100) {
                throw new \InvalidArgumentException('doubleToDyadic: not reached');
            }
        }
        return ['num' => gmp_init(sprintf('%.0f', $y)), 'exp' => $e];
    }

    /** The numerator N with cdfRec(a / 2^52, n, k) = N / 2^(52 n). */
    public static function cdfRecNumerator(int $n, int $k, \GMP|int $a): \GMP
    {
        $A = self::grid();
        if (gmp_cmp($a, 0) < 0 || gmp_cmp($a, $A) > 0) {
            throw new \InvalidArgumentException('cdfRecNumerator: a must be in [0, 2^52]');
        }
        $b = gmp_sub($A, $a);
        $kk = min($k, $n);
        $row = array_fill(0, $kk + 1, gmp_init(1));
        $pw = gmp_init(1);
        for ($m = 0; $m < $n; $m++) {
            $nxt = [];
            $pwNext = gmp_mul($pw, $A);
            for ($j = 0; $j <= $kk; $j++) {
                $nxt[$j] = $j >= $m + 1 ? $pwNext
                    : gmp_add(gmp_mul($a, $j === 0 ? gmp_init(0) : $row[$j - 1]), gmp_mul($b, $row[$j]));
            }
            $row = $nxt;
            $pw = $pwNext;
        }
        return $row[$kk];
    }

    /** Exactly decides alpha < cdfRec(a / 2^52, n, k). @param array{num:\GMP|int,exp:int} $alpha */
    public static function cdfExceeds(int $n, int $k, \GMP|int $a, array $alpha): bool
    {
        $lhs = gmp_mul(self::cdfRecNumerator($n, $k, $a), gmp_pow(2, $alpha['exp']));
        return gmp_cmp($lhs, gmp_mul($alpha['num'], gmp_pow(self::grid(), $n))) > 0;
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
        $A = 1 << self::CP_GRID_BITS;
        return $a < 0 ? 0 : ($a > $A ? $A : $a);
    }

    /** A bracket of at most the tolerance around the point where the antitone `exceeds` flips, from any start. @return array{hi:int,lo:int} */
    public static function certifyBracket(int $start, \Closure $exceeds): array
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
        return ['hi' => $hi, 'lo' => $lo];
    }

    private static function isInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f);
    }

    /** Exact one-sided upper bound with its certificate. @return array{upper:int|float,upperUnits:int,lowerUnits:int} */
    public static function clopperPearsonCertified(mixed $k, mixed $n, mixed $alpha): array
    {
        if (!(self::isInt($k) && self::isInt($n) && Js::num($k) >= 0 && Js::num($n) >= 0 && Js::num($k) <= Js::num($n))) {
            throw new \InvalidArgumentException('clopperPearsonUpper: need integers 0 <= k <= n');
        }
        $fa = Js::num($alpha);
        if ($fa === null || !($fa > 0 && $fa < 1)) {
            throw new \InvalidArgumentException('clopperPearsonUpper: alpha must be in (0, 1)');
        }
        $k = (int)Js::num($k);
        $n = (int)Js::num($n);
        $A = 1 << self::CP_GRID_BITS;
        if ($n === 0 || $k === $n) {
            return ['upper' => 1, 'upperUnits' => $A, 'lowerUnits' => $A];
        }
        $al = self::doubleToDyadic($fa);
        $start = self::clamp((int)ceil(self::floatGuess($k, $n, $fa) * 4503599627370496.0) + self::TOL_UNITS);
        $br = self::certifyBracket($start, static fn(int $a): bool => self::cdfExceeds($n, $k, $a, $al));
        return ['upper' => $br['hi'] / 4503599627370496.0, 'upperUnits' => $br['hi'], 'lowerUnits' => $br['lo']];
    }

    public static function clopperPearsonUpper(mixed $k, mixed $n, mixed $alpha): int|float
    {
        return self::clopperPearsonCertified($k, $n, $alpha)['upper'];
    }
}
