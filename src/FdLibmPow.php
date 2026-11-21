<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * `Math.pow` of the reference: fdlibm's __ieee754_pow (e_pow.c), statement for statement with the same constants, plus the
 * reference language's rule that (+-1) ** +-Infinity is NaN. Method: log2(x) to extra precision as w1 + w2,
 * y * log2(x) = n + y' with |y'| <= 0.5, x**y = 2**n * exp(y' * ln2). The C library's pow() may round differently in the last
 * unit; this routine does not depend on it. The constants are the shortest decimals that read back as fdlibm's doubles.
 */
final class FdLibmPow
{
    private const SIGNIF = 0x7fffffff;

    /** Wraps to a signed 32-bit integer. */
    private static function i32(int $v): int
    {
        $v &= 0xffffffff;
        return $v >= 0x80000000 ? $v - 0x100000000 : $v;
    }

    private static function bits(float $x): int
    {
        return unpack('P', pack('e', $x))[1];
    }

    private static function fromBits(int $b): float
    {
        return unpack('e', pack('P', $b))[1];
    }

    /** The high word as a signed 32-bit integer. */
    private static function hi(float $x): int
    {
        return self::i32(self::bits($x) >> 32);
    }

    /** The low word as a signed 32-bit integer. */
    private static function lo(float $x): int
    {
        return self::i32(self::bits($x));
    }

    private static function setHi(float $x, int $h): float
    {
        return self::fromBits((($h & 0xffffffff) << 32) | (self::bits($x) & 0xffffffff));
    }

    /** x with its low word cleared. */
    private static function lo0(float $x): float
    {
        return self::fromBits(self::bits($x) & ~0xffffffff);
    }

    /** z * 2**n for a result below the normal range (fdlibm scalbn: one rounding, in the final multiply by 2**-54). */
    private static function scalbnTiny(float $z, int $n): float
    {
        $k = ((self::hi($z) & 0x7ff00000) >> 20) + $n;
        if ($k <= -54) {
            return 0.0;
        }
        return self::setHi($z, (self::hi($z) & ~0x7ff00000) | (($k + 54) << 20)) * 5.551115123125783e-17; // 2**-54
    }

    public static function pow(int|float $x, int|float $y): float
    {
        $x = (float) $x;
        $y = (float) $y;
        // y == zero: x**0 = 1
        if ($y == 0.0) {
            return 1.0;
        }
        // NaN propagates
        if (is_nan($x) || is_nan($y)) {
            return NAN;
        }

        $yAbs = abs($y);
        $xAbs = abs($x);
        // special values of y
        if ($y == 2.0) {
            return $x * $x;
        } elseif ($y == 0.5) {
            if ($x >= -PHP_FLOAT_MAX) {
                return sqrt($x + 0.0); // x == -infinity is handled later; + 0.0 for x == -0.0
            }
        } elseif ($yAbs == 1.0) {
            return $y == 1.0 ? $x : fdiv(1.0, $x);
        } elseif ($yAbs == INF) {
            if ($xAbs == 1.0) {
                return NAN; // (+-1)**+-inf is NaN
            } elseif ($xAbs > 1.0) {
                return $y >= 0 ? $y : 0.0; // (|x| > 1)**+-inf = inf, 0
            }
            return $y < 0 ? -$y : 0.0; // (|x| < 1)**-+inf = inf, 0
        }

        $hx = self::hi($x);
        $ix = $hx & self::SIGNIF;

        // yIsInt = 0: y is not an integer, 1: y is an odd integer, 2: y is an even integer (only needed for x < 0)
        $yIsInt = 0;
        if ($hx < 0) {
            if ($yAbs >= 9007199254740992.0) {
                $yIsInt = 2; // even: ulp(2^53) = 2
            } elseif ($yAbs >= 1.0) {
                $yAbsAsLong = (int) $yAbs;
                if ((float) $yAbsAsLong == $yAbs) {
                    $yIsInt = 2 - ($yAbsAsLong & 1);
                }
            }
        }

        // special values of x
        if ($xAbs == 0.0 || $xAbs == INF || $xAbs == 1.0) {
            $z = $xAbs; // x is +-0, +-inf, +-1
            if ($y < 0.0) {
                $z = fdiv(1.0, $z);
            }
            if ($hx < 0) {
                if ((self::i32($ix - 0x3ff00000) | $yIsInt) === 0) {
                    $z = NAN; // (-1)**non-int is NaN
                } elseif ($yIsInt === 1) {
                    $z = -1.0 * $z; // (x < 0)**odd = -(|x|**odd)
                }
            }
            return $z;
        }

        $n = ($hx >> 31) + 1;
        // (x < 0)**(non-int) is NaN
        if (($n | $yIsInt) === 0) {
            return NAN;
        }

        $s = 1.0; // sign of the result: -1 for (negative)**(odd integer)
        if (($n | ($yIsInt - 1)) === 0) {
            $s = -1.0;
        }

        // |y| is huge
        if ($yAbs > 2147485695.9999995) { // |y| > ~2**31
            $invLn2 = 1.4426950408889634;     // 1/ln2
            $invLn2H = 1.4426946640014648;    // 21 bits of 1/ln2
            $invLn2L = 3.768874985636099e-07; // 1/ln2 tail
            // over/underflow if x is not close to one
            if ($xAbs < 0.9999995231628418) {
                return $y < 0.0 ? $s * INF : $s * 0.0;
            }
            if ($xAbs > 1.0000009536743162) {
                return $y > 0.0 ? $s * INF : $s * 0.0;
            }
            // now |1 - x| is tiny <= 2**-20: log(x) by x - x^2/2 + x^3/3 - x^4/4
            $t = $xAbs - 1.0; // t has 20 trailing zeros
            $w = ($t * $t) * (0.5 - $t * (0.3333333333333333333333 - $t * 0.25));
            $u = $invLn2H * $t; // invLn2H has 21 significant bits
            $v = $t * $invLn2L - $w * $invLn2;
            $t1 = $u + $v;
            $t1 = self::lo0($t1);
            $t2 = $v - ($t1 - $u);
        } else {
            $cp = 0.9617966939259756;     // 2/(3 ln2)
            $cpH = 0.9617967009544373;    // (float)cp
            $cpL = -7.028461650952758e-09; // tail of cpH
            $n = 0;
            // subnormal x
            if ($ix < 0x00100000) {
                $xAbs *= 9007199254740992.0;
                $n -= 53;
                $ix = self::hi($xAbs);
            }
            $n += ($ix >> 20) - 0x3ff;
            $j = $ix & 0x000fffff;
            // determine the interval
            $ix = $j | 0x3ff00000; // normalize ix
            if ($j <= 0x3988E) {
                $k = 0; // |x| < sqrt(3/2)
            } elseif ($j < 0xBB67A) {
                $k = 1; // |x| < sqrt(3)
            } else {
                $k = 0;
                $n += 1;
                $ix -= 0x00100000;
            }
            $xAbs = self::setHi($xAbs, $ix);

            // ss = sH + sL = (x - 1)/(x + 1) or (x - 1.5)/(x + 1.5)
            $dpH = 0.5849624872207642;
            $dpL = 1.350039202129749e-08;
            // polynomial coefficients for (3/2)*(log(x) - 2s - 2/3*s**3)
            $l1 = 0.5999999999999946;
            $l2 = 0.4285714285785502;
            $l3 = 0.33333332981837743;
            $l4 = 0.272728123808534;
            $l5 = 0.23066074577556175;
            $l6 = 0.20697501780033842;
            $kD = (float) $k;
            $bpK = 1.0 + 0.5 * $kD; // BP[0] = 1.0, BP[1] = 1.5
            $u = $xAbs - $bpK;
            $v = 1.0 / ($xAbs + $bpK);
            $ss = $u * $v;
            $sH = self::lo0($ss);
            // tH = xAbs + BP[k], high part
            $tH = self::setHi(0.0, self::i32((($ix >> 1) | 0x20000000) + 0x00080000 + ($k << 18)));
            $tL = $xAbs - ($tH - $bpK);
            $sL = $v * (($u - $sH * $tH) - $sH * $tL);
            // log(xAbs)
            $s2 = $ss * $ss;
            $r = $s2 * $s2 * ($l1 + $s2 * ($l2 + $s2 * ($l3 + $s2 * ($l4 + $s2 * ($l5 + $s2 * $l6)))));
            $r += $sL * ($sH + $ss);
            $s2 = $sH * $sH;
            $tH = 3.0 + $s2 + $r;
            $tH = self::lo0($tH);
            $tL = $r - (($tH - 3.0) - $s2);
            // u + v = ss * (1 + ...)
            $u = $sH * $tH;
            $v = $sL * $tH + $tL * $ss;
            // 2/(3 log2) * (ss + ...)
            $pH = $u + $v;
            $pH = self::lo0($pH);
            $pL = $v - ($pH - $u);
            $zH = $cpH * $pH; // cpH + cpL = 2/(3 log2)
            $zL = $cpL * $pH + $pL * $cp + $dpL * $kD;
            // log2(xAbs) = (ss + ...) * 2/(3 log2) = n + dpH + zH + zL
            $t = (float) $n;
            $t1 = ((($zH + $zL) + $dpH * $kD) + $t);
            $t1 = self::lo0($t1);
            $t2 = $zL - ((($t1 - $t) - $dpH * $kD) - $zH);
        }

        // split y into y1 + y2 and compute (y1 + y2) * (t1 + t2)
        $y1 = self::lo0($y);
        $pL = ($y - $y1) * $t1 + $y * $t2;
        $pH = $y1 * $t1;
        $z = $pL + $pH;
        $j = self::hi($z);
        $i = self::lo($z);
        if ($j >= 0x40900000) { // z >= 1024
            if ($j !== 0x40900000 || $i !== 0) { // z > 1024
                return $s * INF; // overflow
            }
            $ovt = 8.0085662595372944372e-0017; // -(1024 - log2(ovfl + .5ulp))
            if ($pL + $ovt > $z - $pH) {
                return $s * INF; // overflow
            }
        } elseif (($j & self::SIGNIF) >= 0x4090cc00) { // z <= -1075
            if ($j !== self::i32(0xc090cc00) || $i !== 0) { // z < -1075
                return $s * 0.0; // underflow
            }
            if ($pL <= $z - $pH) {
                return $s * 0.0; // underflow
            }
        }

        // 2**(pH + pL)
        $p1 = 0.16666666666666602;
        $p2 = -0.0027777777777015593;
        $p3 = 6.613756321437934e-05;
        $p4 = -1.6533902205465252e-06;
        $p5 = 4.1381367970572385e-08;
        $lg2 = 0.6931471805599453;
        $lg2H = 0.6931471824645996;
        $lg2L = -1.904654299957768e-09;
        $i = $j & self::SIGNIF;
        $k = ($i >> 20) - 0x3ff;
        $n = 0;
        if ($i > 0x3fe00000) { // |z| > 0.5: n = [z + 0.5]
            $n = self::i32($j + (0x00100000 >> ($k + 1)));
            $k = (($n & self::SIGNIF) >> 20) - 0x3ff; // new k for n
            $t = self::setHi(0.0, $n & ~(0x000fffff >> $k));
            $n = (($n & 0x000fffff) | 0x00100000) >> (20 - $k);
            if ($j < 0) {
                $n = -$n;
            }
            $pH -= $t;
        }
        $t = $pL + $pH;
        $t = self::lo0($t);
        $u = $t * $lg2H;
        $v = ($pL - ($t - $pH)) * $lg2 + $t * $lg2L;
        $z = $u + $v;
        $w = $v - ($z - $u);
        $t = $z * $z;
        $t1 = $z - $t * ($p1 + $t * ($p2 + $t * ($p3 + $t * ($p4 + $t * $p5))));
        $r = ($z * $t1) / ($t1 - 2.0) - ($w + $z * $w);
        $z = 1.0 - ($r - $z);
        $j = self::i32(self::hi($z) + ($n << 20));
        if (($j >> 20) <= 0) {
            $z = self::scalbnTiny($z, $n); // subnormal output
        } else {
            $z = self::setHi($z, $j);
        }
        return $s * $z;
    }
}
