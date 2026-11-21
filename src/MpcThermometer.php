<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** Thermometer (unary) encoding of a bounded integer: ge[k] = [v >= k] for k = 1..M, so MAX is a position-wise OR. */
final class MpcThermometer
{
    /**
     * Encodes v in {0..M}; v is clamped into range (fail-safe). v is a JS number (non-finite clamps like Math.trunc).
     *
     * @return list<int>
     */
    public static function thermometerEncode(float $v, int $M): array
    {
        if ($M < 0) {
            throw new \InvalidArgumentException('thermometerEncode: M must be a non-negative integer');
        }
        $tr = is_nan($v) ? NAN : ($v < 0 ? ceil($v) : floor($v));
        $clamped = is_nan($tr) ? NAN : max(0.0, min((float) $M, $tr));
        $bits = [];
        for ($k = 1; $k <= $M; $k++) {
            $bits[] = $clamped >= $k ? 1 : 0; // NaN compares false: all zero
        }
        return $bits;
    }

    /** Number of 1s (robust to non-monotone input). @param list<int|\GMP> $bits */
    public static function thermometerDecode(array $bits): int
    {
        $c = 0;
        foreach ($bits as $b) {
            if ($b instanceof \GMP ? gmp_cmp($b, 1) === 0 : $b === 1) {
                $c++;
            }
        }
        return $c;
    }
}
