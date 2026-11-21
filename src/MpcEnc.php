<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Privacy-amplified OT choice-bit encoding (the selective-failure remedy): the receiver chooses with m = 61 + 3s uniform bits b
 * and takes x = sum g_k b_k (mod p) for a public gadget vector g. s = 0 is the legacy plain binary encoding. A receiver operand
 * (EncShare) is ['value' => GMP, 'bits' => list<int>].
 */
final class MpcEnc
{
    public const FIELD_BITS = 61;
    public const STAT_SEC = 64;
    public const MIN_STAT_SEC = 40;

    public static function encBits(int $s): int
    {
        return self::FIELD_BITS + 3 * $s;
    }

    /** @return list<\GMP> */
    public static function makeGadget(int $s, MpcFieldRng $rng, bool $unsafe = false): array
    {
        if ($s < 0 || $s > 64) {
            throw new \InvalidArgumentException('statSec must be an integer in [0, 64]');
        }
        if ($s < self::MIN_STAT_SEC && !$unsafe) {
            throw new \InvalidArgumentException("statSec $s is below " . self::MIN_STAT_SEC . ': refused (tests may pass the explicit unsafe flag)');
        }
        $m = self::encBits($s);
        $g = [];
        for ($k = 0; $k < $m; $k++) {
            $g[] = $s === 0 ? MpcField::mod(gmp_pow(2, $k)) : $rng->next();
        }
        return $g;
    }

    /** @param list<\GMP> $g @param list<int> $bits */
    public static function encValue(array $g, array $bits): \GMP
    {
        if (count($g) !== count($bits)) {
            throw new \InvalidArgumentException('encValue: gadget / bits length mismatch');
        }
        $v = gmp_init(0);
        foreach ($g as $k => $gk) {
            if ($bits[$k] === 1) {
                $v = gmp_add($v, $gk);
            }
        }
        return MpcField::mod($v);
    }

    /** @return array{value:\GMP,bits:list<int>} */
    public static function plainShare(\GMP $x): array
    {
        $v = MpcField::mod($x);
        $bits = [];
        for ($k = 0; $k < self::FIELD_BITS; $k++) {
            $bits[] = gmp_testbit($v, $k) ? 1 : 0;
        }
        return ['value' => $v, 'bits' => $bits];
    }

    /** @return list<\GMP> */
    public static function plainGadget(): array
    {
        $g = [];
        for ($k = 0; $k < self::FIELD_BITS; $k++) {
            $g[] = MpcField::mod(gmp_pow(2, $k));
        }
        return $g;
    }

    /** m uniform bits from a field source (the 60 low bits of each draw are uniform). @return list<int> */
    public static function randomBits(int $m, MpcFieldRng $rng): array
    {
        $out = [];
        $k = 0;
        while ($k < $m) {
            $w = $rng->next();
            for ($i = 0; $i < 60 && $k < $m; $i++, $k++) {
                $out[] = gmp_testbit($w, $i) ? 1 : 0;
            }
        }
        return $out;
    }

    /** @param list<\GMP> $g @return array{value:\GMP,bits:list<int>} */
    public static function sampleEnc(array $g, MpcFieldRng $rng): array
    {
        $bits = self::randomBits(count($g), $rng);
        return ['value' => self::encValue($g, $bits), 'bits' => $bits];
    }
}
