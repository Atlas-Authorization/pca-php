<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The seeded PRNG behind the invariant property generators: mulberry32 (the same 32-bit generator the other conformance
 * generators use, so its stream for a seed can be checked against any other implementation of it).
 *
 * The reference harness drives its properties through a property-testing library whose byte stream cannot be reproduced here
 * and no such library exists for PHP, so this runtime explores its OWN deterministic case streams. The seed scheme: one stream
 * per property, seeded from (seed, property index) by {@see forProperty}; a property draws `numRuns` cases from its stream.
 * The same (seed, index) therefore always gives the same cases, and another seed gives another stream.
 */
final class InvariantsRng
{
    private const MASK = 0xFFFFFFFF;

    private int $a;

    public function __construct(int $seed)
    {
        $this->a = $seed & self::MASK;
    }

    /** The stream of property number `$index` for `$seed` (the seed's high half is folded in, so any int seed is distinct). */
    public static function forProperty(int $seed, int $index): self
    {
        return new self((($seed ^ ($seed >> 32)) + $index * 0x9E3779B1) & self::MASK);
    }

    /** Math.imul on unsigned 32-bit operands (a plain product would overflow PHP's int). */
    private static function imul(int $a, int $b): int
    {
        return ((($a & 0xFFFF) * $b) + (((($a >> 16) & 0xFFFF) * $b & 0xFFFF) << 16)) & self::MASK;
    }

    /** The next float in [0, 1). */
    public function next(): float
    {
        $this->a = ($this->a + 0x6D2B79F5) & self::MASK;
        $t = $this->a;
        $t = self::imul($t ^ ($t >> 15), $t | 1);
        $t = ($t ^ (($t + self::imul($t ^ ($t >> 7), $t | 61)) & self::MASK)) & self::MASK;
        return (($t ^ ($t >> 14)) & self::MASK) / 4294967296.0;
    }

    /** A uniform integer in [lo, hi]. */
    public function int(int $lo, int $hi): int
    {
        return min($hi, $lo + (int)floor($this->next() * ($hi - $lo + 1)));
    }

    /** An integer in [lo, hi] that hits each bound about 6% of the time (edge cases are where properties break). */
    public function intB(int $lo, int $hi): int
    {
        $r = $this->next();
        return $r < 0.06 ? $lo : ($r < 0.12 ? $hi : $this->int($lo, $hi));
    }

    /** A float in [lo, hi] (never NaN) that hits each bound about 6% of the time. */
    public function dbl(float $lo, float $hi): float
    {
        $r = $this->next();
        return $r < 0.06 ? $lo : ($r < 0.12 ? $hi : $lo + $this->next() * ($hi - $lo));
    }

    public function bool(): bool
    {
        return $this->next() < 0.5;
    }

    /** @param list<mixed> $xs */
    public function pick(array $xs): mixed
    {
        return $xs[$this->int(0, count($xs) - 1)];
    }

    /** `$n` random bytes. */
    public function bytes(int $n): string
    {
        $s = '';
        for ($i = 0; $i < $n; $i++) {
            $s .= chr($this->int(0, 255));
        }
        return $s;
    }

    /** A printable-ASCII (0x20 to 0x7e) string of length min..max. */
    public function string(int $min, int $max): string
    {
        $n = $this->int($min, $max);
        $s = '';
        for ($i = 0; $i < $n; $i++) {
            $s .= chr($this->int(0x20, 0x7E));
        }
        return $s;
    }
}
