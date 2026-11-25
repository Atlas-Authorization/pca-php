<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * A source of uniform field elements: deterministic SplitMix64 (low 64 bits of the seed) drawing unbiased elements by rejection
 * sampling, or, from secure(), fresh random bytes rejection sampled the same way. The 64-bit state is a GMP value because PHP
 * integers do not wrap.
 */
final class MpcFieldRng
{
    private \GMP $s;
    private \GMP $m64;
    private \GMP $limit;
    private \GMP $c0;
    private \GMP $c1;
    private \GMP $c2;

    public function __construct(?\GMP $seed = null, private readonly bool $secure = false)
    {
        $this->m64 = gmp_pow(2, 64);
        $this->limit = gmp_sub($this->m64, 8); // the largest multiple of p inside 64 bits is 2^64 - 8, so `mod p` stays uniform
        $this->c0 = gmp_init('9e3779b97f4a7c15', 16);
        $this->c1 = gmp_init('bf58476d1ce4e5b9', 16);
        $this->c2 = gmp_init('94d049bb133111eb', 16);
        $this->s = gmp_mod($seed ?? gmp_init('243f6a8885a308d3', 16), $this->m64);
    }

    public static function secure(): self
    {
        return new self(gmp_init(0), true);
    }

    public function nextU64(): \GMP
    {
        if ($this->secure) {
            return gmp_init(bin2hex(random_bytes(8)), 16);
        }
        $this->s = gmp_mod(gmp_add($this->s, $this->c0), $this->m64);
        $z = $this->s;
        $z = gmp_mod(gmp_mul(gmp_xor($z, gmp_div_q($z, 1 << 30)), $this->c1), $this->m64);
        $z = gmp_mod(gmp_mul(gmp_xor($z, gmp_div_q($z, 1 << 27)), $this->c2), $this->m64);
        return gmp_xor($z, gmp_div_q($z, 1 << 31));
    }

    public function next(): \GMP
    {
        while (true) {
            $u = $this->nextU64();
            if (gmp_cmp($u, $this->limit) < 0) {
                return gmp_mod($u, MpcField::prime());
            }
        }
    }
}
