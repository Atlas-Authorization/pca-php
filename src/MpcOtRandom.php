<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * A source of scalars and seeds for OT needs: the CSPRNG (secure()) or a deterministic SplitMix64 stream (fromSeed(), for
 * reproducible tests only). scalar() is uniform in [1, L); bytes($n) are $n random bytes (each 64-bit draw yields up to 8 bytes,
 * low byte first, and a partly used draw is discarded).
 */
final class MpcOtRandom
{
    private function __construct(private readonly ?MpcFieldRng $stream)
    {
    }

    public static function secure(): self
    {
        return new self(null);
    }

    public static function fromSeed(\GMP $seed): self
    {
        return new self(new MpcFieldRng($seed));
    }

    private function u64(): \GMP
    {
        return $this->stream !== null ? $this->stream->nextU64() : gmp_init(bin2hex(random_bytes(8)), 16);
    }

    public function scalar(): \GMP
    {
        $l = MpcEc::l();
        for ($attempt = 0; $attempt < 8; $attempt++) {
            $acc = gmp_init(0);
            for ($i = 0; $i < 4; $i++) {
                $acc = gmp_add(gmp_mul($acc, gmp_pow(2, 64)), $this->u64());
            }
            $s = gmp_mod($acc, $l);
            if (gmp_sign($s) !== 0) {
                return $s;
            }
        }
        throw new \RuntimeException('otRandom: entropy stream returned zero scalars repeatedly (RNG failure)');
    }

    public function bytes(int $n): string
    {
        $out = '';
        while (strlen($out) < $n) {
            $out .= strrev((string) hex2bin(str_pad(gmp_strval($this->u64(), 16), 16, '0', STR_PAD_LEFT)));
        }
        return substr($out, 0, $n);
    }
}
