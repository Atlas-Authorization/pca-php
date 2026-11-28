<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Word-array kernels for the OT-extension hot path: AES-128-CTR column PRG, 32x32 bit transposes, GF(2^128) on four little-endian
 * u32 words, and the batched tweakable correlation-robust hash H(x, t) = pi(pi(x) ^ t) ^ pi(x) with a fixed-key AES-128 truncated to
 * 64 bits. A word array is a list of UNSIGNED 32-bit values held in PHP ints. AES comes from ext-openssl.
 */
final class MpcOtx
{
    /** Number of bit columns of the IKNP matrix (kappa). */
    public const COLS = 128;
    private const M32 = 0xFFFFFFFF;

    /** Little-endian bytes of a non-negative bigint, exactly $len bytes (the low bytes). */
    public static function bigToBytes(\GMP $v, int $len): string
    {
        return MpcEc::le($v, $len);
    }

    /** The bigint with the given little-endian bytes. */
    public static function bytesToBig(string $b): \GMP
    {
        return $b === '' ? gmp_init(0) : gmp_init(bin2hex(strrev($b)), 16);
    }

    private static function prgKey(string $seed): string
    {
        return substr(hash('sha256', 'atlas-pca-mpc/ot-prg-aes' . $seed, true), 0, 16);
    }

    /** @return list<int> */
    public static function leWords(string $b, int $off, int $n): array
    {
        if ($n === 0) {
            return [];
        }
        return array_values(unpack('V' . $n, $b, $off));
    }

    /** @param list<int> $w */
    public static function leBytes(array $w, int $n): string
    {
        return $n === 0 ? '' : pack('V' . $n, ...array_slice($w, 0, $n));
    }

    /** $nwords u32 words of the PRG stream of $seed from AES block $startBlock (high tail bits unmasked). @return list<int> */
    public static function prgColumn(string $seed, int $startBlock, int $nwords): array
    {
        if ($nwords === 0) {
            return [];
        }
        $iv = str_repeat("\0", 8) . pack('J', $startBlock);
        $ks = openssl_encrypt(str_repeat("\0", $nwords * 4), 'aes-128-ctr', self::prgKey($seed), OPENSSL_RAW_DATA, $iv);
        if ($ks === false) {
            throw new \RuntimeException('AES-CTR failed');
        }
        return self::leWords($ks, 0, $nwords);
    }

    /** Clears the bits at positions >= $nbits in a little-endian word column. @param list<int> $col */
    public static function maskTail(array &$col, int $nbits): void
    {
        $full = $nbits >> 5;
        $rem = $nbits & 31;
        if ($rem !== 0) {
            $col[$full] &= (1 << $rem) - 1;
        }
        for ($i = $rem !== 0 ? $full + 1 : $full, $n = count($col); $i < $n; $i++) {
            $col[$i] = 0;
        }
    }

    /** In-place transpose of a 32x32 bit matrix held as 32 u32 words from $off. @param list<int> $a */
    public static function transpose32(array &$a, int $off): void
    {
        $m = 0x0000ffff;
        for ($j = 16; $j !== 0; $j >>= 1, $m = ($m ^ ($m << $j)) & self::M32) {
            for ($k = 0; $k < 32; $k = ($k + $j + 1) & ~$j) {
                $t = ((($a[$off + $k] >> $j) ^ $a[$off + $k + $j]) & $m);
                $a[$off + $k] ^= ($t << $j) & self::M32;
                $a[$off + $k + $j] ^= $t;
            }
        }
    }

    /**
     * Transposes COLS bit-columns (each $W words, concatenated) into $rows rows of four words.
     *
     * @param list<int> $cols @return list<int>
     */
    public static function transposeCols(array $cols, int $W, int $rows): array
    {
        $out = array_fill(0, $rows * 4, 0);
        $blocks = ($rows + 31) >> 5;
        for ($rb = 0; $rb < $blocks; $rb++) {
            for ($cb = 0; $cb < 4; $cb++) {
                $tmp = [];
                for ($c = 0; $c < 32; $c++) {
                    $tmp[$c] = $cols[($cb * 32 + $c) * $W + $rb];
                }
                self::transpose32($tmp, 0);
                $lim = min(32, $rows - $rb * 32);
                for ($r = 0; $r < $lim; $r++) {
                    $out[($rb * 32 + $r) * 4 + $cb] = $tmp[$r];
                }
            }
        }
        return $out;
    }

    /** acc ^= the four-word element at v[vo..]. @param list<int> $acc @param list<int> $v */
    public static function gfXorInto(array &$acc, array $v, int $vo): void
    {
        $acc[0] ^= $v[$vo];
        $acc[1] ^= $v[$vo + 1];
        $acc[2] ^= $v[$vo + 2];
        $acc[3] ^= $v[$vo + 3];
    }

    /** acc *= x in GF(2^128) (x^128 = x^7 + x^2 + x + 1). @param list<int> $acc */
    public static function gfMulX(array &$acc): void
    {
        $carry = $acc[3] >> 31;
        $acc[3] = (($acc[3] << 1) | ($acc[2] >> 31)) & self::M32;
        $acc[2] = (($acc[2] << 1) | ($acc[1] >> 31)) & self::M32;
        $acc[1] = (($acc[1] << 1) | ($acc[0] >> 31)) & self::M32;
        $acc[0] = (($acc[0] << 1) & self::M32) ^ ($carry !== 0 ? 0x87 : 0);
    }

    /**
     * XORs into $acc chi[j] (four words) for every set bit j of the word column col[off..off+len).
     *
     * @param list<int> $col @param list<int> $chi @param list<int> $acc
     */
    public static function accumColumn(array $col, int $off, int $len, array $chi, array &$acc): void
    {
        for ($w = 0; $w < $len; $w++) {
            $x = $col[$off + $w];
            $base = $w << 5;
            while ($x !== 0) {
                $j = $base + strlen(decbin($x & -$x)) - 1;
                $o = $j << 2;
                $acc[0] ^= $chi[$o];
                $acc[1] ^= $chi[$o + 1];
                $acc[2] ^= $chi[$o + 2];
                $acc[3] ^= $chi[$o + 3];
                $x &= $x - 1;
            }
        }
    }

    /**
     * sum_i x^i * (sum_{j in col_i} chi_j) by Horner over the columns: the KOS combination of both roles.
     *
     * @param list<int> $cols @param list<int> $chi @return list<int>
     */
    public static function kosCombine(array $cols, int $W, array $chi): array
    {
        $acc = [0, 0, 0, 0];
        for ($i = self::COLS - 1; $i >= 0; $i--) {
            self::gfMulX($acc);
            $part = [0, 0, 0, 0];
            self::accumColumn($cols, $i * $W, $W, $chi, $part);
            self::gfXorInto($acc, $part, 0);
        }
        return $acc;
    }

    /** @return list<int> */
    public static function gfFromBig(\GMP $v): array
    {
        $out = [];
        for ($i = 0; $i < 4; $i++) {
            $out[] = gmp_intval(gmp_and(gmp_div_q($v, gmp_pow(2, 32 * $i), GMP_ROUND_MINUSINF), 0xFFFFFFFF));
        }
        return $out;
    }

    /** @param list<int> $w */
    public static function gfToBig(array $w, int $off = 0): \GMP
    {
        $v = gmp_init(0);
        for ($i = 3; $i >= 0; $i--) {
            $v = gmp_add(gmp_mul($v, gmp_pow(2, 32)), $w[$off + $i]);
        }
        return $v;
    }

    private static function aesEcb(string $buf): string
    {
        if ($buf === '') {
            return '';
        }
        $key = substr(hash('sha256', 'atlas-pca-mpc/ot-crh-aes-fixed-key', true), 0, 16);
        $r = openssl_encrypt($buf, 'aes-128-ecb', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING);
        if ($r === false) {
            throw new \RuntimeException('AES-ECB failed');
        }
        return $r;
    }

    /** The 64-bit session domain of a channel: SHA-256(tag, binding)[0..8] as two little-endian words. @return list<int> */
    public static function otTweakDomain(string $binding): array
    {
        return self::leWords(hash('sha256', 'atlas-pca-mpc/ot-crh-tweak-domain/v2' . $binding, true), 0, 2);
    }

    /**
     * H(tweak, row_j) for n rows of four words: two u32 words per row (the low 64 bits of the TMMO hash). $tweak is
     * ['offset' => int, 'domain' => list<int>] or null.
     *
     * @param list<int> $rows @return list<int>
     */
    public static function tmmoCrh(array $rows, int $n, ?array $tweak): array
    {
        $offset = $tweak === null ? 0 : $tweak['offset'];
        $dom = $tweak === null ? [0, 0] : $tweak['domain'];
        if ($offset < 0 || $offset > 9007199254740991) {
            throw new \InvalidArgumentException('tmmoCrh: tweak offset must be a non-negative safe integer');
        }
        if (count($dom) !== 2) {
            throw new \InvalidArgumentException('tmmoCrh: tweak domain must be 2 words');
        }
        $aw = self::leWords(self::aesEcb(self::leBytes($rows, $n * 4)), 0, $n * 4);
        $b = [];
        for ($j = 0; $j < $n; $j++) {
            $o = $j * 4;
            $v = $offset + $j;
            $b[$o] = $aw[$o] ^ ($v & self::M32);
            $b[$o + 1] = $aw[$o + 1] ^ (($v >> 32) & self::M32);
            $b[$o + 2] = $aw[$o + 2] ^ $dom[0];
            $b[$o + 3] = $aw[$o + 3] ^ $dom[1];
        }
        $cw = self::leWords(self::aesEcb(self::leBytes($b, $n * 4)), 0, $n * 4);
        $out = [];
        for ($j = 0; $j < $n; $j++) {
            $out[] = $cw[4 * $j] ^ $aw[4 * $j];
            $out[] = $cw[4 * $j + 1] ^ $aw[4 * $j + 1];
        }
        return $out;
    }

    /** The 64-bit value of the two words at index j of a tmmoCrh output. @param list<int> $h */
    public static function word64(array $h, int $j): \GMP
    {
        return gmp_add(gmp_mul(gmp_init($h[2 * $j + 1]), gmp_pow(2, 32)), $h[2 * $j]);
    }
}
