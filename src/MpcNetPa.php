<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Pairwise-authenticated field shares for the identifiable-abort mode of the networked runner: each share carries one tag per
 * verifier and one key per peer, so a bad opening is attributable to the party that sent it. The operations are linear and local.
 *
 * Records: PA ['x' => GMP, 'tag' => list<GMP>, 'key' => list<GMP>]; AW ['v' => PA, 'm' => list<PA>] (a value share plus one MAC
 * share per global key); env ['id' => int, 'n' => int, 'delta' => GMP, 'tagged' => bool].
 */
final class MpcNetPa
{
    private static function zip(array $a, array $b, callable $f): array
    {
        $o = [];
        foreach ($a as $i => $x) {
            $o[] = $f($x, $b[$i]);
        }
        return $o;
    }

    public static function paAdd(array $a, array $b): array
    {
        return ['x' => MpcField::fadd($a['x'], $b['x']), 'tag' => self::zip($a['tag'], $b['tag'], MpcField::fadd(...)), 'key' => self::zip($a['key'], $b['key'], MpcField::fadd(...))];
    }

    public static function paSub(array $a, array $b): array
    {
        return ['x' => MpcField::fsub($a['x'], $b['x']), 'tag' => self::zip($a['tag'], $b['tag'], MpcField::fsub(...)), 'key' => self::zip($a['key'], $b['key'], MpcField::fsub(...))];
    }

    public static function paNeg(array $a): array
    {
        return ['x' => MpcField::fneg($a['x']), 'tag' => array_map(MpcField::fneg(...), $a['tag']), 'key' => array_map(MpcField::fneg(...), $a['key'])];
    }

    public static function paScale(array $a, \GMP $c): array
    {
        $f = static fn(\GMP $t): \GMP => MpcField::fmul($t, $c);
        return ['x' => MpcField::fmul($a['x'], $c), 'tag' => array_map($f, $a['tag']), 'key' => array_map($f, $a['key'])];
    }

    /** Adds a PUBLIC constant to party 0's share (every party applies the same call). */
    public static function paAddPublic0(array $env, array $a, \GMP $c): array
    {
        if ($env['id'] === 0) {
            return ['x' => MpcField::fadd($a['x'], $c), 'tag' => $a['tag'], 'key' => $a['key']];
        }
        if (!$env['tagged']) {
            return $a;
        }
        $key = $a['key'];
        $key[0] = MpcField::fsub($key[0], MpcField::fmul($env['delta'], $c));
        return ['x' => $a['x'], 'tag' => $a['tag'], 'key' => $key];
    }

    public static function wAdd(array $a, array $b): array
    {
        return ['v' => self::paAdd($a['v'], $b['v']), 'm' => self::zip($a['m'], $b['m'], self::paAdd(...))];
    }

    public static function wSub(array $a, array $b): array
    {
        return ['v' => self::paSub($a['v'], $b['v']), 'm' => self::zip($a['m'], $b['m'], self::paSub(...))];
    }

    public static function wNeg(array $a): array
    {
        return ['v' => self::paNeg($a['v']), 'm' => array_map(self::paNeg(...), $a['m'])];
    }

    public static function wScale(array $a, \GMP $c): array
    {
        return ['v' => self::paScale($a['v'], $c), 'm' => array_map(static fn(array $p): array => self::paScale($p, $c), $a['m'])];
    }

    /** x + c for a PUBLIC c: party 0's value share moves by c and every MAC share moves by alpha_i * c. @param list<array> $alpha */
    public static function wAddPublic(array $env, array $a, \GMP $c, array $alpha): array
    {
        $m = [];
        foreach ($a['m'] as $l => $p) {
            $m[] = self::paAdd($p, self::paScale($alpha[$l], $c));
        }
        return ['v' => self::paAddPublic0($env, $a['v'], $c), 'm' => $m];
    }

    /** Verifies peer $from's opened share x with tag against my key for that peer. */
    public static function paVerify(array $env, array $a, int $from, \GMP $x, \GMP $tag): bool
    {
        return gmp_cmp(MpcField::fadd($a['key'][$from], MpcField::fmul($env['delta'], $x)), $tag) === 0;
    }

    // ---- wire codec ----

    public static function paWidth(int $n, bool $tagged): int
    {
        return $tagged ? 1 + 2 * ($n - 1) : 1;
    }

    /** @return list<\GMP> */
    public static function paFlat(array $a, int $id, int $n, bool $tagged): array
    {
        $out = [$a['x']];
        if ($tagged) {
            for ($j = 0; $j < $n; $j++) {
                if ($j !== $id) {
                    $out[] = $a['tag'][$j];
                }
            }
            for ($j = 0; $j < $n; $j++) {
                if ($j !== $id) {
                    $out[] = $a['key'][$j];
                }
            }
        }
        return $out;
    }

    /** @param list<\GMP> $nums */
    public static function paParse(array $nums, int $off, int $id, int $n, bool $tagged): array
    {
        $x = $nums[$off] ?? throw new \OutOfRangeException('paParse: short input');
        if (!$tagged) {
            return ['x' => $x, 'tag' => [], 'key' => []];
        }
        $tag = array_fill(0, $n, gmp_init(0));
        $key = array_fill(0, $n, gmp_init(0));
        $o = $off + 1;
        for ($j = 0; $j < $n; $j++) {
            if ($j !== $id) {
                $tag[$j] = $nums[$o++] ?? throw new \OutOfRangeException('paParse: short input');
            }
        }
        for ($j = 0; $j < $n; $j++) {
            if ($j !== $id) {
                $key[$j] = $nums[$o++] ?? throw new \OutOfRangeException('paParse: short input');
            }
        }
        return ['x' => $x, 'tag' => $tag, 'key' => $key];
    }

    public static function awWidth(int $n, int $keys, bool $tagged): int
    {
        return (1 + $keys) * self::paWidth($n, $tagged);
    }

    /** @return list<\GMP> */
    public static function awFlat(array $a, int $id, int $n, bool $tagged): array
    {
        $out = self::paFlat($a['v'], $id, $n, $tagged);
        foreach ($a['m'] as $p) {
            array_push($out, ...self::paFlat($p, $id, $n, $tagged));
        }
        return $out;
    }

    /** @param list<\GMP> $nums */
    public static function awParse(array $nums, int $off, int $id, int $n, int $keys, bool $tagged): array
    {
        $w = self::paWidth($n, $tagged);
        $v = self::paParse($nums, $off, $id, $n, $tagged);
        $m = [];
        for ($l = 0; $l < $keys; $l++) {
            $m[] = self::paParse($nums, $off + (1 + $l) * $w, $id, $n, $tagged);
        }
        return ['v' => $v, 'm' => $m];
    }

    /** Authenticated sharings consumed per triple with the given number of sacrifice partners. */
    public static function sharingsPerTriple(int $partners): int
    {
        return 3 + 2 * $partners;
    }
}
