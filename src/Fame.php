<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * FAME (Agrawal and Chase, CCS 2017, ePrint 2017/807): ciphertext-policy ABE in the asymmetric (type-3) pairing, adaptively secure
 * in the random-oracle model, for monotone span programs with an injective row labelling. Group work is blst (through ext-ffi, see
 * Bls12), GT work is the shim over blst's public API (native/pca_gt.c); scalars are GMP integers. This class is only the scheme's
 * arithmetic; the wire format and AEAD are in Abe.
 *
 * Shapes: mpk = ['h' => [P2, P2], 't' => [GT, GT]]; msk = ['a' => [s, s], 'b' => [s, s], 'g' => [P1, P1, P1]];
 * key = ['k0' => [P2 x3], 'kp' => [P1 x3], 'attrs' => [name => [P1 x3]]]; ct = ['ct0' => [P2 x3], 'rows' => list<[P1 x3]>].
 * P1 / P2 are Bls12 point buffers, GT elements are 576-byte strings.
 *
 * shortcut: scalar arithmetic is GMP, not constant time (see Bls12); the point and GT work is.
 */
final class Fame
{
    public const ATTR_DST = 'ATLAS-PCA-ABE:FAME:H-G1:SHA256-SSWU-RO:v1';

    /** a random non-zero scalar (48 random bytes reduced mod r) */
    public static function randomScalar(): \GMP
    {
        while (true) {
            $v = Bls12::mod(Bls12::os2ip(random_bytes(48)));
            if (gmp_sign($v) !== 0) {
                return $v;
            }
        }
    }

    private static function hashToG1(string $msg): \FFI\CData
    {
        return Bls12::hashToG1($msg, self::ATTR_DST);
    }

    /** H(y, l, t): kind byte 1, length-prefixed attribute, l, t */
    private static function hAttr(string $attr, int $l, int $t): \FFI\CData
    {
        $attr = Js::utf8($attr);
        return self::hashToG1("\x01" . pack('N', strlen($attr)) . $attr . chr($l) . chr($t));
    }

    /** H0(j, l, t): the column-indexed oracle (kind byte 2) */
    private static function hCol(int $j, int $l, int $t): \FFI\CData
    {
        return self::hashToG1("\x02" . pack('N', $j) . chr($l) . chr($t));
    }

    /**
     * @param list<\GMP> $a two scalars
     * @param list<\GMP> $b two scalars
     * @param list<\GMP> $d three scalars
     * @return array{0:array,1:array} [mpk, msk]
     */
    public static function setup(array $a, array $b, array $d): array
    {
        $egh = Bls12::gtPairing(Bls12::generator(1), Bls12::generator(2));
        $h2 = Bls12::generator(2);
        $g1 = Bls12::generator(1);
        $mpk = [
            'h' => [Bls12::pMul(2, $h2, $a[0]), Bls12::pMul(2, $h2, $a[1])],
            't' => [Bls12::gtPow($egh, Bls12::add(Bls12::mul($d[0], $a[0]), $d[2])), Bls12::gtPow($egh, Bls12::add(Bls12::mul($d[1], $a[1]), $d[2]))],
        ];
        $msk = ['a' => $a, 'b' => $b, 'g' => [Bls12::pMul(1, $g1, $d[0]), Bls12::pMul(1, $g1, $d[1]), Bls12::pMul(1, $g1, $d[2])]];
        return [$mpk, $msk];
    }

    /** (sum_l oracle(l)^pow[l] + g^sigma)^aInv */
    private static function keyTerm(callable $oracle, array $pow, \GMP $sigma, \GMP $aInv): \FFI\CData
    {
        $sum = Bls12::pMul(1, Bls12::generator(1), $sigma);
        for ($l = 0; $l < 3; $l++) {
            $sum = Bls12::pAdd(1, $sum, Bls12::pMul(1, $oracle($l), $pow[$l]));
        }
        return Bls12::pMul(1, $sum, $aInv);
    }

    /**
     * @param list<string> $attrs distinct attribute names
     * @param list<\GMP> $r two scalars
     * @param list<\GMP> $sigmas one per attribute
     */
    public static function keygen(array $msk, array $attrs, array $r, array $sigmas, \GMP $sigmaPrime): array
    {
        if (count($sigmas) < count($attrs)) {
            throw new \InvalidArgumentException('fame keygen: one sigma per attribute is required');
        }
        $pow = [Bls12::mul($msk['b'][0], $r[0]), Bls12::mul($msk['b'][1], $r[1]), Bls12::add($r[0], $r[1])];
        $aInv = [Bls12::inv($msk['a'][0]), Bls12::inv($msk['a'][1])];
        $g1 = Bls12::generator(1);
        $g2 = Bls12::generator(2);
        $key = ['k0' => [], 'kp' => [], 'attrs' => []];
        for ($l = 0; $l < 3; $l++) {
            $key['k0'][$l] = Bls12::pMul(2, $g2, $pow[$l]);
        }
        $zero = gmp_init(0);
        foreach (array_values($attrs) as $i => $y) {
            $comp = [];
            for ($t = 0; $t < 2; $t++) {
                $comp[$t] = self::keyTerm(static fn(int $l) => self::hAttr($y, $l, $t), $pow, $sigmas[$i], $aInv[$t]);
            }
            $comp[2] = Bls12::pMul(1, $g1, Bls12::sub($zero, $sigmas[$i]));
            $key['attrs'][$y] = $comp;
        }
        for ($t = 0; $t < 2; $t++) {
            $k = self::keyTerm(static fn(int $l) => self::hCol(0, $l, $t), $pow, $sigmaPrime, $aInv[$t]);
            $key['kp'][$t] = Bls12::pAdd(1, $k, $msk['g'][$t]);
        }
        $key['kp'][2] = Bls12::pAdd(1, Bls12::pMul(1, $g1, Bls12::sub($zero, $sigmaPrime)), $msk['g'][2]);
        return $key;
    }

    // ---- span program from the threshold tree ----

    /**
     * The leaves in depth-first order with their span-program rows (Shamir down the tree): each row is
     * ['attr' => string, 'vec' => [column => \GMP]], column 0 (the secret column) always 1.
     *
     * @return list<array{attr:string,vec:array<int,\GMP>}>
     */
    public static function buildRows(array $tree): array
    {
        $rows = [];
        $ncols = 1;
        self::walkRows($tree, [0 => gmp_init(1)], $ncols, $rows);
        return $rows;
    }

    private static function walkRows(array $n, array $vec, int &$ncols, array &$rows): void
    {
        if ($n['leaf']) {
            $rows[] = ['attr' => $n['attr'], 'vec' => $vec];
            return;
        }
        $base = $ncols;
        $ncols += $n['t'] - 1;
        foreach ($n['of'] as $idx => $child) {
            $cv = $vec;
            $x = gmp_init($idx + 1);
            $pw = gmp_init(1);
            for ($k = 1; $k < $n['t']; $k++) {
                $pw = Bls12::mul($pw, $x);
                $cv[$base + $k - 1] = $pw;
            }
            self::walkRows($child, $cv, $ncols, $rows);
        }
    }

    /**
     * @param list<\GMP> $s two scalars
     * @return array{0:array,1:string} [ct, KEM key (GT bytes)]
     */
    public static function encrypt(array $mpk, array $tree, array $s): array
    {
        $memo = [];
        $colTerm = function (int $j, int $l) use (&$memo, $s): \FFI\CData {
            return $memo["$j/$l"] ??= Bls12::pAdd(1, Bls12::pMul(1, self::hCol($j, $l, 0), $s[0]), Bls12::pMul(1, self::hCol($j, $l, 1), $s[1]));
        };
        $rows = [];
        foreach (self::buildRows($tree) as $row) {
            $out = [];
            for ($l = 0; $l < 3; $l++) {
                $acc = Bls12::pAdd(1, Bls12::pMul(1, self::hAttr($row['attr'], $l, 0), $s[0]), Bls12::pMul(1, self::hAttr($row['attr'], $l, 1), $s[1]));
                foreach ($row['vec'] as $j => $m) {
                    $acc = Bls12::pAdd(1, $acc, Bls12::pMul(1, $colTerm($j, $l), $m));
                }
                $out[$l] = $acc;
            }
            $rows[] = $out;
        }
        $g2 = Bls12::generator(2);
        $ct = ['rows' => $rows, 'ct0' => [Bls12::pMul(2, $mpk['h'][0], $s[0]), Bls12::pMul(2, $mpk['h'][1], $s[1]), Bls12::pMul(2, $g2, Bls12::add($s[0], $s[1]))]];
        $k = Bls12::gtMul(Bls12::gtPow($mpk['t'][0], $s[0]), Bls12::gtPow($mpk['t'][1], $s[1]));
        return [$ct, $k];
    }

    // ---- decrypt ----

    /** L_i(0) = prod_{j!=i} x_j / (x_j - x_i). Null on an empty set, a zero point or points that coincide mod r. @param list<\GMP> $xs @return ?list<\GMP> */
    public static function lagrangeAtZero(array $xs): ?array
    {
        if ($xs === []) {
            return null;
        }
        $seen = [];
        foreach ($xs as $x) {
            $xr = gmp_strval(Bls12::mod($x));
            if ($xr === '0' || isset($seen[$xr])) {
                return null;
            }
            $seen[$xr] = true;
        }
        $out = [];
        foreach ($xs as $i => $xi) {
            $num = gmp_init(1);
            $den = gmp_init(1);
            foreach ($xs as $j => $xj) {
                if ($j !== $i) {
                    $num = Bls12::mul($num, $xj);
                    $den = Bls12::mul($den, Bls12::sub($xj, $xi));
                }
            }
            $out[] = Bls12::mul($num, Bls12::inv($den)); // the points are distinct and non-zero, so den is non-zero
        }
        return $out;
    }

    /** The first t satisfiable children of every gate, bottom-up; null when has() does not satisfy the subtree. @param callable(string):bool $has */
    private static function plan(array $n, callable $has, int $offset): ?array
    {
        if ($n['leaf']) {
            return $has($n['attr']) ? ['row' => $offset] : null;
        }
        $of = [];
        $off = $offset;
        foreach ($n['of'] as $i => $child) {
            $sub = self::plan($child, $has, $off);
            if ($sub !== null) {
                $of[] = ['x' => gmp_init($i + 1), 'sub' => $sub];
            }
            if (count($of) >= $n['t']) {
                break;
            }
            $off += AbePolicy::leafCount($child);
        }
        return count($of) < $n['t'] ? null : ['of' => $of];
    }

    /** @param array<int,\GMP> $out row => weight */
    private static function weights(array $p, \GMP $w, array &$out): bool
    {
        if (!isset($p['of'])) {
            $out[$p['row']] = $w;
            return true;
        }
        $lam = self::lagrangeAtZero(array_map(static fn(array $c): \GMP => $c['x'], $p['of']));
        if ($lam === null) {
            return false;
        }
        foreach ($p['of'] as $i => $c) {
            if (!self::weights($c['sub'], Bls12::mul($w, $lam[$i]), $out)) {
                return false;
            }
        }
        return true;
    }

    /** The KEM key (GT bytes), or null when the key does not satisfy the tree or a point is degenerate. */
    public static function decrypt(array $key, array $tree, array $ct): ?string
    {
        $rows = AbePolicy::leafAttrs($tree);
        if (count($rows) !== count($ct['rows'])) {
            return null;
        }
        $p = self::plan($tree, static fn(string $a): bool => isset($key['attrs'][$a]), 0);
        $w = [];
        if ($p === null || !self::weights($p, gmp_init(1), $w)) {
            return null;
        }
        $g1s = [];
        $g2s = [];
        for ($l = 0; $l < 3; $l++) {
            $ctProd = Bls12::identity(1);
            $keyProd = $key['kp'][$l];
            foreach ($w as $i => $wi) {
                if (!isset($key['attrs'][$rows[$i]])) {
                    return null;
                }
                $ctProd = Bls12::pAdd(1, $ctProd, Bls12::pMul(1, $ct['rows'][$i][$l], $wi));
                $keyProd = Bls12::pAdd(1, $keyProd, Bls12::pMul(1, $key['attrs'][$rows[$i]][$l], $wi));
            }
            array_push($g1s, $keyProd, Bls12::pNeg(1, $ctProd));
            array_push($g2s, $ct['ct0'][$l], $key['k0'][$l]);
        }
        try {
            return Bls12::gtPairingProduct($g1s, $g2s);
        } catch (\InvalidArgumentException) {
            return null; // an identity point: the pairing is not defined
        }
    }
}
