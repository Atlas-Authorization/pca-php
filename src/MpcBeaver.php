<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Secure multiplication of two additively-shared values with Beaver triples (a trusted dealer supplies the triples). A triple is
 * ['a' => list<GMP>, 'b' => ..., 'c' => ...] (c = a*b, each component additively shared); an opened protocol message is
 * ['label' => 'd'|'e', 'value' => GMP, 'shares' => list<GMP>].
 */
final class MpcBeaver
{
    /** @return list<array{a:list<\GMP>,b:list<\GMP>,c:list<\GMP>}> */
    public static function genTriples(int $count, int $n, MpcFieldRng $rng): array
    {
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = self::genTriple($n, $rng);
        }
        return $out;
    }

    /** @return array{a:list<\GMP>,b:list<\GMP>,c:list<\GMP>} */
    public static function genTriple(int $n, MpcFieldRng $rng): array
    {
        $a = $rng->next();
        $b = $rng->next();
        $c = MpcField::fmul($a, $b);
        return ['a' => MpcSharing::share($a, $n, $rng), 'b' => MpcSharing::share($b, $n, $rng), 'c' => MpcSharing::share($c, $n, $rng)];
    }

    /**
     * x*y consuming $triple; every opened value is appended to $transcript when it is passed.
     *
     * @param list<\GMP> $x @param list<\GMP> $y @return list<\GMP>
     */
    public static function beaverMul(array $x, array $y, array $triple, ?array &$transcript = null): array
    {
        if (count($x) !== count($y)) {
            throw new \InvalidArgumentException('beaverMul: operand party counts differ');
        }
        foreach ([$triple['a'], $triple['b'], $triple['c']] as $part) {
            if (!is_array($part) || count($part) !== count($x)) {
                throw new \InvalidArgumentException('beaverMul: triple party count differs from the operands');
            }
        }
        $dShares = MpcSharing::subSV($x, $triple['a']);
        $eShares = MpcSharing::subSV($y, $triple['b']);
        $d = MpcSharing::reconstruct($dShares);
        $e = MpcSharing::reconstruct($eShares);
        if ($transcript !== null) {
            $transcript[] = ['label' => 'd', 'value' => $d, 'shares' => $dShares];
            $transcript[] = ['label' => 'e', 'value' => $e, 'shares' => $eShares];
        }
        $de = MpcField::fmul($d, $e);
        $z = [];
        for ($i = 0, $n = count($x); $i < $n; $i++) {
            $zi = MpcField::fadd($triple['c'][$i], MpcField::fadd(MpcField::fmul($d, $triple['b'][$i]), MpcField::fmul($e, $triple['a'][$i])));
            $z[] = $i === 0 ? MpcField::fadd($zi, $de) : $zi;
        }
        return $z;
    }
}
