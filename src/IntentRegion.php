<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentOmega.php';

/**
 * Regions (region.ts): the part of the outcome space a cell question was about, written in value terms so an observation keeps its
 * meaning when the space is refined. A region is an Obj `{verb, dims: {path: {kind: 'num', lo, hi} | {kind: 'cat', values, cells}}}`;
 * a cell index list is a list of ints. Failures the reference throws as Errors are thrown as \InvalidArgumentException.
 */
final class IntentRegion
{
    private static function numCellCount(mixed $d): int
    {
        return count(IntentOmega::numCells($d));
    }

    private static function dimSize(mixed $d): int
    {
        return Js::opt($d, 'kind') === 'num' ? self::numCellCount($d) : count(Js::opt($d, 'values'));
    }

    private static function copyValues(mixed $d): array
    {
        return array_map(static fn($v) => Jsx::spread($v), Js::opt($d, 'values'));
    }

    /** The region a cell of the verb space covers. @param list<int> $idx */
    public static function regionOfCell(mixed $vs, array $idx): Obj
    {
        $dims = new Obj();
        foreach (Js::opt($vs, 'dims') as $k => $d) {
            if (Js::opt($d, 'kind') === 'num') {
                $cells = IntentOmega::numCells($d);
                if (!isset($idx[$k]) || !isset($cells[$idx[$k]])) {
                    throw new \TypeError('cell index out of range');
                }
                $dims->set(Js::opt($d, 'path'), Obj::of(['kind' => 'num', 'lo' => $cells[$idx[$k]]->get('lo'), 'hi' => $cells[$idx[$k]]->get('hi')]));
            } else {
                $dims->set(Js::opt($d, 'path'), Obj::of(['kind' => 'cat', 'values' => self::copyValues($d), 'cells' => [$idx[$k]]]));
            }
        }
        return Obj::of(['verb' => Js::opt($vs, 'verb'), 'dims' => $dims]);
    }

    /** Replace one dimension of a region; `$part` is `{lo, hi}` or `{cells}` matching the dimension's kind. */
    public static function restrictRegion(mixed $r, mixed $d, mixed $part): Obj
    {
        $dims = Jsx::spread(Js::opt($r, 'dims'));
        $kind = Js::opt($d, 'kind');
        $path = Js::opt($d, 'path');
        if ($kind === 'num' && Js::has($part, 'lo')) {
            $dims->set($path, Obj::of(['kind' => 'num', 'lo' => Js::opt($part, 'lo'), 'hi' => Js::opt($part, 'hi')]));
        } elseif ($kind === 'cat' && Js::has($part, 'cells')) {
            $dims->set($path, Obj::of(['kind' => 'cat', 'values' => self::copyValues($d), 'cells' => Js::spread(Js::opt($part, 'cells'))]));
        } else {
            throw new \InvalidArgumentException('restrictRegion: part does not match the kind of ' . Js::str($path));
        }
        return Obj::of(['verb' => Js::opt($r, 'verb'), 'dims' => $dims]);
    }

    private static function refDim(string $path, mixed $rd): Obj
    {
        return Obj::of(['kind' => 'cat', 'path' => $path, 'values' => Js::opt($rd, 'values')]);
    }

    private static function inCells(mixed $cells, int $c): bool
    {
        foreach (Js::spread($cells) as $x) {
            if (Js::num($x) === (float)$c) {
                return true;
            }
        }
        return false;
    }

    /**
     * The cells of dimension `$d` covered by the region dimension (null = unrestricted): 'inner' (wholly inside) or 'outer' (meeting it).
     * @return list<int>
     */
    public static function dimCellsIn(mixed $d, mixed $rd, string $mode): array
    {
        $num = Js::opt($d, 'kind') === 'num';
        $n = self::dimSize($d);
        $all = $n > 0 ? range(0, $n - 1) : [];
        if (!Js::truthy($rd)) {
            return $all;
        }
        $path = (string)Js::opt($d, 'path');
        if ($num) {
            if (Js::opt($rd, 'kind') !== 'num') {
                throw new \InvalidArgumentException("region: $path is numeric in Ω but categorical in the region");
            }
            $cells = IntentOmega::numCells($d);
            $rlo = Js::num(Js::opt($rd, 'lo'));
            $rhi = Js::num(Js::opt($rd, 'hi'));
            return array_values(array_filter($all, static function (int $i) use ($cells, $mode, $rlo, $rhi): bool {
                $lo = (float)Js::num($cells[$i]->get('lo'));
                $hi = (float)Js::num($cells[$i]->get('hi'));
                return $mode === 'inner' ? ($lo >= $rlo && $hi <= $rhi) : ($hi >= $rlo && $lo <= $rhi);
            }));
        }
        if (Js::opt($rd, 'kind') !== 'cat') {
            throw new \InvalidArgumentException("region: $path is categorical in Ω but numeric in the region");
        }
        $ref = self::refDim($path, $rd);
        $inCells = Js::opt($rd, 'cells');
        return array_values(array_filter($all, static fn(int $i): bool => self::inCells($inCells, IntentOmega::catCellOf($ref, IntentOmega::catRep($d, $i)))));
    }

    /**
     * Flat cell indices of the verb space covered by the region (row-major, last dimension fastest); refuses a restriction the space
     * lacks. @return list<int>
     */
    public static function regionCells(mixed $vs, mixed $r, string $mode): array
    {
        if (Js::opt($r, 'verb') !== Js::opt($vs, 'verb')) {
            throw new \InvalidArgumentException('region: verb ' . Js::str(Js::opt($r, 'verb')) . ' does not match ' . Js::str(Js::opt($vs, 'verb')));
        }
        $dimsOf = Js::opt($vs, 'dims');
        $rdims = Js::opt($r, 'dims');
        foreach (Jsx::keys($rdims) as $p) {
            $found = false;
            foreach ($dimsOf as $d) {
                if (Js::opt($d, 'path') === $p) {
                    $found = true;
                    break;
                }
            }
            if (!$found) {
                throw new \InvalidArgumentException("region: restricts $p, which Ω has no dimension for");
            }
        }
        $per = [];
        foreach ($dimsOf as $d) {
            $rd = Js::has($rdims, (string)Js::opt($d, 'path')) ? Js::opt($rdims, (string)Js::opt($d, 'path')) : null;
            $per[] = self::dimCellsIn($d, $rd, $mode);
        }
        foreach ($per as $x) {
            if (count($x) === 0) {
                return [];
            }
        }
        $acc = [0];
        foreach ($per as $k => $cells) {
            $size = self::dimSize($dimsOf[$k]);
            $next = [];
            foreach ($acc as $f) {
                foreach ($cells as $c) {
                    $next[] = $f * $size + $c;
                }
            }
            $acc = $next;
        }
        return $acc;
    }

    public static function valueInRegionDim(string $path, mixed $rd, mixed $x): bool
    {
        if (Js::opt($rd, 'kind') === 'num') {
            return Js::isNum($x) && Js::num($x) >= Js::num(Js::opt($rd, 'lo')) && Js::num($x) <= Js::num(Js::opt($rd, 'hi'));
        }
        return is_string($x) && self::inCells(Js::opt($rd, 'cells'), IntentOmega::catCellOf(self::refDim($path, $rd), $x));
    }
}
