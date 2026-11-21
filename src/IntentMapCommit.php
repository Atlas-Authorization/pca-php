<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/IntentMap.php';

/**
 * The wallet side of the committed (Merkle, per-leaf salted) form of an Intent Map (map-commit.ts): maps an Intent Map onto the leaf
 * layout of the core `commitMap`. Needs `IntentMap::commitMap($headers, $cells, $metrics, $learnerDigest, $secret)` (the map module);
 * the map is an Obj `{omega, cells, metrics, learner, ...}`.
 */
final class IntentMapCommit
{
    private static function f(mixed $x): float
    {
        return (float)(Js::num($x) ?? NAN);
    }

    private static function numCellCount(mixed $lo, mixed $hi, mixed $cuts): int
    {
        $n = 0;
        $l = self::f($lo);
        $h = self::f($hi);
        $cur = $l;
        foreach ($cuts as $c) {
            $c = self::f($c);
            if ($c < $l || $c > $h) {
                continue;
            }
            if ($cur <= $c - 1) {
                $n++;
            }
            $n++;
            $cur = $c + 1;
        }
        return $cur <= $h ? $n + 1 : $n;
    }

    private static function orEmpty(mixed $x): array
    {
        return $x === null ? [] : Js::spread($x);
    }

    /** Commit an Intent Map; `$secret` (32 random bytes kept per session) derives every leaf salt. */
    public static function commitIntentMap(mixed $m, string $secret): mixed
    {
        $omegaVerbs = Js::opt(Js::get($m, 'omega'), 'verbs');
        $headers = [];
        foreach ($omegaVerbs as $v) {
            $dims = [];
            foreach (Js::opt($v, 'dims') as $d) {
                if (Js::opt($d, 'kind') === 'num') {
                    $lo = Js::opt($d, 'lo');
                    $hi = Js::opt($d, 'hi');
                    $cuts = array_values(array_filter(self::orEmpty(Js::opt($d, 'cuts')), static fn($c) => self::f($c) >= self::f($lo) && self::f($c) <= self::f($hi)));
                    $dims[] = Obj::of(['kind' => 'num', 'path' => Js::opt($d, 'path'), 'lo' => $lo, 'hi' => $hi, 'cuts' => $cuts]);
                } else {
                    $dims[] = Obj::of(['kind' => 'cat', 'path' => Js::opt($d, 'path'), 'values' => array_map(
                        static fn($x) => Obj::of(['kind' => Js::opt($x, 'kind'), 'value' => Js::opt($x, 'value')]), self::orEmpty(Js::opt($d, 'values')))]);
                }
            }
            $headers[] = Obj::of(['verb' => Js::opt($v, 'verb'), 'dims' => $dims]);
        }
        $cells = new Obj();
        foreach ($omegaVerbs as $v) {
            $counts = [];
            foreach (Js::opt($v, 'dims') as $d) {
                $counts[] = Js::opt($d, 'kind') === 'num'
                    ? self::numCellCount(Js::opt($d, 'lo'), Js::opt($d, 'hi'), self::orEmpty(Js::opt($d, 'cuts')))
                    : count(self::orEmpty(Js::opt($d, 'values')));
            }
            $total = 1;
            foreach ($counts as $c) {
                $total *= $c;
            }
            $slots = $total > 0 ? array_fill(0, $total, null) : [];
            $verb = Js::opt($v, 'verb');
            foreach (Js::opt($m, 'cells') as $c) {
                if (Js::opt($c, 'verb') !== $verb) {
                    continue;
                }
                $cell = Js::opt($c, 'cell');
                if (count($cell) !== count($counts)) {
                    throw new \InvalidArgumentException("commitIntentMap: cell of $verb has the wrong arity");
                }
                $flat = 0;
                foreach ($cell as $j => $i) {
                    if (!(IntentWb::isSafeInt($i) && self::f($i) >= 0 && self::f($i) < $counts[$j])) {
                        throw new \InvalidArgumentException("commitIntentMap: cell index out of range for $verb");
                    }
                    $flat = $flat * $counts[$j] + (int)self::f($i);
                }
                $slots[$flat] = Obj::of(['cell' => array_values($cell), 'p_ppm' => Js::opt($c, 'p_ppm'), 'in_grant' => Js::opt($c, 'in_grant')]);
            }
            if (count($slots) !== $total || in_array(null, $slots, true)) {
                throw new \InvalidArgumentException("commitIntentMap: the map does not list every cell of $verb");
            }
            $cells->set((string)$verb, $slots);
        }
        $metrics = new Obj();
        $mm = Js::opt($m, 'metrics');
        foreach (Jsx::keys($mm) as $k) {
            if ($k !== 'log2_vs_mbits') {
                $metrics->set($k, Js::opt($mm, $k));
            }
        }
        if (Js::opt($mm, 'log2_vs_mbits') !== null) {
            $metrics->set('log2_vs_mbits', Js::opt($mm, 'log2_vs_mbits'));
        }
        return IntentMap::commitMap($headers, $cells, $metrics, Pca::hashCanonical(Js::opt($m, 'learner')), $secret);
    }
}
