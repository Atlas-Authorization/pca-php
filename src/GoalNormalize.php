<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';

/** Stable JSON and canonical Goal order. */
final class GoalNormalize
{
    /** JSON.stringify of a value (a string's lone surrogates are escaped). */
    public static function jq(mixed $v): string
    {
        return Js::stringify($v);
    }

    /** Sorted-key JSON, undefined members dropped: an in-memory key for maps and sets, NOT a signed encoding. */
    public static function stable(mixed $v): string
    {
        if (is_array($v) && array_is_list($v)) {
            return '[' . implode(',', array_map(fn($x) => AnalyzerJs::isUndef($x) ? '' : self::stable($x), $v)) . ']';
        }
        if (!($v instanceof Obj)) {
            return self::jq($v);
        }
        $keys = array_values(array_filter($v->keys(), fn($k) => !AnalyzerJs::isUndef($v->get($k))));
        usort($keys, fn($a, $b) => AnalyzerJs::u16cmp($a, $b));
        return '{' . implode(',', array_map(fn($k) => self::jq($k) . ':' . self::stable($v->get($k)), $keys)) . '}';
    }

    /** @param list<mixed> $xs @return list<mixed> a stable sort by a string id (members whose id is not a string compare equal). */
    private static function byId(array $xs, string $field): array
    {
        return GoalJs::stableSort($xs, function ($a, $b) use ($field) {
            $x = AnalyzerJs::jget($a, $field);
            $y = AnalyzerJs::jget($b, $field);
            return is_string($x) && is_string($y) ? AnalyzerJs::u16cmp($x, $y) : 0;
        });
    }

    /** `[...new Set(xs)].sort()`: de-duplicated (SameValueZero), then ordered by String(x) in UTF-16 order. @return list<mixed> */
    public static function sortedUnique(mixed $xs): array
    {
        $uniq = [];
        foreach (AnalyzerJs::reqList($xs) as $x) {
            foreach ($uniq as $u) {
                if (AnalyzerJs::strictEq($u, $x)) {
                    continue 2;
                }
            }
            $uniq[] = $x;
        }
        return GoalJs::stableSort($uniq, fn($a, $b) => AnalyzerJs::u16cmp(AnalyzerJs::jsStr($a), AnalyzerJs::jsStr($b)));
    }

    /**
     * Grants, prohibits, bounds and holes strictly increasing by id (code-unit order), wildcardAck / mayTouch sorted and
     * de-duplicated. Duplicated ids are NOT merged: they stay and the typechecker refuses them.
     */
    public static function canonicalizeGoal(mixed $g): Obj
    {
        if (!($g instanceof Obj)) {
            throw new \TypeError('goal must be an object');
        }
        $out = AnalyzerJs::copy($g);
        $out->set('grants', self::byId(AnalyzerJs::reqList(AnalyzerJs::jget($g, 'grants')), 'gid'));
        $out->set('prohibits', self::byId(AnalyzerJs::reqList(AnalyzerJs::jget($g, 'prohibits')), 'pid'));
        $out->set('bounds', self::byId(AnalyzerJs::reqList(AnalyzerJs::jget($g, 'bounds')), 'bid'));
        $out->set('holes', self::byId(AnalyzerJs::reqList(AnalyzerJs::jget($g, 'holes')), 'hid'));
        $out->set('wildcardAck', self::sortedUnique(AnalyzerJs::jget($g, 'wildcardAck')));
        $deleg = AnalyzerJs::jget($g, 'deleg');
        $d = AnalyzerJs::spread($deleg);
        $d->set('mayTouch', self::sortedUnique(AnalyzerJs::jget($deleg, 'mayTouch')));
        $out->set('deleg', $d);
        return $out;
    }
}
