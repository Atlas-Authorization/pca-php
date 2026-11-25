<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/K3Sig.php';
require_once __DIR__ . '/GrantService.php';

/** The JavaScript `undefined` of the parsed-JSON model: an absent member (null is JSON null). Compare with `Jsx::U`. */
final class Undef
{
}

/**
 * JavaScript property-read, comparison, coercion and iteration semantics for hostile JSON values (an absent member is the
 * sentinel {@see Jsx::U}), so a port can give the same answer, the same order or the same refusal (a thrown error) as the reference
 * when a malformed document reaches it. Values are the parsed-JSON model (Obj, list arrays, string, Num / int / float, bool, null).
 */
final class Jsx
{
    public static Undef $U;

    public static function init(): void
    {
        self::$U ??= new Undef();
    }

    public static function isUndef(mixed $v): bool
    {
        return $v instanceof Undef;
    }

    public static function truthy(mixed $v): bool
    {
        return !($v instanceof Undef) && Js::truthy($v);
    }

    /** `o[k]` without throwing: undefined for an absent member or a value without members. */
    public static function get(mixed $o, string $k): mixed
    {
        self::init();
        if ($o instanceof Obj) {
            return $o->has($k) ? $o->get($k) : self::$U;
        }
        if (is_array($o)) {
            if ($k === 'length') {
                return count($o);
            }
            return preg_match('/\A(?:0|[1-9][0-9]*)\z/', $k) === 1 && (int)$k < count($o) ? array_values($o)[(int)$k] : self::$U;
        }
        if (is_string($o)) {
            if ($k === 'length') {
                return K3Sig::utf16Len($o);
            }
            if (preg_match('/\A(?:0|[1-9][0-9]*)\z/', $k) === 1 && (int)$k < K3Sig::utf16Len($o)) {
                $u = (string)mb_convert_encoding($o, 'UTF-16BE', 'UTF-8');
                return (string)mb_convert_encoding(substr($u, (int)$k * 2, 2), 'UTF-8', 'UTF-16BE');
            }
        }
        return self::$U;
    }

    /** `o[k]` where o must not be null or undefined (a TypeError otherwise). */
    public static function rd(mixed $o, string $k): mixed
    {
        if ($o === null || $o instanceof Undef) {
            throw new \TypeError("Cannot read properties of " . ($o === null ? 'null' : 'undefined') . " (reading '$k')"); // the runtime's wording: it reaches results as a reason text
        }
        return self::get($o, $k);
    }

    /** Object.keys. @return list<string> */
    public static function keys(mixed $o): array
    {
        if ($o instanceof Obj) {
            return Js::ownKeys($o->keys());
        }
        if (is_array($o)) {
            return array_map('strval', array_keys(array_values($o)));
        }
        if (is_string($o)) {
            return array_map('strval', array_keys(array_fill(0, K3Sig::utf16Len($o), 0)));
        }
        return [];
    }

    /** `{...v}`: an object's own members, an array's or a string's indices, nothing for any other value. */
    public static function spread(mixed $v): Obj
    {
        $o = new Obj();
        if ($v instanceof Obj) {
            foreach ($v->keys() as $k) {
                $o->set($k, $v->get($k));
            }
        } elseif (is_array($v)) {
            foreach (array_values($v) as $i => $x) {
                $o->set((string)$i, $x);
            }
        } elseif (is_string($v)) {
            foreach (preg_split('//u', $v, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $i => $c) {
                $o->set((string)$i, $c);
            }
        }
        return $o;
    }

    /** String(v) with `undefined` as the text "undefined". */
    public static function str(mixed $v): string
    {
        return $v instanceof Undef ? 'undefined' : Js::str($v);
    }

    /** Number(v) for a JSON value (an object is NaN, an array goes through its string form). */
    public static function toNum(mixed $v): float
    {
        if ($v instanceof Undef) {
            return NAN;
        }
        if ($v === null) {
            return 0.0;
        }
        if (is_bool($v)) {
            return $v ? 1.0 : 0.0;
        }
        if (Js::isNum($v)) {
            return (float)Js::num($v);
        }
        if (is_string($v)) {
            return GrantHttp::jsNumber($v);
        }
        if (is_array($v)) {
            return GrantHttp::jsNumber(Js::str($v));
        }
        return NAN;
    }

    private static function prim(mixed $v): mixed
    {
        return is_array($v) ? Js::str($v) : ($v instanceof Obj ? '[object Object]' : $v);
    }

    private static function u16(string $s): string
    {
        return (string)mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }

    /** JS `a < b` (false when either side is NaN). */
    public static function lt(mixed $a, mixed $b): bool
    {
        $a = self::prim($a);
        $b = self::prim($b);
        if (is_string($a) && is_string($b)) {
            return strcmp(self::u16($a), self::u16($b)) < 0;
        }
        return self::toNum($a) < self::toNum($b);
    }

    public static function gt(mixed $a, mixed $b): bool
    {
        return self::lt($b, $a);
    }

    /** -1 / 1 / 0 by relational order. */
    public static function cmp(mixed $a, mixed $b): int
    {
        return self::lt($a, $b) ? -1 : (self::gt($a, $b) ? 1 : 0);
    }

    /** `Number(a) - Number(b)`. */
    public static function sub(mixed $a, mixed $b): float
    {
        return self::toNum($a) - self::toNum($b);
    }

    /** `first || rest()` for numbers: zero and NaN are falsy. */
    public static function or(float $first, callable $rest): float
    {
        return ($first != 0 && $first === $first) ? $first : $rest();
    }

    /** The values `for (const x of v)` visits: an array's items or a string's code points; anything else throws. @return list<mixed> */
    public static function iter(mixed $v): array
    {
        if (is_array($v) && array_is_list($v)) {
            return $v;
        }
        if (is_string($v)) {
            return preg_split('//u', $v, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }
        throw new \TypeError('not iterable');
    }

    /** `JSON.parse(JSON.stringify(v))`: a deep copy in which -0 becomes 0. */
    public static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::plain($v->get($k)));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::plain(...), $v);
        }
        if (Js::isNum($v) && Js::num($v) === 0.0) {
            return 0;
        }
        return $v;
    }

    /** Array.prototype.sort with a numeric comparator (stable; NaN counts as equal). A non-array throws. */
    public static function sort(mixed $list, callable $cmp): array
    {
        if (!is_array($list) || !array_is_list($list)) {
            throw new \TypeError('sort is not a function');
        }
        usort($list, static function ($a, $b) use ($cmp): int {
            $r = $cmp($a, $b);
            return $r < 0 ? -1 : ($r > 0 ? 1 : 0);
        });
        return $list;
    }
}
Jsx::init();
