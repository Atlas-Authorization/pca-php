<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * JavaScript-semantics helpers for the policy analyzer port. Inputs are parsed-JSON trees (Obj, list arrays, string, Num / int /
 * float, bool, null). A missing member is the sentinel `Jsx::$U` (JavaScript `undefined`); null is JSON null. `U` never appears in a
 * result ({@see self::uobj} drops it). Every dict the analyzer builds is an Obj, every list a PHP list.
 */
final class AnalyzerJs
{
    public static function undef(): Undef
    {
        Jsx::init();
        return Jsx::$U;
    }

    public static function isUndef(mixed $v): bool
    {
        return $v instanceof Undef;
    }

    /** `o[k]`: undefined for an absent member; reading a member of null / undefined throws (TypeError), as in JavaScript. */
    public static function jget(mixed $o, string $k): mixed
    {
        return Jsx::rd($o, $k);
    }

    /** `o?.k`. */
    public static function oget(mixed $o, string $k): mixed
    {
        return ($o === null || $o instanceof Undef) ? self::undef() : Jsx::get($o, $k);
    }

    /** An own member of a plain object, else `$default` (undefined unless given); never throws. */
    public static function own(mixed $o, string $k, mixed $default = null, bool $hasDefault = false): mixed
    {
        if ($o instanceof Obj && $o->has($k)) {
            return $o->get($k);
        }
        return $hasDefault ? $default : self::undef();
    }

    public static function has(mixed $o, string $k): bool
    {
        return $o instanceof Obj && $o->has($k);
    }

    public static function isObj(mixed $v): bool
    {
        return $v instanceof Obj;
    }

    public static function isArr(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    public static function isNum(mixed $v): bool
    {
        return Js::isNum($v);
    }

    /** The binary64 value of a JSON number (callers check isNum first). */
    public static function jsnum(mixed $v): float
    {
        return (float)Js::num($v);
    }

    /** `v ?? default`. */
    public static function nn(mixed $v, mixed $default): mixed
    {
        return ($v === null || $v instanceof Undef) ? $default : $v;
    }

    /** `typeof v === 'number' && Number.isFinite(v)`: the binary64 value, else null. */
    public static function fin(mixed $v): ?float
    {
        if (Js::isNum($v)) {
            $f = (float)Js::num($v);
            if (is_finite($f)) {
                return $f;
            }
        }
        return null;
    }

    public static function isFin(mixed $v): bool
    {
        return self::fin($v) !== null;
    }

    public static function truthy(mixed $v): bool
    {
        return Jsx::truthy($v);
    }

    /** `a === b` over JSON values (objects and arrays by identity / structure of the same instance; numbers by value). */
    public static function strictEq(mixed $a, mixed $b): bool
    {
        if ($a instanceof Undef || $b instanceof Undef) {
            return $a === $b;
        }
        if ($a === null || $b === null) {
            return $a === $b;
        }
        if (is_bool($a) || is_bool($b)) {
            return is_bool($a) && is_bool($b) && $a === $b;
        }
        if (Js::isNum($a) || Js::isNum($b)) {
            return Js::isNum($a) && Js::isNum($b) && self::jsnum($a) == self::jsnum($b);
        }
        if (is_string($a) && is_string($b)) {
            return $a === $b;
        }
        return $a === $b;
    }

    /** `xs.includes(x)` (SameValueZero: NaN equals NaN); a non-array throws. */
    public static function includes(mixed $xs, mixed $x): bool
    {
        foreach (self::reqList($xs) as $e) {
            if (self::strictEq($e, $x)) {
                return true;
            }
            if (Js::isNum($e) && Js::isNum($x) && is_nan(self::jsnum($e)) && is_nan(self::jsnum($x))) {
                return true;
            }
        }
        return false;
    }

    /** @return list<mixed> the array itself; anything else throws (TypeError). */
    public static function reqList(mixed $x): array
    {
        if (!is_array($x) || !array_is_list($x)) {
            throw new \TypeError('not an array');
        }
        return $x;
    }

    /** String(v), undefined as "undefined". */
    public static function jsStr(mixed $v): string
    {
        return Jsx::str($v);
    }

    /** The JS Number::toString text of a double. */
    public static function numStr(float $f): string
    {
        return Js::str($f);
    }

    /** Number(v). */
    public static function toNumber(mixed $v): float
    {
        return Jsx::toNum($v);
    }

    public static function jsGt(mixed $a, mixed $b): bool
    {
        return Jsx::gt($a, $b);
    }

    public static function jsLt(mixed $a, mixed $b): bool
    {
        return Jsx::lt($a, $b);
    }

    /** `JSON.stringify(v)` of a JSON tree (undefined members dropped, undefined in an array is null, -0 as 0, own-key order). */
    public static function jsJson(mixed $v): string
    {
        if ($v instanceof Undef) {
            return 'null';
        }
        if (is_array($v) && array_is_list($v)) {
            return '[' . implode(',', array_map(self::jsJson(...), $v)) . ']';
        }
        if ($v instanceof Obj) {
            $parts = [];
            foreach (Js::ownKeys($v->keys()) as $k) {
                $x = $v->get($k);
                if (!($x instanceof Undef)) {
                    $parts[] = Json::lenientStr($k) . ':' . self::jsJson($x);
                }
            }
            return '{' . implode(',', $parts) . '}';
        }
        return Js::stringify($v);
    }

    /** JavaScript own-key order of an object. @return list<string> */
    public static function keyOrder(Obj $o): array
    {
        return Js::ownKeys($o->keys());
    }

    /** An object literal from a PHP assoc array: members whose value is undefined are absent. */
    public static function uobj(array $d): Obj
    {
        $o = new Obj();
        foreach ($d as $k => $v) {
            if (!($v instanceof Undef)) {
                $o->set((string)$k, $v);
            }
        }
        return $o;
    }

    /** `{...o}` (nullish spreads nothing; a string or array spreads its indices). */
    public static function spread(mixed $o): Obj
    {
        return Jsx::spread($o);
    }

    /** A shallow copy of an Obj. */
    public static function copy(Obj $o): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        return $c;
    }

    /** UTF-16BE bytes of a string: sorts (strcmp) in JavaScript's default string order (UTF-16 code units). */
    public static function u16key(string $s): string
    {
        return (string)mb_convert_encoding($s, 'UTF-16BE', 'UTF-8');
    }

    /** -1 / 0 / 1 in JavaScript's default string order. */
    public static function u16cmp(string $a, string $b): int
    {
        return strcmp(self::u16key($a), self::u16key($b)) <=> 0;
    }

    /** `x.toFixed($digits)`: the exact decimal expansion of the double, ties away from zero. */
    public static function toFixed(float $x, int $digits = 2): string
    {
        if (is_nan($x)) {
            return 'NaN';
        }
        if (is_infinite($x)) {
            return $x > 0 ? 'Infinity' : '-Infinity';
        }
        $neg = $x < 0;
        $s = sprintf('%.50f', abs($x));            // exact for every tie (a tie has a short dyadic expansion)
        [$ip, $fp] = explode('.', $s) + [1 => ''];
        $keep = substr($fp, 0, $digits);
        $next = (int)($fp[$digits] ?? '0');
        $digitsStr = $ip . $keep;
        if ($next >= 5) {                          // round half up on the decimal text (away from zero)
            $a = str_split($digitsStr);
            $i = count($a) - 1;
            while ($i >= 0) {
                if ($a[$i] === '9') {
                    $a[$i] = '0';
                    $i--;
                } else {
                    $a[$i] = (string)((int)$a[$i] + 1);
                    break;
                }
            }
            $digitsStr = ($i < 0 ? '1' : '') . implode('', $a);
        }
        $int = $digits > 0 ? substr($digitsStr, 0, strlen($digitsStr) - $digits) : $digitsStr;
        $frac = $digits > 0 ? substr($digitsStr, -$digits) : '';
        $out = $int . ($digits > 0 ? '.' . $frac : '');
        return ($neg ? '-' : '') . $out;
    }
}
