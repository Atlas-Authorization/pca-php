<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';

/**
 * JavaScript string and key semantics the goal package reproduces over parsed-JSON trees, on top of {@see AnalyzerJs} (property
 * reads, truthiness, ===, Number(x), relational comparison, undefined sentinel, toFixed, UTF-16 key order). Strings are UTF-8 /
 * WTF-8 byte strings; a lone surrogate is its 3-byte WTF-8 form.
 */
final class GoalJs
{
    /** The UTF-16 code units of a (WTF-8) string. @return list<int> */
    public static function units(string $s): array
    {
        $u = [];
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $u[] = $b;
                $i++;
            } elseif ($b < 0xE0) {
                $u[] = (($b & 0x1F) << 6) | (ord($s[$i + 1] ?? "\0") & 0x3F);
                $i += 2;
            } elseif ($b < 0xF0) {
                $u[] = (($b & 0x0F) << 12) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 2] ?? "\0") & 0x3F);
                $i += 3;
            } else {
                $cp = ((($b & 7) << 18) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 12) | ((ord($s[$i + 2] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 3] ?? "\0") & 0x3F)) - 0x10000;
                $u[] = 0xD800 + ($cp >> 10);
                $u[] = 0xDC00 + ($cp & 0x3FF);
                $i += 4;
            }
        }
        return $u;
    }

    /** The string of a UTF-16 unit list (a lone surrogate becomes its WTF-8 3-byte form). @param list<int> $u */
    public static function fromUnits(array $u): string
    {
        $out = '';
        $n = count($u);
        for ($i = 0; $i < $n; $i++) {
            $x = $u[$i];
            if ($x >= 0xD800 && $x <= 0xDBFF && $i + 1 < $n && $u[$i + 1] >= 0xDC00 && $u[$i + 1] <= 0xDFFF) {
                $cp = 0x10000 + (($x - 0xD800) << 10) + ($u[$i + 1] - 0xDC00);
                $out .= chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
                $i++;
            } elseif ($x < 0x80) {
                $out .= chr($x);
            } elseif ($x < 0x800) {
                $out .= chr(0xC0 | ($x >> 6)) . chr(0x80 | ($x & 0x3F));
            } else {
                $out .= chr(0xE0 | ($x >> 12)) . chr(0x80 | (($x >> 6) & 0x3F)) . chr(0x80 | ($x & 0x3F));
            }
        }
        return $out;
    }

    /** s.length (UTF-16 units). */
    public static function ulen(string $s): int
    {
        return Js::len($s);
    }

    /** JS string equality (same UTF-16 units; for WTF-8 byte strings the same bytes). */
    public static function strEq(string $a, string $b): bool
    {
        return $a === $b;
    }

    /** Object.keys(o): an Obj's own keys in JS order, an Array's / String's indices, nothing for other primitives; null / undefined throws. @return list<string> */
    public static function okeys(mixed $o): array
    {
        if ($o === null || $o instanceof Undef) {
            throw new \TypeError('cannot convert undefined or null to object');
        }
        if ($o instanceof Obj) {
            return Js::ownKeys($o->keys());
        }
        if (is_array($o) && array_is_list($o)) {
            return array_map('strval', array_keys($o));
        }
        if (is_string($o)) {
            return array_map('strval', array_keys(self::units($o)));
        }
        return [];
    }

    /** `o[k]` for a key of Object.keys(o); undefined when absent. */
    public static function kget(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->has($k) ? $o->get($k) : AnalyzerJs::undef();
        }
        if (is_array($o) && array_is_list($o)) {
            return $o[(int)$k] ?? AnalyzerJs::undef();
        }
        if (is_string($o)) {
            $u = self::units($o);
            return isset($u[(int)$k]) ? self::fromUnits([$u[(int)$k]]) : AnalyzerJs::undef();
        }
        return AnalyzerJs::undef();
    }

    /** s.toLowerCase() (a lone surrogate is unchanged). */
    public static function lower(string $s): string
    {
        if (mb_check_encoding($s, 'UTF-8')) {
            return mb_strtolower($s, 'UTF-8');
        }
        $parts = preg_split('/(\xED[\xA0-\xBF][\x80-\xBF])/', $s, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [$s];
        $out = '';
        foreach ($parts as $i => $p) {
            $out .= $i % 2 === 1 ? $p : mb_strtolower($p, 'UTF-8');
        }
        return $out;
    }

    /** A stable sort (PHP 8 usort is stable): `$cmp(a, b)` returns a negative, zero or positive int. @param list<mixed> $xs @return list<mixed> */
    public static function stableSort(array $xs, callable $cmp): array
    {
        usort($xs, $cmp);
        return $xs;
    }
}
