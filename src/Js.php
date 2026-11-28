<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * The JavaScript semantics the protocol bridges reproduce byte for byte (truthiness, JSON.stringify, encodeURIComponent), and
 * option reads that accept either a parsed JSON object (Obj) or a PHP associative array keyed by the reference's option names.
 * Values are the parsed-JSON model: Obj, list arrays, string, Num / int / float, bool, null.
 */
final class Js
{
    /** Option `$k` of `$o` (an Obj, an assoc array, or null); null when absent (the reference's undefined). */
    public static function opt(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        return is_array($o) && !array_is_list($o) ? ($o[$k] ?? null) : null;
    }

    /** o[k] with JS property-read semantics: null / undefined throws a TypeError, a non-object has no members. */
    public static function get(mixed $o, string $k): mixed
    {
        if ($o === null) {
            throw new \TypeError("Cannot read properties of null (reading '$k')");
        }
        return self::opt($o, $k);
    }

    /** True when `$o` is a JSON object that has member `$k` (even with a null value). */
    public static function has(mixed $o, string $k): bool
    {
        return ($o instanceof Obj && $o->has($k)) || (is_array($o) && !array_is_list($o) && array_key_exists($k, $o));
    }

    /** True when `$o` is a JSON object (an Obj or a non-list PHP array). */
    public static function isObj(mixed $o): bool
    {
        return $o instanceof Obj || (is_array($o) && ($o === [] ? false : !array_is_list($o)));
    }

    /** String(x) of a JSON value. */
    public static function str(mixed $v): string
    {
        if (is_string($v)) {
            return $v;
        }
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (Js::isNum($v)) {
            $f = Js::num($v);
            return is_nan($f) ? 'NaN' : (is_infinite($f) ? ($f > 0 ? 'Infinity' : '-Infinity') : Js::stringify($v));
        }
        if (is_array($v) && array_is_list($v)) {
            return implode(',', array_map(static fn($x) => $x === null ? '' : self::str($x), $v));
        }
        return '[object Object]';
    }

    /** True when `$x` is a JSON number. */
    public static function isNum(mixed $x): bool
    {
        return $x instanceof Num || is_int($x) || is_float($x);
    }

    /** The binary64 value of a JSON number, or null. */
    public static function num(mixed $x): ?float
    {
        return $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : null);
    }

    /** True for a list whose every element is a string. */
    public static function isStrList(mixed $x): bool
    {
        if (!is_array($x) || !array_is_list($x)) {
            return false;
        }
        foreach ($x as $s) {
            if (!is_string($s)) {
                return false;
            }
        }
        return true;
    }

    /** JS truthiness: null / false / 0 / -0 / NaN / "" are falsy; an empty array or object is truthy. */
    public static function truthy(mixed $v): bool
    {
        if ($v === null || $v === false || $v === '') {
            return false;
        }
        $f = self::num($v);
        return $f === null || !($f == 0.0 || is_nan($f));
    }

    /** The JS string length (UTF-16 code units) of a UTF-8 / WTF-8 string. */
    public static function len(string $s): int
    {
        // 4-byte sequences are surrogate pairs (2 units); every other sequence is 1 unit
        return preg_match_all('/[\x00-\x7F\xC0-\xEF]/', $s) + 2 * preg_match_all('/[\xF0-\xF7]/', $s);
    }

    /** JSON.stringify of a JSON value (compact, insertion order, the JS number form, lone surrogates as \udXXX). */
    public static function stringify(mixed $v): string
    {
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (is_string($v)) {
            return Json::lenientStr($v);
        }
        $f = self::num($v);
        if ($f !== null) {
            return is_finite($f) ? ($f == 0.0 ? '0' : IntentWb::jsNumStr($f)) : 'null';
        }
        if (is_array($v) && array_is_list($v)) {
            return '[' . implode(',', array_map(self::stringify(...), $v)) . ']';
        }
        if ($v instanceof Obj) {
            $parts = [];
            foreach (self::ownKeys($v->keys()) as $k) {
                $parts[] = Json::lenientStr($k) . ':' . self::stringify($v->get($k));
            }
            return '{' . implode(',', $parts) . '}';
        }
        if (is_array($v)) {
            $parts = [];
            foreach ($v as $k => $x) {
                $parts[] = Json::lenientStr((string)$k) . ':' . self::stringify($x);
            }
            return '{' . implode(',', $parts) . '}';
        }
        throw new \TypeError('JSON.stringify: unsupported ' . get_debug_type($v));
    }

    /**
     * The JS own-property order of an object's keys: array-index keys ("0" .. "4294967294", canonical) ascending first, then the
     * other keys in insertion order.
     * @param list<string> $keys @return list<string>
     */
    public static function ownKeys(array $keys): array
    {
        $idx = [];
        $rest = [];
        foreach ($keys as $k) {
            if (preg_match('/\A(?:0|[1-9][0-9]{0,9})\z/', $k) === 1 && (int)$k <= 4294967294) {
                $idx[] = $k;
            } else {
                $rest[] = $k;
            }
        }
        usort($idx, static fn(string $a, string $b): int => (int)$a <=> (int)$b);
        return [...$idx, ...$rest];
    }

    /**
     * JSON.parse: the RFC 8259 grammar, a repeated key keeps its first position and its last value, every number becomes its
     * JS value (the Number::toString lexeme; -0 kept). Throws JsonError on a syntax error.
     */
    public static function parse(string $s): mixed
    {
        return IntentWb::norm((new Parser($s, 4096, true))->run());
    }

    /** `JSON.parse` that refuses a duplicate member (json_decode and JSON.parse keep the last one); numbers keep their JSON.parse values. */
    public static function parseNoDuplicates(string $s): mixed
    {
        return IntentWb::norm((new Parser($s, 4096, false, true))->run());
    }

    /** The UTF-8 bytes a JS TextEncoder writes for a (WTF-8) string: a lone surrogate becomes U+FFFD. */
    public static function utf8(string $s): string
    {
        return (string)preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\u{FFFD}", $s);
    }

    /** encodeURIComponent: UTF-8 percent-encoding of everything outside A-Z a-z 0-9 - _ . ! ~ * ' ( ). A lone surrogate throws (URIError). */
    public static function encodeURIComponent(string $s): string
    {
        if (Json::hasLoneSurrogate($s)) {
            throw new \InvalidArgumentException('URI malformed');
        }
        return strtr(rawurlencode($s), ['%21' => '!', '%2A' => '*', '%27' => "'", '%28' => '(', '%29' => ')']);
    }

    /** Array spread ([...x]) of a JSON value: a list is copied, a string splits into code points, anything else is not iterable. */
    public static function spread(mixed $x): array
    {
        if (is_array($x) && array_is_list($x)) {
            return $x;
        }
        if (is_string($x)) {
            // by code point; a lone surrogate (3-byte WTF-8, invalid as UTF-8) stays one element
            preg_match_all('/[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF4][\x80-\xBF]{3}|[\x80-\xFF]/', $x, $m);
            return $m[0];
        }
        throw new \TypeError('value is not iterable');
    }
}

/**
 * Raw bytes where the reference distinguishes a Uint8Array from a string (a string there is text, for example base64url).
 * Where the reference only takes bytes, a plain PHP string is accepted as the bytes too.
 */
final class Bytes
{
    public function __construct(public readonly string $raw)
    {
    }

    /** The raw bytes of a Bytes or a PHP string; null for anything else. */
    public static function of(mixed $v): ?string
    {
        return $v instanceof self ? $v->raw : (is_string($v) ? $v : null);
    }
}
