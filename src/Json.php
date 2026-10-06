<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Canonical JSON matching @atlasauth/pca and the Go reference verifier byte-for-byte.
 * Values must come from json_decode($s, false): JSON objects are stdClass, arrays are PHP lists.
 * (Assoc arrays are also accepted as objects; an empty PHP array is a JSON array.)
 */
final class Json
{
    public static function parse(string $data): mixed
    {
        return json_decode($data, false, 512, JSON_THROW_ON_ERROR);
    }

    public static function canonicalize(mixed $v): string
    {
        $out = '';
        self::ser($out, $v);
        return $out;
    }

    private static function str(string &$out, string $s): void
    {
        $out .= '"';
        $n = strlen($s);
        for ($i = 0; $i < $n; $i++) {
            $c = $s[$i];
            $o = ord($c);
            if ($c === '"') {
                $out .= '\\"';
            } elseif ($c === '\\') {
                $out .= '\\\\';
            } elseif ($o === 8) {
                $out .= '\\b';
            } elseif ($o === 12) {
                $out .= '\\f';
            } elseif ($o === 10) {
                $out .= '\\n';
            } elseif ($o === 13) {
                $out .= '\\r';
            } elseif ($o === 9) {
                $out .= '\\t';
            } elseif ($o < 0x20) {
                $out .= sprintf('\\u%04x', $o);
            } else {
                $out .= $c; // UTF-8 bytes (incl. non-ASCII, 0x7f) emitted raw
            }
        }
        $out .= '"';
    }

    private static function num(int|float $n): string
    {
        if (is_int($n)) {
            return (string)$n;
        }
        if (is_nan($n) || is_infinite($n)) {
            throw new \InvalidArgumentException('canonicalize: non-finite number');
        }
        if ($n == 0.0) {
            return '0';
        }
        if ($n == floor($n) && abs($n) < 1e21) {
            return sprintf('%.0f', $n);
        }
        $s = (string)$n; // shortest round-trip repr
        if (stripos($s, 'e') !== false) {
            // expand exponent to plain decimal (Go 'f', -1)
            [$m, $e] = preg_split('/e/i', $s);
            $neg = $m[0] === '-';
            $m = ltrim($m, '-');
            $dot = strpos($m, '.');
            $digits = str_replace('.', '', $m);
            $ip = $dot === false ? strlen($m) : $dot;
            $pos = $ip + (int)$e;
            if ($pos <= 0) {
                $s = '0.' . str_repeat('0', -$pos) . $digits;
            } elseif ($pos >= strlen($digits)) {
                $s = $digits . str_repeat('0', $pos - strlen($digits));
            } else {
                $s = substr($digits, 0, $pos) . '.' . substr($digits, $pos);
            }
            $s = ($neg ? '-' : '') . $s;
        }
        return $s;
    }

    /** @return int[] UTF-16 code units of a UTF-8 string */
    private static function utf16(string $s): array
    {
        $units = [];
        $cps = preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY);
        if ($cps === false) {
            throw new \InvalidArgumentException('invalid UTF-8');
        }
        foreach ($cps as $ch) {
            $cp = mb_ord_compat($ch);
            if ($cp >= 0x10000) {
                $cp -= 0x10000;
                $units[] = 0xD800 + ($cp >> 10);
                $units[] = 0xDC00 + ($cp & 0x3FF);
            } else {
                $units[] = $cp;
            }
        }
        return $units;
    }

    private static function less(string $a, string $b): int
    {
        $x = self::utf16($a);
        $y = self::utf16($b);
        $n = min(count($x), count($y));
        for ($i = 0; $i < $n; $i++) {
            if ($x[$i] !== $y[$i]) {
                return $x[$i] <=> $y[$i];
            }
        }
        return count($x) <=> count($y);
    }

    private static function ser(string &$out, mixed $v): void
    {
        if ($v === null) {
            $out .= 'null';
        } elseif (is_bool($v)) {
            $out .= $v ? 'true' : 'false';
        } elseif (is_string($v)) {
            self::str($out, $v);
        } elseif (is_int($v) || is_float($v)) {
            $out .= self::num($v);
        } elseif (is_array($v) && ($v === [] || array_is_list($v))) {
            $out .= '[';
            foreach ($v as $i => $x) {
                if ($i > 0) {
                    $out .= ',';
                }
                self::ser($out, $x);
            }
            $out .= ']';
        } elseif (is_array($v) || $v instanceof \stdClass) {
            $props = is_array($v) ? $v : get_object_vars($v);
            $keys = array_map('strval', array_keys($props));
            usort($keys, [self::class, 'less']);
            $out .= '{';
            $first = true;
            foreach ($keys as $k) {
                if (!$first) {
                    $out .= ',';
                }
                $first = false;
                self::str($out, $k);
                $out .= ':';
                // numeric-string keys become int keys in PHP arrays; look up both
                $val = array_key_exists($k, $props) ? $props[$k] : $props[(int)$k];
                self::ser($out, $val);
            }
            $out .= '}';
        } else {
            throw new \InvalidArgumentException('canonicalize: unsupported type ' . get_debug_type($v));
        }
    }
}

/** Codepoint of one UTF-8 character without requiring ext-mbstring. */
function mb_ord_compat(string $ch): int
{
    $o = ord($ch[0]);
    return match (strlen($ch)) {
        1 => $o,
        2 => (($o & 0x1F) << 6) | (ord($ch[1]) & 0x3F),
        3 => (($o & 0x0F) << 12) | ((ord($ch[1]) & 0x3F) << 6) | (ord($ch[2]) & 0x3F),
        default => (($o & 0x07) << 18) | ((ord($ch[1]) & 0x3F) << 12) | ((ord($ch[2]) & 0x3F) << 6) | (ord($ch[3]) & 0x3F),
    };
}
