<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** A JSON number kept as its source lexeme (never coerced to PHP int/float). */
final class Num
{
    public function __construct(public readonly string $lexeme)
    {
    }

    public function isInt(): bool
    {
        return preg_match('/\A-?(?:0|[1-9][0-9]*)\z/D', $this->lexeme) === 1;
    }

    /** Integer value; only meaningful for a strict-valid integer lexeme (|n| <= 2^53-1). */
    public function int(): int
    {
        return (int)$this->lexeme;
    }

    /** Float value (strtod; independent of the `precision` ini). */
    public function float(): float
    {
        return (float)$this->lexeme;
    }

    /** Strict-profile error string, or null when the lexeme is in the canonical number form. */
    public function strictError(): ?string
    {
        $l = $this->lexeme;
        if (preg_match('/[eE]/', $l)) {
            return 'exponent form is not allowed';
        }
        if ($l === '-0') {
            return 'negative zero is not allowed';
        }
        if (str_contains($l, '.')) {
            if (str_ends_with($l, '0')) {
                return 'trailing fractional zero is not canonical';
            }
            $digits = ltrim(str_replace(['-', '.'], '', $l), '0');
            if (strlen($digits) > 15) {
                return 'more than 15 significant digits';
            }
            [$ip, $fp] = explode('.', ltrim($l, '-'), 2);
            if ($ip === '0' && strlen($fp) - strlen(ltrim($fp, '0')) >= 6) {
                return 'non-integer magnitude below 1e-6';
            }
            return null;
        }
        $abs = ltrim($l, '-');
        if (strlen($abs) > 16 || (strlen($abs) === 16 && strcmp($abs, '9007199254740991') > 0)) {
            return 'integer outside the safe range';
        }
        return null;
    }
}

/**
 * A JSON object that preserves every key exactly (including "" and keys containing U+0000, numeric-looking
 * keys, and key order). PHP arrays/stdClass cannot: they coerce "1" to int and reject "\0..." properties.
 */
final class Obj
{
    /** @var list<string> */
    private array $keys = [];
    /** @var array<string,mixed> 'k'.key => value */
    private array $vals = [];

    /** Build from a PHP assoc array (internal use: keys must be plain non-numeric-coercion-safe strings). */
    public static function of(array $a): self
    {
        $o = new self();
        foreach ($a as $k => $v) {
            $o->set((string)$k, $v);
        }
        return $o;
    }

    public function has(string $k): bool
    {
        return array_key_exists('k' . $k, $this->vals);
    }

    public function get(string $k): mixed
    {
        return $this->vals['k' . $k] ?? null;
    }

    /** @return bool true when newly added, false on a duplicate (value is NOT replaced) */
    public function add(string $k, mixed $v): bool
    {
        if ($this->has($k)) {
            return false;
        }
        $this->set($k, $v);
        return true;
    }

    public function set(string $k, mixed $v): void
    {
        if (!$this->has($k)) {
            $this->keys[] = $k;
        }
        $this->vals['k' . $k] = $v;
    }

    /** @return list<string> */
    public function keys(): array
    {
        return $this->keys;
    }

    public function without(string ...$drop): self
    {
        $o = new self();
        foreach ($this->keys as $k) {
            if (!in_array($k, $drop, true)) {
                $o->set($k, $this->get($k));
            }
        }
        return $o;
    }
}

final class JsonError extends \RuntimeException
{
}

/**
 * Strict JSON profile + strict canonical form (wire format v2). Values: Obj, list arrays, string, Num, bool, null.
 */
final class Json
{
    public const MAX_DEPTH = 32;
    public const MAX_CHARS = 1048576;

    // ---- strict parse ---------------------------------------------------------------------

    /** Strict profile parse of signed bytes. Throws JsonError. */
    public static function parseStrict(string $text, bool $requireObject = false): mixed
    {
        if (!preg_match('//u', $text)) {
            throw new JsonError('invalid UTF-8');
        }
        if (strlen($text) > self::MAX_CHARS) { // 2^20 UTF-8 BYTES
            throw new JsonError('input too long');
        }
        $v = (new Parser($text, self::MAX_DEPTH))->run();
        self::canonicalizeStrict($v); // number form, lone surrogates, depth
        if ($requireObject && !($v instanceof Obj)) {
            throw new JsonError('top-level value must be an object');
        }
        return $v;
    }

    /** Loader parse (grammar-strict, but number form / lone surrogates / depth are left to the wire check). */
    public static function parseLax(string $text): mixed
    {
        if (!preg_match('//u', $text)) {
            throw new JsonError('invalid UTF-8');
        }
        return (new Parser($text, 512))->run();
    }

    // ---- canonical form -------------------------------------------------------------------

    /** STRICT canonical JSON (throws JsonError on any profile violation). */
    public static function canonicalizeStrict(mixed $v): string
    {
        $out = '';
        self::ser($out, $v, 1);
        return $out;
    }

    public static function hasLoneSurrogate(string $s): bool
    {
        return preg_match('/\xED[\xA0-\xBF]/', $s) === 1;
    }

    private static function str(string &$out, string $s): void
    {
        if (self::hasLoneSurrogate($s)) {
            throw new JsonError('lone surrogate in string');
        }
        $out .= '"' . preg_replace_callback(
            '/["\\\\\x00-\x1f]/',
            static function (array $m): string {
                $c = $m[0];
                return match ($c) {
                    '"' => '\\"', '\\' => '\\\\', "\x08" => '\\b', "\x0c" => '\\f',
                    "\n" => '\\n', "\r" => '\\r', "\t" => '\\t',
                    default => sprintf('\\u%04x', ord($c)),
                };
            },
            $s
        ) . '"';
    }

    private static function ser(string &$out, mixed $v, int $depth): void
    {
        if ($v === null) {
            $out .= 'null';
        } elseif (is_bool($v)) {
            $out .= $v ? 'true' : 'false';
        } elseif (is_string($v)) {
            self::str($out, $v);
        } elseif ($v instanceof Num) {
            $e = $v->strictError();
            if ($e !== null) {
                throw new JsonError($e);
            }
            $out .= $v->lexeme; // the canonical form IS the lexeme (no float round-trip, no `precision` ini)
        } elseif (is_array($v) && array_is_list($v)) {
            if ($depth > self::MAX_DEPTH) {
                throw new JsonError('nesting too deep');
            }
            $out .= '[';
            foreach ($v as $i => $x) {
                if ($i > 0) {
                    $out .= ',';
                }
                self::ser($out, $x, $depth + 1);
            }
            $out .= ']';
        } elseif ($v instanceof Obj) {
            if ($depth > self::MAX_DEPTH) {
                throw new JsonError('nesting too deep');
            }
            $keys = $v->keys();
            usort($keys, 'strcmp'); // bytewise over UTF-8
            $out .= '{';
            $first = true;
            foreach ($keys as $k) {
                if (!$first) {
                    $out .= ',';
                }
                $first = false;
                self::str($out, $k);
                $out .= ':';
                self::ser($out, $v->get($k), $depth + 1);
            }
            $out .= '}';
        } else {
            throw new JsonError('canonicalize: unsupported type ' . get_debug_type($v));
        }
    }
}

/** Hand-written RFC 8259 parser (bytes of valid UTF-8). */
final class Parser
{
    private int $i = 0;
    private int $n;

    public function __construct(private string $s, private int $maxDepth)
    {
        $this->n = strlen($s);
    }

    private function err(string $m): never
    {
        throw new JsonError("$m at byte {$this->i}");
    }

    public function run(): mixed
    {
        $v = $this->value(1);
        $this->ws();
        if ($this->i < $this->n) {
            $this->err('trailing data');
        }
        return $v;
    }

    private function ws(): void
    {
        while ($this->i < $this->n) {
            $c = $this->s[$this->i];
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                $this->i++;
            } else {
                break;
            }
        }
    }

    private function value(int $depth): mixed
    {
        $this->ws();
        if ($this->i >= $this->n) {
            $this->err('unexpected end');
        }
        $c = $this->s[$this->i];
        if ($c === '{') {
            if ($depth > $this->maxDepth) {
                $this->err('nesting too deep');
            }
            $this->i++;
            $o = new Obj();
            $this->ws();
            if ($this->peek() === '}') {
                $this->i++;
                return $o;
            }
            while (true) {
                $this->ws();
                if ($this->peek() !== '"') {
                    $this->err('expected string key');
                }
                $k = $this->string();
                $this->ws();
                if ($this->peek() !== ':') {
                    $this->err("expected ':'");
                }
                $this->i++;
                $v = $this->value($depth + 1);
                if (!$o->add($k, $v)) {
                    $this->err('duplicate key');
                }
                $this->ws();
                $d = $this->peek();
                $this->i++;
                if ($d === '}') {
                    return $o;
                }
                if ($d !== ',') {
                    $this->err("expected ',' or '}'");
                }
            }
        }
        if ($c === '[') {
            if ($depth > $this->maxDepth) {
                $this->err('nesting too deep');
            }
            $this->i++;
            $a = [];
            $this->ws();
            if ($this->peek() === ']') {
                $this->i++;
                return $a;
            }
            while (true) {
                $a[] = $this->value($depth + 1);
                $this->ws();
                $d = $this->peek();
                $this->i++;
                if ($d === ']') {
                    return $a;
                }
                if ($d !== ',') {
                    $this->err("expected ',' or ']'");
                }
            }
        }
        if ($c === '"') {
            return $this->string();
        }
        if ($c === '-' || ($c >= '0' && $c <= '9')) {
            if (!preg_match('/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/', $this->s, $m, 0, $this->i)) {
                $this->err('bad number');
            }
            $this->i += strlen($m[0]);
            return new Num($m[0]);
        }
        foreach (['true' => true, 'false' => false, 'null' => null] as $lit => $val) {
            if (substr($this->s, $this->i, strlen($lit)) === $lit) {
                $this->i += strlen($lit);
                return $val;
            }
        }
        $this->err('unexpected character');
    }

    private function peek(): string
    {
        return $this->i < $this->n ? $this->s[$this->i] : '';
    }

    private function hex4(): int
    {
        $h = substr($this->s, $this->i, 4);
        if (strlen($h) !== 4 || !ctype_xdigit($h)) {
            $this->err('bad \\u escape');
        }
        $this->i += 4;
        return hexdec($h);
    }

    private static function utf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) { // includes lone surrogates (WTF-8), rejected later by the strict profile
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F)) . chr(0x80 | (($cp >> 6) & 0x3F))
            . chr(0x80 | ($cp & 0x3F));
    }

    private function string(): string
    {
        $this->i++; // opening quote
        $out = '';
        while (true) {
            if ($this->i >= $this->n) {
                $this->err('unterminated string');
            }
            // fast path: run of ordinary bytes
            $len = strcspn($this->s, "\"\\\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                . "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", $this->i);
            $out .= substr($this->s, $this->i, $len);
            $this->i += $len;
            if ($this->i >= $this->n) {
                $this->err('unterminated string');
            }
            $c = $this->s[$this->i];
            if ($c === '"') {
                $this->i++;
                return $out;
            }
            if ($c !== '\\') {
                $this->err('raw control character in string');
            }
            $this->i++;
            $e = $this->peek();
            $this->i++;
            switch ($e) {
                case '"': $out .= '"'; break;
                case '\\': $out .= '\\'; break;
                case '/': $out .= '/'; break;
                case 'b': $out .= "\x08"; break;
                case 'f': $out .= "\x0c"; break;
                case 'n': $out .= "\n"; break;
                case 'r': $out .= "\r"; break;
                case 't': $out .= "\t"; break;
                case 'u':
                    $cp = $this->hex4();
                    if ($cp >= 0xD800 && $cp <= 0xDBFF && substr($this->s, $this->i, 2) === '\\u') {
                        $save = $this->i;
                        $this->i += 2;
                        $lo = $this->hex4();
                        if ($lo >= 0xDC00 && $lo <= 0xDFFF) {
                            $cp = 0x10000 + (($cp - 0xD800) << 10) + ($lo - 0xDC00);
                        } else {
                            $this->i = $save; // leave the next escape to be parsed on its own
                        }
                    }
                    $out .= self::utf8($cp);
                    break;
                default:
                    $this->err('unknown escape');
            }
        }
    }
}
