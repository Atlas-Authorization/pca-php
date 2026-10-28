<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Common.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;

/** Internal: a parse failure with the position it was detected at. */
final class JsJsonFail extends \RuntimeException
{
    public function __construct(string $m, public readonly int $pos, public readonly bool $extra = false)
    {
        parent::__construct($m);
    }
}

/**
 * JSON.parse with V8-style error messages (the vectors pin the reference's reason text, which embeds the engine's message).
 * Grammar: RFC 8259 (NaN, Infinity and friends are refused), duplicate keys keep the last value, numbers keep their lexeme
 * ({@see Num}). The V8 wording covers the common failures (end of input, unexpected token / string / number, trailing text).
 * Positions are byte offsets (equal to UTF-16 positions for the ASCII documents the vectors use).
 */
final class JsJson
{
    private int $i = 0;
    private int $n;

    private function __construct(private string $s)
    {
        $this->n = strlen($s);
    }

    /** @throws JsError */
    public static function parse(string $text): mixed
    {
        try {
            return (new self($text))->run();
        } catch (JsJsonFail $e) {
            throw new JsError(self::message($text, $e));
        }
    }

    private static function message(string $text, JsJsonFail $e): string
    {
        $stripped = ltrim($text, " \t\n\r");
        if ($stripped === '') {
            return 'Unexpected end of JSON input';
        }
        $lead = strlen($text) - strlen($stripped);
        foreach (['null', 'true', 'false'] as $lit) {
            if ($lit[0] === $stripped[0]) {
                $k = 0;
                while ($k < strlen($lit) && $lead + $k < strlen($text) && $text[$lead + $k] === $lit[$k]) {
                    $k++;
                }
                if ($k < strlen($lit)) {
                    return self::v8($text, $lead + $k);
                }
            }
        }
        if ($e->extra) {
            return 'Unexpected non-whitespace character after JSON at position ' . $e->pos;
        }
        return self::v8($text, $e->pos);
    }

    private static function v8(string $text, int $pos): string
    {
        $n = strlen($text);
        if ($pos >= $n) {
            return 'Unexpected end of JSON input';
        }
        if (in_array($text, ['NaN', 'Infinity', 'undefined', '[object Object]'], true)) {
            return "\"$text\" is not valid JSON";
        }
        $ch = $text[$pos];
        if ($ch === '"') {
            return "Unexpected string in JSON at position $pos";
        }
        if (ctype_digit($ch) || $ch === '-') {
            return "Unexpected number in JSON at position $pos";
        }
        $ctx = 10;
        if ($n < 2 * $ctx + 1) {
            return "Unexpected token '$ch', \"$text\" is not valid JSON";
        }
        if ($pos < $ctx) {
            return "Unexpected token '$ch', \"" . substr($text, 0, $pos + $ctx) . '"... is not valid JSON';
        }
        if ($pos < $n - $ctx) {
            return "Unexpected token '$ch', ...\"" . substr($text, $pos - $ctx, 2 * $ctx) . '"... is not valid JSON';
        }
        return "Unexpected token '$ch', ...\"" . substr($text, $pos - $ctx) . '" is not valid JSON';
    }

    private function fail(string $m, ?int $pos = null): never
    {
        throw new JsJsonFail($m, $pos ?? $this->i);
    }

    private function run(): mixed
    {
        $this->ws();
        $v = $this->value();
        $this->ws();
        if ($this->i < $this->n) {
            throw new JsJsonFail('Extra data', $this->i, true);
        }
        return $v;
    }

    private function ws(): void
    {
        while ($this->i < $this->n && strpos(" \t\n\r", $this->s[$this->i]) !== false) {
            $this->i++;
        }
    }

    private function peek(): string
    {
        return $this->i < $this->n ? $this->s[$this->i] : '';
    }

    private function value(): mixed
    {
        $c = $this->peek();
        if ($c === '"') {
            return $this->string();
        }
        if ($c === '{') {
            return $this->object();
        }
        if ($c === '[') {
            return $this->arr();
        }
        foreach (['null' => null, 'true' => true, 'false' => false] as $lit => $v) {
            if (substr($this->s, $this->i, strlen($lit)) === $lit) {
                $this->i += strlen($lit);
                return $v;
            }
        }
        if ($c !== '' && ($c === '-' || ctype_digit($c))) {
            if (preg_match('/\G-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/', $this->s, $m, 0, $this->i) === 1) {
                $this->i += strlen($m[0]);
                return new Num($m[0]);
            }
        }
        if (in_array(substr($this->s, $this->i, 3), ['NaN'], true) || substr($this->s, $this->i, 8) === 'Infinity' || substr($this->s, $this->i, 9) === '-Infinity') {
            throw new JsJsonFail('constant', 0);
        }
        $this->fail('Expecting value');
    }

    private function object(): Obj
    {
        $this->i++;
        $o = new Obj();
        $this->ws();
        if ($this->peek() === '}') {
            $this->i++;
            return $o;
        }
        if ($this->peek() !== '"') {
            $this->fail('Expecting property name enclosed in double quotes');
        }
        while (true) {
            $k = $this->string();
            $this->ws();
            if ($this->peek() !== ':') {
                $this->fail("Expecting ':' delimiter");
            }
            $this->i++;
            $this->ws();
            $o->set($k, $this->value());
            $this->ws();
            $d = $this->peek();
            if ($d === '}') {
                $this->i++;
                return $o;
            }
            if ($d !== ',') {
                $this->fail("Expecting ',' delimiter");
            }
            $this->i++;
            $this->ws();
            if ($this->peek() !== '"') {
                $this->fail('Expecting property name enclosed in double quotes');
            }
        }
    }

    private function arr(): array
    {
        $this->i++;
        $a = [];
        $this->ws();
        if ($this->peek() === ']') {
            $this->i++;
            return $a;
        }
        while (true) {
            $this->ws();
            $a[] = $this->value();
            $this->ws();
            $d = $this->peek();
            if ($d === ']') {
                $this->i++;
                return $a;
            }
            if ($d !== ',') {
                $this->fail("Expecting ',' delimiter");
            }
            $this->i++;
        }
    }

    private static function utf8(int $cp): string
    {
        if ($cp < 0x80) {
            return chr($cp);
        }
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18)) . chr(0x80 | (($cp >> 12) & 0x3F)) . chr(0x80 | (($cp >> 6) & 0x3F)) . chr(0x80 | ($cp & 0x3F));
    }

    private function hex4(int $at): int
    {
        $h = substr($this->s, $at, 4);
        if (strlen($h) !== 4 || !ctype_xdigit($h)) {
            $this->fail('Invalid \\uXXXX escape', $at - 1);
        }
        return (int)hexdec($h);
    }

    private function string(): string
    {
        $start = $this->i;
        $this->i++;
        $out = '';
        while (true) {
            if ($this->i >= $this->n) {
                $this->fail('Unterminated string starting at', $start);
            }
            $c = $this->s[$this->i];
            if ($c === '"') {
                $this->i++;
                return $out;
            }
            if (ord($c) < 0x20) {
                $this->fail('Invalid control character at');
            }
            if ($c !== '\\') {
                $out .= $c;
                $this->i++;
                continue;
            }
            $this->i++;
            if ($this->i >= $this->n) {
                $this->fail('Unterminated string starting at', $start);
            }
            $e = $this->s[$this->i];
            if ($e === 'u') {
                $cp = $this->hex4($this->i + 1);
                $this->i += 5;
                if ($cp >= 0xD800 && $cp <= 0xDBFF && substr($this->s, $this->i, 2) === '\\u') {
                    $lo = $this->hex4($this->i + 2);
                    if ($lo >= 0xDC00 && $lo <= 0xDFFF) {
                        $cp = 0x10000 + (($cp - 0xD800) << 10) + ($lo - 0xDC00);
                        $this->i += 6;
                    }
                }
                $out .= self::utf8($cp);
                continue;
            }
            $map = ['"' => '"', '\\' => '\\', '/' => '/', 'b' => "\x08", 'f' => "\x0C", 'n' => "\n", 'r' => "\r", 't' => "\t"];
            if (!isset($map[$e])) {
                $this->fail('Invalid \\escape', $this->i - 1);
            }
            $out .= $map[$e];
            $this->i++;
        }
    }
}
