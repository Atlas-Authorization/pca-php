<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';

/** A CEL rejection: {code, message, at}. */
final class PolicyBridgeCelReject extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message, public readonly int $at)
    {
        parent::__construct($message);
    }
}

/**
 * Strict CEL parser (the reference's subset). It reads the source as JavaScript does: a list of UTF-16 code units, each
 * one a WTF-8 character (an astral code point is two surrogate halves), so offsets and messages agree with the reference.
 */
final class PolicyBridgeCelParser
{
    private const MAX_EXPR = 4096;
    private const MAX_DEPTH = 32;
    private const MAX_NODES = 256;
    private const MAX_LIST = 64;
    private const MAX_STR = 256;
    private const PUNCT = ['&&', '||', '==', '!=', '<=', '>=', '<', '>', '!', '(', ')', '[', ']', ',', '.', '-'];
    private const UNSUPPORTED_CH = [
        '+' => 'arithmetic (+)', '*' => 'arithmetic (*)', '/' => 'arithmetic (/)', '%' => 'arithmetic (%)', '?' => 'the conditional operator',
        ':' => 'the conditional operator / map literal', '{' => 'map or message literal', '}' => 'map or message literal', '@' => '@',
        '&' => 'bitwise &', '|' => 'bitwise |', '^' => '^', '~' => '~', '=' => 'assignment', '`' => 'quoted identifier',
    ];
    private const RELOPS = ['==', '!=', '<', '<=', '>', '>='];
    private const REJECTED_FUNCS = [
        'size', 'matches', 'exists', 'all', 'exists_one', 'map', 'filter', 'int', 'uint', 'double', 'string', 'bytes', 'bool', 'duration',
        'type', 'dyn', 'min', 'max', 'getHours', 'getDayOfWeek', 'getMinutes', 'getSeconds', 'getFullYear', 'getMonth', 'getDate',
        'getDayOfMonth', 'getDayOfYear', 'getMilliseconds', 'extract', 'format', 'lowerAscii', 'upperAscii', 'trim', 'split', 'join',
        'replace', 'substring', 'indexOf', 'lastIndexOf', 'charAt', 'isIpv4', 'inIpRange', 'cidr', 'ip', 'isCIDR', 'containsIp', 'url',
        'quantity', 'semver', 'optional',
    ];
    private const ESCAPES = ['\\' => '\\', '"' => '"', "'" => "'", 'n' => "\n", 't' => "\t", 'r' => "\r"];

    /** @var list<string> */
    private array $src;
    private int $n;
    /** @var list<array{k:string,v:string,at:int}> */
    private array $toks = [];
    private int $pos = 0;
    private int $nodes = 0;

    /** @param list<string> $src */
    private function __construct(array $src)
    {
        $this->src = $src;
        $this->n = count($src);
    }

    private static function wtf8(int $u): string
    {
        if ($u < 0x80) {
            return chr($u);
        }
        if ($u < 0x800) {
            return chr(0xC0 | ($u >> 6)) . chr(0x80 | ($u & 0x3F));
        }
        return chr(0xE0 | ($u >> 12)) . chr(0x80 | (($u >> 6) & 0x3F)) . chr(0x80 | ($u & 0x3F));
    }

    /** The UTF-16 units of a (WTF-8) string, one WTF-8 character each. @return list<string> */
    public static function units(string $s): array
    {
        $u = [];
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $u[] = $s[$i];
                $i++;
            } elseif ($b < 0xE0) {
                $u[] = self::wtf8((($b & 0x1F) << 6) | (ord($s[$i + 1] ?? "\0") & 0x3F));
                $i += 2;
            } elseif ($b < 0xF0) {
                $u[] = self::wtf8((($b & 0x0F) << 12) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 2] ?? "\0") & 0x3F));
                $i += 3;
            } else {
                $cp = ((($b & 7) << 18) | ((ord($s[$i + 1] ?? "\0") & 0x3F) << 12) | ((ord($s[$i + 2] ?? "\0") & 0x3F) << 6) | (ord($s[$i + 3] ?? "\0") & 0x3F)) - 0x10000;
                $u[] = self::wtf8(0xD800 + ($cp >> 10));
                $u[] = self::wtf8(0xDC00 + ($cp & 0x3FF));
                $i += 4;
            }
        }
        return $u;
    }

    private static function rej(string $code, string $message, int $at): never
    {
        throw new PolicyBridgeCelReject($code, $message, $at);
    }

    private static function isLetter(string $c): bool
    {
        return strlen($c) === 1 && (ctype_alpha($c) || $c === '_');
    }

    private static function isDigit(string $c): bool
    {
        return strlen($c) === 1 && ctype_digit($c);
    }

    /** The AST of an expression: null / a non-string source is an empty expression. */
    public static function parse(mixed $expression): array
    {
        if (!is_string($expression) || $expression === '') {
            self::rej('syntax', 'empty expression', 0);
        }
        $p = new self(self::units($expression));
        if ($p->n > self::MAX_EXPR) {
            self::rej('too_complex', 'expression longer than ' . self::MAX_EXPR . ' characters', 0);
        }
        $p->lex();
        $root = $p->expr(0);
        if ($p->pos < count($p->toks)) {
            $t = $p->toks[$p->pos];
            self::rej('syntax', "unexpected '" . $t['v'] . "'", $t['at']);
        }
        return $root;
    }

    private function at(int $i): string
    {
        return $this->src[$i] ?? '';
    }

    private function lex(): void
    {
        $src = $this->src;
        $n = $this->n;
        $i = 0;
        while ($i < $n) {
            $c = $src[$i];
            if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r") {
                $i++;
                continue;
            }
            if ($c === '/' && $this->at($i + 1) === '/') {
                self::rej('unsupported', 'comments', $i);
            }
            if (self::isLetter($c)) {
                $j = $i + 1;
                while ($j < $n && (self::isLetter($src[$j]) || self::isDigit($src[$j]))) {
                    $j++;
                }
                $w = implode('', array_slice($src, $i, $j - $i));
                if (in_array($w, ['r', 'b', 'R', 'B'], true) && in_array($this->at($j), ['"', "'"], true)) {
                    self::rej('unsupported', (strtolower($w) === 'r' ? 'raw string' : 'bytes') . ' literal', $i);
                }
                $this->toks[] = ['k' => 'id', 'v' => $w, 'at' => $i];
                $i = $j;
                continue;
            }
            if (self::isDigit($c)) {
                $j = $i;
                while ($j < $n && self::isDigit($src[$j])) {
                    $j++;
                }
                $nxt = $this->at($j);
                if ($nxt === '.' && self::isDigit($this->at($j + 1))) {
                    self::rej('unsupported', 'double literal', $i);
                }
                if ($nxt === 'e' || $nxt === 'E') {
                    self::rej('unsupported', 'double literal', $i);
                }
                if ($nxt === 'u' || $nxt === 'U') {
                    self::rej('unsupported', 'unsigned integer literal', $i);
                }
                if ($nxt === 'x' || $nxt === 'X') {
                    self::rej('unsupported', 'hexadecimal literal', $i);
                }
                $w = implode('', array_slice($src, $i, $j - $i));
                if (strlen($w) > 1 && $w[0] === '0') {
                    self::rej('unsupported', 'integer literal with a leading zero', $i);
                }
                $this->toks[] = ['k' => 'int', 'v' => $w, 'at' => $i];
                $i = $j;
                continue;
            }
            if ($c === '"' || $c === "'") {
                if ($this->at($i + 1) === $c && $this->at($i + 2) === $c) {
                    self::rej('unsupported', 'triple-quoted string', $i);
                }
                $j = $i + 1;
                $parts = [];
                while (true) {
                    $d = $this->at($j);
                    if ($d === '' || $d === "\n" || $d === "\r") {
                        self::rej('syntax', 'unterminated string', $i);
                    }
                    if ($d === $c) {
                        break;
                    }
                    if ($d === '\\') {
                        $e = $this->at($j + 1);
                        if ($e === '' || !array_key_exists($e, self::ESCAPES)) {
                            self::rej('unsupported', 'string escape \\' . $e, $j);
                        }
                        $parts[] = self::ESCAPES[$e];
                        $j += 2;
                        continue;
                    }
                    $parts[] = $d;
                    $j++;
                }
                if (count($parts) > self::MAX_STR) {
                    self::rej('too_complex', 'string literal longer than ' . self::MAX_STR, $i);
                }
                $this->toks[] = ['k' => 'str', 'v' => implode('', $parts), 'at' => $i];
                $i = $j + 1;
                continue;
            }
            $p = null;
            $two = $c . $this->at($i + 1);
            foreach (self::PUNCT as $x) {
                if (strlen($x) === 2 ? $two === $x : $c === $x) {
                    $p = $x;
                    break;
                }
            }
            if ($p === null) {
                if (array_key_exists($c, self::UNSUPPORTED_CH)) {
                    self::rej('unsupported', self::UNSUPPORTED_CH[$c], $i);
                }
                self::rej('syntax', "unexpected character '$c'", $i);
            }
            $this->toks[] = ['k' => 'p', 'v' => $p, 'at' => $i];
            $i += strlen($p);
        }
    }

    private static function fdiv(int $a, int $b): int
    {
        return intdiv($a, $b) - (($a % $b !== 0 && ($a < 0) !== ($b < 0)) ? 1 : 0);
    }

    private static function daysFromCivil(int $y, int $m, int $d): int
    {
        if ($m <= 2) {
            $y--;
        }
        $era = self::fdiv($y >= 0 ? $y : $y - 399, 400);
        $yoe = $y - $era * 400;
        $doy = self::fdiv(153 * ($m + ($m > 2 ? -3 : 9)) + 2, 5) + $d - 1;
        $doe = $yoe * 365 + self::fdiv($yoe, 4) - self::fdiv($yoe, 100) + $doy;
        return $era * 146097 + $doe - 719468;
    }

    private static function parseTimestamp(string $s, int $at): int
    {
        if (preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?Z\z/', $s, $m) !== 1) {
            self::rej('unsupported', 'timestamp() argument must be RFC 3339 UTC (Z) with at most millisecond precision', $at);
        }
        [$y, $mo, $d, $h, $mi, $sec] = [(int)$m[1], (int)$m[2], (int)$m[3], (int)$m[4], (int)$m[5], (int)$m[6]];
        $ms = (int)str_pad($m[7] ?? '', 3, '0', STR_PAD_RIGHT);
        $leap = $y % 4 === 0 && ($y % 100 !== 0 || $y % 400 === 0);
        $dim = [31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        if (!($mo >= 1 && $mo <= 12 && $d >= 1 && $d <= $dim[$mo - 1] && $h <= 23 && $mi <= 59 && $sec <= 59)) {
            self::rej('unsupported', 'timestamp() is not a real instant', $at);
        }
        return (((self::daysFromCivil($y, $mo, $d) * 24 + $h) * 60 + $mi) * 60 + $sec) * 1000 + $ms;
    }

    // ---- parser ---------------------------------------------------------------------------------------------------------------

    private function peek(): ?array
    {
        return $this->toks[$this->pos] ?? null;
    }

    private function isP(string $v): bool
    {
        $t = $this->peek();
        return $t !== null && $t['k'] === 'p' && $t['v'] === $v;
    }

    private function eat(string $v): bool
    {
        if ($this->isP($v)) {
            $this->pos++;
            return true;
        }
        return false;
    }

    private function need(string $v): void
    {
        if (!$this->eat($v)) {
            $t = $this->peek();
            self::rej('syntax', "expected '$v'", $t !== null ? $t['at'] : $this->n);
        }
    }

    private function tick(int $at): void
    {
        $this->nodes++;
        if ($this->nodes > self::MAX_NODES) {
            self::rej('too_complex', 'more than ' . self::MAX_NODES . ' nodes', $at);
        }
    }

    private function expr(int $d): array
    {
        if ($d > self::MAX_DEPTH) {
            $t = $this->peek();
            self::rej('too_complex', 'nesting deeper than ' . self::MAX_DEPTH, $t !== null ? $t['at'] : 0);
        }
        return $this->orE($d);
    }

    private function orE(int $d): array
    {
        $left = $this->andE($d);
        while ($this->isP('||')) {
            $at = $this->peek()['at'];
            $this->pos++;
            $this->tick($at);
            $left = ['t' => 'or', 'l' => $left, 'r' => $this->andE($d), 'at' => $at];
        }
        return $left;
    }

    private function andE(int $d): array
    {
        $left = $this->rel($d);
        while ($this->isP('&&')) {
            $at = $this->peek()['at'];
            $this->pos++;
            $this->tick($at);
            $left = ['t' => 'and', 'l' => $left, 'r' => $this->rel($d), 'at' => $at];
        }
        return $left;
    }

    private static function isRelop(array $t): bool
    {
        return ($t['k'] === 'p' && in_array($t['v'], self::RELOPS, true)) || ($t['k'] === 'id' && $t['v'] === 'in');
    }

    private function rel(int $d): array
    {
        $left = $this->unary($d);
        $t = $this->peek();
        if ($t === null || !self::isRelop($t)) {
            return $left;
        }
        $this->pos++;
        $this->tick($t['at']);
        $n = ['t' => 'rel', 'op' => $t['v'], 'l' => $left, 'r' => $this->unary($d), 'at' => $t['at']];
        $u = $this->peek();
        if ($u !== null && self::isRelop($u)) {
            self::rej('unsupported', 'chained comparison', $u['at']);
        }
        return $n;
    }

    private function unary(int $d): array
    {
        $t = $this->peek();
        if ($t !== null && $t['k'] === 'p' && $t['v'] === '!') {
            $this->pos++;
            $this->tick($t['at']);
            if ($d + 1 > self::MAX_DEPTH) {
                self::rej('too_complex', 'nesting deeper than ' . self::MAX_DEPTH, $t['at']);
            }
            return ['t' => 'not', 'e' => $this->unary($d + 1), 'at' => $t['at']];
        }
        if ($t !== null && $t['k'] === 'p' && $t['v'] === '-') {
            $nx = $this->toks[$this->pos + 1] ?? null;
            if ($nx === null || $nx['k'] !== 'int') {
                self::rej('unsupported', 'unary minus on a non-literal', $t['at']);
            }
            $this->pos += 2;
            return $this->intNode('-' . $nx['v'], $t['at']);
        }
        return $this->member($d);
    }

    private function intNode(string $text, int $at): array
    {
        $this->tick($at);
        $f = (float)$text; // Number(text): a literal too long for a double is Infinity (an (int) cast of it would be 0)
        $v = (int)$f;
        if (!is_finite($f) || abs($f) > 9007199254740991.0) {
            self::rej('unsupported', 'integer literal outside the safe-integer range', $at);
        }
        return ['t' => 'int', 'v' => $v, 'at' => $at];
    }

    /** @return list<array> */
    private function args(int $d): array
    {
        $a = [];
        if (!$this->isP(')')) {
            $a[] = $this->expr($d + 1);
            while ($this->eat(',')) {
                $a[] = $this->expr($d + 1);
            }
        }
        $this->need(')');
        return $a;
    }

    private function member(int $d): array
    {
        $n = $this->primary($d);
        while ($this->isP('.')) {
            $dot = $this->peek();
            $this->pos++;
            $ident = $this->peek();
            if ($ident === null || $ident['k'] !== 'id') {
                self::rej('syntax', "expected a name after '.'", $dot['at']);
            }
            $this->pos++;
            if ($this->isP('(')) {
                $this->pos++;
                $a = $this->args($d);
                if (!in_array($ident['v'], ['startsWith', 'endsWith', 'contains'], true)) {
                    self::rej('unsupported', "method '" . $ident['v'] . "'", $ident['at']);
                }
                if (count($a) !== 1) {
                    self::rej('syntax', "'" . $ident['v'] . "' takes one argument", $ident['at']);
                }
                $this->tick($ident['at']);
                $n = ['t' => 'method', 'target' => $n, 'fn' => $ident['v'], 'arg' => $a[0], 'at' => $ident['at']];
            } else {
                if ($n['t'] !== 'var') {
                    self::rej('unsupported', 'field selection on something that is not a declared variable', $dot['at']);
                }
                $n['name'] = $n['name'] . '.' . $ident['v'];
            }
        }
        if ($this->isP('[')) {
            self::rej('unsupported', 'index operator', $this->peek()['at']);
        }
        return $n;
    }

    private function primary(int $d): array
    {
        $t = $this->peek();
        if ($t === null) {
            self::rej('syntax', 'unexpected end of expression', $this->n);
        }
        if ($t['k'] === 'int') {
            $this->pos++;
            return $this->intNode($t['v'], $t['at']);
        }
        if ($t['k'] === 'str') {
            $this->pos++;
            $this->tick($t['at']);
            return ['t' => 'str', 'v' => $t['v'], 'at' => $t['at']];
        }
        if ($t['k'] === 'p' && $t['v'] === '(') {
            $this->pos++;
            $e = $this->expr($d + 1);
            $this->need(')');
            return $e;
        }
        if ($t['k'] === 'p' && $t['v'] === '[') {
            $this->pos++;
            $items = [];
            if (!$this->isP(']')) {
                while (true) {
                    if (count($items) >= self::MAX_LIST) {
                        self::rej('too_complex', 'list longer than ' . self::MAX_LIST, $t['at']);
                    }
                    $items[] = $this->expr($d + 1);
                    if (!$this->eat(',')) {
                        break;
                    }
                }
            }
            $this->need(']');
            $this->tick($t['at']);
            return ['t' => 'list', 'items' => $items, 'at' => $t['at']];
        }
        if ($t['k'] === 'id') {
            $this->pos++;
            if ($t['v'] === 'true' || $t['v'] === 'false') {
                $this->tick($t['at']);
                return ['t' => 'bool', 'v' => $t['v'] === 'true', 'at' => $t['at']];
            }
            if ($t['v'] === 'null') {
                self::rej('unsupported', 'null', $t['at']);
            }
            if ($this->isP('(')) {
                $this->pos++;
                $a = $this->args($d);
                if ($t['v'] === 'has') {
                    if (count($a) !== 1 || $a[0]['t'] !== 'var') {
                        self::rej('syntax', 'has() takes one declared variable', $t['at']);
                    }
                    $this->tick($t['at']);
                    return ['t' => 'has', 'e' => $a[0], 'at' => $t['at']];
                }
                if ($t['v'] === 'timestamp') {
                    if (count($a) !== 1 || $a[0]['t'] !== 'str') {
                        self::rej('unsupported', 'timestamp() of a non-literal', $t['at']);
                    }
                    return ['t' => 'ts', 'v' => self::parseTimestamp($a[0]['v'], $t['at']), 'at' => $t['at']];
                }
                self::rej('unsupported', (in_array($t['v'], self::REJECTED_FUNCS, true) ? 'function' : 'unknown function') . " '" . $t['v'] . "'", $t['at']);
            }
            if ($t['v'] === 'in') {
                self::rej('syntax', "unexpected 'in'", $t['at']);
            }
            $this->tick($t['at']);
            return ['t' => 'var', 'name' => $t['v'], 'at' => $t['at']];
        }
        self::rej('syntax', "unexpected '" . $t['v'] . "'", $t['at']);
    }
}

/** The CEL -> PCA condition translation over a parsed expression and a schema. */
final class PolicyBridgeCelTranslator
{
    /** @var array<string,true> */
    private array $fields = [];

    public function __construct(private readonly Obj $svars)
    {
    }

    /** @return list<string> */
    public function fields(): array
    {
        $f = array_map('strval', array_keys($this->fields));
        sort($f, SORT_STRING);
        return $f;
    }

    private static function rej(string $code, string $message, int $at): never
    {
        throw new PolicyBridgeCelReject($code, $message, $at);
    }

    private function operand(array $n): array
    {
        switch ($n['t']) {
            case 'var':
                if (!$this->svars->has($n['name'])) {
                    self::rej('unknown_identifier', "'" . $n['name'] . "' is not declared in the schema", $n['at']);
                }
                return ['kind' => 'var', 'v' => $this->svars->get($n['name']), 'name' => $n['name']];
            case 'int':
                return ['kind' => 'lit', 'type' => 'int', 'value' => $n['v']];
            case 'str':
                return ['kind' => 'lit', 'type' => 'string', 'value' => $n['v']];
            case 'bool':
                return ['kind' => 'lit', 'type' => 'bool', 'value' => $n['v']];
            case 'ts':
                return ['kind' => 'lit', 'type' => 'timestamp_ms', 'value' => $n['v']];
        }
        self::rej('unsupported', 'a computed value as a comparison operand', $n['at']);
    }

    private static function typeOf(array $o): string
    {
        return $o['kind'] === 'var' ? $o['v']->get('type') : $o['type'];
    }

    private function read(array $o): string
    {
        $p = $o['v']->get('path');
        $this->fields[$p] = true;
        return $p;
    }

    /** @return list<array> */
    private function flat(array $n, string $t, array $out = []): array
    {
        if ($n['t'] === $t) {
            $out = $this->flat($n['l'], $t, $out);
            return $this->flat($n['r'], $t, $out);
        }
        $out[] = $n;
        return $out;
    }

    public function tr(array $n): array
    {
        $t = $n['t'];
        if ($t === 'or') {
            return ['any_of' => array_map($this->tr(...), $this->flat($n, 'or'))];
        }
        if ($t === 'and') {
            return ['all_of' => array_map($this->tr(...), $this->flat($n, 'and'))];
        }
        if ($t === 'not') {
            return ['not' => $this->tr($n['e'])];
        }
        if ($t === 'has') {
            $o = $this->operand($n['e']);
            if ($o['kind'] !== 'var') {
                self::rej('syntax', 'has() takes a declared variable', $n['at']);
            }
            if ($o['v']->get('optional') !== true) {
                self::rej('has_requires_optional', 'has(' . $o['name'] . '): mark the variable optional in the schema (its container must always be present)', $n['at']);
            }
            return ['field' => $this->read($o), 'op' => 'exists', 'value' => true];
        }
        if ($t === 'var') {
            $o = $this->operand($n);
            $hint = ($o['kind'] === 'var' && $o['v']->get('type') === 'bool') ? ' (write ' . $n['name'] . ' == true)' : '';
            self::rej('unsupported', "a bare variable '" . $n['name'] . "' as a condition" . $hint, $n['at']);
        }
        if ($t === 'method') {
            $tg = $this->operand($n['target']);
            if ($tg['kind'] !== 'var' || $tg['v']->get('type') !== 'string') {
                self::rej('type_mismatch', $n['fn'] . ' needs a string variable', $n['at']);
            }
            if ($n['arg']['t'] !== 'str' || $n['arg']['v'] === '') {
                self::rej('unsupported', $n['fn'] . ' of anything but a non-empty string literal', $n['at']);
            }
            $lit = $n['arg']['v'];
            if ($n['fn'] === 'startsWith') {
                return ['field' => $this->read($tg), 'op' => 'prefix', 'value' => $lit];
            }
            $esc = (string)preg_replace('/[\\\\*?]/', '\\\\$0', $lit);
            $glob = $n['fn'] === 'endsWith' ? '*' . $esc : '*' . $esc . '*';
            if (Js::len($glob) > 512) {
                self::rej('too_complex', 'literal too long for a glob', $n['at']);
            }
            return ['field' => $this->read($tg), 'op' => 'like', 'value' => $glob];
        }
        if ($t === 'rel') {
            if ($n['op'] === 'in') {
                $left = $this->operand($n['l']);
                if ($left['kind'] !== 'var') {
                    self::rej('constant_expression', 'the left side of "in" must be a declared variable', $n['at']);
                }
                if ($n['r']['t'] !== 'list' || $n['r']['items'] === []) {
                    self::rej('unsupported', '"in" against anything but a non-empty list literal', $n['at']);
                }
                $items = array_map($this->operand(...), $n['r']['items']);
                foreach ($items as $i) {
                    if ($i['kind'] !== 'lit' || $i['type'] !== $left['v']->get('type')) {
                        self::rej('type_mismatch', 'list items must be ' . $left['v']->get('type') . ' literals', $n['at']);
                    }
                }
                return ['field' => $this->read($left), 'op' => 'in', 'value' => array_map(static fn($i) => $i['value'], $items)];
            }
            $left = $this->operand($n['l']);
            $right = $this->operand($n['r']);
            if ($left['kind'] === 'lit' && $right['kind'] === 'lit') {
                self::rej('constant_expression', 'a comparison of two literals', $n['at']);
            }
            if (self::typeOf($left) !== self::typeOf($right)) {
                self::rej('type_mismatch', self::typeOf($left) . ' against ' . self::typeOf($right), $n['at']);
            }
            $ty = self::typeOf($left);
            $eqOp = $n['op'] === '==' || $n['op'] === '!=';
            if (!$eqOp && $ty === 'bool') {
                self::rej('type_mismatch', 'ordering of booleans', $n['at']);
            }
            $pcaOp = ['==' => 'eq', '!=' => 'ne', '<' => 'lt', '<=' => 'lte', '>' => 'gt', '>=' => 'gte'][$n['op']];
            $flip = ['eq' => 'eq', 'ne' => 'ne', 'lt' => 'gt', 'lte' => 'gte', 'gt' => 'lt', 'gte' => 'lte'];
            if ($left['kind'] === 'var' && $right['kind'] === 'var') {
                return ['field' => $this->read($left), 'op' => $pcaOp, 'ref' => $this->read($right)];
            }
            if ($left['kind'] === 'var') {
                return ['field' => $this->read($left), 'op' => $pcaOp, 'value' => $right['value']];
            }
            return ['field' => $this->read($right), 'op' => $flip[$pcaOp], 'value' => $left['value']];
        }
        self::rej('constant_expression', 'a bare constant is not a condition', $n['at']);
    }
}

/** Strict CEL: one boolean expression as one PCA condition, or a rejection naming the construct. */
final class PolicyBridgeCel
{
    private const FORBIDDEN = ['__proto__', 'constructor', 'prototype'];
    private const INTERNAL = ['ok' => false, 'code' => 'syntax', 'message' => 'internal error', 'at' => 0];

    /** The units of a result back to code points: a surrogate pair written as two halves becomes one character. */
    private static function pairs(string $s): string
    {
        if (!str_contains($s, "\xED")) {
            return $s;
        }
        return preg_replace_callback('/\xED([\xA0-\xAF])([\x80-\xBF])\xED([\xB0-\xBF])([\x80-\xBF])/', static function (array $m): string {
            $hi = 0xD000 + ((ord($m[1]) & 0x3F) << 6) + (ord($m[2]) & 0x3F);
            $lo = 0xD000 + ((ord($m[3]) & 0x3F) << 6) + (ord($m[4]) & 0x3F);
            return mb_chr(0x10000 + (($hi - 0xD800) << 10) + ($lo - 0xDC00), 'UTF-8');
        }, $s) ?? $s;
    }

    private static function fin(mixed $v): mixed
    {
        if (is_string($v)) {
            return self::pairs($v);
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(self::fin(...), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set(self::pairs((string)$k), self::fin($x));
            }
            return $o;
        }
        return $v;
    }

    private static function error(PolicyBridgeCelReject $e): array
    {
        return ['ok' => false, 'code' => $e->codeName, 'message' => $e->getMessage(), 'at' => $e->at];
    }

    /** Parse a CEL expression of the supported subset: {ok: true, ast} or {ok: false, code, message, at}. */
    public static function parseCel(mixed $expression): Obj
    {
        try {
            return self::fin(['ok' => true, 'ast' => PolicyBridgeCelParser::parse($expression)]);
        } catch (PolicyBridgeCelReject $e) {
            return self::fin(self::error($e));
        } catch (\Throwable) { // the reference reports any non-rejection as an internal error
            return self::fin(self::INTERNAL);
        }
    }

    private static function schemaError(mixed $s): ?string
    {
        if (!($s instanceof Obj)) {
            return 'the schema must be an object';
        }
        $vars = $s->get('vars');
        if (!($vars instanceof Obj)) {
            return 'the schema needs a vars object';
        }
        foreach (Js::ownKeys($vars->keys()) as $name) {
            $v = $vars->get($name);
            if (preg_match('/\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\z/', $name) !== 1 || array_intersect(explode('.', $name), self::FORBIDDEN) !== []) {
                return "bad variable name '$name'";
            }
            $path = $v instanceof Obj ? $v->get('path') : null;
            if (!($v instanceof Obj) || !is_string($path) || preg_match('/\A(?:action|subject|env)(?:\.[A-Za-z_][A-Za-z0-9_]*)+\z/', $path) !== 1 || array_intersect(explode('.', $path), self::FORBIDDEN) !== []) {
                return "variable '$name' needs a path rooted at action, subject or env";
            }
            $t = $v->get('type');
            if (!is_string($t) || !in_array($t, ['string', 'int', 'bool', 'timestamp_ms'], true)) {
                return "variable '$name' has an unsupported type";
            }
            if ($v->has('optional') && !is_bool($v->get('optional'))) {
                return "variable '$name': optional must be a boolean";
            }
        }
        return null;
    }

    /** @return array<string,mixed> unit-form result (call fin before returning it) */
    private static function toCondition(mixed $expression, mixed $schema): array
    {
        $se = self::schemaError($schema);
        if ($se !== null) {
            return ['ok' => false, 'code' => 'bad_schema', 'message' => $se, 'at' => 0];
        }
        try {
            $ast = PolicyBridgeCelParser::parse($expression);
        } catch (PolicyBridgeCelReject $e) {
            return self::error($e);
        } catch (\Throwable) {
            return self::INTERNAL;
        }
        $tr = new PolicyBridgeCelTranslator($schema->get('vars'));
        try {
            $condition = $tr->tr($ast);
            $fields = $tr->fields();
            if ($fields === []) {
                throw new PolicyBridgeCelReject('constant_expression', 'the expression reads no variable', 0);
            }
            return ['ok' => true, 'condition' => $condition, 'fields' => $fields];
        } catch (PolicyBridgeCelReject $e) {
            return self::error($e);
        } catch (\Throwable) {
            return self::INTERNAL;
        }
    }

    /**
     * ONE boolean CEL expression as a PCA condition: {ok: true, condition, fields} or {ok: false, code, message, at}.
     * `$schema` is {vars: {name: {path, type, optional?}}}.
     */
    public static function celToCondition(mixed $expression, mixed $schema): Obj
    {
        return self::fin(self::toCondition($expression, $schema));
    }

    /** @return array<string,mixed> */
    private static function toPredicate(mixed $expression, mixed $schema, mixed $scope): array
    {
        $r = self::toCondition($expression, $schema);
        if (!$r['ok']) {
            return $r;
        }
        if (!($scope instanceof Obj)) {
            throw new \TypeError("cannot read properties of null (reading 'verb')");
        }
        $p = [];
        if ($scope->has('verb')) {
            $p['verb'] = $scope->get('verb');
        }
        if ($scope->has('resource')) {
            $p['resource'] = $scope->get('resource');
        }
        $p['where'] = [$r['condition']];
        return ['ok' => true, 'predicate' => $p, 'fields' => $r['fields']];
    }

    /** One CEL expression as a permit predicate for `scope.verb` (and optionally `scope.resource`). */
    public static function celToPredicate(mixed $expression, mixed $schema, mixed $scope): Obj
    {
        return self::fin(self::toPredicate($expression, $schema, $scope));
    }

    private static function jsText(bool $present, mixed $x): string
    {
        if (!$present) {
            return 'undefined';
        }
        if ($x === null) {
            return 'null';
        }
        if (is_bool($x)) {
            return $x ? 'true' : 'false';
        }
        return Js::str($x);
    }

    /**
     * A batch of named CEL expressions: every one is translated or REPORTED; one rejection makes `report.errors` non-empty, and
     * decide then denies everything (an incomplete import never grants).
     */
    public static function celConditionsToPca(mixed $items, mixed $schema): Obj
    {
        if (!is_array($items) || !array_is_list($items)) {
            throw new \TypeError('items is not iterable');
        }
        $predicates = [];
        $translated = [];
        $errors = [];
        foreach ($items as $it) {
            if (!($it instanceof Obj)) {
                throw new \TypeError('item is not an object');
            }
            $scope = new Obj();
            if ($it->has('verb')) {
                $scope->set('verb', $it->get('verb'));
            }
            if ($it->has('resource')) {
                $scope->set('resource', $it->get('resource'));
            }
            $r = self::toPredicate($it->get('expression'), $schema, $scope);
            $name = self::jsText($it->has('name'), $it->get('name'));
            if ($r['ok']) {
                $predicates[] = $r['predicate'];
                $translated[] = "$name: translated exactly (reads " . implode(', ', $r['fields']) . ')';
            } else {
                $errors[] = "$name: rejected (" . $r['code'] . ') at ' . $r['at'] . ': ' . $r['message'];
            }
        }
        return self::fin(['predicates' => $predicates, 'denies' => [], 'caveats' => [], 'report' => ['source' => 'cel', 'translated' => $translated, 'skipped' => [], 'errors' => $errors]]);
    }
}
