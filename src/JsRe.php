<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/SafeRegex.php';

/**
 * A translator from the JavaScript regular expression dialect (ECMAScript, no flags, Annex B leniency) used by `path_re` of the suggestion rules to a PCRE
 * pattern with the same meaning on UTF-16 code units. It exists so a rule set is accepted or refused exactly as the reference's `new RegExp(...)` does and
 * matches the same locations. Syntax the reference rejects throws \ValueError. Supported: literals, `.`, anchors, `\b \B`, classes with ranges and class
 * escapes, groups `(...)` and `(?:...)`, alternation, greedy and lazy quantifiers. Lookaround, named groups and back-references are refused (the rule
 * validator refuses them before a pattern is compiled).
 *
 * Every UTF-16 code unit is one PCRE code point: a surrogate unit u is the code point u + 0x100000 (so a lone surrogate is matched as one character, as in
 * the reference), every other unit is itself.
 *
 * @internal helper of {@see ActionsImportSuggest}; not part of the package's public surface.
 */
final class JsRe
{
    private const WS = [[9, 13], [32, 32], [0xA0, 0xA0], [0x1680, 0x1680], [0x2000, 0x200A], [0x2028, 0x2029], [0x202F, 0x202F], [0x205F, 0x205F], [0x3000, 0x3000], [0xFEFF, 0xFEFF]];
    private const DIGIT = [[48, 57]];
    private const WORD = [[48, 57], [65, 90], [95, 95], [97, 122]];
    private const MAX = 0xFFFF;
    private const CTRL = [102 => 12, 110 => 10, 114 => 13, 116 => 9, 118 => 11]; // f n r t v

    /** @var array<string,string> compiled pattern cache */
    private static array $cache = [];

    /** @var list<int> */
    private array $s;
    private int $i = 0;

    /** @param list<int> $units */
    private function __construct(array $units)
    {
        $this->s = $units;
    }

    // ---- interval sets --------------------------------------------------------------------------------------------------

    /** @param list<array{int,int}> $iv @return list<array{int,int}> */
    private static function norm(array $iv): array
    {
        usort($iv, static fn(array $a, array $b): int => [$a[0], $a[1]] <=> [$b[0], $b[1]]);
        $out = [];
        foreach ($iv as [$lo, $hi]) {
            $n = count($out);
            if ($n > 0 && $lo <= $out[$n - 1][1] + 1) {
                $out[$n - 1][1] = max($out[$n - 1][1], $hi);
            } else {
                $out[] = [$lo, $hi];
            }
        }
        return $out;
    }

    /** @param list<array{int,int}> $iv @return list<array{int,int}> */
    private static function neg(array $iv): array
    {
        $out = [];
        $cur = 0;
        foreach (self::norm($iv) as [$lo, $hi]) {
            if ($lo > $cur) {
                $out[] = [$cur, $lo - 1];
            }
            $cur = $hi + 1;
        }
        if ($cur <= self::MAX) {
            $out[] = [$cur, self::MAX];
        }
        return $out;
    }

    private static function cp(int $u): string
    {
        return '\\x{' . dechex($u >= 0xD800 && $u <= 0xDFFF ? $u + 0x100000 : $u) . '}';
    }

    /** @param list<array{int,int}> $iv */
    private static function cls(array $iv): string
    {
        $iv = self::norm($iv);
        if ($iv === []) {
            return '(?!)';
        }
        $out = '[';
        foreach ($iv as [$lo, $hi]) {
            if ($lo < 0xD800) {
                $out .= self::range($lo, min($hi, 0xD7FF));
            }
            if ($hi >= 0xD800 && $lo <= 0xDFFF) {
                $out .= self::range(max($lo, 0xD800), min($hi, 0xDFFF));
            }
            if ($hi > 0xDFFF) {
                $out .= self::range(max($lo, 0xE000), $hi);
            }
        }
        return $out . ']';
    }

    private static function range(int $lo, int $hi): string
    {
        return $lo === $hi ? self::cp($lo) : self::cp($lo) . '-' . self::cp($hi);
    }

    /** @return list<array{int,int}>|null */
    private static function classOf(int $c): ?array
    {
        return match ($c) {
            100 => self::DIGIT, 119 => self::WORD, 115 => self::WS,
            68 => self::neg(self::DIGIT), 87 => self::neg(self::WORD), 83 => self::neg(self::WS),
            default => null,
        };
    }

    // ---- parser ---------------------------------------------------------------------------------------------------------

    private function peek(int $k = 0): int
    {
        return $this->s[$this->i + $k] ?? -1;
    }

    private function err(string $msg): never
    {
        throw new \ValueError("Invalid regular expression: $msg");
    }

    private function disjunction(int $depth): string
    {
        $alts = [$this->alternative($depth)];
        while ($this->peek() === 124) {
            $this->i++;
            $alts[] = $this->alternative($depth);
        }
        return implode('|', $alts);
    }

    private function alternative(int $depth): string
    {
        $out = '';
        while ($this->i < count($this->s) && $this->peek() !== 124 && $this->peek() !== 41) {
            $out .= $this->term($depth);
        }
        return $out;
    }

    /** {n}, {n,} or {n,m} at the cursor: [min, max or null, length], or null when the brace is not a quantifier. @return array{int,?int,int}|null */
    private function braced(): ?array
    {
        $j = $this->i + 1;
        $a = $j;
        while (($this->s[$j] ?? -1) >= 48 && ($this->s[$j] ?? -1) <= 57) {
            $j++;
        }
        if ($j === $a) {
            return null;
        }
        $lo = (int)implode('', array_map('chr', array_slice($this->s, $a, $j - $a)));
        $hi = $lo;
        if (($this->s[$j] ?? -1) === 44) {
            $j++;
            $b = $j;
            while (($this->s[$j] ?? -1) >= 48 && ($this->s[$j] ?? -1) <= 57) {
                $j++;
            }
            $hi = $j === $b ? null : (int)implode('', array_map('chr', array_slice($this->s, $b, $j - $b)));
        }
        if (($this->s[$j] ?? -1) !== 125) {
            return null;
        }
        $j++;
        if ($hi !== null && $hi < $lo) {
            $this->err('numbers out of order in {} quantifier');
        }
        return [$lo, $hi, $j - $this->i];
    }

    private function quantifier(string $atom): string
    {
        $c = $this->peek();
        if ($c === 42 || $c === 43 || $c === 63) {
            $this->i++;
            $q = chr($c);
        } else {
            $b = $c === 123 ? $this->braced() : null;
            if ($b === null) {
                return $atom;
            }
            $this->i += $b[2];
            $q = '{' . $b[0] . ',' . ($b[1] ?? '') . '}';
        }
        if ($this->peek() === 63) {
            $this->i++;
            $q .= '?';
        }
        return $atom . $q;
    }

    private function term(int $depth): string
    {
        $c = $this->peek();
        if ($c === 94) {
            $this->i++;
            return '\\A';
        }
        if ($c === 36) {
            $this->i++;
            return '\\z';
        }
        if ($c === 92 && ($this->peek(1) === 98 || $this->peek(1) === 66)) {
            $this->i += 2;
            // PHP's /u also turns on Unicode word semantics, so the ASCII-only word boundary is spelled out
            $w = '[0-9A-Za-z_]';
            return $this->s[$this->i - 1] === 98
                ? "(?:(?<=$w)(?!$w)|(?<!$w)(?=$w))"
                : "(?:(?<=$w)(?=$w)|(?<!$w)(?!$w))";
        }
        if ($c === 42 || $c === 43 || $c === 63) {
            $this->err('nothing to repeat');
        }
        if ($c === 123 && $this->braced() !== null) {
            $this->err('nothing to repeat');
        }
        return $this->quantifier($this->atom($depth));
    }

    private function atom(int $depth): string
    {
        $c = $this->peek();
        if ($depth > 200) {
            $this->err('too deeply nested');
        }
        if ($c === 40) {
            $this->i++;
            if ($this->peek() === 63) {
                if ($this->peek(1) !== 58) {
                    $this->err('invalid group');
                }
                $this->i += 2;
                $head = '(?:';
            } else {
                $head = '(';
            }
            $body = $this->disjunction($depth + 1);
            if ($this->peek() !== 41) {
                $this->err('unterminated group');
            }
            $this->i++;
            return $head . $body . ')';
        }
        if ($c === 46) {
            $this->i++;
            return '[^\\x{a}\\x{d}\\x{2028}\\x{2029}]';
        }
        if ($c === 91) {
            return $this->charClass();
        }
        if ($c === 92) {
            return $this->atomEscape();
        }
        $this->i++;
        return self::cp($c);
    }

    private function hex(int $n): ?int
    {
        $h = '';
        for ($k = 0; $k < $n; $k++) {
            $u = $this->s[$this->i + $k] ?? -1;
            if (!(($u >= 48 && $u <= 57) || ($u >= 65 && $u <= 70) || ($u >= 97 && $u <= 102))) {
                return null;
            }
            $h .= chr($u);
        }
        $this->i += $n;
        return (int)hexdec($h);
    }

    /** The code unit a character escape at `\` denotes (cursor past the escape). */
    private function escapeChar(bool $inClass): int
    {
        $this->i++; // the backslash
        if ($this->i >= count($this->s)) {
            $this->err('\\ at end of pattern');
        }
        $c = $this->s[$this->i];
        if (isset(self::CTRL[$c])) {
            $this->i++;
            return self::CTRL[$c];
        }
        if ($c === 99) { // c
            $nxt = $this->peek(1);
            if (($nxt >= 65 && $nxt <= 90) || ($nxt >= 97 && $nxt <= 122)) {
                $this->i += 2;
                return $nxt % 32;
            }
            if ($inClass && (($nxt >= 48 && $nxt <= 57) || $nxt === 95)) {
                $this->i += 2;
                return $nxt % 32;
            }
            return 92; // a lone backslash; the `c` is read next
        }
        if ($c === 48) { // 0
            $this->i++;
            $p = $this->peek();
            if ($p >= 48 && $p <= 55) {
                $v = 0;
                $n = 0;
                while ($n < 3 && $this->peek() >= 48 && $this->peek() <= 55 && $v * 8 + ($this->peek() - 48) <= 255) {
                    $v = $v * 8 + ($this->peek() - 48);
                    $this->i++;
                    $n++;
                }
                return $v;
            }
            return 0;
        }
        if ($c === 120) { // x
            $this->i++;
            return $this->hex(2) ?? 120;
        }
        if ($c === 117) { // u
            $this->i++;
            return $this->hex(4) ?? 117;
        }
        if ($c === 98 && $inClass) {
            $this->i++;
            return 8;
        }
        if ($c >= 49 && $c <= 57) {
            $this->err('back-references are not supported');
        }
        $this->i++;
        return $c; // includes `k`
    }

    private function atomEscape(): string
    {
        $iv = self::classOf($this->peek(1));
        if ($iv !== null) {
            $this->i += 2;
            return self::cls($iv);
        }
        return self::cp($this->escapeChar(false));
    }

    /** @return array{?int,?list<array{int,int}>} (code unit, interval set) */
    private function classAtom(): array
    {
        $c = $this->peek();
        if ($c === 92) {
            $iv = self::classOf($this->peek(1));
            if ($iv !== null) {
                $this->i += 2;
                return [null, $iv];
            }
            return [$this->escapeChar(true), null];
        }
        $this->i++;
        return [$c, null];
    }

    private function charClass(): string
    {
        $this->i++;
        $negate = false;
        if ($this->peek() === 94) {
            $negate = true;
            $this->i++;
        }
        $iv = [];
        while (true) {
            if ($this->i >= count($this->s)) {
                $this->err('unterminated character class');
            }
            if ($this->peek() === 93) {
                $this->i++;
                break;
            }
            [$a, $aset] = $this->classAtom();
            if ($this->peek() === 45 && $this->peek(1) !== 93 && $this->peek(1) !== -1) {
                $this->i++;
                [$b, $bset] = $this->classAtom();
                if ($aset !== null || $bset !== null) { // Annex B: a class escape on either side makes the dash a literal
                    array_push($iv, ...($aset ?? [[$a, $a]]), ...[[45, 45]], ...($bset ?? [[$b, $b]]));
                    continue;
                }
                if ($a > $b) {
                    $this->err('range out of order in character class');
                }
                $iv[] = [$a, $b];
                continue;
            }
            array_push($iv, ...($aset ?? [[$a, $a]]));
        }
        return self::cls($negate ? self::neg($iv) : $iv);
    }

    // ---- entry points ---------------------------------------------------------------------------------------------------

    /** The PCRE pattern (with delimiters and the `u` modifier) for a JavaScript pattern, or \ValueError. */
    public static function translate(string $pattern): string
    {
        if (isset(self::$cache[$pattern])) {
            return self::$cache[$pattern];
        }
        $p = new self(SafeRegex::units($pattern));
        $out = $p->disjunction(0);
        if ($p->i < count($p->s)) {
            $p->err("unmatched ')'");
        }
        $rx = '/' . $out . '/u';
        if (@preg_match($rx, '') === false) {
            throw new \ValueError('Invalid regular expression: not representable');
        }
        if (count(self::$cache) >= 256) {
            self::$cache = [];
        }
        return self::$cache[$pattern] = $rx;
    }

    /** Throws \ValueError when the reference's `new RegExp(pattern)` would throw. */
    public static function compile(string $pattern): string
    {
        return self::translate($pattern);
    }

    /** RegExp.prototype.test: a match anywhere in the string (as UTF-16 code units). */
    public static function test(string $compiled, string $s): bool
    {
        $subject = '';
        foreach (SafeRegex::units($s) as $u) {
            $subject .= mb_chr($u >= 0xD800 && $u <= 0xDFFF ? $u + 0x100000 : $u, 'UTF-8');
        }
        return @preg_match($compiled, $subject) === 1;
    }
}
