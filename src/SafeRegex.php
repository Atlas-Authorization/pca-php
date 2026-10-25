<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * A linear-time, budgeted regular-expression matcher for untrusted `re:` / `matches` patterns, plus the
 * linear-time-safe source guard and the per-document regex work budget.
 *
 * Port of packages/pca/src safe-regex.ts (Thompson NFA + Pike simulation over UTF-16 code units, exactly like a flagless
 * JS RegExp), predicates.ts isSafeRegexSource (the backtracking-cost guard) and regex-budget.ts (document / request
 * budgets). PHP's preg engine is NEVER run on an untrusted pattern: the pattern is parsed once, by this parser.
 *
 * `fullMatch($src, $subject)` is semantically `new RegExp('^(?:' + src + ')$').test(subject)` for every accepted pattern;
 * null when `src` is outside the subset (or too large) or the per-match work budget would be exceeded.
 *
 * Strings are PHP strings in the Json representation (UTF-8; a lone surrogate is a 3-byte WTF-8 sequence); every length
 * and every character test is over UTF-16 code units (an astral character is two units).
 */
final class SafeRegex
{
    /** Largest NFA (instruction count) a pattern may compile to. */
    public const MAX_NFA_INSTRUCTIONS = 4096;
    /** Largest `{n,m}` bound. */
    public const MAX_REPEAT = 64;
    /** Hard cap on (NFA size x (subject length + 1)). */
    public const MAX_MATCH_STEPS = 2000000;

    /** isSafeRegexSource: largest bounded repeat, backtracking-cost budget (bits) and the cost of an unbounded quantifier. */
    public const MAX_BOUNDED_REPEAT = 64;
    public const MAX_REGEX_COST_BITS = 22;
    public const UNBOUNDED_QUANTIFIER_BITS = 8;

    /** Per-document regex work budget (regex-budget.ts). */
    public const MAX_REGEX_EVALUATIONS_PER_DOCUMENT = 64;
    public const MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT = 8192;
    public const MAX_REGEX_STEPS_PER_DOCUMENT = 5000000;
    public const REGEX_REQUEST_SCALE = 4;

    /** Bounded compiled-program cache (a verdict is a pure function of the source; the cache only saves work). */
    private const CACHE_MAX = 1024;

    // instruction opcodes
    public const OP_SET = 0;
    public const OP_SPLIT = 1;
    public const OP_JMP = 2;
    public const OP_BOL = 3;
    public const OP_EOL = 4;
    public const OP_MATCH = 5;

    public const DIGIT = [[0x30, 0x39]];
    public const WORD = [[0x30, 0x39], [0x41, 0x5a], [0x5f, 0x5f], [0x61, 0x7a]];
    public const SPACE = [
        [0x09, 0x0d], [0x20, 0x20], [0xa0, 0xa0], [0x1680, 0x1680], [0x2000, 0x200a], [0x2028, 0x2029],
        [0x202f, 0x202f], [0x205f, 0x205f], [0x3000, 0x3000], [0xfeff, 0xfeff],
    ];
    public const LINE_TERMINATORS = [[0x0a, 0x0a], [0x0d, 0x0d], [0x2028, 0x2029]];

    /** @var array<string, ?array> */
    private static array $cache = [];
    /** The open budget scope (a synchronous module-level slot, restored in `finally`). */
    private static ?SafeRegexBudget $current = null;

    // ---- UTF-16 view of a Json string -------------------------------------------------------------------------------

    /** Number of UTF-16 code units (JS `.length`): astral characters count 2, WTF-8 lone surrogates count 1. */
    public static function utf16Len(string $s): int
    {
        return strlen($s) - preg_match_all('/[\x80-\xBF]/', $s) + preg_match_all('/[\xF0-\xF7]/', $s);
    }

    /**
     * The UTF-16 code units of a Json string (UTF-8, lone surrogates as WTF-8). A byte that does not start a well-formed
     * sequence (never produced by the Json parser) is taken as U+FFFD.
     *
     * @return list<int>
     */
    public static function units(string $s): array
    {
        $out = [];
        $n = strlen($s);
        $i = 0;
        while ($i < $n) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $out[] = $b;
                $i++;
                continue;
            }
            $len = $b >= 0xF0 && $b <= 0xF7 ? 4 : ($b >= 0xE0 ? ($b <= 0xEF ? 3 : 0) : ($b >= 0xC2 ? 2 : 0));
            $ok = $len > 0 && $i + $len <= $n;
            for ($k = 1; $ok && $k < $len; $k++) {
                $c = ord($s[$i + $k]);
                if ($c < 0x80 || $c > 0xBF) {
                    $ok = false;
                }
            }
            if (!$ok) {
                $out[] = 0xFFFD;
                $i++;
                continue;
            }
            if ($len === 2) {
                $cp = (($b & 0x1F) << 6) | (ord($s[$i + 1]) & 0x3F);
            } elseif ($len === 3) {
                $cp = (($b & 0x0F) << 12) | ((ord($s[$i + 1]) & 0x3F) << 6) | (ord($s[$i + 2]) & 0x3F);
            } else {
                $cp = (($b & 0x07) << 18) | ((ord($s[$i + 1]) & 0x3F) << 12) | ((ord($s[$i + 2]) & 0x3F) << 6)
                    | (ord($s[$i + 3]) & 0x3F);
            }
            if ($cp >= 0x10000) {
                $cp -= 0x10000;
                $out[] = 0xD800 | ($cp >> 10);
                $out[] = 0xDC00 | ($cp & 0x3FF);
            } else {
                $out[] = $cp;
            }
            $i += $len;
        }
        return $out;
    }

    /** `s.startsWith(prefix)` over UTF-16 code units. */
    public static function startsWithUnits(string $s, string $prefix): bool
    {
        if (str_starts_with($s, $prefix)) {
            return true; // a byte prefix of a well-formed (pairs-combined) string is a code-unit prefix
        }
        $a = self::units($s);
        $b = self::units($prefix);
        $m = count($b);
        if ($m > count($a)) {
            return false;
        }
        for ($i = 0; $i < $m; $i++) {
            if ($a[$i] !== $b[$i]) {
                return false;
            }
        }
        return true;
    }

    // ---- the source guard (predicates.ts isSafeRegexSource) ---------------------------------------------------------

    private static function isDigitUnit(?int $c): bool
    {
        return $c !== null && $c >= 0x30 && $c <= 0x39;
    }

    /**
     * `^\{(\d+)(?:(,)(\d*))?\}` (or, with $maxDigits, `^\{(\d{1,N})(?:(,)(\d{0,N}))?\}`) at $i over code units.
     *
     * @param list<int> $u
     * @return array{0:string,1:bool,2:string,3:int}|null [lo digits, has comma, hi digits, match length]
     */
    private static function scanBrace(array $u, int $i, ?int $maxDigits): ?array
    {
        $n = count($u);
        $j = $i + 1;
        $lo = '';
        while ($j < $n && self::isDigitUnit($u[$j])) {
            $lo .= chr($u[$j]);
            $j++;
        }
        if ($lo === '' || ($maxDigits !== null && strlen($lo) > $maxDigits)) {
            return null; // fewer digits would be followed by a digit: no match either
        }
        $c = $u[$j] ?? null;
        if ($c === 0x7D) { // }
            return [$lo, false, '', $j + 1 - $i];
        }
        if ($c !== 0x2C) { // ,
            return null;
        }
        $k = $j + 1;
        $hi = '';
        while ($k < $n && self::isDigitUnit($u[$k])) {
            $hi .= chr($u[$k]);
            $k++;
        }
        if ($maxDigits !== null && strlen($hi) > $maxDigits) {
            return null; // the optional group fails, and then `}` would be needed where `,` is
        }
        if (($u[$k] ?? null) !== 0x7D) {
            return null;
        }
        return [$lo, true, $hi, $k + 1 - $i];
    }

    /**
     * Validate that a `re:` / `matches` pattern is in the linear-time-safe subset: no quantified group containing a
     * quantifier or an alternation, no backreferences / lookaround / named groups, bounded repeats <= 64, a total
     * backtracking-cost budget of 22 bits; and the source must ALSO compile in the linear-time engine. Never throws.
     */
    public static function isSafeRegexSource(mixed $src): bool
    {
        if (!is_string($src)) {
            return false;
        }
        try {
            return self::isSafeRegexSourceInner($src);
        } catch (\Throwable) {
            return false;
        }
    }

    private static function isSafeRegexSourceInner(string $src): bool
    {
        $u = self::units($src);
        $n = count($u);
        // frames: [hasQuant, hasAlt]
        $stack = [[false, false]];
        $prev = 'none'; // 'none' | 'atom' | array frame
        $bits = 0;
        $i = 0;
        while ($i < $n) {
            $ch = $u[$i];
            if ($ch === 0x5C) { // backslash
                $nx = $u[$i + 1] ?? null;
                if ($nx === null) {
                    return false;
                }
                if (($nx >= 0x31 && $nx <= 0x39) || $nx === 0x6B) { // 1-9 or k: backreference
                    return false;
                }
                $i += 2;
                $prev = 'atom';
                continue;
            }
            if ($ch === 0x5B) { // [
                $j = $i + 1;
                if (($u[$j] ?? null) === 0x5E) {
                    $j++;
                }
                for (; $j < $n && $u[$j] !== 0x5D; $j++) {
                    if ($u[$j] === 0x5C) {
                        $j++;
                    }
                }
                if ($j >= $n) {
                    return false;
                }
                $i = $j + 1;
                $prev = 'atom';
                continue;
            }
            if ($ch === 0x28) { // (
                if (($u[$i + 1] ?? null) === 0x3F) {
                    if (($u[$i + 2] ?? null) !== 0x3A) {
                        return false; // lookahead / lookbehind / named group
                    }
                    $i += 3;
                } else {
                    $i += 1;
                }
                $stack[] = [false, false];
                $prev = 'none';
                continue;
            }
            if ($ch === 0x29) { // )
                if (count($stack) < 2) {
                    return false;
                }
                $f = array_pop($stack);
                $p = count($stack) - 1;
                $stack[$p][0] = $stack[$p][0] || $f[0];
                $stack[$p][1] = $stack[$p][1] || $f[1];
                $prev = $f;
                $i++;
                continue;
            }
            if ($ch === 0x7C) { // |
                if (++$bits > self::MAX_REGEX_COST_BITS) {
                    return false;
                }
                $stack[count($stack) - 1][1] = true;
                $prev = 'none';
                $i++;
                continue;
            }
            $q = null; // [len, unbounded, max(float), options(float)]
            if ($ch === 0x2A || $ch === 0x2B) { // * +
                $q = [1, true, INF, INF];
            } elseif ($ch === 0x3F) { // ?
                $q = [1, false, 1.0, 2.0];
            } elseif ($ch === 0x7B) { // {
                $m = self::scanBrace($u, $i, null);
                if ($m === null) {
                    return false;
                }
                $lo = (float)$m[0];
                $hi = !$m[1] ? $lo : ($m[2] === '' ? INF : (float)$m[2]);
                if ($hi < $lo) {
                    return false;
                }
                $q = [$m[3], $hi === INF, $hi, $hi === INF ? INF : $hi - $lo + 1];
            }
            if ($q !== null) {
                if ($prev === 'none') {
                    return false; // nothing to repeat
                }
                if (is_array($prev) && ($prev[0] || $prev[1])) {
                    return false; // nested quantifier
                }
                if (!$q[1] && $q[2] !== INF && $q[2] > self::MAX_BOUNDED_REPEAT) {
                    return false;
                }
                $bits += $q[1] ? self::UNBOUNDED_QUANTIFIER_BITS : ($q[3] > 1 ? self::ceilLog2($q[3]) : 0);
                if ($bits > self::MAX_REGEX_COST_BITS) {
                    return false;
                }
                $stack[count($stack) - 1][0] = true;
                $i += $q[0];
                if (($u[$i] ?? null) === 0x3F) {
                    $i++; // lazy modifier
                }
                $prev = 'none';
                continue;
            }
            $i++;
            $prev = 'atom';
        }
        return count($stack) === 1 && self::compileCached($src) !== null;
    }

    /** Math.ceil(Math.log2(x)) for a finite x > 1 (here x <= 65, an integer). */
    private static function ceilLog2(float $x): int
    {
        $b = 0;
        $p = 1.0;
        while ($p < $x) {
            $p *= 2;
            $b++;
        }
        return $b;
    }

    // ---- compile -----------------------------------------------------------------------------------------------------

    /**
     * Compile `src` into an NFA program (list of [op, x, y, ranges|null, negated]), or null when it is outside the
     * supported subset or too large. Never throws.
     */
    public static function compile(mixed $src): ?array
    {
        try {
            if (!is_string($src)) {
                return null;
            }
            $ast = (new SafeRegexParser(self::units($src)))->parse();
            $prog = [];
            self::emit($ast, $prog);
            $prog[] = [self::OP_MATCH, 0, 0, null, false];
            if (count($prog) > self::MAX_NFA_INSTRUCTIONS) {
                return null;
            }
            return $prog;
        } catch (\Throwable) {
            return null;
        }
    }

    /** compile() through the bounded cache (the null verdict is cached too). */
    public static function compileCached(string $src): ?array
    {
        $k = 'k' . $src;
        if (array_key_exists($k, self::$cache)) {
            return self::$cache[$k];
        }
        $p = self::compile($src);
        if (count(self::$cache) >= self::CACHE_MAX) {
            unset(self::$cache[array_key_first(self::$cache)]); // evict the oldest entry only
        }
        self::$cache[$k] = $p;
        return $p;
    }

    private static function emit(array $node, array &$prog): void
    {
        if (count($prog) > self::MAX_NFA_INSTRUCTIONS) {
            throw new SafeRegexRefuse('pattern too large');
        }
        switch ($node[0]) {
            case 'set':
                $prog[] = [self::OP_SET, 0, 0, $node[1], $node[2]];
                return;
            case 'bol':
                $prog[] = [self::OP_BOL, 0, 0, null, false];
                return;
            case 'eol':
                $prog[] = [self::OP_EOL, 0, 0, null, false];
                return;
            case 'cat':
                foreach ($node[1] as $it) {
                    self::emit($it, $prog);
                }
                return;
            case 'alt':
                $jmps = [];
                $items = $node[1];
                $cnt = count($items);
                for ($i = 0; $i < $cnt; $i++) {
                    if ($i < $cnt - 1) {
                        $split = count($prog);
                        $prog[] = [self::OP_SPLIT, $split + 1, -1, null, false];
                        self::emit($items[$i], $prog);
                        $jmps[] = count($prog);
                        $prog[] = [self::OP_JMP, -1, 0, null, false];
                        $prog[$split][2] = count($prog);
                    } else {
                        self::emit($items[$i], $prog);
                    }
                }
                foreach ($jmps as $j) {
                    $prog[$j][1] = count($prog);
                }
                return;
            case 'rep':
                [, $body, $min, $max] = $node;
                for ($i = 0; $i < $min; $i++) {
                    self::emit($body, $prog);
                }
                if ($max === null) { // unbounded
                    $split = count($prog);
                    $prog[] = [self::OP_SPLIT, $split + 1, -1, null, false];
                    self::emit($body, $prog);
                    $prog[] = [self::OP_JMP, $split, 0, null, false];
                    $prog[$split][2] = count($prog);
                } else {
                    $splits = [];
                    for ($i = $min; $i < $max; $i++) {
                        $splits[] = count($prog);
                        $prog[] = [self::OP_SPLIT, count($prog) + 1, -1, null, false];
                        self::emit($body, $prog);
                    }
                    foreach ($splits as $sp) {
                        $prog[$sp][2] = count($prog);
                    }
                }
                if (count($prog) > self::MAX_NFA_INSTRUCTIONS) {
                    throw new SafeRegexRefuse('pattern too large');
                }
                return;
        }
        throw new SafeRegexRefuse('unknown node');
    }

    // ---- match -------------------------------------------------------------------------------------------------------

    /** CharSet.has: binary search over sorted merged ranges, negation applied at test time. */
    private static function setHas(array $ranges, bool $negated, int $c): bool
    {
        $lo = 0;
        $hi = count($ranges) - 1;
        $inside = false;
        while ($lo <= $hi) {
            $mid = ($lo + $hi) >> 1;
            $r = $ranges[$mid];
            if ($c < $r[0]) {
                $hi = $mid - 1;
            } elseif ($c > $r[1]) {
                $lo = $mid + 1;
            } else {
                $inside = true;
                break;
            }
        }
        return $inside !== $negated;
    }

    /**
     * Full-match a UTF-16 code-unit list against a compiled program: true / false, or null when the work budget would be
     * exceeded. O(|subject| x |program|), no backtracking.
     *
     * @param list<int> $subject
     */
    public static function run(array $prog, array $subject): ?bool
    {
        $plen = count($prog);
        $n = count($subject);
        if ($plen * ($n + 1) > self::MAX_MATCH_STEPS) {
            return null;
        }
        $mark = array_fill(0, $plen, -1);
        $gen = 0;
        $matched = false;

        $add = static function (array &$list, int $pc0, int $pos) use ($prog, $n, &$mark, &$gen, &$matched): void {
            $stack = [$pc0];
            while ($stack !== []) {
                $pc = array_pop($stack);
                if ($mark[$pc] === $gen) {
                    continue;
                }
                $mark[$pc] = $gen;
                $ins = $prog[$pc];
                switch ($ins[0]) {
                    case self::OP_JMP:
                        $stack[] = $ins[1];
                        break;
                    case self::OP_SPLIT:
                        $stack[] = $ins[2];
                        $stack[] = $ins[1];
                        break;
                    case self::OP_BOL:
                        if ($pos === 0) {
                            $stack[] = $pc + 1;
                        }
                        break;
                    case self::OP_EOL:
                        if ($pos === $n) {
                            $stack[] = $pc + 1;
                        }
                        break;
                    case self::OP_MATCH:
                        if ($pos === $n) {
                            $matched = true;
                        }
                        break;
                    case self::OP_SET:
                        $list[] = $pc;
                        break;
                }
            }
        };

        $gen++;
        $clist = [];
        $add($clist, 0, 0);
        for ($pos = 0; $pos < $n; $pos++) {
            $c = $subject[$pos];
            $gen++;
            $nlist = [];
            foreach ($clist as $pc) {
                $ins = $prog[$pc];
                if (self::setHas($ins[3], $ins[4], $c)) {
                    $add($nlist, $pc + 1, $pos + 1);
                }
            }
            $clist = $nlist;
            if ($clist === [] && !$matched) {
                return false;
            }
        }
        return $matched;
    }

    /**
     * `new RegExp('^(?:' + src + ')$').test(subject)` over the supported subset, in linear time. Null when `src` is
     * outside the subset (or too large) or the work budget is exceeded; the caller fails closed. Never throws.
     */
    public static function fullMatch(string $src, string $subject): ?bool
    {
        try {
            $re = self::compileCached($src);
            if ($re === null) {
                return null;
            }
            return self::run($re, self::units($subject));
        } catch (\Throwable) {
            return null;
        }
    }

    // ---- per-document regex work budget (regex-budget.ts) -----------------------------------------------------------

    /** Program length of `src` through the compiled cache, null when it does not compile. */
    public static function progLen(string $src): ?int
    {
        $c = self::compileCached($src);
        return $c === null ? null : count($c);
    }

    /** A request-level budget (REGEX_REQUEST_SCALE documents' worth); run sections through `$b->run(fn)`. */
    public static function requestBudget(): SafeRegexBudget
    {
        return new SafeRegexBudget(self::REGEX_REQUEST_SCALE, null, false);
    }

    /** The open scope (null outside any scope). */
    public static function currentBudget(): ?SafeRegexBudget
    {
        return self::$current;
    }

    /** @internal installs / restores the open scope (SafeRegexBudget::run). */
    public static function swapBudget(?SafeRegexBudget $b): ?SafeRegexBudget
    {
        $prev = self::$current;
        self::$current = $b;
        return $prev;
    }

    /**
     * Run `fn` as ONE document. With an explicit budget it runs inside that budget; else it joins an open document scope;
     * else it opens a fresh document budget, chained to the enclosing request budget if there is one.
     *
     * @template T
     * @param callable():T $fn
     * @return T
     */
    public static function withBudget(callable $fn, ?SafeRegexBudget $budget = null): mixed
    {
        if ($budget !== null) {
            return $budget->run($fn);
        }
        if (self::$current !== null && self::$current->isDocument) {
            return $fn();
        }
        return (new SafeRegexBudget(1, self::$current, true))->run($fn);
    }

    /** The open scope's refusal count (0 outside a scope). */
    public static function regexRefusals(): int
    {
        return self::$current === null ? 0 : self::$current->refusals;
    }

    /**
     * Charge one regex evaluation (pattern `src` against a subject of `subjectLen` UTF-16 units) to the open scope; false
     * when it would exceed the budget (the caller must NOT run the match). Outside any scope: a fresh single-use budget.
     */
    public static function charge(string $src, int $subjectLen): bool
    {
        return (self::$current ?? new SafeRegexBudget(1, null, true))->charge($src, $subjectLen);
    }
}

/** A regex work budget: a DOCUMENT budget (scale 1) optionally chained to a REQUEST budget (scale REGEX_REQUEST_SCALE). */
final class SafeRegexBudget
{
    public int $evaluations = 0;
    public int $chars = 0;
    public int $steps = 0;
    /** Number of evaluations refused so far. */
    public int $refusals = 0;

    public function __construct(
        private readonly int $scale = 1,
        private readonly ?SafeRegexBudget $parent = null,
        public readonly bool $isDocument = true,
    ) {
    }

    public function parentBudget(): ?SafeRegexBudget
    {
        return $this->parent;
    }

    /** Charge one evaluation of `src` against a subject of `subjectLen` units; false = refused (and the budget poisoned). */
    public function charge(string $src, int $subjectLen): bool
    {
        $len = SafeRegex::progLen($src);
        if ($len === null) {
            $this->refusals++;
            return false;
        }
        $ev = $this->evaluations + 1;
        $chars = $this->chars + SafeRegex::utf16Len($src);
        $steps = $this->steps + $len * ($subjectLen + 1);
        $k = $this->scale;
        if (
            $ev > SafeRegex::MAX_REGEX_EVALUATIONS_PER_DOCUMENT * $k
            || $chars > SafeRegex::MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT * $k
            || $steps > SafeRegex::MAX_REGEX_STEPS_PER_DOCUMENT * $k
            || ($this->parent !== null && !$this->parent->charge($src, $subjectLen))
        ) {
            // Poison the budget so a later, cheaper pattern cannot sneak in after an over-budget one.
            $this->evaluations = SafeRegex::MAX_REGEX_EVALUATIONS_PER_DOCUMENT * $k + 1;
            $this->refusals++;
            return false;
        }
        $this->evaluations = $ev;
        $this->chars = $chars;
        $this->steps = $steps;
        return true;
    }

    /**
     * Make this the open scope for the synchronous `fn` (the previous scope is restored in `finally`).
     *
     * @template T
     * @param callable():T $fn
     * @return T
     */
    public function run(callable $fn): mixed
    {
        $prev = SafeRegex::swapBudget($this);
        try {
            return $fn();
        } finally {
            SafeRegex::swapBudget($prev);
        }
    }
}

/** @internal a pattern outside the supported subset. */
final class SafeRegexRefuse extends \RuntimeException
{
}

/**
 * @internal The safe-regex parser over UTF-16 code units. AST nodes: ['set', ranges, negated] | ['bol'] | ['eol'] |
 * ['cat', items] | ['alt', items] | ['rep', node, min, max|null (unbounded)].
 */
final class SafeRegexParser
{
    private int $i = 0;
    private int $n;

    /** @param list<int> $s */
    public function __construct(private readonly array $s)
    {
        $this->n = count($s);
    }

    private function at(int $k): ?int
    {
        return $this->s[$k] ?? null;
    }

    private static function refuse(string $m): never
    {
        throw new SafeRegexRefuse($m);
    }

    public function parse(): array
    {
        $node = $this->alt();
        if ($this->i < $this->n) {
            self::refuse('unbalanced )');
        }
        return $node;
    }

    private function alt(): array
    {
        $items = [$this->cat()];
        while ($this->at($this->i) === 0x7C) {
            $this->i++;
            $items[] = $this->cat();
        }
        return count($items) === 1 ? $items[0] : ['alt', $items];
    }

    private function cat(): array
    {
        $items = [];
        while ($this->i < $this->n && $this->s[$this->i] !== 0x7C && $this->s[$this->i] !== 0x29) {
            $items[] = $this->quantified();
        }
        return ['cat', $items];
    }

    /** `^\{(\d{1,4})(?:(,)(\d{0,4}))?\}` at the cursor. */
    private function brace(): ?array
    {
        $j = $this->i + 1;
        $lo = '';
        while ($j < $this->n && $this->s[$j] >= 0x30 && $this->s[$j] <= 0x39) {
            $lo .= chr($this->s[$j]);
            $j++;
        }
        if ($lo === '' || strlen($lo) > 4) {
            return null;
        }
        $c = $this->at($j);
        if ($c === 0x7D) {
            return [$lo, false, '', $j + 1 - $this->i];
        }
        if ($c !== 0x2C) {
            return null;
        }
        $k = $j + 1;
        $hi = '';
        while ($k < $this->n && $this->s[$k] >= 0x30 && $this->s[$k] <= 0x39) {
            $hi .= chr($this->s[$k]);
            $k++;
        }
        if (strlen($hi) > 4 || $this->at($k) !== 0x7D) {
            return null;
        }
        return [$lo, true, $hi, $k + 1 - $this->i];
    }

    private function quantified(): array
    {
        $atom = $this->atom();
        $c = $this->at($this->i);
        if ($c === 0x2A) { // *
            $min = 0;
            $max = null;
            $this->i++;
        } elseif ($c === 0x2B) { // +
            $min = 1;
            $max = null;
            $this->i++;
        } elseif ($c === 0x3F) { // ?
            $min = 0;
            $max = 1;
            $this->i++;
        } elseif ($c === 0x7B) { // {
            $m = $this->brace();
            if ($m === null) {
                self::refuse('{ is not a well-formed quantifier');
            }
            $min = (int)$m[0];
            $max = !$m[1] ? $min : ($m[2] === '' ? null : (int)$m[2]);
            if ($max !== null && $max < $min) {
                self::refuse('quantifier range out of order');
            }
            $this->i += $m[3];
        } else {
            return $atom;
        }
        if ($atom[0] === 'bol' || $atom[0] === 'eol') {
            self::refuse('nothing to repeat (assertion)');
        }
        if (($max !== null && $max > SafeRegex::MAX_REPEAT) || $min > SafeRegex::MAX_REPEAT) {
            self::refuse('repeat bound too large');
        }
        if ($this->at($this->i) === 0x3F) {
            $this->i++; // lazy: no effect on a full-match boolean
        }
        return ['rep', $atom, $min, $max];
    }

    private function atom(): array
    {
        $c = $this->s[$this->i];
        switch ($c) {
            case 0x28: // (
                $this->i++;
                if ($this->at($this->i) === 0x3F) {
                    if ($this->at($this->i + 1) !== 0x3A) {
                        self::refuse('lookaround / named groups are not supported');
                    }
                    $this->i += 2;
                }
                $node = $this->alt();
                if ($this->at($this->i) !== 0x29) {
                    self::refuse('unterminated group');
                }
                $this->i++;
                return $node;
            case 0x5B: // [
                return $this->cls();
            case 0x2E: // .
                $this->i++;
                return ['set', SafeRegex::LINE_TERMINATORS, true];
            case 0x5E: // ^
                $this->i++;
                return ['bol'];
            case 0x24: // $
                $this->i++;
                return ['eol'];
            case 0x5C: // backslash
                $e = $this->escapeInner(false);
                return ['set', $e[0], $e[1]];
            case 0x2A:
            case 0x2B:
            case 0x3F:
                self::refuse('nothing to repeat');
            case 0x7B:
                self::refuse('{ is not a well-formed quantifier');
            default:
                $this->i++;
                return ['set', [[$c, $c]], false];
        }
    }

    private static function isHex(?int $c): bool
    {
        return $c !== null && (($c >= 0x30 && $c <= 0x39) || ($c >= 0x41 && $c <= 0x46) || ($c >= 0x61 && $c <= 0x66));
    }

    private static function isAlnum(int $c): bool
    {
        return ($c >= 0x30 && $c <= 0x39) || ($c >= 0x41 && $c <= 0x5A) || ($c >= 0x61 && $c <= 0x7A);
    }

    /** @return array{0:list<array{0:int,1:int}>,1:bool,2:bool,3:?int} [ranges, negated, isClassEscape, single code] */
    private function escapeInner(bool $inClass): array
    {
        $this->i++; // backslash
        $c = $this->at($this->i);
        if ($c === null) {
            self::refuse('trailing backslash');
        }
        $this->i++;
        $single = static fn(int $code): array => [[[$code, $code]], false, false, $code];
        switch ($c) {
            case 0x64: // d
                return [SafeRegex::DIGIT, false, true, null];
            case 0x44: // D
                return [SafeRegex::DIGIT, true, true, null];
            case 0x77: // w
                return [SafeRegex::WORD, false, true, null];
            case 0x57: // W
                return [SafeRegex::WORD, true, true, null];
            case 0x73: // s
                return [SafeRegex::SPACE, false, true, null];
            case 0x53: // S
                return [SafeRegex::SPACE, true, true, null];
            case 0x74: // t
                return $single(9);
            case 0x6E: // n
                return $single(10);
            case 0x76: // v
                return $single(11);
            case 0x66: // f
                return $single(12);
            case 0x72: // r
                return $single(13);
            case 0x30: // 0
                $nx = $this->at($this->i);
                if ($nx !== null && $nx >= 0x30 && $nx <= 0x39) {
                    self::refuse('octal escape');
                }
                return $single(0);
            case 0x78: { // x
                $a = $this->at($this->i);
                $b = $this->at($this->i + 1);
                if (!self::isHex($a) || !self::isHex($b)) {
                    self::refuse('bad \\x escape');
                }
                $this->i += 2;
                return $single(intval(chr($a) . chr($b), 16));
            }
            case 0x75: { // u
                $h = '';
                for ($k = 0; $k < 4; $k++) {
                    $d = $this->at($this->i + $k);
                    if (!self::isHex($d)) {
                        self::refuse('bad \\u escape');
                    }
                    $h .= chr($d);
                }
                $this->i += 4;
                return $single(intval($h, 16));
            }
            case 0x63: { // c
                $l = $this->at($this->i);
                if ($l === null || !(($l >= 0x41 && $l <= 0x5A) || ($l >= 0x61 && $l <= 0x7A))) {
                    self::refuse('bad \\c escape');
                }
                $this->i++;
                return $single($l % 32);
            }
            case 0x62: // b
                if ($inClass) {
                    return $single(8); // [\b] is backspace
                }
                self::refuse('word-boundary assertions are not supported');
            default:
                if (self::isAlnum($c) || $c === 0x5F) {
                    self::refuse('escape is not supported');
                }
                return $single($c);
        }
    }

    /** @param list<array{0:int,1:int}> $ranges */
    public static function normalize(array $ranges): array
    {
        usort($ranges, static fn(array $a, array $b): int => $a[0] <=> $b[0]);
        $out = [];
        foreach ($ranges as $r) {
            $last = count($out) - 1;
            if ($last >= 0 && $r[0] <= $out[$last][1] + 1) {
                $out[$last][1] = max($out[$last][1], $r[1]);
            } else {
                $out[] = [$r[0], $r[1]];
            }
        }
        return $out;
    }

    /** @param list<array{0:int,1:int}> $r */
    public static function complement(array $r): array
    {
        $out = [];
        $next = 0;
        foreach (self::normalize($r) as [$a, $b]) {
            if ($a > $next) {
                $out[] = [$next, $a - 1];
            }
            $next = $b + 1;
        }
        if ($next <= 0xFFFF) {
            $out[] = [$next, 0xFFFF];
        }
        return $out;
    }

    /** @return array{ranges: list<array{0:int,1:int}>, ch: ?int, cls: bool} */
    private function readAtom(): array
    {
        $c = $this->s[$this->i];
        if ($c === 0x5C) {
            $e = $this->escapeInner(true);
            // a negated class escape (\D \W \S) contributes the complement as ranges
            $rs = $e[1] ? self::complement($e[0]) : $e[0];
            return ['ranges' => $rs, 'ch' => $e[3], 'cls' => $e[2]];
        }
        $this->i++;
        return ['ranges' => [[$c, $c]], 'ch' => $c, 'cls' => false];
    }

    private function cls(): array
    {
        $this->i++; // [
        $negated = false;
        if ($this->at($this->i) === 0x5E) {
            $negated = true;
            $this->i++;
        }
        $ranges = [];
        for (;;) {
            $c = $this->at($this->i);
            if ($c === null) {
                self::refuse('unterminated class');
            }
            if ($c === 0x5D) {
                $this->i++;
                break;
            }
            $a = $this->readAtom();
            $nx = $this->at($this->i + 1);
            if ($this->at($this->i) === 0x2D && $nx !== null && $nx !== 0x5D) {
                $this->i++;
                $b = $this->readAtom();
                if ($a['cls'] || $b['cls']) {
                    // Annex B: a class escape as a range endpoint makes the '-' a literal
                    foreach ($a['ranges'] as $r) {
                        $ranges[] = [$r[0], $r[1]];
                    }
                    $ranges[] = [0x2D, 0x2D];
                    foreach ($b['ranges'] as $r) {
                        $ranges[] = [$r[0], $r[1]];
                    }
                } else {
                    if ($a['ch'] > $b['ch']) {
                        self::refuse('class range out of order');
                    }
                    $ranges[] = [$a['ch'], $b['ch']];
                }
            } else {
                foreach ($a['ranges'] as $r) {
                    $ranges[] = [$r[0], $r[1]];
                }
            }
        }
        return ['set', self::normalize($ranges), $negated];
    }
}
