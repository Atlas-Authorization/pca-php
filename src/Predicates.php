<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/SafeRegex.php';

/**
 * Deterministic, non-code predicate DSL evaluator (spec §5.1 "semantic action-predicates") and the Intent Layer v2 `layers`
 * check (V5). Port of the evaluator part of packages/pca/src/predicates.ts and of intent-layers.ts (the TypeScript is
 * authoritative; the DEFAULT code path, not the PCA_VERIFIED_CORE opt-in).
 *
 * Predicates are PURE DATA. Every public function is total and never throws; anything malformed, unknown or missing
 * FAILS CLOSED (condition false, predicate not matched, ceiling denies).
 *
 * VALUES are in the Json representation (Obj, list arrays, Num, string, bool, null) as from Json::parseLax. JS semantics
 * reproduced:
 *   - member reads are OWN members of an Obj only (arrays and scalars have no named members);
 *   - a number is a Num, judged by the binary64 VALUE of its lexeme (large integers round like JSON.parse; a lexeme
 *     beyond the binary64 range is +/-Infinity); a bool is never a number;
 *   - string `.length`, prefix tests, globs and regexes work over UTF-16 code units;
 *   - lt/lte/gt/gte order strings by their UTF-8 bytes (Unicode code point order); a lone surrogate has no order;
 *   - `eq` / `in` is the equality of the TS lenient canonical JSON: same JSON type and value (2 == 2.0, 0 == -0,
 *     2 != "2", true != 1), objects by key set and member values; any non-finite number ANYWHERE in either operand makes
 *     the comparison false (the canonicalizer throws, deepEq catches).
 */
final class Predicates
{
    /** Longest field value a `like`/`matches` leaf is tested against (UTF-16 units). */
    public const MAX_PATTERN_SUBJECT_LEN = 512;
    /** Longest `like` glob / `matches` regex source accepted (UTF-16 units). */
    public const MAX_LIKE_PATTERN_LEN = 512;
    public const MAX_MATCHES_PATTERN_LEN = 200;
    /** Upper bound on nodes visited while resolving a `member_of` transitive closure. */
    public const MAX_MEMBER_CLOSURE_NODES = 10000;
    /** Longest resource string a `re:` pattern is evaluated against (UTF-16 units). */
    public const MAX_RE_RESOURCE_LEN = 512;
    /** Longest `re:` pattern source (UTF-16 units). */
    public const MAX_RE_PATTERN_LEN = 200;

    /** The Intent Layer v2 ceilings, in evaluation order. */
    public const LAYER_CEILINGS = ['org', 'site', 'std'];

    private const ROOTS = ['action', 'subject', 'env'];
    private const FORBIDDEN = ['__proto__', 'constructor', 'prototype'];

    // ---- JS value helpers -------------------------------------------------------------------------------------------

    /** `o[k]` as an own member: [true, value] or [false, null] (absent member, or `o` not an object). */
    private static function own(mixed $o, string $k): array
    {
        return $o instanceof Obj && $o->has($k) ? [true, $o->get($k)] : [false, null];
    }

    private static function isObj(mixed $x): bool
    {
        return $x instanceof Obj;
    }

    /** `x !== null && typeof x === 'object'` (arrays included). */
    private static function isObject(mixed $x): bool
    {
        return $x instanceof Obj || is_array($x);
    }

    /** `ctx?.action?.params` is undefined, null or not an object. */
    private static function paramsUnavailable(Obj $ctx): bool
    {
        [$ha, $a] = self::own($ctx, 'action');
        if (!$ha) {
            return true;
        }
        [$hp, $p] = self::own($a, 'params');
        return !$hp || !self::isObject($p);
    }

    private static function isParamsPath(string $s): bool
    {
        return $s === 'action.params' || str_starts_with($s, 'action.params.');
    }

    // ---- resolvePath ------------------------------------------------------------------------------------------------

    /**
     * Resolve a dotted path into the context. Own members only; unknown root => not found.
     *
     * @return array{found: bool, value?: mixed}
     */
    public static function resolvePath(Obj $ctx, mixed $path): array
    {
        [$found, $v] = self::resolve($ctx, $path);
        return $found ? ['found' => true, 'value' => $v] : ['found' => false];
    }

    /** @return array{0: bool, 1: mixed} */
    private static function resolve(Obj $ctx, mixed $path): array
    {
        if (!is_string($path) || $path === '') {
            return [false, null];
        }
        $segs = explode('.', $path);
        if (!in_array($segs[0], self::ROOTS, true)) {
            return [false, null];
        }
        [$has, $cur] = self::own($ctx, $segs[0]);
        if (!$has) {
            return [false, null];
        }
        $n = count($segs);
        for ($i = 1; $i < $n; $i++) {
            $s = $segs[$i];
            if (in_array($s, self::FORBIDDEN, true) || !self::isObject($cur)) {
                return [false, null];
            }
            if (is_array($cur)) {
                if (preg_match('/\A(?:0|[1-9][0-9]*)\z/', $s) !== 1) {
                    return [false, null];
                }
                // Number(s) >= length: a digit run too long for an int is beyond any array length
                if (strlen($s) > 18 || (int)$s >= count($cur)) {
                    return [false, null];
                }
                $cur = $cur[(int)$s];
            } else {
                if (!$cur->has($s)) {
                    return [false, null];
                }
                $cur = $cur->get($s);
            }
        }
        return [true, $cur];
    }

    // ---- equality and order -----------------------------------------------------------------------------------------

    /** The binary64 value of a JSON number (a Num, or a PHP int / float built by a host), else null. Never a bool. */
    private static function numVal(mixed $v): ?float
    {
        if ($v instanceof Num) {
            return $v->float();
        }
        if (is_int($v) || is_float($v)) {
            return (float)$v;
        }
        return null;
    }

    /** Does a Json value contain a number whose binary64 value is not finite (the canonicalizer would throw)? */
    private static function hasNonFinite(mixed $v): bool
    {
        $f = self::numVal($v);
        if ($f !== null) {
            return !is_finite($f);
        }
        if (is_array($v)) {
            foreach ($v as $x) {
                if (self::hasNonFinite($x)) {
                    return true;
                }
            }
            return false;
        }
        if ($v instanceof Obj) {
            foreach ($v->keys() as $k) {
                if (self::hasNonFinite($v->get($k))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** Structural equality of two finite Json values (what equal lenient canonical texts mean). */
    private static function jeq(mixed $a, mixed $b): bool
    {
        if ($a === null || $b === null) {
            return $a === null && $b === null;
        }
        if (is_bool($a) || is_bool($b)) {
            return $a === $b;
        }
        $fa = self::numVal($a);
        $fb = self::numVal($b);
        if ($fa !== null || $fb !== null) {
            return $fa !== null && $fb !== null && $fa == $fb; // 0 == -0 (both serialize as '0')
        }
        if (is_string($a) || is_string($b)) {
            return is_string($a) && is_string($b) && $a === $b;
        }
        if (is_array($a) && is_array($b)) {
            if (count($a) !== count($b)) {
                return false;
            }
            foreach ($a as $i => $x) {
                if (!self::jeq($x, $b[$i])) {
                    return false;
                }
            }
            return true;
        }
        if ($a instanceof Obj && $b instanceof Obj) {
            $ka = $a->keys();
            if (count($ka) !== count($b->keys())) {
                return false;
            }
            foreach ($ka as $k) {
                if (!$b->has($k) || !self::jeq($a->get($k), $b->get($k))) {
                    return false;
                }
            }
            return true;
        }
        return false; // array vs object, or a non-Json value
    }

    /** canonicalize(a) === canonicalize(b); false where either cannot be canonicalized. */
    private static function deepEq(mixed $a, mixed $b): bool
    {
        try {
            if (self::hasNonFinite($a) || self::hasNonFinite($b)) {
                return false;
            }
            return self::jeq($a, $b);
        } catch (\Throwable) {
            return false;
        }
    }

    /** NORMATIVE string order: UTF-8 byte order; a string with a lone surrogate has no order (null). */
    private static function orderUtf8(string $a, string $b): ?int
    {
        if (Json::hasLoneSurrogate($a) || Json::hasLoneSurrogate($b)) {
            return null;
        }
        return strcmp($a, $b) <=> 0;
    }

    private static function ordered(mixed $a, mixed $b): ?int
    {
        $x = self::numVal($a);
        $y = self::numVal($b);
        if ($x !== null && $y !== null) {
            if (is_finite($x) && is_finite($y)) {
                return $x < $y ? -1 : ($x > $y ? 1 : 0);
            }
        }
        if (is_string($a) && is_string($b)) {
            return self::orderUtf8($a, $b);
        }
        return null;
    }

    // ---- glob / type tags / member closure --------------------------------------------------------------------------

    /**
     * Anchored glob tokens over UTF-16 units: [0, unit] literal | [1] one unit | [2] star. Null on a dangling trailing
     * backslash. Consecutive `*` collapse to one.
     */
    private static function parseGlob(array $g): ?array
    {
        $out = [];
        $n = count($g);
        for ($i = 0; $i < $n; $i++) {
            $ch = $g[$i];
            if ($ch === 0x5C) {
                if ($i + 1 >= $n) {
                    return null;
                }
                $out[] = [0, $g[$i + 1]];
                $i++;
            } elseif ($ch === 0x2A) {
                if ($out === [] || $out[count($out) - 1][0] !== 2) {
                    $out[] = [2];
                }
            } elseif ($ch === 0x3F) {
                $out[] = [1];
            } else {
                $out[] = [0, $ch];
            }
        }
        return $out;
    }

    /** Anchored glob match in O(|glob| x |s|), no regex engine; null on a malformed glob. */
    private static function globMatch(string $glob, string $subject): ?bool
    {
        $toks = self::parseGlob(SafeRegex::units($glob));
        if ($toks === null) {
            return null;
        }
        $s = SafeRegex::units($subject);
        $ns = count($s);
        $nt = count($toks);
        $ti = 0;
        $si = 0;
        $starTi = -1;
        $starSi = 0;
        while ($si < $ns) {
            $t = $toks[$ti] ?? null;
            if ($t !== null && $t[0] === 2) {
                $starTi = ++$ti;
                $starSi = $si;
            } elseif ($t !== null && ($t[0] === 1 || $s[$si] === $t[1])) {
                $ti++;
                $si++;
            } elseif ($starTi >= 0) {
                $ti = $starTi;
                $si = ++$starSi;
            } else {
                return false;
            }
        }
        while ($ti < $nt && $toks[$ti][0] === 2) {
            $ti++;
        }
        return $ti === $nt;
    }

    /** `is_a` type/tag test; null when the value carries no decidable type/tag. */
    private static function typeTagMatch(mixed $v, string $t): ?bool
    {
        if (is_string($v)) {
            return $v === $t || SafeRegex::startsWithUnits($v, $t . '::');
        }
        if ($v instanceof Obj) {
            $decidable = false;
            $matched = false;
            if ($v->has('type')) {
                $ty = $v->get('type');
                if (is_string($ty)) {
                    $decidable = true;
                    if ($ty === $t || SafeRegex::startsWithUnits($ty, $t . '::')) {
                        $matched = true;
                    }
                }
            }
            if ($v->has('tags')) {
                $tags = $v->get('tags');
                if (is_array($tags)) {
                    $decidable = true;
                    foreach ($tags as $x) {
                        if ($x === $t) {
                            $matched = true;
                            break;
                        }
                    }
                }
            }
            return $decidable ? $matched : null;
        }
        return null;
    }

    /** Direct neighbours of `node` in an adjacency map (own string | string[] values only). */
    private static function neighboursOf(Obj $adj, string $node): array
    {
        if (in_array($node, self::FORBIDDEN, true) || !$adj->has($node)) {
            return [];
        }
        $raw = $adj->get($node);
        if (is_string($raw)) {
            return [$raw];
        }
        if (is_array($raw)) {
            return array_values(array_filter($raw, 'is_string'));
        }
        return [];
    }

    /** Reflexive, bounded, cycle-guarded transitive closure of `start` (a set keyed 'k'.id). */
    private static function memberClosure(string $start, Obj $adj): array
    {
        $seen = ['k' . $start => true];
        $queue = [$start];
        $head = 0;
        $visited = 0;
        while ($head < count($queue) && $visited < self::MAX_MEMBER_CLOSURE_NODES) {
            $visited++;
            $node = $queue[$head++];
            foreach (self::neighboursOf($adj, $node) as $nb) {
                if (!isset($seen['k' . $nb])) {
                    $seen['k' . $nb] = true;
                    $queue[] = $nb;
                }
            }
        }
        return $seen;
    }

    // ---- conditions -------------------------------------------------------------------------------------------------

    /** Tri-valued evaluation of one LEAF condition: 'true' | 'false' | 'unknown'. */
    private static function triLeaf(Obj $c, Obj $ctx): string
    {
        [, $field] = self::own($c, 'field');
        if (!is_string($field) || $field === '') {
            return 'unknown';
        }
        [, $op] = self::own($c, 'op');
        if (!is_string($op)) {
            return 'unknown';
        }
        // "params unavailable" is NOT "field absent": a params-rooted condition fails closed.
        if (self::isParamsPath($field) && self::paramsUnavailable($ctx)) {
            return 'unknown';
        }
        [$hasRef, $ref] = self::own($c, 'ref');
        if (is_string($ref) && self::isParamsPath($ref) && self::paramsUnavailable($ctx)) {
            return 'unknown';
        }
        [$found, $v] = self::resolve($ctx, $field);
        [$hasValue, $value] = self::own($c, 'value');
        if ($op === 'exists') {
            $wantAbsent = $hasValue && $value === false;
            return ($wantAbsent ? !$found : $found) ? 'true' : 'false';
        }
        if (!$found) {
            return 'unknown';
        }

        if ($op === 'member_of') {
            if (!is_string($v)) {
                return 'unknown';
            }
            [, $collPath] = self::own($c, 'collection');
            if (!is_string($collPath) || $collPath === '') {
                return 'unknown';
            }
            [$cf, $coll] = self::resolve($ctx, $collPath);
            if (!$cf || !self::isObj($coll)) {
                return 'unknown';
            }
            if ($hasRef) {
                [$rf, $target] = self::resolve($ctx, $ref);
                if (!$rf) {
                    return 'unknown';
                }
            } else {
                if (!$hasValue) {
                    return 'unknown';
                }
                $target = $value;
            }
            $targets = is_array($target) ? array_values(array_filter($target, 'is_string'))
                : (is_string($target) ? [$target] : []);
            if ($targets === []) {
                return 'unknown';
            }
            $reach = self::memberClosure($v, $coll);
            foreach ($targets as $t) {
                if (isset($reach['k' . $t])) {
                    return 'true';
                }
            }
            return 'false';
        }

        if ($hasRef) {
            [$rf, $operand] = self::resolve($ctx, $ref);
            if (!$rf) {
                return 'unknown';
            }
        } else {
            if (!$hasValue) {
                return 'unknown';
            }
            $operand = $value;
        }

        switch ($op) {
            case 'eq':
                return self::deepEq($v, $operand) ? 'true' : 'false';
            case 'ne':
                return self::deepEq($v, $operand) ? 'false' : 'true';
            case 'in':
            case 'nin':
                if (!is_array($operand)) {
                    return 'unknown';
                }
                $any = false;
                foreach ($operand as $x) {
                    if (self::deepEq($v, $x)) {
                        $any = true;
                        break;
                    }
                }
                return ($op === 'in' ? $any : !$any) ? 'true' : 'false';
            case 'lt':
            case 'lte':
            case 'gt':
            case 'gte':
                $o = self::ordered($v, $operand);
                if ($o === null) {
                    return 'unknown';
                }
                $ok = $op === 'lt' ? $o < 0 : ($op === 'lte' ? $o <= 0 : ($op === 'gt' ? $o > 0 : $o >= 0));
                return $ok ? 'true' : 'false';
            case 'prefix':
                if (!is_string($v) || !is_string($operand)) {
                    return 'unknown';
                }
                return SafeRegex::startsWithUnits($v, $operand) ? 'true' : 'false';
            case 'like':
                if (!is_string($v) || !is_string($operand)) {
                    return 'unknown';
                }
                if (SafeRegex::utf16Len($operand) > self::MAX_LIKE_PATTERN_LEN
                    || SafeRegex::utf16Len($v) > self::MAX_PATTERN_SUBJECT_LEN) {
                    return 'unknown';
                }
                $m = self::globMatch($operand, $v);
                if ($m === null) {
                    return 'unknown';
                }
                return $m ? 'true' : 'false';
            case 'matches':
                if (!is_string($v) || !is_string($operand)) {
                    return 'unknown';
                }
                $vlen = SafeRegex::utf16Len($v);
                if (SafeRegex::utf16Len($operand) > self::MAX_MATCHES_PATTERN_LEN || $vlen > self::MAX_PATTERN_SUBJECT_LEN) {
                    return 'unknown';
                }
                if (!SafeRegex::isSafeRegexSource($operand)) {
                    return 'unknown';
                }
                if (!SafeRegex::charge($operand, $vlen)) {
                    return 'unknown'; // per-document regex work budget (fail closed)
                }
                $r = SafeRegex::fullMatch($operand, $v);
                return $r === null ? 'unknown' : ($r ? 'true' : 'false');
            case 'is_a':
                if (!is_string($operand) || $operand === '') {
                    return 'unknown';
                }
                $t = self::typeTagMatch($v, $operand);
                return $t === null ? 'unknown' : ($t ? 'true' : 'false');
            default:
                return 'unknown';
        }
    }

    /** Is this condition a boolean grouping (`all_of` / `any_of` / `not`)? */
    public static function isGroupCondition(mixed $c): bool
    {
        return $c instanceof Obj && ($c->has('all_of') || $c->has('any_of') || $c->has('not'));
    }

    /** Is this condition a leaf comparison (has a string `field`)? */
    public static function isLeafCondition(mixed $c): bool
    {
        return $c instanceof Obj && !self::isGroupCondition($c) && is_string($c->get('field'));
    }

    /** Tri-valued evaluation of any condition (leaf or grouping): 'true' | 'false' | 'unknown'. Never throws. */
    public static function evaluateConditionTri(mixed $c, Obj $ctx): string
    {
        try {
            return SafeRegex::withBudget(static fn(): string => self::triInner($c, $ctx));
        } catch (\Throwable) {
            return 'unknown';
        }
    }

    private static function triInner(mixed $c, Obj $ctx): string
    {
        try {
            if (!self::isObject($c)) {
                return 'unknown';
            }
            if (self::isGroupCondition($c)) {
                if ($c->has('all_of')) {
                    $xs = $c->get('all_of');
                    if (!is_array($xs) || $xs === []) {
                        return 'unknown';
                    }
                    $sawUnknown = false;
                    foreach ($xs as $x) {
                        $t = self::evaluateConditionTri($x, $ctx);
                        if ($t === 'false') {
                            return 'false';
                        }
                        if ($t === 'unknown') {
                            $sawUnknown = true;
                        }
                    }
                    return $sawUnknown ? 'unknown' : 'true';
                }
                if ($c->has('any_of')) {
                    $xs = $c->get('any_of');
                    if (!is_array($xs) || $xs === []) {
                        return 'unknown';
                    }
                    $sawUnknown = false;
                    foreach ($xs as $x) {
                        $t = self::evaluateConditionTri($x, $ctx);
                        if ($t === 'true') {
                            return 'true';
                        }
                        if ($t === 'unknown') {
                            $sawUnknown = true;
                        }
                    }
                    return $sawUnknown ? 'unknown' : 'false';
                }
                $inner = self::evaluateConditionTri($c->get('not'), $ctx);
                return $inner === 'true' ? 'false' : ($inner === 'false' ? 'true' : 'unknown');
            }
            if (!($c instanceof Obj)) {
                return 'unknown'; // an array has no `field`
            }
            return self::triLeaf($c, $ctx);
        } catch (\Throwable) {
            return 'unknown';
        }
    }

    /** Evaluate one condition: true iff it is CLEANLY decided true (fail closed otherwise). Never throws. */
    public static function evaluateCondition(mixed $c, Obj $ctx): bool
    {
        return self::evaluateConditionTri($c, $ctx) === 'true';
    }

    // ---- predicates -------------------------------------------------------------------------------------------------

    private static function verbMatches(mixed $p, string $verb): bool
    {
        if (is_string($p)) {
            return $p === '*' || $p === $verb;
        }
        if (is_array($p)) {
            foreach ($p as $x) {
                if (is_string($x) && ($x === '*' || $x === $verb)) {
                    return true;
                }
            }
        }
        return false;
    }

    /** `pattern` is the predicate's `resource` member ([present, value]). */
    private static function resourceMatches(bool $present, mixed $pattern, string $resource): bool
    {
        if (!$present) {
            return true;
        }
        if (!is_string($pattern)) {
            return false;
        }
        if ($pattern === '*') {
            return true;
        }
        if (str_starts_with($pattern, 're:')) {
            $src = substr($pattern, 3);
            if (SafeRegex::utf16Len($src) > self::MAX_RE_PATTERN_LEN) {
                return false;
            }
            $rlen = SafeRegex::utf16Len($resource);
            if ($rlen > self::MAX_RE_RESOURCE_LEN) {
                return false;
            }
            if (!SafeRegex::isSafeRegexSource($src)) {
                return false;
            }
            if (!SafeRegex::charge($src, $rlen)) {
                return false; // per-document regex work budget (fail closed)
            }
            return SafeRegex::fullMatch($src, $resource) === true;
        }
        if (str_ends_with($pattern, '*')) {
            return SafeRegex::startsWithUnits($resource, substr($pattern, 0, -1));
        }
        return $pattern === $resource;
    }

    /** Does a single predicate permit the action? Never throws. */
    public static function predicateMatches(mixed $p, Obj $ctx): bool
    {
        try {
            return SafeRegex::withBudget(static fn(): bool => self::predicateMatchesInner($p, $ctx));
        } catch (\Throwable) {
            return false;
        }
    }

    private static function predicateMatchesInner(mixed $p, Obj $ctx): bool
    {
        try {
            if (!($p instanceof Obj)) {
                return false; // a non-object, or an array (no `verb` member)
            }
            [, $a] = self::own($ctx, 'action');
            if (!($a instanceof Obj)) {
                return false;
            }
            $verb = $a->get('verb');
            $resource = $a->get('resource');
            if (!$a->has('verb') || !is_string($verb) || !$a->has('resource') || !is_string($resource)) {
                return false;
            }
            if (!self::verbMatches($p->get('verb'), $verb)) {
                return false;
            }
            if (!self::resourceMatches($p->has('resource'), $p->get('resource'), $resource)) {
                return false;
            }
            if ($p->has('where')) {
                $where = $p->get('where');
                if (!is_array($where)) {
                    return false;
                }
                foreach ($where as $c) {
                    if (!self::evaluateCondition($c, $ctx)) {
                        return false;
                    }
                }
            }
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * An action is allowed iff it matches AT LEAST ONE predicate. Default-deny: an empty list allows nothing.
     *
     * @return array{allowed: bool, matched?: mixed, reason?: string}
     */
    public static function evaluatePredicates(mixed $predicates, Obj $ctx): array
    {
        try {
            return SafeRegex::withBudget(static fn(): array => self::evaluatePredicatesInner($predicates, $ctx));
        } catch (\Throwable) {
            return ['allowed' => false, 'reason' => 'predicate evaluation error (fail closed)'];
        }
    }

    private static function evaluatePredicatesInner(mixed $predicates, Obj $ctx): array
    {
        try {
            if (!is_array($predicates) || $predicates === []) {
                return ['allowed' => false, 'reason' => 'envelope grants no predicates'];
            }
            foreach ($predicates as $p) {
                if (self::predicateMatches($p, $ctx)) {
                    return ['allowed' => true, 'matched' => $p];
                }
            }
            [, $a] = self::own($ctx, 'action');
            [$hv, $verb] = self::own($a, 'verb');
            [$hr, $res] = self::own($a, 'resource');
            return ['allowed' => false, 'reason' => 'no predicate permits ' . self::jsString($hv, $verb) . ' on '
                . self::jsString($hr, $res)];
        } catch (\Throwable) {
            return ['allowed' => false, 'reason' => 'predicate evaluation error (fail closed)'];
        }
    }

    /** ECMAScript String(v) of a member read ([present, value]; absent => "undefined"). */
    private static function jsString(bool $present, mixed $v): string
    {
        return $present ? self::jsStr($v) : 'undefined';
    }

    /** ECMAScript String(v) of a Json value (template-literal interpolation in the reason). */
    private static function jsStr(mixed $v): string
    {
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (is_string($v)) {
            return $v;
        }
        $f = self::numVal($v);
        if ($f !== null) {
            return self::jsNumStr($f);
        }
        if (is_array($v)) {
            return implode(',', array_map(static fn(mixed $x): string => $x === null ? '' : self::jsStr($x), $v));
        }
        return '[object Object]';
    }

    /** ECMAScript Number::toString of a binary64. */
    private static function jsNumStr(float $v): string
    {
        if (is_nan($v)) {
            return 'NaN';
        }
        if (is_infinite($v)) {
            return $v > 0 ? 'Infinity' : '-Infinity';
        }
        if ($v === 0.0) {
            return '0';
        }
        $sign = $v < 0 ? '-' : '';
        $a = abs($v);
        $s = '';
        for ($p = 1; $p <= 17; $p++) { // the shortest round-tripping digit string
            $s = sprintf('%.' . ($p - 1) . 'e', $a);
            if ((float)$s === $a) {
                break;
            }
        }
        [$mant, $exp] = explode('e', $s);
        $digits = rtrim(str_replace('.', '', $mant), '0');
        if ($digits === '') {
            $digits = '0';
        }
        $k = strlen($digits);
        $n = (int)$exp + 1; // value = 0.digits x 10^n
        if ($k <= $n && $n <= 21) {
            return $sign . $digits . str_repeat('0', $n - $k);
        }
        if (0 < $n && $n <= 21) {
            return $sign . substr($digits, 0, $n) . '.' . substr($digits, $n);
        }
        if (-6 < $n && $n <= 0) {
            return $sign . '0.' . str_repeat('0', -$n) . $digits;
        }
        $e = $n - 1;
        return $sign . ($k === 1 ? $digits : $digits[0] . '.' . substr($digits, 1)) . 'e' . ($e > 0 ? '+' : '-') . abs($e);
    }

    // ---- Intent Layer v2 layers (intent-layers.ts) -------------------------------------------------------------------

    /** Every own key of `o` is in `allowed` (closed member set). */
    private static function closedTo(Obj $o, array $allowed): bool
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return false;
            }
        }
        return true;
    }

    /** A well-formed layer: an object with exactly one member, `predicates`, an array (closed member set). */
    public static function isLayerPolicy(mixed $l): bool
    {
        return $l instanceof Obj && self::closedTo($l, ['predicates']) && $l->has('predicates') && is_array($l->get('predicates'));
    }

    /** A well-formed layer admits the action iff some predicate matches (an empty list admits nothing). */
    private static function layerAdmits(Obj $l, Obj $ctx): bool
    {
        return self::evaluatePredicates($l->get('predicates'), $ctx)['allowed'];
    }

    /**
     * The `layers` check of the v2 verification order: the action must be inside G^org, then G^site, then G^std (absent =
     * no constraint). The first ceiling that denies is named. `layers` must be an object with no member other than `org`,
     * `site`, `std` (an unknown member fails, reported as `org`); a layer is exactly `{predicates: [...]}`; a ceiling present with `null` or
     * any value other than `{predicates: [...]}` is malformed and fails (named), as does an empty predicate list. Never
     * throws.
     *
     * @return array{status: 'pass'}|array{status: 'fail', layer: string, reason: string}
     */
    public static function decideLayerCeilings(mixed $layers, Obj $ctx): array
    {
        if ($layers instanceof Obj && !self::closedTo($layers, self::LAYER_CEILINGS)) {
            return ['status' => 'fail', 'layer' => 'org', 'reason' => 'layers: unknown member (the layers object is {org?, site?, std?})'];
        }
        return self::ceilingsOf($layers, $ctx);
    }

    /** @return array{status: 'pass'}|array{status: 'fail', layer: string, reason: string} */
    private static function ceilingsOf(mixed $layers, Obj $ctx): array
    {
        try {
            if (!($layers instanceof Obj)) {
                return ['status' => 'fail', 'layer' => 'org', 'reason' => 'layers: the layers member is malformed (not an object)'];
            }
            foreach (self::LAYER_CEILINGS as $k) {
                if (!$layers->has($k)) {
                    continue;
                }
                $layer = $layers->get($k);
                if (!self::isLayerPolicy($layer)) {
                    return ['status' => 'fail', 'layer' => $k,
                        'reason' => "layers: the $k ceiling is malformed (null or not {predicates: [...]})"];
                }
                if (!self::layerAdmits($layer, $ctx)) {
                    return ['status' => 'fail', 'layer' => $k,
                        'reason' => "layers: the action is outside the $k ceiling (a ceiling is never a question)"];
                }
            }
            return ['status' => 'pass'];
        } catch (\Throwable $e) {
            return ['status' => 'fail', 'layer' => 'org', 'reason' => 'layers: evaluation error (fail closed): ' . $e->getMessage()];
        }
    }

    /**
     * The full layer decision for one action, in order: outside G^org / G^site / G^std (or a malformed ceiling) ->
     * ['decision' => 'ceiling', 'layer' => k]; inside a denied region -> ['decision' => 'intent_denied']; inside G^task_0
     * or some delta -> ['decision' => 'admit', 'by' => i]; otherwise ['decision' => 'intent_required']. A grant member
     * other than org / site / std / task / denied is malformed: `intent_denied` (checked first). A `denied` present
     * but not an array, a `task` that is not an array (it is required), or any entry of either that is not
     * `{predicates: [...]}`, is malformed: `intent_denied`. Absent `denied` = []. Never throws.
     *
     * @return array{decision: string, layer?: string, by?: int}
     */
    public static function decideLayers(mixed $g, Obj $ctx): array
    {
        try {
            if ($g instanceof Obj && !self::closedTo($g, [...self::LAYER_CEILINGS, 'task', 'denied'])) {
                return ['decision' => 'intent_denied'];
            }
            $c = self::ceilingsOf($g, $ctx);
            if ($c['status'] === 'fail') {
                return ['decision' => 'ceiling', 'layer' => $c['layer']];
            }
            // $g is an Obj here (a non-object fails the ceiling check as 'org')
            $denied = $g->has('denied') ? $g->get('denied') : [];
            [, $task] = self::own($g, 'task');
            if (!is_array($denied) || !is_array($task)) {
                return ['decision' => 'intent_denied'];
            }
            foreach ([$denied, $task] as $list) {
                foreach ($list as $l) {
                    if (!self::isLayerPolicy($l)) {
                        return ['decision' => 'intent_denied'];
                    }
                }
            }
            foreach ($denied as $d) {
                if (self::layerAdmits($d, $ctx)) {
                    return ['decision' => 'intent_denied'];
                }
            }
            foreach ($task as $i => $t) {
                if (self::layerAdmits($t, $ctx)) {
                    return ['decision' => 'admit', 'by' => $i];
                }
            }
            return ['decision' => 'intent_required'];
        } catch (\Throwable) {
            return ['decision' => 'intent_denied'];
        }
    }
}
