<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Explain.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/PolicyBridgeCel.php';

/** A construct outside the modeled Cedar subset; the message lands in the report. */
final class PolicyBridgeCedarError extends \RuntimeException
{
}

/**
 * Import external authorization policy into PCA predicates (the reference's pca-policy-bridge).
 *
 *   cedarToPca(text)            Cedar permit / forbid policies
 *   regoToPca(text)             OPA / Rego allow-rule subset
 *   openfgaToPca(model, tuples) OpenFGA / Zanzibar ReBAC model + relationship tuples
 *   celToCondition(...)         strict CEL expressions (see PolicyBridgeCel)
 *   decide(result, ctx)         deny-overrides-permit over a translation, on the core predicate evaluator
 *
 * Every translator returns {predicates, denies, caveats, report: {source, translated, skipped, errors}} as an Obj; whatever is
 * not modeled fails closed. Text is read the way JavaScript reads it: the regex engine runs on valid UTF-8, so a lone surrogate
 * (WTF-8) is parked on a plane-16 private-use code point while a translator runs and restored in the result; lengths and cuts
 * are counted in UTF-16 units. shortcut: input that really contains U+100000..U+1007FF would be read as a lone surrogate.
 */
final class PolicyBridge
{
    // JS \s / String.trim() whitespace, as the body of a character class
    private const WS = "\\t\\n\\x{0B}\\x{0C}\\r \\x{A0}\\x{1680}\\x{2000}-\\x{200A}\\x{2028}\\x{2029}\\x{202F}\\x{205F}\\x{3000}\\x{FEFF}";
    private const W = 'A-Za-z0-9_';
    private const S = '[' . self::WS . ']';
    private const DOT = '[^\n\r\x{2028}\x{2029}]';
    private const NB = '(?<![' . self::W . '])';   // \b before a word character
    private const NA = '(?![' . self::W . '])';    // \b after a word character
    private const ENTITY_PARENTS = 'env.entity_parents';
    private const MAX_DEPTH = 32;
    private const MAX_RECURSION = 2000;

    private static int $depth = 0;

    // ---- text semantics -----------------------------------------------------------------------------------------------------

    /** Park each lone surrogate on U+100000 + (unit - 0xD800), a valid code point the regex engine accepts. */
    private static function san(string $s): string
    {
        if (!str_contains($s, "\xED")) {
            return $s;
        }
        return preg_replace_callback('/\xED([\xA0-\xBF])([\x80-\xBF])/', static function (array $m): string {
            $u = 0xD000 + ((ord($m[1]) & 0x3F) << 6) + (ord($m[2]) & 0x3F);
            return mb_chr(0x100000 + ($u - 0xD800), 'UTF-8');
        }, $s) ?? $s;
    }

    private static function out(string $s): string
    {
        if (!str_contains($s, "\xF4\x80")) {
            return $s;
        }
        return preg_replace_callback('/\xF4\x80[\x80-\x9F][\x80-\xBF]/', static function (array $m): string {
            $u = 0xD800 + (mb_ord($m[0], 'UTF-8') - 0x100000);
            return chr(0xED) . chr(0x80 | (($u >> 6) & 0x3F)) . chr(0x80 | ($u & 0x3F));
        }, $s) ?? $s;
    }

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

    /** The result tree as the reference's JSON model: assoc arrays become Obj, strings pass through $fix. */
    private static function fin(mixed $v, \Closure $fix): mixed
    {
        if (is_string($v)) {
            return $fix($v);
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return array_map(static fn($x) => self::fin($x, $fix), $v);
            }
            $o = new Obj();
            foreach ($v as $k => $x) {
                $o->set($fix((string)$k), self::fin($x, $fix));
            }
            return $o;
        }
        return $v;
    }

    private static function finCedar(mixed $v): mixed
    {
        // a restored high half directly before a restored low half is one astral character to the reference (e.g. like "\uD83D\\\uDE00")
        return self::fin($v, static fn(string $s): string => self::pairs(self::out($s)));
    }

    private static function trim(string $s): string
    {
        return self::rx((string)preg_replace('/\A' . self::S . '+|' . self::S . '+\z/u', '', $s));
    }

    private static function rx(string|null|false $r): string
    {
        if (!is_string($r)) {
            throw new \RuntimeException('regular expression failure');
        }
        return $r;
    }

    private static function ulen(string $sanitized): int
    {
        return Js::len(self::out($sanitized));
    }

    private static function cutUnits(string $sanitized, int $n): string
    {
        return self::san(Explain::slice16(self::out($sanitized), 0, $n));
    }

    private static function truncate(string $s): string
    {
        $one = self::trim((string)preg_replace('/' . self::S . '+/u', ' ', $s));
        return self::ulen($one) > 80 ? self::cutUnits($one, 77) . '...' : $one;
    }

    /** s[:-1] by UTF-16 unit (a dropped low surrogate leaves the lone high half). */
    private static function chopLast(string $s): string
    {
        if ($s === '') {
            return '';
        }
        $last = mb_substr($s, -1, null, 'UTF-8');
        $rest = mb_substr($s, 0, mb_strlen($s, 'UTF-8') - 1, 'UTF-8');
        if (strlen($last) === 4) {
            return $rest . mb_chr(0x100000 + ((mb_ord($last, 'UTF-8') - 0x10000) >> 10), 'UTF-8');
        }
        return $rest;
    }

    /** JavaScript UTF-16 code units of a (WTF-8) string. @return list<int> */
    private static function units(string $s): array
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

    /** @param list<int> $a @param list<int> $b */
    private static function cmpUnits(array $a, array $b): int
    {
        $n = min(count($a), count($b));
        for ($i = 0; $i < $n; $i++) {
            if ($a[$i] !== $b[$i]) {
                return $a[$i] <=> $b[$i];
            }
        }
        return count($a) <=> count($b);
    }

    /** @param list<string> $xs @return list<string> sorted by UTF-16 code units (the reference's default sort) */
    private static function sortUnits(array $xs): array
    {
        $k = [];
        foreach ($xs as $x) {
            $k[] = [self::units($x), $x];
        }
        usort($k, static fn(array $a, array $b): int => self::cmpUnits($a[0], $b[0]));
        return array_map(static fn(array $p): string => $p[1], $k);
    }

    private static function jverb(mixed $v): string
    {
        return is_string($v) ? Json::lenientStr($v) : '[' . implode(',', array_map(static fn($x) => Json::lenientStr($x), $v)) . ']';
    }

    /** `Number(s)` of a decimal literal. */
    private static function number(string $s): int|float
    {
        if (str_contains($s, '.')) {
            return (float)$s;
        }
        $f = (float)$s;
        return abs($f) > 9007199254740991.0 ? $f : (int)$s;
    }

    // ---- bracket and quote aware scanning (ASCII delimiters: byte-safe on UTF-8) -------------------------------------------------

    private static function indexOfTopLevel(string $text, string $token): int
    {
        $depth = 0;
        $inStr = false;
        $n = strlen($text);
        for ($i = 0; $i < $n; $i++) {
            $ch = $text[$i];
            if ($inStr) {
                if ($ch === '"') {
                    $inStr = false;
                }
                continue;
            }
            if ($ch === '"') {
                $inStr = true;
                continue;
            }
            if ($ch === '(' || $ch === '[' || $ch === '{') {
                $depth++;
            } elseif ($ch === ')' || $ch === ']' || $ch === '}') {
                $depth--;
            } elseif ($depth === 0 && substr_compare($text, $token, $i, strlen($token)) === 0) {
                return $i;
            }
        }
        return -1;
    }

    /** @return list<string> */
    private static function splitTopLevel(string $text, string $delim): array
    {
        $out = [];
        $depth = 0;
        $inStr = false;
        $start = 0;
        $i = 0;
        $n = strlen($text);
        $dl = strlen($delim);
        while ($i < $n) {
            $ch = $text[$i];
            if ($inStr) {
                if ($ch === '"') {
                    $inStr = false;
                }
                $i++;
                continue;
            }
            if ($ch === '"') {
                $inStr = true;
                $i++;
                continue;
            }
            if ($ch === '(' || $ch === '[' || $ch === '{') {
                $depth++;
            } elseif ($ch === ')' || $ch === ']' || $ch === '}') {
                $depth--;
            }
            if ($depth === 0 && substr_compare($text, $delim, $i, $dl) === 0) {
                $out[] = substr($text, $start, $i - $start);
                $i += $dl - 1;
                $start = $i + 1;
            }
            $i++;
        }
        $out[] = substr($text, $start);
        return $out;
    }

    private static function matchDelim(string $text, int $open, string $o, string $c): int
    {
        $depth = 0;
        $inStr = false;
        $n = strlen($text);
        for ($i = $open; $i < $n; $i++) {
            $ch = $text[$i];
            if ($inStr) {
                if ($ch === '"') {
                    $inStr = false;
                }
                continue;
            }
            if ($ch === '"') {
                $inStr = true;
            } elseif ($ch === $o) {
                $depth++;
            } elseif ($ch === $c) {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            }
        }
        return -1;
    }

    /** @return array<string,mixed> */
    private static function newReport(string $source): array
    {
        return ['source' => $source, 'translated' => [], 'skipped' => [], 'errors' => []];
    }

    /** @return array<string,mixed> */
    private static function result(array $predicates, array $denies, array $report): array
    {
        return ['predicates' => $predicates, 'denies' => $denies, 'caveats' => [], 'report' => $report];
    }

    /** @param list<string> $parts @return list<string> */
    private static function trimmedNonEmpty(array $parts): array
    {
        $o = [];
        foreach ($parts as $p) {
            $t = self::trim($p);
            if ($t !== '') {
                $o[] = $t;
            }
        }
        return $o;
    }

    /** Full-match $re (an unanchored body) against $s; null or the groups (unmatched groups null). */
    private static function full(string $re, string $s): ?array
    {
        $r = preg_match('/\A(?:' . $re . ')\z/u', $s, $m, PREG_UNMATCHED_AS_NULL);
        if ($r === false) {
            throw new \RuntimeException('regular expression failure');
        }
        return $r === 1 ? $m : null;
    }

    // ---- Cedar ----------------------------------------------------------------------------------------------------------------

    /** Cedar `permit` / `forbid` policies as permit predicates and deny predicates (consume with decide). */
    public static function cedarToPca(string $policyText): Obj
    {
        return self::translateCedar($policyText, true);
    }

    /** `$errorGuards = false` omits the trailing "no attribute was missing" guard (bare structure; not exact). */
    public static function translateCedar(string $policyText, bool $errorGuards): Obj
    {
        $report = self::newReport('cedar');
        $predicates = [];
        $denies = [];
        $cleaned = self::rx(preg_replace('~//[^\n]*~u', '', self::san($policyText)));
        foreach (self::trimmedNonEmpty(self::splitTopLevel($cleaned, ';')) as $stmt) {
            try {
                self::$depth = 0;
                self::translateStatement($stmt, $predicates, $denies, $report, $errorGuards);
            } catch (PolicyBridgeCedarError $e) {
                $report['errors'][] = 'policy "' . self::truncate($stmt) . '": ' . $e->getMessage();
            }
        }
        return self::finCedar(self::result($predicates, $denies, $report));
    }

    private static function translateStatement(string $stmt, array &$permits, array &$denies, array &$report, bool $errorGuards): void
    {
        $body = $stmt;
        if (preg_match('/\A' . self::S . '*(?:@[A-Za-z_][' . self::W . ']*' . self::S . '*\([^)]*\)' . self::S . '*)+/u', $body, $am) === 1) {
            $body = substr($body, strlen($am[0]));
        }
        if (preg_match('/\A' . self::S . '*(permit|forbid)' . self::S . '*\(/iu', $body, $head) !== 1) {
            $report['skipped'][] = 'unrecognized statement: "' . self::truncate($stmt) . '"';
            return;
        }
        $effect = strtolower($head[1]) === 'forbid' ? 'forbid' : 'permit';
        $openIdx = strpos($body, '(');
        $closeIdx = self::matchDelim($body, $openIdx, '(', ')');
        if ($closeIdx < 0) {
            throw new PolicyBridgeCedarError('unterminated scope parentheses');
        }
        $scopeText = substr($body, $openIdx + 1, $closeIdx - $openIdx - 1);
        $rest = substr($body, $closeIdx + 1);
        $scope = self::parseScope($scopeText);
        $where = $scope['scopeConditions'];
        $guards = [];
        foreach (self::parseConditionBlocks($rest) as [$kind, $text]) {
            $parsed = self::parseExpr($text);
            if ($parsed === null) {
                $report['skipped'][] = 'unmodeled ' . $kind . '-condition "' . self::truncate($text) . "\" \u{2014} policy dropped (fail closed)";
                if ($effect === 'forbid') {
                    $report['errors'][] = "forbid could not be fully modeled and was dropped \u{2014} treat result as fail-closed: \"" . self::truncate($stmt) . '"';
                }
                return;
            }
            $where[] = $kind === 'when' ? $parsed : ['not' => $parsed];
            $g = self::noError($parsed);
            if ($g !== null) {
                $guards[] = $g;
            }
        }
        $conditionCount = count($where);
        if ($errorGuards && $guards !== []) {
            $where[] = count($guards) === 1 ? $guards[0] : ['all_of' => $guards];
        }
        $predicate = ['verb' => $scope['verb']];
        if (($scope['resource'] ?? null) !== null) {
            $predicate['resource'] = $scope['resource'];
        }
        if ($where !== []) {
            $predicate['where'] = $where;
        }
        $res = $scope['resource'] ?? null;
        $on = ($res !== null && $res !== '') ? ' on ' . $res : '';
        if ($effect === 'permit') {
            $permits[] = $predicate;
            $report['translated'][] = "permit \u{2192} verb " . self::jverb($scope['verb']) . $on . " ($conditionCount condition(s))";
        } else {
            $denies[] = $predicate;
            $report['translated'][] = "forbid \u{2192} deny verb " . self::jverb($scope['verb']) . $on . " ($conditionCount condition(s))";
        }
    }

    /** @return array{verb:string|list<string>,scopeConditions:list<array>,resource?:string} */
    private static function parseScope(string $scopeText): array
    {
        $clauses = self::trimmedNonEmpty(self::splitTopLevel($scopeText, ','));
        $result = ['verb' => '*', 'scopeConditions' => []];
        foreach ($clauses as $clause) {
            $m = self::full('(principal|action|resource)' . self::NA . self::S . '*(?:(==|in|is)' . self::S . '*)?((?s:.*))', $clause);
            if ($m === null) {
                throw new PolicyBridgeCedarError('unparseable scope clause "' . self::truncate($clause) . '"');
            }
            $variable = $m[1];
            $op = $m[2] ?? '';
            $operand = self::trim($m[3] ?? '');
            if ($op === '') {
                continue;
            }
            if ($variable === 'action') {
                if ($op === '==') {
                    $eid = self::entityId($operand);
                    if ($eid === null) {
                        throw new PolicyBridgeCedarError('action == expects an Action entity, got "' . self::truncate($operand) . '"');
                    }
                    $result['verb'] = $eid;
                } elseif ($op === 'in' && str_starts_with($operand, '[')) {
                    $verbs = [];
                    foreach (self::trimmedNonEmpty(self::splitTopLevel(self::chopLast(substr($operand, 1)), ',')) as $it) {
                        $eid = self::entityId($it);
                        if ($eid === null) {
                            throw new PolicyBridgeCedarError('action in [...] expects Action entities, got "' . self::truncate($it) . '"');
                        }
                        $verbs[] = $eid;
                    }
                    $result['verb'] = $verbs;
                } else {
                    throw new PolicyBridgeCedarError('unsupported action scope operator "' . $op . '"');
                }
            } else {
                $field = $variable === 'resource' ? 'action.resource' : 'subject.id';
                if ($op === '==') {
                    $uid = self::entityUid($operand);
                    if ($variable === 'resource') {
                        if ($uid === null) {
                            throw new PolicyBridgeCedarError('resource == expects an entity, got "' . self::truncate($operand) . '"');
                        }
                        $result['resource'] = $uid;
                    } else {
                        if ($uid === null) {
                            throw new PolicyBridgeCedarError('principal == expects an entity, got "' . self::truncate($operand) . '"');
                        }
                        $result['scopeConditions'][] = ['field' => $field, 'op' => 'eq', 'value' => $uid];
                    }
                } elseif ($op === 'is') {
                    $t = self::typeName($operand);
                    if ($t === null) {
                        throw new PolicyBridgeCedarError($variable . ' is expects a type, got "' . self::truncate($operand) . '"');
                    }
                    $result['scopeConditions'][] = ['field' => $field, 'op' => 'is_a', 'value' => $t];
                } else {
                    $mem = self::memberOfCondition($field, $operand);
                    if ($mem === null) {
                        throw new PolicyBridgeCedarError($variable . ' in expects an entity (hierarchy), got "' . self::truncate($operand) . '"');
                    }
                    $result['scopeConditions'][] = $mem;
                }
            }
        }
        return $result;
    }

    /** @return list<array{0:string,1:string}> */
    private static function parseConditionBlocks(string $rest): array
    {
        $blocks = [];
        $pos = 0;
        $re = '/' . self::NB . '(when|unless)' . self::NA . self::S . '*\{/u';
        while (preg_match($re, $rest, $m, PREG_OFFSET_CAPTURE, $pos) === 1) {
            $kind = $m[1][0] === 'unless' ? 'unless' : 'when';
            $open = strpos($rest, '{', $m[0][1]);
            $close = self::matchDelim($rest, $open, '{', '}');
            if ($close < 0) {
                throw new PolicyBridgeCedarError("unterminated $kind block");
            }
            $blocks[] = [$kind, substr($rest, $open + 1, $close - $open - 1)];
            $pos = $close + 1;
        }
        return $blocks;
    }

    private static function parseExpr(string $text): ?array
    {
        if (++self::$depth > self::MAX_RECURSION) {
            throw new PolicyBridgeCedarError('Maximum call stack size exceeded');
        }
        try {
            $t = self::trim($text);
            if ($t === '') {
                return null;
            }
            $ors = self::trimmedNonEmpty(self::splitTopLevel($t, '||'));
            if (count($ors) > 1) {
                $subs = [];
                foreach ($ors as $s) {
                    $p = self::parseExpr($s);
                    if ($p === null) {
                        return null;
                    }
                    $subs[] = $p;
                }
                return ['any_of' => $subs];
            }
            $ands = self::trimmedNonEmpty(self::splitTopLevel($t, '&&'));
            if (count($ands) > 1) {
                $subs = [];
                foreach ($ands as $s) {
                    $p = self::parseExpr($s);
                    if ($p === null) {
                        return null;
                    }
                    $subs[] = $p;
                }
                return ['all_of' => $subs];
            }
            if (str_starts_with($t, '(') && self::matchDelim($t, 0, '(', ')') === strlen($t) - 1) {
                return self::parseExpr(substr($t, 1, -1));
            }
            return self::parseAtom($t);
        } finally {
            self::$depth--;
        }
    }

    private const CMP_TOKENS = [['==', 'eq'], ['!=', 'ne'], ['<=', 'lte'], ['>=', 'gte'], ['<', 'lt'], ['>', 'gt']];

    private static function parseAtom(string $text): ?array
    {
        $t = self::trim($text);
        foreach (self::CMP_TOKENS as [$tok, $op]) {
            $idx = self::indexOfTopLevel($t, $tok);
            if ($idx >= 0) {
                return self::buildComparison(self::trim(substr($t, 0, $idx)), $op, self::trim(substr($t, $idx + strlen($tok))));
            }
        }
        $wm = self::full('((?s:.*?)[^' . self::WS . '])' . self::S . '+(in|is|like|has)' . self::S . '+((?s:.+))', $t);
        if ($wm !== null) {
            return self::buildWordOp(self::trim($wm[1]), $wm[2], self::trim($wm[3]));
        }
        return null;
    }

    private static function buildComparison(string $lhsRaw, string $op, string $rhsRaw): ?array
    {
        $field = self::toFieldPath($lhsRaw);
        if ($field === null) {
            return null;
        }
        if ($field === 'action.verb') {
            if ($op !== 'eq' && $op !== 'ne') {
                return null;
            }
            $eid = self::entityId($rhsRaw);
            return $eid === null ? null : ['field' => $field, 'op' => $op, 'value' => $eid];
        }
        if (self::isPathExpr($rhsRaw)) {
            $ref = self::toFieldPath($rhsRaw);
            if ($ref !== null) {
                return ['field' => $field, 'op' => $op, 'ref' => $ref];
            }
        }
        [$ok, $value] = self::toLiteral($rhsRaw);
        if (!$ok) {
            return null;
        }
        return ['field' => $field, 'op' => $op, 'value' => $value];
    }

    private static function buildWordOp(string $lhsRaw, string $kind, string $rhsRaw): ?array
    {
        if ($kind === 'has') {
            if (preg_match('/\A[A-Za-z_][' . self::W . ']*\z/', $rhsRaw) !== 1) {
                return null;
            }
            $field = self::toFieldPath($lhsRaw . '.' . $rhsRaw);
            return $field === null ? null : ['field' => $field, 'op' => 'exists'];
        }
        $field = self::toFieldPath($lhsRaw);
        if ($field === null) {
            return null;
        }
        if ($field === 'action.verb') {
            if ($kind !== 'in') {
                return null;
            }
            $inner = str_starts_with($rhsRaw, '[') && str_ends_with($rhsRaw, ']') ? substr($rhsRaw, 1, -1) : $rhsRaw;
            $ids = [];
            foreach (self::trimmedNonEmpty(self::splitTopLevel($inner, ',')) as $x) {
                $ids[] = self::entityId($x);
            }
            return ($ids !== [] && !in_array(null, $ids, true)) ? ['field' => $field, 'op' => 'in', 'value' => $ids] : null;
        }
        if ($kind === 'is') {
            $t = self::typeName($rhsRaw);
            return $t === null ? null : ['field' => $field, 'op' => 'is_a', 'value' => $t];
        }
        if ($kind === 'like') {
            $sm = self::full('"((?s:.*))"', $rhsRaw);
            if ($sm === null) {
                return null;
            }
            return ['field' => $field, 'op' => 'like', 'value' => self::cedarLikeToGlob($sm[1])];
        }
        if (str_starts_with($rhsRaw, '[')) {
            $inner = str_ends_with($rhsRaw, ']') ? substr($rhsRaw, 1, -1) : substr($rhsRaw, 1);
            $items = self::trimmedNonEmpty(self::splitTopLevel($inner, ','));
            $allUid = $items !== [];
            foreach ($items as $it) {
                if (self::entityUid($it) === null) {
                    $allUid = false;
                    break;
                }
            }
            if ($allUid) {
                return ['field' => $field, 'op' => 'member_of', 'value' => array_map(static fn($it) => self::entityUid($it), $items), 'collection' => self::ENTITY_PARENTS];
            }
            $values = [];
            foreach ($items as $it) {
                [$ok, $v] = self::toLiteral($it);
                if (!$ok) {
                    return null;
                }
                $values[] = $v;
            }
            return ['field' => $field, 'op' => 'in', 'value' => $values];
        }
        return self::memberOfCondition($field, $rhsRaw);
    }

    private static function memberOfCondition(string $field, string $operand): ?array
    {
        $uid = self::entityUid($operand);
        if ($uid !== null) {
            return ['field' => $field, 'op' => 'member_of', 'value' => $uid, 'collection' => self::ENTITY_PARENTS];
        }
        if (self::isPathExpr($operand)) {
            $ref = self::toFieldPath($operand);
            if ($ref !== null) {
                return ['field' => $field, 'op' => 'member_of', 'ref' => $ref, 'collection' => self::ENTITY_PARENTS];
            }
        }
        return null;
    }

    private static function isPathExpr(string $expr): bool
    {
        return preg_match('/\A(principal|resource|action|context)' . self::NA . '/', $expr) === 1;
    }

    private static function toFieldPath(string $expr): ?string
    {
        switch ($expr) {
            case 'principal':
                return 'subject.id';
            case 'resource':
                return 'action.resource';
            case 'action':
                return 'action.verb';
            case 'context':
                return 'env';
        }
        if (preg_match('/\Aprincipal\.([A-Za-z_][' . self::W . '.]*)\z/', $expr, $m) === 1) {
            return 'subject.' . $m[1];
        }
        if (preg_match('/\Aresource\.([A-Za-z_][' . self::W . '.]*)\z/', $expr, $m) === 1) {
            return 'env.resource.' . $m[1];
        }
        if (preg_match('/\Acontext\.([A-Za-z_][' . self::W . '.]*)\z/', $expr, $m) === 1) {
            return 'env.' . $m[1];
        }
        return null;
    }

    private static function typeName(string $expr): ?string
    {
        $s = self::trim($expr);
        return preg_match('/\A[A-Za-z_][' . self::W . ']*(?:::[A-Za-z_][' . self::W . ']*)*\z/', $s) === 1 ? $s : null;
    }

    private static function entityId(string $expr): ?string
    {
        $m = self::full(self::DOT . '+::"([^"]*)"', self::trim($expr));
        return $m === null ? null : $m[1];
    }

    private static function entityUid(string $expr): ?string
    {
        $m = self::full('(' . self::DOT . '+)::"([^"]*)"', self::trim($expr));
        return $m === null ? null : $m[1] . '::' . $m[2];
    }

    /** @return array{0:bool,1:mixed} */
    private static function toLiteral(string $expr): array
    {
        $s = self::trim($expr);
        $m = self::full('"([^"]*)"', $s);
        if ($m !== null) {
            return [true, $m[1]];
        }
        if ($s === 'true') {
            return [true, true];
        }
        if ($s === 'false') {
            return [true, false];
        }
        if (preg_match('/\A-?[0-9]+(?:\.[0-9]+)?\z/', $s) === 1) {
            return [true, self::number($s)];
        }
        $uid = self::entityUid($s);
        return $uid !== null ? [true, $uid] : [false, null];
    }

    private static function escapeGlobLiteral(string $ch): string
    {
        return ($ch === '*' || $ch === '?' || $ch === '\\') ? '\\' . $ch : $ch;
    }

    private static function cedarLikeToGlob(string $inner): string
    {
        $chars = preg_split('//u', $inner, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $out = '';
        $n = count($chars);
        for ($i = 0; $i < $n;) {
            $ch = $chars[$i];
            if ($ch === '\\') {
                $nxt = $chars[$i + 1] ?? null;
                if ($nxt === '*') {
                    $out .= '\\*';
                    $i += 2;
                    continue;
                }
                if ($nxt !== null) {
                    $out .= self::escapeGlobLiteral($nxt);
                    $i += 2;
                    continue;
                }
                $out .= '\\\\';
                $i++;
                continue;
            }
            $out .= $ch === '*' ? '*' : self::escapeGlobLiteral($ch);
            $i++;
        }
        return $out;
    }

    // --- Cedar evaluation-error semantics: the guard that makes a policy apply only when no absent attribute is read ---------------

    private const TOTAL_FIELDS = ['subject.id', 'action.verb', 'action.resource', 'env'];

    /** @return list<string> */
    private static function guardedPaths(?string $field): array
    {
        if ($field === null || in_array($field, self::TOTAL_FIELDS, true) || str_starts_with($field, 'env.entity_parents')) {
            return [];
        }
        return (str_starts_with($field, 'subject.') || str_starts_with($field, 'env.')) ? [$field] : [];
    }

    private static function allOf(array $xs): array
    {
        return count($xs) === 1 ? $xs[0] : ['all_of' => $xs];
    }

    private static function anyOf(array $xs): array
    {
        return count($xs) === 1 ? $xs[0] : ['any_of' => $xs];
    }

    /** "Evaluating this expression raises no Cedar error", as a condition (null = it cannot). */
    private static function noError(array $c): ?array
    {
        if (array_key_exists('not', $c)) {
            return self::noError($c['not']);
        }
        if (array_key_exists('all_of', $c) || array_key_exists('any_of', $c)) {
            $isAnd = array_key_exists('all_of', $c);
            $kids = $isAnd ? $c['all_of'] : $c['any_of'];
            $acc = null;
            foreach (array_reverse($kids) as $kid) {
                $n = self::noError($kid);
                $cont = $acc === null ? null : self::anyOf([$isAnd ? ['not' => $kid] : $kid, $acc]);
                $acc = $n === null ? $cont : ($cont === null ? $n : self::allOf([$n, $cont]));
            }
            return $acc;
        }
        $field = $c['field'] ?? null;
        if (($c['op'] ?? null) === 'exists' && $field !== null) {
            $base = (string)preg_replace('/\.[^.]+\z/u', '', $field);
            $deep = count(explode('.', $base)) >= (str_starts_with($base, 'env.resource') ? 3 : 2);
            $needs = $deep ? array_map(static fn($p) => ['field' => $p, 'op' => 'exists'], self::guardedPaths($base)) : [];
            return $needs === [] ? null : self::allOf($needs);
        }
        $needs = array_map(static fn($p) => ['field' => $p, 'op' => 'exists'], [...self::guardedPaths($field), ...self::guardedPaths($c['ref'] ?? null)]);
        return $needs === [] ? null : self::allOf($needs);
    }

    // ---- Rego -------------------------------------------------------------------------------------------------------------------

    /** OPA / Rego `allow` rules (a conjunction of input comparisons per rule) as permit predicates; anything else drops its rule. */
    public static function regoToPca(string $moduleText): Obj
    {
        $report = self::newReport('rego');
        $predicates = [];
        $src = self::rx(preg_replace('/#[^\n]*/u', '', self::san($moduleText)));
        if (preg_match('/' . self::NB . 'package' . self::S . '+([A-Za-z_][' . self::W . '.]*)/u', $src, $pkg) === 1) {
            $report['translated'][] = 'package ' . $pkg[1];
        }
        $d = preg_match('/' . self::NB . 'default' . self::S . '+allow' . self::S . '*(?::?=)' . self::S . '*(true|false)' . self::NA . '/u', $src, $dm) === 1;
        if ($d && $dm[1] === 'true') {
            $report['skipped'][] = '`default allow = true` is not modeled (cannot express allow-unless); treated as default-deny';
        } elseif (!$d) {
            $report['skipped'][] = 'no `default allow = false` found; assuming default-deny';
        }
        foreach (self::extractAllowBodies($src, $report) as $body) {
            self::translateRule($body, $predicates, $report);
        }
        return self::finCedar(self::result($predicates, [], $report));
    }

    /** @return list<string> */
    private static function extractAllowBodies(string $src, array &$report): array
    {
        $bodies = [];
        $pos = 0;
        $re = '/' . self::NB . 'allow' . self::NA . self::S . '*(?:(?::?=' . self::S . '*true' . self::NA . '|=' . self::S . '*true' . self::NA . '|' . self::NB . 'if' . self::NA . ')' . self::S . '*)?\{/u';
        while (preg_match($re, $src, $m, PREG_OFFSET_CAPTURE, $pos) === 1) {
            $open = strpos($src, '{', $m[0][1]);
            $close = self::matchDelim($src, $open, '{', '}');
            if ($close < 0) {
                $report['errors'][] = 'unterminated `allow { ... }` block';
                break;
            }
            $bodies[] = substr($src, $open + 1, $close - $open - 1);
            $pos = $close + 1;
        }
        return $bodies;
    }

    private static function translateRule(string $body, array &$predicates, array &$report): void
    {
        $statements = [];
        foreach ((preg_split('/[\n;]/', $body) ?: []) as $s) {
            $t = self::trim($s);
            if ($t !== '') {
                $statements[] = $t;
            }
        }
        $verb = '*';
        $resource = null;
        $where = [];
        foreach ($statements as $stmt) {
            $parsed = self::parseStatement($stmt);
            $kind = $parsed[0];
            if ($kind === 'unmodeled') {
                $report['skipped'][] = 'unmodeled statement "' . self::truncate($stmt) . "\" \u{2014} rule dropped (fail closed)";
                return;
            }
            if ($kind === 'verb') {
                if (is_string($verb) && $verb === '*') {
                    $verb = $parsed[1];
                } else {
                    $have = is_array($verb) ? $verb : [$verb];
                    $nxt = is_array($parsed[1]) ? $parsed[1] : [$parsed[1]];
                    $both = array_values(array_filter($have, static fn($v) => in_array($v, $nxt, true)));
                    if ($both === []) {
                        $report['translated'][] = 'rule can never match (contradictory action selectors), nothing emitted';
                        return;
                    }
                    $verb = count($both) === 1 ? $both[0] : $both;
                }
            } elseif ($kind === 'resource') {
                if ($resource !== null && $resource !== $parsed[1]) {
                    $report['translated'][] = 'rule can never match (contradictory resource selectors), nothing emitted';
                    return;
                }
                $resource = $parsed[1];
            } else {
                $where[] = $parsed[1];
            }
        }
        $predicate = ['verb' => $verb];
        if ($resource !== null) {
            $predicate['resource'] = $resource;
        }
        if ($where !== []) {
            $predicate['where'] = $where;
        }
        $predicates[] = $predicate;
        $report['translated'][] = "allow \u{2192} verb " . self::jverb($verb) . (($resource !== null && $resource !== '') ? ' on ' . $resource : '') . ' (' . count($where) . ' condition(s))';
    }

    /** @return array{0:string,1:mixed} */
    private static function parseStatement(string $stmt): array
    {
        $unmodeled = ['unmodeled', null];
        $s = self::trim($stmt);
        $nm = self::full('not' . self::S . '+((?s:.+))', $s);
        if ($nm !== null) {
            $inner = self::parseStatement(self::trim($nm[1]));
            if ($inner[0] !== 'condition') {
                return $unmodeled;
            }
            $c = $inner[1];
            if (($c['op'] ?? null) === 'eq' && is_string($c['field'] ?? null)) {
                $needs = [['field' => $c['field'], 'op' => 'exists']];
                if (is_string($c['ref'] ?? null)) {
                    $needs[] = ['field' => $c['ref'], 'op' => 'exists'];
                }
                return ['condition', ['not' => ['all_of' => [...$needs, $c]]]];
            }
            return ['condition', ['not' => $c]];
        }
        $builtin = self::parseBuiltin($s);
        if ($builtin !== null) {
            return $builtin;
        }
        if (preg_match('/:=|' . self::NB . 'some' . self::NA . '|' . self::NB . 'every' . self::NA . '|\[' . self::DOT . '*\|' . self::DOT . '*\]/u', $s) === 1) {
            return $unmodeled;
        }
        if (str_contains($s, '(')) {
            return $unmodeled;
        }
        if (preg_match('/' . self::NB . 'input\.[' . self::W . '.]*\[/', $s) === 1) {
            return $unmodeled;
        }
        $m = self::full('(input\.[' . self::W . '.]+)' . self::S . '*(==|!=|<=|>=|<|>|' . self::NB . 'in' . self::NA . ')' . self::S . '*((?s:.+))', $s);
        if ($m === null) {
            return $unmodeled;
        }
        $path = $m[1];
        $opTok = $m[2];
        $rhsRaw = self::trim($m[3]);
        $sub = substr($path, 6);
        if ($opTok === 'in') {
            [$ok, $values] = self::parseSetLiteral($rhsRaw);
            if (!$ok) {
                return $unmodeled;
            }
            if ($sub === 'action') {
                $verbs = array_values(array_filter($values, 'is_string'));
                if (count($verbs) !== count($values)) {
                    return $unmodeled;
                }
                return ['verb', $verbs];
            }
            return ['condition', ['field' => 'env.' . $sub, 'op' => 'in', 'value' => $values]];
        }
        if (($opTok === '==' || $opTok === '!=') && preg_match('/\Ainput\.[' . self::W . '.]+\z/', $rhsRaw) === 1) {
            return ['condition', ['field' => 'env.' . $sub, 'op' => $opTok === '!=' ? 'ne' : 'eq', 'ref' => 'env.' . substr($rhsRaw, 6)]];
        }
        [$ok, $value] = self::regoLiteral($rhsRaw);
        if (!$ok) {
            return $unmodeled;
        }
        if ($opTok === '==') {
            if ($sub === 'action' && is_string($value)) {
                return ['verb', $value];
            }
            if ($sub === 'resource' && is_string($value)) {
                return ['resource', $value];
            }
            return ['condition', ['field' => 'env.' . $sub, 'op' => 'eq', 'value' => $value]];
        }
        if ($opTok === '!=') {
            return ['condition', ['field' => 'env.' . $sub, 'op' => 'ne', 'value' => $value]];
        }
        if (is_bool($value) || !(is_int($value) || is_float($value))) {
            return $unmodeled;
        }
        $cmp = $opTok === '<' ? 'lt' : ($opTok === '<=' ? 'lte' : ($opTok === '>' ? 'gt' : 'gte'));
        return ['condition', ['field' => 'env.' . $sub, 'op' => $cmp, 'value' => $value]];
    }

    /** @return array{0:string,1:mixed}|null */
    private static function parseBuiltin(string $s): ?array
    {
        $sw = self::full('startswith\(' . self::S . '*(input\.[' . self::W . '.]+)' . self::S . '*,' . self::S . '*"([^"]*)"' . self::S . '*\)', $s);
        if ($sw !== null) {
            return ['condition', ['field' => 'env.' . substr($sw[1], 6), 'op' => 'prefix', 'value' => $sw[2]]];
        }
        $gm = self::full('glob\.match\(' . self::S . '*"([^"]*)"' . self::S . '*,' . self::S . '*(\[' . self::S . '*\]|null)' . self::S . '*,' . self::S . '*(input\.[' . self::W . '.]+)' . self::S . '*\)', $s);
        if ($gm !== null) {
            $pattern = $gm[1];
            if (preg_match('/[\[\]{}]/', $pattern) === 1) {
                return ['unmodeled', null];
            }
            if (str_starts_with($gm[2], '[') && preg_match('/[*?\\\\]/', $pattern) === 1) {
                return ['unmodeled', null];
            }
            return ['condition', ['field' => 'env.' . substr($gm[3], 6), 'op' => 'like', 'value' => $pattern]];
        }
        return null;
    }

    /** @return array{0:bool,1:mixed} */
    private static function regoLiteral(string $expr): array
    {
        $s = self::trim($expr);
        $m = self::full('"([^"]*)"', $s);
        if ($m !== null) {
            return [true, $m[1]];
        }
        if ($s === 'true') {
            return [true, true];
        }
        if ($s === 'false') {
            return [true, false];
        }
        if (preg_match('/\A-?[0-9]+(?:\.[0-9]+)?\z/', $s) === 1) {
            return [true, self::number($s)];
        }
        return [false, null];
    }

    /** @return array{0:bool,1:list<mixed>} */
    private static function parseSetLiteral(string $expr): array
    {
        $s = self::trim($expr);
        $isSet = str_starts_with($s, '{') && str_ends_with($s, '}');
        $isArr = str_starts_with($s, '[') && str_ends_with($s, ']');
        if (!$isSet && !$isArr) {
            return [false, []];
        }
        $values = [];
        foreach (self::trimmedNonEmpty(self::splitTopLevel(substr($s, 1, -1), ',')) as $it) {
            [$ok, $v] = self::regoLiteral($it);
            if (!$ok) {
                return [false, []];
            }
            $values[] = $v;
        }
        return [true, $values];
    }

    // ---- OpenFGA ----------------------------------------------------------------------------------------------------------------

    private static function isRewrite(mixed $v): bool
    {
        return $v instanceof Obj || is_array($v);
    }

    private static function hasOwn(mixed $o, string $k): bool
    {
        return $o instanceof Obj && $o->has($k);
    }

    private static function oget(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    /** @return list<mixed>|null */
    private static function childNodes(mixed $container): ?array
    {
        if (!self::isRewrite($container)) {
            return null;
        }
        $child = self::oget($container, 'child');
        return is_array($child) && array_is_list($child) ? $child : null;
    }

    private static function relationOf(mixed $v): ?string
    {
        if (!self::isRewrite($v)) {
            return null;
        }
        $rel = self::oget($v, 'relation');
        return is_string($rel) && $rel !== '' ? $rel : null;
    }

    /** @return array<string,mixed> */
    private static function buildPlan(mixed $node): array
    {
        $fail = static fn(string $reason, bool $partial = false): array => ['ok' => false, 'partial' => $partial, 'reason' => $reason];
        if (self::hasOwn($node, 'this')) {
            return ['ok' => true, 'plan' => ['kind' => 'direct'], 'partial' => false];
        }
        if (self::hasOwn($node, 'computedUserset')) {
            $rel = self::oget($node->get('computedUserset'), 'relation');
            if (!is_string($rel) || $rel === '') {
                return $fail('computedUserset without a relation');
            }
            return ['ok' => true, 'plan' => ['kind' => 'computed', 'relation' => $rel], 'partial' => false];
        }
        if (self::hasOwn($node, 'union')) {
            $children = self::childNodes($node->get('union'));
            if ($children === null) {
                return $fail('union without children');
            }
            $subs = [];
            $partial = false;
            foreach ($children as $child) {
                if (!self::isRewrite($child)) {
                    $partial = true;
                    continue;
                }
                $sub = self::buildPlan($child);
                if (!$sub['ok'] || !array_key_exists('plan', $sub)) {
                    $partial = true; // OR under-approximates safely: drop the unmodeled child
                    continue;
                }
                if ($sub['partial']) {
                    $partial = true;
                }
                $subs[] = $sub['plan'];
            }
            if ($subs === []) {
                return $fail('union with no modeled children', $partial);
            }
            return ['ok' => true, 'plan' => ['kind' => 'union', 'children' => $subs], 'partial' => $partial];
        }
        if (self::hasOwn($node, 'intersection')) {
            $children = self::childNodes($node->get('intersection'));
            if ($children === null) {
                return $fail('intersection without children');
            }
            $subs = [];
            foreach ($children as $child) {
                if (!self::isRewrite($child)) {
                    return $fail('intersection child is not a rewrite');
                }
                $sub = self::buildPlan($child);
                if (!$sub['ok'] || !array_key_exists('plan', $sub)) {
                    return $fail('intersection child unmodeled (' . ($sub['reason'] ?? 'unsupported') . ')');
                }
                $subs[] = $sub['plan'];
            }
            if ($subs === []) {
                return $fail('intersection with no children');
            }
            return ['ok' => true, 'plan' => ['kind' => 'intersection', 'children' => $subs], 'partial' => false];
        }
        if (self::hasOwn($node, 'difference')) {
            $diff = $node->get('difference');
            if (!self::isRewrite($diff)) {
                return $fail('malformed difference');
            }
            $baseNode = self::oget($diff, 'base');
            $subNode = self::oget($diff, 'subtract');
            if (!self::isRewrite($baseNode) || !self::isRewrite($subNode)) {
                return $fail('difference needs both base and subtract');
            }
            $base = self::buildPlan($baseNode);
            $subtract = self::buildPlan($subNode);
            if (!$base['ok'] || !array_key_exists('plan', $base)) {
                return $fail('difference base unmodeled (' . ($base['reason'] ?? '?') . ')');
            }
            if (!$subtract['ok'] || !array_key_exists('plan', $subtract)) {
                return $fail('difference subtract unmodeled (' . ($subtract['reason'] ?? '?') . ')');
            }
            return ['ok' => true, 'plan' => ['kind' => 'difference', 'base' => $base['plan'], 'subtract' => $subtract['plan']], 'partial' => $base['partial'] || $subtract['partial']];
        }
        if (self::hasOwn($node, 'tupleToUserset')) {
            $ttu = $node->get('tupleToUserset');
            if (!self::isRewrite($ttu)) {
                return $fail('malformed tupleToUserset');
            }
            $tuplesetRel = self::relationOf(self::oget($ttu, 'tupleset'));
            $computedRel = self::relationOf(self::oget($ttu, 'computedUserset'));
            if ($tuplesetRel === null) {
                return $fail('tupleToUserset without a tupleset relation');
            }
            if ($computedRel === null) {
                return $fail('tupleToUserset without a computedUserset relation');
            }
            return ['ok' => true, 'plan' => ['kind' => 'ttu', 'tupleset' => $tuplesetRel, 'computed' => $computedRel], 'partial' => false];
        }
        return $fail('unknown rewrite node');
    }

    private static function describePlan(array $plan): string
    {
        switch ($plan['kind']) {
            case 'direct':
                return 'direct';
            case 'computed':
                return 'computed ' . $plan['relation'];
            case 'union':
                return 'union[' . implode(', ', array_map(self::describePlan(...), $plan['children'])) . ']';
            case 'intersection':
                return 'intersection[' . implode(', ', array_map(self::describePlan(...), $plan['children'])) . ']';
            case 'difference':
                return 'difference(' . self::describePlan($plan['base']) . ' - ' . self::describePlan($plan['subtract']) . ')';
        }
        return $plan['computed'] . ' from ' . $plan['tupleset'];
    }

    /**
     * Type -> relation -> rewrite node, in the reference's insertion order; each is ordered ['k'.name => [name, value]].
     * @return array<string,array{0:string,1:array<string,array{0:string,1:mixed}>}>|null
     */
    private static function parseModel(mixed $model, array &$report): ?array
    {
        if (!self::isRewrite($model)) {
            $report['errors'][] = 'model is not an object';
            return null;
        }
        $defs = self::oget($model, 'type_definitions');
        if (!is_array($defs) || !array_is_list($defs)) {
            $report['errors'][] = 'model.type_definitions is missing or not an array';
            return null;
        }
        $out = [];
        foreach ($defs as $d) {
            if (!self::isRewrite($d)) {
                continue;
            }
            $t = self::oget($d, 'type');
            if (!is_string($t) || $t === '') {
                continue;
            }
            $rels = self::oget($d, 'relations');
            $relMap = [];
            if ($rels instanceof Obj) {
                foreach (Js::ownKeys($rels->keys()) as $name) {
                    if (self::isRewrite($rels->get($name))) {
                        $relMap['k' . $name] = [$name, $rels->get($name)];
                    }
                }
            } elseif (is_array($rels)) {
                foreach ($rels as $i => $node) {
                    if (self::isRewrite($node)) {
                        $relMap['k' . $i] = [(string)$i, $node];
                    }
                }
            }
            $out['k' . $t] = [$t, $relMap];
        }
        return $out;
    }

    /** @return list<array{user:string,relation:string,object:string}> */
    private static function parseTuples(mixed $tuples, bool $missing, array &$report): array
    {
        if (!is_array($tuples) || !array_is_list($tuples)) {
            if (!$missing) {
                $report['errors'][] = 'tuples is not an array';
            }
            return [];
        }
        $out = [];
        foreach ($tuples as $t) {
            if (!($t instanceof Obj)) {
                continue;
            }
            $user = $t->get('user');
            $relation = $t->get('relation');
            $obj = $t->get('object');
            if (is_string($user) && is_string($relation) && is_string($obj)) {
                $out[] = ['user' => $user, 'relation' => $relation, 'object' => $obj];
            }
        }
        return $out;
    }

    /**
     * An OpenFGA / Zanzibar model plus relationship tuples as one permit per (user, object, relation) triple that holds
     * (`this`, computedUserset, union, intersection, difference, tupleToUserset; bounded and cycle-guarded).
     * Omit `$tuples` for "no tuples given" (an explicit null is reported).
     */
    public static function openfgaToPca(mixed $model, mixed ...$more): Obj
    {
        $report = self::newReport('openfga');
        $predicates = [];
        $typeRelations = self::parseModel($model, $report);
        $tupleList = self::parseTuples($more[0] ?? null, $more === [], $report);
        $fix = static fn(string $s): string => $s;
        if ($typeRelations === null) {
            return self::fin(self::result($predicates, [], $report), $fix);
        }

        $direct = [];            // obj\0rel => ['k'.user => user]
        $usersSeen = [];
        $wildcardTypes = [];
        $objectsSeen = [];
        $usersetTuples = 0;
        foreach ($tupleList as $t) {
            $objectsSeen['k' . $t['object']] = $t['object'];
            $direct[$t['object'] . "\0" . $t['relation']]['k' . $t['user']] = $t['user'];
            if (str_contains($t['user'], '#')) {
                $usersetTuples++;
            } elseif (self::isWildcard($t['user'])) {
                $wt = substr($t['user'], 0, -2);
                $wildcardTypes['k' . $wt] = $wt;
            } else {
                $usersSeen['k' . $t['user']] = $t['user'];
            }
        }
        if ($usersetTuples > 0) {
            $report['skipped'][] = "$usersetTuples userset-valued tuple(s) (user contains '#') not expanded to concrete users";
        }

        $plans = [];
        foreach ($typeRelations as [$type, $relations]) {
            foreach ($relations as [$relation, $node]) {
                $built = self::buildPlan($node);
                if (!$built['ok'] || !array_key_exists('plan', $built)) {
                    $report['skipped'][] = "relation $type#$relation: " . ($built['reason'] ?? 'unsupported rewrite') . " \u{2014} skipped";
                    continue;
                }
                if ($built['partial']) {
                    $report['skipped'][] = "relation $type#$relation: some union children unsupported and dropped (under-approximated)";
                }
                $plans[$type . "\0" . $relation] = $built['plan'];
                $report['translated'][] = "relation $type#$relation (" . self::describePlan($built['plan']) . ')';
            }
        }

        $typeOf = static function (string $obj): string {
            $i = strpos($obj, ':');
            return $i === false ? $obj : substr($obj, 0, $i);
        };
        $objectOfUserset = static function (string $p): string {
            $i = strpos($p, '#');
            return $i === false ? $p : substr($p, 0, $i);
        };

        $holdsRel = null;
        $evalPlan = null;
        $holdsRel = static function (string $user, string $obj, string $relation, int $depth, array $visited) use (&$evalPlan, $plans, $typeOf): bool {
            $key = $obj . "\0" . $relation;
            if ($depth > self::MAX_DEPTH || isset($visited[$key])) {
                return false;
            }
            $plan = $plans[$typeOf($obj) . "\0" . $relation] ?? null;
            if ($plan === null) {
                return false;
            }
            $visited[$key] = true;
            return $evalPlan($user, $obj, $relation, $plan, $depth, $visited);
        };
        $evalPlan = static function (string $user, string $obj, string $relation, array $plan, int $depth, array $visited) use (&$holdsRel, &$evalPlan, $direct, $typeOf, $objectOfUserset): bool {
            switch ($plan['kind']) {
                case 'direct':
                    $s = $direct[$obj . "\0" . $relation] ?? null;
                    return $s !== null && (isset($s['k' . $user]) || isset($s['k' . $typeOf($user) . ':*']));
                case 'computed':
                    return $holdsRel($user, $obj, $plan['relation'], $depth + 1, $visited);
                case 'union':
                    foreach ($plan['children'] as $c) {
                        if ($evalPlan($user, $obj, $relation, $c, $depth, $visited)) {
                            return true;
                        }
                    }
                    return false;
                case 'intersection':
                    foreach ($plan['children'] as $c) {
                        if (!$evalPlan($user, $obj, $relation, $c, $depth, $visited)) {
                            return false;
                        }
                    }
                    return true;
                case 'difference':
                    return $evalPlan($user, $obj, $relation, $plan['base'], $depth, $visited) && !$evalPlan($user, $obj, $relation, $plan['subtract'], $depth, $visited);
            }
            $related = $direct[$obj . "\0" . $plan['tupleset']] ?? null;
            if ($related === null) {
                return false;
            }
            foreach ($related as $p) {
                if ($holdsRel($user, $objectOfUserset($p), $plan['computed'], $depth + 1, $visited)) {
                    return true;
                }
            }
            return false;
        };

        $sortedUsers = self::sortUnits(array_values($usersSeen));
        foreach (self::sortUnits(array_values($objectsSeen)) as $obj) {
            $type = $typeOf($obj);
            $relations = $typeRelations['k' . $type][1] ?? null;
            if ($relations === null) {
                $report['skipped'][] = "object $obj: type \"$type\" not defined in model \u{2014} ignored";
                continue;
            }
            foreach (self::sortUnits(array_map(static fn(array $r): string => $r[0], array_values($relations))) as $relation) {
                if (!isset($plans[$type . "\0" . $relation])) {
                    continue;
                }
                foreach ($sortedUsers as $user) {
                    if ($holdsRel($user, $obj, $relation, 0, [])) {
                        $predicates[] = ['verb' => $relation, 'resource' => $obj, 'where' => [['field' => 'subject.id', 'op' => 'eq', 'value' => $user]]];
                    }
                }
                // a public tuple (`type:*`) grants every subject of that type, including ones no tuple names
                foreach (self::sortUnits(array_values($wildcardTypes)) as $wtype) {
                    if (!$holdsRel($wtype . ":\0anyone", $obj, $relation, 0, [])) {
                        continue;
                    }
                    $named = array_values(array_filter($sortedUsers, static fn(string $u): bool => $typeOf($u) === $wtype));
                    $where = [['field' => 'subject.id', 'op' => 'like', 'value' => self::escapeGlob($wtype) . ':*']];
                    if ($named !== []) {
                        $where[] = ['not' => ['field' => 'subject.id', 'op' => 'in', 'value' => $named]];
                    }
                    $predicates[] = ['verb' => $relation, 'resource' => $obj, 'where' => $where];
                }
            }
        }
        return self::fin(self::result($predicates, [], $report), $fix);
    }

    private static function isWildcard(string $user): bool
    {
        return str_ends_with($user, ':*') && strlen($user) > 2 && !str_contains($user, '#');
    }

    private static function escapeGlob(string $t): string
    {
        return (string)preg_replace('/[*?\\\\]/', '\\\\$0', $t);
    }

    // ---- decide -----------------------------------------------------------------------------------------------------------------

    private static function length(mixed $x): ?int
    {
        if ($x === null) {
            throw new \TypeError("cannot read properties of null (reading 'length')");
        }
        if (is_array($x)) {
            return count($x);
        }
        return is_string($x) ? Js::len($x) : null;
    }

    /**
     * One action under a translation with deny-overrides-permit (Cedar's combining rule), on the core evaluator. An incomplete
     * translation (`report.errors` non-empty) denies everything. A `$ctx` that is not an object is evaluated as an empty one.
     *
     * @return array<string,mixed>
     */
    public static function decide(mixed $result, mixed $ctx): array
    {
        $ctx = $ctx instanceof Obj ? $ctx : new Obj();
        $report = $result instanceof Obj ? $result->get('report') : null;
        if ($report !== null && Js::truthy($report)) {
            if ($report instanceof Obj) {
                if (!$report->has('errors')) {
                    throw new \TypeError("cannot read properties of undefined (reading 'length')");
                }
                $n = self::length($report->get('errors'));
            } else {
                $n = self::length(null);
            }
            if ($n !== null && $n > 0) {
                return ['allowed' => false, 'reason' => 'translation incomplete (fail closed)'];
            }
        }
        if (!($result instanceof Obj) || !$result->has('denies')) {
            throw new \TypeError('cannot read properties of undefined');
        }
        $denies = $result->get('denies');
        $n = self::length($denies);
        if ($n !== null && $n > 0) {
            $denied = Predicates::evaluatePredicates($denies, $ctx);
            if ($denied['allowed']) {
                return ['allowed' => false, 'matched' => $denied['matched'] ?? null, 'reason' => 'forbidden by deny policy'];
            }
        }
        return Predicates::evaluatePredicates($result->get('predicates'), $ctx);
    }

    // ---- strict CEL (PolicyBridgeCel) -------------------------------------------------------------------------------------------

    public static function parseCel(mixed $expression): Obj
    {
        return PolicyBridgeCel::parseCel($expression);
    }

    public static function celToCondition(mixed $expression, mixed $schema): Obj
    {
        return PolicyBridgeCel::celToCondition($expression, $schema);
    }

    public static function celToPredicate(mixed $expression, mixed $schema, mixed $scope): Obj
    {
        return PolicyBridgeCel::celToPredicate($expression, $schema, $scope);
    }

    public static function celConditionsToPca(mixed $items, mixed $schema): Obj
    {
        return PolicyBridgeCel::celConditionsToPca($items, $schema);
    }
}
