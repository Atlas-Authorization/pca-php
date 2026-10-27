<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * The ternary decision, the tighten-only model rule (rule 21) and the units rule (rule 20): a port of decision.ts and
 * envelope-rules.ts (security contract C-50..C-55). A decision is `deny < escalate < allow`; {@see Decision::meet} (the
 * minimum) is the only way two decisions combine, so `escalate` never becomes `allow` by composition.
 *
 * Every function is total and never throws; anything malformed fails closed (a refusal, never an allow). Inputs are the
 * library's JSON values (Obj, lists, strings, Num, bool, null); a member that is ABSENT is told apart from JSON null.
 */
final class Decision
{
    public const RANK = ['deny' => 0, 'escalate' => 1, 'allow' => 2];
    /** A failing check is escalate-class iff its reason (after `<check>: `) starts with one of these. */
    public const ESCALATE_REASON_PREFIXES = ['intent_required:', 'escalate:'];
    public const MODEL_ENV_ROOTS = ['class', 'prov', 'judge'];
    public const MAX_TIGHTEN_RULES = 64;
    private const NAME_RE = '/\A[a-z][a-z0-9_]{0,63}\z/D';
    private const PARAM_PATH_RE = '/\Aaction\.params\.[A-Za-z0-9_-]{1,64}\z/D';

    // ---- the lattice --------------------------------------------------------------------------------------------------

    /** The meet of two decisions: the lower one. An unknown value is `deny` (fail closed). */
    public static function meet(mixed $a, mixed $b): string
    {
        if (!is_string($a) || !is_string($b) || !isset(self::RANK[$a]) || !isset(self::RANK[$b])) {
            return 'deny';
        }
        return self::RANK[$a] <= self::RANK[$b] ? $a : $b;
    }

    /** Meet over a list (`allow` for the empty list). */
    public static function meetAll(array $ds): string
    {
        $acc = 'allow';
        foreach ($ds as $d) {
            $acc = self::meet($acc, $d);
        }
        return $acc;
    }

    /** The highest decision a model signal permits: ok -> allow, escalate -> escalate, anything else -> deny. */
    public static function signalCeiling(mixed $s): string
    {
        return $s === 'ok' ? 'allow' : ($s === 'escalate' ? 'escalate' : 'deny');
    }

    /** G-T9: a model can only tighten. `tighten(d, s) <= d`; `tighten(d, 'ok') = d`. */
    public static function tighten(mixed $base, mixed $signal): string
    {
        return self::meet($base, self::signalCeiling($signal));
    }

    /**
     * The decision of a verdict: allow -> allow; at least one failing check and EVERY failing check escalate-class ->
     * escalate; otherwise deny. A failing check is escalate-class iff it has at least one reason `<check>: <body>` and every
     * such body starts with an escalate prefix; a failing check with no reason of its own is a hard failure (deny).
     *
     * @param array<string,mixed> $checks check name => status (`'fail'` is a failure)
     * @param array<int,mixed>    $reasons
     */
    public static function decisionOf(bool $allow, array $checks, array $reasons): string
    {
        try {
            if ($allow === true) {
                return 'allow';
            }
            $failing = 0;
            foreach ($checks as $name => $status) {
                if ($status !== 'fail') {
                    continue;
                }
                $failing++;
                $head = $name . ': ';
                $own = array_values(array_filter($reasons, static fn($r): bool => is_string($r) && str_starts_with($r, $head)));
                if ($own === []) {
                    return 'deny';
                }
                foreach ($own as $r) {
                    $body = substr($r, strlen($head));
                    $ok = false;
                    foreach (self::ESCALATE_REASON_PREFIXES as $p) {
                        if (str_starts_with($body, $p)) {
                            $ok = true;
                            break;
                        }
                    }
                    if (!$ok) {
                        return 'deny';
                    }
                }
            }
            return $failing > 0 ? 'escalate' : 'deny';
        } catch (\Throwable) {
            return 'deny';
        }
    }

    /** {@see decisionOf} over a verdict Obj `{allow, checks, reasons}` (the vector shape). Total. */
    public static function decisionOfVerdict(mixed $v): string
    {
        try {
            if (!($v instanceof Obj) || !($v->get('checks') instanceof Obj)) {
                return 'deny';
            }
            $checks = [];
            foreach ($v->get('checks')->keys() as $k) {
                $checks[$k] = $v->get('checks')->get($k);
            }
            $rs = $v->get('reasons');
            return self::decisionOf($v->get('allow') === true, $checks, is_array($rs) && array_is_list($rs) ? $rs : []);
        } catch (\Throwable) {
            return 'deny';
        }
    }

    /**
     * The reasons a verdict lists: `$base` (the core's own), then `<name>: <reason>` for EVERY failing v2 check (one without a
     * reason adds none; an identical text is listed once, in the order first seen). `foldV2Reasons` of decision.ts.
     *
     * @param list<string> $base
     * @param list<array{name: string, ok: mixed, reason?: mixed}> $v2
     * @return list<string>
     */
    public static function foldV2Reasons(array $base, array $v2): array
    {
        $out = $base;
        foreach ($v2 as $c) {
            if ($c['ok'] !== true && isset($c['reason']) && !in_array($c['name'] . ': ' . $c['reason'], $out, true)) {
                $out[] = $c['name'] . ': ' . $c['reason'];
            }
        }
        return $out;
    }

    /** A PEP's decision: an answer can only upgrade `escalate`; anything else is returned UNCHANGED (as the reference does). */
    public static function pepDecision(mixed $d, mixed $answered): mixed
    {
        return $d === 'escalate' && $answered === true ? 'allow' : $d;
    }

    // ---- rule 21: model polarity -------------------------------------------------------------------------------------

    /** Is `$path` a model-derived env path? `$singleSource` names the worlds decided by ONE oracle. */
    public static function isModelDerivedPath(mixed $path, array $singleSource = []): bool
    {
        if (!is_string($path)) {
            return false;
        }
        $seg = explode('.', $path);
        if ($seg[0] !== 'env' || count($seg) < 2) {
            return false;
        }
        if (in_array($seg[1], self::MODEL_ENV_ROOTS, true)) {
            return true;
        }
        if ($seg[1] === 'world') {
            return count($seg) === 2 ? count($singleSource) > 0 : in_array($seg[2], $singleSource, true);
        }
        return false;
    }

    /** @param array<string,true> $out */
    private static function collectPaths(mixed $c, array &$out, int $depth): void
    {
        if ($depth > 64 || !($c instanceof Obj)) {
            return;
        }
        foreach (['all_of', 'any_of'] as $k) {
            $xs = $c->get($k);
            if (is_array($xs) && array_is_list($xs)) {
                foreach ($xs as $x) {
                    self::collectPaths($x, $out, $depth + 1);
                }
            }
        }
        if ($c->has('not')) {
            self::collectPaths($c->get('not'), $out, $depth + 1);
        }
        foreach (['field', 'ref', 'collection'] as $k) {
            if (is_string($c->get($k))) {
                $out[$c->get($k)] = true;
            }
        }
    }

    /** Every `where` condition of every predicate in a list of predicate lists. @return list<mixed> */
    private static function wheres(mixed $predicateLists, ?string $verb): array
    {
        $out = [];
        foreach (is_array($predicateLists) && array_is_list($predicateLists) ? $predicateLists : [] as $list) {
            if (!is_array($list) || !array_is_list($list)) {
                continue;
            }
            foreach ($list as $p) {
                if ($verb !== null && !self::verbInScope($p, $verb)) {
                    continue;
                }
                $w = $p instanceof Obj ? $p->get('where') : null;
                if (is_array($w) && array_is_list($w)) {
                    foreach ($w as $c) {
                        $out[] = $c;
                    }
                }
            }
        }
        return $out;
    }

    /**
     * Every model-derived env path a list of predicate lists reads (`field`, `ref` or `collection` of any nested
     * condition), sorted by UTF-8 byte order and de-duplicated.
     * @return list<string>
     */
    public static function modelPathsRead(mixed $predicateLists, array $singleSource = []): array
    {
        $found = [];
        foreach (self::wheres($predicateLists, null) as $c) {
            self::collectPaths($c, $found, 0);
        }
        $paths = array_values(array_filter(array_map('strval', array_keys($found)),
            static fn(string $p): bool => self::isModelDerivedPath($p, $singleSource)));
        usort($paths, 'strcmp');
        return $paths;
    }

    private static function closedMembers(Obj $o, array $required, array $optional, string $where): ?string
    {
        foreach (IntentWb::jsKeys($o) as $k) {
            if (!in_array($k, $required, true) && !in_array($k, $optional, true)) {
                return "unknown member '$where.$k'";
            }
        }
        foreach ($required as $k) {
            if (!$o->has($k)) {
                return "missing member '$where.$k'";
            }
        }
        return null;
    }

    /** Null = well-formed. `$present` false = the member is absent (always well-formed). */
    public static function tightenListError(mixed $t, bool $present = true): ?string
    {
        if (!$present) {
            return null;
        }
        if (!is_array($t) || !array_is_list($t)) {
            return 'tighten must be an array';
        }
        if (count($t) > self::MAX_TIGHTEN_RULES) {
            return 'tighten has more than ' . self::MAX_TIGHTEN_RULES . ' rules';
        }
        $ids = [];
        foreach ($t as $i => $r) {
            if (!($r instanceof Obj)) {
                return "tighten[$i] must be an object";
            }
            $e = self::closedMembers($r, ['id', 'when', 'signal'], ['reason'], "tighten[$i]");
            if ($e !== null) {
                return $e;
            }
            $id = $r->get('id');
            if (!is_string($id) || preg_match(self::NAME_RE, $id) !== 1) {
                return "tighten[$i].id must match ^[a-z][a-z0-9_]{0,63}$";
            }
            if (isset($ids[$id])) {
                return "tighten[$i].id '$id' is a duplicate";
            }
            $ids[$id] = true;
            if (!($r->get('when') instanceof Obj)) {
                return "tighten[$i].when must be a condition object";
            }
            if ($r->get('signal') !== 'escalate' && $r->get('signal') !== 'deny') {
                return "tighten[$i].signal must be 'escalate' or 'deny'";
            }
            if ($r->has('reason') && (!is_string($r->get('reason')) || SafeRegex::utf16Len($r->get('reason')) > 256)) {
                return "tighten[$i].reason must be a string of at most 256 characters";
            }
        }
        return null;
    }

    /**
     * Rule 21. Input members: predicates (list of predicate lists), tighten, polarity, single_source, context {action,
     * subject, env}. Returns `['outcome' => ok|escalate|deny, 'legacy' => bool, 'offending' => list<string>, 'reason'?]`.
     * A grant-side `where` that reads a model-derived path is a hard refusal unless the mode is `legacy`; then the rules in
     * order (`when` true -> its signal; unknown -> escalate; false -> none); the outcome is the meet of all signals.
     */
    public static function decideTighten(mixed $input): array
    {
        $res = static function (string $o, bool $legacy, array $off, ?string $reason = null): array {
            $r = ['outcome' => $o, 'legacy' => $legacy, 'offending' => $off];
            if ($reason !== null) {
                $r['reason'] = $reason;
            }
            return $r;
        };
        try {
            if (!($input instanceof Obj)) {
                throw new \InvalidArgumentException('input is not an object');
            }
            $ss = $input->get('single_source');
            $single = [];
            foreach (is_array($ss) && array_is_list($ss) ? $ss : [] as $x) {
                if (is_string($x)) {
                    $single[] = $x;
                }
            }
            $polarity = $input->get('polarity');
            if ($input->has('polarity') && $polarity !== 'legacy') {
                return $res('deny', false, [], "model_polarity must be 'legacy' when present");
            }
            $le = self::tightenListError($input->get('tighten'), $input->has('tighten'));
            if ($le !== null) {
                return $res('deny', false, [], "malformed tighten list: $le");
            }
            $offending = self::modelPathsRead($input->get('predicates'), $single);
            $legacy = $polarity === 'legacy' && count($offending) > 0;
            if (count($offending) > 0 && !$legacy) {
                return $res('deny', false, $offending, "a grant's where reads model-derived path(s) " . implode(', ', $offending)
                    . ': a model may only tighten (move them into tighten[]) (rule 21)');
            }
            $out = 'ok';
            $reason = null;
            $ctx = $input->get('context') instanceof Obj ? $input->get('context') : new Obj();
            $rules = $input->has('tighten') ? $input->get('tighten') : [];
            foreach ($rules as $r) {
                $t = Predicates::evaluateConditionTri($r->get('when'), $ctx);
                $sig = null;
                $why = '';
                $sigName = $r->get('signal');
                if ($t === 'true') {
                    $sig = $sigName;
                    $why = ($sigName === 'deny' ? 'denied by' : 'escalate: asked by') . " tighten rule '" . $r->get('id') . "'"
                        . ($r->has('reason') ? ' (' . $r->get('reason') . ')' : '');
                } elseif ($t === 'unknown') {
                    $sig = 'escalate';
                    $why = "escalate: rule '" . $r->get('id') . "' could not be decided (a value it reads is missing or ill-typed)";
                }
                if ($sig !== null && self::RANK[self::signalCeiling($sig)] < self::RANK[self::signalCeiling($out)]) {
                    $out = $sig;
                    $reason = $why;
                }
            }
            return $res($out, $legacy, $offending, $reason);
        } catch (\Throwable $e) {
            return $res('deny', false, [], 'evaluation error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- rule 20: units ------------------------------------------------------------------------------------------------

    /** Null = well-formed policy unit tags: `{ 'action.params.<name>': {kind, currency?, exponent?} }`, closed. */
    public static function unitTagsError(mixed $u): ?string
    {
        if (!($u instanceof Obj)) {
            return 'units must be an object';
        }
        $keys = IntentWb::jsKeys($u);
        if (count($keys) > 64) {
            return 'units has more than 64 entries';
        }
        foreach ($keys as $k) {
            if (preg_match(self::PARAM_PATH_RE, $k) !== 1) {
                return "units key '$k' must be an action.params.<name> path";
            }
            $t = $u->get($k);
            if (!($t instanceof Obj)) {
                return "units['$k'] must be an object";
            }
            $e = self::closedMembers($t, ['kind'], ['currency', 'exponent'], "units['$k']");
            if ($e !== null) {
                return $e;
            }
            $kind = $t->get('kind');
            if (!is_string($kind) || $kind === '' || SafeRegex::utf16Len($kind) > 64) {
                return "units['$k'].kind must be a string of 1..64 characters";
            }
            $cur = $t->get('currency');
            if ($t->has('currency') && (!is_string($cur) || $cur === '' || SafeRegex::utf16Len($cur) > 16)) {
                return "units['$k'].currency must be a string of 1..16 characters";
            }
            if ($t->has('exponent')) {
                $x = $t->get('exponent');
                if (!(IntentWb::isSafeInt($x) && $x instanceof Num && $x->float() >= 0 && $x->float() <= 18)) {
                    return "units['$k'].exponent must be an integer in [0, 18]";
                }
            }
        }
        return null;
    }

    private static function tagText(?Obj $t): string
    {
        if ($t === null) {
            return 'no unit';
        }
        $k = $t->get('kind');
        $s = $k === null ? '?' : IntentWb::jsStr($k);
        if ($t->has('currency')) {
            $s .= '/' . IntentWb::jsStr($t->get('currency'));
        }
        if ($t->has('exponent')) {
            $s .= '/e' . IntentWb::jsStr($t->get('exponent'));
        }
        return $s;
    }

    private static function sameTag(Obj $a, Obj $b): bool
    {
        foreach (['kind', 'currency', 'exponent'] as $k) {
            if ($a->has($k) !== $b->has($k)) {
                return false;
            }
            if ($a->has($k) && !IntentWb::scalarEq($a->get($k), $b->get($k))) {
                return false;
            }
        }
        return true;
    }

    private static function verbInScope(mixed $p, string $verb): bool
    {
        $v = $p instanceof Obj ? $p->get('verb') : null;
        return $v === '*' || $v === $verb || (is_array($v) && array_is_list($v) && in_array($verb, $v, true));
    }

    /**
     * Rule 20. Input members: units, schema_units, verb_params, verb, predicates. `['ok' => true]` iff (1) every policy tag
     * whose parameter the verb declares equals the unit the schema declares for it, and (2) no grant-side `where` term in
     * scope of the verb reads a unit-bearing parameter without a tag. Total.
     * @return array{ok: bool, reason?: string}
     */
    public static function decideUnits(mixed $input): array
    {
        $fail = static fn(string $m): array => ['ok' => false, 'reason' => $m];
        try {
            if (!($input instanceof Obj)) {
                throw new \InvalidArgumentException('input is not an object');
            }
            $te = self::unitTagsError($input->get('units'));
            if ($te !== null) {
                return $fail($te);
            }
            /** @var Obj $tags */
            $tags = $input->get('units');
            $verb = $input->get('verb');
            if (!is_string($verb) || $verb === '') {
                return $fail('the verb is missing');
            }
            $sUnits = $input->has('schema_units') ? $input->get('schema_units') : new Obj();
            if (!($sUnits instanceof Obj)) {
                return $fail('the schema units table must be an object');
            }
            $params = $input->get('verb_params');
            if (!($params instanceof Obj)) {
                return $fail("the schema does not declare verb '$verb'");
            }
            $declared = static function (string $path) use ($params, $sUnits): array {
                $d = $params->has($path) ? $params->get($path) : null;
                if (!($d instanceof Obj)) {
                    return [false, null];
                }
                $id = $d->get('unit');
                $tag = is_string($id) && $sUnits->has($id) ? $sUnits->get($id) : null;
                return [true, $tag instanceof Obj ? $tag : null];
            };
            $tagKeys = $tags->keys();
            usort($tagKeys, 'strcmp');
            foreach ($tagKeys as $path) {
                [$has, $tag] = $declared($path);
                if (!$has) {
                    continue;
                }
                if ($tag === null || !self::sameTag($tag, $tags->get($path))) {
                    return $fail("'$path' is declared as " . self::tagText($tag) . ' by the action schema but the policy term is tagged '
                        . self::tagText($tags->get($path)) . ' (unit confusion)');
                }
            }
            $read = [];
            foreach (self::wheres($input->get('predicates'), $verb) as $c) {
                self::collectPaths($c, $read, 0);
            }
            $readKeys = array_map('strval', array_keys($read));
            usort($readKeys, 'strcmp');
            foreach ($readKeys as $path) {
                if (preg_match(self::PARAM_PATH_RE, $path) !== 1) {
                    continue;
                }
                [$has, $tag] = $declared($path);
                if ($has && $tag !== null && !$tags->has($path)) {
                    return $fail("a policy term reads '$path' (" . self::tagText($tag) . ') without a unit tag');
                }
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return $fail('evaluation error (fail closed): ' . $e->getMessage());
        }
    }
}
