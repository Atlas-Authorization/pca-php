<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/ActionsImport.php';
require_once __DIR__ . '/ActionsImportRulesData.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/JsRe.php';
require_once __DIR__ . '/Pca.php';

/**
 * The deterministic suggestion layer (native port of import/suggest.ts and import/rules.ts of the reference actions package). A versioned rule set
 * proposes traits, param roles and param tags for a draft def. Union only: a suggestion can ADD a trait, a role (to a param that has none) or a tag,
 * never remove or replace anything, and it never marks a def confirmed. A suggested def is still `pca.unreviewed` for floor purposes; suggestions only
 * improve the card and the review queue. A rule set and a suggestion are the package's JSON model (Obj, list arrays, strings); `path_re` is a
 * JavaScript regular expression (see {@see JsRe}).
 */
final class ActionsImportSuggest
{
    public const SUGGEST_RULES_KIND = 'pca-suggest-rules';
    public const SUGGEST_RULES_DOMAIN = 'atlas-pca/suggest-rules/v1';
    /** The version of the shipped rule set ({@see defaultRules}). */
    public const DEFAULT_RULES_VERSION = '1.1.0';
    public const MAX_RULES = 1024;
    public const MAX_LIST = 64;
    private const MATCH_KEYS = ['methods', 'path_re', 'name_tokens', 'name_tokens_strict', 'param_names', 'param_names_all', 'param_types', 'param_formats', 'roles', 'effects'];
    private const PARAM_TYPES = ['string', 'integer', 'boolean', 'date', 'datetime', 'duration', 'set', 'array', 'object_ref'];
    private const INT_ROLES = ['money.amount', 'money.fee', 'count.limit', 'bytes.size'];
    // a group that holds a quantifier or an alternation, followed by another quantifier: the shapes that backtrack exponentially
    private const NESTED_QUANTIFIER = '/\([^)]*[+*][^)]*\)[+*{]|\([^)]*\|[^)]*\)[+*{]/';

    private static ?Obj $defaultRules = null;

    // ---- rule set validation, seal, signature ---------------------------------------------------------------------------

    private static function isOne(mixed $v): bool
    {
        return $v instanceof Num && Js::num($v) === 1.0;
    }

    private static function isStrList(mixed $v, int $mx = self::MAX_LIST): bool
    {
        if (!is_array($v) || !array_is_list($v) || $v === [] || count($v) > $mx) {
            return false;
        }
        foreach ($v as $x) {
            if (!is_string($x) || Js::len($x) === 0 || Js::len($x) > 64) {
                return false;
            }
        }
        return true;
    }

    /** Null if the rule set is well formed: closed members, unique ids, safe regular expressions, known trait/role/tag names. @param list<string>|null $known */
    public static function suggestRulesError(mixed $r, ?array $known = null): ?string
    {
        if (!($r instanceof Obj)) {
            return 'rules must be an object';
        }
        foreach ($r->keys() as $k) {
            if (!in_array($k, ['v', 'kind', 'version', 'rules', 'digest', 'sig'], true)) {
                return "unknown member '$k'";
            }
        }
        if (!self::isOne($r->get('v')) || $r->get('kind') !== self::SUGGEST_RULES_KIND) {
            return 'not a suggest-rules document (v 1)';
        }
        if (!is_string($r->get('version')) || preg_match('/\A[0-9]+\.[0-9]+\.[0-9]+\z/', $r->get('version')) !== 1) {
            return 'version must be semver';
        }
        $rules = $r->get('rules');
        if (!is_array($rules) || !array_is_list($rules) || $rules === [] || count($rules) > self::MAX_RULES) {
            return 'rules must be 1..' . self::MAX_RULES . ' entries';
        }
        $ids = [];
        foreach ($rules as $rule) {
            if (!($rule instanceof Obj)) {
                return 'a rule must be an object';
            }
            foreach ($rule->keys() as $k) {
                if (!in_array($k, ['id', 'match', 'adds', 'note'], true)) {
                    return "rule: unknown member '$k'";
                }
            }
            $rid = $rule->get('id');
            if (!is_string($rid) || preg_match('/\ASR-[0-9]{3,4}\z/', $rid) !== 1 || isset($ids[$rid])) {
                return 'rule ids must be unique SR-nnn';
            }
            $ids[$rid] = true;
            $w = $rid;
            $note = $rule->get('note');
            if (!is_string($note) || Js::len($note) === 0 || Js::len($note) > 200) {
                return "$w: note must be 1..200 characters";
            }
            $m = $rule->get('match');
            if (!($m instanceof Obj) || $m->keys() === []) {
                return "$w: match must be a non-empty object";
            }
            foreach ($m->keys() as $k) {
                if (!in_array($k, self::MATCH_KEYS, true)) {
                    return "$w: unknown match member '$k'";
                }
            }
            foreach (['methods', 'name_tokens', 'name_tokens_strict', 'param_names', 'param_names_all', 'param_formats', 'roles'] as $k) {
                if ($m->has($k) && !self::isStrList($m->get($k))) {
                    return "$w: match.$k must be 1..64 short strings";
                }
            }
            if ($m->has('methods')) {
                foreach ($m->get('methods') as $s) {
                    if (mb_strtoupper($s) !== $s) {
                        return "$w: methods are uppercase";
                    }
                }
            }
            if ($m->has('param_types')) {
                $ok = self::isStrList($m->get('param_types'));
                foreach ($ok ? $m->get('param_types') : [] as $t) {
                    $ok = $ok && in_array($t, self::PARAM_TYPES, true);
                }
                if (!$ok) {
                    return "$w: match.param_types is not a list of param types";
                }
            }
            if ($m->has('effects') && !self::isStrList($m->get('effects'), 12)) {
                return "$w: match.effects must be a list of effects";
            }
            if ($m->has('path_re')) {
                $p = $m->get('path_re');
                if (!is_string($p) || Js::len($p) === 0 || Js::len($p) > 128) {
                    return "$w: path_re must be 1..128 characters";
                }
                if (preg_match(self::NESTED_QUANTIFIER, $p) === 1 || preg_match('/\\\\[1-9]/', $p) === 1 || preg_match('/\(\?[<=!]/', $p) === 1) {
                    return "$w: path_re uses a construct outside the bounded subset (nested quantifiers, backreferences, lookaround)";
                }
                try {
                    JsRe::compile($p);
                } catch (\ValueError) {
                    return "$w: path_re is not a regular expression";
                }
            }
            $hasParam = $m->has('param_names') || $m->has('param_names_all') || $m->has('param_formats') || $m->has('roles');
            if ($m->has('param_types') && !$m->has('param_names') && !$m->has('param_formats') && !$m->has('param_names_all')) {
                return "$w: param_types needs param_names, param_names_all or param_formats";
            }
            if (!self::isStrList($rule->get('adds'), 16)) {
                return "$w: adds must be 1..16 entries";
            }
            foreach ($rule->get('adds') as $a) {
                if (str_starts_with($a, 'tag:')) {
                    if (!in_array(substr($a, 4), Actions::PARAM_TAGS, true)) {
                        return "$w: unknown tag '$a'";
                    }
                    if (!$hasParam) {
                        return "$w: a tag needs a param matcher";
                    }
                } elseif (Actions::isRole($a)) {
                    if (!$hasParam) {
                        return "$w: a role needs a param matcher";
                    }
                } elseif (preg_match(Actions::TRAIT_ID_RE, $a) === 1) {
                    if ($known !== null && !in_array($a, $known, true)) {
                        return "$w: unknown trait '$a'";
                    }
                } else {
                    return "$w: '$a' is not a trait, role or tag:";
                }
            }
        }
        return null;
    }

    /** b64u sha256 of the strict canonical rule set (without digest and sig). */
    public static function rulesDigest(Obj $r): string
    {
        return Pca::hashCanonical(Obj::of(['d' => self::SUGGEST_RULES_DOMAIN, 'rules' => Obj::of(
            ['v' => $r->get('v'), 'kind' => $r->get('kind'), 'version' => $r->get('version'), 'rules' => $r->get('rules')])]));
    }

    public static function sealRules(Obj $r): Obj
    {
        $out = $r->without();
        $out->set('digest', self::rulesDigest($r));
        return $out;
    }

    private static function rulesMessage(string $digest): string
    {
        return self::SUGGEST_RULES_DOMAIN . "\0" . Json::canonicalizeNative(Obj::of(['digest' => $digest]));
    }

    /** Sign a rule set as the rules publisher (a release step; the signature covers the digest). $secret is a 32-byte Ed25519 seed. */
    public static function signRules(Obj $r, string $kid, string $secret): Obj
    {
        $bad = self::suggestRulesError($r);
        if ($bad !== null) {
            throw new ActionKitError('bad_rules', $bad);
        }
        $sealed = self::sealRules($r);
        $sealed->set('sig', Obj::of(['alg' => 'ed25519', 'kid' => $kid, 'value' => Pca::b64u((new KeyPair($secret))->sign(self::rulesMessage($sealed->get('digest'))))]));
        return $sealed;
    }

    /** Verify a signed rule set against pinned publisher keys ({kid, pk}): shape, digest, signature. Never throws. @return Obj {ok, reason?} */
    public static function verifyRules(mixed $doc, mixed $pins): Obj
    {
        try {
            $bad = self::suggestRulesError($doc);
            if ($bad !== null) {
                return Obj::of(['ok' => false, 'reason' => $bad]);
            }
            if ($doc->get('digest') !== self::rulesDigest($doc)) {
                return Obj::of(['ok' => false, 'reason' => 'digest does not match the rules']);
            }
            $sig = $doc->get('sig');
            if (!Js::truthy($sig)) {
                return Obj::of(['ok' => false, 'reason' => 'the rule set is not signed']);
            }
            $kid = $sig instanceof Obj && $sig->has('kid') ? $sig->get('kid') : null;
            $k = null;
            foreach (is_array($pins) ? $pins : [] as $p) {
                if ($p instanceof Obj && $kid !== null && $p->get('kid') === $kid) {
                    $k = $p;
                    break;
                }
            }
            if ($k === null) {
                $shown = $sig instanceof Obj && $sig->has('kid') ? Js::str($kid) : 'undefined';
                return Obj::of(['ok' => false, 'reason' => "no pinned rules key '$shown'"]);
            }
            $pk = $k->get('pk');
            $value = $sig instanceof Obj ? $sig->get('value') : null;
            return is_string($pk) && Pca::verifyEd25519B64u($pk, self::rulesMessage($doc->get('digest')), $value)
                ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'reason' => 'rules signature invalid']);
        } catch (\Throwable $e) {
            return Obj::of(['ok' => false, 'reason' => 'rules verification error: ' . $e->getMessage()]);
        }
    }

    // ---- the shipped rule set -------------------------------------------------------------------------------------------

    /** The shipped suggestion rules (unsealed). */
    public static function defaultRules(): Obj
    {
        return self::$defaultRules ??= Json::parseLax(ActionsImportRulesData::JSON);
    }

    /** The shipped rules with their digest. */
    public static function defaultRulesSealed(): Obj
    {
        return self::sealRules(self::defaultRules());
    }

    // ---- facts ----------------------------------------------------------------------------------------------------------

    /** Light stemmer: plural, -ing, -ed and a trailing -e fold together (`charges`, `charged`, `charging` -> `charg`). */
    public static function stem(string $t): string
    {
        $s = $t;
        $n = Js::len($s);
        if ($n > 4 && str_ends_with($s, 'ies')) {
            $s = substr($s, 0, -3) . 'y';
        } elseif (preg_match('/(?:ss|x|z|ch|sh)es\z/', $s) === 1 && $n > 4) {
            $s = substr($s, 0, -2);
        } elseif ($n > 3 && str_ends_with($s, 's') && !str_ends_with($s, 'ss')) {
            $s = substr($s, 0, -1);
        }
        $n = Js::len($s);
        if ($n > 5 && str_ends_with($s, 'ing')) {
            $s = substr($s, 0, -3);
        } elseif ($n > 4 && str_ends_with($s, 'ed')) {
            $s = substr($s, 0, -2);
        }
        if (Js::len($s) > 3 && str_ends_with($s, 'e')) {
            $s = substr($s, 0, -1);
        }
        return $s;
    }

    /** @return list<string> */
    private static function pathTokens(string $p): array
    {
        $out = [];
        foreach (explode('/', $p) as $s) {
            if ($s !== '' && !str_contains($s, '{') && !str_contains($s, '}')) {
                array_push($out, ...ActionsImport::tokensOf($s));
            }
        }
        return $out;
    }

    private static function u16Slice(string $s, int $n): string
    {
        if (Js::len($s) <= $n) {
            return $s;
        }
        return GoalJs::fromUnits(array_slice(SafeRegex::units($s), 0, $n));
    }

    /**
     * What the rules match on: {methods, locs, tokens, strict, params: [{name, tokens, type, format?, role?}], effects} of an ActionDef.
     *
     * @return array<string,mixed>
     */
    public static function factsOf(Obj $d): array
    {
        $b = $d->get('bindings');
        $b = $b instanceof Obj ? $b : new Obj();
        $methods = [];
        $addMethod = static function (string $m) use (&$methods): void {
            $u = mb_strtoupper($m);
            if (!in_array($u, $methods, true)) {
                $methods[] = $u;
            }
        };
        $locs = [];
        $src = [];
        $pathSrc = [];
        $t = [];
        foreach (array_slice(explode('.', $d->get('verb')), 1) as $s) {
            array_push($t, ...ActionsImport::tokensOf($s));
        }
        $src[] = $t;
        foreach (is_array($d->get('aliases')) ? $d->get('aliases') : [] as $a) {
            $src[] = ActionsImport::tokensOf($a);
        }
        $src[] = ActionsImport::tokensOf($d->get('title'));
        if (Js::truthy($b->get('openapi'))) {
            $o = $b->get('openapi');
            $src[] = ActionsImport::tokensOf($o->get('operationId'));
            if (Js::truthy($o->get('method'))) {
                $addMethod($o->get('method'));
            }
            if (Js::truthy($o->get('path'))) {
                $locs[] = $o->get('path');
                $pathSrc[count($src)] = true;
                $src[] = self::pathTokens($o->get('path'));
            }
        }
        if (Js::truthy($b->get('http'))) {
            $h = $b->get('http');
            $addMethod($h->get('method'));
            $locs[] = $h->get('path');
            $pathSrc[count($src)] = true;
            $src[] = self::pathTokens($h->get('path'));
        }
        if (Js::truthy($b->get('mcp'))) {
            $locs[] = $b->get('mcp')->get('tool');
            $src[] = ActionsImport::tokensOf($b->get('mcp')->get('tool'));
        }
        if (Js::truthy($b->get('graphql'))) {
            $g = $b->get('graphql');
            $addMethod($g->get('op'));
            $locs[] = $g->get('field');
            $src[] = ActionsImport::tokensOf($g->get('field'));
        }
        if (Js::truthy($b->get('grpc'))) {
            $g = $b->get('grpc');
            $locs[] = $g->get('service') . '/' . $g->get('method');
            $src[] = ActionsImport::tokensOf($g->get('service'));
            $src[] = ActionsImport::tokensOf($g->get('method'));
        }
        if (Js::truthy($b->get('asyncapi'))) {
            $a = $b->get('asyncapi');
            $addMethod($a->get('op'));
            $locs[] = $a->get('channel');
            $src[] = ActionsImport::tokensOf($a->get('channel'));
        }
        $tokens = [];
        $strict = [];
        foreach ($src as $i => $s) {
            if ($tokens !== []) {
                $tokens[] = '|';
            }
            array_push($tokens, ...array_map([self::class, 'stem'], $s));
            if (!isset($pathSrc[$i])) {
                if ($strict !== []) {
                    $strict[] = '|';
                }
                array_push($strict, ...array_map([self::class, 'stem'], $s));
            }
        }
        $params = [];
        $names = $d->get('params')->keys();
        usort($names, [Actions::class, 'u16Order']);
        foreach ($names as $name) {
            $p = $d->get('params')->get($name);
            $e = ['name' => $name, 'tokens' => array_map([self::class, 'stem'], ActionsImport::tokensOf($name)), 'type' => $p->get('type')];
            if (Js::truthy($p->get('format'))) {
                $e['format'] = $p->get('format');
            }
            if (Js::truthy($p->get('role'))) {
                $e['role'] = $p->get('role');
            }
            $params[] = $e;
        }
        return ['methods' => $methods, 'locs' => array_map(fn($l) => self::u16Slice($l, 512), $locs), 'tokens' => $tokens, 'strict' => $strict, 'params' => $params,
            'effects' => array_values(array_unique($d->get('effects')))];
    }

    /** @param list<string> $hay @param list<string> $pat */
    private static function hasSeq(array $hay, array $pat): bool
    {
        $n = count($pat);
        if ($n === 0) {
            return false;
        }
        for ($i = 0; $i + $n <= count($hay); $i++) {
            if (array_slice($hay, $i, $n) === $pat) {
                return true;
            }
        }
        return false;
    }

    /** @return list<string> */
    private static function patOf(string $s): array
    {
        return array_map([self::class, 'stem'], ActionsImport::tokensOf($s));
    }

    /** A suggestion with nothing in it: {traits: [], roles: {}, tags: {}, fired: []}. */
    public static function emptySuggestion(): Obj
    {
        return Obj::of(['traits' => [], 'roles' => new Obj(), 'tags' => new Obj(), 'fired' => []]);
    }

    private static function roleFits(mixed $role, mixed $typ): bool
    {
        if (!is_string($role)) {
            return false;
        }
        if (in_array($role, self::INT_ROLES, true)) {
            return $typ === 'integer';
        }
        if (str_starts_with($role, 'time.')) {
            return in_array($typ, ['date', 'datetime', 'integer'], true);
        }
        return $typ === 'string';
    }

    private static function isTraitAdd(string $a): bool
    {
        return !str_starts_with($a, 'tag:') && !Actions::isRole($a);
    }

    /** @param list<string> $xs @return list<string> */
    private static function sorted(array $xs): array
    {
        $xs = array_values(array_unique($xs));
        usort($xs, [Actions::class, 'u16Order']);
        return $xs;
    }

    /** @param list<string> $xs @param list<string> $in */
    private static function anyIn(array $xs, array $in): bool
    {
        foreach ($xs as $x) {
            if (in_array($x, $in, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Run the rules over a def. Only trait ids in `$registry` (when given: a map keyed by trait id) can be suggested. Pure and deterministic.
     *
     * @param array<string,mixed>|null $registry
     */
    public static function suggestWithRules(Obj $d, Obj $rules, ?array $registry = null): Obj
    {
        $f = self::factsOf($d);
        $traits = [];
        $roles = new Obj();
        $tags = new Obj();
        $fired = [];
        $stems = $f['tokens'];
        foreach ($rules->get('rules') as $rule) {
            $m = $rule->get('match');
            if (Js::truthy($m->get('methods')) && !self::anyIn($m->get('methods'), $f['methods'])) {
                continue;
            }
            if (Js::truthy($m->get('effects')) && !self::anyIn($m->get('effects'), $f['effects'])) {
                continue;
            }
            if (Js::truthy($m->get('name_tokens'))) {
                $hit = false;
                foreach ($m->get('name_tokens') as $p) {
                    $hit = $hit || self::hasSeq($stems, self::patOf($p));
                }
                if (!$hit) {
                    continue;
                }
            }
            if (Js::truthy($m->get('name_tokens_strict'))) {
                $hit = false;
                foreach ($m->get('name_tokens_strict') as $p) {
                    $hit = $hit || self::hasSeq($f['strict'], self::patOf($p));
                }
                if (!$hit) {
                    continue;
                }
            }
            if (Js::truthy($m->get('path_re'))) {
                $rx = JsRe::compile($m->get('path_re'));
                $hit = false;
                foreach ($f['locs'] as $loc) {
                    $hit = $hit || JsRe::test($rx, $loc);
                }
                if (!$hit) {
                    continue;
                }
            }
            if (Js::truthy($m->get('roles'))) {
                $hit = false;
                foreach ($f['params'] as $p) {
                    $hit = $hit || (array_key_exists('role', $p) && in_array($p['role'], $m->get('roles'), true));
                }
                if (!$hit) {
                    continue;
                }
            }
            $matched = [];
            if ($m->get('param_names') !== null || $m->get('param_formats') !== null) {
                $pats = array_map([self::class, 'patOf'], is_array($m->get('param_names')) ? $m->get('param_names') : []);
                foreach ($f['params'] as $p) {
                    if (Js::truthy($m->get('param_types')) && !in_array($p['type'], $m->get('param_types'), true)) {
                        continue;
                    }
                    if (Js::truthy($m->get('param_names'))) {
                        $hit = false;
                        foreach ($pats as $q) {
                            $hit = $hit || self::hasSeq($p['tokens'], $q);
                        }
                        if (!$hit) {
                            continue;
                        }
                    }
                    if (Js::truthy($m->get('param_formats')) && (!array_key_exists('format', $p) || !in_array($p['format'], $m->get('param_formats'), true))) {
                        continue;
                    }
                    $matched[] = $p;
                }
                if ($matched === []) {
                    continue;
                }
            }
            if (Js::truthy($m->get('param_names_all'))) {
                $ok = true;
                foreach ($m->get('param_names_all') as $n) {
                    $q = self::patOf($n);
                    $any = false;
                    foreach ($f['params'] as $p) {
                        $any = $any || (self::hasSeq($p['tokens'], $q)
                            && (!Js::truthy($m->get('param_types')) || in_array($p['type'], $m->get('param_types'), true) || $p['type'] === 'string'));
                    }
                    if (!$any) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok) {
                    continue;
                }
            }
            $fired[] = $rule->get('id');
            foreach ($rule->get('adds') as $a) {
                if (str_starts_with($a, 'tag:')) {
                    foreach ($matched as $p) {
                        $cur = $tags->get($p['name']) ?? [];
                        if (!in_array(substr($a, 4), $cur, true)) {
                            $cur[] = substr($a, 4);
                        }
                        $tags->set($p['name'], $cur);
                    }
                } elseif (self::isTraitAdd($a)) {
                    if ($registry === null || array_key_exists($a, $registry)) {
                        $traits[$a] = true;
                    }
                } else {
                    foreach ($matched as $p) {
                        if (!array_key_exists('role', $p) && !$roles->has($p['name']) && self::roleFits($a, $p['type'])) {
                            $roles->set($p['name'], $a);
                        }
                    }
                }
            }
        }
        unset($traits['pca.unreviewed']);
        $tagKeys = $tags->keys();
        usort($tagKeys, [Actions::class, 'u16Order']);
        $outTags = new Obj();
        foreach ($tagKeys as $k) {
            $outTags->set($k, self::sorted($tags->get($k)));
        }
        return Obj::of(['traits' => self::sorted(array_map('strval', array_keys($traits))), 'roles' => $roles, 'tags' => $outTags, 'fired' => $fired]);
    }

    /** Union two suggestions (the restrictive direction, so no intersection is needed). */
    public static function unionSuggestions(Obj $a, Obj $b): Obj
    {
        $roles = $b->get('roles')->without();
        foreach ($a->get('roles')->keys() as $k) {
            $roles->set($k, $a->get('roles')->get($k));
        }
        $tags = new Obj();
        foreach (array_values(array_unique(array_merge($a->get('tags')->keys(), $b->get('tags')->keys()))) as $k) {
            $tags->set((string)$k, self::sorted(array_merge($a->get('tags')->get((string)$k) ?? [], $b->get('tags')->get((string)$k) ?? [])));
        }
        return Obj::of(['traits' => self::sorted(array_merge($a->get('traits'), $b->get('traits'))), 'roles' => $roles, 'tags' => $tags,
            'fired' => array_merge($a->get('fired'), $b->get('fired'))]);
    }

    /**
     * Apply a suggestion to a def. UNION ONLY: traits are added, a role is set only on a param without one, tags are added; nothing is removed or replaced, no
     * attestation is created, and `review.state` goes from `unreviewed` to `suggested` (a `suggested` def stays `suggested`; an `authored` or `confirmed` def
     * keeps its state, its digest simply changes). `$by`: {rules?: {version, digest, fired}, models?: [...]}.
     */
    public static function applySuggestion(Obj $d, Obj $s, Obj $by): Obj
    {
        $params = new Obj();
        $addedRoles = new Obj();
        $addedTags = new Obj();
        foreach ($d->get('params')->keys() as $name) {
            $p = $d->get('params')->get($name);
            $q = $p;
            $role = $s->get('roles')->get($name);
            if ($role !== null && !$p->has('role') && self::roleFits($role, $p->get('type'))) {
                $q = $q->without();
                $q->set('role', $role);
                $addedRoles->set($name, $role);
            }
            $t = $s->get('tags')->get($name);
            if ($t !== null) {
                $have = is_array($p->get('tags')) ? $p->get('tags') : [];
                $fresh = array_values(array_filter($t, static fn($x) => !in_array($x, $have, true)));
                if ($fresh !== []) {
                    $q = $q->without();
                    $q->set('tags', self::sorted(array_merge($have, $fresh)));
                    $addedTags->set($name, $fresh);
                }
            }
            $params->set($name, $q);
        }
        $dTraits = is_array($d->get('traits')) ? $d->get('traits') : [];
        $freshTraits = array_values(array_filter($s->get('traits'), static fn($t) => !in_array($t, $dTraits, true)));
        // a money-moving action must be safe to repeat (lint LD-004): add the optional idempotency key the pack generator adds
        $idem = $d->get('idempotency');
        if (in_array('pca.money_moving', $s->get('traits'), true) && ($idem === null || ($idem instanceof Obj && $idem->get('mode') === 'none'))) {
            $idem = Obj::of(['mode' => 'key_param', 'param' => 'idempotency_key']);
            if (!$params->has('idempotency_key')) {
                $params->set('idempotency_key', Obj::of(['type' => 'string', 'max_len' => new Num('64'), 'required' => false]));
            }
        }
        $review = $d->get('review');
        $prev = $review->get('suggested_by') ?? new Obj();
        $prevAdded = $prev->get('added') ?? Obj::of(['traits' => [], 'roles' => new Obj(), 'tags' => new Obj()]);
        $roles = $prevAdded->get('roles')->without();
        foreach ($addedRoles->keys() as $k) {
            $roles->set($k, $addedRoles->get($k));
        }
        $tagKeys = self::sorted(array_map('strval', array_merge($prevAdded->get('tags')->keys(), $addedTags->keys())));
        $tags = new Obj();
        foreach ($tagKeys as $k) {
            $tags->set($k, self::sorted(array_merge($prevAdded->get('tags')->get($k) ?? [], $addedTags->get($k) ?? [])));
        }
        $added = Obj::of(['traits' => self::sorted(array_merge($prevAdded->get('traits'), $freshTraits)), 'roles' => $roles, 'tags' => $tags]);
        $rules = $by->get('rules') ?? $prev->get('rules');
        $models = array_merge(is_array($prev->get('models')) ? $prev->get('models') : [], is_array($by->get('models')) ? $by->get('models') : []);
        $sb = new Obj();
        if (Js::truthy($rules)) {
            $sb->set('rules', $rules);
        }
        if ($models !== []) {
            $sb->set('models', $models);
        }
        $sb->set('added', $added);
        $state = in_array($review->get('state'), ['unreviewed', 'suggested'], true) ? 'suggested' : $review->get('state');
        $out = $d->without();
        $out->set('params', $params);
        if ($idem !== null) {
            $out->set('idempotency', $idem);
        }
        if ($freshTraits !== [] || $dTraits !== []) {
            $out->set('traits', self::sorted(array_merge($dTraits, $s->get('traits'))));
        }
        $rv = $review->without();
        $rv->set('state', $state);
        $rv->set('suggested_by', $sb);
        $out->set('review', $rv);
        return $out;
    }
}
