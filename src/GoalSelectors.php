<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalCard.php';
require_once __DIR__ . '/GoalOntologies.php';

/**
 * Trait selectors and role-addressed parameters for the Goal IR. A selector goal ("SelGoal") names a verb or a trait class in its
 * grants, prohibitions and bounds, and may name a parameter by ROLE; it is lowered against the PINNED catalog to an ordinary goal
 * (one grant per verb). Fail-closed rules: a grant verb with no unique parameter of a named role is dropped from the grant
 * (reported); a prohibition whose role term is unresolved for a verb applies to that verb unconditionally; a bound whose role value
 * cannot be resolved for every selected verb is a type error; an allow selector is positive (no `none_of`, at least one trait); an
 * unconfirmed verb carries `pca.unreviewed`: a class ALLOW never covers it, a class prohibition or bound over a trait selector
 * ALWAYS covers it; an unknown trait id is a type error.
 */
final class GoalSelectors
{
    public const UNREVIEWED = 'pca.unreviewed';
    public const SEL_ID_RE = '/\A[0-9A-Za-z_]{1,64}\z/';
    public const ROLE_MARK = "\x01role:";

    // ---- helpers ------------------------------------------------------------------------------------------------------

    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    /** `x.length` of an array or string; null for a value without one; null / undefined throws. */
    private static function len(mixed $x): ?int
    {
        if ($x === null || $x instanceof Undef) {
            throw new \TypeError('cannot read properties of null or undefined (reading length)');
        }
        if (is_array($x) && array_is_list($x)) {
            return count($x);
        }
        return is_string($x) ? Js::len($x) : null;
    }

    private static function lenPos(mixed $x): bool
    {
        $n = self::len($x);
        return $n !== null && $n > 0;
    }

    /** JSON.stringify of a value, undefined as the text "undefined". */
    private static function jq(mixed $v): string
    {
        return $v instanceof Undef ? 'undefined' : AnalyzerJs::jsJson($v);
    }

    private static function s(mixed $v): string
    {
        return AnalyzerJs::jsStr($v);
    }

    private static function cmpStr(mixed $a, mixed $b): int
    {
        return AnalyzerJs::u16cmp(self::s($a), self::s($b));
    }

    /** @return list<string> */
    private static function sortedKeys(array $reg): array
    {
        $k = array_map('strval', array_keys($reg));
        usort($k, static fn($a, $b) => AnalyzerJs::u16cmp($a, $b));
        return $k;
    }

    // ---- catalogs -----------------------------------------------------------------------------------------------------

    /**
     * The catalog of a pack of defs (verb ids and parameter paths are the defs' own): {known, verbs}.
     *
     * @param list<Obj> $defs
     * @param array<string,array>|null $reg
     */
    public static function selCatalogOfDefs(array $defs, ?array $reg = null, ?Obj $review = null): Obj
    {
        $reg ??= Actions::coreRegistry();
        $verbs = [];
        foreach ($defs as $d) {
            $params = self::g($d, 'params');
            $names = GoalJs::okeys($params);
            usort($names, static fn($a, $b) => AnalyzerJs::u16cmp($a, $b));
            $roles = new Obj();
            foreach ($names as $name) {
                $p = GoalJs::kget($params, $name);
                $r = self::g($p, 'role');
                if (!($r instanceof Undef)) {
                    $key = Js::str($r);
                    $roles->set($key, array_merge($roles->has($key) ? $roles->get($key) : [], [$name]));
                }
            }
            $verbs[] = Obj::of(['verb' => self::g($d, 'verb'), 'traits' => Actions::effective($d, $reg, $review)['closure'], 'roles' => $roles]);
        }
        $verbs = GoalJs::stableSort($verbs, static fn($a, $b) => self::cmpStr($a->get('verb'), $b->get('verb')));
        return Obj::of(['known' => self::sortedKeys($reg), 'verbs' => $verbs]);
    }

    /**
     * The catalog of one shipped domain ontology (the NL short ids and NL parameter names, with the traits of the defs behind them):
     * shipped as data; only the core registry with no review is derived.
     */
    public static function selCatalogOfDomain(string $domain, ?array $reg = null, ?Obj $review = null): Obj
    {
        if ($reg !== null || $review !== null) {
            throw new \LogicException('only the shipped trait registry is derived natively');
        }
        return GoalOntologies::shippedCatalog($domain) ?? throw new \TypeError('unknown domain ' . Js::stringify($domain));
    }

    /** Digest of the catalog (what `SelGoal.catDigest` must equal). */
    public static function selCatalogDigest(mixed $c): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-sel-catalog/v1', 'catalog' => $c]));
    }

    public static function selGoalDigest(mixed $g): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-ir-sel/v1', 'goal' => $g]));
    }

    // ---- G-A4: the verbs of a Class selector --------------------------------------------------------------------------

    private static function hasAll(mixed $ts, mixed $req): bool
    {
        foreach (AnalyzerJs::reqList($req) as $t) {
            if (!AnalyzerJs::includes($ts, $t)) {
                return false;
            }
        }
        return true;
    }

    private static function hasNone(mixed $ts, mixed $ex): bool
    {
        foreach (AnalyzerJs::reqList($ex) as $t) {
            if (AnalyzerJs::includes($ts, $t)) {
                return false;
            }
        }
        return true;
    }

    /** The verbs of the catalog, in catalog order, whose trait closure contains every `all_of` trait and none of the `none_of` traits. @return list<mixed> */
    public static function classVerbs(mixed $cat, mixed $allOf, mixed $noneOf): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList(self::g($cat, 'verbs')) as $v) {
            if (self::hasAll(self::g($v, 'traits'), $allOf) && self::hasNone(self::g($v, 'traits'), $noneOf)) {
                $out[] = self::g($v, 'verb');
            }
        }
        return $out;
    }

    /** The verbs a class ALLOW covers: the class, minus every unconfirmed verb. @return list<mixed> */
    public static function allowClassVerbs(mixed $cat, mixed $allOf, mixed $noneOf): array
    {
        return self::classVerbs($cat, $allOf, array_merge(AnalyzerJs::reqList($noneOf), [self::UNREVIEWED]));
    }

    /** The verbs a class PROHIBITION or bound covers: the class, plus every unconfirmed verb whatever the selector says. @return list<mixed> */
    public static function floatClassVerbs(mixed $cat, mixed $allOf, mixed $noneOf): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList(self::g($cat, 'verbs')) as $v) {
            if (AnalyzerJs::includes(self::g($v, 'traits'), self::UNREVIEWED) || (self::hasAll(self::g($v, 'traits'), $allOf) && self::hasNone(self::g($v, 'traits'), $noneOf))) {
                $out[] = self::g($v, 'verb');
            }
        }
        return $out;
    }

    // ---- role resolution ----------------------------------------------------------------------------------------------

    private static function find(mixed $xs, string $k, mixed $want): mixed
    {
        foreach (AnalyzerJs::reqList($xs) as $x) {
            if (AnalyzerJs::strictEq(self::g($x, $k), $want)) {
                return $x;
            }
        }
        return null;
    }

    public static function declOf(mixed $ont, mixed $verb): mixed
    {
        return self::find(self::g($ont, 'verbs'), 'verb', $verb);
    }

    public static function infoOf(mixed $cat, mixed $verb): mixed
    {
        return self::find(self::g($cat, 'verbs'), 'verb', $verb);
    }

    /** The one parameter of `verb` carrying `role`, with its declared type; none, several or undeclared: null. */
    public static function resolveRole(mixed $ont, mixed $cat, mixed $verb, mixed $role): ?Obj
    {
        $info = self::infoOf($cat, $verb);
        $decl = self::declOf($ont, $verb);
        if ($info === null || $decl === null) {
            return null;
        }
        $roles = self::g($info, 'roles');
        $paths = $roles instanceof Obj && is_string($role) && $roles->has($role) ? $roles->get($role) : [];
        if (self::len($paths) !== 1) {
            return null;
        }
        $p = self::find(self::g($decl, 'params'), 'path', self::g($paths, '0'));
        return $p === null ? null : AnalyzerJs::uobj(['path' => self::g($p, 'path'), 'ty' => self::g($p, 'ty')]);
    }

    /** The member `k` when it is a string (a switch on anything else would compare loosely). */
    private static function kk(mixed $o): ?string
    {
        $k = self::g($o, 'k');
        return is_string($k) ? $k : null;
    }

    private static function resolveTerm(mixed $ont, mixed $cat, mixed $verb, mixed $t): ?Obj
    {
        switch (self::kk($t)) {
            case 'param':
                return AnalyzerJs::uobj(['k' => 'param', 'path' => self::g($t, 'path'), 'ty' => self::g($t, 'ty')]);
            case 'lit':
                return AnalyzerJs::uobj(['k' => 'lit', 'v' => self::g($t, 'v')]);
            case 'hist':
                return AnalyzerJs::uobj(['k' => 'hist', 'bid' => self::g($t, 'bid'), 'u' => self::g($t, 'u')]);
            case 'role':
                $r = self::resolveRole($ont, $cat, $verb, self::g($t, 'role'));
                return $r === null ? null : AnalyzerJs::uobj(['k' => 'param', 'path' => $r->get('path'), 'ty' => $r->has('ty') ? $r->get('ty') : AnalyzerJs::undef()]);
        }
        return null;
    }

    /** null as soon as one role term is unresolved for the verb. */
    private static function resolveCond(mixed $ont, mixed $cat, mixed $verb, mixed $c): ?Obj
    {
        $k = self::g($c, 'k');
        if ($k === 'true') {
            return Obj::of(['k' => 'true']);
        }
        if ($k === 'cmp') {
            $l = self::resolveTerm($ont, $cat, $verb, self::g($c, 'l'));
            $r = self::resolveTerm($ont, $cat, $verb, self::g($c, 'r'));
            return $l !== null && $r !== null ? AnalyzerJs::uobj(['k' => 'cmp', 'op' => self::g($c, 'op'), 'l' => $l, 'r' => $r]) : null;
        }
        if ($k === 'and' || $k === 'or') {
            $a = self::resolveCond($ont, $cat, $verb, self::g($c, 'a'));
            $b = self::resolveCond($ont, $cat, $verb, self::g($c, 'b'));
            return $a !== null && $b !== null ? Obj::of(['k' => $k, 'a' => $a, 'b' => $b]) : null;
        }
        if ($k === 'not') {
            $a = self::resolveCond($ont, $cat, $verb, self::g($c, 'c'));
            return $a !== null ? Obj::of(['k' => 'not', 'c' => $a]) : null;
        }
        return null;
    }

    // ---- the expansion ------------------------------------------------------------------------------------------------

    /** @return list<mixed> */
    private static function grantVerbs(mixed $cat, mixed $s): array
    {
        return self::g($s, 'k') === 'verb' ? [self::g($s, 'verb')] : self::allowClassVerbs($cat, self::g($s, 'all_of'), self::g($s, 'none_of'));
    }

    /**
     * @param array{grants:list<Obj>,prohibits:list<Obj>,bounds:list<Obj>} $report
     * @return list<array{src:mixed,g:Obj}>
     */
    private static function expandGrants(mixed $ont, mixed $cat, mixed $gs, array &$report): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList($gs) as $gr) {
            $sel = self::g($gr, 'sel');
            $verbs = self::grantVerbs($cat, $sel);
            $dropped = [];
            foreach ($verbs as $v) {
                $c = self::resolveCond($ont, $cat, $v, self::g($gr, 'cond'));
                if ($c === null) {
                    $dropped[] = Obj::of(['verb' => $v, 'reason' => 'role_unresolved']);
                    continue;
                }
                $out[] = ['src' => self::g($gr, 'gid'), 'g' => AnalyzerJs::uobj([
                    'gid' => self::g($sel, 'k') === 'class' ? self::s(self::g($gr, 'gid')) . '.' . self::s($v) : self::g($gr, 'gid'),
                    'verb' => $v, 'res' => self::g($gr, 'res'), 'cond' => $c,
                ])];
            }
            $report['grants'][] = AnalyzerJs::uobj(['gid' => self::g($gr, 'gid'), 'verbs' => $verbs, 'dropped' => $dropped]);
        }
        return $out;
    }

    /** @return list<mixed> */
    private static function prohVerbs(mixed $ont, mixed $cat, mixed $t): array
    {
        $k = self::g($t, 'k');
        if ($k === 'verb') {
            return [self::g($t, 'verb')];
        }
        if ($k === 'effect') {
            $out = [];
            foreach (AnalyzerJs::reqList(self::g($ont, 'verbs')) as $v) {
                if (AnalyzerJs::strictEq(self::g($v, 'cls'), self::g($t, 'cls'))) {
                    $out[] = self::g($v, 'verb');
                }
            }
            return $out;
        }
        return self::floatClassVerbs($cat, self::g($t, 'all_of'), self::g($t, 'none_of'));
    }

    /**
     * @param array{grants:list<Obj>,prohibits:list<Obj>,bounds:list<Obj>} $report
     * @return list<Obj>
     */
    private static function expandProhibits(mixed $ont, mixed $cat, mixed $ps, array &$report): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList($ps) as $p) {
            $target = self::g($p, 'target');
            $verbs = self::prohVerbs($ont, $cat, $target);
            $unconditional = [];
            foreach ($verbs as $v) {
                $c = self::resolveCond($ont, $cat, $v, self::g($p, 'cond'));
                if ($c === null) {
                    $unconditional[] = $v;
                }
                $out[] = AnalyzerJs::uobj([
                    'pid' => self::g($target, 'k') === 'verb' ? self::g($p, 'pid') : self::s(self::g($p, 'pid')) . '.' . self::s($v),
                    'target' => Obj::of(['k' => 'verb', 'verb' => $v]), 'res' => self::g($p, 'res'), 'cond' => $c ?? Obj::of(['k' => 'true']),
                ]);
            }
            $report['prohibits'][] = AnalyzerJs::uobj(['pid' => self::g($p, 'pid'), 'verbs' => $verbs, 'unconditional' => $unconditional]);
        }
        return $out;
    }

    /** @param list<array{src:mixed,g:Obj}> $es @return list<mixed> */
    private static function idsOf(array $es, mixed $srcs): array
    {
        $out = [];
        foreach ($es as $e) {
            if (AnalyzerJs::includes($srcs, $e['src'])) {
                $out[] = self::g($e['g'], 'gid');
            }
        }
        return $out;
    }

    /** @param list<array{src:mixed,g:Obj}> $es @param list<mixed> $vs @return list<mixed> */
    private static function gidsOfVerbs(array $es, array $vs): array
    {
        $out = [];
        foreach ($es as $e) {
            if (AnalyzerJs::includes($vs, self::g($e['g'], 'verb'))) {
                $out[] = self::g($e['g'], 'gid');
            }
        }
        return $out;
    }

    /** @param list<array{src:mixed,g:Obj}> $es @param list<mixed> $gids @return list<mixed> */
    private static function verbsOfGids(array $es, array $gids): array
    {
        $out = [];
        foreach ($es as $e) {
            if (AnalyzerJs::includes($gids, self::g($e['g'], 'gid'))) {
                $out[] = self::g($e['g'], 'verb');
            }
        }
        return $out;
    }

    /** @param list<array{src:mixed,g:Obj}> $es @return list<mixed> */
    private static function boundRoleVerbs(mixed $ont, mixed $cat, array $es, mixed $s): array
    {
        $k = self::g($s, 'k');
        if ($k === 'gids') {
            return self::verbsOfGids($es, self::idsOf($es, self::g($s, 'gids')));
        }
        if ($k === 'effect') {
            $out = [];
            foreach (AnalyzerJs::reqList(self::g($ont, 'verbs')) as $v) {
                if (AnalyzerJs::strictEq(self::g($v, 'cls'), self::g($s, 'cls'))) {
                    $out[] = self::g($v, 'verb');
                }
            }
            return $out;
        }
        return self::verbsOfGids($es, self::gidsOfVerbs($es, self::floatClassVerbs($cat, self::g($s, 'all_of'), self::g($s, 'none_of'))));
    }

    /**
     * One value term for the whole bound: the shared path when every verb agrees; the role key `@<role>` when the paths differ but the
     * type is one.
     *
     * @param list<mixed> $vs
     * @return array{term:Obj,how:string}|null
     */
    private static function boundValue(mixed $ont, mixed $cat, array $vs, mixed $t): ?array
    {
        switch (self::kk($t)) {
            case 'param':
                return ['term' => AnalyzerJs::uobj(['k' => 'param', 'path' => self::g($t, 'path'), 'ty' => self::g($t, 'ty')]), 'how' => 'literal'];
            case 'lit':
                return ['term' => AnalyzerJs::uobj(['k' => 'lit', 'v' => self::g($t, 'v')]), 'how' => 'literal'];
            case 'hist':
                return ['term' => AnalyzerJs::uobj(['k' => 'hist', 'bid' => self::g($t, 'bid'), 'u' => self::g($t, 'u')]), 'how' => 'literal'];
            case 'role':
                $rs = [];
                foreach ($vs as $v) {
                    $r = self::resolveRole($ont, $cat, $v, self::g($t, 'role'));
                    if ($r === null) {
                        return null;
                    }
                    $rs[] = $r;
                }
                if ($rs === []) {
                    return null;
                }
                $ty = static fn(Obj $r): mixed => $r->has('ty') ? $r->get('ty') : AnalyzerJs::undef();
                $same = static fn($a, $b): bool => self::jq($a) === self::jq($b);
                $allPath = true;
                $allTy = true;
                foreach ($rs as $r) {
                    $allTy = $allTy && $same($ty($r), $ty($rs[0]));
                    $allPath = $allPath && AnalyzerJs::strictEq($r->get('path'), $rs[0]->get('path')) && $same($ty($r), $ty($rs[0]));
                }
                if ($allPath) {
                    return ['term' => AnalyzerJs::uobj(['k' => 'param', 'path' => $rs[0]->get('path'), 'ty' => $ty($rs[0])]), 'how' => 'shared_path'];
                }
                if ($allTy) {
                    return ['term' => AnalyzerJs::uobj(['k' => 'param', 'path' => '@' . self::s(self::g($t, 'role')), 'ty' => $ty($rs[0])]), 'how' => 'role_key'];
                }
        }
        return null;
    }

    /**
     * @param list<array{src:mixed,g:Obj}> $es
     * @param array{grants:list<Obj>,prohibits:list<Obj>,bounds:list<Obj>} $report
     * @return list<Obj>
     */
    private static function expandBounds(mixed $ont, mixed $cat, array $es, mixed $bs, array &$report): array
    {
        $out = [];
        foreach (AnalyzerJs::reqList($bs) as $b) {
            $bsel = self::g($b, 'sel');
            $bv = self::boundValue($ont, $cat, self::boundRoleVerbs($ont, $cat, $es, $bsel), self::g($b, 'value'));
            if ($bv === null) {
                continue; // a type error (selReasons), never reached when the goal is well typed
            }
            $mk = static fn(Obj $sel): Obj => AnalyzerJs::uobj([
                'bid' => self::g($b, 'bid'), 'sel' => $sel, 'agg' => self::g($b, 'agg'), 'value' => $bv['term'], 'key' => self::g($b, 'key'),
                'window' => self::g($b, 'window'), 'scope' => self::g($b, 'scope'), 'cap' => self::g($b, 'cap'), 'onExceed' => self::g($b, 'onExceed'),
            ]);
            $k = self::g($bsel, 'k');
            $gids = null;
            if ($k === 'gids') {
                $gids = self::idsOf($es, self::g($bsel, 'gids'));
            } elseif ($k === 'trait') {
                $gids = self::gidsOfVerbs($es, self::floatClassVerbs($cat, self::g($bsel, 'all_of'), self::g($bsel, 'none_of')));
            }
            if ($k === 'effect') {
                $out[] = $mk(AnalyzerJs::uobj(['k' => 'effect', 'cls' => self::g($bsel, 'cls')]));
                $report['bounds'][] = AnalyzerJs::uobj(['bid' => self::g($b, 'bid'), 'gids' => [], 'dropped' => false, 'value' => $bv['how']]);
                continue;
            }
            if ($gids === null) {
                throw new \TypeError('cannot read properties of undefined (reading length)');
            }
            if ($gids === []) {
                $report['bounds'][] = AnalyzerJs::uobj(['bid' => self::g($b, 'bid'), 'gids' => [], 'dropped' => true, 'value' => $bv['how']]);
                continue;
            }
            $out[] = $mk(Obj::of(['k' => 'gids', 'gids' => $gids]));
            $report['bounds'][] = AnalyzerJs::uobj(['bid' => self::g($b, 'bid'), 'gids' => $gids, 'dropped' => false, 'value' => $bv['how']]);
        }
        return $out;
    }

    /** Lower a selector goal to an ordinary Goal against the PINNED catalog. Pure and total; typing is `selReasons` + the core typechecker. */
    public static function expandSelGoal(mixed $sg, mixed $ont, mixed $cat): Obj
    {
        $report = ['grants' => [], 'prohibits' => [], 'bounds' => []];
        $es = self::expandGrants($ont, $cat, self::g($sg, 'grants'), $report);
        $prohibits = self::expandProhibits($ont, $cat, self::g($sg, 'prohibits'), $report);
        $bounds = self::expandBounds($ont, $cat, $es, self::g($sg, 'bounds'), $report);
        $deleg = AnalyzerJs::spread(self::g($sg, 'deleg'));
        $deleg->set('mayTouch', self::idsOf($es, self::g(self::g($sg, 'deleg'), 'mayTouch')));
        $holes = [];
        foreach (AnalyzerJs::reqList(self::g($sg, 'holes')) as $h) {
            $hh = AnalyzerJs::spread($h);
            $hh->set('affects', self::idsOf($es, self::g($h, 'affects')));
            $holes[] = $hh;
        }
        $goal = AnalyzerJs::uobj([
            'v' => new Num('1'), 'principal' => self::g($sg, 'principal'), 'ontDigest' => self::g($sg, 'ontDigest'), 'nlDigest' => self::g($sg, 'nlDigest'),
            'sources' => self::g($sg, 'sources'), 'grants' => array_map(static fn($e) => $e['g'], $es), 'prohibits' => $prohibits, 'bounds' => $bounds,
            'validity' => self::g($sg, 'validity'), 'deleg' => $deleg, 'escalateOn' => self::g($sg, 'escalateOn'),
            'wildcardAck' => self::idsOf($es, self::g($sg, 'wildcardAck')), 'holes' => $holes,
        ]);
        return Obj::of(['goal' => $goal, 'report' => Obj::of($report)]);
    }

    // ---- typing of the selector layer ---------------------------------------------------------------------------------

    private static function allKnown(mixed $known, mixed $ids): bool
    {
        foreach (AnalyzerJs::reqList($ids) as $i) {
            if (!(self::lenPos($i) && AnalyzerJs::includes($known, $i))) {
                return false;
            }
        }
        return true;
    }

    private static function grantSelOk(mixed $cat, mixed $g): bool
    {
        $s = self::g($g, 'sel');
        return self::g($s, 'k') === 'verb'
            || (self::lenPos(self::g($s, 'all_of')) && self::len(self::g($s, 'none_of')) === 0 && self::allKnown(self::g($cat, 'known'), self::g($s, 'all_of')));
    }

    private static function prohSelOk(mixed $cat, mixed $p): bool
    {
        $t = self::g($p, 'target');
        return self::g($t, 'k') !== 'trait'
            || (self::allKnown(self::g($cat, 'known'), self::g($t, 'all_of')) && self::allKnown(self::g($cat, 'known'), self::g($t, 'none_of')));
    }

    private static function boundSelOk(mixed $cat, mixed $gs, mixed $b): bool
    {
        $s = self::g($b, 'sel');
        $k = self::g($s, 'k');
        if ($k === 'gids') {
            foreach (AnalyzerJs::reqList(self::g($s, 'gids')) as $i) {
                $any = false;
                foreach (AnalyzerJs::reqList($gs) as $g) {
                    if (AnalyzerJs::strictEq(self::g($g, 'gid'), $i)) {
                        $any = true;
                        break;
                    }
                }
                if (!$any) {
                    return false;
                }
            }
            return true;
        }
        if ($k === 'effect') {
            return true;
        }
        return self::allKnown(self::g($cat, 'known'), self::g($s, 'all_of')) && self::allKnown(self::g($cat, 'known'), self::g($s, 'none_of'));
    }

    /**
     * The type reasons of the selector layer, preceded by the wire checks (`catalog_digest_mismatch`, `bad_id`). [] = well typed at this
     * layer.
     *
     * @return list<string>
     */
    public static function selReasons(mixed $sg, mixed $ont, mixed $cat): array
    {
        $out = [];
        if (!AnalyzerJs::strictEq(self::g($sg, 'catDigest'), self::selCatalogDigest($cat))) {
            $out[] = 'catalog_digest_mismatch';
        }
        $ids = [];
        foreach (AnalyzerJs::reqList(self::g($sg, 'grants')) as $x) {
            $ids[] = self::g($x, 'gid');
        }
        foreach (AnalyzerJs::reqList(self::g($sg, 'prohibits')) as $x) {
            $ids[] = self::g($x, 'pid');
        }
        foreach (AnalyzerJs::reqList(self::g($sg, 'bounds')) as $x) {
            $ids[] = self::g($x, 'bid');
        }
        $badId = false;
        foreach ($ids as $i) {
            if (preg_match(self::SEL_ID_RE, self::s($i)) !== 1) {
                $badId = true;
                break;
            }
        }
        if ($badId) {
            $out[] = 'bad_id';
        }
        $mismatch = false;
        foreach (AnalyzerJs::reqList(self::g($cat, 'verbs')) as $v) {
            if (self::declOf($ont, self::g($v, 'verb')) === null) {
                $mismatch = true;
                break;
            }
        }
        if ($mismatch) {
            $out[] = 'catalog_mismatch';
        }
        if (!self::allOf(AnalyzerJs::reqList(self::g($sg, 'grants')), static fn($g) => self::grantSelOk($cat, $g))) {
            $out[] = 'bad_grant_selector';
        }
        if (!self::allOf(AnalyzerJs::reqList(self::g($sg, 'prohibits')), static fn($p) => self::prohSelOk($cat, $p))) {
            $out[] = 'bad_prohibit_selector';
        }
        if (!self::allOf(AnalyzerJs::reqList(self::g($sg, 'bounds')), static fn($b) => self::boundSelOk($cat, self::g($sg, 'grants'), $b))) {
            $out[] = 'bad_bound_selector';
        }
        $scratch = ['grants' => [], 'prohibits' => [], 'bounds' => []];
        $es = self::expandGrants($ont, $cat, self::g($sg, 'grants'), $scratch);
        if (!self::allOf(AnalyzerJs::reqList(self::g($sg, 'bounds')), static fn($b) => self::boundValue($ont, $cat, self::boundRoleVerbs($ont, $cat, $es, self::g($b, 'sel')), self::g($b, 'value')) !== null)) {
            $out[] = 'unresolved_role_bound';
        }
        return $out;
    }

    /** @param list<mixed> $xs */
    private static function allOf(array $xs, callable $f): bool
    {
        foreach ($xs as $x) {
            if (!$f($x)) {
                return false;
            }
        }
        return true;
    }

    /**
     * CompileX: selector reasons first (fail closed), then expansion and the core compiler. Pass `$compileGoal(goal, ont) ->
     * {ok, policy | reasons}`; with none, the package's own compiler is used.
     */
    public static function compileSelGoal(mixed $sg, mixed $ont, mixed $cat, ?callable $compileGoal = null): Obj
    {
        $rs = self::selReasons($sg, $ont, $cat);
        if ($rs !== []) {
            return Obj::of(['ok' => false, 'reasons' => $rs]);
        }
        $x = self::expandSelGoal($sg, $ont, $cat);
        if ($compileGoal === null) {
            require_once __DIR__ . '/GoalCompiler.php';
            $compileGoal = GoalCompiler::compileGoal(...);
        }
        $c = $compileGoal($x->get('goal'), $ont);
        return Js::truthy(self::g($c, 'ok'))
            ? Obj::of(['ok' => true, 'policy' => self::g($c, 'policy'), 'goal' => $x->get('goal'), 'report' => $x->get('report')])
            : Obj::of(['ok' => false, 'reasons' => self::g($c, 'reasons')]);
    }

    // ---- acts ---------------------------------------------------------------------------------------------------------

    /**
     * Add the role keys a role-addressed bound may read: for every role the act's verb carries on exactly one parameter that the act
     * supplies, `@<role>` is that parameter's value. Any `@` key the caller sent is removed first (a caller cannot forge a role value).
     */
    public static function withRoleParams(mixed $act, mixed $cat): Obj
    {
        $src = self::g($act, 'params');
        $params = new Obj();
        foreach (GoalJs::okeys($src) as $k) {
            if (!str_starts_with($k, '@')) {
                $params->set($k, GoalJs::kget($src, $k));
            }
        }
        $info = self::infoOf($cat, self::g($act, 'verb'));
        if ($info !== null) {
            $roles = self::g($info, 'roles');
            foreach (GoalJs::okeys($roles) as $role) {
                $paths = GoalJs::kget($roles, $role);
                if (self::len($paths) === 1) {
                    $p0 = self::s(self::g($paths, '0'));
                    if ($params->has($p0)) {
                        $params->set('@' . $role, $params->get($p0));
                    }
                }
            }
        }
        $out = AnalyzerJs::spread($act);
        $out->set('params', $params);
        return $out;
    }

    // ---- the policy card ----------------------------------------------------------------------------------------------

    private static function selectorText(mixed $all, mixed $none, array $reg): string
    {
        $phrase = static function ($i) use ($reg): string {
            $t = is_string($i) && isset($reg[$i]) ? ($reg[$i]['card_phrase'] ?? null) : null;
            return $t !== null ? self::s($t) : self::s($i);
        };
        $join = static fn($xs, string $sep): string => implode($sep, array_map($phrase, AnalyzerJs::reqList($xs)));
        $a = self::lenPos($all) ? 'every action that ' . $join($all, ' and ') : 'every action';
        return self::lenPos($none) ? $a . ', except those that ' . $join($none, ' or ') : $a;
    }

    /**
     * The card of a selector goal: one line per selector clause in the words of the trait phrases (never a model), with the verbs the
     * pinned catalog gives it, then the card of the expansion (the exact clauses that run).
     *
     * @param array<string,array>|null $reg
     */
    public static function renderSelCard(mixed $sg, mixed $ont, mixed $cat, ?array $reg = null): Obj
    {
        $reg ??= Actions::coreRegistry();
        $x = self::expandSelGoal($sg, $ont, $cat);
        $goal = $x->get('goal');
        $report = $x->get('report');
        $q = static fn($v): string => self::jq($v);
        $qs = static fn($xs): string => implode(', ', array_map($q, $xs));
        $lines = [];
        $warnings = [];
        foreach (AnalyzerJs::reqList(self::g($sg, 'grants')) as $i => $g) {
            $r = self::g(self::g($report, 'grants'), (string)$i);
            $s = self::g($g, 'sel');
            if (self::g($s, 'k') === 'class') {
                $vs = self::g($r, 'verbs');
                $lines[] = 'ALLOW ' . $q(self::g($g, 'gid')) . ': ' . self::selectorText(self::g($s, 'all_of'), [], $reg)
                    . ' [' . count($vs) . ' verb(s) in the pinned catalog: ' . $qs($vs) . ']';
            }
            foreach (AnalyzerJs::reqList(self::g($r, 'dropped')) as $d) {
                $warnings[] = 'grant ' . $q(self::g($g, 'gid')) . ' does not cover ' . $q(self::g($d, 'verb')) . ': it has no unique parameter for a role the condition names';
            }
        }
        foreach (AnalyzerJs::reqList(self::g($sg, 'prohibits')) as $i => $p) {
            $r = self::g(self::g($report, 'prohibits'), (string)$i);
            $t = self::g($p, 'target');
            if (self::g($t, 'k') === 'trait') {
                $vs = self::g($r, 'verbs');
                $lines[] = 'NEVER ' . $q(self::g($p, 'pid')) . ': ' . self::selectorText(self::g($t, 'all_of'), self::g($t, 'none_of'), $reg) . ', today ' . count($vs)
                    . ' verb(s) [' . $qs($vs) . ']; it also covers every verb added to the catalog later';
            }
            foreach (AnalyzerJs::reqList(self::g($r, 'unconditional')) as $v) {
                $warnings[] = 'prohibition ' . $q(self::g($p, 'pid')) . ' applies to ' . $q($v) . ' without its condition: the verb has no unique parameter for a role the condition names';
            }
        }
        $rb = self::g($report, 'bounds');
        foreach (AnalyzerJs::reqList(self::g($sg, 'bounds')) as $i => $b) {
            $r = $i < count($rb) ? $rb[$i] : null;
            $s = self::g($b, 'sel');
            if (self::g($s, 'k') === 'trait' && $r !== null) {
                $lines[] = 'LIMIT ' . $q(self::g($b, 'bid')) . ': over ' . self::selectorText(self::g($s, 'all_of'), self::g($s, 'none_of'), $reg)
                    . ' (' . count(self::g($r, 'gids')) . ' grant(s))';
            }
            if ($r !== null && self::g($r, 'dropped') === true) {
                $warnings[] = 'limit ' . $q(self::g($b, 'bid')) . ' selects no grant and bounds nothing';
            }
            if ($r !== null && self::g($r, 'value') === 'role_key') {
                $warnings[] = 'limit ' . $q(self::g($b, 'bid')) . ' sums a role the verbs carry on different parameters: the action must supply the role key';
            }
        }
        $core = GoalCard::renderCard($goal);
        return Obj::of([
            'lines' => array_merge($lines, AnalyzerJs::reqList(self::g($core, 'lines'))),
            'warnings' => array_merge($warnings, AnalyzerJs::reqList(self::g($core, 'warnings'))),
        ]);
    }

    /**
     * The closure of a trait id list under the registry (a selector written with a parent trait covers the children by `implies`).
     *
     * @param array<string,array>|null $reg
     * @return list<string>
     */
    public static function traitClosure(mixed $ids, ?array $reg = null): array
    {
        return Actions::closure($reg ?? Actions::coreRegistry(), $ids);
    }

    // ---- the carrier form ---------------------------------------------------------------------------------------------

    private static function carryTerm(mixed $t): Obj
    {
        switch (self::kk($t)) {
            case 'role':
                return Obj::of(['k' => 'param', 'path' => self::ROLE_MARK . self::s(self::g($t, 'role')), 'ty' => Obj::of(['k' => 's'])]);
            case 'param':
                return AnalyzerJs::uobj(['k' => 'param', 'path' => self::g($t, 'path'), 'ty' => self::g($t, 'ty')]);
            case 'lit':
                return AnalyzerJs::uobj(['k' => 'lit', 'v' => self::g($t, 'v')]);
        }
        return AnalyzerJs::uobj(['k' => 'hist', 'bid' => self::g($t, 'bid'), 'u' => self::g($t, 'u')]);
    }

    private static function carryCond(mixed $c): Obj
    {
        $k = self::kk($c);
        switch ($k) {
            case 'true':
                return Obj::of(['k' => 'true']);
            case 'cmp':
                return AnalyzerJs::uobj(['k' => 'cmp', 'op' => self::g($c, 'op'), 'l' => self::carryTerm(self::g($c, 'l')), 'r' => self::carryTerm(self::g($c, 'r'))]);
            case 'and':
            case 'or':
                return Obj::of(['k' => $k, 'a' => self::carryCond(self::g($c, 'a')), 'b' => self::carryCond(self::g($c, 'b'))]);
        }
        return Obj::of(['k' => 'not', 'c' => self::carryCond(self::g($c, 'c'))]);
    }

    /** Array.prototype.join: null and undefined are the empty text. */
    private static function join(mixed $xs, string $sep): string
    {
        return implode($sep, array_map(static fn($x) => $x === null || $x instanceof Undef ? '' : self::s($x), AnalyzerJs::reqList($xs)));
    }

    private static function sel2(mixed $all, mixed $none): string
    {
        return self::join($all, "\x02") . "\x01" . self::join($none, "\x02");
    }

    /**
     * An ordinary Goal's worth of data carrying a selector goal (selectors ride in strings and role-marked params), so the extracted
     * model decodes it with its existing Goal decoder.
     */
    public static function selCarrier(mixed $sg): Obj
    {
        $grants = [];
        foreach (AnalyzerJs::reqList(self::g($sg, 'grants')) as $g) {
            $s = self::g($g, 'sel');
            $grants[] = AnalyzerJs::uobj([
                'gid' => self::g($g, 'gid'),
                'verb' => self::g($s, 'k') === 'verb' ? "V\x01" . self::s(self::g($s, 'verb')) : "C\x01" . self::sel2(self::g($s, 'all_of'), self::g($s, 'none_of')),
                'res' => self::g($g, 'res'), 'cond' => self::carryCond(self::g($g, 'cond')),
            ]);
        }
        $prohibits = [];
        foreach (AnalyzerJs::reqList(self::g($sg, 'prohibits')) as $p) {
            $t = self::g($p, 'target');
            $k = self::g($t, 'k');
            $verb = $k === 'verb' ? "V\x01" . self::s(self::g($t, 'verb'))
                : ($k === 'effect' ? "E\x01" . self::s(self::g($t, 'cls')) : "T\x01" . self::sel2(self::g($t, 'all_of'), self::g($t, 'none_of')));
            $prohibits[] = AnalyzerJs::uobj([
                'pid' => self::g($p, 'pid'), 'res' => self::g($p, 'res'), 'cond' => self::carryCond(self::g($p, 'cond')),
                'target' => Obj::of(['k' => 'verb', 'verb' => $verb]),
            ]);
        }
        $bounds = [];
        foreach (AnalyzerJs::reqList(self::g($sg, 'bounds')) as $b) {
            $s = self::g($b, 'sel');
            $k = self::g($s, 'k');
            $sel = $k === 'gids' ? AnalyzerJs::uobj(['k' => 'gids', 'gids' => self::g($s, 'gids')])
                : ($k === 'effect' ? AnalyzerJs::uobj(['k' => 'effect', 'cls' => self::g($s, 'cls')])
                    : Obj::of(['k' => 'effect', 'cls' => "T\x01" . self::sel2(self::g($s, 'all_of'), self::g($s, 'none_of'))]));
            $bounds[] = AnalyzerJs::uobj([
                'bid' => self::g($b, 'bid'), 'key' => self::g($b, 'key'), 'window' => self::g($b, 'window'), 'scope' => self::g($b, 'scope'),
                'cap' => self::g($b, 'cap'), 'onExceed' => self::g($b, 'onExceed'), 'agg' => self::g($b, 'agg'),
                'value' => self::carryTerm(self::g($b, 'value')), 'sel' => $sel,
            ]);
        }
        return AnalyzerJs::uobj([
            'v' => new Num('1'), 'principal' => self::g($sg, 'principal'), 'ontDigest' => self::g($sg, 'ontDigest'), 'nlDigest' => self::g($sg, 'nlDigest'),
            'sources' => self::g($sg, 'sources'), 'grants' => $grants, 'prohibits' => $prohibits, 'bounds' => $bounds, 'validity' => self::g($sg, 'validity'),
            'deleg' => self::g($sg, 'deleg'), 'escalateOn' => self::g($sg, 'escalateOn'), 'wildcardAck' => self::g($sg, 'wildcardAck'), 'holes' => self::g($sg, 'holes'),
        ]);
    }

    /**
     * The catalog tape the extracted model reads: known trait ids, then per verb: verb, traits, number of roles, (role, paths)*.
     *
     * @return list<array{0:string,1:mixed}>
     */
    public static function encodeSelCatalog(mixed $c): array
    {
        $strs = static function ($xs): array {
            $out = [['i', self::len($xs)]];
            foreach (AnalyzerJs::reqList($xs) as $x) {
                $out[] = ['s', $x];
            }
            return $out;
        };
        $verbs = AnalyzerJs::reqList(self::g($c, 'verbs'));
        $out = array_merge($strs(self::g($c, 'known')), [['i', count($verbs)]]);
        foreach ($verbs as $v) {
            $roles = self::g($v, 'roles');
            $keys = GoalJs::okeys($roles);
            $out = array_merge($out, [['s', self::g($v, 'verb')]], $strs(self::g($v, 'traits')), [['i', count($keys)]]);
            foreach ($keys as $r) {
                $out = array_merge($out, [['s', $r]], $strs(GoalJs::kget($roles, $r)));
            }
        }
        return $out;
    }
}
