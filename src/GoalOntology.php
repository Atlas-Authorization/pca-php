<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/GoalJs.php';
require_once __DIR__ . '/GoalIrError.php';
require_once __DIR__ . '/GoalSign.php';
require_once __DIR__ . '/GoalDigests.php';
require_once __DIR__ . '/GoalNormalize.php';
require_once __DIR__ . '/GoalExamples.php';
require_once __DIR__ . '/Pca.php';

/** A JavaScript Set over JSON values: objects and arrays by identity (a parsed tree shares none), everything else by value. */
final class GoalJsSet
{
    private static int $fresh = 0;
    /** @var array<string,true> */
    private array $s = [];

    /** @param list<mixed> $items */
    public function __construct(array $items = [])
    {
        foreach ($items as $i) {
            $this->add($i);
        }
    }

    /** The SameValueZero key of a value. */
    public static function key(mixed $x): string
    {
        if ($x instanceof Obj) {
            return 'o' . spl_object_id($x);
        }
        if (is_array($x)) {
            return 'a' . (++self::$fresh);
        }
        if ($x instanceof Undef) {
            return 'u';
        }
        if ($x === null) {
            return 'z';
        }
        if (is_bool($x)) {
            return $x ? 'b1' : 'b0';
        }
        if (Js::isNum($x)) {
            $f = (float)Js::num($x);
            return is_nan($f) ? 'nNaN' : ($f == 0.0 ? 'n0' : 'n' . sprintf('%.17g', $f));
        }
        return 's' . $x;
    }

    public function add(mixed $x): void
    {
        $this->s[self::key($x)] = true;
    }

    public function has(mixed $x): bool
    {
        return isset($this->s[self::key($x)]);
    }

    public function length(): int
    {
        return count($this->s);
    }
}

/**
 * The intent-fidelity ontology: the signed authoring vocabulary (aliases, templates, units), its projection onto the IR ontology,
 * its well-formedness checker, template instantiation, slot typing and locale-aware amount parsing. Ontologies, goals and slot
 * values are parsed-JSON trees (Obj, list arrays, scalars); results are Obj / list trees with undefined members absent.
 */
final class GoalOntology
{
    public const EFFECT_CLASSES = ['read', 'reversible', 'external_send', 'irreversible'];
    public const FOREVER = 9007199254740991;
    private const MAX_SAFE = 9007199254740991.0;
    /** JavaScript whitespace (String.prototype.trim / \s) as UTF-8 byte alternatives. */
    private const WS = '(?:[\t\n\x0B\f\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)';
    /** U+200B..U+200F, U+2060, U+FEFF. */
    private const INVIS = '/\xE2\x80[\x8B-\x8F]|\xE2\x81\xA0|\xEF\xBB\xBF/';

    // ---- JS plumbing ----

    private static function g(mixed $o, string $k): mixed
    {
        return AnalyzerJs::jget($o, $k);
    }

    private static function undef(): Undef
    {
        return AnalyzerJs::undef();
    }

    private static function isU(mixed $x): bool
    {
        return $x instanceof Undef;
    }

    /** Not null and not undefined (an optional-chaining guard). */
    private static function def(mixed $x): bool
    {
        return $x !== null && !($x instanceof Undef);
    }

    private static function eq(mixed $a, mixed $b): bool
    {
        return AnalyzerJs::strictEq($a, $b);
    }

    private static function truthy(mixed $x): bool
    {
        return AnalyzerJs::truthy($x);
    }

    /** @return list<mixed> */
    private static function list(mixed $x): array
    {
        return AnalyzerJs::reqList($x);
    }

    private static function str(mixed $x): string
    {
        return AnalyzerJs::jsStr($x);
    }

    /** `s.startsWith(p)` for strings; anything else throws. */
    private static function sw(mixed $s, mixed $p): bool
    {
        if (!is_string($s) || !is_string($p)) {
            throw new \TypeError('startsWith needs strings');
        }
        return str_starts_with($s, $p);
    }

    private static function nfkc(string $s): string
    {
        if (preg_match('//u', $s) === 1) {
            $r = \Normalizer::normalize($s, \Normalizer::FORM_KC);
            if ($r === false) {
                throw new \InvalidArgumentException('cannot normalize');
            }
            return $r;
        }
        // a lone surrogate (3-byte WTF-8) is left as it is; the text between is normalized
        $parts = preg_split('/(\xED[\xA0-\xBF][\x80-\xBF])/', $s, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [$s];
        $out = '';
        foreach ($parts as $i => $p) {
            if ($i % 2 === 1) {
                $out .= $p;
                continue;
            }
            $r = \Normalizer::normalize($p, \Normalizer::FORM_KC);
            if ($r === false) {
                throw new \InvalidArgumentException('cannot normalize');
            }
            $out .= $r;
        }
        return $out;
    }

    private static function norm(string $s): string
    {
        return (string)preg_replace(self::INVIS, '', GoalJs::lower(self::nfkc($s)));
    }

    private static function trim(string $s): string
    {
        $s = (string)preg_replace('/\A' . self::WS . '+/', '', $s);
        return (string)preg_replace('/' . self::WS . '+\z/', '', $s);
    }

    private static function hasInvis(string $s): bool
    {
        return preg_match(self::INVIS, $s) === 1;
    }

    /** Object.entries(o): the own members in JavaScript key order; null / undefined throws; other primitives have none. @return list<array{0:string,1:mixed}> */
    private static function entries(mixed $o): array
    {
        $out = [];
        foreach (GoalJs::okeys($o) as $k) {
            $out[] = [$k, GoalJs::kget($o, $k)];
        }
        return $out;
    }

    /** @return list<mixed> */
    private static function values(mixed $o): array
    {
        return array_map(static fn(array $e): mixed => $e[1], self::entries($o));
    }

    /** `for (const e of x)`: an array's elements or a string's code points; anything else throws. @return list<mixed> */
    private static function iter(mixed $x): array
    {
        if (is_array($x) && array_is_list($x)) {
            return $x;
        }
        if (is_string($x)) {
            preg_match_all('/[\x00-\x7F]|[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}/', $x, $m);
            return $m[0];
        }
        throw new \TypeError('not iterable');
    }

    /** `xs.find(pred)`: the first element for which the predicate is truthy, else undefined. */
    private static function find(mixed $xs, callable $pred): mixed
    {
        foreach (self::list($xs) as $x) {
            if (self::truthy($pred($x))) {
                return $x;
            }
        }
        return self::undef();
    }

    /** o[k] for an own member of a plain object, else undefined (a null / undefined object throws). */
    private static function own(mixed $o, mixed $k): mixed
    {
        if ($o === null || $o instanceof Undef) {
            throw new \TypeError('cannot read properties of null');
        }
        return $o instanceof Obj && is_string($k) && $o->has($k) ? $o->get($k) : self::undef();
    }

    private static function lenPos(mixed $x): bool
    {
        return (is_array($x) && array_is_list($x) && $x !== []) || (is_string($x) && $x !== '');
    }

    private static function isInteger(mixed $x): bool
    {
        if (!Js::isNum($x)) {
            return false;
        }
        $f = (float)Js::num($x);
        return is_finite($f) && $f == floor($f);
    }

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    // ---- digest and signature ----

    public static function ontologyDigest(mixed $o): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/goal-intent-ontology/v1', 'ontology' => $o]));
    }

    public static function signOntology(mixed $o, mixed $secret, mixed $opts = null): mixed
    {
        return GoalSign::signPayload('ontology', $o, $secret, $opts);
    }

    public static function verifyOntology(mixed $s, mixed $pins): bool
    {
        return GoalSign::verifyPayload($s, 'ontology', $pins);
    }

    // ---- verbs and projection ----

    /** The canonical verb id of an id or declared alias; case and homoglyph variants are NOT guessed. */
    public static function resolveVerb(mixed $o, mixed $word): mixed
    {
        if (!is_string($word)) {
            throw new \TypeError('word.trim is not a function');
        }
        $w = self::trim($word);
        foreach (self::list(self::g($o, 'verbs')) as $v) {
            if (self::eq(self::g($v, 'id'), $w)) {
                return $w;
            }
        }
        $hit = self::own(self::g($o, 'aliases'), $w);
        return self::isU($hit) ? null : $hit;
    }

    /** The currency a goal is written in: the first money quantity in its conditions or bound caps (null without money). */
    public static function goalCcy(mixed $g): mixed
    {
        $found = self::undef();
        $t = function (mixed $x) use (&$found): void {
            if (self::g($x, 'k') !== 'lit') {
                return;
            }
            $v = self::g($x, 'v');
            foreach (self::g($v, 'k') === 'set' ? self::list(self::g($v, 'items')) : [$v] as $i) {
                if (self::isU($found) && self::g($i, 'k') === 'q' && self::g(self::g(self::g($i, 'q'), 'u'), 'k') === 'money') {
                    $found = self::g(self::g(self::g($i, 'q'), 'u'), 'ccy');
                }
            }
        };
        $c = function (mixed $x) use (&$c, $t): void {
            $k = self::g($x, 'k');
            if ($k === 'cmp') {
                $t(self::g($x, 'l'));
                $t(self::g($x, 'r'));
            } elseif ($k === 'and' || $k === 'or') {
                $c(self::g($x, 'a'));
                $c(self::g($x, 'b'));
            } elseif ($k === 'not') {
                $c(self::g($x, 'c'));
            }
        };
        foreach (self::list(self::g($g, 'grants')) as $gr) {
            $c(self::g($gr, 'cond'));
        }
        foreach (self::list(self::g($g, 'prohibits')) as $p) {
            $c(self::g($p, 'cond'));
        }
        foreach (self::list(self::g($g, 'escalateOn')) as $x) {
            $c($x);
        }
        foreach (self::list(self::g($g, 'bounds')) as $b) {
            $cap = self::g($b, 'cap');
            if (self::isU($found) && self::g(self::g($cap, 'u'), 'k') === 'money') {
                $found = self::g(self::g($cap, 'u'), 'ccy');
            }
        }
        return self::isU($found) ? null : $found;
    }

    private static function paramTy(mixed $p, mixed $ccy): Obj
    {
        $kind = self::g($p, 'kind');
        if ($kind === 'id' || $kind === 'enum' || $kind === 'text') {
            return Obj::of(['k' => 's']);
        }
        if ($kind === 'money') {
            $ccys = self::g($p, 'ccys');
            if (self::def($ccy) && self::def($ccys) && AnalyzerJs::includes($ccys, $ccy)) {
                $c = $ccy;
            } elseif (self::def($ccys) && AnalyzerJs::includes($ccys, 'USD')) {
                $c = 'USD';
            } else {
                $l = self::list($ccys);
                $c = $l === [] ? self::undef() : $l[0];
            }
            return Obj::of(['k' => 'q', 'u' => AnalyzerJs::uobj(['k' => 'money', 'ccy' => $c])]);
        }
        return Obj::of(['k' => 'q', 'u' => AnalyzerJs::uobj(['k' => $kind])]);
    }

    /** T1's `Ontology` (verbs with effect class and typed parameters, relation tables) for an intent ontology. `$opts`: {ccy?, rels?}. */
    public static function toIrOntology(mixed $o, mixed $opts = null): Obj
    {
        $ccy = Js::opt($opts, 'ccy');
        $verbs = [];
        foreach (self::list(self::g($o, 'verbs')) as $v) {
            $params = self::g($v, 'params');
            $paths = array_map(static fn(array $e): string => $e[0], self::entries($params));
            usort($paths, static fn(string $a, string $b): int => AnalyzerJs::u16cmp($a, $b));
            $verbs[] = AnalyzerJs::uobj([
                'verb' => self::g($v, 'id'), 'cls' => self::g($v, 'effect'),
                'params' => array_map(static fn(string $path): Obj => Obj::of(['path' => $path, 'ty' => self::paramTy(self::own($params, $path), $ccy)]), $paths),
            ]);
        }
        $rels = Js::opt($opts, 'rels');
        return Obj::of(['verbs' => $verbs, 'rels' => $rels ?? []]);
    }

    /** The IR ontology a goal is typed and decided against: money parameters in the goal's own currency. */
    public static function ontologyForGoal(mixed $o, mixed $g, mixed $rels = null): Obj
    {
        $ccy = self::goalCcy($g);
        $opts = Obj::of(['rels' => $rels ?? []]);
        if ($ccy !== null) {
            $opts->set('ccy', $ccy);
        }
        return self::toIrOntology($o, $opts);
    }

    /** Relation anchors a goal mentions, declared with no members (typing needs them; facts come per case). @return list<Obj> */
    public static function goalAnchors(mixed $g): array
    {
        $out = [];
        $sel = function (mixed $s) use (&$sel, &$out): void {
            $k = self::g($s, 'k');
            if ($k === 'related') {
                $out[self::str(self::g($s, 'rel')) . "\0" . self::str(self::g($s, 'anchor'))] = AnalyzerJs::uobj(['rel' => self::g($s, 'rel'), 'anchor' => self::g($s, 'anchor'), 'members' => []]);
            } elseif ($k === 'all_of') {
                foreach (self::list(self::g($s, 'parts')) as $p) {
                    $sel($p);
                }
            }
        };
        foreach (self::list(self::g($g, 'grants')) as $gr) {
            $sel(self::g($gr, 'res'));
        }
        foreach (self::list(self::g($g, 'prohibits')) as $p) {
            $sel(self::g($p, 'res'));
        }
        $keys = array_map('strval', array_keys($out));
        usort($keys, static fn(string $a, string $b): int => AnalyzerJs::u16cmp($a, $b));
        return array_map(static fn(string $k): Obj => $out[$k], $keys);
    }

    // ---- slot references ----

    /** @return list<mixed> */
    private static function refsRes(mixed $s): array
    {
        $d = static fn(mixed $x): array => self::sw($x, '$') ? [substr($x, 1)] : [];
        $k = self::g($s, 'k');
        if ($k === 'exact') {
            return $d(self::g($s, 'id'));
        }
        if ($k === 'oneof') {
            return array_merge([], ...array_map($d, self::list(self::g($s, 'ids'))));
        }
        if ($k === 'related') {
            return $d(self::g($s, 'anchor'));
        }
        if ($k === 'all_of') {
            return array_merge([], ...array_map(self::refsRes(...), self::list(self::g($s, 'parts'))));
        }
        return [];
    }

    /** @return list<mixed> */
    private static function refsTerm(mixed $x): array
    {
        return self::g($x, 'k') === 'slot' ? [self::g($x, 'slot')] : [];
    }

    /** @return list<mixed> */
    private static function refsCond(mixed $c): array
    {
        $k = self::g($c, 'k');
        if ($k === 'cmp') {
            return array_merge(self::refsTerm(self::g($c, 'l')), self::refsTerm(self::g($c, 'r')));
        }
        if ($k === 'and' || $k === 'or') {
            return array_merge(self::refsCond(self::g($c, 'a')), self::refsCond(self::g($c, 'b')));
        }
        if ($k === 'not') {
            return self::refsCond(self::g($c, 'c'));
        }
        return [];
    }

    /** @return list<mixed> */
    private static function refsGrant(mixed $g): array
    {
        return array_merge(self::refsRes(self::g($g, 'res')), self::refsCond(self::g($g, 'cond')));
    }

    /** @return list<mixed> */
    private static function refsBound(mixed $b): array
    {
        return self::truthy(self::g($b, 'cap_slot')) ? [self::g($b, 'cap_slot')] : [];
    }

    /** @return list<mixed> */
    private static function slotRefs(mixed $t): array
    {
        $out = [];
        foreach (self::list(self::g($t, 'grants')) as $g) {
            $out = array_merge($out, self::refsGrant($g));
        }
        foreach (self::list(self::g($t, 'prohibits')) as $p) {
            $out = array_merge($out, self::refsGrant($p));
        }
        foreach (self::list(self::g($t, 'bounds')) as $b) {
            $out = array_merge($out, self::refsBound($b));
        }
        return $out;
    }

    // ---- the checker ----

    /** Well-formedness checker: every defect as {code, where, msg}; an empty list means well formed. @return list<Obj> */
    public static function checkOntology(mixed $o): array
    {
        $issues = [];
        $bad = static function (string $code, mixed $where, string $msg) use (&$issues): void {
            $issues[] = AnalyzerJs::uobj(['code' => $code, 'where' => $where, 'msg' => $msg]);
        };
        $typeIds = new GoalJsSet();
        $prefixes = new GoalJsSet();
        foreach (self::iter(self::g($o, 'types')) as $t) {
            $tid = self::g($t, 'id');
            if ($typeIds->has($tid)) {
                $bad('dup_type', $tid, 'duplicate type id');
            }
            $typeIds->add($tid);
            $pre = self::g($t, 'id_prefix');
            if (!self::truthy($pre) || $prefixes->has($pre)) {
                $bad('dup_prefix', $tid, 'id prefix empty or reused');
            }
            $prefixes->add($pre);
        }
        $units = self::g($o, 'units');
        foreach (self::entries($units) as [$u, $d]) {
            $exp = self::g($d, 'exponent');
            $money = self::g($d, 'kind') === 'money';
            if ($money && !(self::isInteger($exp) && (float)Js::num($exp) >= 0 && (float)Js::num($exp) <= 4)) {
                $bad('unit_exponent', $u, 'money unit needs an integer exponent 0..4');
            }
            if (!$money && !self::isU($exp)) {
                $bad('unit_exponent', $u, 'only money units carry an exponent');
            }
        }
        $relIds = new GoalJsSet();
        foreach (self::iter(self::g($o, 'relations')) as $r) {
            $rid = self::g($r, 'id');
            if ($relIds->has($rid)) {
                $bad('dup_relation', $rid, 'duplicate relation');
            }
            $relIds->add($rid);
            if (!$typeIds->has(self::g($r, 'from')) || !$typeIds->has(self::g($r, 'to'))) {
                $bad('relation_type', $rid, 'relation endpoint type is not declared');
            }
        }
        $verbIds = new GoalJsSet();
        $verbs = [];
        foreach (self::iter(self::g($o, 'verbs')) as $v) {
            $vid = self::g($v, 'id');
            if ($verbIds->has($vid)) {
                $bad('dup_verb', $vid, 'duplicate verb');
            }
            $verbIds->add($vid);
            $verbs[GoalJsSet::key($vid)] = $v;
            if (!AnalyzerJs::includes(self::EFFECT_CLASSES, self::g($v, 'effect'))) {
                $bad('no_effect_class', $vid, 'verb has no valid effect class');
            }
            if (!$typeIds->has(self::g($v, 'resource_type'))) {
                $bad('verb_resource_type', $vid, 'resource type is not declared');
            }
            foreach (self::entries(self::g($v, 'params')) as [$p, $pt]) {
                $kind = self::g($pt, 'kind');
                $w = self::str($vid) . '.' . $p;
                if ($kind === 'money') {
                    $ccys = self::g($pt, 'ccys');
                    if (!self::lenPos($ccys)) {
                        $bad('param_ccy', $w, 'money parameter lists no currency');
                    }
                    foreach (!self::def($ccys) ? [] : self::iter($ccys) as $c) {
                        if (AnalyzerJs::oget(is_string($c) ? self::own($units, $c) : self::undef(), 'kind') !== 'money') {
                            $bad('unit_unknown', $w, 'currency ' . self::str($c) . ' is not a declared money unit');
                        }
                    }
                } elseif ($kind === 'enum') {
                    if (!self::lenPos(self::g($pt, 'values'))) {
                        $bad('param_enum', $w, 'enum parameter has no values');
                    }
                } elseif ($kind === 'id') {
                    $of = self::g($pt, 'of');
                    if (!self::truthy($of) || !$typeIds->has($of)) {
                        $bad('param_type', $w, 'id parameter type is not declared');
                    }
                } elseif ($kind !== 'text') {
                    $any = false;
                    foreach (self::values($units) as $u) {
                        if (self::eq(self::g($u, 'kind'), $kind)) {
                            $any = true;
                            break;
                        }
                    }
                    if (!$any) {
                        $bad('unit_unknown', $w, 'no declared unit of kind ' . self::str($kind));
                    }
                }
            }
        }
        $seen = [];
        $aliases = self::g($o, 'aliases');
        foreach (self::entries($aliases) as [$k, $target]) {
            if ($k !== self::norm($k) || (preg_match('/[^\x20-\x7e]/', $k) === 1 && $k !== self::nfkc($k))) {
                $bad('alias_key', $k, 'alias key is not in normalized form');
            }
            if (self::hasInvis($k)) {
                $bad('alias_key', $k, 'alias key contains invisible characters');
            }
            $n = self::norm($k);
            if (array_key_exists($n, $seen) && $seen[$n] !== $k) {
                $bad('alias_collision', $k, 'collides with ' . $seen[$n] . ' after normalization');
            }
            $seen[$n] = $k;
            if (!$verbIds->has($target)) {
                $bad('alias_target', $k, 'alias target is not a canonical verb');
            }
            if (is_string($target) && $aliases instanceof Obj && $aliases->has($target)) {
                $bad('alias_chain', $k, 'alias target is itself an alias (chain or cycle)');
            }
            if ($verbIds->has($k) && $k !== $target) {
                $bad('alias_shadow', $k, 'alias shadows a canonical verb');
            }
        }
        $tids = new GoalJsSet();
        foreach (self::list(self::g($o, 'templates')) as $t) {
            $tid = self::g($t, 'id');
            $w = 'template:' . self::str($tid);
            if ($tids->has($tid)) {
                $bad('dup_template', $w, 'duplicate template id');
            }
            $tids->add($tid);
            $slots = self::list(self::g($t, 'slots'));
            $slotNames = new GoalJsSet(array_map(static fn(mixed $s): mixed => self::g($s, 'name'), $slots));
            if ($slotNames->length() !== count($slots)) {
                $bad('dup_slot', $w, 'duplicate slot');
            }
            foreach (self::slotRefs($t) as $r) {
                if (!$slotNames->has($r)) {
                    $bad('slot_undeclared', $w, 'slot ' . self::str($r) . ' is used but not declared');
                }
            }
            foreach ($slots as $s) {
                $sw = $w . '.' . self::str(self::g($s, 'name'));
                $sk = self::g($s, 'kind');
                if ($sk === 'id' || $sk === 'id_list') {
                    $of = self::g($s, 'of');
                    if (!self::truthy($of) || !$typeIds->has($of)) {
                        $bad('slot_type', $sw, 'id slot type is not declared');
                    }
                }
                if ($sk === 'money') {
                    $ccy = self::g($s, 'ccy');
                    $u = self::isU($ccy) || is_string($ccy) ? self::own($units, self::isU($ccy) ? '' : $ccy) : self::undef();
                    if (AnalyzerJs::oget($u, 'kind') !== 'money') {
                        $bad('slot_ccy', $sw, 'money slot currency is not a declared unit');
                    }
                }
                if (($sk === 'enum' || $sk === 'enum_list') && !self::lenPos(self::g($s, 'values'))) {
                    $bad('slot_enum', $sw, 'enum slot has no values');
                }
                if (!self::truthy(self::g($s, 'mandatory')) && self::isU(self::g($s, 'default'))) {
                    $bad('slot_default', $sw, 'optional slot needs a default (an unfilled slot must be a hole or a default)');
                }
                if (!AnalyzerJs::includes(self::slotRefs($t), self::g($s, 'name'))) {
                    $bad('slot_unused', $sw, 'declared slot is never used');
                }
            }
            $tgrants = self::list(self::g($t, 'grants'));
            $tbounds = self::list(self::g($t, 'bounds'));
            if ($tgrants === []) {
                $bad('empty_allow', $w, 'template has no grant (empty Allow set)');
            }
            $gids = new GoalJsSet(array_map(static fn(mixed $g): mixed => self::g($g, 'gid'), $tgrants));
            if ($gids->length() !== count($tgrants)) {
                $bad('dup_gid', $w, 'duplicate grant id');
            }
            foreach ($tgrants as $g) {
                $vk = GoalJsSet::key(self::g($g, 'verb'));
                $v = $verbs[$vk] ?? null;
                $gw = $w . '.' . self::str(self::g($g, 'gid'));
                if ($v === null) {
                    $bad('grant_verb', $gw, 'grant verb is not in the ontology');
                    continue;
                }
                self::checkResource($o, self::g($g, 'res'), $v, $gw, $bad);
                self::checkCond(self::g($g, 'cond'), $v, $t, $gw, $bad);
                $res = self::g($g, 'res');
                if (self::g($res, 'k') === 'any' && !(self::g($v, 'effect') === 'read' && $tbounds !== [])) {
                    $bad('unbounded', $gw, 'wildcard resource in a template');
                }
                if (self::g($v, 'effect') !== 'read' && self::g($res, 'k') === 'related' && $tbounds === []) {
                    $bad('unbounded', $gw, 'non-read grant on a related set needs an aggregate bound');
                }
            }
            foreach (self::list(self::g($t, 'prohibits')) as $p) {
                $tg = self::g($p, 'target');
                $pw = $w . '.' . self::str(self::g($p, 'pid'));
                if (self::g($tg, 'k') === 'verb' && !array_key_exists(GoalJsSet::key(self::g($tg, 'verb')), $verbs)) {
                    $bad('prohibit_verb', $pw, 'prohibit verb is not in the ontology');
                }
                if (self::g($tg, 'k') === 'effect' && !AnalyzerJs::includes(self::EFFECT_CLASSES, self::g($tg, 'cls'))) {
                    $bad('prohibit_effect', $pw, 'unknown effect class');
                }
            }
            foreach ($tbounds as $b) {
                $bw = $w . '.' . self::str(self::g($b, 'bid'));
                $over = self::g($b, 'over');
                if (!self::eq($over, 'all')) {
                    foreach (self::list($over) as $x) {
                        if (!$gids->has($x)) {
                            $bad('bound_over', $bw, 'bound selects an unknown grant');
                            break;
                        }
                    }
                }
                $csName = self::g($b, 'cap_slot');
                if (self::truthy($csName) && !$slotNames->has($csName)) {
                    $bad('slot_undeclared', $w, 'cap slot ' . self::str($csName) . ' is not declared');
                }
                if (self::truthy($csName)) {
                    $cs = self::find($slots, static fn(mixed $x): bool => self::eq(self::g($x, 'name'), $csName));
                    if (!self::isU($cs)) {
                        $csk = self::g($cs, 'kind');
                        $agg = self::g($b, 'agg');
                        if ($csk !== 'money' && $csk !== 'count') {
                            $bad('bound_cap', $bw, 'cap slot must be money or count');
                        }
                        if ($agg === 'count' && $csk !== 'count') {
                            $bad('bound_cap', $bw, 'count bound needs a count slot');
                        }
                        if ($agg === 'sum' && $csk !== 'money') {
                            $bad('bound_cap', $bw, 'sum bound over money needs a money slot');
                        }
                    }
                }
                if (self::g($b, 'agg') === 'sum' && !self::truthy(self::g($b, 'param'))) {
                    $bad('bound_value', $bw, 'sum bound has no value parameter');
                }
            }
            // non-empty and bounded after instantiation with the declared example
            $g = self::instantiateTemplate($o, $tid, self::g($t, 'example'), Obj::of(['principal' => 'p', 'nl' => '']));
            $holes = self::list(self::g($g, 'holes'));
            if ($holes !== []) {
                $ids = array_map(static fn(mixed $h): string => ($x = self::g($h, 'hid')) === null || self::isU($x) ? '' : self::str($x), $holes);
                $bad('example_holes', $w, 'example leaves holes: ' . implode(',', $ids));
            } elseif (count(self::list(self::g($g, 'grants'))) !== count($tgrants)) {
                $bad('empty_allow', $w, 'example instantiation dropped a grant');
            } elseif (!self::allowWitness($o, $g)) {
                $bad('empty_allow', $w, 'instantiated template has an empty Allow set');
            }
        }
        return $issues;
    }

    private static function checkResource(mixed $o, mixed $s, mixed $v, string $w, callable $bad): void
    {
        $rt = self::g($v, 'resource_type');
        $ty = self::find(self::g($o, 'types'), static fn(mixed $t): bool => self::eq(self::g($t, 'id'), $rt));
        $prefix = AnalyzerJs::oget($ty, 'id_prefix');
        $idOk = static fn(mixed $i, mixed $pre): bool => self::sw($i, '$') || (!self::isU($pre) && self::sw($i, $pre));
        $k = self::g($s, 'k');
        if ($k === 'exact') {
            if (!$idOk(self::g($s, 'id'), $prefix)) {
                $bad('resource_type', $w, 'exact resource id has the wrong type prefix');
            }
        } elseif ($k === 'oneof') {
            $ids = self::list(self::g($s, 'ids'));
            if ($ids === []) {
                $bad('resource_empty', $w, 'one_of is empty');
            }
            foreach ($ids as $i) {
                if (!$idOk($i, $prefix)) {
                    $bad('resource_type', $w, 'one_of member has the wrong type prefix');
                }
            }
        } elseif ($k === 'related') {
            $rel = self::g($s, 'rel');
            $r = self::find(self::g($o, 'relations'), static fn(mixed $x): bool => self::eq(self::g($x, 'id'), $rel));
            if (self::isU($r)) {
                $bad('relation_unknown', $w, 'relation ' . self::str($rel) . ' is not declared');
            } else {
                if (!self::eq(self::g($r, 'to'), $rt)) {
                    $bad('relation_type', $w, 'relation target type differs from the verb resource type');
                }
                $rf = self::g($r, 'from');
                $anchorPre = AnalyzerJs::oget(self::find(self::g($o, 'types'), static fn(mixed $t): bool => self::eq(self::g($t, 'id'), $rf)), 'id_prefix');
                if (!$idOk(self::g($s, 'anchor'), $anchorPre)) {
                    $bad('resource_type', $w, 'relation anchor has the wrong type prefix');
                }
            }
        } elseif ($k === 'all_of') {
            $parts = self::list(self::g($s, 'parts'));
            if (count($parts) < 2) {
                $bad('all_of_arity', $w, 'all_of needs at least two parts');
            }
            foreach ($parts as $x) {
                self::checkResource($o, $x, $v, $w, $bad);
            }
        }
    }

    private static function checkCond(mixed $c, mixed $v, mixed $t, string $w, callable $bad): void
    {
        $k = self::g($c, 'k');
        if ($k === 'and' || $k === 'or') {
            self::checkCond(self::g($c, 'a'), $v, $t, $w, $bad);
            self::checkCond(self::g($c, 'b'), $v, $t, $w, $bad);
            return;
        }
        if ($k === 'not') {
            self::checkCond(self::g($c, 'c'), $v, $t, $w, $bad);
            return;
        }
        if ($k !== 'cmp') {
            return;
        }
        $l = self::g($c, 'l');
        $p = self::g($l, 'k') === 'param' ? self::own(self::g($v, 'params'), self::g($l, 'path')) : self::undef();
        if (self::g($l, 'k') !== 'param' || !self::truthy($p)) {
            $bad('cond_param', $w, 'left side of a comparison must be a declared parameter of the verb');
            return;
        }
        $op = self::g($c, 'op');
        $pk = self::g($p, 'kind');
        if (in_array($op, ['lt', 'lte', 'gt', 'gte'], true) && in_array($pk, ['text', 'enum', 'id'], true)) {
            $bad('cond_order', $w, 'ordering on a text/enum/id parameter');
        }
        $x = self::g($c, 'r');
        $xk = self::g($x, 'k');
        if ($xk === 'slot') {
            $sn = self::g($x, 'slot');
            $s = self::find(self::g($t, 'slots'), static fn(mixed $q): bool => self::eq(self::g($q, 'name'), $sn));
            if (self::isU($s)) {
                return;
            }
            $sk = self::g($s, 'kind');
            if ($pk === 'money') {
                $okKind = $sk === 'money';
            } else {
                $okKind = self::eq($pk, $sk) || ($pk === 'enum' && in_array($sk, ['enum', 'enum_list'], true))
                    || ($pk === 'id' && in_array($sk, ['id', 'id_list'], true)) || ($pk === 'text' && $sk === 'text_list');
            }
            if (!$okKind) {
                $bad('cond_type', $w, 'slot ' . self::str(self::g($s, 'name')) . ' (' . self::str($sk) . ') does not type-check against parameter kind ' . self::str($pk));
            }
            $ccys = self::g($p, 'ccys');
            $scc = self::g($s, 'ccy');
            if ($pk === 'money' && $sk === 'money' && !(self::def($ccys) && AnalyzerJs::includes($ccys, self::isU($scc) ? '' : $scc))) {
                $bad('cond_unit', $w, 'slot currency is not accepted by the parameter');
            }
            $lst = in_array($sk, ['id_list', 'enum_list', 'text_list'], true);
            if ($lst !== in_array($op, ['in', 'nin'], true)) {
                $bad('cond_type', $w, 'list slots pair with in/nin and scalar slots with the other operators');
            }
        } elseif ($xk === 'lit') {
            $lv = self::g($x, 'v');
            if (self::g($lv, 'k') === 'set') {
                $items = self::list(self::g($lv, 'items'));
                if ($items === []) {
                    $bad('cond_type', $w, 'empty literal list');
                }
                foreach ($items as $i) {
                    self::litCheck($i, $p, $w, $bad);
                }
                if (!in_array($op, ['in', 'nin'], true)) {
                    $bad('cond_type', $w, 'a literal set pairs with in/nin');
                }
            } else {
                self::litCheck($lv, $p, $w, $bad);
                if (in_array($op, ['in', 'nin'], true)) {
                    $bad('cond_type', $w, 'in/nin needs a list');
                }
            }
        } else {
            $bad('cond_term', $w, 'unsupported right-hand term');
        }
    }

    private static function litCheck(mixed $l, mixed $p, string $w, callable $bad): void
    {
        $pk = self::g($p, 'kind');
        $k = self::g($l, 'k');
        if ($k === 'q') {
            $u = self::g(self::g($l, 'q'), 'u');
            if (!self::eq(self::g($u, 'k'), $pk)) {
                $bad('cond_type', $w, 'literal kind differs from the parameter kind');
            }
            $ccys = self::g($p, 'ccys');
            if (self::g($u, 'k') === 'money' && !(self::def($ccys) && AnalyzerJs::includes($ccys, self::g($u, 'ccy')))) {
                $bad('cond_unit', $w, 'literal currency is not accepted by the parameter');
            }
        } elseif ($k === 's') {
            if (!in_array($pk, ['enum', 'id', 'text'], true)) {
                $bad('cond_type', $w, 'literal kind differs from the parameter kind');
            }
            $vals = self::g($p, 'values');
            if ($pk === 'enum' && !(self::def($vals) && AnalyzerJs::includes($vals, self::g($l, 's')))) {
                $bad('cond_enum', $w, 'enum literal is not a member');
            }
        } else {
            $bad('cond_type', $w, 'nested literal set');
        }
    }

    /** A cheap Allow witness for the checker: build an action from the grant's selector and conditions. */
    private static function allowWitness(mixed $o, mixed $g): bool
    {
        $ont = self::ontologyForGoal($o, $g);
        foreach (self::list(self::g($g, 'grants')) as $gr) {
            $w = GoalExamples::allowWitness($g, $gr, $ont);
            if ($w === null || self::isU($w)) {
                return false;
            }
        }
        return true;
    }

    // ---- slot typing and instantiation ----

    /** Number.isSafeInteger(n) (and n >= 0 unless signed), with -0 refused. */
    private static function safeN(mixed $n, bool $signed): bool
    {
        if (!Js::isNum($n)) {
            return false;
        }
        $f = (float)Js::num($n);
        if (!is_finite($f) || $f != floor($f) || abs($f) > self::MAX_SAFE || ($f == 0.0 && fdiv(1.0, $f) < 0)) {
            return false;
        }
        return $signed || $f >= 0;
    }

    private static function quantityOf(mixed $s, mixed $v): ?Obj
    {
        if (is_string($v) || self::isList($v)) {
            return null;
        }
        if (!$v instanceof Obj) {
            throw new \TypeError("cannot use 'in' operator on a non-object");
        }
        $kind = self::g($s, 'kind');
        if ($v->has('minor') && $kind === 'money' && self::eq(self::g($v, 'ccy'), self::g($s, 'ccy')) && self::safeN($v->get('minor'), false)) {
            return Obj::of(['u' => AnalyzerJs::uobj(['k' => 'money', 'ccy' => self::g($v, 'ccy')]), 'n' => $v->get('minor')]);
        }
        if ($v->has('n') && $kind === 'count' && self::safeN($v->get('n'), false)) {
            return Obj::of(['u' => Obj::of(['k' => 'count']), 'n' => $v->get('n')]);
        }
        if ($v->has('ms') && $kind === 'duration' && self::safeN($v->get('ms'), false)) {
            return Obj::of(['u' => Obj::of(['k' => 'duration']), 'n' => $v->get('ms')]);
        }
        if ($v->has('epoch_ms') && $kind === 'instant' && self::safeN($v->get('epoch_ms'), true)) {
            return Obj::of(['u' => Obj::of(['k' => 'instant']), 'n' => $v->get('epoch_ms')]);
        }
        return null;
    }

    private static function sv(mixed $s): Obj
    {
        return Obj::of(['k' => 's', 's' => $s]);
    }

    private static function idOk(mixed $x): bool
    {
        return is_string($x) && preg_match('/\A[A-Za-z0-9_-]+\z/', $x) === 1;
    }

    /**
     * Typed value(s) of a slot, or a reason string when it is missing / invalid (the slot then becomes a Hole); null for a slot kind
     * the reference switch does not handle. @return list<Obj>|string|null
     */
    public static function slotLits(mixed $o, mixed $s, mixed $v = null): array|string|null
    {
        if (func_num_args() < 3) {
            $v = self::undef();
        }
        if (self::isU($v)) {
            return 'missing';
        }
        $kind = self::g($s, 'kind');
        if (in_array($kind, ['money', 'count', 'duration', 'instant'], true)) {
            $q = self::quantityOf($s, $v);
            if ($q === null) {
                return 'ill-typed';
            }
            $mx = self::g($s, 'max');
            if (!self::isU($mx) && AnalyzerJs::jsGt($kind === 'instant' ? 0 : $q->get('n'), $mx)) {
                return 'above the template maximum';
            }
            return [Obj::of(['k' => 'q', 'q' => $q])];
        }
        if ($kind === 'id' || $kind === 'id_list') {
            $of = self::g($s, 'of');
            $pre = AnalyzerJs::oget(self::find(self::g($o, 'types'), static fn(mixed $t): bool => self::eq(self::g($t, 'id'), $of)), 'id_prefix');
            if ($kind === 'id') {
                return is_string($v) && self::truthy($pre) && self::sw($v, $pre) && Js::len($v) > Js::len($pre) && self::idOk($v) ? [self::sv($v)] : 'ill-typed';
            }
            if (self::isList($v) && $v !== []) {
                foreach ($v as $x) {
                    if (!(self::truthy($pre) && self::sw($x, $pre) && self::idOk($x))) {
                        return 'ill-typed';
                    }
                }
                return array_map(self::sv(...), $v);
            }
            return 'ill-typed';
        }
        $vals = self::g($s, 'values');
        if ($kind === 'enum') {
            return is_string($v) && self::def($vals) && AnalyzerJs::includes($vals, $v) ? [self::sv($v)] : 'ill-typed';
        }
        if ($kind === 'enum_list') {
            if (self::isList($v) && $v !== []) {
                foreach ($v as $x) {
                    if (!(self::def($vals) && AnalyzerJs::includes($vals, $x))) {
                        return 'ill-typed';
                    }
                }
                return array_map(self::sv(...), $v);
            }
            return 'ill-typed';
        }
        if ($kind === 'text_list') {
            if (self::isList($v) && $v !== []) {
                foreach ($v as $x) {
                    if (!(is_string($x) && $x !== '' && $x === self::nfkc($x) && !self::hasInvis($x))) {
                        return 'ill-typed';
                    }
                }
                return array_map(self::sv(...), $v);
            }
            return 'ill-typed';
        }
        return null;
    }

    private static function listSlot(mixed $t, mixed $name): bool
    {
        $s = self::find(self::g($t, 'slots'), static fn(mixed $x): bool => self::eq(self::g($x, 'name'), $name));
        $k = self::isU($s) || self::isU(self::g($s, 'kind')) ? '' : self::g($s, 'kind');
        return is_string($k) && str_ends_with($k, '_list');
    }

    /**
     * Template -> Goal (IR, canonical order). Mandatory slots that are missing or ill-typed become Holes; every clause depending on a
     * hole is dropped (the most restrictive completion); a prohibition that depends on a hole widens to every resource. Limits become
     * IR bounds over the surviving grants (admitting grant, lifetime window, session scope). `$opts`: {principal, nl, sources?}.
     */
    public static function instantiateTemplate(mixed $o, mixed $templateId, mixed $values, mixed $opts): mixed
    {
        $t = self::find(self::g($o, 'templates'), static fn(mixed $x): bool => self::eq(self::g($x, 'id'), $templateId));
        if (self::isU($t)) {
            throw new \InvalidArgumentException('unknown template ' . self::str($templateId));
        }
        /** @var array<string,mixed> $bound */
        $bound = [];
        $holes = [];
        foreach (self::list(self::g($t, 'slots')) as $s) {
            $name = self::g($s, 'name');
            $v = self::own($values, $name);
            $r = self::slotLits($o, $s, $v === null || self::isU($v) ? self::g($s, 'default') : $v);
            if (is_string($r)) {
                $ccy = self::g($s, 'ccy');
                $holes[] = AnalyzerJs::uobj([
                    'hid' => $name,
                    'q' => 'What is the ' . str_replace('_', ' ', self::str($name)) . ' (' . self::str(self::g($s, 'kind')) . (self::truthy($ccy) ? ' ' . self::str($ccy) : '') . ')? (' . $r . ')',
                    'domain' => [], 'affects' => [], 'global' => false,
                ]);
            } else {
                $bound[GoalJsSet::key($name)] = $r;
            }
        }
        $deps = static function (array $refs) use (&$bound): bool {
            foreach ($refs as $r) {
                if (!array_key_exists(GoalJsSet::key($r), $bound)) {
                    return false;
                }
            }
            return true;
        };
        $boundList = static function (mixed $name) use (&$bound): mixed {
            $k = GoalJsSet::key($name);
            if (!array_key_exists($k, $bound)) {
                throw new \TypeError("cannot read properties of undefined (reading '0')");
            }
            return $bound[$k];
        };
        $single = static function (mixed $name) use ($boundList): mixed {
            $l = $boundList($name);
            if (!is_array($l)) {
                throw new \TypeError("cannot read properties of undefined (reading '0')");
            }
            return $l[0] ?? self::undef();
        };
        $sub = static fn(mixed $i): mixed => self::sw($i, '$') ? self::g($single(substr($i, 1)), 's') : $i;
        $subPart = static function (mixed $r) use ($sub): mixed {
            $k = self::g($r, 'k');
            if ($k === 'exact') {
                return AnalyzerJs::uobj(['k' => 'exact', 'id' => $sub(self::g($r, 'id'))]);
            }
            if ($k === 'oneof') {
                return AnalyzerJs::uobj(['k' => 'oneof', 'ids' => array_map($sub, self::list(self::g($r, 'ids')))]);
            }
            $m = AnalyzerJs::spread($r);
            $m->set('anchor', $sub(self::g($r, 'anchor')));
            return $m;
        };
        $subRes = static function (mixed $r) use ($subPart): mixed {
            $k = self::g($r, 'k');
            if ($k === 'any') {
                return $r;
            }
            if ($k === 'all_of') {
                return Obj::of(['k' => 'all_of', 'parts' => array_map($subPart, self::list(self::g($r, 'parts')))]);
            }
            return $subPart($r);
        };
        $verbOf = [];
        foreach (self::list(self::g($o, 'verbs')) as $v) {
            $verbOf[GoalJsSet::key(self::g($v, 'id'))] ??= $v;
        }
        $tyOf = static function (mixed $verb, mixed $path, mixed $ccy) use ($o, $verbOf): Obj {
            $vk = $verb === null || self::isU($verb) ? null : GoalJsSet::key($verb);
            $p = $vk !== null && array_key_exists($vk, $verbOf) ? self::own(self::g($verbOf[$vk], 'params'), $path) : self::undef();
            if (self::isU($p) || $p === null) {
                $p = self::undef();
                foreach (self::list(self::g($o, 'verbs')) as $v) {
                    $x = self::own(self::g($v, 'params'), $path);
                    if (!self::isU($x)) {
                        $p = $x;
                        break;
                    }
                }
            }
            if (!self::truthy($p)) {
                throw new \InvalidArgumentException('parameter ' . self::str($path) . ' is not declared by any verb');
            }
            return self::paramTy($p, $ccy);
        };
        $lit = static function (mixed $x) use ($boundList, $single, $t): mixed {
            $k = self::g($x, 'k');
            if ($k === 'slot') {
                $l = $boundList(self::g($x, 'slot'));
                return Obj::of(['k' => 'lit', 'v' => self::listSlot($t, self::g($x, 'slot')) ? AnalyzerJs::uobj(['k' => 'set', 'items' => $l ?? self::undef()]) : $single(self::g($x, 'slot'))]);
            }
            return $k === 'lit' ? AnalyzerJs::uobj(['k' => 'lit', 'v' => self::g($x, 'v')]) : null;
        };
        $ccyOf = static function (mixed $x): mixed {
            if ($x !== null && self::g($x, 'k') === 'lit' && self::g(self::g($x, 'v'), 'k') === 'q' && self::g(self::g(self::g(self::g($x, 'v'), 'q'), 'u'), 'k') === 'money') {
                return self::g(self::g(self::g(self::g($x, 'v'), 'q'), 'u'), 'ccy');
            }
            return null;
        };
        $subCond = static function (mixed $c, mixed $verb) use (&$subCond, $lit, $ccyOf, $tyOf): mixed {
            $k = self::g($c, 'k');
            if ($k === 'true') {
                return $c;
            }
            if ($k === 'and' || $k === 'or') {
                return Obj::of(['k' => $k, 'a' => $subCond(self::g($c, 'a'), $verb), 'b' => $subCond(self::g($c, 'b'), $verb)]);
            }
            if ($k === 'not') {
                return Obj::of(['k' => 'not', 'c' => $subCond(self::g($c, 'c'), $verb)]);
            }
            $lv = $lit(self::g($c, 'l'));
            $rv = $lit(self::g($c, 'r'));
            $hint = $ccyOf($lv);
            $hint ??= $ccyOf($rv);
            $term = static function (mixed $x, mixed $v) use ($tyOf, $verb, $hint): mixed {
                if ($v !== null) {
                    return $v;
                }
                $path = self::g($x, 'path');
                return AnalyzerJs::uobj(['k' => 'param', 'path' => $path, 'ty' => $tyOf($verb, $path, $hint)]);
            };
            return AnalyzerJs::uobj(['k' => 'cmp', 'op' => self::g($c, 'op'), 'l' => $term(self::g($c, 'l'), $lv), 'r' => $term(self::g($c, 'r'), $rv)]);
        };
        $dropped = new GoalJsSet();
        $grants = [];
        $tBounds = self::list(self::g($t, 'bounds'));
        $tGrants = self::list(self::g($t, 'grants'));
        $keep = [];
        foreach ($tBounds as $i => $b) {
            $keep[$i] = $deps(self::refsBound($b));
        }
        foreach ($tBounds as $i => $b) {
            if ($keep[$i]) {
                continue;
            }
            foreach ($tGrants as $g) {
                $over = self::g($b, 'over');
                if (self::eq($over, 'all') || AnalyzerJs::includes($over, self::g($g, 'gid'))) {
                    $dropped->add(self::g($g, 'gid'));
                }
            }
        }
        foreach ($tGrants as $g) {
            if ($dropped->has(self::g($g, 'gid')) || !$deps(self::refsGrant($g))) {
                $dropped->add(self::g($g, 'gid'));
            } else {
                $grants[] = AnalyzerJs::uobj(['gid' => self::g($g, 'gid'), 'verb' => self::g($g, 'verb'), 'res' => $subRes(self::g($g, 'res')), 'cond' => $subCond(self::g($g, 'cond'), self::g($g, 'verb'))]);
            }
        }
        $prohibits = [];
        foreach (self::list(self::g($t, 'prohibits')) as $p) {
            $tg = self::g($p, 'target');
            if (self::g($tg, 'k') === 'verb') {
                $verb = self::g($tg, 'verb');
            } else {
                $cls = self::g($tg, 'cls');
                $fv = self::find(self::g($o, 'verbs'), static fn(mixed $v): bool => self::eq(self::g($v, 'effect'), $cls));
                $verb = AnalyzerJs::oget($fv, 'id');
                $verb = self::isU($verb) ? null : $verb;
            }
            if ($deps(self::refsGrant($p))) {
                $prohibits[] = AnalyzerJs::uobj(['pid' => self::g($p, 'pid'), 'target' => $tg, 'res' => $subRes(self::g($p, 'res')), 'cond' => $subCond(self::g($p, 'cond'), $verb)]);
            } else {
                $prohibits[] = AnalyzerJs::uobj(['pid' => self::g($p, 'pid'), 'target' => $tg, 'res' => Obj::of(['k' => 'any', 'reason' => 'hole']), 'cond' => Obj::of(['k' => 'true'])]);
            }
        }
        $kept = array_map(static fn(Obj $g): mixed => self::g($g, 'gid'), $grants);
        $bounds = [];
        foreach ($tBounds as $i => $b) {
            if (!$keep[$i]) {
                continue;
            }
            $over = self::g($b, 'over');
            if (self::eq($over, 'all')) {
                $gids = $kept;
            } else {
                $gids = [];
                foreach (self::list($over) as $x) {
                    if (AnalyzerJs::includes($kept, $x)) {
                        $gids[] = $x;
                    }
                }
            }
            if ($gids === []) {
                continue;
            }
            $cs = self::g($b, 'cap_slot');
            $capLit = self::truthy($cs) ? $single($cs) : null;
            $cap = $capLit !== null && self::g($capLit, 'k') === 'q' ? self::g($capLit, 'q') : self::g($b, 'cap');
            $verb = null;
            foreach ($grants as $g) {
                if (self::eq(self::g($g, 'gid'), $gids[0])) {
                    $verb = self::g($g, 'verb');
                    break;
                }
            }
            if ($verb === null) {
                throw new \TypeError("cannot read properties of undefined (reading 'verb')");
            }
            $agg = self::g($b, 'agg');
            $capu = self::g($cap, 'u');
            $bounds[] = AnalyzerJs::uobj([
                'bid' => self::g($b, 'bid'), 'sel' => Obj::of(['k' => 'gids', 'gids' => $gids]), 'agg' => $agg,
                'value' => $agg === 'sum'
                    ? AnalyzerJs::uobj(['k' => 'param', 'path' => self::g($b, 'param'), 'ty' => $tyOf($verb, self::g($b, 'param'), self::g($capu, 'k') === 'money' ? self::g($capu, 'ccy') : null)])
                    : Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'count']), 'n' => 1])])]),
                'key' => '', 'window' => Obj::of(['k' => 'lifetime']), 'scope' => Obj::of(['k' => 'session']), 'cap' => $cap, 'onExceed' => self::g($b, 'onExceed'),
            ]);
        }
        $srcs = self::g($opts, 'sources');
        return GoalNormalize::canonicalizeGoal(AnalyzerJs::uobj([
            'v' => 1, 'principal' => self::g($opts, 'principal'), 'ontDigest' => self::ontologyDigest($o), 'nlDigest' => GoalDigests::nlDigest(self::g($opts, 'nl')),
            'sources' => self::def($srcs) ? self::list($srcs) : [],
            'grants' => $grants, 'prohibits' => $prohibits, 'bounds' => $bounds,
            'validity' => Obj::of(['notBefore' => 0, 'notAfter' => self::FOREVER, 'maxIdle' => 0]),
            'deleg' => Obj::of(['maxDepth' => 0, 'narrowOnly' => true, 'mayTouch' => []]),
            'escalateOn' => [], 'wildcardAck' => [], 'holes' => $holes,
        ]));
    }

    // ---- locale-aware human number parsing (interpreter front end only; the IR has no locale) ----

    /** @param mixed $locale 'en' reads ',' as thousands, 'de' reads '.' as thousands */
    public static function parseHumanAmount(mixed $text, mixed $exponent, mixed $locale = null): Obj
    {
        if (!is_string($text)) {
            throw new \TypeError('text.normalize is not a function');
        }
        if (!Js::isNum($exponent)) {
            throw new \TypeError('exponent is not a number');
        }
        $ex = (float)Js::num($exponent);
        $t = (string)preg_replace('/[^0-9.,]/', '', self::trim(self::nfkc($text)));
        $fail = static fn(string $r): Obj => Obj::of(['ok' => false, 'reason' => $r]);
        if (preg_match('/\A[0-9][0-9.,]*\z/', $t) !== 1 || preg_match('/[.,]{2}/', $t) === 1) {
            return $fail('not a number');
        }
        $lastDot = strrpos($t, '.');
        $lastDot = $lastDot === false ? -1 : $lastDot;
        $lastComma = strrpos($t, ',');
        $lastComma = $lastComma === false ? -1 : $lastComma;
        $dec = null;
        $thou = null;
        if ($lastDot >= 0 && $lastComma >= 0) {
            $dec = $lastDot > $lastComma ? '.' : ',';
            $thou = $dec === '.' ? ',' : '.';
        } elseif ($lastDot >= 0 || $lastComma >= 0) {
            $sep = $lastDot >= 0 ? '.' : ',';
            $parts = explode($sep, $t);
            $groupLike = count($parts) > 2 || strlen($parts[count($parts) - 1]) === 3;
            if (!$groupLike) {
                $dec = $sep;
            } elseif (count($parts) > 2) {
                $thou = $sep;
            } elseif (self::truthy($locale)) {
                if (($locale === 'en') === ($sep === ',')) {
                    $thou = $sep;
                } else {
                    $dec = $sep;
                }
            } else {
                return $fail('ambiguous separator');
            }
        }
        $intPart = $t;
        $frac = '';
        if ($dec !== null) {
            $i = (int)strrpos($t, $dec);
            $intPart = substr($t, 0, $i);
            $frac = substr($t, $i + 1);
        }
        if ($thou !== null) {
            $groups = explode($thou, $intPart);
            foreach (array_slice($groups, 1) as $gp) {
                if (strlen($gp) !== 3) {
                    return $fail('malformed grouping');
                }
            }
            if ($groups[0] === '' || strlen($groups[0]) > 3) {
                return $fail('malformed grouping');
            }
            $intPart = implode('', $groups);
        }
        if ((float)strlen($frac) > $ex) {
            return $fail('more decimals than the currency allows');
        }
        $digits = ltrim($intPart . str_pad($frac, (int)max(0.0, $ex), '0', STR_PAD_RIGHT), '0');
        $digits = $digits === '' ? '0' : $digits;
        if (strlen($digits) > 16 || (strlen($digits) === 16 && strcmp($digits, '9007199254740991') > 0)) {
            return $fail('out of range');
        }
        return Obj::of(['ok' => true, 'minor' => (int)$digits]);
    }

    /**
     * The strict front-end contract over parseHumanAmount: only digits, '.' and ',' after one optional leading currency symbol; with a
     * locale, a decimal separator that contradicts it is refused; without one, a repeated or ambiguous separator is a Hole, not a guess.
     */
    public static function parseMoney(mixed $text, mixed $exponent, mixed $locale): Obj
    {
        $t = (string)preg_replace('/\A(?:\$|\xE2\x82\xAC|\xC2\xA3)' . self::WS . '*/', '', self::trim(self::str($text)));
        $bad = Obj::of(['error' => 'BAD_NUMBER']);
        if (preg_match('/\A[0-9][0-9.,]*\z/', $t) !== 1) {
            return $bad;
        }
        $locale = $locale instanceof Undef ? null : $locale;
        $both = str_contains($t, '.') && str_contains($t, ',');
        if ($locale !== null && $both && $t[max((int)strrpos($t, '.'), (int)strrpos($t, ','))] !== ($locale === 'en' ? '.' : ',')) {
            return $bad;
        }
        if ($locale === null && !$both && preg_match_all('/[.,]/', $t) > 1) {
            return Obj::of(['hole' => 'AMBIGUOUS_NUMBER']);
        }
        $r = self::parseHumanAmount($t, $exponent, $locale);
        if ($r->get('ok') === true) {
            return Obj::of(['minor' => $r->get('minor')]);
        }
        return $r->get('reason') === 'ambiguous separator' ? Obj::of(['hole' => 'AMBIGUOUS_NUMBER']) : $bad;
    }
}
