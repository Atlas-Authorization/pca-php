<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Js.php';

/** Where the drafting importers resolve `#/...` references and report what they could not represent. */
final class DraftCtx
{
    /** @param list<string> $todo */
    public function __construct(public mixed $root, public array $todo = [], public ?int $left = null)
    {
    }
}

/**
 * Value-dependent reversibility, the wallet floor test and the DRAFTING importers of the action schema: an MCP `tools/list` or an OpenAPI document
 * becomes a draft schema plus the `todo` list of decisions the developer must make before signing (semantic types, sensitivities, units,
 * reversibility). Local `$ref`s are followed, `allOf` is merged and `anyOf` / `oneOf` collapse to the single non-null variant or to the union of
 * string constants; whatever stays unrepresentable is declared `string` and flagged. Both importers are pure over JSON. (The signing, key, digest and
 * verification quartet and the conformance checks are in {@see IntentV2Schema} and {@see SignersMore}.)
 */
final class ActionSchemaDraft
{
    public const WELL_KNOWN_PCA_ACTIONS_PATH = '/.well-known/pca-actions.json';
    private const MAX_REF_DEPTH = 8;
    private const MAX_REF_NODES = 20000;
    private const REV_RANK = ['reversible' => 0, 'rate_limited' => 1, 'irreversible' => 2];

    private static function safeInt(mixed $x): bool
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) && $f == floor($f) && abs($f) <= 9007199254740991.0;
    }

    /** `isInt` of the reference: a safe integer that is not negative zero. */
    private static function isInt(mixed $x): bool
    {
        $f = Js::num($x);
        return self::safeInt($x) && !($f === 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function own(mixed $o, string $k): bool
    {
        return $o instanceof Obj && $o->has($k);
    }

    // ---- value-dependent reversibility, the wallet floor ----------------------------------------------------------

    /** rev(v, omega): the value-dependent class (an unmapped or absent value is the declared default, else irreversible: fail closed). */
    public static function reversibilityOf(mixed $v, mixed $params): mixed
    {
        $by = Jsx::get($v, 'reversibility_by');
        if (Jsx::truthy($by)) {
            $pm = Jsx::get($by, 'param');
            if (!is_string($pm)) {
                throw new \TypeError('param.slice is not a function');
            }
            $name = self::sliceUnits($pm, strlen('action.params.'));
            $k = null;
            if (self::own($params, $name)) {
                $x = $params->get($name);
                $k = is_string($x) ? $x : (is_bool($x) ? ($x ? 'true' : 'false') : (self::isInt($x) ? Jsx::str($x) : null));
            }
            $map = Jsx::get($by, 'map');
            if ($k !== null && self::own($map, $k)) {
                return $map->get($k);
            }
            $d = Jsx::get($by, 'default');
            return $d instanceof Undef || $d === null ? 'irreversible' : $d;
        }
        $r = Jsx::get($v, 'reversibility');
        if (!($r instanceof Undef) && $r !== null) {
            return $r;
        }
        return Jsx::get($v, 'kind') === 'read' ? 'reversible' : 'irreversible';
    }

    /** `s.slice(n)` over UTF-16 units of a string (`n` ASCII prefix units here). */
    private static function sliceUnits(string $s, int $from): string
    {
        return (string)mb_substr($s, $from, null, 'UTF-8');
    }

    /** `floorApplies`: the semantic type is on the wallet floor (exact match, or a prefix). `$floor`: `{prefixes?, exact?}` or null. */
    public static function floorApplies(mixed $semantic, mixed $floor = null): bool
    {
        $pre = Jsx::get($floor, 'prefixes');
        $pre = $pre instanceof Undef || $pre === null ? IntentSchema::WALLET_FLOOR_PREFIXES : Jsx::iter($pre);
        $ex = Jsx::get($floor, 'exact');
        $ex = $ex instanceof Undef || $ex === null ? IntentSchema::WALLET_FLOOR_EXACT : Jsx::iter($ex);
        if (in_array($semantic, $ex, true)) {
            return true;
        }
        foreach ($pre as $p) {
            if (!is_string($semantic)) {
                throw new \TypeError('semantic.startsWith is not a function');
            }
            if (str_starts_with($semantic, Jsx::str($p))) {
                return true;
            }
        }
        return false;
    }

    // ---- JSON-schema flattening -----------------------------------------------------------------------------------

    /** A local `#/a/b` JSON pointer in `$root`; absent when not local, not found or not an object. */
    private static function pointer(mixed $root, string $ref): mixed
    {
        Jsx::init();
        if (!str_starts_with($ref, '#/')) {
            return Jsx::$U;
        }
        $cur = $root;
        foreach (explode('/', substr($ref, 2)) as $raw) {
            $seg = str_replace(['~1', '~0'], ['/', '~'], $raw);
            if ($cur instanceof Obj) {
                if (!$cur->has($seg)) {
                    return Jsx::$U;
                }
                $cur = $cur->get($seg);
            } elseif (is_array($cur) && array_is_list($cur) && preg_match('/\A(?:0|[1-9][0-9]*)\z/', $seg) === 1 && (int)$seg < count($cur)) {
                $cur = $cur[(int)$seg];
            } else {
                return Jsx::$U;
            }
        }
        return $cur instanceof Obj || is_array($cur) ? $cur : Jsx::$U;
    }

    private static function clip(string $s, int $n): string
    {
        return (string)mb_substr($s, 0, $n, 'UTF-8');
    }

    private static function copyInto(Obj $into, mixed $from): void
    {
        $f = Jsx::spread($from);
        foreach ($f->keys() as $k) {
            $into->set($k, $f->get($k));
        }
    }

    /** The importer's reading of a schema node: `$ref` followed, `allOf` merged, `anyOf` / `oneOf` collapsed (see the class comment). */
    private static function flatten(mixed $s, DraftCtx $c, string $where, int $depth = 0): Obj
    {
        if (!($s instanceof Obj) && !is_array($s)) {
            return new Obj();
        }
        $c->left = ($c->left ?? self::MAX_REF_NODES) - 1;
        if ($c->left < 0) {
            if ($c->left === -1) {
                $c->todo[] = "$where: schema expansion stopped after " . self::MAX_REF_NODES . ' nodes (declared string; refine or drop)';
            }
            return new Obj();
        }
        if ($depth > self::MAX_REF_DEPTH) {
            $c->todo[] = "$where: schema nesting or reference chain deeper than " . self::MAX_REF_DEPTH . ' (declared string; refine or drop)';
            return new Obj();
        }
        $cur = $s instanceof Obj ? $s : new Obj();
        $ref = Jsx::get($cur, '$ref');
        if (is_string($ref)) {
            $target = self::pointer($c->root, $ref);
            if ($target instanceof Undef) {
                $c->todo[] = "$where: reference '" . self::clip($ref, 120) . "' is not a local reference that resolves (declared string; refine or drop)";
                return new Obj();
            }
            $merged = Jsx::spread(self::flatten($target, $c, $where, $depth + 1)); // a copy: `{...target, ...siblings}` never writes into the referenced schema
            self::copyInto($merged, $cur->without('$ref'));
            $cur = $merged;
        }
        $all = Jsx::get($cur, 'allOf');
        if (is_array($all) && array_is_list($all)) {
            $rest = $cur->without('allOf');
            $acc = new Obj();
            foreach ($all as $m) {
                $f = self::flatten($m, $c, $where, $depth + 1);
                $next = Jsx::spread($acc);
                self::copyInto($next, $f);
                $props = new Obj();
                self::copyInto($props, Jsx::get($acc, 'properties'));
                self::copyInto($props, Jsx::get($f, 'properties'));
                $req = [];
                foreach ([Jsx::get($acc, 'required'), Jsx::get($f, 'required')] as $r) {
                    foreach ($r instanceof Undef || $r === null ? [] : Jsx::iter($r) as $x) {
                        $req[] = $x;
                    }
                }
                $next->set('properties', $props);
                $next->set('required', $req);
                $acc = $next;
            }
            $cur = Jsx::spread($acc);
            self::copyInto($cur, $rest);
        }
        $alts = Jsx::get($cur, 'anyOf');
        if ($alts instanceof Undef || $alts === null) {
            $alts = Jsx::get($cur, 'oneOf');
        }
        if (is_array($alts) && array_is_list($alts)) {
            $rest = $cur->without('anyOf', 'oneOf');
            $live = [];
            foreach ($alts as $m) {
                $f = self::flatten($m, $c, $where, $depth + 1);
                $t = Jsx::get($f, 'type');
                $isNull = $t === 'null' || (is_array($t) && array_is_list($t) && count(array_filter($t, static fn($x): bool => $x !== 'null')) === 0);
                if (!$isNull) {
                    $live[] = $f;
                }
            }
            if (count($live) === 1) {
                $out = Jsx::spread($live[0]);
                self::copyInto($out, $rest);
                return $out;
            }
            $consts = [];
            foreach ($live as $m) {
                $k = Jsx::get($m, 'const');
                $e = Jsx::get($m, 'enum');
                $consts[] = is_string($k) ? [$k] : (is_array($e) && array_is_list($e) && count(array_filter($e, 'is_string')) === count($e) ? $e : null);
            }
            if (count($live) > 1 && !in_array(null, $consts, true)) {
                $out = Jsx::spread($rest);
                $out->set('type', 'string');
                $out->set('enum', array_values(array_unique(array_merge(...$consts))));
                return $out;
            }
            $c->todo[] = "$where: a union of " . count($live) . ' schemas has no schema representation (declared string; refine or drop)';
            return $rest;
        }
        $k = Jsx::get($cur, 'const');
        if (!($k instanceof Undef) && Jsx::get($cur, 'enum') instanceof Undef && is_string($k)) {
            $cur = Jsx::spread($cur);
            $cur->set('enum', [$k]);
        }
        return $cur;
    }

    private static function description(mixed $d): string
    {
        if (!is_string($d)) {
            throw new \TypeError('s.description.slice is not a function');
        }
        return self::clip($d, 1024);
    }

    /** @return ?list<string> */
    private static function stringList(mixed $v): ?array
    {
        return is_array($v) && array_is_list($v) && count(array_filter($v, 'is_string')) === count($v) ? $v : null;
    }

    /** JSON Schema property -> parameter declaration; sensitivity defaults to `material`; unrepresentable shapes become flagged `string` placeholders. */
    private static function declOf(string $name, mixed $schema, bool $required, DraftCtx $c): Obj
    {
        $s = self::flatten($schema, $c, "action.params.$name");
        $ty = Jsx::get($s, 'type');
        $t = $ty;
        if (is_array($ty) && array_is_list($ty)) {
            $t = Jsx::$U;
            foreach ($ty as $x) {
                if ($x !== 'null') {
                    $t = $x;
                    break;
                }
            }
        }
        $sem = Jsx::get($s, 'x-pca-semantic');
        $sen = Jsx::get($s, 'x-pca-sensitivity');
        $base = Obj::of(['semantic' => $sem instanceof Undef || $sem === null ? 'unknown' : $sem, 'sensitivity' => $sen instanceof Undef || $sen === null ? 'material' : $sen]);
        if (!$required) {
            $base->set('required', false);
        }
        if (Jsx::truthy(Jsx::get($s, 'description'))) {
            $base->set('description', self::description(Jsx::get($s, 'description')));
        }
        if (!Jsx::truthy($sem)) {
            $c->todo[] = "action.params.$name: semantic type";
        }
        $enumStrings = self::stringList(Jsx::get($s, 'enum'));
        $mk = static function (string $type, ?Obj $extra = null) use ($base): Obj {
            $o = Obj::of(['type' => $type]);
            foreach ($base->keys() as $k) {
                $o->set($k, $base->get($k));
            }
            foreach ($extra === null ? [] : $extra->keys() as $k) {
                $o->set($k, $extra->get($k));
            }
            return $o;
        };
        if ($t === 'integer') {
            $x = new Obj();
            $min = Jsx::get($s, 'minimum');
            $emin = Jsx::get($s, 'exclusiveMinimum');
            $max = Jsx::get($s, 'maximum');
            $emax = Jsx::get($s, 'exclusiveMaximum');
            if (self::safeInt($min)) {
                $x->set('min', $min);
            } elseif (self::safeInt($emin)) {
                $x->set('min', Sign::n(Js::num($emin) + 1));
            }
            if (self::safeInt($max)) {
                $x->set('max', $max);
            } elseif (self::safeInt($emax)) {
                $x->set('max', Sign::n(Js::num($emax) - 1));
            }
            if (Jsx::truthy(Jsx::get($s, 'x-pca-unit'))) {
                $x->set('unit', Jsx::get($s, 'x-pca-unit'));
            }
            if (Jsx::truthy(Jsx::get($s, 'x-pca-accumulates-into'))) {
                $x->set('accumulates_into', Jsx::get($s, 'x-pca-accumulates-into'));
            }
            return $mk('integer', $x);
        }
        if ($t === 'boolean') {
            return $mk('boolean');
        }
        if ($t === 'string' && Jsx::get($s, 'format') === 'date') {
            return $mk('date');
        }
        if ($t === 'string') {
            $x = new Obj();
            if ($enumStrings !== null) {
                $x->set('values', $enumStrings);
            }
            $ml = Jsx::get($s, 'maxLength');
            if (self::safeInt($ml) && Js::num($ml) > 0) {
                $x->set('max_len', $ml);
            }
            return $mk('string', $x);
        }
        if ($t === 'array') {
            $it = self::flatten(Jsx::get($s, 'items'), $c, "action.params.$name" . '[]');
            $itEnum = self::stringList(Jsx::get($it, 'enum'));
            $minI = Jsx::get($s, 'minItems');
            $maxI = Jsx::get($s, 'maxItems');
            if (Jsx::truthy(Jsx::get($s, 'uniqueItems')) && $itEnum !== null) {
                $x = Obj::of(['values' => $itEnum]);
                if (self::safeInt($minI)) {
                    $x->set('min_items', $minI);
                }
                if (self::safeInt($maxI)) {
                    $x->set('max_items', $maxI);
                }
                return $mk('set', $x);
            }
            $itT = Jsx::get($it, 'type');
            $itT = is_array($itT) && array_is_list($itT) ? ($itT[0] ?? Jsx::$U) : $itT;
            $x = new Obj();
            if ($itT === 'integer') {
                $x->set('items', 'integer');
            }
            if (self::safeInt($maxI)) {
                $x->set('max_items', $maxI);
            }
            if (self::safeInt($minI)) {
                $x->set('min_items', $minI);
            }
            return $mk('array', $x);
        }
        $c->todo[] = "action.params.$name: type '" . Jsx::str($t) . "' has no schema representation (declared string; refine or drop)";
        return $mk('string');
    }

    /** MCP annotations give a LOWER bound on reversibility (hints never lower a classification). @return array{kind:string,atLeast:string} */
    public static function reversibilityFromMcpHints(mixed $annotations): array
    {
        if (Jsx::get($annotations, 'readOnlyHint') === true) {
            return ['kind' => 'read', 'atLeast' => 'reversible'];
        }
        if (Jsx::get($annotations, 'destructiveHint') === true) {
            return ['kind' => 'write', 'atLeast' => 'rate_limited'];
        }
        return ['kind' => 'write', 'atLeast' => 'reversible'];
    }

    /** @param list<Obj> $verbs */
    private static function result(array $verbs, mixed $site, array $todo): Obj
    {
        usort($verbs, static fn(Obj $a, Obj $b): int => IntentWb::compareUtf8(Jsx::str($a->get('verb')), Jsx::str($b->get('verb'))));
        return Obj::of(['schema' => Obj::of(['v' => 1, 'kind' => IntentV2::ACTION_SCHEMA_KIND, 'site' => Jsx::get($site, 'site'), 'aud' => Jsx::get($site, 'aud'),
            'version' => Jsx::get($site, 'version'), 'verbs' => $verbs]), 'todo' => $todo]);
    }

    /** @return list<string> the keys of an object, ordered bytewise over UTF-8 */
    private static function sortedKeys(mixed $o): array
    {
        $k = Jsx::keys($o);
        usort($k, static fn(string $a, string $b): int => IntentWb::compareUtf8($a, $b));
        return $k;
    }

    /**
     * Draft schema from an MCP `tools/list`: verb = prefix + tool name; every write verb is drafted `irreversible` (a destructive hint keeps it at least
     * `rate_limited`). `$site`: `{site, aud, version, verbPrefix?}`. @return Obj `{schema, todo}`
     */
    public static function draftSchemaFromMcpTools(mixed $tools, mixed $site): Obj
    {
        $verbs = [];
        $c = new DraftCtx(null, []);
        foreach (Jsx::iter($tools) as $t) {
            $name = Jsx::str(Jsx::rd($t, 'name'));
            $input = Jsx::get($t, 'inputSchema');
            $c->root = $input;
            $c->left = null;
            $flat = self::flatten($input, $c, "$name: inputSchema");
            $props = Jsx::get($flat, 'properties');
            $props = $props instanceof Undef || $props === null ? new Obj() : $props;
            $rq = Jsx::get($flat, 'required');
            $req = [];
            foreach ($rq instanceof Undef || $rq === null ? [] : Jsx::iter($rq) as $x) {
                $req[Jsx::str($x)] = true;
            }
            $params = new Obj();
            foreach (self::sortedKeys($props) as $n) {
                if (preg_match('/\A[A-Za-z0-9_]{1,64}\z/', $n) !== 1) {
                    $c->todo[] = "$name: parameter '$n' is not a schema name ([A-Za-z0-9_]{1,64}); rename it";
                    continue;
                }
                $params->set("action.params.$n", self::declOf($n, Jsx::get($props, $n), isset($req[$n]), $c));
            }
            $h = self::reversibilityFromMcpHints(Jsx::get($t, 'annotations'));
            $pf = Jsx::get($site, 'verbPrefix');
            $verb = ($pf instanceof Undef || $pf === null ? '' : Jsx::str($pf)) . $name;
            if ($h['kind'] === 'write') {
                $c->todo[] = "$verb: reversibility (drafted irreversible)";
            }
            $v = Obj::of(['verb' => $verb, 'kind' => $h['kind'], 'params' => $params, 'reversibility' => $h['kind'] === 'read' ? 'reversible' : 'irreversible', 'mcp' => Obj::of(['tool' => Jsx::get($t, 'name')])]);
            if (Jsx::truthy(Jsx::get($t, 'description'))) {
                $v->set('description', self::description(Jsx::get($t, 'description')));
            }
            $verbs[] = $v;
        }
        $todo = $c->todo;
        return self::result($verbs, $site, $todo);
    }

    /** The JSON media type of a request body: `application/json` first, else any `application/*+json`. */
    private static function jsonBodySchema(mixed $b): mixed
    {
        $content = Jsx::get($b, 'content');
        if (!($content instanceof Obj) && !is_array($content)) {
            return Jsx::$U;
        }
        $keys = self::sortedKeys($content);
        $key = null;
        foreach ($keys as $k) {
            if (strtolower($k) === 'application/json') {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            foreach ($keys as $k) {
                if (preg_match('/\Aapplication\/[^;]*\+json(;|\z)/i', $k) === 1) {
                    $key = $k;
                    break;
                }
            }
        }
        return $key === null ? Jsx::$U : Jsx::get(Jsx::get($content, $key), 'schema');
    }

    /**
     * Draft schema from OpenAPI: one verb per operation with an `operationId` (`x-pca-verb` names it); the parameters are its path and query parameters
     * (path-item parameters included, the operation's own winning) plus the properties of its JSON request body (which wins a name clash); header and
     * cookie parameters are flagged. `$site`: `{site, aud, version}`. @return Obj `{schema, todo}`
     */
    public static function draftSchemaFromOpenApi(mixed $doc, mixed $site): Obj
    {
        Jsx::init();
        $verbs = [];
        $c = new DraftCtx($doc, []);
        $deref = static function (mixed $x) use ($doc, $c): mixed {
            if (!($x instanceof Obj) && !is_array($x)) {
                return Jsx::$U;
            }
            $r = Jsx::get($x, '$ref');
            if (!is_string($r)) {
                return $x;
            }
            $t = self::pointer($doc, $r);
            if ($t instanceof Undef) {
                $c->todo[] = "reference '" . self::clip($r, 120) . "' is not a local reference that resolves";
            }
            return $t;
        };
        $seen = [];
        $paths = Jsx::get($doc, 'paths');
        $paths = $paths instanceof Undef || $paths === null ? new Obj() : $paths;
        foreach (self::sortedKeys($paths) as $path) {
            $ops = Jsx::get($paths, $path);
            $sp = Jsx::get($ops, 'parameters');
            $shared = is_array($sp) && array_is_list($sp) ? $sp : [];
            foreach (self::sortedKeys($ops) as $method) {
                $op = Jsx::get($ops, $method);
                if (!($op instanceof Obj) || !Jsx::truthy(Jsx::get($op, 'operationId'))) {
                    continue;
                }
                $opId = Jsx::str(Jsx::get($op, 'operationId'));
                $c->left = self::MAX_REF_NODES;
                $xk = Jsx::get($op, 'x-pca-kind');
                $read = Jsx::truthy($xk) ? $xk === 'read' : (strtolower($method) === 'get' || strtolower($method) === 'head');
                $xv = Jsx::get($op, 'x-pca-verb');
                $verb = Jsx::str($xv instanceof Undef || $xv === null ? Jsx::get($op, 'operationId') : $xv);
                if (isset($seen[$verb])) {
                    $c->todo[] = "$verb: declared by more than one operation; give each a distinct x-pca-verb";
                }
                $seen[$verb] = true;
                $params = new Obj();
                $addName = static function (string $name, mixed $sch, bool $required, string $source) use ($params, $c, $opId): void {
                    if (preg_match('/\A[A-Za-z0-9_]{1,64}\z/', $name) !== 1) {
                        $c->todo[] = "$opId: parameter '$name' is not a schema name; rename it";
                        return;
                    }
                    if ($params->has("action.params.$name")) {
                        $c->todo[] = "$opId: '$name' is declared by both the $source and another source; kept the first";
                        return;
                    }
                    $params->set("action.params.$name", self::declOf($name, $sch, $required, $c));
                };
                // the request body first (it wins a name clash), then the operation's own parameters over the path item's; the importer's own notes interleave in order
                $body = self::flatten(self::jsonBodySchema($deref(Jsx::get($op, 'requestBody'))), $c, "$opId: request body");
                $bprops = Jsx::get($body, 'properties');
                $bprops = $bprops instanceof Undef || $bprops === null ? new Obj() : $bprops;
                $br = Jsx::get($body, 'required');
                $breq = [];
                foreach ($br instanceof Undef || $br === null ? [] : Jsx::iter($br) as $x) {
                    $breq[Jsx::str($x)] = true;
                }
                foreach (self::sortedKeys($bprops) as $n) {
                    $addName($n, Jsx::get($bprops, $n), isset($breq[$n]), 'request body');
                }
                $merged = [];
                $own = Jsx::get($op, 'parameters');
                foreach (array_merge($shared, is_array($own) && array_is_list($own) ? $own : []) as $raw) {
                    $q = $deref($raw);
                    if (!is_string(Jsx::get($q, 'name')) || !is_string(Jsx::get($q, 'in'))) {
                        continue;
                    }
                    $merged[Jsx::get($q, 'in') . ':' . Jsx::get($q, 'name')] = $q;
                }
                $keys = array_map('strval', array_keys($merged));
                usort($keys, static fn(string $a, string $b): int => IntentWb::compareUtf8($a, $b));
                foreach ($keys as $key) {
                    $q = $merged[$key];
                    $in = Jsx::get($q, 'in');
                    if ($in !== 'path' && $in !== 'query') {
                        $c->todo[] = "$opId: $in parameter '" . Jsx::get($q, 'name') . "' is not an action parameter (the schema sees path, query and body parameters only)";
                        continue;
                    }
                    $qs = Jsx::get($q, 'schema');
                    $sch = Jsx::spread(Jsx::truthy($qs) ? $qs : new Obj());
                    $qd = Jsx::get($q, 'description');
                    if (Jsx::truthy($qd) && !Jsx::truthy(Jsx::get(Jsx::truthy($qs) ? $qs : new Obj(), 'description'))) {
                        $sch->set('description', $qd);
                    }
                    $addName(Jsx::get($q, 'name'), $sch, $in === 'path' || Jsx::get($q, 'required') === true, "$in parameters");
                }
                $xr = Jsx::get($op, 'x-pca-reversibility');
                $rev = $xr instanceof Undef || $xr === null ? ($read ? 'reversible' : 'irreversible') : $xr;
                if (!$read && !Jsx::truthy($xr)) {
                    $c->todo[] = "$verb: reversibility (drafted irreversible)";
                }
                $v = Obj::of(['verb' => $verb, 'kind' => $read ? 'read' : 'write', 'params' => $params, 'reversibility' => $rev,
                    'openapi' => Obj::of(['operationId' => Jsx::get($op, 'operationId')])]);
                if (Jsx::truthy(Jsx::get($op, 'description'))) {
                    $v->set('description', self::description(Jsx::get($op, 'description')));
                }
                $verbs[] = $v;
            }
        }
        return self::result($verbs, $site, $c->todo);
    }
}
