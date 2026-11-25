<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Actions.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';

/** The mutable state of one import run (the reference's context). @internal */
final class ImportCtx
{
    /** @var list<Obj> */
    public array $todo = [];
    /** @var array<string,true> */
    public array $verbs = [];
    /** @var array<string,string> */
    public array $aliases = [];
    /** @var list<Obj> */
    public array $defs = [];

    /** @param array<string,int> $lim @param array<string,true> $ext */
    public function __construct(public readonly string $ns, public readonly string $kind, public readonly array $lim, public readonly Obj $source, public readonly array $ext, public mixed $root)
    {
    }
}

/** The bounded node budget of one operation's `$ref` expansion. @internal */
final class ImportBudget
{
    public bool $exhausted = false;

    public function __construct(public int $left)
    {
    }
}

/**
 * What every action importer shares (native port of import/limits.ts and import/common.ts of the reference actions package): the input bounds,
 * result shapes, text hygiene, verb naming, the bounded `$ref` resolver, the JSON Schema to ParamDef flattening and the single place a draft ActionDef
 * is assembled (always `unreviewed`); plus the OpenAPI, MCP, JSON Schema and AsyncAPI importers. Sources are parsed JSON values (Obj, list, string,
 * Num, bool, null); an importer returns {defs, todo, source}. The reference's JavaScript string semantics (UTF-16 lengths, lone surrogates,
 * property reads on any value) are reproduced where an output depends on them.
 */
final class ActionsImport
{
    /** The shape of an import namespace (`ns`). */
    public const NS_RE = '/\A[a-z][a-z0-9_]{0,31}\z/';

    public const DEFAULT_IMPORT_LIMITS = ['max_bytes' => 67108864, 'max_ops' => 20000, 'max_json_depth' => 64, 'max_nodes' => 6000000, 'max_ref_nodes' => 20000, 'max_ref_depth' => 8];
    public const HARD_IMPORT_LIMITS = ['max_bytes' => 268435456, 'max_ops' => 50000, 'max_json_depth' => 128, 'max_nodes' => 20000000, 'max_ref_nodes' => 200000, 'max_ref_depth' => 16];
    public const MAX_IMPORT_OPS = 20000;
    public const IMPORT_KINDS = ['openapi', 'mcp', 'graphql', 'grpc', 'asyncapi', 'jsonschema'];
    public const DEFAULT_EXTENSIONS = ['x-pca-verb', 'x-pca-role', 'x-pca-internal'];
    private const ACTION_WORDS = ['get', 'list', 'read', 'fetch', 'find', 'search', 'query', 'show', 'describe', 'create', 'add', 'new', 'make', 'insert', 'post', 'put', 'set',
        'update', 'patch', 'edit', 'modify', 'delete', 'remove', 'destroy', 'drop', 'send', 'notify', 'publish', 'invite', 'cancel', 'refund', 'charge', 'pay', 'run', 'exec',
        'execute', 'invoke', 'start', 'stop', 'enable', 'disable', 'approve', 'reject', 'close', 'open', 'merge', 'export', 'import', 'upload', 'download', 'subscribe',
        'unsubscribe', 'revoke', 'grant', 'transfer'];
    private const FORMATS = ['email' => 'email', 'uuid' => 'uuid', 'uri' => 'url', 'url' => 'url', 'idn-email' => 'email', 'semver' => 'semver'];
    private const RESERVED = ['__proto__', 'constructor', 'prototype'];
    private const INT_ROLES = ['money.amount', 'money.fee', 'count.limit', 'bytes.size'];
    private const LONE = '/\xED[\xA0-\xBF][\x80-\xBF]/';
    private const CTRL = '/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\xC2[\x80-\x9f]|\xE2\x80[\xA8\xA9\xAA-\xAE]|\xE2\x81[\xA6-\xA9]/';
    private const METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];
    private const EFFECT_OF = ['get' => ['read'], 'head' => ['read'], 'options' => ['read'], 'trace' => ['read'], 'post' => ['create'], 'put' => ['update'], 'patch' => ['update'], 'delete' => ['delete']];
    private const NATURAL = ['get', 'head', 'options', 'trace', 'put', 'delete'];
    private const BODY_TYPES = ['application/json', 'application/x-www-form-urlencoded', 'multipart/form-data'];

    // ---- limits ------------------------------------------------------------------------------------------------------------

    private static function isSafeInteger(mixed $v): bool
    {
        $f = Js::num($v);
        return $f !== null && is_finite($f) && fmod($f, 1.0) == 0.0 && abs($f) <= 9007199254740991.0;
    }

    private static function intNum(mixed $n): bool
    {
        $f = Js::num($n);
        return self::isSafeInteger($n) && !($f == 0.0 && fdiv(1.0, $f) < 0);
    }

    /** @return array<string,int> */
    public static function resolveLimits(mixed $over = null): array
    {
        $out = self::DEFAULT_IMPORT_LIMITS;
        foreach (array_keys($out) as $k) {
            if (!($over instanceof Obj) || !$over->has($k)) {
                continue;
            }
            $v = $over->get($k);
            if (!self::isSafeInteger($v) || Js::num($v) < 1) {
                throw new ActionKitError('bad_limit', "limit $k must be a positive safe integer");
            }
            $out[$k] = (int)min((int)Js::num($v), self::HARD_IMPORT_LIMITS[$k]);
        }
        return $out;
    }

    private static function fffd(string $s): string
    {
        return (string)preg_replace(self::LONE, "\xEF\xBF\xBD", $s);
    }

    /** @param array<string,int> $lim */
    public static function textSizeCheck(mixed $text, array $lim): void
    {
        if (!is_string($text)) {
            throw new ActionKitError('bad_source', 'the source must be text');
        }
        if (Js::len($text) * 3 > $lim['max_bytes'] && strlen(self::fffd($text)) > $lim['max_bytes']) {
            throw new ActionKitError('import_limit', 'the source is larger than ' . $lim['max_bytes'] . ' bytes');
        }
    }

    /** Walk a parsed source iteratively; refuse anything that is too deep or large. Returns the node count. @param array<string,int> $lim */
    public static function checkParsed(mixed $root, array $lim): int
    {
        $nodes = 0;
        $size = 0;
        $stack = [[$root, 0]];
        while ($stack) {
            [$v, $d] = array_pop($stack);
            $nodes++;
            if ($nodes > $lim['max_nodes']) {
                throw new ActionKitError('import_limit', 'the source has more than ' . $lim['max_nodes'] . ' nodes');
            }
            if ($d > $lim['max_json_depth']) {
                throw new ActionKitError('import_limit', 'the source nests deeper than ' . $lim['max_json_depth']);
            }
            if ($v === null || is_bool($v)) {
                $size += 4;
            } elseif (Js::isNum($v)) {
                if (!is_finite((float)Js::num($v))) {
                    throw new ActionKitError('bad_source', 'the source holds a non-finite number');
                }
                $size += 8;
            } elseif (is_string($v)) {
                $size += Js::len($v);
            } elseif (is_array($v) && array_is_list($v)) {
                $size += 2 + count($v);
                foreach ($v as $x) {
                    $stack[] = [$x, $d + 1];
                }
            } elseif ($v instanceof Obj) {
                foreach ($v->keys() as $k) {
                    $size += Js::len($k) + 4;
                    $stack[] = [$v->get($k), $d + 1];
                }
            } else {
                throw new ActionKitError('bad_source', 'the source holds a ' . get_debug_type($v));
            }
            if ($size > $lim['max_bytes']) {
                throw new ActionKitError('import_limit', 'the source is larger than ' . $lim['max_bytes'] . ' bytes');
            }
        }
        return $nodes;
    }

    // ---- context ----------------------------------------------------------------------------------------------------------

    public static function newCtx(string $kind, mixed $source, mixed $opts): ImportCtx
    {
        $o = $opts instanceof Obj ? $opts : new Obj();
        $ns = $o->get('ns');
        if (!is_string($ns) || preg_match(self::NS_RE, $ns) !== 1) {
            throw new ActionKitError('bad_ns', 'ns must match [a-z][a-z0-9_]{0,31}');
        }
        $lim = self::resolveLimits($o->get('limits'));
        if (is_string($source)) {
            self::textSizeCheck($source, $lim);
            $digest = Pca::b64u(hash('sha256', self::fffd($source), true));
        } elseif ($source instanceof Bytes) { // a binary source (a gRPC FileDescriptorSet)
            if (strlen($source->raw) > $lim['max_bytes']) {
                throw new ActionKitError('import_limit', 'the source is larger than ' . $lim['max_bytes'] . ' bytes');
            }
            $digest = Pca::b64u(hash('sha256', $source->raw, true));
        } else {
            self::checkParsed($source, $lim);
            $digest = Pca::b64u(hash('sha256', Json::canonicalizeLenient($source), true));
        }
        $now = $o->get('now') ?? new Num('0');
        if (!self::isSafeInteger($now) || Js::num($now) < 0) {
            throw new ActionKitError('bad_opts', 'now must be a non-negative integer');
        }
        $ext = $o->get('allowExtensions');
        if ($ext === null) {
            $ext = self::DEFAULT_EXTENSIONS;
        } elseif (is_string($ext)) {
            $ext = preg_split('//u', $ext, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        } elseif (!is_array($ext) || !array_is_list($ext)) {
            throw new \TypeError('allowExtensions is not iterable');
        }
        $uri = $o->get('uri');
        $licence = $o->get('licence');
        $src = Obj::of(['kind' => $kind, 'uri' => self::clip($uri === null ? "source:$kind" : $uri, 2048), 'spec_digest' => $digest,
            'licence' => self::clip($licence === null ? 'unknown' : $licence, 128), 'imported_at' => new Num((string)(int)Js::num($now))]);
        $set = [];
        foreach ($ext as $x) {
            $set[(string)$x] = true;
        }
        return new ImportCtx($ns, $kind, $lim, $src, $set, $source);
    }

    public static function addTodo(ImportCtx $c, string $where, string $code, string $message): void
    {
        // a hostile spec could make millions of todos: keep the first 5,000 and one sentinel
        $n = count($c->todo);
        if ($n < 5000) {
            $c->todo[] = Obj::of(['where' => self::clip($where, 200), 'code' => $code, 'message' => self::clip($message, 400)]);
        } elseif ($n === 5000) {
            $c->todo[] = Obj::of(['where' => '*', 'code' => 'todo_truncated', 'message' => 'further notes omitted']);
        }
    }

    public static function finish(ImportCtx $c): Obj
    {
        return Obj::of(['defs' => $c->defs, 'todo' => $c->todo, 'source' => $c->source]);
    }

    // ---- text hygiene -----------------------------------------------------------------------------------------------------

    private static function trimWs(string $s): string
    {
        return (string)preg_replace('/\A(?:' . IntentWb::JS_WS . ')+|(?:' . IntentWb::JS_WS . ')+\z/', '', $s);
    }

    /** NFC, no lone surrogates, no control or bidi-override characters, whitespace collapsed, cut to $maxBytes at a code point. */
    public static function clip(mixed $s, int $maxBytes): string
    {
        if (!is_string($s)) {
            return '';
        }
        $t = (string)preg_replace(self::LONE, '', $s);
        $t = (string)preg_replace(self::CTRL, ' ', $t);
        $n = \Normalizer::normalize($t, \Normalizer::FORM_C);
        $t = $n === false ? $t : $n;
        $t = self::trimWs((string)preg_replace('/(?:' . IntentWb::JS_WS . ')+/', ' ', $t));
        if (strlen($t) <= $maxBytes) {
            return $t;
        }
        $out = '';
        foreach (preg_split('//u', $t, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) {
            if (strlen($out) + strlen($ch) > $maxBytes) {
                break;
            }
            $out .= $ch;
        }
        return self::trimWs($out);
    }

    private static function firstText(int $mx, mixed ...$xs): string
    {
        foreach ($xs as $x) {
            $t = self::clip($x, $mx);
            if ($t !== '') {
                return $t;
            }
        }
        return '';
    }

    // ---- tokens and verbs -------------------------------------------------------------------------------------------------

    /** @return list<string> */
    public static function tokensOf(mixed $name): array
    {
        $n = \Normalizer::normalize(Js::utf8(IntentWb::jsStr($name)), \Normalizer::FORM_KD); // a lone surrogate is a separator, as any non-alphanumeric
        $s = (string)preg_replace('/[\x{0300}-\x{036F}]/u', '', $n === false ? '' : $n);
        $s = (string)preg_replace('/([A-Z]+)([A-Z][a-z])/', '$1 $2', (string)preg_replace('/([a-z0-9])([A-Z])/', '$1 $2', $s));
        return array_values(array_filter(preg_split('/[^a-z0-9]+/', mb_strtolower($s)) ?: [], static fn($t) => $t !== ''));
    }

    /** @param list<string> $toks */
    private static function seg(array $toks): string
    {
        $s = implode('_', $toks);
        if (strlen($s) <= 32) {
            return $s;
        }
        $h = substr(strtolower((string)preg_replace('/[^a-z0-9]/i', '', Pca::b64u(hash('sha256', $s, true)))), 0, 4);
        return substr($s, 0, 27) . '_' . str_pad($h, 4, '0');
    }

    public static function verbOf(string $ns, mixed $raw): string
    {
        $parts = array_values(array_filter(array_map([self::class, 'tokensOf'], preg_split('/(?:[.\/:]|' . IntentWb::JS_WS . ')+/', IntentWb::jsStr($raw)) ?: []), static fn($t) => $t));
        if (count($parts) >= 2) {
            $segs = array_map([self::class, 'seg'], $parts);
        } else {
            $t = $parts[0] ?? ['op'];
            if (count($t) >= 2 && in_array($t[0], self::ACTION_WORDS, true)) {
                $segs = [self::seg(array_slice($t, 1)), self::seg([$t[0]])];
            } elseif (count($t) >= 2 && in_array($t[count($t) - 1], self::ACTION_WORDS, true)) {
                $segs = [self::seg(array_slice($t, 0, -1)), self::seg([$t[count($t) - 1]])];
            } else {
                $segs = [self::seg($t)];
            }
        }
        if (count($segs) > 5) {
            $segs = array_merge(array_slice($segs, 0, 2), array_slice($segs, -3));
        }
        $v = $ns . '.' . implode('.', $segs);
        return preg_match(Actions::VERB_RE, $v) !== 1 || strlen($v) > 128 ? "$ns.op" : $v;
    }

    public static function aliasOf(mixed $raw, string $verb): ?string
    {
        $a = implode('_', self::tokensOf($raw));
        return $a !== '' && strlen($a) <= 64 && preg_match(Actions::ALIAS_RE, $a) === 1 && $a !== $verb ? $a : null;
    }

    public static function humanize(mixed $name): string
    {
        $t = self::tokensOf($name);
        return $t === [] ? '' : implode(' ', array_merge([mb_strtoupper(mb_substr($t[0], 0, 1)) . mb_substr($t[0], 1)], array_slice($t, 1)));
    }

    private static function uniqueVerb(ImportCtx $c, string $verb, string $where): string
    {
        if (!isset($c->verbs[$verb])) {
            return $verb;
        }
        for ($n = 2; $n < 100000; $n++) {
            $sfx = "_$n";
            $dot = strrpos($verb, '.');
            $last = substr($verb, $dot + 1);
            $cand = substr($verb, 0, $dot + 1) . substr($last, 0, 32 - strlen($sfx)) . $sfx;
            if (!isset($c->verbs[$cand]) && preg_match(Actions::VERB_RE, $cand) === 1) {
                self::addTodo($c, $where, 'duplicate_verb', "verb '$verb' is taken by an earlier operation; this one is '$cand'");
                return $cand;
            }
        }
        throw new ActionKitError('import_limit', 'too many operations map to one verb');
    }

    // ---- JSON value helpers -----------------------------------------------------------------------------------------------

    /** o[k] for a JSON value: an own member of an object, else undefined. */
    private static function g(mixed $o, string $k): mixed
    {
        return $o instanceof Obj && $o->has($k) ? $o->get($k) : JsUndefined::U;
    }

    private static function undef(mixed $v): bool
    {
        return $v === JsUndefined::U;
    }

    private static function nullish(mixed $v): mixed
    {
        return $v === JsUndefined::U ? null : $v;
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /** {...v}: an object's members, an array's / string's indexed members, nothing for a scalar. */
    private static function spreadObj(mixed $v): Obj
    {
        if ($v instanceof Obj) {
            return $v->without();
        }
        $o = new Obj();
        if (self::isList($v)) {
            foreach ($v as $i => $x) {
                $o->set((string)$i, $x);
            }
        } elseif (is_string($v)) {
            $u = (string)mb_convert_encoding($v, 'UTF-16LE', 'UTF-8');
            for ($i = 0; $i < intdiv(strlen($u), 2); $i++) {
                $o->set((string)$i, (string)mb_convert_encoding(substr($u, 2 * $i, 2), 'UTF-8', 'UTF-16LE'));
            }
        }
        return $o;
    }

    /** [...v]: an array or a string (by code point); anything else is not iterable. @return list<mixed> */
    private static function spreadArr(mixed $v): array
    {
        if (self::isList($v)) {
            return $v;
        }
        if (is_string($v)) {
            return preg_split('//u', $v, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        }
        throw new \TypeError('value is not iterable');
    }

    private static function decodeUri(string $s): string
    {
        if (preg_match('/%(?![0-9A-Fa-f]{2})/', $s) === 1) {
            return $s;
        }
        $d = rawurldecode($s);
        return preg_match('//u', $d) === 1 ? $d : $s;
    }

    /** Follow a local `#/a/b` JSON pointer in $root; null when absent, not local, or not an object or array. */
    public static function pointer(mixed $root, mixed $ref): mixed
    {
        if (!is_string($ref) || !str_starts_with($ref, '#/')) {
            return null;
        }
        $cur = $root;
        foreach (explode('/', substr($ref, 2)) as $raw) {
            $seg = self::decodeUri(str_replace('~0', '~', str_replace('~1', '/', $raw)));
            if ($cur instanceof Obj) {
                if (!$cur->has($seg)) {
                    return null;
                }
                $cur = $cur->get($seg);
            } elseif (self::isList($cur)) {
                if (preg_match('/\A(?:0|[1-9][0-9]*)\z/', $seg) === 1 && (int)$seg < count($cur)) {
                    $cur = $cur[(int)$seg];
                } else {
                    return null;
                }
            } else {
                return null;
            }
        }
        return $cur instanceof Obj || self::isList($cur) ? $cur : null;
    }

    /** @internal for the GraphQL and gRPC importers of this package */
    public static function newBudget(ImportCtx $c): ImportBudget
    {
        return new ImportBudget($c->lim['max_ref_nodes']);
    }

    private static function mergeAll(Obj $a, Obj $m): Obj
    {
        $out = $a->without();
        foreach ($m->keys() as $k) {
            $out->set($k, $m->get($k));
        }
        $props = self::spreadObj($a->get('properties'));
        foreach (self::spreadObj($m->get('properties'))->keys() as $k) {
            $props->set($k, self::spreadObj($m->get('properties'))->get($k));
        }
        $out->set('properties', $props);
        $out->set('required', array_merge(self::spreadArr($a->get('required') ?? []), self::spreadArr($m->get('required') ?? [])));
        return $out;
    }

    private static function isNullType(Obj $m): bool
    {
        $t = self::g($m, 'type');
        if ($t === 'null') {
            return true;
        }
        return self::isList($t) && $t !== [] && count(array_filter($t, static fn($x) => $x === 'null')) === count($t);
    }

    private static function overlay(Obj $base, Obj $over): Obj
    {
        $o = $base->without();
        foreach ($over->keys() as $k) {
            $o->set($k, $over->get($k));
        }
        return $o;
    }

    /**
     * Follow local `$ref`s, merge `allOf`, collapse `anyOf`/`oneOf` to the single non-null variant or to a union of string constants. What stays
     * unrepresentable is noted and left as `{}` (declared `string`, which fails closed). Bounded by `max_ref_depth` per chain and one budget of
     * nodes per operation.
     *
     * @param list<string> $chain
     */
    private static function resolveSchema(mixed $s, ImportCtx $c, ImportBudget $bud, string $where, array $chain = [], int $depth = 0): Obj
    {
        if (!($s instanceof Obj)) {
            return new Obj();
        }
        if ($bud->left <= 0) {
            if (!$bud->exhausted) {
                $bud->exhausted = true;
                self::addTodo($c, $where, 'ref_budget', 'schema expansion stopped after ' . $c->lim['max_ref_nodes'] . ' nodes (declared string; refine or drop)');
            }
            return new Obj();
        }
        $bud->left--;
        if ($depth > $c->lim['max_ref_depth']) {
            self::addTodo($c, $where, 'ref_depth', 'schema nesting or reference chain deeper than ' . $c->lim['max_ref_depth'] . ' (declared string; refine or drop)');
            return new Obj();
        }
        $cur = $s;
        if (is_string($cur->get('$ref'))) {
            $ref = $cur->get('$ref');
            if (in_array($ref, $chain, true)) {
                self::addTodo($c, $where, 'cyclic_ref', "reference '" . self::clip($ref, 120) . "' is cyclic (declared string; refine or drop)");
                return new Obj();
            }
            $target = self::pointer($c->root, $ref);
            if ($target === null) {
                self::addTodo($c, $where, 'unresolved_ref', "reference '" . self::clip($ref, 120) . "' is not a local reference that resolves (declared string; refine or drop)");
                return new Obj();
            }
            $cur = self::overlay(self::resolveSchema($target, $c, $bud, $where, array_merge($chain, [$ref]), $depth + 1), $cur->without('$ref'));
        }
        if (self::isList($cur->get('allOf'))) {
            $rest = $cur->without('allOf');
            $merged = new Obj();
            foreach (array_map(fn($m) => self::resolveSchema($m, $c, $bud, $where, $chain, $depth + 1), $cur->get('allOf')) as $m) {
                $merged = self::mergeAll($merged, $m);
            }
            $cur = self::overlay($merged, $rest);
        }
        $alts = self::isList($cur->get('anyOf')) ? $cur->get('anyOf') : (self::isList($cur->get('oneOf')) ? $cur->get('oneOf') : null);
        if ($alts !== null) {
            $rest = $cur->without('anyOf', 'oneOf');
            $live = array_values(array_filter(array_map(fn($m) => self::resolveSchema($m, $c, $bud, $where, $chain, $depth + 1), $alts), static fn(Obj $m) => !self::isNullType($m)));
            if (count($live) === 1) {
                return self::overlay($live[0], $rest);
            }
            $consts = [];
            foreach ($live as $m) {
                if (is_string($m->get('const'))) {
                    $consts[] = [$m->get('const')];
                } elseif (self::isList($m->get('enum')) && count(array_filter($m->get('enum'), 'is_string')) === count($m->get('enum'))) {
                    $consts[] = $m->get('enum');
                } else {
                    $consts[] = null;
                }
            }
            if (count($live) > 1 && !in_array(null, $consts, true)) {
                $all = [];
                foreach ($consts as $xs) {
                    foreach ($xs as $x) {
                        $all[] = $x;
                    }
                }
                $out = $rest->without();
                $out->set('type', 'string');
                $out->set('enum', array_values(array_unique($all)));
                return $out;
            }
            self::addTodo($c, $where, 'union', 'a union of ' . count($live) . ' schemas has no representation (declared string; refine or drop)');
            return $rest;
        }
        if ($cur->has('const') && !$cur->has('enum') && is_string($cur->get('const'))) {
            $cur = $cur->without();
            $cur->set('enum', [$cur->get('const')]);
        }
        return $cur;
    }

    // ---- JSON Schema -> params --------------------------------------------------------------------------------------------

    /** `[A-Za-z0-9_]{1,64}`; anything else is replaced by `_` (an astral character is two UTF-16 units, so two). */
    public static function paramSeg(mixed $raw): string
    {
        $s = '';
        foreach (preg_split('//u', Js::utf8((string)$raw), -1, PREG_SPLIT_NO_EMPTY) ?: [] as $ch) { // a lone surrogate is one character
            $s .= preg_match('/\A[A-Za-z0-9_]\z/', $ch) === 1 ? $ch : str_repeat('_', strlen($ch) === 4 ? 2 : 1);
        }
        if (preg_match('/\A_+\z/', $s) === 1) {
            $s = '';
        }
        $s = substr($s, 0, 64);
        return $s !== '' ? $s : 'p';
    }

    private static function isRoleOk(string $r): bool
    {
        return in_array($r, Actions::CORE_ROLES, true) || preg_match(Actions::ID_ROLE_RE, $r) === 1 || preg_match(Actions::CUSTOM_ROLE_RE, $r) === 1;
    }

    /** @return list<string>|null */
    private static function enumStrs(mixed $e): ?array
    {
        if (!self::isList($e) || $e === [] || count($e) > 256) {
            return null;
        }
        foreach ($e as $x) {
            if (!is_string($x) || $x === '' || strlen(self::fffd($x)) > 256 || preg_match(self::LONE, $x) === 1 || !\Normalizer::isNormalized($x, \Normalizer::FORM_C)) {
                return null;
            }
        }
        return array_values(array_unique($e));
    }

    /** `Array.isArray(t) ? t.find(x => x !== 'null') : t` (undefined when none). */
    private static function firstNonNull(mixed $t): mixed
    {
        if (self::isList($t)) {
            foreach ($t as $x) {
                if ($x !== 'null') {
                    return $x;
                }
            }
            return JsUndefined::U;
        }
        return $t;
    }

    private static function num(int $i): Num
    {
        return new Num((string)$i);
    }

    private static function leafParam(Obj $s, bool $required, ImportCtx $c, ImportBudget $bud, string $where): Obj
    {
        $t0 = self::firstNonNull(self::g($s, 'type'));
        $enumStr = self::enumStrs($s->get('enum'));
        $items = $s->get('items');
        $t = !self::undef($t0) && $t0 !== null ? $t0 : ($enumStr ? 'string' : ($items instanceof Obj || self::isList($items) ? 'array' : JsUndefined::U));
        $base = Obj::of(['type' => 'string']);
        if (!$required) {
            $base->set('required', false);
        }
        $desc = self::clip($s->get('description'), 280);
        if ($desc !== '') {
            $base->set('description', $desc);
        }
        $roleExt = isset($c->ext['x-pca-role']) && is_string($s->get('x-pca-role')) ? $s->get('x-pca-role') : null;
        $withRole = function (Obj $p) use ($roleExt, $c, $where): Obj {
            if ($roleExt === null) {
                return $p;
            }
            if (!self::isRoleOk($roleExt) || (in_array($roleExt, self::INT_ROLES, true) && $p->get('type') !== 'integer')) {
                self::addTodo($c, $where, 'role_ignored', "x-pca-role '" . self::clip($roleExt, 64) . "' is not valid for a " . $p->get('type') . ' parameter');
                return $p;
            }
            $o = $p->without();
            $o->set('role', $roleExt);
            return $o;
        };
        $fmt = $s->get('format');
        if ($t === 'integer' || ($t === 'number' && is_string($fmt) && in_array($fmt, ['int32', 'int64'], true))) {
            $p = $base->without();
            $p->set('type', 'integer');
            $mn = $s->get('minimum');
            $mx = $s->get('maximum');
            $exMin = $s->get('exclusiveMinimum');
            $exMax = $s->get('exclusiveMaximum');
            if (self::intNum($mn) && $exMin !== true) {
                $p->set('min', self::num((int)Js::num($mn)));
            } elseif (self::intNum($exMin)) {
                $p->set('min', self::num((int)Js::num($exMin) + 1));
            } elseif (self::intNum($mn) && $exMin === true) {
                $p->set('min', self::num((int)Js::num($mn) + 1));
            }
            if (self::intNum($mx) && $exMax !== true) {
                $p->set('max', self::num((int)Js::num($mx)));
            } elseif (self::intNum($exMax)) {
                $p->set('max', self::num((int)Js::num($exMax) - 1));
            } elseif (self::intNum($mx) && $exMax === true) {
                $p->set('max', self::num((int)Js::num($mx) - 1));
            }
            if ($p->has('min') && $p->has('max') && Js::num($p->get('min')) > Js::num($p->get('max'))) {
                $p = $p->without('min', 'max');
            }
            return $withRole($p);
        }
        if ($t === 'boolean') {
            $p = $base->without();
            $p->set('type', 'boolean');
            return $withRole($p);
        }
        if ($t === 'string') {
            $f = is_string($fmt) ? $fmt : '';
            if ($f === 'date' || $f === 'date-time') {
                $p = $base->without();
                $p->set('type', $f === 'date' ? 'date' : 'datetime');
                return $withRole($p);
            }
            $p = $base->without();
            $p->set('type', 'string');
            if ($enumStr) {
                $p->set('values', $enumStr);
            } elseif (self::isList($s->get('enum')) && count($s->get('enum')) > 0) {
                self::addTodo($c, $where, 'enum_dropped', 'enum values are not 1..256 plain strings (declared as a free string; refine)');
            }
            if (isset(self::FORMATS[$f])) {
                $p->set('format', self::FORMATS[$f]);
            }
            $ml = $s->get('maxLength');
            if (self::intNum($ml) && 0 < Js::num($ml) && Js::num($ml) <= 16777216) {
                $p->set('max_len', self::num((int)Js::num($ml)));
            }
            return $withRole($p);
        }
        if ($t === 'array') {
            $it = self::resolveSchema($items, $c, $bud, $where . '[]');
            $itEnum = self::enumStrs($it->get('enum'));
            $lim = new Obj();
            $mi = $s->get('maxItems');
            $ni = $s->get('minItems');
            if (self::intNum($mi) && Js::num($mi) >= 0) {
                $lim->set('max_items', self::num((int)Js::num($mi)));
            }
            if (self::intNum($ni) && Js::num($ni) >= 0) {
                $lim->set('min_items', self::num((int)Js::num($ni)));
            }
            if ($lim->has('min_items') && $lim->has('max_items') && Js::num($lim->get('min_items')) > Js::num($lim->get('max_items'))) {
                $lim = new Obj();
            }
            if ($s->get('uniqueItems') === true && $itEnum) {
                $p = $base->without();
                $p->set('type', 'set');
                $p->set('values', $itEnum);
                return $withRole(self::overlay($p, $lim));
            }
            $itT = self::firstNonNull(self::g($it, 'type'));
            $item = is_string($itT) && in_array($itT, ['integer', 'string', 'boolean'], true) ? $itT : null;
            if ($item === null && !self::undef($itT)) {
                self::addTodo($c, $where, 'array_items', "array items of type '" . self::clip(IntentWb::jsStr($itT), 40) . "' are not declared (items left open)");
            }
            $p = $base->without();
            $p->set('type', 'array');
            if ($item !== null) {
                $p->set('items', $item);
            }
            return $withRole(self::overlay($p, $lim));
        }
        $shown = IntentWb::jsStr(self::undef($t) || $t === null ? 'none' : $t);
        if ($t === 'number') {
            self::addTodo($c, $where, 'unsupported_type', "type 'number' (fractions) has no ActionDef representation (declared string; use an integer unit, or refine)");
        } else {
            self::addTodo($c, $where, 'unsupported_type', "type '" . self::clip($shown, 40) . "' has no representation (declared string; refine or drop)");
        }
        $p = $base->without();
        $p->set('type', 'string');
        return $withRole($p);
    }

    private static function placeholderObject(Obj $s, bool $required, ImportCtx $c, string $where): Obj
    {
        self::addTodo($c, $where, 'object_leaf', 'an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)');
        $p = Obj::of(['type' => 'string']);
        if (!$required) {
            $p->set('required', false);
        }
        $d = self::clip($s->get('description'), 280);
        if ($d !== '') {
            $p->set('description', $d);
        }
        return $p;
    }

    /** @param list<string> $keys @return list<string> UTF-8 byte order */
    private static function utf8Sorted(array $keys): array
    {
        usort($keys, 'strcmp');
        return $keys;
    }

    /**
     * Nested objects become dotted names up to MAX_PARAM_PATH_DEPTH segments; an object below that (or without properties) is a `string`
     * placeholder; a child of an optional parent is optional. At most MAX_DEF_PARAMS params; the rest are dropped, noted.
     *
     * @internal shared with the GraphQL and gRPC importers of this package
     *
     * @param list<string> $prefix
     */
    public static function flattenObject(Obj $schema, ImportCtx $c, ImportBudget $bud, string $where, Obj $out, array $prefix = [], bool $parentRequired = true): void
    {
        $props = $schema->get('properties') instanceof Obj ? $schema->get('properties') : new Obj();
        $r = $schema->get('required');
        $req = [];
        foreach (self::isList($r) ? $r : [] as $x) {
            if (is_string($x)) {
                $req[$x] = true;
            }
        }
        foreach (self::utf8Sorted($props->keys()) as $name) {
            if (in_array($name, self::RESERVED, true)) {
                self::addTodo($c, "$where: $name", 'skipped_param', "parameter name '$name' is reserved; dropped");
                continue;
            }
            $child = self::resolveSchema($props->get($name), $c, $bud, "$where: $name");
            if ($child->get('readOnly') === true) {
                continue; // response-only; not an input
            }
            $sname = self::paramSeg($name);
            if ($sname !== $name) {
                self::addTodo($c, "$where: $name", 'renamed_param', "parameter '" . self::clip($name, 80) . "' is declared as '$sname'");
            }
            $path = array_merge($prefix, [$sname]);
            $full = implode('.', $path);
            $required = $parentRequired && isset($req[$name]);
            $isObject = self::g($child, 'type') === 'object' || (!$child->has('type') && $child->get('properties') instanceof Obj);
            if ($isObject && $child->get('properties') instanceof Obj && count($child->get('properties')->keys()) > 0 && count($path) < Actions::MAX_PARAM_PATH_DEPTH) {
                self::flattenObject($child, $c, $bud, "$where: $full", $out, $path, $required);
                continue;
            }
            if (count($out->keys()) >= Actions::MAX_DEF_PARAMS) {
                self::addTodo($c, $where, 'too_many_params', 'more than ' . Actions::MAX_DEF_PARAMS . " parameters; '$full' and the rest are dropped");
                return;
            }
            $collides = $out->has($full);
            foreach ($out->keys() as $k) {
                $collides = $collides || str_starts_with($k, "$full.") || str_starts_with($full, "$k.");
            }
            if ($collides) {
                self::addTodo($c, "$where: $full", 'skipped_param', "parameter '$full' collides with another; kept the first");
                continue;
            }
            $out->set($full, $isObject ? self::placeholderObject($child, $required, $c, "$where: $full") : self::leafParam($child, $required, $c, $bud, "$where: $full"));
        }
    }

    // ---- assembling a draft def --------------------------------------------------------------------------------------------

    /**
     * Assemble, validate and register a draft def. A def that fails validation is dropped, noted (never emitted).
     *
     * @internal shared with the GraphQL and gRPC importers of this package
     *
     * @param list<string> $effects @param list<string>|null $traits
     */
    public static function emitDef(ImportCtx $c, string $name, array $effects, string $scope, Obj $params, Obj $bindings, ?string $verb = null, mixed $title = null,
        mixed $description = null, ?Obj $idempotency = null, ?array $traits = null, bool $noAlias = false): ?Obj
    {
        if (count($c->defs) >= $c->lim['max_ops']) {
            throw new ActionKitError('import_limit', 'more than ' . $c->lim['max_ops'] . ' operations');
        }
        $rawVerb = $verb ?? self::verbOf($c->ns, $name);
        $verb = self::uniqueVerb($c, preg_match(Actions::VERB_RE, $rawVerb) === 1 ? $rawVerb : self::verbOf($c->ns, $name), $name);
        $segs = explode('.', $verb);
        $rtype = count($segs) > 2 ? implode('.', array_slice($segs, 0, -1)) : $segs[0];
        $ttl = self::firstText(Actions::MAX_TITLE_BYTES, $title, self::humanize($name), $verb);
        $desc = self::clip($description, min(Actions::MAX_DESCRIPTION_BYTES, 600));
        $alias = $noAlias ? null : self::aliasOf($name, $verb);
        $d = Obj::of(['v' => new Num('1'), 'kind' => 'pca-action-def', 'verb' => $verb]);
        if ($alias !== null && !isset($c->aliases[$alias]) && !isset($c->verbs[$alias])) {
            $d->set('aliases', [$alias]);
        }
        $d->set('title', $ttl !== '' ? $ttl : $verb);
        if ($desc !== '') {
            $d->set('description', $desc);
        }
        $eff = array_values(array_unique($effects));
        sort($eff, SORT_STRING);
        $d->set('effects', $eff);
        $d->set('resource', Obj::of(['type' => preg_match('/\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}\z/', $rtype) === 1 ? $rtype : $segs[0],
            'id' => Obj::of(['prefix' => '', 'class' => 'any_safe', 'len' => [new Num('1'), new Num('128')]]), 'scope' => $scope]));
        $d->set('params', $params);
        if ($idempotency !== null) {
            $d->set('idempotency', $idempotency);
        }
        if ($traits) {
            $tr = array_values(array_unique($traits));
            sort($tr, SORT_STRING);
            $d->set('traits', $tr);
        }
        $d->set('bindings', $bindings);
        $d->set('review', Obj::of(['state' => 'unreviewed']));
        $src = new Obj();
        foreach (['kind', 'uri', 'spec_digest', 'licence', 'imported_at'] as $k) {
            $src->set($k, $c->source->get($k));
        }
        $d->set('source', $src);
        $bad = Actions::validateDef($d);
        if ($bad !== null) {
            self::addTodo($c, $name, 'invalid_def', "not emitted: $bad");
            return null;
        }
        $c->verbs[$verb] = true;
        if ($d->has('aliases')) {
            $c->aliases[$d->get('aliases')[0]] = $verb;
        }
        $c->defs[] = $d;
        return $d;
    }

    /** @param list<string>|null $traits @return list<string> */
    public static function withTrait(?array $traits, string $t): array
    {
        return array_values(array_unique(array_merge($traits ?? [], [$t])));
    }

    // ---- MCP --------------------------------------------------------------------------------------------------------------

    /** MCP `tools/list` to drafts. The annotations are HINTS from the tool's own server and are untrusted: they can only add restriction. $source is a `tools/list` result {tools} or the tool array itself. */
    public static function importMcp(mixed $source, mixed $opts): Obj
    {
        $c = self::newCtx('mcp', $source, $opts);
        $tools = self::isList($source) ? $source : ($source instanceof Obj && self::isList($source->get('tools')) ? $source->get('tools') : null);
        if ($tools === null) {
            throw new ActionKitError('bad_source', 'an MCP source is a tool array or a tools/list result {tools: [...]}');
        }
        $seen = [];
        foreach ($tools as $t) {
            if (!($t instanceof Obj) || !is_string($t->get('name')) || Js::len($t->get('name')) === 0 || Js::len($t->get('name')) > 256) {
                self::addTodo($c, '(tool)', 'skipped_op', 'an entry without a usable name is skipped');
                continue;
            }
            $name = $t->get('name');
            if (isset($seen[$name])) {
                self::addTodo($c, $name, 'duplicate_tool', 'a tool name listed twice; the first is kept');
                continue;
            }
            $seen[$name] = true;
            $c->root = $t->get('inputSchema');
            $bud = self::newBudget($c);
            $inp = self::resolveSchema($t->get('inputSchema'), $c, $bud, "$name: inputSchema");
            $params = new Obj();
            self::flattenObject($inp, $c, $bud, $name, $params);
            $a = $t->get('annotations') instanceof Obj ? $t->get('annotations') : new Obj();
            $read = $a->get('readOnlyHint') === true && $a->get('destructiveHint') !== true;
            $effects = $read ? ['read'] : ($a->get('destructiveHint') === true ? ['update', 'delete'] : ['update']);
            self::emitDef($c, $name, $effects, 'one', $params, Obj::of(['mcp' => Obj::of(['tool' => self::clip($name, 256)])]), null,
                is_string($a->get('title')) && $a->get('title') !== '' ? $a->get('title') : $t->get('title'), $t->get('description'),
                $a->get('idempotentHint') === true ? Obj::of(['mode' => 'natural']) : null, $a->get('openWorldHint') === true ? self::withTrait(null, 'pca.network_egress') : null);
        }
        return self::finish($c);
    }

    // ---- JSON Schema ------------------------------------------------------------------------------------------------------

    /** One JSON Schema plus a caller-given verb to one def. $opts: the common import options plus `verb` (required), `title`, `description`, `effects` (default ["update"]). */
    public static function importJsonSchema(mixed $schema, mixed $opts): Obj
    {
        $c = self::newCtx('jsonschema', $schema, $opts);
        $verb = $opts->get('verb');
        if (!is_string($verb) || preg_match(Actions::VERB_RE, $verb) !== 1 || !str_starts_with($verb, $opts->get('ns') . '.')) {
            throw new ActionKitError('bad_verb', "verb must be a valid verb in namespace '" . $opts->get('ns') . "'");
        }
        $effects = $opts->get('effects') ?? ['update'];
        if (!self::isList($effects) || $effects === [] || count(array_filter($effects, static fn($e) => is_string($e) && in_array($e, Actions::EFFECTS, true))) !== count($effects)) {
            throw new ActionKitError('bad_effects', 'effects must be 1+ known effects');
        }
        if (!($schema instanceof Obj)) {
            throw new ActionKitError('bad_source', 'a JSON Schema must be an object');
        }
        $bud = self::newBudget($c);
        $root = self::resolveSchema($schema, $c, $bud, $verb);
        $params = new Obj();
        if ($root->get('type') === 'object' || $root->get('properties') instanceof Obj) {
            self::flattenObject($root, $c, $bud, $verb, $params);
        } else {
            self::addTodo($c, $verb, 'not_object', 'the schema is not an object schema: the def has no parameters');
        }
        $title = $opts->get('title');
        $description = $opts->get('description');
        self::emitDef($c, implode('_', array_slice(explode('.', $verb), 1)), $effects, 'one', $params, new Obj(), $verb,
            $title ?? (is_string($root->get('title')) ? $root->get('title') : null), $description ?? self::clip($root->get('description'), 600));
        return self::finish($c);
    }

    // ---- OpenAPI ----------------------------------------------------------------------------------------------------------

    /** The object a `$ref` chain ends at (an array is possible: callers read members through g()); null when it does not resolve. */
    private static function derefChain(ImportCtx $c, mixed $x, string $where): mixed
    {
        if (!($x instanceof Obj)) {
            return null;
        }
        if (!is_string($x->get('$ref'))) {
            return $x;
        }
        $seen = [];
        $cur = $x;
        while ($cur instanceof Obj && is_string($cur->get('$ref'))) {
            if (in_array($cur->get('$ref'), $seen, true) || count($seen) > $c->lim['max_ref_depth']) {
                self::addTodo($c, $where, 'cyclic_ref', 'a reference chain is cyclic or too deep');
                return null;
            }
            $seen[] = $cur->get('$ref');
            $t = self::pointer($c->root, $cur->get('$ref'));
            if ($t === null) {
                self::addTodo($c, $where, 'unresolved_ref', "reference '" . self::clip($cur->get('$ref'), 120) . "' does not resolve locally");
                return null;
            }
            $cur = $t;
        }
        return $cur;
    }

    /** @return array{0:list<string>,1:bool} */
    private static function pathFacts(string $path): array
    {
        $segs = array_values(array_filter(explode('/', $path), static fn($s) => $s !== ''));
        $ends = $segs !== [] && preg_match('/\A\{[^\n\r\x{2028}\x{2029}]+\}\z/u', $segs[count($segs) - 1]) === 1;
        $nouns = [];
        foreach ($segs as $s) {
            if (!str_contains($s, '{') && !str_contains($s, '}') && preg_match('/\A(?:v[0-9]+(?:\.[0-9]+)?|api|rest|public|latest)\z/i', $s) !== 1) {
                foreach (self::tokensOf($s) as $t) {
                    $nouns[] = $t;
                }
            }
        }
        return [$nouns, $ends];
    }

    private static function swagger2Param(Obj $p): Obj
    {
        if ($p->has('schema') || $p->get('in') === 'body') {
            return $p;
        }
        $skip = ['name', 'in', 'required', 'description'];
        $out = new Obj();
        $schema = new Obj();
        foreach ($skip as $k) {
            if ($p->has($k)) {
                $out->set($k, $p->get($k));
            }
        }
        foreach ($p->keys() as $k) {
            if (!in_array($k, $skip, true)) {
                $schema->set($k, $p->get($k));
            }
        }
        $out->set('schema', $schema);
        return $out;
    }

    /** @param list<Obj> $params */
    private static function bodySchema(ImportCtx $c, Obj $op, array $params, bool $swagger, string $where): mixed
    {
        if ($swagger) {
            foreach ($params as $q) {
                if ($q->get('in') === 'body') {
                    return self::g($q, 'schema');
                }
            }
            return JsUndefined::U;
        }
        $rb = self::derefChain($c, self::g($op, 'requestBody'), $where);
        $content = self::g($rb, 'content');
        if (!($content instanceof Obj)) {
            return JsUndefined::U;
        }
        $keys = self::utf8Sorted($content->keys());
        $pick = null;
        foreach (self::BODY_TYPES as $t) {
            foreach ($keys as $k) {
                if (self::trimWs(explode(';', mb_strtolower($k))[0]) === $t) {
                    $pick = $k;
                    break 2;
                }
            }
        }
        if ($pick === null) {
            foreach ($keys as $k) {
                if (preg_match('/\Aapplication\/[^;]*\+json(;|\z)/i', $k) === 1) {
                    $pick = $k;
                    break;
                }
            }
        }
        if ($pick === null) {
            if ($keys) {
                self::addTodo($c, $where, 'body_type', 'request body media types (' . implode(', ', array_map(static fn($k) => self::clip($k, 40), array_slice($keys, 0, 3))) . ') are not form or JSON; the body is not declared');
            }
            return JsUndefined::U;
        }
        return self::g($content->get($pick), 'schema');
    }

    /** OpenAPI 3.x and Swagger 2 to drafts: one def per operation, parameters from path / query / body (nested bodies flattened to dotted names), the method giving the initial effects. */
    public static function importOpenApi(mixed $source, mixed $opts): Obj
    {
        $c = self::newCtx('openapi', $source, $opts);
        if (!($source instanceof Obj)) {
            throw new ActionKitError('bad_source', 'an OpenAPI document must be an object');
        }
        $swagger = is_string($source->get('swagger')) && str_starts_with($source->get('swagger'), '2');
        $v3 = is_string($source->get('openapi')) && str_starts_with($source->get('openapi'), '3.');
        if (!$swagger && !$v3) {
            throw new ActionKitError('bad_source', "not an OpenAPI 3.x or Swagger 2 document (missing 'openapi: 3.x' or 'swagger: 2.0')");
        }
        $paths = $source->get('paths') instanceof Obj ? $source->get('paths') : new Obj();
        $globalSecurity = self::isList($source->get('security')) ? $source->get('security') : null;
        $ns = $opts->get('ns');
        foreach (self::utf8Sorted($paths->keys()) as $path) {
            $item0 = self::derefChain($c, $paths->get($path), $path);
            if ($item0 === null) {
                continue;
            }
            $shared = self::g($item0, 'parameters');
            $shared = self::isList($shared) ? $shared : [];
            foreach (self::METHODS as $method) {
                $op = self::g($item0, $method);
                if (!($op instanceof Obj)) {
                    continue;
                }
                $where = strtoupper($method) . ' ' . self::clip($path, 120);
                $oid = $op->get('operationId');
                $operationId = is_string($oid) && Js::len($oid) > 0 && Js::len($oid) <= 200 ? $oid : null;
                [$nouns, $ends] = self::pathFacts($path);
                $nameRaw = is_string($op->get('x-pca-verb')) && isset($c->ext['x-pca-verb']) ? $op->get('x-pca-verb') : null;
                if ($nameRaw !== null && preg_match('/\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}\z/', $nameRaw) === 1 && str_starts_with($nameRaw, $ns . '.')) {
                    $verb = $nameRaw;
                } elseif ($operationId !== null) {
                    $verb = self::verbOf($ns, $operationId);
                } else {
                    $verb = self::verbOf($ns, implode(' ', array_merge(array_slice($nouns, -2), [$method === 'get' && !$ends ? 'list' : $method])));
                }
                $c->root = $source;
                $bud = self::newBudget($c);
                $merged = [];
                $own = $op->get('parameters');
                foreach (array_merge($shared, self::isList($own) ? $own : []) as $raw) {
                    $q0 = self::derefChain($c, $raw, $where);
                    if (!($q0 instanceof Obj) || !is_string($q0->get('name')) || !is_string($q0->get('in'))) {
                        continue;
                    }
                    $q = $swagger ? self::swagger2Param($q0) : $q0;
                    $merged[$q->get('in') . ':' . $q->get('name')] = $q;
                }
                $allp = array_values($merged);
                $params = new Obj();
                $idemParam = null;
                $body = self::bodySchema($c, $op, $allp, $swagger, $where);
                if (!self::undef($body)) {
                    $b = self::resolveSchema($body, $c, $bud, "$where: request body");
                    if ($b->get('type') === 'object' || $b->get('properties') instanceof Obj) {
                        self::flattenObject($b, $c, $bud, $where, $params);
                    } else {
                        self::addTodo($c, $where, 'body_shape', 'the request body is not an object schema; it is not declared');
                    }
                }
                usort($allp, static fn(Obj $a, Obj $b): int => strcmp($a->get('in') . ':' . $a->get('name'), $b->get('in') . ':' . $b->get('name')));
                foreach ($allp as $q) {
                    $name = $q->get('name');
                    if ($q->get('in') === 'header' && preg_match('/\Aidempotency-key\z/i', $name) === 1) {
                        $idemParam = 'idempotency_key';
                        continue;
                    }
                    if ($q->get('in') === 'body') {
                        continue;
                    }
                    if (!in_array($q->get('in'), ['path', 'query', 'formData'], true)) {
                        self::addTodo($c, $where, 'param_location', self::clip($q->get('in'), 12) . " parameter '" . self::clip($name, 60) . "' is not an action parameter (path, query and body only)");
                        continue;
                    }
                    $sname = self::paramSeg($name);
                    if ($sname !== $name) {
                        self::addTodo($c, "$where: $name", 'renamed_param', "parameter '" . self::clip($name, 80) . "' is declared as '$sname'");
                    }
                    $clash = $params->has($sname);
                    foreach ($params->keys() as $k) {
                        $clash = $clash || str_starts_with($k, "$sname.");
                    }
                    if ($clash) {
                        self::addTodo($c, "$where: $name", 'skipped_param', "'$sname' is declared by the body and by a " . $q->get('in') . " parameter; kept the body's");
                        continue;
                    }
                    if (count($params->keys()) >= 64) {
                        self::addTodo($c, $where, 'too_many_params', 'more than 64 parameters; the rest are dropped');
                        break;
                    }
                    $sq = $q->get('schema') ?? new Obj();
                    $qd = self::g($q, 'description');
                    $extra = Js::truthy(self::nullish($qd)) && !Js::truthy(self::nullish(self::g($sq, 'description'))) ? Obj::of(['description' => $qd]) : new Obj();
                    $sch = self::resolveSchema(self::overlay(self::spreadObj($sq), $extra), $c, $bud, "$where: $name");
                    $params->set($sname, self::leafParam($sch, $q->get('in') === 'path' || $q->get('required') === true, $c, $bud, "$where: $name"));
                }
                if ($idemParam !== null && !$params->has($idemParam)) {
                    $params->set($idemParam, Obj::of(['type' => 'string', 'required' => false, 'max_len' => new Num('255')]));
                } else {
                    $idemParam = null;
                }
                $scope = $ends || $method === 'post' ? 'one' : 'set';
                $sec = self::isList($op->get('security')) ? $op->get('security') : $globalSecurity;
                $scopes = [];
                foreach ($sec ?? [] as $r) {
                    if ($r instanceof Obj) {
                        foreach ($r->keys() as $k) {
                            if (self::isList($r->get($k))) {
                                foreach ($r->get($k) as $x) {
                                    if (is_string($x)) {
                                        $scopes[$x] = true;
                                    }
                                }
                            }
                        }
                    }
                }
                $scopes = self::utf8Sorted(array_map('strval', array_keys($scopes)));
                if ($scopes) {
                    self::addTodo($c, $where, 'required_scope', 'requires scope: ' . implode(', ', array_map(static fn($s) => self::clip($s, 60), array_slice($scopes, 0, 12))));
                }
                if ($op->get('deprecated') === true) {
                    self::addTodo($c, $where, 'deprecated', 'the operation is marked deprecated');
                }
                foreach ($op->keys() as $k) {
                    if (str_starts_with($k, 'x-') && !isset($c->ext[$k])) {
                        self::addTodo($c, $where, 'extension_ignored', "extension '" . self::clip($k, 60) . "' is ignored (not allow-listed)");
                        break;
                    }
                }
                $summary = $op->get('summary');
                $desc = $op->get('description');
                self::emitDef($c, $operationId ?? $where, self::EFFECT_OF[$method], $scope, $params,
                    Obj::of(['openapi' => Obj::of(['operationId' => $operationId ?? self::clip($method . '_' . $path, 200), 'method' => strtoupper($method), 'path' => self::clip($path, 240)])]),
                    $verb, is_string($summary) && $summary !== '' ? $summary : $operationId, is_string($desc) ? $desc : (is_string($summary) ? $summary : null),
                    $idemParam !== null ? Obj::of(['mode' => 'key_param', 'param' => $idemParam]) : (in_array($method, self::NATURAL, true) ? Obj::of(['mode' => 'natural']) : null),
                    null, $operationId === null);
            }
        }
        return self::finish($c);
    }

    // ---- AsyncAPI ---------------------------------------------------------------------------------------------------------

    private static function derefAsync(ImportCtx $c, mixed $x, string $where, int $depth = 0): ?Obj
    {
        if (!($x instanceof Obj)) {
            return null;
        }
        if (!is_string($x->get('$ref'))) {
            return $x;
        }
        if ($depth > $c->lim['max_ref_depth']) {
            self::addTodo($c, $where, 'ref_depth', 'a reference chain is too deep');
            return null;
        }
        $t = self::pointer($c->root, $x->get('$ref'));
        if ($t === null) {
            self::addTodo($c, $where, 'unresolved_ref', "reference '" . self::clip($x->get('$ref'), 120) . "' does not resolve locally");
            return null;
        }
        return self::derefAsync($c, $t, $where, $depth + 1);
    }

    /** @param list<mixed> $msgs */
    private static function payloadParams(ImportCtx $c, array $msgs, string $where, Obj $params, ImportBudget $bud): void
    {
        $resolved = array_values(array_filter(array_map(fn($m) => self::derefAsync($c, $m, $where), $msgs), static fn($m) => $m !== null));
        if (!$resolved) {
            return;
        }
        if (count($resolved) > 1) {
            self::addTodo($c, $where, 'message_variants', count($resolved) . ' message variants: only the first is declared');
        }
        if (!$resolved[0]->has('payload')) {
            return;
        }
        $s = self::resolveSchema($resolved[0]->get('payload'), $c, $bud, "$where: payload");
        if ($s->get('type') === 'object' || $s->get('properties') instanceof Obj) {
            self::flattenObject($s, $c, $bud, $where, $params);
        } else {
            self::addTodo($c, $where, 'payload_shape', 'the message payload is not an object schema; it is not declared');
        }
    }

    private static function channelParams(ImportCtx $c, Obj $ch, string $where, Obj $params): void
    {
        $ps = self::derefAsync($c, $ch->get('parameters'), $where);
        if ($ps === null) {
            return;
        }
        foreach (self::utf8Sorted($ps->keys()) as $name) {
            $s = self::paramSeg($name);
            if ($params->has($s)) {
                continue;
            }
            $params->set($s, Obj::of(['type' => 'string', 'max_len' => new Num('256')]));
        }
    }

    /** AsyncAPI 2.x / 3.x to drafts. Sending to a channel is effect `send`, receiving is `read`; the message payload becomes the params. A broker publish leaves the trust domain, so it stays `send` unless the channel carries the allow-listed `x-pca-internal: true`. */
    public static function importAsyncApi(mixed $source, mixed $opts): Obj
    {
        $c = self::newCtx('asyncapi', $source, $opts);
        if (!($source instanceof Obj) || !is_string($source->get('asyncapi')) || preg_match('/\A[23]\./', $source->get('asyncapi')) !== 1) {
            throw new ActionKitError('bad_source', "not an AsyncAPI 2.x or 3.x document (missing 'asyncapi: 2.x|3.x')");
        }
        $ns = $opts->get('ns');
        $v3 = str_starts_with($source->get('asyncapi'), '3');
        $channels = $source->get('channels') instanceof Obj ? $source->get('channels') : new Obj();
        $internal = static fn(Obj $ch): bool => isset($c->ext['x-pca-internal']) && $ch->get('x-pca-internal') === true;
        $emit = function (?string $opName, string $chName, Obj $ch, string $action, Obj $op, array $msgs) use ($c, $ns, $source, $internal): void {
            $where = "$action " . self::clip($chName, 100);
            $bud = self::newBudget($c);
            $c->root = $source;
            $params = new Obj();
            self::channelParams($c, $ch, $where, $params);
            self::payloadParams($c, $msgs, $where, $params, $bud);
            $effects = $action === 'receive' ? ['read'] : ($internal($ch) ? ['create'] : ['send']);
            self::emitDef($c, $opName ?? $where, $effects, 'one', $params, Obj::of(['asyncapi' => Obj::of(['channel' => self::clip($chName, 250), 'op' => $action])]),
                $opName === null ? self::verbOf($ns, "$chName $action") : null, is_string($op->get('summary')) ? $op->get('summary') : null,
                is_string($op->get('description')) ? $op->get('description') : null, null, null, $opName === null);
        };
        if ($v3) {
            $ops = $source->get('operations') instanceof Obj ? $source->get('operations') : new Obj();
            foreach (self::utf8Sorted($ops->keys()) as $oid) {
                $op = self::derefAsync($c, $ops->get($oid), $oid);
                if ($op === null || !is_string($op->get('action')) || !in_array($op->get('action'), ['send', 'receive'], true)) {
                    self::addTodo($c, $oid, 'skipped_op', 'an operation without action send|receive is skipped');
                    continue;
                }
                $chRef = self::derefAsync($c, $op->get('channel'), $oid);
                if ($chRef === null) {
                    continue;
                }
                $chan = $op->get('channel');
                $chName = is_string($chRef->get('address')) ? $chRef->get('address') : ($chan instanceof Obj && is_string($chan->get('$ref')) ? array_slice(explode('/', $chan->get('$ref')), -1)[0] : $oid);
                if (self::isList($op->get('messages')) && count($op->get('messages')) > 0) {
                    $msgs = $op->get('messages');
                } elseif ($chRef->get('messages') instanceof Obj) {
                    $msgs = array_map(static fn($k) => $chRef->get('messages')->get($k), self::utf8Sorted($chRef->get('messages')->keys()));
                } else {
                    $msgs = [];
                }
                $emit($oid, $chName, $chRef, $op->get('action'), $op, $msgs);
            }
        } else {
            foreach (self::utf8Sorted($channels->keys()) as $chName) {
                $ch = self::derefAsync($c, $channels->get($chName), $chName);
                if ($ch === null) {
                    continue;
                }
                foreach (['publish' => 'send', 'subscribe' => 'receive'] as $key => $action) {
                    $op = self::derefAsync($c, $ch->get($key), $chName);
                    if ($op === null) {
                        continue;
                    }
                    $m = self::derefAsync($c, $op->get('message'), $chName);
                    $msgs = $m !== null && self::isList($m->get('oneOf')) ? $m->get('oneOf') : ($m !== null ? [$m] : []);
                    $oid = $op->get('operationId');
                    $emit(is_string($oid) && $oid !== '' ? $oid : null, $chName, $ch, $action, $op, $msgs);
                }
            }
        }
        return self::finish($c);
    }

    // ---- pipeline ---------------------------------------------------------------------------------------------------------

    /** Import one source of the given kind. Every def is `unreviewed`. */
    public static function importActions(mixed $kind, mixed $source, mixed $opts): Obj
    {
        switch ($kind) {
            case 'openapi':
                return self::importOpenApi($source, $opts);
            case 'mcp':
                return self::importMcp($source, $opts);
            case 'asyncapi':
                return self::importAsyncApi($source, $opts);
            case 'jsonschema':
                return self::importJsonSchema($source, $opts);
            case 'graphql':
                return ActionsImportGraphql::importGraphql($source, $opts);
            case 'grpc':
                return ActionsImportGrpc::importGrpc($source, $opts);
        }
        throw new ActionKitError('bad_kind', "unknown import kind '" . IntentWb::jsStr($kind) . "' (one of " . implode(', ', self::IMPORT_KINDS) . ')');
    }

    /**
     * Suggest for already imported defs: new defs (state `suggested`) and the model errors, if any. `$o`: mode ('rules' default, 'model' = rules plus the
     * adapters, 'none'), rules (an Obj rule set), registry (a map keyed by trait id; default the core registry), models (a list of {@see ModelAdapter}).
     * A suggestion only ever ADDS restriction and never confirms a def: an authority decision still needs a pinned reviewer's signed review.
     *
     * @param list<Obj> $defs
     * @param Obj|array<string,mixed>|null $o
     * @return Obj {defs: list<Obj>, errors: list<Obj {verb, model, error}>}
     */
    public static function suggestDefs(array $defs, mixed $o = null): Obj
    {
        $mode = Js::opt($o, 'mode') ?? 'rules';
        if ($mode === 'none') {
            return Obj::of(['defs' => array_values($defs), 'errors' => []]);
        }
        $registry = Js::opt($o, 'registry') ?? Actions::coreRegistry();
        $rules = Js::opt($o, 'rules') ?? ActionsImportSuggest::defaultRules();
        $digest = ActionsImportSuggest::rulesDigest($rules);
        $out = [];
        $errors = [];
        foreach ($defs as $d) {
            $s = ActionsImportSuggest::suggestWithRules($d, $rules, $registry);
            $models = null;
            if ($mode === 'model') {
                $run = ActionsImportModel::suggestWithModels($d, Js::opt($o, 'models') ?? [], $registry);
                foreach ($run->get('errors') as $e) {
                    $errors[] = Obj::of(['verb' => $d->get('verb'), 'model' => $e->get('model'), 'error' => $e->get('error')]);
                }
                $traits = array_values(array_unique(array_merge($s->get('traits'), $run->get('suggestion')->get('traits'))));
                usort($traits, [Actions::class, 'u16Order']);
                $s = Obj::of(['traits' => $traits, 'roles' => $s->get('roles'), 'tags' => $s->get('tags'), 'fired' => $s->get('fired')]);
                $models = $run->get('models');
            }
            $by = Obj::of(['rules' => Obj::of(['version' => $rules->get('version'), 'digest' => $digest, 'fired' => $s->get('fired')])]);
            if ($models !== null && $models !== []) {
                $by->set('models', $models);
            }
            $out[] = ActionsImportSuggest::applySuggestion($d, $s, $by);
        }
        return Obj::of(['defs' => $out, 'errors' => $errors]);
    }

    /**
     * Import then suggest. `$suggest` as for {@see suggestDefs}. Returns the import report with the suggested defs and `suggestErrors`.
     *
     * @param Obj|array<string,mixed>|null $suggest
     */
    public static function importAndSuggest(mixed $kind, mixed $source, mixed $opts, mixed $suggest = null): Obj
    {
        $r = self::importActions($kind, $source, $opts);
        $s = self::suggestDefs($r->get('defs'), $suggest);
        $out = $r->without();
        $out->set('defs', $s->get('defs'));
        $out->set('suggestErrors', $s->get('errors'));
        return $out;
    }

    /** One def per line, strict canonical JSON, sorted by verb: byte-reproducible. @param list<Obj> $defs */
    public static function defsToJsonl(array $defs): string
    {
        usort($defs, static fn(Obj $a, Obj $b): int => Actions::u16Order($a->get('verb'), $b->get('verb')));
        return implode("\n", array_map([Json::class, 'canonicalizeStrict'], $defs)) . ($defs ? "\n" : '');
    }

    /** Parse and validate a JSONL file of defs. Throws ActionKitError('bad_defs') naming the first bad line. @return list<Obj> */
    public static function jsonlToDefs(string $text): array
    {
        $out = [];
        foreach (explode("\n", $text) as $i => $line) {
            $l = self::trimWs($line);
            if ($l === '') {
                continue;
            }
            try {
                $v = Json::parseLax($l);
            } catch (\Throwable) {
                throw new ActionKitError('bad_defs', 'line ' . ($i + 1) . ': not JSON');
            }
            $bad = Actions::validateDef($v);
            if ($bad !== null) {
                throw new ActionKitError('bad_defs', 'line ' . ($i + 1) . ": $bad");
            }
            $out[] = $v;
        }
        return $out;
    }
}

require_once __DIR__ . '/ActionsImportGraphql.php';
require_once __DIR__ . '/ActionsImportGrpc.php';
require_once __DIR__ . '/ActionsImportSuggest.php';
require_once __DIR__ . '/ActionsImportModel.php';
