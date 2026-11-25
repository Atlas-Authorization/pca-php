<?php

declare(strict_types=1);

namespace Atlas\Pca;

use Atlas\Pca\Attest\Common;

/**
 * Authoring forms of an ActionDef (native port of the authoring module of the reference actions package): the param and resource
 * shorthands, the entry expansion, and the document loaders over a parsed value (loadActionsValue) and over text, YAML 1.2 core schema or
 * JSON, with source positions (loadActionsText). One action has one digest whichever way it was written; every expanded def is checked
 * by Actions::validateDef. The YAML syntax layer is ActionsYamlLoad (see there for what it refuses beyond the reference).
 *
 * Values are the package JSON model (Obj, list, string, Num, bool, null; a raw float only for NaN and the infinities). A result is an Obj
 * {defs, notes, errors, locs, rules[, ns]}.
 */
final class ActionsAuthor
{
    public const MAX_AUTHOR_BYTES = 1048576;
    public const IDEMPOTENCY_PARAM = 'idempotency_key';
    private const AUTO_IDEMPOTENT_EFFECTS = ['send', 'pay', 'create', 'provision', 'publish'];
    private const BLAST_RADII = ['one', 'bounded', 'tenant', 'global'];
    private const RESOURCE_SCOPES = ['one', 'set', 'tenant', 'global'];
    private const PROVENANCE_LEVELS = ['first_party', 'tool', 'agent'];
    private const ID_CLASSES = ['digits', 'hex', 'alnum', 'slug', 'uuid', 'any_safe'];
    private const ENTRY_KEYS = ['v', 'kind', 'verb', 'aliases', 'title', 'description', 'effects', 'resource', 'params', 'reversibility', 'blast',
        'side_effects', 'idempotency', 'context', 'traits', 'audience', 'compensates', 'bindings', 'examples', 'review', 'source', 'since'];
    private const FILE_KEYS = ['ns', 'since', 'actions'];
    private const SHORTHAND_RE = '/\A([a-z_]+(?::[a-z0-9_]+(?:\.[a-z0-9_]+){0,3})?)(?:\(((?:(?!\xE2\x80[\xA8\xA9])[^\n\r])*)\))?(\?)?\z/';

    // ---- small helpers -----------------------------------------------------------------------------------------------------

    private static function num(int $i): Num
    {
        return new Num((string)$i);
    }

    /** @param array<string,mixed> $a */
    private static function obj(array $a): Obj
    {
        return Obj::of($a);
    }

    private static function trim(string $s): string
    {
        return Common::jsTrim($s);
    }

    /** @return array{0:list<string>,1:array<string,string>} */
    private static function splitArgs(string $s): array
    {
        $pos = [];
        $named = [];
        foreach (explode(',', $s) as $raw) {
            $a = self::trim($raw);
            if ($a === '') {
                continue;
            }
            $eq = strpos($a, '=');
            if ($eq !== false && $eq > 0) {
                $named['k' . self::trim(substr($a, 0, $eq))] = self::trim(substr($a, $eq + 1));
            } else {
                $pos[] = $a;
            }
        }
        return [$pos, $named];
    }

    private static function intArg(?string $s, string $what): ?int
    {
        if ($s === null) {
            return null;
        }
        if (preg_match('/\A-?[0-9]{1,15}\z/', $s) !== 1) {
            throw new ActionKitError('bad_shorthand', "$what must be an integer, got '$s'");
        }
        return (int)$s;
    }

    /** @param list<string> $pos @param array<string,string> $named @param list<string> $names */
    private static function only(array $pos, array $named, int $n, array $names, string $shorthand): void
    {
        if (count($pos) > $n) {
            throw new ActionKitError('bad_shorthand', "'$shorthand' takes at most $n positional argument(s)");
        }
        foreach (array_keys($named) as $k) {
            if (!in_array(substr($k, 1), $names, true)) {
                throw new ActionKitError('bad_shorthand', "'$shorthand' has no option '" . substr($k, 1) . "'");
            }
        }
    }

    /** @return list<string> */
    private static function listArg(string $s, string $shorthand): array
    {
        $xs = array_map(self::trim(...), explode('|', $s));
        foreach ($xs as $x) {
            if ($x === '') {
                throw new ActionKitError('bad_shorthand', "'$shorthand' needs values separated by |");
            }
        }
        return $xs;
    }

    // ---- shorthands --------------------------------------------------------------------------------------------------------

    /**
     * Expand one param shorthand (email phone url uuid ccy country secret bool date datetime duration text(N) string(N) message(N)
     * int(MIN..MAX) count(MAX) money(CCY|@param, max=, min=, exp=, provenance=) id:<type> enum(a|b) set(a|b) array(items, max=, min=));
     * a trailing `?` makes it optional.
     * @throws ActionKitError bad_shorthand
     */
    public static function parseParamShorthand(string $src): Obj
    {
        if (preg_match(self::SHORTHAND_RE, self::trim($src), $m, PREG_UNMATCHED_AS_NULL) !== 1) {
            throw new ActionKitError('bad_shorthand', "unknown param shorthand '$src'");
        }
        $name = $m[1];
        $inner = $m[2];
        $optional = $m[3] === '?';
        [$pos, $named] = self::splitArgs($inner ?? '');
        $bare = static function () use ($inner, $name): void {
            if ($inner !== null) {
                throw new ActionKitError('bad_shorthand', "'$name' takes no arguments");
            }
        };
        switch (true) {
            case $name === 'email':
                $bare();
                $p = ['type' => 'string', 'role' => 'contact.email', 'format' => 'email', 'tags' => ['pii'], 'max_len' => self::num(254)];
                break;
            case $name === 'phone':
                $bare();
                $p = ['type' => 'string', 'role' => 'contact.phone', 'format' => 'phone_e164', 'tags' => ['pii'], 'max_len' => self::num(16)];
                break;
            case $name === 'url':
                $bare();
                $p = ['type' => 'string', 'role' => 'url.target', 'format' => 'url', 'max_len' => self::num(2048)];
                break;
            case $name === 'uuid':
                $bare();
                $p = ['type' => 'string', 'format' => 'uuid', 'max_len' => self::num(36)];
                break;
            case $name === 'ccy':
                $bare();
                $p = ['type' => 'string', 'role' => 'money.currency', 'format' => 'iso_currency', 'max_len' => self::num(3)];
                break;
            case $name === 'country':
                $bare();
                $p = ['type' => 'string', 'format' => 'iso_country', 'max_len' => self::num(2)];
                break;
            case $name === 'secret':
                $bare();
                $p = ['type' => 'string', 'role' => 'credential.secret', 'tags' => ['secret'], 'max_len' => self::num(512)];
                break;
            case $name === 'bool':
                $bare();
                $p = ['type' => 'boolean'];
                break;
            case $name === 'date':
                $bare();
                $p = ['type' => 'date'];
                break;
            case $name === 'datetime':
                $bare();
                $p = ['type' => 'datetime'];
                break;
            case $name === 'duration':
                self::only($pos, $named, 1, [], 'duration');
                $mx = self::intArg($pos[0] ?? null, 'duration max (ms)');
                $p = ['type' => 'duration'];
                if ($mx !== null) {
                    $p['min'] = self::num(0);
                    $p['max'] = self::num($mx);
                }
                break;
            case $name === 'text' || $name === 'string':
                self::only($pos, $named, 1, [], $name);
                $n = self::intArg($pos[0] ?? null, "$name length");
                $p = ['type' => 'string'];
                if ($n !== null) {
                    $p['max_len'] = self::num($n);
                }
                break;
            case $name === 'message':
                self::only($pos, $named, 1, [], 'message');
                $ml = self::intArg($pos[0] ?? null, 'message length');
                $p = ['type' => 'string', 'role' => 'text.message', 'tags' => ['free_text_outbound'], 'max_len' => self::num($ml ?? 1024)];
                break;
            case $name === 'int':
                self::only($pos, $named, 1, [], 'int');
                $r = null;
                if ($pos !== []) {
                    if (preg_match('/\A(-?[0-9]{1,15})\.\.(-?[0-9]{1,15})\z/', $pos[0], $r) !== 1) {
                        throw new ActionKitError('bad_shorthand', 'int takes MIN..MAX, for example int(0..100)');
                    }
                }
                $p = ['type' => 'integer'];
                if ($r !== null) {
                    $p['min'] = self::num((int)$r[1]);
                    $p['max'] = self::num((int)$r[2]);
                }
                break;
            case $name === 'count':
                self::only($pos, $named, 1, [], 'count');
                $mx = self::intArg($pos[0] ?? null, 'count max');
                $p = ['type' => 'integer', 'role' => 'count.limit', 'min' => self::num(1)];
                if ($mx !== null) {
                    $p['max'] = self::num($mx);
                }
                $p['unit'] = self::obj(['kind' => 'count']);
                break;
            case $name === 'money':
                self::only($pos, $named, 1, ['max', 'min', 'exp', 'provenance'], 'money');
                $c = $pos[0] ?? null;
                if ($c === null) {
                    throw new ActionKitError('bad_shorthand', 'money needs a currency: money(USD) or money(@currency_param)');
                }
                $ccy = str_starts_with($c, '@') ? self::obj(['from' => substr($c, 1)]) : $c;
                $mx = self::intArg($named['kmax'] ?? null, 'money max');
                $prov = $named['kprovenance'] ?? 'first_party'; // an amount defaults to provenance first_party
                if (!in_array($prov, self::PROVENANCE_LEVELS, true)) {
                    throw new ActionKitError('bad_shorthand', 'money provenance must be one of ' . implode(', ', self::PROVENANCE_LEVELS));
                }
                $mn = self::intArg($named['kmin'] ?? null, 'money min');
                $ex = self::intArg($named['kexp'] ?? null, 'money exp');
                $p = ['type' => 'integer', 'role' => 'money.amount', 'min' => self::num($mn ?? 1)];
                if ($mx !== null) {
                    $p['max'] = self::num($mx);
                }
                $p['unit'] = self::obj(['kind' => 'money', 'ccy' => $ccy, 'exp' => self::num($ex ?? 2)]);
                $p['provenance_min'] = $prov;
                break;
            case $name === 'enum' || $name === 'set':
                if ($inner === null) {
                    throw new ActionKitError('bad_shorthand', "$name needs values: $name(a|b|c)");
                }
                $p = ['type' => $name === 'enum' ? 'string' : 'set', 'values' => self::listArg($inner, $name)];
                break;
            case $name === 'array':
                self::only($pos, $named, 1, ['max', 'min'], 'array');
                $items = $pos[0] ?? null;
                if ($items !== 'string' && $items !== 'integer') {
                    throw new ActionKitError('bad_shorthand', 'array(items): items is string or integer');
                }
                $mx = self::intArg($named['kmax'] ?? null, 'array max');
                $mn = self::intArg($named['kmin'] ?? null, 'array min');
                $p = ['type' => 'array', 'items' => $items];
                if ($mn !== null) {
                    $p['min_items'] = self::num($mn);
                }
                if ($mx !== null) {
                    $p['max_items'] = self::num($mx);
                }
                break;
            case str_starts_with($name, 'id:'):
                $bare();
                $p = ['type' => 'string', 'role' => 'id.' . substr($name, 3), 'max_len' => self::num(64)];
                break;
            default:
                throw new ActionKitError('bad_shorthand', "unknown param shorthand '$name'");
        }
        if ($optional) {
            $p['required'] = false;
        }
        return self::obj($p);
    }

    /**
     * `type`, `type:*`, `type:exact`, `type:prefix*` or `type:prefix*{class,min..max}`, with an optional `@one|set|tenant|global`.
     * @throws ActionKitError bad_shorthand
     */
    public static function parseResourceShorthand(string $src): Obj
    {
        $s = self::trim($src);
        $scope = null;
        if (preg_match('/\A.*@([a-z]+)\z/s', $s, $at, PREG_OFFSET_CAPTURE) === 1) {
            $name = $at[1][0];
            if (!in_array($name, self::RESOURCE_SCOPES, true)) {
                throw new ActionKitError('bad_shorthand', "unknown resource scope '@$name'");
            }
            $scope = $name;
            $s = substr($s, 0, $at[1][1] - 1);
        }
        $colon = strpos($s, ':');
        if ($colon === false) {
            return self::obj(['type' => $s, 'id' => '*', 'scope' => $scope ?? 'tenant']);
        }
        $typ = substr($s, 0, $colon);
        $idsrc = substr($s, $colon + 1);
        if ($idsrc === '*') {
            return self::obj(['type' => $typ, 'id' => '*', 'scope' => $scope ?? 'set']);
        }
        $star = strpos($idsrc, '*');
        if ($star === false) {
            return self::obj(['type' => $typ, 'id' => self::obj(['exact' => $idsrc]), 'scope' => $scope ?? 'one']);
        }
        $prefix = substr($idsrc, 0, $star);
        $rest = substr($idsrc, $star + 1);
        $cls = 'alnum';
        $ln = [8, 32];
        if ($rest !== '') {
            if (preg_match('/\A\{([a-z_]+),([0-9]{1,3})\.\.([0-9]{1,3})\}\z/', $rest, $r) !== 1 || !in_array($r[1], self::ID_CLASSES, true)) {
                throw new ActionKitError('bad_shorthand', "resource id '$idsrc': expected prefix*{class,min..max}");
            }
            $cls = $r[1];
            $ln = [(int)$r[2], (int)$r[3]];
        }
        return self::obj([
            'type' => $typ,
            'id' => self::obj(['prefix' => $prefix, 'class' => $cls, 'len' => [self::num($ln[0]), self::num($ln[1])]]),
            'scope' => $scope ?? 'one',
        ]);
    }

    /** The title an action gets when it names none: "acme.invoice.send" -> "Send invoice". */
    public static function defaultTitle(string $verb): string
    {
        $seg = array_slice(explode('.', $verb), 1);
        $act = $seg === [] ? $verb : $seg[count($seg) - 1];
        $t = str_replace('_', ' ', implode(' ', [$act, ...array_slice($seg, 0, -1)]));
        return mb_strtoupper(mb_substr($t, 0, 1, 'UTF-8'), 'UTF-8') . mb_substr($t, 1, null, 'UTF-8');
    }

    private static function asList(mixed $v): mixed
    {
        return is_string($v) ? [$v] : $v;
    }

    // ---- entries -----------------------------------------------------------------------------------------------------------

    /**
     * Expand one authoring entry (shorthands or full def members) to {def, notes}. A full def (it has `kind`) is taken exactly as written;
     * Actions::validateDef decides about it.
     * @return array{def:Obj,notes:list<Obj>}
     * @throws ActionKitError bad_action / bad_shorthand for a malformed entry
     */
    public static function expandAction(mixed $entry, ?string $since = null): array
    {
        if (!($entry instanceof Obj)) {
            throw new ActionKitError('bad_action', 'an action must be an object');
        }
        foreach ($entry->keys() as $k) {
            if (!in_array($k, self::ENTRY_KEYS, true)) {
                throw new ActionKitError('bad_action', "unknown member '$k'");
            }
        }
        if ($entry->has('v')) {
            $v = $entry->get('v');
            if (!($v instanceof Num || is_float($v)) || Js::num($v) !== 1.0) {
                throw new ActionKitError('bad_action', 'unsupported def version');
            }
        }
        if ($entry->has('kind') && $entry->get('kind') !== Actions::ACTION_DEF_KIND) {
            throw new ActionKitError('bad_action', "kind must be '" . Actions::ACTION_DEF_KIND . "'");
        }
        $verb = $entry->get('verb');
        if (!is_string($verb)) {
            throw new ActionKitError('bad_action', 'verb is required');
        }
        $notes = [];
        if ($entry->has('kind')) {
            $full = new Obj();
            $full->set('v', self::num(1)); // the full form is taken exactly as written
            foreach ($entry->keys() as $k) {
                $full->set($k, $entry->get($k));
            }
            $je0 = Actions::jsonProfileError($full);
            if ($je0 !== null) {
                throw new ActionKitError('bad_action', "not strict JSON: $je0");
            }
            return ['def' => $full, 'notes' => $notes];
        }
        $out = new Obj();
        $out->set('v', self::num(1));
        $out->set('kind', Actions::ACTION_DEF_KIND);
        $out->set('verb', $verb);
        if ($entry->has('aliases')) {
            $out->set('aliases', self::asList($entry->get('aliases')));
        }
        $out->set('title', $entry->get('title') !== null ? $entry->get('title') : self::defaultTitle($verb));
        if ($entry->has('description')) {
            $out->set('description', $entry->get('description'));
        }
        if ($entry->has('effects')) {
            $out->set('effects', self::asList($entry->get('effects')));
        }
        if ($entry->has('resource')) {
            $res = $entry->get('resource');
            $out->set('resource', is_string($res) ? self::parseResourceShorthand($res) : $res);
        }
        $params = new Obj();
        if ($entry->has('params')) {
            $ep = $entry->get('params');
            if (!($ep instanceof Obj)) {
                throw new ActionKitError('bad_action', 'params must be an object');
            }
            foreach ($ep->keys() as $k) {
                $v = $ep->get($k);
                $params->set($k, is_string($v) ? self::parseParamShorthand($v) : $v);
            }
        }
        if ($entry->has('reversibility')) {
            $out->set('reversibility', $entry->get('reversibility'));
        }
        if ($entry->has('blast')) {
            $b = $entry->get('blast');
            $out->set('blast', is_string($b) ? self::obj(['radius' => $b]) : $b);
        }
        if (is_string($entry->get('blast')) && !in_array($entry->get('blast'), self::BLAST_RADII, true)) {
            throw new ActionKitError('bad_action', "unknown blast radius '" . $entry->get('blast') . "'");
        }
        if ($entry->has('side_effects')) {
            $out->set('side_effects', $entry->get('side_effects'));
        }
        $effects = self::isList($out->get('effects')) ? $out->get('effects') : [];
        $idemSet = $entry->has('idempotency');
        $idem = $entry->get('idempotency');
        if (is_string($idem)) {
            $idem = $idem === 'key_param' ? self::obj(['mode' => 'key_param', 'param' => self::IDEMPOTENCY_PARAM]) : self::obj(['mode' => $idem]);
        }
        if (!$idemSet && array_intersect(array_filter($effects, 'is_string'), self::AUTO_IDEMPOTENT_EFFECTS) !== []) {
            $idemSet = true;
            $idem = self::obj(['mode' => 'key_param', 'param' => self::IDEMPOTENCY_PARAM]);
            $notes[] = self::obj(['verb' => $verb, 'message' => self::IDEMPOTENCY_PARAM . ' auto-added']);
        }
        if ($idem instanceof Obj && $idem->get('mode') === 'key_param' && $idem->get('param') === self::IDEMPOTENCY_PARAM && !$params->has(self::IDEMPOTENCY_PARAM)) {
            $params->set(self::IDEMPOTENCY_PARAM, self::obj(['type' => 'string', 'max_len' => self::num(64)]));
        }
        if ($idemSet) {
            $out->set('idempotency', $idem);
        }
        $out->set('params', $params);
        foreach (['context', 'traits'] as $k) {
            if ($entry->has($k)) {
                $out->set($k, self::asList($entry->get($k)));
            }
        }
        foreach (['audience', 'compensates', 'bindings', 'examples', 'source'] as $k) {
            if ($entry->has($k)) {
                $out->set($k, $entry->get($k));
            }
        }
        $out->set('review', $entry->get('review') !== null ? $entry->get('review') : self::obj(['state' => 'authored']));
        $sn = $entry->get('since') !== null ? $entry->get('since') : $since;
        if ($sn !== null) {
            $out->set('since', $sn);
        }
        $je = Actions::jsonProfileError($out);
        if ($je !== null) {
            throw new ActionKitError('bad_action', "not strict JSON: $je");
        }
        return ['def' => $out, 'notes' => $notes];
    }

    private static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    private static function hasProtoKey(mixed $v, int $depth = 0): bool
    {
        if ($depth > 40) {
            return true;
        }
        if (self::isList($v)) {
            foreach ($v as $x) {
                if (self::hasProtoKey($x, $depth + 1)) {
                    return true;
                }
            }
            return false;
        }
        if ($v instanceof Obj) {
            foreach ($v->keys() as $k) {
                if ($k === '__proto__' || self::hasProtoKey($v->get($k), $depth + 1)) {
                    return true;
                }
            }
        }
        return false;
    }

    // ---- documents ---------------------------------------------------------------------------------------------------------

    private static function result(): Obj
    {
        return self::obj(['defs' => [], 'notes' => [], 'errors' => [], 'locs' => new Obj(), 'rules' => new Obj()]);
    }

    /** The result with its errors replaced by one document-level error. */
    private static function fail(Obj $res, string $msg): Obj
    {
        $o = new Obj();
        foreach ($res->keys() as $k) {
            $o->set($k, $k === 'errors' ? [self::obj(['message' => $msg])] : $res->get($k));
        }
        return $o;
    }

    /**
     * Expand an already parsed document ({ns, since?, actions: [...]}, or one raw def) to {defs, notes, errors, locs, rules[, ns]}. Never
     * throws.
     */
    public static function loadActionsValue(mixed $doc): Obj
    {
        $res = self::result();
        if (self::hasProtoKey($doc)) {
            return self::fail($res, "the document contains a '__proto__' member or nests deeper than 40");
        }
        if (!($doc instanceof Obj)) {
            return self::fail($res, 'the document must be an object');
        }
        $since = null;
        if ($doc->get('kind') === Actions::ACTION_DEF_KIND) {
            $entries = [$doc];
        } else {
            foreach ($doc->keys() as $k) {
                if (!in_array($k, self::FILE_KEYS, true)) {
                    return self::fail($res, "unknown top-level member '$k' (expected ns, since, actions)");
                }
            }
            $ns = $doc->get('ns');
            if (!is_string($ns) || preg_match('/\A[a-z][a-z0-9_]{0,31}\z/', $ns) !== 1) {
                return self::fail($res, 'ns must be a lowercase identifier');
            }
            $res->set('ns', $ns);
            if (is_string($doc->get('since'))) {
                $since = $doc->get('since');
            } elseif ($doc->has('since')) {
                return self::fail($res, 'since must be a string');
            }
            if (!self::isList($doc->get('actions'))) {
                return self::fail($res, 'actions must be a list');
            }
            $entries = $doc->get('actions');
        }
        $defs = [];
        $notes = [];
        $errors = [];
        $rulesOut = new Obj();
        foreach ($entries as $index => $e) {
            $verb = $e instanceof Obj && is_string($e->get('verb')) ? $e->get('verb') : null;
            $err = static function (string $message) use (&$errors, $index, $verb): void {
                $x = self::obj(['index' => self::num($index)]);
                if ($verb !== null && $verb !== '') {
                    $x->set('verb', $verb);
                }
                $x->set('message', $message);
                $errors[] = $x;
            };
            try {
                $hasRules = false;
                $rules = null;
                $entry = $e;
                if ($e instanceof Obj && $e->has('rules')) {
                    $hasRules = true;
                    $rules = $e->get('rules');
                    $entry = $e->without('rules');
                }
                $ex = self::expandAction($entry, $since);
                $d = $ex['def'];
                $bad = Actions::validateDef($d);
                if ($bad !== null) {
                    $err($bad);
                    continue;
                }
                if ($hasRules) {
                    $re = ActionsRulesValidate::error($d, $rules);
                    if ($re !== null) {
                        $err($re);
                        continue;
                    }
                    $rulesOut->set($d->get('verb'), $rules);
                }
                $defs[] = $d;
                array_push($notes, ...$ex['notes']);
            } catch (\Throwable $x) {
                $err($x instanceof ActionKitError ? $x->getMessage() : 'malformed action: ' . $x->getMessage());
            }
        }
        $res->set('defs', $defs);
        $res->set('notes', $notes);
        $res->set('errors', $errors);
        $res->set('rules', $rulesOut);
        return $res;
    }

    /** One entry's positions are only attached by loadActionsText. @param list<array{0:int,1:int,2:list<array{0:string,1:int,2:int}>}> $pos */
    private static function attachPositions(Obj $res, array $pos): void
    {
        $failed = [];
        foreach ($res->get('errors') as $e) {
            $i = $e->get('index');
            if ($i instanceof Num) {
                $failed[$i->int()] = true;
            }
        }
        $order = [];
        foreach (array_keys($pos) as $i) {
            if (!isset($failed[$i])) {
                $order[] = $i;
            }
        }
        $locs = $res->get('locs');
        foreach ($res->get('defs') as $k => $d) {
            $p = isset($order[$k]) ? $pos[$order[$k]] : null;
            if ($p !== null) {
                $l = self::obj(['line' => self::num($p[0]), 'column' => self::num($p[1])]);
                $params = new Obj();
                foreach ($p[2] as [$name, $line, $col]) {
                    $params->set($name, self::obj(['line' => self::num($line), 'column' => self::num($col)]));
                }
                $l->set('params', $params);
                $locs->set($d->get('verb'), $l);
            }
        }
        foreach ($res->get('errors') as $e) {
            $i = $e->get('index');
            $idx = $i instanceof Num ? $i->int() : null;
            if ($idx !== null && $idx >= 0 && $idx < count($pos)) {
                $e->set('line', self::num($pos[$idx][0]));
                $e->set('column', self::num($pos[$idx][1]));
            } elseif ($idx === null) {
                $e->set('line', self::num(1));
                $e->set('column', self::num(1));
            }
        }
    }

    private static function textFail(string $message, int $line = 1, int $column = 1): Obj
    {
        $res = self::result();
        $res->set('errors', [self::obj(['message' => $message, 'line' => self::num($line), 'column' => self::num($column)])]);
        return $res;
    }

    /**
     * Load an authoring file (YAML 1.2 core schema or JSON) with source positions. Input above MAX_AUTHOR_BYTES is refused. Never throws:
     * a syntax error is one error "not YAML: ..." / "not JSON: ..." with the position of the problem.
     */
    public static function loadActionsText(string $text, string $fmt = 'yaml'): Obj
    {
        if (strlen($text) > self::MAX_AUTHOR_BYTES) {
            return self::textFail('the file is larger than ' . self::MAX_AUTHOR_BYTES . ' bytes');
        }
        $positions = null;
        if ($fmt === 'json') {
            if (preg_match('//u', $text) !== 1) {
                return self::textFail('not JSON: invalid UTF-8');
            }
            try {
                $value = (new Parser($text, 512, true))->run(); // JSON.parse: a repeated key keeps the last value
            } catch (\Throwable $e) {
                return self::textFail('not JSON: ' . $e->getMessage());
            }
            try { // JSON is YAML: only the positions come from the YAML parse, the value from the JSON parse
                // libyaml refuses a \uD800-\uDFFF escape that JSON allows (a surrogate pair); only positions come from this parse, so each one
                // becomes a same-length \u0020 (the columns of what follows are unchanged)
                $masked = preg_replace_callback('/\\\\(?:u[dD][89a-fA-F][0-9a-fA-F]{2}|.)/s', static fn(array $m): string => strlen($m[0]) === 6 && ($m[0][1] === 'u') ? '\\u0020' : $m[0], $text);
                $positions = ActionsYamlLoad::positionsOf(ActionsYamlLoad::parseDocument($masked ?? $text, false));
            } catch (\Throwable) {
                $positions = null;
            }
        } else {
            try {
                $root = ActionsYamlLoad::parseDocument($text);
                $value = ActionsYamlLoad::toValue($root);
                $positions = ActionsYamlLoad::positionsOf($root);
            } catch (ActionsYamlError $e) {
                return self::textFail('not YAML: ' . $e->getMessage(), $e->yamlLine, $e->yamlColumn);
            } catch (\Throwable $e) {
                return self::textFail('not YAML: ' . $e->getMessage());
            }
        }
        $res = self::loadActionsValue($value);
        if ($positions !== null) {
            self::attachPositions($res, $positions);
        }
        return $res;
    }

    /**
     * The typed constructor over the JSON form: the same expansion as the loader (so the same digest).
     * @throws ActionKitError bad_action on a malformed spec
     */
    public static function action(string $verb, Obj $spec): Obj
    {
        $entry = new Obj();
        $entry->set('verb', $verb);
        foreach ($spec->keys() as $k) {
            $entry->set($k, $spec->get($k));
        }
        $d = self::expandAction($entry)['def'];
        $bad = Actions::validateDef($d);
        if ($bad !== null) {
            throw new ActionKitError('bad_action', "$verb: $bad");
        }
        return $d;
    }
}
