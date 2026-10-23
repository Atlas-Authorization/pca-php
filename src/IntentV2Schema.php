<?php

declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Part of {@see IntentV2} (a trait so the 3800-line class is split into mutation-testable files): rule 14 (signed action schemas).
 * Members are used through IntentV2 only; constants and shared helpers stay in IntentV2.
 */
trait IntentV2Schema
{
    // ==== rule 14: signed action schemas =============================================================================

    private static function paramDeclError(string $path, mixed $d, mixed $units): ?string
    {
        if (preg_match(self::PARAM_PATH_RE, $path) !== 1) {
            return "parameter path '$path' is not action.params.<name>";
        }
        if (in_array(self::paramName($path), self::RESERVED_NAMES, true)) {
            return "parameter name '$path' is reserved (__proto__ / constructor / prototype)";
        }
        if (!($d instanceof Obj)) {
            return "$path: declaration must be an object";
        }
        foreach (self::jsKeys($d) as $k) {
            if (!in_array($k, self::PARAM_KEYS, true)) {
                return "$path: unknown member '$k'";
            }
        }
        $type = self::m($d, 'type');
        if (!is_string($type) || !in_array($type, self::PARAM_TYPES, true)) {
            return "$path: unknown type";
        }
        if (!self::isStr(self::m($d, 'semantic'), 128)) {
            return "$path: semantic must be a non-empty string";
        }
        $sens = self::m($d, 'sensitivity');
        if (!is_string($sens) || !in_array($sens, self::SENSITIVITIES, true)) {
            return "$path: unknown sensitivity";
        }
        if ($d->has('required') && !is_bool($d->get('required'))) {
            return "$path: required must be a boolean";
        }
        $values = self::m($d, 'values');
        if (!self::isU($values)) {
            $ok = self::isList($values) && count($values) > 0 && count($values) <= self::MAX_SCHEMA_VALUES;
            foreach ($ok ? $values : [] as $x) {
                if (!self::isStr($x)) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "$path: values must be 1.." . self::MAX_SCHEMA_VALUES . ' strings';
            }
            if (!self::distinct($values)) {
                return "$path: values must be distinct";
            }
            if ($type !== 'string' && $type !== 'set') {
                return "$path: values apply to string and set only";
            }
        }
        if ($type === 'set' && self::isU($values)) {
            return "$path: a set needs values";
        }
        $items = self::m($d, 'items');
        foreach (['min', 'max'] as $k) {
            if ($d->has($k) && (!self::isInt($d->get($k)) || ($type !== 'integer' && !($type === 'array' && $items === 'integer')))) {
                return "$path: $k must be a safe integer on an integer parameter";
            }
        }
        $min = self::m($d, 'min');
        $max = self::m($d, 'max');
        if (self::isInt($min) && self::isInt($max) && self::f($min) > self::f($max)) {
            return "$path: min > max";
        }
        $unit = self::m($d, 'unit');
        if (!self::isU($unit) && ($type !== 'integer' || !is_string($unit) || !($units instanceof Obj) || !$units->has($unit))) {
            return "$path: unit must name a declared unit of an integer parameter";
        }
        if ($d->has('max_len') && (!self::isInt($d->get('max_len')) || self::f($d->get('max_len')) < 1)) {
            return "$path: max_len must be a positive safe integer";
        }
        if (!self::isU($items) && ($type !== 'array' || !self::isStr($items, 64))) {
            return "$path: items applies to array only";
        }
        foreach (['min_items', 'max_items'] as $k) {
            if ($d->has($k) && (!self::isNonNeg($d->get($k)) || ($type !== 'set' && $type !== 'array'))) {
                return "$path: $k must be a non-negative safe integer on a set or array";
            }
        }
        $mi = self::m($d, 'min_items');
        $ma = self::m($d, 'max_items');
        if (self::isInt($mi) && self::isInt($ma) && self::f($mi) > self::f($ma)) {
            return "$path: min_items > max_items";
        }
        if ($d->has('default') && $d->get('default') === null) {
            return "$path: default must not be null (absent = no default)";
        }
        $pnd = self::m($d, 'principal_neutral_default');
        if (!self::isU($pnd) && !is_bool($pnd)) {
            return "$path: principal_neutral_default must be a boolean";
        }
        if ($pnd === true && !$d->has('default')) {
            return "$path: principal_neutral_default needs a default";
        }
        $ai = self::m($d, 'accumulates_into');
        if (!self::isU($ai)) {
            if ($type !== 'integer') {
                return "$path: accumulates_into applies to integer parameters only";
            }
            if (!self::isList($ai) || count($ai) === 0 || count($ai) > 8) {
                return "$path: accumulates_into must be 1..8 unit ids";
            }
            foreach ($ai as $u) {
                if (!is_string($u) || self::u16len($u) > 64 || preg_match(self::UNIT_ID_RE, $u) !== 1) {
                    return "$path: accumulates_into entries must be unit ids";
                }
            }
            if (!self::distinct($ai)) {
                return "$path: accumulates_into must be distinct";
            }
        }
        if ($d->has('issued_by_site') && !is_bool($d->get('issued_by_site'))) {
            return "$path: issued_by_site must be a boolean";
        }
        if ($d->has('description') && !self::isStr($d->get('description'), 1024)) {
            return "$path: description must be a string";
        }
        return null;
    }

    private static function inRev(mixed $x): bool
    {
        return is_string($x) && in_array($x, self::SCHEMA_REVERSIBILITY, true);
    }

    private static function verbDeclError(mixed $v, mixed $units): ?string
    {
        if (!($v instanceof Obj)) {
            return 'verb entry must be an object';
        }
        foreach (self::jsKeys($v) as $k) {
            if (!in_array($k, self::VERB_KEYS, true)) {
                return "verb entry: unknown member '$k'";
            }
        }
        if (!self::isStr(self::m($v, 'verb'), 128)) {
            return 'verb entry: verb must be a non-empty string';
        }
        $at = "verb '" . $v->get('verb') . "'";
        $kind = self::m($v, 'kind');
        if ($kind !== 'read' && $kind !== 'write') {
            return "$at: kind must be read or write";
        }
        $params = self::m($v, 'params');
        if (!($params instanceof Obj)) {
            return "$at: params must be an object";
        }
        $names = self::jsKeys($params);
        if (count($names) > self::MAX_SCHEMA_PARAMS) {
            return "$at: more than " . self::MAX_SCHEMA_PARAMS . ' parameters';
        }
        foreach ($names as $p) {
            $e = self::paramDeclError($p, $params->get($p), $units);
            if ($e !== null) {
                return "$at: $e";
            }
        }
        if ($v->has('reversibility') && !self::inRev($v->get('reversibility'))) {
            return "$at: unknown reversibility";
        }
        if ($v->has('reversibility_by')) {
            $r = $v->get('reversibility_by');
            $ok = $r instanceof Obj;
            foreach ($ok ? self::jsKeys($r) : [] as $k) {
                if (!in_array($k, ['param', 'map', 'default'], true)) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "$at: reversibility_by must be {param, map, default?}";
            }
            $rp = self::m($r, 'param');
            if (!is_string($rp) || !$params->has($rp)) {
                return "$at: reversibility_by.param must be a declared parameter";
            }
            $map = self::m($r, 'map');
            $ok = $map instanceof Obj && count($map->keys()) > 0;
            foreach ($ok ? $map->keys() : [] as $k) {
                if (!self::inRev($map->get($k))) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "$at: reversibility_by.map must map values to reversibility classes";
            }
            if ($r->has('default') && !self::inRev($r->get('default'))) {
                return "$at: reversibility_by.default is not a reversibility class";
            }
        }
        if ($v->has('mcp')) {
            $x = $v->get('mcp');
            if (!($x instanceof Obj) || implode(',', self::jsKeys($x)) !== 'tool' || !self::isStr(self::m($x, 'tool'), 128)) {
                return "$at: mcp must be {tool}";
            }
        }
        if ($v->has('openapi')) {
            $x = $v->get('openapi');
            if (!($x instanceof Obj) || implode(',', self::jsKeys($x)) !== 'operationId' || !self::isStr(self::m($x, 'operationId'), 128)) {
                return "$at: openapi must be {operationId}";
            }
        }
        foreach (['harm', 'effects', 'returns'] as $k) {
            if ($v->has($k) && !($v->get($k) instanceof Obj)) {
                return "$at: $k must be an object";
            }
        }
        if ($v->has('world') && !self::isList($v->get('world'))) {
            return "$at: world must be an array";
        }
        if ($v->has('description') && !self::isStr($v->get('description'), 1024)) {
            return "$at: description must be a string";
        }
        return null;
    }

    /** Structural validation of a signed schema document (actionSchemaShapeError). Null = well-formed. Never throws. */
    public static function actionSchemaShapeError(mixed $doc): ?string
    {
        try {
            if (!($doc instanceof Obj)) {
                return 'schema is not an object';
            }
            foreach (self::jsKeys($doc) as $k) {
                if (!in_array($k, self::DOC_KEYS, true)) {
                    return "unknown member '$k'";
                }
            }
            if (!self::eq(self::m($doc, 'v'), 1)) {
                return 'unsupported schema version';
            }
            if (self::m($doc, 'kind') !== self::ACTION_SCHEMA_KIND) {
                return "kind must be '" . self::ACTION_SCHEMA_KIND . "'";
            }
            if (!self::isStr(self::m($doc, 'site'), 2048) || !self::isStr(self::m($doc, 'aud'), 256) || !self::isStr(self::m($doc, 'version'), 128)) {
                return 'site, aud and version must be non-empty strings';
            }
            $units = self::m($doc, 'units');
            if (!self::isU($units)) {
                if (!($units instanceof Obj)) {
                    return 'units must be an object';
                }
                foreach (self::jsKeys($units) as $id) {
                    $u = $units->get($id);
                    if (preg_match(self::UNIT_ID_RE, $id) !== 1 || self::u16len($id) > 64) {
                        return "unit id '$id' is malformed";
                    }
                    if (!($u instanceof Obj) || !self::isStr(self::m($u, 'kind'), 64)) {
                        return "unit '$id' must be an object with a kind";
                    }
                    foreach (self::jsKeys($u) as $k) {
                        if (!in_array($k, ['kind', 'currency', 'exponent'], true)) {
                            return "unit '$id': unknown member";
                        }
                    }
                    if ($u->has('currency') && !self::isStr($u->get('currency'), 16)) {
                        return "unit '$id': currency must be a string";
                    }
                    if ($u->has('exponent') && !(self::isNonNeg($u->get('exponent')) && self::f($u->get('exponent')) <= 18)) {
                        return "unit '$id': exponent must be an integer in [0, 18]";
                    }
                }
            }
            if ($doc->has('state') && !self::isList($doc->get('state'))) {
                return 'state must be an array';
            }
            $verbs = self::m($doc, 'verbs');
            if (!self::isList($verbs) || count($verbs) === 0 || count($verbs) > self::MAX_SCHEMA_VERBS) {
                return 'verbs must be 1..' . self::MAX_SCHEMA_VERBS . ' entries';
            }
            $seen = [];
            foreach ($verbs as $v) {
                $e = self::verbDeclError($v, $units);
                if ($e !== null) {
                    return $e;
                }
                $name = $v->get('verb');
                if (isset($seen['k' . $name])) {
                    return "verb '$name' is declared twice";
                }
                $seen['k' . $name] = true;
            }
            $s = self::m($doc, 'sig');
            if (!($s instanceof Obj)) {
                return 'sig must be an object';
            }
            foreach (self::jsKeys($s) as $k) {
                if (!in_array($k, self::SIG_KEYS, true)) {
                    return "sig: unknown member '$k'";
                }
            }
            if (($se = self::suiteError(self::m($s, 'alg'))) !== null) {
                return "sig.alg: $se";
            }
            if (!self::isStr(self::m($s, 'kid'), 128)) {
                return 'sig.kid must be a non-empty string';
            }
            if (Pca::unb64u(self::m($s, 'value')) === null) {
                return 'sig.value is not canonical base64url';
            }
            if ($s->has('pq_value') && Pca::unb64u($s->get('pq_value')) === null) {
                return 'sig.pq_value is not canonical base64url';
            }
            self::canonicalize($doc->without('sig'));
            return null;
        } catch (\Throwable $e) {
            return 'malformed schema: ' . $e->getMessage();
        }
    }

    /**
     * verifyActionSchema: shape, `keys` an array, `sig.kid` names a listed key (string `pq_pk` when present), that key's pk is
     * 32 bytes and its suite implemented, `sig.alg` equals the KEY's suite, and the signature verifies (a PQ key only as pinned
     * by the key entry). Never throws. @return array{ok:bool, reason?:string}
     */
    public static function verifyActionSchema(mixed $doc, mixed $keys): array
    {
        try {
            $bad = self::actionSchemaShapeError($doc);
            if ($bad !== null) {
                return self::bad($bad);
            }
            /** @var Obj $doc */
            if (!self::isList($keys)) {
                return self::bad('the schema keys must be an array');
            }
            $sig = $doc->get('sig');
            $kid = $sig->get('kid');
            $key = null;
            foreach ($keys as $k) {
                if ($k instanceof Obj && self::eq(self::m($k, 'kid'), $kid)) {
                    $key = $k;
                    break;
                }
            }
            if ($key === null) {
                return self::bad("no schema key with kid '$kid'");
            }
            if ($key->has('pq_pk') && !is_string($key->get('pq_pk'))) {
                return self::bad('the schema key pq_pk must be a string');
            }
            $pk = self::m($key, 'pk');
            if (Pca::unb64u($pk, 32) === null) {
                return self::bad('schema key pk is not canonical base64url (32 bytes)');
            }
            if (($kse = self::suiteError(self::m($key, 'alg'))) !== null) {
                return self::bad("schema key: $kse");
            }
            $ka = self::suiteOf(self::m($key, 'alg'));
            if ($ka !== self::suiteOf(self::m($sig, 'alg'))) {
                return self::bad('sig.alg does not match the pinned key suite');
            }
            $pq = self::m($key, 'pq_pk');
            $msg = self::ACTION_SCHEMA_DOMAIN . self::canonicalize($doc->without('sig'));
            if (!self::verifyPinned($ka, $pk, $pq, $msg, self::m($sig, 'value'), self::m($sig, 'pq_value'), self::isU($pq) ? null : $pk, $pq)) {
                return self::bad('schema signature invalid');
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return self::bad('schema verification error: ' . $e->getMessage());
        }
    }

    /** The schema's content address over the whole signed document. Throws JsonError on a non-canonical document. */
    public static function actionSchemaDigest(mixed $doc): string
    {
        return self::hashCanonical(Obj::of(['d' => self::ACTION_SCHEMA_REF_DOMAIN, 's' => $doc]));
    }

    /** schemaVerb: the first verb entry (an object) whose `verb` is `$verb`, else absent. */
    public static function schemaVerb(mixed $doc, mixed $verb): mixed
    {
        $verbs = self::m($doc, 'verbs');
        if (!self::isList($verbs)) {
            return self::undef();
        }
        foreach ($verbs as $v) {
            if ($v instanceof Obj && is_string($verb) && self::m($v, 'verb') === $verb) {
                return $v;
            }
        }
        return self::undef();
    }

    private static function isCalendarDate(string $s): bool
    {
        if (preg_match(self::DATE_RE, $s, $m) !== 1) {
            return false;
        }
        $y = (int)$m[1];
        $mo = (int)$m[2];
        $d = (int)$m[3];
        if ($y < 1 || $mo < 1 || $mo > 12 || $d < 1) {
            return false;
        }
        $leap = ($y % 4 === 0 && $y % 100 !== 0) || $y % 400 === 0;
        return $d <= [31, $leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][$mo - 1];
    }

    /** A declared numeric bound (absent -> `$default`), as a float; a present non-number bound is NAN (never satisfied). */
    private static function bound(mixed $d, string $k, ?float $default): ?float
    {
        $x = self::m($d, $k);
        if (self::isU($x)) {
            return $default;
        }
        return self::f($x) ?? NAN;
    }

    /** paramValueViolation: null when `$x` lies in the declared domain, else ['code' => bad_type|out_of_domain, 'reason']. */
    public static function paramValueViolation(mixed $d, mixed $x): ?array
    {
        $maxLen = self::bound($d, 'max_len', (float)self::DEFAULT_MAX_LEN);
        $ml = self::jsNumStr($maxLen);
        $bt = fn(string $r) => ['code' => 'bad_type', 'reason' => $r];
        $od = fn(string $r) => ['code' => 'out_of_domain', 'reason' => $r];
        $values = self::m($d, 'values');
        $min = self::bound($d, 'min', null);
        $max = self::bound($d, 'max', null);
        $type = self::m($d, 'type');
        // strict, like the reference: a non-string `type` must not loosely match a case (true == 'string')
        switch (is_string($type) ? $type : '') {
            case 'string':
                if (!is_string($x) || self::lone($x)) {
                    return $bt('expected a string');
                }
                if (!(strlen($x) <= $maxLen)) {
                    return $od("longer than $ml UTF-8 bytes");
                }
                if (!self::isU($values) && !(self::isList($values) && in_array($x, $values, true))) {
                    return $od('not one of the declared values');
                }
                return null;
            case 'integer':
                if (!self::isInt($x)) {
                    return $bt('expected a safe integer');
                }
                if ($min !== null && !(self::f($x) >= $min)) {
                    return $od('below min ' . self::jsNumStr($min));
                }
                if ($max !== null && !(self::f($x) <= $max)) {
                    return $od('above max ' . self::jsNumStr($max));
                }
                return null;
            case 'boolean':
                return is_bool($x) ? null : $bt('expected a boolean');
            case 'date':
                if (!is_string($x)) {
                    return $bt('expected a YYYY-MM-DD string');
                }
                return self::isCalendarDate($x) ? null : $od('not a calendar date YYYY-MM-DD');
            case 'set':
                if (!self::isList($x) || count(array_filter($x, 'is_string')) !== count($x)) {
                    return $bt('expected an array of strings');
                }
                if (!self::distinct($x)) {
                    return $od('set members must be distinct');
                }
                $vals = self::isList($values) ? $values : [];
                foreach ($x as $e) {
                    if (!in_array($e, $vals, true)) {
                        return $od('set member not among the declared values');
                    }
                }
                $n = (float)count($x);
                if (!($n >= self::bound($d, 'min_items', 0.0)) || !($n <= self::bound($d, 'max_items', (float)count($vals)))) {
                    return $od('set size outside the declared bounds');
                }
                return null;
            case 'array':
                if (!self::isList($x)) {
                    return $bt('expected an array');
                }
                $ints = self::m($d, 'items') === 'integer';
                foreach ($x as $e) {
                    $ok = $ints ? self::isInt($e) : (is_string($e) && !self::lone($e) && strlen($e) <= $maxLen);
                    if (!$ok) {
                        return $bt($ints ? 'array items must be safe integers' : "array items must be strings of at most $ml UTF-8 bytes");
                    }
                    if ($ints && (($min !== null && !(self::f($e) >= $min)) || ($max !== null && !(self::f($e) <= $max)))) {
                        return $od('array item outside min/max');
                    }
                }
                $n = (float)count($x);
                if (!($n >= self::bound($d, 'min_items', 0.0)) || !($n <= self::bound($d, 'max_items', (float)self::DEFAULT_MAX_ITEMS))) {
                    return $od('array length outside the declared bounds');
                }
                return null;
            default:
                return $bt('unknown declared type');
        }
    }

    /**
     * conformAction (rule 14 step 5, first failure wins): params_not_object, unknown_verb, undeclared_param (params keys in
     * UTF-8 byte order), then every declared path in UTF-8 byte order: missing_param, bad_type / out_of_domain.
     * @return array{ok:bool, code?:string, path?:string, reason?:string, verb?:Obj}
     */
    public static function conformAction(mixed $doc, mixed $verb, mixed $params): array
    {
        if (!($params instanceof Obj)) {
            return ['ok' => false, 'code' => 'params_not_object', 'reason' => 'params must be a JSON object'];
        }
        $v = self::schemaVerb($doc, $verb);
        if (self::isU($v)) {
            return ['ok' => false, 'code' => 'unknown_verb', 'reason' => "verb '" . self::txt($verb) . "' is not declared by the schema"];
        }
        $vp = self::m($v, 'params');
        $vp = $vp instanceof Obj ? $vp : new Obj();
        foreach (self::sortUtf8($params->keys()) as $k) {
            $path = 'action.params.' . $k;
            if (!$vp->has($path)) {
                return ['ok' => false, 'code' => 'undeclared_param', 'path' => $path,
                    'reason' => "parameter '$path' is not declared for '" . self::txt($verb) . "'"];
            }
        }
        foreach (self::sortUtf8($vp->keys()) as $path) {
            $d = $vp->get($path);
            $name = self::paramName($path);
            if (!$params->has($name)) {
                if (self::m($d, 'required') !== false) {
                    return ['ok' => false, 'code' => 'missing_param', 'path' => $path, 'reason' => "required parameter '$path' is missing"];
                }
                continue;
            }
            $bad = self::paramValueViolation($d, $params->get($name));
            if ($bad !== null) {
                return ['ok' => false, 'code' => $bad['code'], 'path' => $path, 'reason' => "'$path': " . $bad['reason']];
            }
        }
        return ['ok' => true, 'verb' => $v];
    }

    /** accumulationParams: the integer params of a verb entry whose `accumulates_into` lists `$unit` (UTF-8 byte order). @return list<string> */
    public static function accumulationParams(mixed $v, mixed $unit): array
    {
        $vp = self::m($v, 'params');
        $out = [];
        foreach ($vp instanceof Obj ? $vp->keys() : [] as $p) {
            $d = $vp->get($p);
            $ai = self::m($d, 'accumulates_into');
            if (self::m($d, 'type') === 'integer' && self::isList($ai) && is_string($unit) && in_array($unit, $ai, true)) {
                $out[] = $p;
            }
        }
        return self::sortUtf8($out);
    }

    /**
     * env.canon of a conforming action: for every PRESENT boolean ("true"/"false"), set (strict canonical JSON of its
     * members sorted by UTF-8 bytes) and array (strict canonical JSON as sent) parameter.
     */
    public static function canonProjection(mixed $doc, mixed $verb, Obj $params): Obj
    {
        $out = new Obj();
        $v = self::schemaVerb($doc, $verb);
        $vp = self::m($v, 'params');
        foreach ($vp instanceof Obj ? self::sortUtf8($vp->keys()) : [] as $path) {
            $name = self::paramName($path);
            if (!$params->has($name)) {
                continue;
            }
            $x = $params->get($name);
            $type = self::m($vp->get($path), 'type');
            if ($type === 'boolean') {
                $out->set($name, $x === true ? 'true' : 'false');
            } elseif ($type === 'set' && self::isList($x)) {
                $out->set($name, self::canonicalize(self::sortUtf8($x)));
            } elseif ($type === 'array') {
                $out->set($name, self::canonicalize($x));
            }
        }
        return $out;
    }
}
