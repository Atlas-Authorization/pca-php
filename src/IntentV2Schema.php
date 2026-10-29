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

    private static function paramDeclError(string $path, mixed $d, mixed $units, bool $v2 = false): ?string
    {
        if (preg_match($v2 ? self::PARAM_PATH_RE_V2 : self::PARAM_PATH_RE, $path) !== 1) {
            return "parameter path '$path' is not action.params.<name>";
        }
        if (array_intersect(explode('.', self::paramName($path)), self::RESERVED_NAMES) !== []) {
            return "parameter name '$path' is reserved (__proto__ / constructor / prototype)";
        }
        if (!($d instanceof Obj)) {
            return "$path: declaration must be an object";
        }
        foreach (self::jsKeys($d) as $k) {
            if (!in_array($k, $v2 ? self::PARAM_KEYS_V2 : self::PARAM_KEYS, true)) {
                return "$path: unknown member '$k'";
            }
        }
        $type = self::m($d, 'type');
        if (!is_string($type) || !in_array($type, $v2 ? self::PARAM_TYPES_V2 : self::PARAM_TYPES, true)) {
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
            if ($d->has($k) && (!self::isInt($d->get($k)) || ($type !== 'integer' && !($v2 && $type === 'duration') && !($type === 'array' && $items === 'integer')))) {
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
        if ($v2) {
            if ($d->has('role') && !self::isStr($d->get('role'), 128)) {
                return "$path: role must be a non-empty string";
            }
            if ($d->has('format') && (!is_string($d->get('format')) || self::formatCheck($d->get('format')) === null || ($type !== 'string' && $type !== 'object_ref'))) {
                return "$path: format must be a known format on a string parameter";
            }
            if ($d->has('tags')) {
                $tg = $d->get('tags');
                $ok = self::isList($tg) && count($tg) <= count(self::SCHEMA_V2_TAGS);
                foreach ($ok ? $tg : [] as $x) {
                    if (!is_string($x) || !in_array($x, self::SCHEMA_V2_TAGS, true)) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok || !self::distinct($tg)) {
                    return "$path: tags must be distinct known tags";
                }
            }
            if ($d->has('provenance_min') && (!is_string($d->get('provenance_min')) || !in_array($d->get('provenance_min'), self::SCHEMA_V2_PROVENANCE, true))) {
                return "$path: unknown provenance_min";
            }
        }
        return null;
    }

    /** Null if `$f` is a well-formed materialized profile (shape only; the semantic check is rule 22). */
    public static function schemaFloorsError(mixed $f): ?string
    {
        if (!($f instanceof Obj)) {
            return 'floors must be an object';
        }
        foreach (self::jsKeys($f) as $k) {
            if (!in_array($k, ['risk', 'rev', 'blast_ppm', 'esc', 'caveats', 'context', 'prules'], true)) {
                return "floors: unknown member '$k'";
            }
        }
        $rng = fn(mixed $x, int $lo, int $hi): bool => self::isInt($x) && self::f($x) >= $lo && self::f($x) <= $hi;
        if (!$rng(self::m($f, 'risk'), 0, 3) || !$rng(self::m($f, 'esc'), 0, 3)) {
            return 'floors.risk and floors.esc must be integers in 0..3';
        }
        if (!self::inRev(self::m($f, 'rev'))) {
            return 'floors.rev is not a reversibility class';
        }
        if (!$rng(self::m($f, 'blast_ppm'), 0, 1000000)) {
            return 'floors.blast_ppm must be an integer in 0..1000000';
        }
        foreach (['caveats' => self::SCHEMA_V2_CAVEATS, 'context' => self::SCHEMA_V2_CONTEXT, 'prules' => self::SCHEMA_V2_PRULES] as $name => $known) {
            $a = self::m($f, $name);
            $ok = self::isList($a) && count($a) <= 64;
            foreach ($ok ? $a : [] as $x) {
                if (!is_string($x) || !(in_array($x, $known, true) || ($name === 'context' && preg_match(self::TAINT_CTX_RE, $x) === 1))) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "floors.$name must be an array of known entries";
            }
            for ($i = 1; $i < count($a); $i++) {
                if (!(strcmp($a[$i - 1], $a[$i]) < 0)) {
                    return "floors.$name must be sorted and distinct";
                }
            }
        }
        return null;
    }

    // ---- v2 string formats (syntactic checks, identical in every language) ----------------------------------------------

    private static function ibanOk(string $s): bool
    {
        if (preg_match('/\A[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}\z/', $s) !== 1) {
            return false;
        }
        $rem = 0;
        foreach (str_split(substr($s, 4) . substr($s, 0, 4)) as $ch) {
            $v = $ch >= 'A' ? ord($ch) - 55 : ord($ch) - 48;
            $rem = ($v > 9 ? $rem * 100 + $v : $rem * 10 + $v) % 97;
        }
        return $rem === 1;
    }

    private static function canonDec(string $n): bool
    {
        return (string)(int)$n === $n;
    }

    private static function cidrOk(string $s): bool
    {
        if (preg_match('/\A([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\/([0-9]{1,2})\z/', $s, $m) === 1) {
            foreach ([$m[1], $m[2], $m[3], $m[4]] as $o) {
                if ((int)$o > 255 || !self::canonDec($o)) {
                    return false;
                }
            }
            return (int)$m[5] <= 32 && self::canonDec($m[5]);
        }
        return preg_match('/\A([0-9a-fA-F:]{2,39})\/([0-9]{1,3})\z/', $s, $m) === 1 && substr_count($m[1], ':') >= 2
            && !str_contains($m[1], ':::') && (int)$m[2] <= 128 && self::canonDec($m[2]);
    }

    /** The checker of a v2 `format` (a callable over a valid UTF-8 string), or null when the format is unknown. */
    public static function formatCheck(string $f): ?callable
    {
        $ws = self::WS;
        $re = fn(string $r): callable => fn(string $s): bool => preg_match($r, $s) === 1;
        return match (true) {
            $f === 'email' => fn(string $s): bool => strlen($s) <= 254 && preg_match('/\A[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})+\z/', $s) === 1,
            $f === 'url' => $re("/\\A[A-Za-z][A-Za-z0-9+.\\-]{0,31}:\\/\\/[^$ws\\/?#]+[^$ws]*\\z/u"),
            $f === 'uri_https' => $re("/\\Ahttps:\\/\\/[^$ws\\/?#]+[^$ws]*\\z/u"),
            $f === 'uuid' => $re('/\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z/'),
            $f === 'iban' => fn(string $s): bool => self::ibanOk($s),
            $f === 'phone_e164' => $re('/\A\+[1-9][0-9]{6,14}\z/'),
            $f === 'cidr' => fn(string $s): bool => self::cidrOk($s),
            $f === 'iso_country' => $re('/\A[A-Z]{2}\z/'),
            $f === 'iso_currency' => $re('/\A[A-Z]{3}\z/'),
            $f === 'semver' => $re('/\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?(?:\+[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?\z/'),
            $f === 'sha256' => $re('/\A[0-9a-f]{64}\z/'),
            preg_match('/\Aid:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}\z/', $f) === 1 => $re('/\A[A-Za-z0-9._:\-]{1,128}\z/'),
            default => null,
        };
    }

    /** @return array{code:string,reason:string}|null */
    private static function formatViolation(mixed $d, string $x): ?array
    {
        if (!($d instanceof Obj) || !$d->has('format')) {
            return null;
        }
        $f = $d->get('format');
        $ck = is_string($f) ? self::formatCheck($f) : null;
        if ($ck === null || !$ck($x)) {
            return ['code' => 'out_of_domain', 'reason' => 'not a valid ' . self::txt($f)];
        }
        return null;
    }

    private static function inRev(mixed $x): bool
    {
        return is_string($x) && in_array($x, self::SCHEMA_REVERSIBILITY, true);
    }

    /** Shape of a verb's `confirmation` (the signature check is rule 22). Null = well-formed. */
    public static function confirmationShapeError(mixed $c): ?string
    {
        if (!($c instanceof Obj)) {
            return 'confirmation must be an object';
        }
        foreach (self::jsKeys($c) as $k) {
            if (!in_array($k, ['def_digest', 'traits_digest', 'facts_digest', 'final_traits', 'dismissed', 'reviewer_kid', 'ts', 'sig'], true)) {
                return "confirmation: unknown member '$k'";
            }
        }
        if (Pca::unb64u(self::m($c, 'def_digest'), 32) === null || Pca::unb64u(self::m($c, 'traits_digest'), 32) === null || Pca::unb64u(self::m($c, 'facts_digest'), 32) === null) {
            return 'confirmation: def_digest, traits_digest and facts_digest must be canonical base64url SHA-256 digests';
        }
        if (Pca::unb64u(self::m($c, 'sig'), 64) === null) {
            return 'confirmation: sig must be a canonical base64url 64-byte signature';
        }
        $ft = self::m($c, 'final_traits');
        $ok = self::isList($ft) && count($ft) <= 64;
        foreach ($ok ? $ft : [] as $x) {
            $ok = $ok && is_string($x) && preg_match(self::TRAIT_ID_RE, $x) === 1;
        }
        if (!$ok) {
            return 'confirmation: final_traits must be trait ids';
        }
        for ($i = 1; $i < count($ft); $i++) {
            if (!(strcmp($ft[$i - 1], $ft[$i]) < 0)) {
                return 'confirmation: final_traits must be sorted and distinct';
            }
        }
        $dm = self::m($c, 'dismissed');
        if (!self::isList($dm) || count($dm) > 64) {
            return 'confirmation: dismissed must be an array';
        }
        foreach ($dm as $d) {
            if (!($d instanceof Obj) || count(array_diff(self::jsKeys($d), ['trait', 'reason'])) > 0 || !is_string(self::m($d, 'trait'))
                || preg_match(self::TRAIT_ID_RE, $d->get('trait')) !== 1 || !self::isStr(self::m($d, 'reason'), 256)) {
                return 'confirmation: dismissed entries must be {trait, reason}';
            }
        }
        if (!self::isStr(self::m($c, 'reviewer_kid'), 128)) {
            return 'confirmation: reviewer_kid must be a non-empty string';
        }
        if (!self::isNonNeg(self::m($c, 'ts'))) {
            return 'confirmation: ts must be a non-negative safe integer';
        }
        return null;
    }

    private static function verbDeclError(mixed $v, mixed $units, bool $v2 = false): ?string
    {
        if (!($v instanceof Obj)) {
            return 'verb entry must be an object';
        }
        foreach (self::jsKeys($v) as $k) {
            if (!in_array($k, $v2 ? self::VERB_KEYS_V2 : self::VERB_KEYS, true)) {
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
            $e = self::paramDeclError($p, $params->get($p), $units, $v2);
            if ($e !== null) {
                return "$at: $e";
            }
        }
        if ($v2) {
            foreach ($names as $p) {
                foreach ($names as $q) {
                    if ($q !== $p && str_starts_with($q, $p . '.')) {
                        return "$at: parameter '$p' is both a value and the parent of '$q'";
                    }
                }
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
        foreach ($v2 ? ['harm', 'returns'] : ['harm', 'effects', 'returns'] as $k) {
            if ($v->has($k) && !($v->get($k) instanceof Obj)) {
                return "$at: $k must be an object";
            }
        }
        if ($v2) {
            $ef = self::m($v, 'effects');
            $ok = self::isList($ef) && count($ef) > 0 && count($ef) <= count(self::SCHEMA_V2_EFFECTS);
            foreach ($ok ? $ef : [] as $x) {
                if (!is_string($x) || !in_array($x, self::SCHEMA_V2_EFFECTS, true)) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "$at: effects must be 1.." . count(self::SCHEMA_V2_EFFECTS) . ' known effects';
            }
            for ($i = 1; $i < count($ef); $i++) {
                if (!(strcmp($ef[$i - 1], $ef[$i]) < 0)) {
                    return "$at: effects must be sorted and distinct";
                }
            }
            $allRead = count(array_filter($ef, fn($x) => $x === 'read')) === count($ef);
            if (($kind === 'read') !== $allRead) {
                return "$at: kind read must hold exactly when every effect is read";
            }
            $tr = self::m($v, 'traits');
            $ok = self::isList($tr) && count($tr) <= 64;
            foreach ($ok ? $tr : [] as $x) {
                if (!is_string($x) || preg_match(self::TRAIT_ID_RE, $x) !== 1) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "$at: traits must be trait ids";
            }
            for ($i = 1; $i < count($tr); $i++) {
                if (!(strcmp($tr[$i - 1], $tr[$i]) < 0)) {
                    return "$at: traits must be sorted and distinct";
                }
            }
            if (Pca::unb64u(self::m($v, 'def'), 32) === null) {
                return "$at: def must be a canonical base64url SHA-256 digest";
            }
            $fe = self::schemaFloorsError(self::m($v, 'floors'));
            if ($fe !== null) {
                return "$at: $fe";
            }
            if ($v->has('confirmation') && ($ce = self::confirmationShapeError($v->get('confirmation'))) !== null) {
                return "$at: $ce";
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
    public static function actionSchemaShapeError(mixed $doc, bool $signed = true): ?string
    {
        try {
            if (!($doc instanceof Obj)) {
                return 'schema is not an object';
            }
            $v2 = self::eq(self::m($doc, 'v'), 2);
            foreach (self::jsKeys($doc) as $k) {
                if (!in_array($k, $v2 ? self::DOC_KEYS_V2 : self::DOC_KEYS, true)) {
                    return "unknown member '$k'";
                }
            }
            if (!self::eq(self::m($doc, 'v'), 1) && !$v2) {
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
            if ($v2) {
                if ($doc->has('traits_digest') && Pca::unb64u($doc->get('traits_digest'), 32) === null) {
                    return 'traits_digest must be a canonical base64url SHA-256 digest';
                }
                if ($doc->has('trait_defs')) {
                    $td = $doc->get('trait_defs');
                    $ok = self::isList($td) && count($td) <= 64;
                    foreach ($ok ? $td : [] as $x) {
                        $ok = $ok && $x instanceof Obj;
                    }
                    if (!$ok) {
                        return 'trait_defs must be an array of up to 64 objects';
                    }
                }
                if ($doc->has('pack')) {
                    $pk = $doc->get('pack');
                    if (!($pk instanceof Obj) || self::sortedJoin($pk) !== 'ns,root,version' || !self::isStr(self::m($pk, 'ns'), 64)
                        || !self::isStr(self::m($pk, 'version'), 128) || Pca::unb64u(self::m($pk, 'root'), 32) === null) {
                        return 'pack must be {ns, version, root}';
                    }
                }
            }
            $verbs = self::m($doc, 'verbs');
            if (!self::isList($verbs) || count($verbs) === 0 || count($verbs) > self::MAX_SCHEMA_VERBS) {
                return 'verbs must be 1..' . self::MAX_SCHEMA_VERBS . ' entries';
            }
            $seen = [];
            foreach ($verbs as $v) {
                $e = self::verbDeclError($v, $units, $v2);
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
            if (!$signed) {
                if ($doc->has('sig')) {
                    return 'an unsigned schema must not carry sig';
                }
            } elseif (!($s instanceof Obj)) {
                return 'sig must be an object';
            }
            foreach ($signed ? self::jsKeys($s) : [] as $k) {
                if (!in_array($k, self::SIG_KEYS, true)) {
                    return "sig: unknown member '$k'";
                }
            }
            if ($signed && ($se = self::suiteError(self::m($s, 'alg'))) !== null) {
                return "sig.alg: $se";
            }
            if ($signed && !self::isStr(self::m($s, 'kid'), 128)) {
                return 'sig.kid must be a non-empty string';
            }
            if ($signed && Pca::unb64u(self::m($s, 'value')) === null) {
                return 'sig.value is not canonical base64url';
            }
            if ($signed && $s->has('pq_value') && Pca::unb64u($s->get('pq_value')) === null) {
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
                return self::formatViolation($d, $x);
            case 'object_ref':
                if (!is_string($x) || self::lone($x) || $x === '') {
                    return $bt('expected a non-empty id string');
                }
                if (!(strlen($x) <= $maxLen)) {
                    return $od("longer than $ml UTF-8 bytes");
                }
                return self::formatViolation($d, $x);
            case 'datetime':
                if (!is_string($x)) {
                    return $bt('expected an RFC 3339 UTC string');
                }
                return preg_match(self::DATETIME_RE, $x, $dm) === 1 && self::isCalendarDate($dm[1]) ? null
                    : $od('not an RFC 3339 UTC datetime YYYY-MM-DDTHH:MM:SS[.fff]Z');
            case 'duration':
                if (!self::isInt($x)) {
                    return $bt('expected a safe integer (milliseconds)');
                }
                if (self::f($x) < 0) {
                    return $od('a duration is not negative');
                }
                if ($min !== null && !(self::f($x) >= $min)) {
                    return $od('below min ' . self::jsNumStr($min));
                }
                if ($max !== null && !(self::f($x) <= $max)) {
                    return $od('above max ' . self::jsNumStr($max));
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
