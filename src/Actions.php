<?php

declare(strict_types=1);

namespace Atlas\Pca;

/** Raised by the registry/pack operations that refuse (the PHP form of the reference's typed error). */
final class ActionKitError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/**
 * Action kit (native port of the small deterministic core of the reference actions package): strict ActionDef parse, normalize
 * and canonical digest, the trait registry and its closure/floor algebra, rule 22 (FloorDecision and the schema floor integrity
 * check), the pack Merkle root and inclusion proof, and T(d)/eff(d). Integers and sets only; every function is pure.
 *
 * Values are the package's JSON model (Obj, list arrays, string, Num, bool, null). Profiles are PHP arrays with the seven fixed
 * members; {@see profObj} turns one into an Obj for canonical hashing and comparison. ActionSchema v2 parsing and the v2
 * parameter types/formats of conformAction live in IntentV2Schema (the schema module); this class does not grow it.
 */
final class Actions
{
    public const ACTION_DEF_KIND = 'pca-action-def';
    public const DEF_DIGEST_DOMAIN = 'atlas-pca/action-def/v1';
    public const VERB_FACTS_DOMAIN = 'atlas-pca/action-verb-facts/v1';
    public const TRAITS_DIGEST_DOMAIN = 'atlas-pca/action-traits/v1';
    public const ROLES_DIGEST_DOMAIN = 'atlas-pca/action-roles/v1';
    public const PACK_DIGEST_DOMAIN = 'atlas-pca/action-pack/v1';
    public const REVIEW_DOMAIN = 'atlas-pca/action-review/v2';
    private const KEY_ROLES = ['reviewer', 'importer', 'model', 'publisher'];

    private const MAX_SAFE = 9007199254740991;
    private const REV_RANK = ['reversible' => 0, 'rate_limited' => 1, 'irreversible' => 2];
    private const EFFECTS = ['read', 'create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'];
    private const BLAST_RADII = ['one', 'bounded', 'tenant', 'global'];
    private const BLAST_PPM = ['one' => 50000, 'bounded' => 300000, 'tenant' => 700000, 'global' => 1000000];
    private const RESOURCE_SCOPES = ['one', 'set', 'tenant', 'global'];
    private const SCOPE_BLAST = ['one' => 'one', 'set' => 'bounded', 'tenant' => 'tenant', 'global' => 'global'];
    private const PARAM_TYPES = ['string', 'integer', 'boolean', 'date', 'datetime', 'duration', 'set', 'array', 'object_ref'];
    private const SENS_RANK = ['free' => 0, 'material' => 1, 'critical' => 2];
    private const PROVENANCE = ['first_party', 'tool', 'agent'];
    private const CORE_ROLES = [
        'money.amount', 'money.currency', 'money.fee', 'party.payee', 'party.payer',
        'contact.email', 'contact.phone', 'contact.address', 'person.name', 'person.dob', 'person.national_id',
        'credential.secret', 'credential.token', 'credential.key',
        'path.fs', 'query.sql', 'query.search', 'code.source', 'code.command', 'url.target',
        'text.message', 'text.public', 'time.not_before', 'time.not_after', 'count.limit', 'bytes.size',
    ];
    private const PARAM_TAGS = ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql'];
    private const PARAM_FORMATS = ['email', 'url', 'uri_https', 'uuid', 'iban', 'phone_e164', 'cidr', 'iso_country', 'iso_currency', 'semver', 'sha256'];
    private const UNIT_KINDS = ['money', 'count', 'bytes', 'duration', 'ratio'];
    private const CAVEAT_KINDS = ['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'];
    private const CONTEXT_KEYS = ['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested'];
    private const PARAM_RULE_IDS = ['array_bounded', 'export_bounded', 'id_not_wildcard', 'money_amount_bounded', 'money_has_currency',
        'pay_has_idempotency', 'recipient_param_declared', 'secret_not_logged'];
    private const IDEMPOTENCY_MODES = ['key_param', 'natural', 'none'];
    private const REVIEW_STATES = ['authored', 'unreviewed', 'suggested', 'confirmed'];
    private const BINDING_KINDS = ['mcp', 'openapi', 'http', 'graphql', 'grpc', 'asyncapi'];
    private const ID_CLASSES = ['digits', 'hex', 'alnum', 'slug', 'uuid', 'any_safe'];
    private const RESERVED = ['__proto__', 'constructor', 'prototype'];
    private const INT_ROLES = ['money.amount', 'money.fee', 'count.limit', 'bytes.size'];
    private const PARAM_KEYS = ['type', 'role', 'required', 'values', 'min', 'max', 'max_len', 'items', 'min_items', 'max_items', 'format', 'unit',
        'tags', 'provenance_min', 'sensitivity', 'accumulates', 'default', 'principal_neutral_default', 'description'];
    private const DEF_KEYS = ['v', 'kind', 'verb', 'aliases', 'title', 'description', 'effects', 'resource', 'params', 'reversibility', 'blast',
        'side_effects', 'idempotency', 'context', 'traits', 'audience', 'compensates', 'bindings', 'examples', 'review', 'source', 'since'];

    private const ID_ROLE_RE = '/\Aid\.[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}\z/';
    private const CUSTOM_ROLE_RE = '/\Ax\.[a-z0-9_]+(?:\.[a-z0-9_]+){1,3}\z/';
    private const ID_FORMAT_RE = '/\Aid:[a-z0-9_]+(?:\.[a-z0-9_]+){0,3}\z/';
    private const TAINT_RE = '/\Asession_taint_max:[a-z_]{1,16}\z/';
    private const VERB_RE = '/\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){1,5}\z/';
    private const ALIAS_RE = '/\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,5}\z/';
    private const PARAM_NAME_RE = '/\A[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}\z/';
    private const TRAIT_ID_RE = '/\A[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}\z/';
    private const RESOURCE_TYPE_RE = '/\A[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}\z/';
    private const UNIT_ID_RE = '/\A[a-z0-9_]+(?:\.[a-z0-9_]+)*\z/';
    private const CCY_RE = '/\A[A-Z]{3}\z/';

    // ---- small helpers ------------------------------------------------------------------------------------------------------

    private static function g(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : null;
    }

    private static function has(mixed $o, string $k): bool
    {
        return $o instanceof Obj && $o->has($k);
    }

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    private static function f(mixed $x): ?float
    {
        if ($x instanceof Num) {
            return (float)$x->lexeme;
        }
        return is_int($x) ? (float)$x : (is_float($x) ? $x : null);
    }

    /** A safe integer by value: integral, |v| <= 2^53-1, not -0 (a bool is not a number). */
    private static function isInt(mixed $x): bool
    {
        $f = self::f($x);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= self::MAX_SAFE && !($f == 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function iv(mixed $x): int
    {
        return (int)self::f($x);
    }

    private static function isNonNeg(mixed $x): bool
    {
        return self::isInt($x) && self::f($x) >= 0;
    }

    private static function isStr(mixed $v, int $max = 256): bool
    {
        return is_string($v) && $v !== '' && strlen($v) <= $max;
    }

    private static function inS(mixed $x, array $options): bool
    {
        return is_string($x) && in_array($x, $options, true);
    }

    private static function eqInt(mixed $x, int $n): bool
    {
        $f = self::f($x);
        return $f !== null && $f == $n;
    }

    private static function distinct(array $xs): bool
    {
        return count(array_unique($xs, SORT_STRING)) === count($xs);
    }

    /** @param list<string> $xs @return list<string> */
    private static function sortUniq(array $xs): array
    {
        $xs = array_values(array_unique($xs, SORT_STRING));
        sort($xs, SORT_STRING);
        return $xs;
    }

    private static function isContextKey(mixed $k): bool
    {
        return is_string($k) && (in_array($k, self::CONTEXT_KEYS, true) || preg_match(self::TAINT_RE, $k) === 1);
    }

    private static function strList(mixed $v, int $mx, callable $ok): bool
    {
        if (!self::isList($v) || count($v) > $mx) {
            return false;
        }
        foreach ($v as $x) {
            if (!is_string($x) || !$ok($x)) {
                return false;
            }
        }
        return self::distinct($v);
    }

    private static function u8(string $s): int
    {
        return strlen($s);
    }

    private static function lone(string $s): bool
    {
        return Json::hasLoneSurrogate($s);
    }

    /** NFC of valid UTF-8 (a string with a lone surrogate was already refused). */
    private static function nfc(string $s): bool
    {
        return preg_match('//u', $s) === 1 && \Normalizer::isNormalized($s, \Normalizer::FORM_C);
    }

    private static function sorted(mixed $o): string
    {
        $k = $o->keys();
        sort($k, SORT_STRING);
        return implode(',', $k);
    }

    // ---- strict JSON profile + ActionDef validation -------------------------------------------------------------------------

    /** Strict JSON profile: plain objects/arrays, NFC strings without lone surrogates, safe integers only, depth <= 32. */
    public static function jsonProfileError(mixed $v, int $depth = 0): ?string
    {
        if ($depth > 32) {
            return 'nesting deeper than 32';
        }
        if ($v === null || is_bool($v)) {
            return null;
        }
        if ($v instanceof Num) {
            return self::isInt($v) ? null : 'numbers must be safe integers (no floats, no -0)';
        }
        if (is_string($v)) {
            if (self::lone($v)) {
                return 'string has a lone surrogate';
            }
            return self::nfc($v) ? null : 'string is not NFC';
        }
        if (self::isList($v)) {
            foreach ($v as $x) {
                if (($e = self::jsonProfileError($x, $depth + 1)) !== null) {
                    return $e;
                }
            }
            return null;
        }
        if ($v instanceof Obj) {
            foreach ($v->keys() as $k) {
                if (self::lone($k) || !self::nfc($k)) {
                    return 'member name is not NFC / has a lone surrogate';
                }
                if (($e = self::jsonProfileError($v->get($k), $depth + 1)) !== null) {
                    return $e;
                }
            }
            return null;
        }
        return 'only JSON values are allowed';
    }

    private static function isRole(mixed $r): bool
    {
        return is_string($r) && (in_array($r, self::CORE_ROLES, true) || preg_match(self::ID_ROLE_RE, $r) === 1 || preg_match(self::CUSTOM_ROLE_RE, $r) === 1);
    }

    private static function isFormat(mixed $f): bool
    {
        return is_string($f) && (in_array($f, self::PARAM_FORMATS, true) || preg_match(self::ID_FORMAT_RE, $f) === 1);
    }

    private static function idClassChars(string $c): string
    {
        $d = '0123456789';
        $l = 'abcdefghijklmnopqrstuvwxyz';
        $u = strtoupper($l);
        return match ($c) {
            'digits' => $d, 'hex' => $d . 'abcdef', 'alnum' => $d . $l . $u, 'slug' => $d . $l . '-_',
            'uuid' => $d . 'abcdef-', default => $d . $l . $u . '._-:/',
        };
    }

    private static function inClass(string $s, string $c): bool
    {
        return $s === '' || strspn($s, self::idClassChars($c)) === strlen($s);
    }

    public static function idPatternError(mixed $p): ?string
    {
        if ($p === '*') {
            return null;
        }
        $bad = "resource.id must be '*', {exact} or {prefix, class, len}";
        if (!($p instanceof Obj)) {
            return $bad;
        }
        $keys = self::sorted($p);
        if ($keys === 'exact') {
            $e = $p->get('exact');
            return is_string($e) && strlen($e) >= 1 && strlen($e) <= 128 && self::inClass($e, 'any_safe') ? null : 'resource.id.exact must be 1..128 safe characters';
        }
        if ($keys !== 'class,len,prefix') {
            return $bad;
        }
        $pre = $p->get('prefix');
        if (!is_string($pre) || strlen($pre) > 32 || !self::inClass($pre, 'any_safe')) {
            return 'resource.id.prefix must be up to 32 safe characters';
        }
        if (!self::inS($p->get('class'), self::ID_CLASSES)) {
            return 'resource.id.class is not an id class';
        }
        $ln = $p->get('len');
        if (!self::isList($ln) || count($ln) !== 2 || !self::isInt($ln[0]) || !self::isInt($ln[1])
            || self::f($ln[0]) < 1 || self::f($ln[0]) > 128 || self::f($ln[1]) < 1 || self::f($ln[1]) > 128) {
            return 'resource.id.len must be [min, max] in 1..128';
        }
        if (self::f($ln[0]) > self::f($ln[1])) {
            return 'resource.id.len: min > max';
        }
        if ($p->get('class') === 'uuid' && ($pre !== '' || self::f($ln[0]) != 36 || self::f($ln[1]) != 36)) {
            return 'a uuid id has no prefix and length exactly [36, 36]';
        }
        return null;
    }

    private static function paramNameError(string $name): ?string
    {
        if (preg_match(self::PARAM_NAME_RE, $name) !== 1) {
            return "param name '$name' is malformed";
        }
        if (array_intersect(explode('.', $name), self::RESERVED) !== []) {
            return "param name '$name' is reserved";
        }
        return null;
    }

    private static function paramError(string $name, mixed $p, array $names): ?string
    {
        if (!($p instanceof Obj)) {
            return "$name: declaration must be an object";
        }
        foreach ($p->keys() as $k) {
            if (!in_array($k, self::PARAM_KEYS, true)) {
                return "$name: unknown member '$k'";
            }
        }
        if (!self::inS($p->get('type'), self::PARAM_TYPES)) {
            return "$name: unknown type";
        }
        $t = $p->get('type');
        if ($p->has('role') && !self::isRole($p->get('role'))) {
            return "$name: unknown role";
        }
        if (is_string($p->get('role')) && in_array($p->get('role'), self::INT_ROLES, true) && $t !== 'integer') {
            return "$name: role requires an integer parameter";
        }
        if ($p->has('required') && !is_bool($p->get('required'))) {
            return "$name: required must be a boolean";
        }
        if ($p->has('values')) {
            $vs = $p->get('values');
            $ok = self::isList($vs) && count($vs) > 0 && count($vs) <= 256;
            foreach ($ok ? $vs : [] as $x) {
                $ok = $ok && self::isStr($x);
            }
            if (!$ok) {
                return "$name: values must be 1..256 non-empty strings";
            }
            if (!self::distinct($vs)) {
                return "$name: values must be distinct";
            }
            if ($t !== 'string' && $t !== 'set') {
                return "$name: values apply to string and set only";
            }
        }
        if ($t === 'set' && !$p->has('values')) {
            return "$name: a set needs values";
        }
        $intLike = $t === 'integer' || $t === 'duration' || ($t === 'array' && $p->get('items') === 'integer');
        foreach (['min', 'max'] as $k) {
            if ($p->has($k) && (!self::isInt($p->get($k)) || !$intLike)) {
                return "$name: $k must be a safe integer on an integer parameter";
            }
        }
        if (self::isInt($p->get('min')) && self::isInt($p->get('max')) && self::f($p->get('min')) > self::f($p->get('max'))) {
            return "$name: min > max";
        }
        if ($p->has('max_len') && (!self::isInt($p->get('max_len')) || self::f($p->get('max_len')) < 1 || self::f($p->get('max_len')) > 16777216
            || !in_array($t, ['string', 'array', 'object_ref'], true))) {
            return "$name: max_len must be 1..16777216 on a string or array";
        }
        if ($p->has('items') && ($t !== 'array' || !self::isStr($p->get('items'), 64))) {
            return "$name: items applies to array only";
        }
        foreach (['min_items', 'max_items'] as $k) {
            if ($p->has($k) && (!self::isNonNeg($p->get($k)) || ($t !== 'set' && $t !== 'array'))) {
                return "$name: $k must be a non-negative integer on a set or array";
            }
        }
        if (self::isInt($p->get('min_items')) && self::isInt($p->get('max_items')) && self::f($p->get('min_items')) > self::f($p->get('max_items'))) {
            return "$name: min_items > max_items";
        }
        if ($p->has('format') && (!self::isFormat($p->get('format')) || ($t !== 'string' && $t !== 'object_ref'))) {
            return "$name: format must be a known format on a string parameter";
        }
        if ($p->has('unit')) {
            $u = $p->get('unit');
            if ($t !== 'integer') {
                return "$name: unit applies to integer parameters only";
            }
            if (!($u instanceof Obj) || !self::inS($u->get('kind'), self::UNIT_KINDS)) {
                return "$name: unit.kind is not a known kind";
            }
            if ($u->get('kind') === 'money') {
                foreach ($u->keys() as $k) {
                    if (!in_array($k, ['kind', 'ccy', 'exp'], true)) {
                        return "$name: unit has unknown members";
                    }
                }
                if (!self::isInt($u->get('exp')) || self::f($u->get('exp')) < 0 || self::f($u->get('exp')) > 18) {
                    return "$name: unit.exp must be an integer in 0..18";
                }
                $c = $u->get('ccy');
                if (is_string($c)) {
                    if (preg_match(self::CCY_RE, $c) !== 1) {
                        return "$name: unit.ccy must be an ISO 4217 style code";
                    }
                } elseif (!($c instanceof Obj) || implode(',', $c->keys()) !== 'from' || !is_string($c->get('from')) || !in_array($c->get('from'), $names, true)) {
                    return "$name: unit.ccy.from must name a declared parameter";
                }
            } elseif (implode(',', $u->keys()) !== 'kind') {
                return "$name: unit has unknown members";
            }
        }
        if ($p->has('tags')) {
            $tg = $p->get('tags');
            $ok = self::isList($tg) && count($tg) <= count(self::PARAM_TAGS);
            foreach ($ok ? $tg : [] as $x) {
                $ok = $ok && self::inS($x, self::PARAM_TAGS);
            }
            if (!$ok || !self::distinct($tg)) {
                return "$name: tags must be distinct known tags";
            }
        }
        if ($p->has('provenance_min') && !self::inS($p->get('provenance_min'), self::PROVENANCE)) {
            return "$name: unknown provenance_min";
        }
        if ($p->has('sensitivity') && !self::inS($p->get('sensitivity'), array_keys(self::SENS_RANK))) {
            return "$name: unknown sensitivity";
        }
        if ($p->has('accumulates')) {
            $a = $p->get('accumulates');
            if ($t !== 'integer') {
                return "$name: accumulates applies to integer parameters only";
            }
            $ok = self::isList($a) && count($a) > 0 && count($a) <= 8;
            foreach ($ok ? $a : [] as $x) {
                $ok = $ok && is_string($x) && strlen($x) <= 64 && preg_match(self::UNIT_ID_RE, $x) === 1;
            }
            if (!$ok || !self::distinct($a)) {
                return "$name: accumulates must be 1..8 distinct unit ids";
            }
        }
        if ($p->has('default') && $p->get('default') === null) {
            return "$name: default must not be null (absent = no default)";
        }
        if ($p->has('principal_neutral_default') && !is_bool($p->get('principal_neutral_default'))) {
            return "$name: principal_neutral_default must be a boolean";
        }
        if ($p->get('principal_neutral_default') === true && !$p->has('default')) {
            return "$name: principal_neutral_default needs a default";
        }
        if ($p->has('description') && !self::isStr($p->get('description'), 1024)) {
            return "$name: description must be a string up to 1024 bytes";
        }
        return null;
    }

    private static function bindingsError(mixed $b): ?string
    {
        if (!($b instanceof Obj)) {
            return 'bindings must be an object';
        }
        $shapes = ['mcp' => [['tool'], []], 'openapi' => [['operationId'], ['method', 'path']], 'http' => [['method', 'path'], []],
            'graphql' => [['op', 'field'], []], 'grpc' => [['service', 'method'], []], 'asyncapi' => [['channel', 'op'], []]];
        foreach ($b->keys() as $k) {
            if (!in_array($k, self::BINDING_KINDS, true)) {
                return "bindings: unknown kind '$k'";
            }
            $v = $b->get($k);
            [$req, $opt] = $shapes[$k];
            if (!($v instanceof Obj)) {
                return "bindings.$k must be an object";
            }
            foreach ($v->keys() as $m) {
                if (!in_array($m, array_merge($req, $opt), true)) {
                    return "bindings.$k: unknown member '$m'";
                }
            }
            foreach ($req as $m) {
                if (!self::isStr($v->get($m), 256)) {
                    return "bindings.$k.$m must be a non-empty string";
                }
            }
            foreach ($opt as $m) {
                if ($v->has($m) && !self::isStr($v->get($m), 256)) {
                    return "bindings.$k.$m must be a non-empty string";
                }
            }
        }
        if ($b->has('graphql') && !in_array($b->get('graphql')->get('op'), ['query', 'mutation', 'subscription'], true)) {
            return 'bindings.graphql.op is not a GraphQL operation kind';
        }
        if ($b->has('asyncapi') && !in_array($b->get('asyncapi')->get('op'), ['send', 'receive'], true)) {
            return 'bindings.asyncapi.op must be send or receive';
        }
        return null;
    }

    private static function reviewError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'review must be an object';
        }
        foreach ($r->keys() as $k) {
            if (!in_array($k, ['state', 'attestation', 'suggested_by', 'provenance'], true)) {
                return "review: unknown member '$k'";
            }
        }
        if (!self::inS($r->get('state'), self::REVIEW_STATES)) {
            return 'review.state is not a review state';
        }
        if ($r->has('provenance')) {
            $pv = $r->get('provenance');
            if (!($pv instanceof Obj)) {
                return 'review.provenance must be an object';
            }
            foreach ($pv->keys() as $k) {
                if ($k !== 'union' && $k !== 'adjudicated') {
                    return "review.provenance: unknown member '$k'";
                }
                if (!self::strList($pv->get($k), 32, fn($t) => preg_match('/\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\z/', $t) === 1)) {
                    return "review.provenance.$k must be a list of at most 32 distinct trait ids";
                }
            }
        }
        if ($r->has('attestation')) {
            $a = $r->get('attestation');
            if (!($a instanceof Obj)) {
                return 'review.attestation must be an object';
            }
            foreach ($a->keys() as $k) {
                if (!in_array($k, ['def_digest', 'traits_digest', 'facts_digest', 'final_traits', 'dismissed', 'reviewer_kid', 'ts', 'sig'], true)) {
                    return "review.attestation: unknown member '$k'";
                }
            }
            if (!self::isStr($a->get('def_digest'), 64) || !self::isStr($a->get('traits_digest'), 64) || !self::isStr($a->get('facts_digest'), 64) || !self::isStr($a->get('reviewer_kid'), 128) || !self::isNonNeg($a->get('ts'))) {
                return 'review.attestation: def_digest, traits_digest, facts_digest, reviewer_kid and ts are required';
            }
            if (!self::strList($a->get('final_traits'), 32, fn($s) => preg_match(self::TRAIT_ID_RE, $s) === 1)) {
                return 'review.attestation.final_traits must be distinct trait ids';
            }
            $d = $a->get('dismissed');
            $ok = self::isList($d) && count($d) <= 32;
            foreach ($ok ? $d : [] as $x) {
                $ok = $ok && $x instanceof Obj && self::sorted($x) === 'reason,trait' && is_string($x->get('trait'))
                    && preg_match(self::TRAIT_ID_RE, $x->get('trait')) === 1 && self::isStr($x->get('reason'), 256);
            }
            if (!$ok) {
                return 'review.attestation.dismissed must be {trait, reason} entries';
            }
            if ($a->has('sig') && !self::isStr($a->get('sig'), 4096)) {
                return 'review.attestation.sig must be a string';
            }
        }
        return null;
    }

    /** Null if `$x` is a well-formed ActionDef (structure only: registry, prules and lint checks are separate). Never throws. */
    public static function validateDef(mixed $x): ?string
    {
        try {
            if (($je = self::jsonProfileError($x)) !== null) {
                return 'not strict JSON: ' . $je;
            }
            if (!($x instanceof Obj)) {
                return 'def must be an object';
            }
            foreach ($x->keys() as $k) {
                if (!in_array($k, self::DEF_KEYS, true)) {
                    return "unknown member '$k'";
                }
            }
            if (!self::eqInt($x->get('v'), 1)) {
                return 'unsupported def version';
            }
            if ($x->get('kind') !== self::ACTION_DEF_KIND) {
                return "kind must be '" . self::ACTION_DEF_KIND . "'";
            }
            $verb = $x->get('verb');
            if (!is_string($verb) || preg_match(self::VERB_RE, $verb) !== 1 || strlen($verb) > 128) {
                return 'verb must be <ns>.<noun...>.<action> (lowercase, 2..6 segments)';
            }
            if ($x->has('aliases') && (!self::strList($x->get('aliases'), 16, fn($s) => preg_match(self::ALIAS_RE, $s) === 1 && strlen($s) <= 128) || in_array($verb, $x->get('aliases'), true))) {
                return 'aliases must be distinct verb-shaped names other than the verb';
            }
            if (!self::isStr($x->get('title'), 120)) {
                return 'title must be a non-empty string up to 120 bytes';
            }
            if ($x->has('description') && !self::isStr($x->get('description'), 1024)) {
                return 'description must be a string';
            }
            if (!self::strList($x->get('effects'), count(self::EFFECTS), fn($s) => in_array($s, self::EFFECTS, true)) || count($x->get('effects')) === 0) {
                return 'effects must be 1..12 distinct known effects';
            }
            $r = $x->get('resource');
            if (!($r instanceof Obj) || self::sorted($r) !== 'id,scope,type') {
                return 'resource must be {type, id, scope}';
            }
            if (!is_string($r->get('type')) || preg_match(self::RESOURCE_TYPE_RE, $r->get('type')) !== 1 || strlen($r->get('type')) > 128) {
                return 'resource.type is malformed';
            }
            if (($ide = self::idPatternError($r->get('id'))) !== null) {
                return $ide;
            }
            if (!self::inS($r->get('scope'), self::RESOURCE_SCOPES)) {
                return 'resource.scope is not a scope';
            }
            $params = $x->get('params');
            if (!($params instanceof Obj)) {
                return 'params must be an object';
            }
            $names = $params->keys();
            if (count($names) > 64) {
                return 'more than 64 parameters';
            }
            foreach ($names as $n) {
                if (($ne = self::paramNameError($n)) !== null) {
                    return $ne;
                }
                foreach ($names as $m) {
                    if ($m !== $n && str_starts_with($m, $n . '.')) {
                        return "param '$n' is both a value and the parent of '$m'";
                    }
                }
            }
            foreach ($names as $n) {
                if (($e = self::paramError($n, $params->get($n), $names)) !== null) {
                    return $e;
                }
            }
            if ($x->has('reversibility')) {
                $rv = $x->get('reversibility');
                if (!is_string($rv)) {
                    if (!($rv instanceof Obj)) {
                        return 'reversibility must be a class or {by, map, default?}';
                    }
                    foreach ($rv->keys() as $k) {
                        if (!in_array($k, ['by', 'map', 'default'], true)) {
                            return 'reversibility must be a class or {by, map, default?}';
                        }
                    }
                    if (!is_string($rv->get('by')) || !in_array($rv->get('by'), $names, true)) {
                        return 'reversibility.by must name a declared parameter';
                    }
                    $m = $rv->get('map');
                    $ok = $m instanceof Obj && count($m->keys()) > 0 && count($m->keys()) <= 256;
                    foreach ($ok ? $m->keys() : [] as $k) {
                        $ok = $ok && self::isStr($k, 128) && self::inS($m->get($k), array_keys(self::REV_RANK));
                    }
                    if (!$ok) {
                        return 'reversibility.map must map values to reversibility classes';
                    }
                    if ($rv->has('default') && !self::inS($rv->get('default'), array_keys(self::REV_RANK))) {
                        return 'reversibility.default is not a class';
                    }
                } elseif (!isset(self::REV_RANK[$rv])) {
                    return 'unknown reversibility class';
                }
            }
            if ($x->has('blast')) {
                $b = $x->get('blast');
                $ok = $b instanceof Obj;
                foreach ($ok ? $b->keys() : [] as $k) {
                    $ok = $ok && in_array($k, ['radius', 'ppm'], true);
                }
                if (!$ok || !self::inS($b->get('radius'), self::BLAST_RADII)) {
                    return 'blast must be {radius, ppm?}';
                }
                if ($b->has('ppm') && !(self::isInt($b->get('ppm')) && self::f($b->get('ppm')) >= 0 && self::f($b->get('ppm')) <= 1000000)) {
                    return 'blast.ppm must be an integer in 0..1000000';
                }
            }
            if ($x->has('side_effects')) {
                $s = $x->get('side_effects');
                $ok = self::isList($s) && count($s) <= 16;
                foreach ($ok ? $s : [] as $e) {
                    $ok = $ok && $e instanceof Obj && self::sorted($e) === 'kind,target' && self::isStr($e->get('target'), 128) && self::inS($e->get('kind'), self::EFFECTS);
                }
                if (!$ok) {
                    return 'side_effects must be {target, kind} entries';
                }
            }
            if ($x->has('idempotency')) {
                $i = $x->get('idempotency');
                $ok = $i instanceof Obj;
                foreach ($ok ? $i->keys() : [] as $k) {
                    $ok = $ok && in_array($k, ['mode', 'param'], true);
                }
                if (!$ok || !self::inS($i->get('mode'), self::IDEMPOTENCY_MODES)) {
                    return 'idempotency must be {mode, param?}';
                }
                $bad = $i->get('mode') === 'key_param' ? (!is_string($i->get('param')) || !in_array($i->get('param'), $names, true)) : $i->has('param');
                if ($bad) {
                    return 'idempotency.param is required for key_param (a declared parameter) and forbidden otherwise';
                }
            }
            if ($x->has('context') && !self::strList($x->get('context'), 16, fn($s) => self::isContextKey($s))) {
                return 'context must be distinct known context keys';
            }
            if ($x->has('traits') && !self::strList($x->get('traits'), 32, fn($s) => preg_match(self::TRAIT_ID_RE, $s) === 1)) {
                return 'traits must be distinct trait ids';
            }
            if ($x->has('audience') && $x->get('audience') !== 'resource') {
                return "audience must be 'resource'";
            }
            if ($x->has('compensates') && (!is_string($x->get('compensates')) || preg_match(self::VERB_RE, $x->get('compensates')) !== 1)) {
                return 'compensates must be a verb';
            }
            if ($x->has('bindings') && ($be = self::bindingsError($x->get('bindings'))) !== null) {
                return $be;
            }
            if ($x->has('examples')) {
                $ex = $x->get('examples');
                if (!self::isList($ex) || count($ex) > 32) {
                    return 'examples must be an array of up to 32 entries';
                }
                foreach ($ex as $e) {
                    $ok = $e instanceof Obj;
                    foreach ($ok ? $e->keys() : [] as $k) {
                        $ok = $ok && in_array($k, ['params', 'under', 'expect'], true);
                    }
                    if (!$ok || !($e->get('params') instanceof Obj) || !in_array($e->get('expect'), ['allow', 'escalate', 'deny'], true)) {
                        return 'example must be {params, under?, expect}';
                    }
                }
            }
            if (($re = self::reviewError($x->get('review'))) !== null) {
                return $re;
            }
            if ($x->has('source')) {
                $s = $x->get('source');
                $ok = $s instanceof Obj;
                foreach ($ok ? $s->keys() : [] as $k) {
                    $ok = $ok && in_array($k, ['kind', 'uri', 'spec_digest', 'licence', 'imported_at'], true);
                }
                if (!$ok || !self::isStr($s->get('kind'), 64) || !self::isStr($s->get('uri'), 2048) || !self::isStr($s->get('spec_digest'), 128)
                    || !self::isStr($s->get('licence'), 128) || ($s->has('imported_at') && !self::isNonNeg($s->get('imported_at')))) {
                    return 'source must be {kind, uri, spec_digest, licence, imported_at?}';
                }
            }
            if ($x->has('since') && !self::isStr($x->get('since'), 64)) {
                return 'since must be a string';
            }
            return null;
        } catch (\Throwable $e) {
            return 'malformed def: ' . $e->getMessage();
        }
    }

    // ---- profile lattice + trait registry -----------------------------------------------------------------------------------

    /** @param array<string,mixed> $p @return array{risk:int,rev:string,blast_ppm:int,esc:int,caveats:list<string>,context:list<string>,prules:list<string>} */
    public static function profile(array $p = []): array
    {
        return ['risk' => $p['risk'] ?? 0, 'rev' => $p['rev'] ?? 'reversible', 'blast_ppm' => $p['blast_ppm'] ?? 0, 'esc' => $p['esc'] ?? 0,
            'caveats' => self::sortUniq($p['caveats'] ?? []), 'context' => self::sortUniq($p['context'] ?? []), 'prules' => self::sortUniq($p['prules'] ?? [])];
    }

    public static function profObj(array $p): Obj
    {
        return Obj::of(['risk' => new Num((string)$p['risk']), 'rev' => $p['rev'], 'blast_ppm' => new Num((string)$p['blast_ppm']),
            'esc' => new Num((string)$p['esc']), 'caveats' => $p['caveats'], 'context' => $p['context'], 'prules' => $p['prules']]);
    }

    /** A profile from its JSON form (Obj); throws when a member is missing or mistyped. */
    public static function profFromObj(mixed $o): array
    {
        if (!($o instanceof Obj)) {
            throw new \InvalidArgumentException('profile must be an object');
        }
        $set = function (string $k) use ($o): array {
            $a = $o->get($k);
            if (!self::isList($a)) {
                throw new \InvalidArgumentException("profile.$k");
            }
            foreach ($a as $x) {
                if (!is_string($x)) {
                    throw new \InvalidArgumentException("profile.$k");
                }
            }
            return $a;
        };
        foreach (['risk', 'blast_ppm', 'esc'] as $k) {
            if (self::f($o->get($k)) === null) {
                throw new \InvalidArgumentException("profile.$k");
            }
        }
        if (!is_string($o->get('rev'))) {
            throw new \InvalidArgumentException('profile.rev');
        }
        return ['risk' => self::iv($o->get('risk')), 'rev' => $o->get('rev'), 'blast_ppm' => self::iv($o->get('blast_ppm')), 'esc' => self::iv($o->get('esc')),
            'caveats' => $set('caveats'), 'context' => $set('context'), 'prules' => $set('prules')];
    }

    private static function intIn(mixed $x, int $lo, int $hi): bool
    {
        return self::isInt($x) && self::f($x) >= $lo && self::f($x) <= $hi;
    }

    public static function profileError(mixed $p): ?string
    {
        if (!($p instanceof Obj)) {
            return 'profile must be an object';
        }
        foreach ($p->keys() as $k) {
            if (!in_array($k, ['risk', 'rev', 'blast_ppm', 'esc', 'caveats', 'context', 'prules'], true)) {
                return "profile: unknown member '$k'";
            }
        }
        if (!self::intIn($p->get('risk'), 0, 3)) {
            return 'profile.risk must be an integer in 0..3';
        }
        if (!self::inS($p->get('rev'), array_keys(self::REV_RANK))) {
            return 'profile.rev is not a reversibility class';
        }
        if (!self::intIn($p->get('blast_ppm'), 0, 1000000)) {
            return 'profile.blast_ppm must be an integer in 0..1000000';
        }
        if (!self::intIn($p->get('esc'), 0, 3)) {
            return 'profile.esc must be an integer in 0..3';
        }
        foreach (['caveats' => self::CAVEAT_KINDS, 'context' => null, 'prules' => self::PARAM_RULE_IDS] as $name => $known) {
            $a = $p->get($name);
            $ok = self::isList($a) && count($a) <= 64;
            foreach ($ok ? $a : [] as $x) {
                $ok = $ok && ($known === null ? self::isContextKey($x) : self::inS($x, $known));
            }
            if (!$ok) {
                return "profile.$name must be an array of known $name entries";
            }
            for ($i = 1; $i < count($a); $i++) {
                if (!(strcmp($a[$i - 1], $a[$i]) < 0)) {
                    return "profile.$name must be sorted and distinct";
                }
            }
        }
        return null;
    }

    public static function join(array $p, array $q): array
    {
        return ['risk' => max($p['risk'], $q['risk']), 'rev' => self::REV_RANK[$p['rev']] >= self::REV_RANK[$q['rev']] ? $p['rev'] : $q['rev'],
            'blast_ppm' => max($p['blast_ppm'], $q['blast_ppm']), 'esc' => max($p['esc'], $q['esc']),
            'caveats' => self::sortUniq(array_merge($p['caveats'], $q['caveats'])), 'context' => self::sortUniq(array_merge($p['context'], $q['context'])),
            'prules' => self::sortUniq(array_merge($p['prules'], $q['prules']))];
    }

    private static function subset(array $a, array $b): bool
    {
        foreach ($a as $x) {
            if (!in_array($x, $b, true)) {
                return false;
            }
        }
        return true;
    }

    public static function leq(array $p, array $q): bool
    {
        return $p['risk'] <= $q['risk'] && self::REV_RANK[$p['rev']] <= self::REV_RANK[$q['rev']] && $p['blast_ppm'] <= $q['blast_ppm'] && $p['esc'] <= $q['esc']
            && self::subset($p['caveats'], $q['caveats']) && self::subset($p['context'], $q['context']) && self::subset($p['prules'], $q['prules']);
    }

    /** @param list<Obj> $defs Null if `defs` form a valid registry, else the first reason. */
    public static function registryError(array $defs, bool $core = false): ?string
    {
        if (count($defs) > 512) {
            return 'a registry holds at most 512 traits';
        }
        $by = [];
        foreach ($defs as $t) {
            if (!($t instanceof Obj)) {
                return 'trait must be an object';
            }
            $id = $t->get('id');
            if (!is_string($id) || preg_match(self::TRAIT_ID_RE, $id) !== 1) {
                return "trait id '" . (is_string($id) ? $id : '?') . "' is malformed";
            }
            if (str_starts_with($id, 'pca.') && !$core) {
                return "trait '$id': the pca. namespace is reserved for core traits";
            }
            if (isset($by[$id])) {
                return "trait '$id' is defined twice";
            }
            $im = $t->get('implies');
            $ok = self::isList($im) && count($im) <= 8;
            foreach ($ok ? $im : [] as $u) {
                $ok = $ok && is_string($u);
            }
            if (!$ok || !self::distinct($im)) {
                return "trait '$id': implies must be up to 8 distinct trait ids";
            }
            if (($pe = self::profileError($t->get('floor'))) !== null) {
                return "trait '$id': $pe";
            }
            $cp = $t->get('card_phrase');
            if (!is_string($cp) || IntentV2::u16len($cp) === 0 || IntentV2::u16len($cp) > 120) {
                return "trait '$id': card_phrase must be a non-empty string up to 120 characters";
            }
            $by[$id] = $t;
        }
        foreach ($defs as $t) {
            foreach ($t->get('implies') as $u) {
                if (!isset($by[$u])) {
                    return "trait '" . $t->get('id') . "' implies unknown trait '$u'";
                }
                if (!self::leq(self::profFromObj($by[$u]->get('floor')), self::profFromObj($t->get('floor')))) {
                    return "trait '" . $t->get('id') . "': floor is below the floor of implied '$u'";
                }
            }
        }
        $depth = [];
        $visiting = [];
        $walk = function (string $i) use (&$walk, &$depth, &$visiting, $by): int {
            if (isset($depth[$i])) {
                return $depth[$i];
            }
            if (isset($visiting[$i])) {
                return -1;
            }
            $visiting[$i] = true;
            $d = 1;
            foreach ($by[$i]->get('implies') as $u) {
                $du = $walk($u);
                if ($du < 0) {
                    return -1;
                }
                $d = max($d, $du + 1);
            }
            unset($visiting[$i]);
            return $depth[$i] = $d;
        };
        foreach ($defs as $t) {
            $d = $walk($t->get('id'));
            if ($d < 0) {
                return "trait '" . $t->get('id') . "': implies cycle";
            }
            if ($d > 8) {
                return "trait '" . $t->get('id') . "': implies depth $d exceeds 8";
            }
        }
        return null;
    }

    /** @param list<Obj> $defs @return array<string,array> id => {id, implies, floor(array), card_phrase} */
    public static function buildRegistry(array $defs, bool $core = false): array
    {
        if (($e = self::registryError($defs, $core)) !== null) {
            throw new ActionKitError('bad_registry', $e);
        }
        $reg = [];
        foreach ($defs as $t) {
            $reg[$t->get('id')] = ['id' => $t->get('id'), 'implies' => $t->get('implies'), 'floor' => self::profFromObj($t->get('floor')), 'card_phrase' => $t->get('card_phrase')];
        }
        return $reg;
    }

    private static function traitObj(array $t): Obj
    {
        return Obj::of(['id' => $t['id'], 'implies' => $t['implies'], 'floor' => self::profObj($t['floor']), 'card_phrase' => $t['card_phrase']]);
    }

    /** Core registry extended with custom traits (which must not use `pca.` and must extend what they imply). @param list<mixed> $custom */
    public static function extendRegistry(array $base, array $custom): array
    {
        $all = array_map([self::class, 'traitObj'], array_values($base));
        foreach ($custom as $c) {
            if (!($c instanceof Obj) || !is_string($c->get('id')) || isset($base[$c->get('id')]) || str_starts_with($c->get('id'), 'pca.')) {
                throw new ActionKitError('bad_registry', 'custom trait may not redefine a core trait');
            }
        }
        return self::buildRegistry(array_merge($all, $custom), true);
    }

    /** @return list<string> */
    public static function closure(array $reg, mixed $ids): array
    {
        $seen = [];
        $stack = is_array($ids) ? array_values($ids) : [];
        while ($stack) {
            $i = array_pop($stack);
            if (!is_string($i) || !isset($reg[$i])) {
                throw new ActionKitError('unknown_trait', 'unknown trait');
            }
            if (isset($seen[$i])) {
                continue;
            }
            $seen[$i] = true;
            foreach ($reg[$i]['implies'] as $u) {
                $stack[] = $u;
            }
        }
        $out = array_keys($seen);
        sort($out, SORT_STRING);
        return $out;
    }

    public static function floorOf(array $reg, mixed $ids): array
    {
        $out = self::profile();
        foreach (self::closure($reg, $ids) as $i) {
            $out = self::join($out, $reg[$i]['floor']);
        }
        return $out;
    }

    /** FloorDecision(G, call, rho): deny if rho.esc > G.max_esc; escalate if a caveat/context is missing or rho.esc > G.preauth_esc; else allow. */
    public static function floorDecision(Obj $grant, Obj $call, array $rho): string
    {
        $maxEsc = self::f($grant->get('max_esc'));
        $pre = self::f($grant->get('preauth_esc'));
        if ($rho['esc'] > $maxEsc) {
            return 'deny';
        }
        if (!self::subset($rho['caveats'], $grant->get('caveats')) || !self::subset($rho['context'], $call->get('context')) || $rho['esc'] > $pre) {
            return 'escalate';
        }
        return 'allow';
    }

    /** [id, implies, own floor, card phrase] - the 22 core traits. */
    private const TABLE = [
        ['money_moving', [], ['risk' => 3, 'rev' => 'rate_limited', 'blast_ppm' => 700000, 'esc' => 2, 'caveats' => ['amount_cap', 'count_cap', 'window'], 'context' => ['idempotency'], 'prules' => ['money_has_currency', 'money_amount_bounded', 'pay_has_idempotency']], 'moves money'],
        ['destructive', [], ['risk' => 2, 'rev' => 'rate_limited', 'esc' => 1, 'caveats' => ['resource_scope'], 'prules' => ['id_not_wildcard']], 'deletes or destroys data'],
        ['irreversible', [], ['risk' => 2, 'rev' => 'irreversible', 'esc' => 1, 'context' => ['fresh_revocation']], 'cannot be undone'],
        ['external_communication', [], ['risk' => 2, 'rev' => 'irreversible', 'caveats' => ['recipient_scope', 'rate_cap'], 'prules' => ['recipient_param_declared']], 'sends to people outside your organisation'],
        ['data_export', [], ['risk' => 2, 'caveats' => ['resource_scope', 'count_cap'], 'prules' => ['export_bounded']], 'exports data'],
        ['privilege_change', [], ['risk' => 3, 'esc' => 3, 'caveats' => ['resource_scope', 'short_expiry']], 'changes who can do what'],
        ['code_execution', [], ['risk' => 3, 'rev' => 'irreversible', 'esc' => 2, 'caveats' => ['resource_scope'], 'context' => ['sandbox_attested']], 'runs code or commands'],
        ['credential_access', [], ['risk' => 3, 'esc' => 3, 'prules' => ['secret_not_logged']], 'reads or handles credentials'],
        ['bulk', [], ['risk' => 2, 'caveats' => ['count_cap'], 'prules' => ['array_bounded']], 'acts on many items at once'],
        ['pii_access', [], ['risk' => 1, 'caveats' => ['resource_scope']], 'touches personal data'],
        ['public_exposure', [], ['risk' => 2, 'rev' => 'irreversible', 'esc' => 1], 'makes content public'],
        ['persistence', [], ['risk' => 2, 'caveats' => ['short_expiry'], 'context' => ['revocable']], 'creates standing access or infrastructure'],
        ['infra_mutation', [], ['risk' => 2, 'rev' => 'rate_limited', 'caveats' => ['resource_scope']], 'changes infrastructure'],
        ['cost_incurring', [], ['risk' => 1, 'caveats' => ['amount_cap']], 'incurs cost'],
        ['legal_binding', [], ['risk' => 3, 'rev' => 'irreversible', 'esc' => 3], 'legally or cryptographically binds you'],
        ['impersonation', ['external_communication'], ['risk' => 2, 'esc' => 1], 'acts as a person'],
        ['network_egress', [], ['risk' => 1, 'caveats' => ['recipient_scope']], 'reaches out to the network'],
        ['financial_data_read', [], ['risk' => 1, 'caveats' => ['resource_scope']], 'reads financial data'],
        ['regulated_data', [], ['risk' => 2, 'esc' => 1], 'handles regulated data'],
        ['scheduled', [], ['risk' => 2, 'caveats' => ['short_expiry', 'count_cap']], 'runs later or repeatedly'],
        ['unreviewed', [], ['risk' => 3, 'rev' => 'irreversible', 'blast_ppm' => 1000000, 'esc' => 2, 'caveats' => ['approval_ref', 'resource_scope'], 'context' => ['dry_run_first']], 'has not been reviewed yet'],
        ['agent_spawning', [], ['risk' => 2, 'caveats' => ['count_cap']], 'starts another agent'],
    ];

    public const EFFECT_TRAITS = [
        'read' => [], 'create' => [], 'update' => [], 'delete' => ['pca.destructive'], 'send' => ['pca.external_communication'], 'pay' => ['pca.money_moving'],
        'exec' => ['pca.code_execution'], 'privilege' => ['pca.privilege_change'], 'export' => ['pca.data_export'], 'publish' => ['pca.public_exposure'],
        'provision' => ['pca.persistence', 'pca.scheduled'], 'sign' => ['pca.legal_binding'],
    ];
    public const TAG_TRAITS = [
        'pii' => ['pca.pii_access'], 'phi' => ['pca.pii_access', 'pca.regulated_data'], 'pci' => ['pca.regulated_data'],
        'secret' => ['pca.credential_access'], 'credential' => ['pca.credential_access'],
    ];
    public const ROLE_TRAITS = [
        'credential.secret' => ['pca.credential_access'], 'credential.token' => ['pca.credential_access'], 'credential.key' => ['pca.credential_access'],
        'url.target' => ['pca.network_egress'],
    ];
    public const ROLE_SENSITIVITY_FLOOR = [
        'money.amount' => 'critical', 'money.currency' => 'material', 'money.fee' => 'material', 'party.payee' => 'critical', 'party.payer' => 'material',
        'contact.email' => 'material', 'contact.phone' => 'material', 'contact.address' => 'material', 'person.name' => 'material', 'person.dob' => 'material',
        'person.national_id' => 'critical', 'credential.secret' => 'critical', 'credential.token' => 'critical', 'credential.key' => 'critical',
        'code.command' => 'critical', 'query.sql' => 'critical', 'text.message' => 'material',
    ];
    public const TAG_SENSITIVITY_FLOOR = [
        'pii' => 'material', 'phi' => 'material', 'pci' => 'material', 'secret' => 'critical', 'credential' => 'critical',
        'free_text_outbound' => 'material', 'code' => 'material', 'path' => 'material', 'sql' => 'material',
    ];

    private static ?array $core = null;

    /** The core registry (22 traits), built once. */
    public static function coreRegistry(): array
    {
        if (self::$core !== null) {
            return self::$core;
        }
        $floors = [];
        $defs = [];
        foreach (self::TABLE as [$name, $implies, $own, $phrase]) {
            $imp = array_map(fn($n) => 'pca.' . $n, $implies);
            $fl = self::profile($own);
            foreach ($imp as $u) {
                $fl = self::join($fl, $floors[$u]);
            }
            $floors['pca.' . $name] = $fl;
            $defs[] = Obj::of(['id' => 'pca.' . $name, 'implies' => $imp, 'floor' => self::profObj($fl), 'card_phrase' => $phrase]);
        }
        return self::$core = self::buildRegistry($defs, true);
    }

    private static function strMap(array $m): Obj
    {
        return Obj::of($m);
    }

    /** Digest of a trait registry (sorted by id): what a pack pins as `traits_digest`. */
    public static function traitsDigest(array $reg): string
    {
        $ids = array_keys($reg);
        sort($ids, SORT_STRING);
        $ts = [];
        foreach ($ids as $i) {
            $t = $reg[$i];
            $im = $t['implies'];
            sort($im, SORT_STRING);
            $ts[] = Obj::of(['id' => $t['id'], 'implies' => $im, 'floor' => self::profObj($t['floor']), 'card_phrase' => $t['card_phrase']]);
        }
        return IntentV2::hashCanonical(Obj::of(['d' => self::TRAITS_DIGEST_DOMAIN, 'traits' => $ts]));
    }

    public static function tablesDigest(): string
    {
        $lists = fn(array $m): Obj => Obj::of(array_map(fn($v) => array_values($v), $m));
        return IntentV2::hashCanonical(Obj::of([
            'd' => self::ROLES_DIGEST_DOMAIN, 'roles' => self::CORE_ROLES, 'effect_traits' => $lists(self::EFFECT_TRAITS), 'role_traits' => $lists(self::ROLE_TRAITS),
            'tag_traits' => $lists(self::TAG_TRAITS), 'role_sensitivity' => Obj::of(self::ROLE_SENSITIVITY_FLOOR), 'tag_sensitivity' => Obj::of(self::TAG_SENSITIVITY_FLOOR),
        ]));
    }

    // ---- normalize + digest -------------------------------------------------------------------------------------------------

    private static function isReadOnly(array $effects): bool
    {
        return count($effects) > 0 && count(array_filter($effects, fn($e) => $e === 'read')) === count($effects);
    }

    private static function maxSens(string $a, string $b): string
    {
        return self::SENS_RANK[$a] >= self::SENS_RANK[$b] ? $a : $b;
    }

    private static function effectiveParamSensitivity(Obj $p): string
    {
        $f = 'free';
        $role = $p->get('role');
        if (is_string($role) && isset(self::ROLE_SENSITIVITY_FLOOR[$role])) {
            $f = self::maxSens($f, self::ROLE_SENSITIVITY_FLOOR[$role]);
        }
        foreach ($p->get('tags') ?? [] as $t) {
            if (isset(self::TAG_SENSITIVITY_FLOOR[$t])) {
                $f = self::maxSens($f, self::TAG_SENSITIVITY_FLOOR[$t]);
            }
        }
        return self::maxSens($p->has('sensitivity') ? $p->get('sensitivity') : 'free', $f);
    }

    /** @param list<string> $xs */
    private static function maxRev(array $xs): string
    {
        $out = 'reversible';
        foreach ($xs as $b) {
            if (is_string($b) && isset(self::REV_RANK[$b]) && self::REV_RANK[$b] > self::REV_RANK[$out]) {
                $out = $b;
            }
        }
        return $out;
    }

    /** Conservative class of a (possibly value-dependent) reversibility declaration: the worst class any call can have. */
    public static function worstReversibility(mixed $r, Obj $params): string
    {
        if (is_string($r)) {
            return $r;
        }
        $d = $params->get($r->get('by'));
        $map = $r->get('map');
        $mapped = array_map(fn($k) => $map->get($k), $map->keys());
        $domain = null;
        if ($d instanceof Obj) {
            if ($d->get('type') === 'boolean') {
                $domain = ['true', 'false'];
            } elseif ($d->get('type') === 'string' && $d->get('values') !== null) {
                $domain = $d->get('values');
            }
        }
        $covered = $domain !== null;
        foreach ($covered ? $domain : [] as $x) {
            $covered = $covered && $map->has((string)$x);
        }
        return self::maxRev($covered ? $mapped : array_merge($mapped, [$r->has('default') ? $r->get('default') : 'irreversible']));
    }

    private static function normalizeParam(Obj $p): Obj
    {
        $out = new Obj();
        foreach ($p->keys() as $k) {
            $out->set($k, $p->get($k));
        }
        $out->set('required', $p->has('required') ? $p->get('required') : true);
        if ($p->has('tags')) {
            $out->set('tags', self::sortUniq($p->get('tags')));
        }
        $out->set('sensitivity', self::effectiveParamSensitivity($p));
        if ($p->has('accumulates')) {
            $out->set('accumulates', self::sortUniq($p->get('accumulates')));
        } else {
            $u = $p->get('unit');
            if ($p->get('role') === 'money.amount' && $u instanceof Obj && $u->get('kind') === 'money' && is_string($u->get('ccy'))) {
                $out->set('accumulates', ['money.' . strtolower($u->get('ccy'))]);
            }
        }
        return $out;
    }

    private static function u16Order(string $a, string $b): int
    {
        return strcmp(mb_convert_encoding($a, 'UTF-16BE', 'UTF-8'), mb_convert_encoding($b, 'UTF-16BE', 'UTF-8'));
    }

    /** The authoring-independent form of a def (assumes validateDef passed): defaults filled, sets sorted, review/examples/source/since removed. */
    public static function normalize(Obj $d): Obj
    {
        $effects = $d->get('effects');
        $rev = $d->has('reversibility') ? $d->get('reversibility') : (self::isReadOnly($effects) ? 'reversible' : 'irreversible');
        $res = $d->get('resource');
        $radius = $d->has('blast') ? $d->get('blast')->get('radius') : self::SCOPE_BLAST[$res->get('scope')];
        $names = $d->get('params')->keys();
        sort($names, SORT_STRING);
        $params = new Obj();
        foreach ($names as $k) {
            $params->set($k, self::normalizeParam($d->get('params')->get($k)));
        }
        if (is_string($rev)) {
            $nrev = $rev;
        } else {
            $nrev = Obj::of(['by' => $rev->get('by'), 'map' => $rev->get('map')]);
            if ($rev->has('default')) {
                $nrev->set('default', $rev->get('default'));
            }
        }
        $idem = Obj::of(['mode' => $d->has('idempotency') ? $d->get('idempotency')->get('mode') : 'none']);
        if ($d->has('idempotency') && $d->get('idempotency')->has('param')) {
            $idem->set('param', $d->get('idempotency')->get('param'));
        }
        $se = [];
        foreach ($d->get('side_effects') ?? [] as $s) {
            $se[] = Obj::of(['target' => $s->get('target'), 'kind' => $s->get('kind')]);
        }
        usort($se, fn($a, $b) => $a->get('target') === $b->get('target') ? strcmp($a->get('kind'), $b->get('kind')) : self::u16Order($a->get('target'), $b->get('target')));
        $ppm = $d->has('blast') && $d->get('blast')->has('ppm') ? self::iv($d->get('blast')->get('ppm')) : 0;
        $out = Obj::of([
            'v' => new Num('1'), 'kind' => $d->get('kind'), 'verb' => $d->get('verb'), 'aliases' => self::sortUniq($d->get('aliases') ?? []),
            'title' => $d->get('title'), 'effects' => self::sortUniq($effects),
            'resource' => Obj::of(['type' => $res->get('type'), 'id' => $res->get('id'), 'scope' => $res->get('scope')]),
            'params' => $params, 'reversibility' => $nrev,
            'blast' => Obj::of(['radius' => $radius, 'ppm' => new Num((string)max(self::BLAST_PPM[$radius], $ppm))]),
            'side_effects' => $se, 'idempotency' => $idem, 'context' => self::sortUniq($d->get('context') ?? []),
            'traits' => self::sortUniq($d->get('traits') ?? []), 'bindings' => $d->has('bindings') ? $d->get('bindings') : new Obj(),
        ]);
        if ($d->has('description')) {
            $out->set('description', $d->get('description'));
        }
        if ($d->has('audience')) {
            $out->set('audience', $d->get('audience'));
        }
        if ($d->has('compensates')) {
            $out->set('compensates', $d->get('compensates'));
        }
        return $out;
    }

    /** b64u(sha256(strictCanonical({d, def: normalize(def)}))). Review state, examples, source and since do not enter it. */
    public static function defDigest(Obj $d): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::DEF_DIGEST_DOMAIN, 'def' => self::normalize($d)]));
    }

    /** b64u(sha256(strictCanonical({d, verb: the verb without traits, floors, confirmation and def}))): the facts a reviewer saw. */
    public static function factsDigest(Obj $verb): string
    {
        return IntentV2::hashCanonical(Obj::of(['d' => self::VERB_FACTS_DOMAIN, 'verb' => $verb->without('traits', 'floors', 'confirmation', 'def')]));
    }

    // ---- pack Merkle root + inclusion proof ---------------------------------------------------------------------------------

    private static function leaf(string $digest): Obj
    {
        return Obj::of(['d' => self::PACK_DIGEST_DOMAIN, 'def' => $digest]);
    }

    /** @param list<string> $digests @return list<string> */
    private static function sortedDigests(array $digests): array
    {
        $s = self::sortUniq($digests);
        if (count($s) !== count($digests)) {
            throw new ActionKitError('duplicate_def', 'a pack lists a def digest twice');
        }
        if (!$s) {
            throw new ActionKitError('empty_pack', 'a pack has at least one def');
        }
        return $s;
    }

    public static function packLeaf(string $digest): Obj
    {
        return self::leaf($digest);
    }

    /** @param list<string> $digests Merkle root over the sorted def digests (RFC 6962 shape, domain separated leaves). */
    public static function packRoot(array $digests): string
    {
        return Pca::merkleRoot(array_map([self::class, 'leaf'], self::sortedDigests($digests)));
    }

    private static function nodeHash(string $l, string $r): string
    {
        return hash('sha256', "\x01" . $l . $r, true);
    }

    private static function subRoot(array $hs): string
    {
        if (count($hs) === 1) {
            return $hs[0];
        }
        $k = 1;
        while ($k * 2 < count($hs)) {
            $k *= 2;
        }
        return self::nodeHash(self::subRoot(array_slice($hs, 0, $k)), self::subRoot(array_slice($hs, $k)));
    }

    /** RFC 6962 inclusion proof of `$digest` in the pack made of `$digests`: {index, size, path: [{side, hash}]} bottom-up. */
    public static function packProof(array $digests, string $digest): Obj
    {
        $s = self::sortedDigests($digests);
        $i = array_search($digest, $s, true);
        if ($i === false) {
            throw new ActionKitError('not_in_pack', 'the digest is not in the pack');
        }
        $seg = array_map(fn($x) => hash('sha256', "\x00" . IntentV2::canonicalize(self::leaf($x)), true), $s);
        $path = [];
        $idx = $i;
        while (count($seg) > 1) {
            $k = 1;
            while ($k * 2 < count($seg)) {
                $k *= 2;
            }
            if ($idx < $k) {
                $path[] = Obj::of(['side' => 'R', 'hash' => Pca::b64u(self::subRoot(array_slice($seg, $k)))]);
                $seg = array_slice($seg, 0, $k);
            } else {
                $path[] = Obj::of(['side' => 'L', 'hash' => Pca::b64u(self::subRoot(array_slice($seg, 0, $k)))]);
                $seg = array_slice($seg, $k);
                $idx -= $k;
            }
        }
        return Obj::of(['index' => new Num((string)$i), 'size' => new Num((string)count($s)), 'path' => array_reverse($path)]);
    }

    /** Does `$proof` show `$digest` is in the pack with root `$root`? */
    public static function verifyPackProof(string $root, mixed $proof, string $digest): bool
    {
        return Pca::verifyInclusion($root, $proof, self::leaf($digest));
    }

    // ---- T(d), decl(d), eff(d) ----------------------------------------------------------------------------------------------

    /**
     * Traits implied by effects, roles, tags, scope and reversibility. $params: Obj entries with type/role/tags/max_items.
     * @param list<string> $effects @param list<Obj> $params @return list<string>
     */
    public static function impliedFromFacts(array $effects, array $params, ?string $scope, string $worstRev): array
    {
        $out = [];
        foreach ($effects as $e) {
            if (!is_string($e) || !isset(self::EFFECT_TRAITS[$e])) {
                throw new \InvalidArgumentException('unknown effect');
            }
            array_push($out, ...self::EFFECT_TRAITS[$e]);
        }
        $ro = self::isReadOnly($effects);
        foreach ($params as $p) {
            $r = $p->get('role');
            if ($r !== null) {
                if (isset(self::ROLE_TRAITS[$r])) {
                    array_push($out, ...self::ROLE_TRAITS[$r]);
                }
                if ($ro && str_starts_with($r, 'money.')) {
                    $out[] = 'pca.financial_data_read';
                }
            }
            foreach ($p->get('tags') ?? [] as $t) {
                if (isset(self::TAG_TRAITS[$t])) {
                    array_push($out, ...self::TAG_TRAITS[$t]);
                }
            }
            if ($p->get('type') === 'array' && $p->get('max_items') === null) {
                $out[] = 'pca.bulk';
            }
        }
        if ($scope !== null && $scope !== 'one') {
            $out[] = 'pca.bulk';
        }
        if ($worstRev === 'irreversible') {
            $out[] = 'pca.irreversible';
        }
        return self::sortUniq($out);
    }

    /** The hint view of T(d): declared + implied-by-its-own-facts. Never reaches enforcement without a valid confirmation. @return list<string> */
    public static function hintTraits(Obj $d): array
    {
        $n = self::normalize($d);
        $ps = array_map(fn($k) => $n->get('params')->get($k), $n->get('params')->keys());
        return self::sortUniq(array_merge($n->get('traits'), self::impliedFromFacts($n->get('effects'), $ps, $n->get('resource')->get('scope'),
            self::worstReversibility($n->get('reversibility'), $n->get('params')))));
    }

    /** The top of the registry: every trait id (core and custom), sorted. @return list<string> */
    public static function topTraits(array $reg): array
    {
        $ids = array_map('strval', array_keys($reg));
        sort($ids, SORT_STRING);
        return $ids;
    }

    /** T(d): "unconfirmed means maximally dangerous" - the top of the registry unless a pinned reviewer signed this exact def. @return list<string> */
    public static function traitsOf(Obj $d, array $reg, ?Obj $pins = null): array
    {
        return self::isConfirmed($d, $reg, $pins) ? self::hintTraits($d) : self::topTraits($reg);
    }

    // ---- human confirmation (pinned reviewer keys) ----------------------------------------------------------------------------

    private static function u16len(string $s): int
    {
        return intdiv(strlen((string)mb_convert_encoding($s, 'UTF-16LE', 'UTF-8')), 2);
    }

    /** Null if the pin set is sound: distinct kids, canonical keys, known roles, no key that is both a reviewer and a machine. */
    public static function reviewerPinsError(mixed $p): ?string
    {
        if (!($p instanceof Obj) || !self::isList($p->get('keys'))) {
            return 'pins must be {keys: [...]}';
        }
        $kids = [];
        $machine = [];
        foreach ($p->get('keys') as $k) {
            $kid = self::g($k, 'kid');
            if (!is_string($kid) || $kid === '' || self::u16len($kid) > 128) {
                return 'a pinned key needs a kid';
            }
            if (isset($kids['k' . $kid])) {
                return "kid '$kid' is pinned twice";
            }
            $kids['k' . $kid] = true;
            if (Pca::unb64u($k->get('pk'), 32) === null) {
                return "key '$kid': pk is not canonical base64url (32 bytes)";
            }
            $roles = $k->get('roles');
            if (!self::isList($roles) || $roles === [] || !self::distinct(array_map('strval', $roles))) {
                return "key '$kid': roles must be distinct known roles";
            }
            foreach ($roles as $r) {
                if (!self::inS($r, self::KEY_ROLES)) {
                    return "key '$kid': roles must be distinct known roles";
                }
            }
            if (in_array('reviewer', $roles, true) && (in_array('importer', $roles, true) || in_array('model', $roles, true))) {
                return "key '$kid': an importer or model key cannot hold the reviewer role";
            }
            foreach (['not_before', 'not_after'] as $t) {
                if ($k->has($t) && !self::isNonNeg($k->get($t))) {
                    return "key '$kid': $t must be a non-negative integer";
                }
            }
            if (in_array('importer', $roles, true) || in_array('model', $roles, true)) {
                $machine[$k->get('pk')] = true;
            }
        }
        foreach ($p->get('keys') as $k) {
            if (in_array('reviewer', $k->get('roles'), true) && isset($machine[$k->get('pk')])) {
                return "key '" . $k->get('kid') . "': the same key material is pinned as an importer or model key";
            }
        }
        return null;
    }

    /** The bytes a reviewer signs: REVIEW_DOMAIN \0 strict canonical JSON of the attestation body. */
    public static function reviewMessage(Obj $b): string
    {
        $dm = array_map(fn($d) => Obj::of(['trait' => $d->get('trait'), 'reason' => $d->get('reason')]), $b->get('dismissed'));
        usort($dm, fn($x, $y) => strcmp($x->get('trait'), $y->get('trait')));
        return self::REVIEW_DOMAIN . "\0" . Json::canonicalizeStrict(Obj::of([
            'def_digest' => $b->get('def_digest'), 'traits_digest' => $b->get('traits_digest'), 'facts_digest' => $b->get('facts_digest'), 'final_traits' => self::sortUniq($b->get('final_traits')),
            'dismissed' => $dm, 'reviewer_kid' => $b->get('reviewer_kid'), 'ts' => $b->get('ts'),
        ]));
    }

    /** The checks def-level and verb-level confirmations share, after the caller bound the digest and the traits. Null = valid. */
    private static function attestationError(Obj $a, array $reg, Obj $pins): ?string
    {
        $accepted = [Actions::traitsDigest($reg)];
        foreach (self::isList($pins->get('traits_digests')) ? $pins->get('traits_digests') : [] as $x) {
            $accepted[] = $x;
        }
        if (!in_array($a->get('traits_digest'), $accepted, true)) {
            return 'the confirmation was made against a different trait registry';
        }
        $ft = $a->get('final_traits');
        $dm = $a->get('dismissed');
        if (!self::isList($ft) || !self::isList($dm) || !self::isInt($a->get('ts')) || !is_string($a->get('reviewer_kid'))) {
            return 'malformed confirmation';
        }
        foreach ($dm as $d) {
            if (!is_string(self::g($d, 'trait')) || !is_string($d->get('reason')) || in_array($d->get('trait'), $ft, true)
                || preg_match('/\A[\s\p{Z}\x{FEFF}]*\z/u', $d->get('reason')) === 1) {
                return 'a dismissed trait is also final, or has no reason';
            }
        }
        $key = null;
        foreach ($pins->get('keys') as $k) {
            if ($k->get('kid') === $a->get('reviewer_kid')) {
                $key = $k;
            }
        }
        if ($key === null || !in_array('reviewer', $key->get('roles'), true)) {
            return 'the reviewer key is not pinned with the reviewer role';
        }
        $ts = self::f($a->get('ts'));
        if (($key->has('not_before') && $ts < self::f($key->get('not_before'))) || ($key->has('not_after') && $ts > self::f($key->get('not_after')))) {
            return 'the confirmation time is outside the key validity';
        }
        return Pca::verifyEd25519B64u($key->get('pk'), self::reviewMessage($a), $a->get('sig')) ? null : 'the confirmation signature is invalid';
    }

    /** Null iff this schema verb carries a VALID confirmation by a pinned reviewer. Never throws: any failure = unconfirmed. */
    public static function verbConfirmationError(mixed $v, array $reg, ?Obj $pins): ?string
    {
        try {
            if ($pins === null) {
                return 'no reviewer keys are pinned';
            }
            if (($pe = self::reviewerPinsError($pins)) !== null) {
                return "bad pins: $pe";
            }
            $a = self::g($v, 'confirmation');
            if (!($a instanceof Obj)) {
                return 'no confirmation';
            }
            if (!is_string($a->get('sig'))) {
                return 'the confirmation is unsigned';
            }
            if (!is_string($v->get('def')) || $a->get('def_digest') !== $v->get('def')) {
                return 'the confirmation covers a different def digest';
            }
            if (!is_string($a->get('facts_digest')) || $a->get('facts_digest') !== self::factsDigest($v)) {
                return 'the confirmation covers different verb facts';
            }
            $ft = $a->get('final_traits');
            $carried = $v->get('traits');
            if (!self::isList($ft) || !self::isList($carried)) {
                return 'malformed confirmation';
            }
            foreach ($ft as $t) {
                if (!is_string($t) || !in_array($t, $carried, true)) {
                    return 'the verb does not carry every trait the reviewer signed';
                }
            }
            return self::attestationError($a, $reg, $pins);
        } catch (\Throwable $e) {
            return 'malformed confirmation: ' . $e->getMessage();
        }
    }

    /** True iff the def's own review attestation is valid against the registry and the pinned reviewer keys. Never throws. */
    public static function isConfirmed(Obj $d, array $reg, ?Obj $pins): bool
    {
        try {
            $r = self::g($d, 'review');
            $a = self::g($r, 'attestation');
            if ($pins === null || self::reviewerPinsError($pins) !== null || self::g($r, 'state') !== 'confirmed' || !($a instanceof Obj)
                || !is_string($a->get('sig')) || $a->get('def_digest') !== self::defDigest($d)) {
                return false;
            }
            $ft = $a->get('final_traits');
            $decl = $d->get('traits') ?? [];
            if (!self::isList($ft) || !self::isList($decl) || self::sortUniq(array_map('strval', $ft)) !== self::sortUniq(array_map('strval', $decl))) {
                return false;
            }
            return self::attestationError($a, $reg, $pins) === null;
        } catch (\Throwable) {
            return false;
        }
    }

    public static function declProfile(Obj $d): array
    {
        $n = self::normalize($d);
        $critical = false;
        foreach ($n->get('params')->keys() as $k) {
            $critical = $critical || self::SENS_RANK[self::effectiveParamSensitivity($n->get('params')->get($k))] >= self::SENS_RANK['critical'];
        }
        return self::profile(['risk' => $critical ? 2 : (self::isReadOnly($n->get('effects')) ? 0 : 1),
            'rev' => self::worstReversibility($n->get('reversibility'), $n->get('params')),
            'blast_ppm' => self::iv($n->get('blast')->get('ppm')), 'context' => $n->get('context')]);
    }

    /** @return array{confirmed:bool,traits:list<string>,closure:list<string>,floor:array,decl:array,eff:array} eff = decl join F(T(d)). */
    public static function effective(Obj $d, array $reg, ?Obj $pins = null): array
    {
        $confirmed = self::isConfirmed($d, $reg, $pins);
        $tr = $confirmed ? self::hintTraits($d) : self::topTraits($reg);
        $fl = self::floorOf($reg, $tr);
        $dp = self::declProfile($d);
        return ['confirmed' => $confirmed, 'traits' => $tr, 'closure' => self::closure($reg, $tr), 'floor' => $fl, 'decl' => $dp, 'eff' => self::join($dp, $fl)];
    }

    // ---- rule 22: whole-document integrity of the carried traits and floors -----------------------------------------------

    private const PFX = 'action.params.';

    /**
     * Recompute from the verb's own visible facts that its `traits` contain every implied trait and that its `floors` are at least the
     * floor of the traits' closure and of the declared reversibility. Null = consistent; else `<code>: <reason>`. Never throws.
     */
    public static function schemaVerbFloorError(mixed $v, array $reg, ?Obj $pins = null): ?string
    {
        try {
            if (!($v instanceof Obj) || !self::isList($v->get('effects')) || !self::isList($v->get('traits')) || !$v->has('floors')) {
                return 'schema_floor_forged: not a v2 verb';
            }
            $ps = [];
            $byName = new Obj();
            $vp = $v->get('params');
            foreach ($vp->keys() as $path) {
                $p = $vp->get($path);
                $ps[] = $p;
                $e = Obj::of(['type' => $p->get('type')]);
                if ($p->has('values')) {
                    $e->set('values', $p->get('values'));
                }
                $byName->set(substr($path, strlen(self::PFX)), $e);
            }
            $rb = $v->get('reversibility_by');
            if ($rb !== null && $rb !== false) {
                $decl = Obj::of(['by' => substr($rb->get('param'), strlen(self::PFX)), 'map' => $rb->get('map')]);
                if ($rb->has('default')) {
                    $decl->set('default', $rb->get('default'));
                }
            } else {
                $decl = $v->has('reversibility') ? $v->get('reversibility') : ($v->get('kind') === 'read' ? 'reversible' : 'irreversible');
            }
            $worst = self::worstReversibility($decl, $byName);
            $implied = self::impliedFromFacts($v->get('effects'), $ps, null, $worst);
            foreach ($implied as $t) {
                if (!in_array($t, $v->get('traits'), true)) {
                    return "schema_traits_forged: missing implied trait $t";
                }
            }
            // unconfirmed means maximally dangerous: no valid signed confirmation => the verb must carry EVERY trait of the registry
            if (self::verbConfirmationError($v, $reg, $pins) !== null) {
                foreach (self::topTraits($reg) as $t) {
                    if (!in_array($t, $v->get('traits'), true)) {
                        return "schema_traits_forged: unconfirmed action must carry every trait (missing $t)";
                    }
                }
            }
            $fl = self::floorOf($reg, $v->get('traits'));
            $floors = self::profFromObj($v->get('floors'));
            if (!self::leq($fl, $floors)) {
                return 'schema_floor_forged: floors are below the floor of the carried traits';
            }
            if ((self::REV_RANK[$floors['rev']] ?? -1) < (self::REV_RANK[$worst] ?? -1)) {
                return 'schema_floor_forged: floors.rev is below the declared reversibility';
            }
            return null;
        } catch (ActionKitError $e) {
            return $e->codeName . ': ' . $e->getMessage();
        } catch (\Throwable $e) {
            return 'schema_floor_forged: ' . $e->getMessage();
        }
    }

    /** Core + the document's own `trait_defs` (checked); when the document carries `traits_digest` the registry must hash to it. */
    public static function registryOfSchema(Obj $doc): array
    {
        $td = $doc->get('trait_defs');
        $reg = self::isList($td) && count($td) > 0 ? self::extendRegistry(self::coreRegistry(), $td) : self::coreRegistry();
        if ($doc->has('traits_digest') && $doc->get('traits_digest') !== self::traitsDigest($reg)) {
            throw new ActionKitError('traits_digest_mismatch', "the document's traits_digest does not match its trait registry");
        }
        return $reg;
    }

    /** Rule 22's integrity half for a whole v2 document. Null = consistent. Never throws. */
    public static function schemaFloorError(Obj $doc, ?Obj $pins = null): ?string
    {
        try {
            $reg = self::registryOfSchema($doc);
            foreach ($doc->get('verbs') as $v) {
                if (($e = self::schemaVerbFloorError($v, $reg, $pins)) !== null) {
                    return $v->get('verb') . ': ' . $e;
                }
            }
            return null;
        } catch (ActionKitError $e) {
            return $e->codeName . ': ' . $e->getMessage();
        } catch (\Throwable $e) {
            return 'bad_registry: ' . $e->getMessage();
        }
    }
}
