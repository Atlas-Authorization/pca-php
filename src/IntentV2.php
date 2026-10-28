<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Decision.php';
require_once __DIR__ . '/Authorize.php';

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/IntentV2Schema.php';
require_once __DIR__ . '/IntentV2Session.php';
require_once __DIR__ . '/IntentV2Acc.php';
require_once __DIR__ . '/IntentV2Map.php';

/**
 * Intent Layer v2 W-A for the native PHP verifier: signed action schemas (rule 14), intent sessions and their revocation
 * (rule 13: a dedicated revocation authority, the full revoked list, append-only against the tracked last epoch),
 * accumulators / monitors / sequencer receipts (rule 15: receipt lifetime and freshness, versioned and fresh key sets,
 * retired keys), the committed map and its Z0 disclosure (rule 19, intent-map-commit.ts) and the v2 verification pipeline
 * that runs after the `intent` check (schema -> intent_session -> layers -> accumulators -> map -> facts -> provenance ->
 * classes). IntentV2::primitive is the one entry for the intent_* conformance primitives (runners and diff-fuzz driver).
 *
 * Port of packages/pca/src action-schema.ts (verifier side; the MCP / OpenAPI importers are developer tooling), intent-strict.ts,
 * intent-session.ts, intent-session-caveat.ts, intent-acc.ts (verifier parts), intent-revocation.ts (+ the signed revocation
 * epoch and the sorted-Merkle non-membership proof of revocation.ts) and intent-v2.ts. The W-B unit (rules 16-18) is
 * IntentWb::decideIntentWb, the V5 ceilings Predicates::decideLayerCeilings.
 *
 * STRICT semantics (conformance/README.md "Intent Layer v2: strict values, absent vs null, suite capability"):
 *   - numbers are judged by the binary64 VALUE of a Num of any lexeme (2 == 2.0); every numeric field must be a safe
 *     integer (not -0) where the rule says integer, else the check fails closed; the clock must be a safe integer;
 *   - lists must be JSON arrays (a string is never iterated); keyed lookups read OWN members only (an own `__proto__` key
 *     is ordinary data); verifier outputs (env.acc / env.mon / env.canon) are plain maps;
 *   - an optional member that is ABSENT means empty / default; one PRESENT with JSON null is malformed and fails closed
 *     (the accumulator `key: null` is the one meaningful null);
 *   - digests are over the strict canonical form of the JS VALUES (a context number written `1.0` hashes like `1`);
 *   - every suite-agile signature (schema, session root, receipt, sequencer key set, revocation epoch) goes through the
 *     SDK's suite dispatch (Pca::verifyPinnedSuite -> Pca::verifySuite); a suite this verifier does not implement
 *     (Pca::suiteAvailable) fails closed with a reason containing `unsupported_suite`; a post-quantum key is used only
 *     as PINNED by the trusted side, never the artifact's own `pq_pk`.
 * Every public decide / verify function is total.
 */
final class IntentV2
{
    use IntentV2Schema;
    use IntentV2Session;
    use IntentV2Acc;
    use IntentV2Map;

    public const ACTION_SCHEMA_DOMAIN = "atlas-pca/action-schema/v1\0";
    public const ACTION_SCHEMA_REF_DOMAIN = 'atlas-pca/action-schema-ref/v1';
    public const ACTION_SCHEMA_KIND = 'pca-action-schema';
    public const MAX_SCHEMA_VERBS = 256;
    public const MAX_SCHEMA_PARAMS = 64;
    public const MAX_SCHEMA_VALUES = 256;
    public const DEFAULT_MAX_LEN = 1024;
    public const DEFAULT_MAX_ITEMS = 64;

    public const INTENT_SESSION_KIND = 'pca-intent-session';
    public const INTENT_SESSION_SIG_DOMAIN = "atlas-pca/intent-session/v1\0";
    public const INTENT_SESSION_REF_DOMAIN = 'atlas-pca/intent-session-ref/v1';
    public const INTENT_SESSION_CAVEAT = 'intent_session';
    public const MAX_SESSION_SEQ = 2147483647;
    public const MAX_SESSION_PRINCIPALS = 16;
    public const MAX_IS_ACC = 16;
    public const MAX_IS_FACTS = 16;
    public const MAX_IS_PROV_PATHS = 32;
    public const MAX_IS_PROV_REFS = 8;
    public const MAX_IS_CLASSES = 8;
    public const MAX_IS_LABELS = 16;
    public const MAX_IS_STRING_BYTES = 256;
    public const INTENT_SESSION_FIELDS = ['session', 'root', 'seq', 'schema', 'acc', 'facts', 'offer_set', 'prov', 'classes', 'labels', 'map_form'];

    public const MAX_SESSION_ACCUMULATORS = 16;
    public const MAX_SESSION_MONITORS = 16;
    public const MAX_MONITOR_WITHIN = 64;
    public const ACC_RECEIPT_DOMAIN = "atlas-pca/acc-receipt/v1\0";
    public const ACC_RECEIPT_REF_DOMAIN = 'atlas-pca/acc-receipt-ref/v1';
    public const ACC_RESERVE_DOMAIN = 'atlas-pca/acc-reserve/v1';
    public const SEQUENCER_KEYS_DOMAIN = "atlas-pca/sequencer-keys/v1\0";
    public const SEQUENCER_KEYS_REF_DOMAIN = 'atlas-pca/sequencer-keys-ref/v1';
    public const RECEIPT_SKEW_MS = 60000;
    /** A receipt lives at most 15 min: `issued_at <= expires_at <= issued_at + 900000`. */
    public const MAX_RECEIPT_LIFETIME_MS = 900000;
    /** Default bound on a receipt's age at verification (`policy.acc.max_receipt_age_s`, 900 s). */
    public const DEFAULT_MAX_RECEIPT_AGE_MS = 900000;
    /** Default bound on a key set's age (`policy.acc.max_keyset_age_s`, 3600 s). */
    public const DEFAULT_MAX_KEYSET_AGE_MS = 3600000;

    public const REVEPOCH_DOMAIN = "atlas-pca/revepoch/v1\0";
    public const REVSET_DOMAIN = "pca-revset/v1\0";
    public const REVOCATION_SKEW_MS = 60000;

    // rule 19 (V15): the committed Intent Map (intent-map-commit.ts)
    public const MAP_TAG_HEADER = "atlas-pca/intent-map/header/v1\0";
    public const MAP_TAG_CELL = "atlas-pca/intent-map/cell/v1\0";
    public const MAP_TAG_METRICS = "atlas-pca/intent-map/metrics/v1\0";
    public const MAP_TAG_LEARNER = "atlas-pca/intent-map/learner/v1\0";
    public const MAP_TAG_NODE = "atlas-pca/intent-map/node/v1\0";
    public const MAP_TAG_COMMIT = "atlas-pca/intent-map/commit/v1\0";
    public const MAP_TAG_SALT = "atlas-pca/intent-map/salt/v1\0";
    public const MAP_FORM_COMMIT = 'commit';
    /** The OTHER value of a categorical dimension (U+22A5). */
    public const MAP_OTHER = "\u{22A5}";
    public const MAX_MAP_LEAVES = 16777216;
    public const MAX_VERB_CELLS = 1048576;
    public const MAX_MAP_DIMS = 16;
    public const MAX_MAP_CUTS = 256;
    public const MAX_MAP_VALUES = 256;
    public const MAX_MAP_STRING_BYTES = 256;
    public const MAP_METRIC_FIELDS = ['residual_risk_ppm', 'burden_ppm', 'uncertainty_ppm', 'disagreement_ppm', 'mean_harm_ppm',
        'fidelity_est_ppm', 'entropy_mbits', 'questions', 'conflicts'];

    /** The token every refusal of a suite this verifier does not implement carries (intent-strict.ts UNSUPPORTED_SUITE). */
    public const UNSUPPORTED_SUITE = 'unsupported_suite';
    /** Names the predicate DSL cannot address: refused as accumulator ids, monitor ids and schema parameter names. */
    public const RESERVED_NAMES = ['__proto__', 'constructor', 'prototype'];

    public const PARAM_PATH_RE = '/\Aaction\.params\.[A-Za-z0-9_]{1,64}\z/';
    public const PARAM_PATH_RE_V2 = '/\Aaction\.params\.[A-Za-z0-9_]{1,64}(?:\.[A-Za-z0-9_]{1,64}){0,2}\z/';
    public const UNIT_ID_RE = '/\A[a-z0-9_]+(?:\.[a-z0-9_]+)*\z/';
    public const ACC_ID_RE = '/\A[A-Za-z0-9_]{1,64}\z/';
    public const KID_RE = '/\A[A-Za-z0-9_.:-]{1,64}\z/';
    private const DATE_RE = '/\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/';

    public const PARAM_TYPES = ['string', 'integer', 'boolean', 'date', 'set', 'array'];
    public const PARAM_TYPES_V2 = ['string', 'integer', 'boolean', 'date', 'set', 'array', 'datetime', 'duration', 'object_ref'];
    public const SCHEMA_V2_EFFECTS = ['read', 'create', 'update', 'delete', 'send', 'pay', 'exec', 'privilege', 'export', 'publish', 'provision', 'sign'];
    public const SCHEMA_V2_CAVEATS = ['amount_cap', 'count_cap', 'window', 'resource_scope', 'recipient_scope', 'approval_ref', 'short_expiry', 'rate_cap'];
    public const SCHEMA_V2_PRULES = ['array_bounded', 'export_bounded', 'id_not_wildcard', 'money_amount_bounded', 'money_has_currency',
        'pay_has_idempotency', 'recipient_param_declared', 'secret_not_logged'];
    public const SCHEMA_V2_CONTEXT = ['approval_ref', 'dry_run_first', 'fresh_revocation', 'idempotency', 'revocable', 'sandbox_attested'];
    public const SCHEMA_V2_TAGS = ['pii', 'phi', 'pci', 'secret', 'credential', 'free_text_outbound', 'code', 'path', 'sql'];
    public const SCHEMA_V2_PROVENANCE = ['first_party', 'tool', 'agent'];
    private const TRAIT_ID_RE = '/\A[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}\z/';
    private const TAINT_CTX_RE = '/\Asession_taint_max:[a-z_]{1,16}\z/';
    public const SENSITIVITIES = ['free', 'material', 'critical'];
    public const SCHEMA_REVERSIBILITY = ['reversible', 'rate_limited', 'irreversible'];
    public const ACC_AGGS = ['sum', 'count', 'distinct', 'max'];
    public const MONITOR_KINDS = ['requires_prior', 'precedes', 'never', 'always', 'responds_within'];

    private const DOC_KEYS = ['v', 'kind', 'site', 'aud', 'version', 'units', 'state', 'verbs', 'sig'];
    private const VERB_KEYS = ['verb', 'kind', 'params', 'reversibility', 'reversibility_by', 'mcp', 'openapi', 'harm', 'world',
        'effects', 'returns', 'description'];
    private const PARAM_KEYS = ['type', 'semantic', 'sensitivity', 'required', 'values', 'min', 'max', 'unit', 'max_len', 'items',
        'min_items', 'max_items', 'default', 'principal_neutral_default', 'accumulates_into', 'issued_by_site', 'description'];
    private const DOC_KEYS_V2 = ['v', 'kind', 'site', 'aud', 'version', 'units', 'state', 'verbs', 'sig', 'traits_digest', 'trait_defs', 'pack'];
    private const VERB_KEYS_V2 = ['verb', 'kind', 'params', 'reversibility', 'reversibility_by', 'mcp', 'openapi', 'harm', 'world',
        'effects', 'returns', 'description', 'traits', 'def', 'floors', 'confirmation'];
    private const PARAM_KEYS_V2 = ['type', 'semantic', 'sensitivity', 'required', 'values', 'min', 'max', 'unit', 'max_len', 'items',
        'min_items', 'max_items', 'default', 'principal_neutral_default', 'accumulates_into', 'issued_by_site', 'description',
        'role', 'format', 'tags', 'provenance_min'];
    private const WS = '\t\n\x0b\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}'; // ECMAScript \s
    private const DATETIME_RE = '/\A([0-9]{4}-[0-9]{2}-[0-9]{2})T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])(?:\.[0-9]{1,3})?Z\z/';
    private const SIG_KEYS = ['alg', 'kid', 'value', 'pq_value'];
    private const ROOT_KEYS = ['v', 'kind', 'session', 'principals', 'intent_ref', 'schema', 'layers', 'accumulators', 'monitors',
        'question_uri', 'revocation', 'flows', 'expires_at', 'signer', 'alg', 'pq_pk', 'sig', 'pq_sig'];
    private const RECEIPT_KEYS = ['v', 'kind', 'session', 'acc', 'seq', 'pre', 'delta', 'post', 'pcactn_digest', 'aud', 'issued_at',
        'expires_at', 'kid', 'ledger', 'signer', 'alg', 'pq_pk', 'sig', 'pq_sig'];
    private const MAX_SAFE = 9007199254740991;

    private const MAP_TAGS = ['header' => self::MAP_TAG_HEADER, 'cell' => self::MAP_TAG_CELL, 'metrics' => self::MAP_TAG_METRICS,
        'learner' => self::MAP_TAG_LEARNER];

    // ==== value helpers ==============================================================================================

    private static ?\stdClass $undef = null;

    /** An ABSENT member (JS `undefined`), distinct from JSON null. Never part of a JSON tree. */
    public static function undef(): \stdClass
    {
        return self::$undef ??= new \stdClass();
    }

    /** ECMAScript String(v) of a member read (absent => "undefined"): the reference's String(p.action?.verb) etc. */
    private static function jsString(mixed $v): string
    {
        return self::isU($v) ? 'undefined' : IntentWb::jsStr($v);
    }

    private static function isU(mixed $x): bool
    {
        return $x === self::undef();
    }

    /** @return array{ok:false, reason:string} */
    private static function bad(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    /** The own member `k` of an Obj, else absent (a non-object has no members). */
    private static function m(mixed $o, string $k): mixed
    {
        return $o instanceof Obj && $o->has($k) ? $o->get($k) : self::undef();
    }

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** Absent -> `$d` (an optional member's default); a present member (null included) is returned as is. */
    private static function dflt(mixed $x, mixed $d): mixed
    {
        return self::isU($x) ? $d : $x;
    }

    /** UTF-8 sequences (a lone surrogate is its 3-byte WTF-8 form) of a string. @return list<string> */
    private static function chars(string $s): array
    {
        preg_match_all('/[\x00-\x7F]|[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3}|[\x80-\xFF]/', $s, $m);
        return $m[0];
    }

    /** String `.length` (UTF-16 code units). */
    public static function u16len(string $s): int
    {
        if (preg_match('/[\x80-\xFF]/', $s) !== 1) {
            return strlen($s);
        }
        $n = 0;
        foreach (self::chars($s) as $c) {
            $n += strlen($c) === 4 ? 2 : 1;
        }
        return $n;
    }

    /** `path.slice('action.params.'.length)` (a well-formed path is ASCII). */
    private static function paramName(string $path): string
    {
        return (string)substr($path, 14);
    }

    private static function lone(string $s): bool
    {
        return Json::hasLoneSurrogate($s);
    }

    /** A non-empty string without lone surrogates of at most `max` UTF-8 bytes. */
    private static function isStr(mixed $v, int $max = 256): bool
    {
        return is_string($v) && $v !== '' && !self::lone($v) && strlen($v) <= $max;
    }

    private static function b32(mixed $v): bool
    {
        return Pca::unb64u($v, 32) !== null;
    }

    /** The binary64 value of a JSON number (a Num of any lexeme, or a PHP int / float), else null (a bool is not a number). */
    private static function f(mixed $x): ?float
    {
        if ($x instanceof Num) {
            return (float)$x->lexeme;
        }
        if (is_int($x)) {
            return (float)$x;
        }
        if (is_float($x)) {
            return $x;
        }
        return null;
    }

    private static function negZero(float $f): bool
    {
        return $f == 0.0 && fdiv(1.0, $f) < 0;
    }

    /** A safe integer by value: integral, |v| <= 2^53-1, not -0 (an integral float such as 5.0 counts). */
    private static function isInt(mixed $x): bool
    {
        $f = self::f($x);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= self::MAX_SAFE && !self::negZero($f);
    }

    private static function isNonNeg(mixed $x): bool
    {
        return self::isInt($x) && self::f($x) >= 0;
    }

    /** The integer value of a safe-integer number. */
    private static function iv(mixed $x): int
    {
        return (int)self::f($x);
    }

    /** Same JSON type and value (numbers by value): the strict equality of two scalars. */
    private static function eq(mixed $a, mixed $b): bool
    {
        if (self::isU($a) || self::isU($b)) {
            return $a === $b;
        }
        $fa = self::f($a);
        $fb = self::f($b);
        if ($fa !== null || $fb !== null) {
            return $fa !== null && $fb !== null && $fa == $fb;
        }
        if (is_string($a) || is_string($b) || is_bool($a) || is_bool($b) || $a === null || $b === null) {
            return $a === $b;
        }
        return is_object($a) && $a === $b;
    }

    /** String members of a list are distinct (by exact bytes). */
    private static function distinct(array $xs): bool
    {
        return count(array_unique($xs, SORT_STRING)) === count($xs);
    }

    /** Array-index property key ("0".."4294967294", no leading zeros). */
    private static function isIndexKey(string $k): bool
    {
        return preg_match('/\A(?:0|[1-9][0-9]{0,9})\z/', $k) === 1 && (int)$k <= 4294967294;
    }

    /** `Object.keys(o)` order of an Obj: array-index keys ascending, then the others in insertion order. @return list<string> */
    public static function jsKeys(Obj $o): array
    {
        $idx = [];
        $rest = [];
        foreach ($o->keys() as $k) {
            if (self::isIndexKey($k)) {
                $idx[] = $k;
            } else {
                $rest[] = $k;
            }
        }
        usort($idx, fn($a, $b) => (int)$a <=> (int)$b);
        return array_merge($idx, $rest);
    }

    /** `Object.keys(o).sort().join()` (only compared with an ASCII literal, so byte order is equivalent). */
    private static function sortedJoin(Obj $o): string
    {
        $k = $o->keys();
        sort($k, SORT_STRING);
        return implode(',', $k);
    }

    /** compareUtf8 of hash.ts: 0 when equal, else UTF-8 bytewise (lone surrogates as U+FFFD), then by length. */
    public static function compareUtf8(string $a, string $b): int
    {
        if ($a === $b) {
            return 0;
        }
        $x = (string)preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\xEF\xBF\xBD", $a);
        $y = (string)preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\xEF\xBF\xBD", $b);
        $n = min(strlen($x), strlen($y));
        for ($i = 0; $i < $n; $i++) {
            $d = ord($x[$i]) - ord($y[$i]);
            if ($d !== 0) {
                return $d;
            }
        }
        return strlen($x) - strlen($y);
    }

    /** @param list<string> $xs @return list<string> */
    private static function sortUtf8(array $xs): array
    {
        usort($xs, fn($a, $b) => self::compareUtf8($a, $b));
        return $xs;
    }

    /** ECMAScript Number::toString of a binary64 value (canonical numbers and reason texts). */
    public static function jsNumStr(float $f): string
    {
        if (is_nan($f)) {
            return 'NaN';
        }
        if (is_infinite($f)) {
            return $f > 0 ? 'Infinity' : '-Infinity';
        }
        if ($f == 0.0) {
            return '0';
        }
        if ($f < 0) {
            return '-' . self::jsNumStr(-$f);
        }
        $s = '';
        for ($p = 1; $p <= 17; $p++) {
            $s = sprintf('%.' . ($p - 1) . 'e', $f);
            if ((float)$s === $f) {
                break;
            }
        }
        if (preg_match('/\A([0-9])(?:\.([0-9]+))?e([+-]?[0-9]+)\z/', $s, $m) !== 1) {
            throw new JsonError('number formatting failed');
        }
        $digits = rtrim($m[1] . ($m[2] ?? ''), '0');
        $digits = $digits === '' ? '0' : $digits;
        $n = (int)$m[3] + 1;
        $k = strlen($digits);
        if ($k <= $n && $n <= 21) {
            return $digits . str_repeat('0', $n - $k);
        }
        if (0 < $n && $n <= 21) {
            return substr($digits, 0, $n) . '.' . substr($digits, $n);
        }
        if (-6 < $n && $n <= 0) {
            return '0.' . str_repeat('0', -$n) . $digits;
        }
        $e = $n - 1;
        $es = ($e >= 0 ? '+' : '-') . abs($e);
        return $k === 1 ? $digits . 'e' . $es : $digits[0] . '.' . substr($digits, 1) . 'e' . $es;
    }

    /** Text of a scalar for a reason string (numbers by value). */
    private static function txt(mixed $x): string
    {
        $f = self::f($x);
        if ($f !== null) {
            return self::jsNumStr($f);
        }
        if (is_string($x)) {
            return $x;
        }
        if (is_bool($x)) {
            return $x ? 'true' : 'false';
        }
        if (self::isList($x)) {
            // ECMAScript String(array): the elements joined by ",", null / undefined as the empty string
            return implode(',', array_map(static fn($e) => $e === null || self::isU($e) ? '' : self::txt($e), $x));
        }
        if ($x instanceof Obj) {
            return '[object Object]';
        }
        return $x === null ? 'null' : (self::isU($x) ? 'undefined' : get_debug_type($x));
    }

    // ==== strict canonical form of JS values ==========================================================================

    /**
     * `canonicalizeStrict` of hash.ts over the JS VALUES of a JSON tree: a Num of any lexeme is written as the number it
     * denotes (`1.0` -> `1`, `1e3` -> `1000`); -0, a non-finite value, an integer above 2^53-1, a fraction below 1e-6 or with
     * more than 15 significant digits, a lone surrogate, nesting past 32 and an absent value throw JsonError. Object keys
     * sort by UTF-8 bytes. PHP ints / floats and assoc arrays are accepted as numbers / objects.
     */
    public static function canonicalize(mixed $v): string
    {
        $out = '';
        self::ser($out, $v, 1);
        return $out;
    }

    public static function hashCanonical(mixed $v): string
    {
        return Pca::b64u(hash('sha256', self::canonicalize($v), true));
    }

    private static function numStrict(float $f): string
    {
        if (!is_finite($f)) {
            throw new JsonError('canonicalize: non-finite number');
        }
        if (self::negZero($f)) {
            throw new JsonError('canonicalize: negative zero');
        }
        if (floor($f) === $f) {
            if (abs($f) > self::MAX_SAFE) {
                throw new JsonError('canonicalize: integer outside the safe range (|n| > 2^53-1)');
            }
            return sprintf('%.0f', $f);
        }
        if (abs($f) < 1e-6) {
            throw new JsonError('canonicalize: non-integer magnitude below 1e-6');
        }
        $s = self::jsNumStr($f);
        if (stripos($s, 'e') !== false) {
            throw new JsonError('canonicalize: non-integer number needs an exponent form');
        }
        if (strlen(ltrim(str_replace(['-', '.'], '', $s), '0')) > 15) {
            throw new JsonError('canonicalize: non-integer number has more than 15 significant digits');
        }
        return $s;
    }

    private static function ser(string &$out, mixed $v, int $depth): void
    {
        if ($v === null) {
            $out .= 'null';
            return;
        }
        if (is_bool($v)) {
            $out .= $v ? 'true' : 'false';
            return;
        }
        if (is_string($v)) {
            if (self::lone($v)) {
                throw new JsonError('canonicalize: lone surrogate in string');
            }
            $out .= Json::canonicalizeStrict($v);
            return;
        }
        $f = self::f($v);
        if ($f !== null) {
            $out .= self::numStrict($f);
            return;
        }
        if (is_array($v) || $v instanceof Obj) {
            if ($depth > Json::MAX_DEPTH) {
                throw new JsonError('canonicalize: nesting too deep');
            }
            if (self::isList($v)) {
                $out .= '[';
                foreach ($v as $i => $x) {
                    if ($i > 0) {
                        $out .= ',';
                    }
                    self::ser($out, $x, $depth + 1);
                }
                $out .= ']';
                return;
            }
            $o = $v instanceof Obj ? $v : Obj::of($v);
            $out .= '{';
            foreach (self::sortUtf8($o->keys()) as $i => $k) {
                if (self::lone($k)) {
                    throw new JsonError('canonicalize: lone surrogate in key');
                }
                if ($i > 0) {
                    $out .= ',';
                }
                $out .= Json::canonicalizeStrict($k) . ':';
                self::ser($out, $o->get($k), $depth + 1);
            }
            $out .= '}';
            return;
        }
        throw new JsonError('canonicalize: unsupported type ' . (self::isU($v) ? 'undefined' : get_debug_type($v)));
    }

    // ==== suites (through the SDK dispatch) ===========================================================================

    /**
     * suiteCapabilityError of intent-strict.ts with this verifier's dispatch: absent = ed25519 (null); a non-string is
     * malformed; a string this verifier does not implement (Pca::suiteAvailable) is `unsupported_suite`.
     */
    public static function suiteError(mixed $alg): ?string
    {
        if (self::isU($alg)) {
            return null;
        }
        if (!is_string($alg)) {
            return 'alg must be a string';
        }
        return Pca::suiteAvailable($alg) ? null : self::UNSUPPORTED_SUITE . ": '$alg'";
    }

    /**
     * suiteError for a session root's SHAPE (sessionRootShapeError): a registered suite (Pca::REGISTERED_SUITES, the TS
     * registry) passes even when this host cannot run it, so the verifier-pin checks of verifySessionRoot (which need no crypto) run before availability, in
     * the reference's order; verifySessionRoot refuses an unavailable signer suite with `unsupported_suite` after the pins.
     */
    private static function suiteKnownError(mixed $alg): ?string
    {
        if (self::isU($alg)) {
            return null;
        }
        if (!is_string($alg)) {
            return 'alg must be a string';
        }
        return in_array($alg, Pca::REGISTERED_SUITES, true) ? null : self::UNSUPPORTED_SUITE . ": '$alg'";
    }

    /** The suite of an `alg` that passed suiteError: absent -> ed25519, else itself. */
    private static function suiteOf(mixed $alg): string
    {
        return self::isU($alg) ? 'ed25519' : (string)$alg;
    }

    /** bindSuiteFields of pq.ts: a non-ed25519 suite binds `alg` and `pq_pk` (an absent `pq_pk` makes the body throw). */
    private static function bindSuite(Obj $base, mixed $alg, mixed $pqPk): Obj
    {
        $suite = self::suiteOf($alg);
        if ($suite === 'ed25519') {
            return $base;
        }
        $o = new Obj();
        foreach ($base->keys() as $k) {
            $o->set($k, $base->get($k));
        }
        $o->set('alg', $suite);
        $o->set('pq_pk', $pqPk);
        return $o;
    }

    /**
     * verifyPinnedSuite of pq.ts through the SDK dispatch (Pca::verifyPinnedSuite). `$alg` has passed suiteError. A PQ
     * suite verifies only under the verifier-side pin `$pinPq` for `$identity` (none when `$pinKey` is null), never under
     * the artifact's own `pq_pk`; a pin that is not a string refuses.
     */
    private static function verifyPinned(mixed $alg, mixed $identity, mixed $artifactPq, string $msg, mixed $sig, mixed $pqSig,
                                         ?string $pinKey = null, mixed $pinPq = null): bool
    {
        if (!is_string($identity) || ($pinKey !== null && ($pinKey !== $identity || !is_string($pinPq)))) {
            return false;
        }
        return Pca::verifyPinnedSuite(self::suiteOf($alg), $identity, self::isU($artifactPq) ? null : $artifactPq, $msg,
            self::isU($sig) ? null : $sig, self::isU($pqSig) ? null : $pqSig, $pinKey !== null ? $pinPq : null) === true;
    }

    /**
     * Registry-signed documents (evolution records, packs): verify `$sig` over DOMAIN . canonical($body) against the pinned `$keys`
     * (the suite comes from the KEY entry). Never throws. @return array{ok:bool, reason?:string}
     */
    public static function verifyRegistrySig(string $domain, Obj $body, mixed $sig, mixed $keys): array
    {
        try {
            if (!self::isList($keys)) {
                return self::bad('the registry keys must be an array');
            }
            $kid = self::m($sig, 'kid');
            $key = null;
            foreach ($keys as $k) {
                if ($k instanceof Obj && self::eq(self::m($k, 'kid'), $kid)) {
                    $key = $k;
                    break;
                }
            }
            if ($key === null) {
                return self::bad('no registry key with kid \'' . (is_string($kid) ? $kid : 'undefined') . '\'');
            }
            if ($key->has('pq_pk') && !is_string($key->get('pq_pk'))) {
                return self::bad('the registry key pq_pk must be a string');
            }
            $pk = self::m($key, 'pk');
            if (Pca::unb64u($pk, 32) === null) {
                return self::bad('registry key pk is not canonical base64url (32 bytes)');
            }
            if (self::suiteError(self::m($key, 'alg')) !== null || self::suiteError(self::m($sig, 'alg')) !== null
                || self::suiteOf(self::m($key, 'alg')) !== self::suiteOf(self::m($sig, 'alg'))) {
                return self::bad('sig.alg does not match the pinned key suite');
            }
            $pq = self::m($key, 'pq_pk');
            if (!self::verifyPinned(self::suiteOf(self::m($key, 'alg')), $pk, $pq, $domain . self::canonicalize($body), self::m($sig, 'value'),
                self::m($sig, 'pq_value'), self::isU($pq) ? null : $pk, $pq)) {
                return self::bad('signature invalid');
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return self::bad('verification error: ' . $e->getMessage());
        }
    }

    /** An Ed25519 signature over `$msg` by the key `$issuer` (b64u). Never throws. */
    public static function verifyEd25519(mixed $issuer, string $msg, mixed $sigValue): bool
    {
        try {
            return self::verifyPinned('ed25519', $issuer, self::undef(), $msg, $sigValue, self::undef());
        } catch (\Throwable) {
            return false;
        }
    }

    // ==== the v2 pipeline (intent-v2.ts) ==============================================================================

    /** A member that is absent, or present as an object. */
    private static function optObj(mixed $o, string $k): bool
    {
        return !($o instanceof Obj) || !$o->has($k) || $o->get($k) instanceof Obj;
    }

    private static function optArr(mixed $o, string $k): bool
    {
        return !($o instanceof Obj) || !$o->has($k) || self::isList($o->get($k));
    }

    /**
     * intentV2ContextError: the whole v2 context; ABSENT members mean empty / default, a member PRESENT with null (or of
     * the wrong JSON type) is malformed. Null = well-formed.
     */
    public static function intentV2ContextError(mixed $ctx): ?string
    {
        if ($ctx === null || self::isU($ctx)) {
            return null;
        }
        if (!($ctx instanceof Obj)) {
            return 'the v2 verifier context must be an object';
        }
        if (!self::optObj($ctx, 'policy')) {
            return 'policy must be an object';
        }
        $pol = self::m($ctx, 'policy');
        if ($pol instanceof Obj) {
            // closed member sets; every flag a JSON boolean and every number a safe integer when present (absent = default)
            foreach (self::jsKeys($pol) as $k) {
                if ($k !== 'session' && $k !== 'schema' && $k !== 'acc' && $k !== 'map' && $k !== 'model_polarity') {
                    return "policy: unknown member '$k'";
                }
            }
            if ($pol->has('model_polarity') && $pol->get('model_polarity') !== 'strict' && $pol->get('model_polarity') !== 'legacy') {
                return "policy.model_polarity must be 'strict' or 'legacy'";
            }
            if (!self::optObj($pol, 'session')) {
                return 'policy.session must be an object';
            }
            $ps = self::m($pol, 'session');
            if ($ps instanceof Obj) {
                foreach (self::jsKeys($ps) as $k) {
                    if ($k !== 'require' && $k !== 'max_revocation_age_s') {
                        return "policy.session: unknown member '$k'";
                    }
                }
                if ($ps->has('require') && !is_bool($ps->get('require'))) {
                    return 'policy.session.require must be a boolean';
                }
                if ($ps->has('max_revocation_age_s') && !self::isNonNeg($ps->get('max_revocation_age_s'))) {
                    return 'policy.session.max_revocation_age_s must be a non-negative safe integer';
                }
            }
            if (!self::optObj($pol, 'schema')) {
                return 'policy.schema must be an object';
            }
            $pc = self::m($pol, 'schema');
            if ($pc instanceof Obj) {
                foreach (self::jsKeys($pc) as $k) {
                    if ($k !== 'closed_world') {
                        return "policy.schema: unknown member '$k'";
                    }
                }
                if ($pc->has('closed_world') && !is_bool($pc->get('closed_world'))) {
                    return 'policy.schema.closed_world must be a boolean';
                }
            }
            if (!self::optObj($pol, 'acc')) {
                return 'policy.acc must be an object';
            }
            $pa = self::m($pol, 'acc');
            if ($pa instanceof Obj) {
                foreach (self::jsKeys($pa) as $k) {
                    if ($k !== 'max_receipt_age_s' && $k !== 'max_keyset_age_s') {
                        return "policy.acc: unknown member '$k'";
                    }
                }
                foreach (['max_receipt_age_s', 'max_keyset_age_s'] as $k) {
                    if ($pa->has($k) && !self::isNonNeg($pa->get($k))) {
                        return "policy.acc.$k must be a non-negative safe integer";
                    }
                }
            }
            if (!self::optObj($pol, 'map')) {
                return 'policy.map must be an object';
            }
            $pm = self::m($pol, 'map');
            if ($pm instanceof Obj) {
                foreach (self::jsKeys($pm) as $k) {
                    if ($k !== 'require' && $k !== 'max_residual_risk_ppm') {
                        return "policy.map: unknown member '$k'";
                    }
                }
                if ($pm->has('require') && !is_bool($pm->get('require'))) {
                    return 'policy.map.require must be a boolean';
                }
                if ($pm->has('max_residual_risk_ppm') && !self::isNonNeg($pm->get('max_residual_risk_ppm'))) {
                    return 'policy.map.max_residual_risk_ppm must be a non-negative safe integer';
                }
            }
        }
        if (!self::optObj($ctx, 'params')) {
            return 'params must be an object';
        }
        if (!self::optObj($ctx, 'env')) {
            return 'env must be an object';
        }
        foreach (['schema', 'session', 'acc'] as $k) {
            if (!self::optObj($ctx, $k)) {
                return "$k must be an object";
            }
        }
        if (!self::optObj($ctx, 'map')) {
            return 'map must be an object';
        }
        foreach (self::m($ctx, 'map') instanceof Obj ? self::jsKeys($ctx->get('map')) : [] as $k) {
            if ($k !== 'disclosure') {
                return "map: unknown member '$k'";
            }
        }
        if ($ctx->has('layers')) {
            $L = $ctx->get('layers');
            if (!($L instanceof Obj)) {
                return 'layers must be an object';
            }
            foreach (self::jsKeys($L) as $k) {
                if (!in_array($k, ['org', 'site', 'std'], true)) {
                    return "layers: unknown member '$k'";
                }
                $v = $L->get($k);
                if (!($v instanceof Obj) || !self::isList(self::m($v, 'predicates'))) {
                    return "layers.$k must be {predicates: [...]}";
                }
            }
        }
        if ($ctx->has('wb')) {
            $wb = $ctx->get('wb');
            if (!($wb instanceof Obj)) {
                return 'wb must be an object';
            }
            if (!self::optObj($wb, 'artifacts')) {
                return 'wb.artifacts must be an object';
            }
            $a = self::m($wb, 'artifacts');
            foreach (['facts', 'labels', 'verdicts'] as $k) {
                if (!self::optArr($a, $k)) {
                    return "wb.artifacts.$k must be an array";
                }
            }
            if (!self::optObj($a, 'offer_set')) {
                return 'wb.artifacts.offer_set must be an object';
            }
            if (!self::optObj($wb, 'policy')) {
                return 'wb.policy must be an object';
            }
            $p = self::m($wb, 'policy');
            if (!self::optObj($p, 'world') || !self::optObj($p, 'provenance')) {
                return 'wb.policy.world / provenance must be objects';
            }
            if (!self::optArr($p, 'classifiers')) {
                return 'wb.policy.classifiers must be an array';
            }
        }
        return null;
    }

    private static function schemaCtxError(mixed $ctx): ?string
    {
        $sc = self::m($ctx, 'schema');
        if (self::isU($sc)) {
            return null;
        }
        if (!($sc instanceof Obj) || !self::isList(self::m($sc, 'docs')) || !self::isList(self::m($sc, 'keys'))) {
            return 'the schema context must be {docs: [...], keys: [...]}';
        }
        return null;
    }

    private static function sessionCtxError(mixed $ctx): ?string
    {
        $se = self::m($ctx, 'session');
        if (self::isU($se)) {
            return null;
        }
        if (!($se instanceof Obj)) {
            return 'the session context must be an object';
        }
        if ($se->has('grants') && !self::isList($se->get('grants'))) {
            return 'the session grants must be an array';
        }
        if ($se->has('revocation') && !($se->get('revocation') instanceof Obj)) {
            return 'the session revocation evidence must be an object';
        }
        if ($se->has('revocation_last') && !($se->get('revocation_last') instanceof Obj)) {
            return 'the tracked last revocation epoch must be an object';
        }
        if ($se->has('pq_pins')) {
            $pp = $se->get('pq_pins');
            if (!($pp instanceof Obj)) {
                return 'the session pq_pins must be an object of strings';
            }
            foreach ($pp->keys() as $k) {
                if (!is_string($pp->get($k))) {
                    return 'the session pq_pins must be an object of strings';
                }
            }
        }
        return null;
    }

    private static function accCtxError(mixed $ctx): ?string
    {
        $a = self::m($ctx, 'acc');
        if (self::isU($a)) {
            return null;
        }
        if (!($a instanceof Obj)) {
            return 'the accumulator context must be an object';
        }
        foreach (['state', 'monitors', 'last_seq', 'keyset_versions'] as $k) {
            if ($a->has($k) && !($a->get($k) instanceof Obj)) {
                return "acc.$k must be an object";
            }
        }
        if ($a->has('keyset_versions')) {
            foreach (self::jsKeys($a->get('keyset_versions')) as $k) {
                if (($e = self::trackedKeySetError($a->get('keyset_versions')->get($k))) !== null) {
                    return "acc.keyset_versions: $e";
                }
            }
        }
        foreach (['receipts', 'sequencer_keys'] as $k) {
            if ($a->has($k) && !self::isList($a->get($k))) {
                return "acc.$k must be an array";
            }
        }
        if ($a->has('last_seq')) {
            foreach ($a->get('last_seq')->keys() as $k) {
                if (!self::isNonNeg($a->get('last_seq')->get($k))) {
                    return 'acc.last_seq values must be non-negative safe integers';
                }
            }
        }
        return null;
    }

    /** `ctx?.a?.b` over own members (absent when any link is missing). */
    private static function cg(mixed $ctx, string ...$path): mixed
    {
        $o = $ctx;
        foreach ($path as $k) {
            $o = self::m($o, $k);
            if (self::isU($o)) {
                return $o;
            }
        }
        return $o;
    }

    /** Rule 14 (`schema`). @return array{ok:bool, reason?:string, doc?:Obj} */
    private static function schemaStep(Obj $p, mixed $ctx): array
    {
        $is = self::m($p, 'intent_session');
        if (($ce = self::schemaCtxError($ctx)) !== null) {
            return self::bad($ce);
        }
        $docs = self::cg($ctx, 'schema', 'docs');
        if (!self::isList($docs) || count($docs) === 0) {
            return self::bad('this verifier has no action schema configured');
        }
        if (!self::isU($is)) {
            $doc = null;
            foreach ($docs as $d) {
                try {
                    if (self::actionSchemaDigest($d) === self::m($is, 'schema')) {
                        $doc = $d;
                        break;
                    }
                } catch (\Throwable) {
                }
            }
            if ($doc === null) {
                return self::bad('intent_session.schema names no schema this verifier accepts');
            }
        } else {
            $doc = $docs[0];
        }
        $v = self::verifyActionSchema($doc, self::cg($ctx, 'schema', 'keys'));
        if (!$v['ok']) {
            return self::bad('schema does not verify: ' . $v['reason']);
        }
        if ($doc->get('aud') !== self::m($p, 'aud')) {
            return self::bad('schema aud does not match the PCActn aud');
        }
        $params = self::m($ctx, 'params');
        if (!($params instanceof Obj)) {
            return self::bad('no plaintext params to check against the schema (closed world needs them)');
        }
        if (self::hashCanonical($params) !== self::cg($p, 'action', 'params_digest')) {
            return self::bad('params do not hash to action.params_digest');
        }
        $c = self::conformAction($doc, self::jsString(self::cg($p, 'action', 'verb')), $params);
        if (!$c['ok']) {
            return self::bad('schema_violation: ' . $c['code'] . ': ' . $c['reason']);
        }
        return ['ok' => true, 'doc' => $doc];
    }

    /** The bound, verified session root (shared by rules 13 and 15). @return array{ok:bool, reason?:string, S?:Obj} */
    private static function boundRoot(Obj $p, mixed $ctx, int $now): array
    {
        $is = self::m($p, 'intent_session');
        $S = self::cg($ctx, 'session', 'root');
        if (self::isU($S)) {
            return self::bad('no session root for this session');
        }
        // a PQ / hybrid root verifies only under the VERIFIER's pin for its signer (session.pq_pins), never its own principals list
        $pins = self::cg($ctx, 'session', 'pq_pins');
        $v = self::verifySessionRoot($S, $pins instanceof Obj ? $pins : null);
        if (!$v['ok']) {
            return self::bad('session root: ' . $v['reason']);
        }
        if (self::sessionRootDigest($S) !== self::m($is, 'root')) {
            return self::bad('intent_session.root is not the digest of the session root');
        }
        if ($S->get('session') !== self::m($is, 'session')) {
            return self::bad('the session root names another session');
        }
        if (!($now < self::iv($S->get('expires_at')))) {
            return self::bad('the session root has expired');
        }
        return ['ok' => true, 'S' => $S];
    }

    /** Rule 13 (`intent_session`). */
    private static function sessionStep(Obj $p, mixed $grant, mixed $ctx, int $now): array
    {
        $maxAgeS = self::cg($ctx, 'policy', 'session', 'max_revocation_age_s');
        if (!self::isU($maxAgeS) && !self::isNonNeg($maxAgeS)) {
            return self::bad('session policy misconfigured: max_revocation_age_s must be a non-negative safe integer (fail closed)');
        }
        $is = self::m($p, 'intent_session');
        if (self::isU($is)) {
            return self::bad('this verifier requires an intent_session but the PCActn carries none');
        }
        if (($ce = self::sessionCtxError($ctx)) !== null) {
            return self::bad($ce);
        }
        $intent = self::m($p, 'intent');
        if (self::isU($intent)) {
            return self::bad('an intent_session needs the envelope.intent binding');
        }
        $r = self::boundRoot($p, $ctx, $now);
        if (!$r['ok']) {
            return $r;
        }
        $S = $r['S'];
        if ($S->get('intent_ref') !== self::m($intent, 'ref')) {
            return self::bad('intent.ref is not the session statement');
        }
        if ($S->get('schema')->get('digest') !== self::m($is, 'schema')) {
            return self::bad('intent_session.schema is not the session schema');
        }
        if ($S->get('schema')->get('aud') !== self::m($p, 'aud')) {
            return self::bad('the session schema is for another audience');
        }
        $seq = self::iv($is->get('seq'));
        if ($seq === 0 && self::m($intent, 'map_digest') !== $S->get('layers')->get('task')->get('map_digest')) {
            return self::bad('a seq-0 action must use the session task map');
        }
        $gc = self::grantSessionCaveat($grant);
        if (($ge = self::intentSessionCaveatError($gc)) !== null) {
            return self::bad("admitting root: $ge");
        }
        if ($gc->get('session') !== $is->get('session') || $gc->get('root') !== $is->get('root') || !self::eq($gc->get('seq'), $seq)) {
            return self::bad('the admitting root is bound to another session, root or seq');
        }
        $principals = [];
        foreach ($S->get('principals') as $x) {
            $principals[] = $x->get('key');
        }
        $isPrincipal = fn(mixed $k) => is_string($k) && in_array($k, $principals, true);
        if (!$isPrincipal(self::m($grant, 'issuer'))) {
            return self::bad('the admitting root is not signed by a session principal');
        }
        $prior = self::dflt(self::cg($ctx, 'session', 'grants'), []);
        if (!self::isList($prior) || count($prior) < $seq) {
            return self::bad("the verifier does not hold the $seq earlier grants of this session");
        }
        for ($i = 0; $i < $seq; $i++) {
            $g = $prior[$i];
            if (!($g instanceof Obj) || !is_string(self::m($g, 'id')) || !is_string(self::m($g, 'issuer'))) {
                return self::bad("session grant $i is not a capability");
            }
            if (($gse = self::suiteError(self::m($g, 'alg'))) !== null) {
                return self::bad("session grant $i: $gse");
            }
            $c = self::grantSessionCaveat($g);
            if (self::intentSessionCaveatError($c) !== null || $c->get('session') !== $is->get('session')
                || $c->get('root') !== $is->get('root') || !self::eq($c->get('seq'), $i)) {
                return self::bad("session grant $i does not belong to this session at seq $i");
            }
            if (!$isPrincipal($g->get('issuer'))) {
                return self::bad("session grant $i is not signed by a session principal");
            }
            if ($i > 0 && self::m($c, 'prev') !== $prior[$i - 1]->get('id')) {
                return self::bad("session grant $i does not chain to grant " . ($i - 1));
            }
        }
        if ($seq > 0 && self::m($gc, 'prev') !== $prior[$seq - 1]->get('id')) {
            return self::bad('the admitting root does not chain to grant ' . ($seq - 1));
        }
        $rev = self::m($S, 'revocation');
        if (!self::isU($rev) || !self::isU($maxAgeS)) {
            $ages = [];
            if (!self::isU($rev)) {
                $ages[] = self::iv($rev->get('max_age_s'));
            }
            if (!self::isU($maxAgeS)) {
                $ages[] = self::iv($maxAgeS);
            }
            $maxAgeMs = min($ages) * 1000;
            if (self::isU($rev)) {
                return self::bad('revocation: the policy requires a revocation epoch but the session root names no revocation authority');
            }
            $ids = [self::sessionRevocationId($is->get('session')), 'pca-intent:map:' . $intent->get('map_digest')];
            for ($i = 0; $i < $seq; $i++) {
                $ids[] = 'pca-intent:delta:' . $prior[$i]->get('id');
            }
            $ids[] = 'pca-intent:delta:' . self::txt(self::m($grant, 'id'));
            $std = self::m($S->get('layers'), 'std');
            if ($std instanceof Obj) {
                $ids[] = 'pca-intent:profile:' . $std->get('profile') . '@' . self::txt($std->get('version'));
            }
            // only the dedicated authority S.revocation.key signs epochs; a PQ epoch verifies only under S.revocation.pq_pk
            $c = ['session' => $is->get('session'), 'authority' => $rev->get('key'), 'ids' => $ids, 'now' => $now, 'maxAgeMs' => $maxAgeMs];
            if ($rev->has('pq_pk')) {
                $c['pqPin'] = $rev->get('pq_pk');
            }
            $last = self::cg($ctx, 'session', 'revocation_last');
            if (!self::isU($last)) {
                $c['last'] = $last;
            }
            $rv = self::checkSessionRevocation(self::cg($ctx, 'session', 'revocation'), $c);
            if (!$rv['ok']) {
                return self::bad('revocation: ' . $rv['reason']);
            }
        }
        return ['ok' => true];
    }

    /** Rule 15 (`accumulators`). @return array{ok:bool, reason?:string, acc?:Obj, mon?:Obj} */
    private static function accStep(Obj $p, mixed $ctx, int $now): array
    {
        $is = $p->get('intent_session');
        $r = self::boundRoot($p, $ctx, $now);
        if (!$r['ok']) {
            return $r;
        }
        $S = $r['S'];
        if (($ce = self::accCtxError($ctx) ?? self::schemaCtxError($ctx)) !== null) {
            return self::bad($ce);
        }
        $verb = self::jsString(self::cg($p, 'action', 'verb'));
        $claims = self::dflt(self::m($is, 'acc'), []);
        $accs = $S->get('accumulators');
        foreach ($claims as $c) {
            $a = null;
            foreach ($accs as $x) {
                if ($x->get('id') === $c->get('id')) {
                    $a = $x;
                    break;
                }
            }
            if ($a === null) {
                return self::bad("claim '" . $c->get('id') . "' names no accumulator of the session");
            }
            if ($a->get('holder')->get('kind') === 'wallet') {
                return self::bad("accumulator '" . $c->get('id') . "' is wallet-held and cannot be claimed at a site");
            }
        }
        $schemaDoc = null;
        foreach (self::dflt(self::cg($ctx, 'schema', 'docs'), []) as $d) {
            try {
                if (self::actionSchemaDigest($d) === $is->get('schema')) {
                    $schemaDoc = $d;
                    break;
                }
            } catch (\Throwable) {
            }
        }
        $params = self::m($ctx, 'params');
        $envAcc = new Obj();
        $envMon = new Obj();
        $state = self::dflt(self::cg($ctx, 'acc', 'state'), new Obj());
        $receipts = self::dflt(self::cg($ctx, 'acc', 'receipts'), []);
        $keySets = self::dflt(self::cg($ctx, 'acc', 'sequencer_keys'), []);
        $lastSeq = self::dflt(self::cg($ctx, 'acc', 'last_seq'), new Obj());
        foreach ($accs as $a) {
            $id = $a->get('id');
            $holder = $a->get('holder');
            $kind = $holder->get('kind');
            if ($kind === 'wallet') {
                continue;
            }
            if ($a->get('sel')->has('accumulates_into') && $schemaDoc === null) {
                return self::bad("accumulator '$id' selects by accumulates_into but the session schema is not available");
            }
            $selected = self::accSelects($a, $verb, $schemaDoc);
            $claim = null;
            foreach ($claims as $c) {
                if ($c->get('id') === $id) {
                    $claim = $c;
                    break;
                }
            }
            $pre = self::m($state, $id);
            if (!$selected) {
                if ($claim !== null) {
                    return self::bad("claim '$id' for an accumulator this action does not feed");
                }
                if ($kind === 'site_local' && !self::isU($pre)) {
                    if (($pe = self::preStateError($a, $pre)) !== null) {
                        return self::bad("accumulator '$id': $pe");
                    }
                    $envAcc->set($id, Obj::of(['post' => new Num((string)self::preValue($a, $pre))]));
                }
                continue;
            }
            if ($claim === null) {
                return self::bad("no claim for accumulator '$id' that this action feeds");
            }
            if (!($params instanceof Obj)) {
                return self::bad('no plaintext params to compute accumulator values');
            }
            $key = $a->get('key');
            if ($key !== null) {
                if (!$params->has(self::paramName($key))) {
                    return self::bad("accumulator '$id': the key parameter $key is missing");
                }
                $sv = $schemaDoc !== null ? self::schemaVerb($schemaDoc, $verb) : self::undef();
                $kd = self::m(self::m($sv, 'params'), $key);
                $sem = self::m($kd, 'semantic');
                if (!is_string($sem) || str_starts_with($sem, 'text.')) {
                    return self::bad("accumulator '$id': the key must be a schema-declared identity (not free text)");
                }
            }
            $v = self::accValueOf($a, $verb, $params, $schemaDoc);
            if (!$v['ok']) {
                return self::bad("accumulator '$id': " . $v['reason']);
            }
            if ($kind === 'site_local') {
                if ($claim->has('receipt')) {
                    return self::bad("accumulator '$id' is site-local: a receipt is not accepted");
                }
                if (self::isU($pre)) {
                    return self::bad("no state for site-local accumulator '$id'");
                }
                if (($pe = self::preStateError($a, $pre)) !== null) {
                    return self::bad("accumulator '$id': $pe");
                }
                $x = self::combineAcc($a, $pre, $v);
                if ($x === null) {
                    return self::bad("accumulator '$id' overflows 2^53-1");
                }
                $post = $x;
            } else {
                if (!$claim->has('receipt')) {
                    return self::bad("accumulator '$id' is sequenced: the claim needs a reservation receipt");
                }
                $rc = null;
                foreach ($receipts as $x) {
                    try {
                        if (self::accReceiptDigest($x) === $claim->get('receipt')) {
                            $rc = $x;
                            break;
                        }
                    } catch (\Throwable) {
                    }
                }
                if ($rc === null) {
                    return self::bad("the reservation receipt for '$id' was not presented");
                }
                // freshness bounds (policy.acc, seconds -> ms; absent = the defaults) and the tracked key-set version of the root
                $pa = self::cg($ctx, 'policy', 'acc');
                $mra = self::m($pa, 'max_receipt_age_s');
                $mka = self::m($pa, 'max_keyset_age_s');
                $tracked = self::m(self::cg($ctx, 'acc', 'keyset_versions'), (string)$holder->get('root'));
                $hv = self::verifyReceiptAgainstHolder($rc, $holder, $keySets, $now, self::isU($mra) ? null : self::iv($mra) * 1000,
                    self::isU($mka) ? null : self::iv($mka) * 1000, null, self::isU($tracked) ? null : $tracked);
                if ($hv === 'unsupported') {
                    return self::bad("the reservation receipt for '$id': " . self::UNSUPPORTED_SUITE
                        . ' (the receipt or the sequencer key set names a suite this verifier does not implement)');
                }
                if ($hv !== 'valid') {
                    return self::bad("the reservation receipt for '$id' is not signed by a key the session sequencer's root-signed key set lists for its issue time");
                }
                if ($rc->get('session') !== $is->get('session') || $rc->get('acc') !== $id || $rc->get('aud') !== self::m($p, 'aud')) {
                    return self::bad("the reservation receipt for '$id' is for another session, accumulator or audience");
                }
                if ($rc->get('pcactn_digest') !== self::pcactnReservationDigest($p)) {
                    return self::bad("the reservation receipt for '$id' is for another action");
                }
                if (!($now <= self::iv($rc->get('expires_at')))) {
                    return self::bad("the reservation receipt for '$id' has expired");
                }
                $last = self::m($lastSeq, $id);
                if (!self::isU($last) && !(self::iv($rc->get('seq')) > self::iv($last))) {
                    return self::bad("the reservation receipt for '$id' replays seq " . self::iv($rc->get('seq'))
                        . ' (last accepted ' . self::iv($last) . ')');
                }
                if (!self::receiptArithmeticOk($a, $rc, $v['val'])) {
                    return self::bad("the reservation receipt for '$id' does not add up");
                }
                $post = self::iv($rc->get('post'));
            }
            if ($a->has('domain_max') && $post > self::iv($a->get('domain_max'))) {
                return self::bad("accumulator '$id' post $post is outside its domain (max " . self::iv($a->get('domain_max')) . ')');
            }
            if (!self::eq($claim->get('post'), $post)) {
                return self::bad('claimed post ' . self::txt($claim->get('post')) . " for '$id' differs from the verifier's $post");
            }
            $envAcc->set($id, Obj::of(['post' => new Num((string)$post)]));
        }
        $mons = self::dflt(self::cg($ctx, 'acc', 'monitors'), new Obj());
        foreach ($S->get('monitors') as $mo) {
            $mid = $mo->get('id');
            $st = self::m($mons, $mid);
            if (!is_string($st) || !in_array($st, self::monitorStates($mo), true)) {
                return self::bad("no valid state for monitor '$mid'");
            }
            $envMon->set($mid, Obj::of(['state' => $st]));
        }
        return ['ok' => true, 'acc' => $envAcc, 'mon' => $envMon];
    }

    /**
     * Run the v2 checks after `intent` (decideIntentV2). Never throws: an internal error fails the check being evaluated.
     * `$ctx` is the verifier state Obj {policy?: {session?: {require?, max_revocation_age_s?}, schema?: {closed_world?},
     * acc?: {max_receipt_age_s?, max_keyset_age_s?}, map?: {require?, max_residual_risk_ppm?}}, params?, schema?: {docs, keys},
     * session?: {root?, grants?, revocation?: {epoch, revoked}, revocation_last?: {epoch, revoked}, pq_pins?: {key: pq_pk}}, layers?: {org?, site?, std?},
     * acc?: {state?, monitors?, receipts?, last_seq?, sequencer_keys?, keyset_versions?}, map?: {disclosure?},
     * wb?: {artifacts?, policy?}} (null = none). A malformed context fails `schema`, `intent_session`, with `intent_session`
     * `accumulators`, and with `map_form` "commit" `map`; a clock that is not a safe integer fails every reported check.
     * @return array{checks: list<array{name:string, ok:bool, reason?:string}>, env: ?Obj, schema: ?Obj}
     *   `env` (or null): canon (rule 14 passed), acc / mon (rule 15 passed), world / prov / class (W-B passed).
     */
    public static function decideIntentV2(mixed $p, mixed $grant, mixed $ctx, int $now): array
    {
        $checks = [];
        $env = null;
        $schemaOut = null;
        $singleSource = [];
        if (!($p instanceof Obj)) {
            return ['checks' => [], 'env' => null, 'schema' => null];
        }
        $present = $p->has('intent_session');
        $committed = $present && self::m($p->get('intent_session'), 'map_form') === self::MAP_FORM_COMMIT;
        $ctxErr = self::intentV2ContextError($ctx);
        if ($ctxErr !== null) {
            foreach (array_merge(['schema', 'intent_session'], $present ? ['accumulators'] : [], $committed ? ['map'] : []) as $name) {
                $checks[] = ['name' => $name, 'ok' => false, 'reason' => "malformed v2 context: $ctxErr"];
            }
            return ['checks' => $checks, 'env' => null, 'schema' => null];
        }
        $clockOk = abs($now) <= self::MAX_SAFE;
        $run = function (string $name, callable $f) use (&$checks, $clockOk): array {
            try {
                $s = $clockOk ? $f() : self::bad('the verifier clock is not a safe integer (fail closed)');
            } catch (\Throwable $e) {
                $s = self::bad("$name error (fail closed): " . $e->getMessage());
            }
            $checks[] = $s['ok'] ? ['name' => $name, 'ok' => true] : ['name' => $name, 'ok' => false, 'reason' => $s['reason']];
            return $s;
        };
        if ($present || self::cg($ctx, 'policy', 'schema', 'closed_world') === true) {
            $run('schema', function () use ($p, $ctx, &$env, &$schemaOut): array {
                $s = self::schemaStep($p, $ctx);
                if ($s['ok']) {
                    $schemaOut = $s['doc'];
                    $env = Obj::of(['canon' => self::canonProjection($s['doc'], self::jsString(self::cg($p, 'action', 'verb')), $ctx->get('params'))]);
                }
                return $s;
            });
        }
        if ($present || self::cg($ctx, 'policy', 'session', 'require') === true) {
            $run('intent_session', fn() => self::sessionStep($p, $grant, $ctx, $now));
        }
        $mapActive = $committed || self::cg($ctx, 'policy', 'map', 'require') === true;
        $params = self::m($ctx, 'params');
        $action = Obj::of([
            'verb' => self::jsString(self::cg($p, 'action', 'verb')),
            'resource' => self::jsString(self::cg($p, 'action', 'resource')),
            'params' => $params instanceof Obj ? $params : new Obj(),
        ]);
        $layers = self::m($ctx, 'layers');
        if ($present && !self::isU($layers)) {
            $run('layers', function () use ($layers, $action, &$env): array {
                $e = new Obj();
                if ($env !== null && $env->has('canon')) {
                    $e->set('canon', $env->get('canon'));
                }
                $d = Predicates::decideLayerCeilings($layers, Obj::of(['action' => $action, 'env' => $e]));
                return ($d['status'] ?? null) === 'pass' ? ['ok' => true] : self::bad((string)($d['reason'] ?? 'rejected'));
            });
        }
        if ($present) {
            $run('accumulators', function () use ($p, $ctx, $now, &$env): array {
                $s = self::accStep($p, $ctx, $now);
                if ($s['ok']) {
                    $env ??= new Obj();
                    $env->set('acc', $s['acc']);
                    $env->set('mon', $s['mon']);
                }
                return $s;
            });
            if ($mapActive) {
                $run('map', fn() => self::mapStep($p, $ctx));
            }
            $is = $p->get('intent_session');
            $wb = null;
            try {
                $in = Obj::of(['now' => new Num((string)$now), 'aud' => self::jsString(self::m($p, 'aud')), 'session' => self::m($is, 'session'),
                    'action' => $action, 'intent_session' => $is]);
                $artifacts = self::cg($ctx, 'wb', 'artifacts');
                if (!self::isU($artifacts)) {
                    $in->set('artifacts', $artifacts);
                }
                $in->set('policy', self::dflt(self::cg($ctx, 'wb', 'policy'), new Obj()));
                $wb = IntentWb::decideIntentWb($in);
            } catch (\Throwable $e) {
                $checks[] = ['name' => 'facts', 'ok' => false, 'reason' => 'W-B error (fail closed): ' . $e->getMessage()];
            }
            if (is_array($wb)) {
                $why = isset($wb['reason']) && is_string($wb['reason']) ? $wb['reason'] : null;
                foreach (['facts', 'provenance', 'classes'] as $name) {
                    $c = $wb['checks'][$name] ?? null;
                    if ($c === null) {
                        continue;
                    }
                    $checks[] = $c === 'pass' ? ['name' => $name, 'ok' => true] : ['name' => $name, 'ok' => false,
                        'reason' => $c === 'question' ? 'intent_required: ' . ($why ?? 'a question is required') : ($why ?? 'rejected')];
                }
                if (isset($wb['single_source']) && is_array($wb['single_source'])) {
                    $singleSource = array_values($wb['single_source']);
                }
                if (($wb['outcome'] ?? null) !== 'deny') {
                    foreach (['world', 'prov', 'class'] as $k) {
                        if (isset($wb['env'][$k])) {
                            $env ??= new Obj();
                            $env->set($k, $wb['env'][$k]);
                        }
                    }
                }
            }
        } elseif ($mapActive) {
            $run('map', fn() => self::mapStep($p, $ctx));
        }
        $legacy = false;
        self::modelRules($p, $grant, $ctx, $env, $schemaOut, $singleSource, $action, $run, $legacy);
        $out = ['checks' => $checks, 'env' => $env, 'schema' => $schemaOut];
        if ($legacy) {
            $out['legacy_model_polarity'] = true;
        }
        return $out;
    }

    /** The predicate lists a model-derived path could widen: the grant's allow-list and the ceilings (V5 layers). */
    private static function allowSidePredicates(?Obj $env, mixed $ctx): array
    {
        $lists = [$env?->get('predicates')];
        $layers = self::m($ctx, 'layers');
        if ($layers instanceof Obj) {
            foreach (['org', 'site', 'std'] as $k) {
                $lists[] = self::m($layers->get($k), 'predicates');
            }
        }
        return $lists;
    }

    /**
     * Rules 20 and 21, evaluated last (after `classes`, so the verifier-computed env is complete); both read the signed
     * ENVELOPE of the stored grant. `units` (20): reported iff `envelope.units` is present. `tighten` (21): reported iff
     * `envelope.tighten` or a `model_polarity` (envelope or policy) is present, or a grant-side `where` reads a
     * model-derived env path (so that case is refused, never silently skipped). A PCActn with none of these verifies
     * exactly as a verifier without the two rules.
     *
     * @param list<string> $single
     */
    private static function modelRules(Obj $p, mixed $grant, mixed $ctx, ?Obj $env, ?Obj $schemaDoc, array $single, Obj $action,
                                       callable $run, bool &$legacy): void
    {
        $envelope = Authorize::readEnvelope($grant);
        $preds = self::allowSidePredicates($envelope, $ctx);
        if ($envelope !== null && $envelope->has('units')) {
            $run('units', function () use ($p, $ctx, $envelope, $schemaDoc, $preds, $action): array {
                if ($schemaDoc !== null) {
                    $doc = $schemaDoc;
                } else {
                    $s = self::schemaStep($p, $ctx);
                    if (!$s['ok']) {
                        return $s;
                    }
                    $doc = $s['doc'];
                }
                $verb = $action->get('verb');
                $decl = null;
                $verbs = $doc->get('verbs');
                foreach (self::isList($verbs) ? $verbs : [] as $v) {
                    if ($v instanceof Obj && $v->get('verb') === $verb) {
                        $decl = $v;
                        break;
                    }
                }
                $in = Obj::of(['units' => $envelope->get('units'), 'verb' => $verb, 'predicates' => $preds]);
                if ($doc->has('units')) {
                    $in->set('schema_units', $doc->get('units'));
                }
                if ($decl !== null && $decl->has('params')) {
                    $in->set('verb_params', $decl->get('params'));
                }
                $d = Decision::decideUnits($in);
                return $d['ok'] ? ['ok' => true] : self::bad((string)$d['reason']);
            });
        }
        $polPolicy = self::cg($ctx, 'policy', 'model_polarity');
        $polarity = self::undef();
        if ($polPolicy !== 'strict') {
            $polarity = (!self::isU($polPolicy) && $polPolicy !== null) ? $polPolicy : self::m($envelope, 'model_polarity');
        }
        if (($envelope !== null && $envelope->has('tighten')) || !self::isU($polarity) || !self::isU($polPolicy)
            || count(Decision::modelPathsRead($preds, $single)) > 0) {
            $run('tighten', function () use ($envelope, $preds, $polarity, $single, $ctx, $env, $action, &$legacy): array {
                $merged = new Obj();
                $hostEnv = self::m($ctx, 'env');
                foreach ($hostEnv instanceof Obj ? $hostEnv->keys() : [] as $k) {
                    $merged->set($k, $hostEnv->get($k));
                }
                foreach ($env !== null ? $env->keys() : [] as $k) {
                    $merged->set($k, $env->get($k));
                }
                $in = Obj::of(['predicates' => $preds, 'single_source' => $single,
                    'context' => Obj::of(['action' => $action, 'env' => $merged])]);
                if ($envelope !== null && $envelope->has('tighten')) {
                    $in->set('tighten', $envelope->get('tighten'));
                }
                if (!self::isU($polarity)) {
                    $in->set('polarity', $polarity);
                }
                $r = Decision::decideTighten($in);
                if ($r['legacy']) {
                    $legacy = true;
                }
                return $r['outcome'] === 'ok' ? ['ok' => true] : self::bad($r['reason'] ?? 'refused');
            });
        }
    }

    /**
     * Rule 19 (`map`, V15 Z0): reported iff `intent_session.map_form` is "commit" or `policy.map.require` is true; after
     * `accumulators` (independent of the earlier checks) and before W-B.
     */
    private static function mapStep(Obj $p, mixed $ctx): array
    {
        if (self::cg($p, 'intent_session', 'map_form') !== self::MAP_FORM_COMMIT) {
            return self::bad('this verifier requires a committed map (intent_session.map_form "commit")');
        }
        $intent = self::m($p, 'intent');
        if (self::isU($intent)) {
            return self::bad('a committed map needs the envelope.intent binding');
        }
        $disclosure = self::cg($ctx, 'map', 'disclosure');
        if (self::isU($disclosure)) {
            return self::bad('no disclosure of the committed map was presented');
        }
        $eps = self::cg($ctx, 'policy', 'map', 'max_residual_risk_ppm');
        $d = self::decideMapDisclosure(self::m($intent, 'map_digest'), self::dflt(self::m($p, 'action'), new Obj()), self::m($ctx, 'params'),
            $disclosure, self::isU($eps) ? null : $eps);
        return $d['ok'] ? ['ok' => true] : self::bad($d['reason']);
    }

    /**
     * One Intent Layer v2 conformance primitive (`primitives.<kind>[].input`), reported in exactly the shape of its
     * `expect` (reasons are never part of it): the shared entry of the native runners and the diff-fuzz driver.
     * Returns [result Obj, reason or null], or null for an unknown kind. Kinds: intent_schema, intent_revocation,
     * intent_world, intent_provenance, intent_classifier, intent_wb_active, intent_read_purpose, intent_map_commit,
     * intent_map. Throws only where the reference does (intent_map_commit over a malformed leaf list).
     * @return array{0: Obj, 1: ?string}|null
     */
    public static function primitive(string $kind, mixed $input): ?array
    {
        $g = fn(string $k) => self::m($input, $k);
        $out = new Obj();
        switch ($kind) {
            case 'intent_schema':
                $v = self::verifyActionSchema($g('schema'), $g('keys'));
                $out->set('sig', $v['ok']);
                if ($v['ok']) {
                    $out->set('digest', self::actionSchemaDigest($g('schema')));
                }
                $c = self::conformAction($g('schema'), $g('verb'), $g('params'));
                $conf = Obj::of(['ok' => $c['ok']]);
                if (!$c['ok']) {
                    $conf->set('code', $c['code']);
                    if (isset($c['path'])) {
                        $conf->set('path', $c['path']);
                    }
                }
                $out->set('conform', $conf);
                return [$out, $v['reason'] ?? ($c['reason'] ?? null)];
            case 'intent_revocation':
                // the evidence is the input WITHOUT the check parameters (so an extra input member makes it malformed)
                $ev = $input instanceof Obj ? $input->without('session', 'scope', 'authority', 'ids', 'now', 'max_age_ms', 'last') : $input;
                $c = ['session' => $g('session'), 'authority' => $g('authority'), 'ids' => $g('ids'), 'now' => $g('now'),
                    'maxAgeMs' => $g('max_age_ms')];
                // `scope` is stripped from the evidence but never passed: the primitive checks against the default scope
                // "pca-intent-session:" + session (conformance README; the reference generator omits it too)
                if (!self::isU($g('last'))) {
                    $c['last'] = $g('last');
                }
                if (!($input instanceof Obj)) {
                    $out->set('ok', false);
                    return [$out, 'session revocation check error (fail closed)'];
                }
                $r = self::checkSessionRevocation($ev, $c);
                $out->set('ok', $r['ok']);
                return [$out, $r['reason'] ?? null];
            case 'intent_world':
                $r = IntentWb::decideIntentWorld($input);
                $out->set('ok', $r['ok']);
                if ($r['ok']) {
                    $out->set('world', $r['world']);
                    $out->set('single_source', $r['single_source']);
                }
                return [$out, $r['reason'] ?? null];
            case 'intent_provenance':
                $r = IntentWb::decideParamProvenance($input);
                $out->set('outcome', $r['outcome']);
                if ($r['outcome'] !== 'deny') {
                    $out->set('labels', $r['labels']);
                    $out->set('classes', $r['classes']);
                    if ($r['outcome'] === 'question') {
                        $out->set('friction', $r['friction'] ?? null);
                    }
                }
                return [$out, $r['reason'] ?? null];
            case 'intent_classifier':
                $r = IntentWb::decideClassifierDimensions($input);
                $out->set('ok', $r['ok']);
                if ($r['ok']) {
                    $out->set('classes', $r['classes']);
                }
                return [$out, $r['reason'] ?? null];
            case 'intent_wb_active':
                $r = IntentWb::intentWbActive($input);
                foreach (['facts', 'provenance', 'classes'] as $k) {
                    $out->set($k, $r[$k]);
                }
                return [$out, null];
            case 'intent_read_purpose':
                $r = IntentWb::decideReadPurpose($input);
                foreach (['outcome', 'minimise', 'uncovered'] as $k) {
                    $out->set($k, $r[$k]);
                }
                return [$out, null];
            case 'intent_map_commit':
                $out->set('map_commit', self::mapCommitOfLeaves($g('leaves')));
                return [$out, null];
            case 'intent_map':
                $eps = $g('max_residual_risk_ppm');
                $r = self::decideMapDisclosure($g('map_commit'), $g('action'), $g('params'), $g('disclosure'), self::isU($eps) ? null : $eps);
                $out->set('ok', $r['ok']);
                if ($r['ok']) {
                    $out->set('cell', array_map(fn(int $x) => new Num((string)$x), $r['cell']));
                    $out->set('p_ppm', new Num((string)$r['p_ppm']));
                }
                return [$out, $r['reason'] ?? null];
            default:
                return null;
        }
    }

    /** True iff any v2 check would be reported (the PCActn carries `intent_session`, a v2 policy is active, or a present context is malformed and the checks fail closed). */
    public static function intentV2Active(mixed $p, mixed $ctx): bool
    {
        return ($p instanceof Obj && $p->has('intent_session'))
            || self::intentV2ContextError($ctx) !== null
            || self::cg($ctx, 'policy', 'schema', 'closed_world') === true
            || self::cg($ctx, 'policy', 'session', 'require') === true
            || self::cg($ctx, 'policy', 'map', 'require') === true;
    }
}
