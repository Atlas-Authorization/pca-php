<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';

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
    public const UNIT_ID_RE = '/\A[a-z0-9_]+(?:\.[a-z0-9_]+)*\z/';
    public const ACC_ID_RE = '/\A[A-Za-z0-9_]{1,64}\z/';
    public const KID_RE = '/\A[A-Za-z0-9_.:-]{1,64}\z/';
    private const DATE_RE = '/\A([0-9]{4})-([0-9]{2})-([0-9]{2})\z/';

    public const PARAM_TYPES = ['string', 'integer', 'boolean', 'date', 'set', 'array'];
    public const SENSITIVITIES = ['free', 'material', 'critical'];
    public const SCHEMA_REVERSIBILITY = ['reversible', 'rate_limited', 'irreversible'];
    public const ACC_AGGS = ['sum', 'count', 'distinct', 'max'];
    public const MONITOR_KINDS = ['requires_prior', 'precedes', 'never', 'always', 'responds_within'];

    private const DOC_KEYS = ['v', 'kind', 'site', 'aud', 'version', 'units', 'state', 'verbs', 'sig'];
    private const VERB_KEYS = ['verb', 'kind', 'params', 'reversibility', 'reversibility_by', 'mcp', 'openapi', 'harm', 'world',
        'effects', 'returns', 'description'];
    private const PARAM_KEYS = ['type', 'semantic', 'sensitivity', 'required', 'values', 'min', 'max', 'unit', 'max_len', 'items',
        'min_items', 'max_items', 'default', 'principal_neutral_default', 'accumulates_into', 'issued_by_site', 'description'];
    private const SIG_KEYS = ['alg', 'kid', 'value', 'pq_value'];
    private const ROOT_KEYS = ['v', 'kind', 'session', 'principals', 'intent_ref', 'schema', 'layers', 'accumulators', 'monitors',
        'question_uri', 'revocation', 'flows', 'expires_at', 'signer', 'alg', 'pq_pk', 'sig', 'pq_sig'];
    private const RECEIPT_KEYS = ['v', 'kind', 'session', 'acc', 'seq', 'pre', 'delta', 'post', 'pcactn_digest', 'aud', 'issued_at',
        'expires_at', 'kid', 'ledger', 'signer', 'alg', 'pq_pk', 'sig', 'pq_sig'];
    private const MAX_SAFE = 9007199254740991;

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

    // ==== rule 13: the PCActn member, the grant caveat, the session root ================================================

    private static function digestList(mixed $v, string $name, int $max): ?string
    {
        if (!self::isList($v) || count($v) > $max) {
            return "'intent_session.$name' must be an array of at most $max digests";
        }
        foreach ($v as $x) {
            if (!self::b32($x)) {
                return "'intent_session.$name' entries must be canonical base64url (32 bytes)";
            }
        }
        if (!self::distinct($v)) {
            return "'intent_session.$name' entries must be distinct";
        }
        return null;
    }

    /** Wire validation of the signed `intent_session` member (validateIntentSessionWire). Null = well-formed. */
    public static function validateIntentSessionWire(mixed $v): ?string
    {
        if (!($v instanceof Obj)) {
            return "'intent_session' must be an object";
        }
        foreach (self::jsKeys($v) as $k) {
            if (!in_array($k, self::INTENT_SESSION_FIELDS, true)) {
                return "unknown field 'intent_session.$k'";
            }
        }
        foreach (['session', 'root', 'seq', 'schema'] as $k) {
            if (!$v->has($k)) {
                return "missing field 'intent_session.$k'";
            }
        }
        foreach (['session', 'root', 'schema'] as $k) {
            if (!self::b32($v->get($k))) {
                return "'intent_session.$k' is not canonical base64url (32 bytes)";
            }
        }
        $seq = $v->get('seq');
        if (!self::isNonNeg($seq) || self::f($seq) > self::MAX_SESSION_SEQ) {
            return "'intent_session.seq' must be a safe integer in [0, 2147483647]";
        }
        if ($v->has('acc')) {
            $acc = $v->get('acc');
            if (!self::isList($acc) || count($acc) > self::MAX_IS_ACC) {
                return "'intent_session.acc' must be an array of at most " . self::MAX_IS_ACC . ' entries';
            }
            $ids = [];
            foreach ($acc as $i => $a) {
                if (!($a instanceof Obj)) {
                    return "'intent_session.acc[$i]' must be an object";
                }
                foreach (self::jsKeys($a) as $k) {
                    if (!in_array($k, ['id', 'post', 'receipt'], true)) {
                        return "unknown field 'intent_session.acc[$i].$k'";
                    }
                }
                $id = self::m($a, 'id');
                if (!is_string($id) || preg_match(self::ACC_ID_RE, $id) !== 1) {
                    return "'intent_session.acc[$i].id' must match [A-Za-z0-9_]{1,64}";
                }
                if (isset($ids['k' . $id])) {
                    return "'intent_session.acc' ids must be distinct";
                }
                $ids['k' . $id] = true;
                if (!self::isNonNeg(self::m($a, 'post'))) {
                    return "'intent_session.acc[$i].post' must be a non-negative safe integer";
                }
                if ($a->has('receipt') && !self::b32($a->get('receipt'))) {
                    return "'intent_session.acc[$i].receipt' is not canonical base64url (32 bytes)";
                }
            }
        }
        if ($v->has('facts') && ($e = self::digestList($v->get('facts'), 'facts', self::MAX_IS_FACTS)) !== null) {
            return $e;
        }
        if ($v->has('offer_set') && !self::b32($v->get('offer_set'))) {
            return "'intent_session.offer_set' is not canonical base64url (32 bytes)";
        }
        if ($v->has('prov')) {
            $prov = $v->get('prov');
            if (!($prov instanceof Obj) || count($prov->keys()) > self::MAX_IS_PROV_PATHS) {
                return "'intent_session.prov' must be an object of at most " . self::MAX_IS_PROV_PATHS . ' entries';
            }
            foreach (self::jsKeys($prov) as $path) {
                if (preg_match(self::PARAM_PATH_RE, $path) !== 1) {
                    return "'intent_session.prov' key '$path' is not action.params.<name>";
                }
                $refs = $prov->get($path);
                $ok = self::isList($refs) && count($refs) > 0 && count($refs) <= self::MAX_IS_PROV_REFS;
                foreach ($ok ? $refs : [] as $r) {
                    if (!self::isStr($r, self::MAX_IS_STRING_BYTES)) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok) {
                    return "'intent_session.prov.$path' must be 1.." . self::MAX_IS_PROV_REFS . ' non-empty strings of at most '
                        . self::MAX_IS_STRING_BYTES . ' UTF-8 bytes';
                }
            }
        }
        if ($v->has('classes') && ($e = self::digestList($v->get('classes'), 'classes', self::MAX_IS_CLASSES)) !== null) {
            return $e;
        }
        if ($v->has('labels') && ($e = self::digestList($v->get('labels'), 'labels', self::MAX_IS_LABELS)) !== null) {
            return $e;
        }
        if ($v->has('map_form') && $v->get('map_form') !== self::MAP_FORM_COMMIT) {
            return "'intent_session.map_form' must be \"commit\" when present";
        }
        return null;
    }

    /** Shape of an `intent_session` grant caveat: exactly {type, session, seq, root, prev?}, prev present iff seq > 0. */
    public static function intentSessionCaveatError(mixed $c): ?string
    {
        if (!($c instanceof Obj) || self::m($c, 'type') !== self::INTENT_SESSION_CAVEAT) {
            return 'not an intent_session caveat';
        }
        foreach (self::jsKeys($c) as $k) {
            if (!in_array($k, ['type', 'session', 'seq', 'root', 'prev'], true)) {
                return "intent_session caveat: unknown member '$k'";
            }
        }
        if (!self::b32(self::m($c, 'session')) || !self::b32(self::m($c, 'root'))) {
            return 'intent_session caveat: session and root must be canonical base64url (32 bytes)';
        }
        $seq = self::m($c, 'seq');
        if (!self::isNonNeg($seq) || self::f($seq) > self::MAX_SESSION_SEQ) {
            return 'intent_session caveat: seq must be a safe integer in [0, 2147483647]';
        }
        if (self::eq($seq, 0) === $c->has('prev')) {
            return 'intent_session caveat: prev is present exactly when seq > 0';
        }
        if ($c->has('prev') && !self::b32($c->get('prev'))) {
            return 'intent_session caveat: prev must be canonical base64url (32 bytes)';
        }
        return null;
    }

    /** The FIRST caveat of `$grant` whose type is `intent_session` (as is), else absent. */
    public static function grantSessionCaveat(mixed $grant): mixed
    {
        $cv = self::m($grant, 'caveats');
        foreach (self::isList($cv) ? $cv : [] as $c) {
            if ($c instanceof Obj && self::m($c, 'type') === self::INTENT_SESSION_CAVEAT) {
                return $c;
            }
        }
        return self::undef();
    }

    private static function predicateShapeOk(mixed $p): bool
    {
        $verb = self::m($p, 'verb');
        if (!($p instanceof Obj)) {
            return false;
        }
        if (is_string($verb)) {
            return true;
        }
        return self::isList($verb) && count($verb) > 0 && count(array_filter($verb, 'is_string')) === count($verb);
    }

    /** Accumulator declaration (rule 15). Null = well-formed. */
    public static function accumulatorDeclError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'accumulator must be an object';
        }
        foreach (self::jsKeys($a) as $k) {
            if (!in_array($k, ['id', 'agg', 'val', 'unit', 'sel', 'win', 'key', 'domain_max', 'cap', 'holder'], true)) {
                return "accumulator: unknown member '$k'";
            }
        }
        $id = self::m($a, 'id');
        if (!is_string($id) || preg_match(self::ACC_ID_RE, $id) !== 1 || in_array($id, self::RESERVED_NAMES, true)) {
            return 'accumulator id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
        }
        $at = "accumulator '$id'";
        $agg = self::m($a, 'agg');
        if (!is_string($agg) || !in_array($agg, self::ACC_AGGS, true)) {
            return "$at: unknown agg";
        }
        $val = self::m($a, 'val');
        if (!self::isU($val) && (!is_string($val) || preg_match(self::PARAM_PATH_RE, $val) !== 1)) {
            return "$at: val must be action.params.<name>";
        }
        $unit = self::m($a, 'unit');
        if (!self::isU($unit) && (!is_string($unit) || self::u16len($unit) > 64 || preg_match(self::UNIT_ID_RE, $unit) !== 1)) {
            return "$at: unit must be a unit id";
        }
        $sel = self::m($a, 'sel');
        if (!($sel instanceof Obj)) {
            return "$at: sel must be an object";
        }
        foreach (self::jsKeys($sel) as $k) {
            if (!in_array($k, ['verbs', 'accumulates_into', 'event'], true)) {
                return "$at: sel has unknown member '$k'";
            }
        }
        $verbs = self::m($sel, 'verbs');
        if (!self::isU($verbs)) {
            $ok = self::isList($verbs) && count($verbs) > 0 && count($verbs) <= 64;
            foreach ($ok ? $verbs : [] as $v) {
                if (!is_string($v) || $v === '') {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return "$at: sel.verbs must be 1..64 verb names";
            }
        }
        $sai = self::m($sel, 'accumulates_into');
        if (!self::isU($sai) && (!is_string($sai) || preg_match(self::UNIT_ID_RE, $sai) !== 1)) {
            return "$at: sel.accumulates_into must be a unit id";
        }
        $event = self::m($sel, 'event');
        if (!self::isU($event) && !(is_string($event) && in_array($event, ['intent_required', 'question', 'clarification'], true))) {
            return "$at: unknown sel.event";
        }
        $actionSel = !self::isU($verbs) || !self::isU($sai);
        if ($actionSel === !self::isU($event)) {
            return "$at: sel names actions (verbs / accumulates_into) or a wallet event, exactly one kind";
        }
        $w = self::m($a, 'win');
        if (!($w instanceof Obj)) {
            return "$at: win must be an object";
        }
        $wk = self::m($w, 'kind');
        if ($wk === 'task') {
            if (count($w->keys()) !== 1) {
                return "$at: win {kind: task} has no other member";
            }
        } elseif ($wk === 'sliding') {
            $ms = self::m($w, 'ms');
            if (self::sortedJoin($w) !== 'kind,ms' || !(self::isInt($ms) && self::f($ms) > 0)) {
                return "$at: win sliding needs a positive ms";
            }
        } elseif ($wk === 'period') {
            $ms = self::m($w, 'ms');
            if (self::sortedJoin($w) !== 'kind,ms,t0' || !(self::isInt($ms) && self::f($ms) > 0) || !self::isNonNeg(self::m($w, 't0'))) {
                return "$at: win period needs a positive ms and t0 >= 0";
            }
        } else {
            return "$at: unknown win kind";
        }
        $key = self::m($a, 'key');
        if ($key !== null && (!is_string($key) || preg_match(self::PARAM_PATH_RE, $key) !== 1)) {
            return "$at: key must be null or action.params.<name>";
        }
        if ($a->has('domain_max') && !self::isNonNeg($a->get('domain_max'))) {
            return "$at: domain_max must be a non-negative safe integer";
        }
        if ($a->has('cap') && !self::isNonNeg($a->get('cap'))) {
            return "$at: cap must be a non-negative safe integer";
        }
        $h = self::m($a, 'holder');
        if (!($h instanceof Obj)) {
            return "$at: holder must be an object";
        }
        $hk = self::m($h, 'kind');
        if ($hk === 'site_local' || $hk === 'wallet') {
            if (count($h->keys()) !== 1) {
                return "$at: holder $hk has no other member";
            }
        } elseif ($hk === 'sequenced') {
            foreach (self::jsKeys($h) as $k) {
                if (!in_array($k, ['kind', 'uri', 'root', 'root_alg', 'root_pq_pk', 'keys_uri'], true)) {
                    return "$at: holder sequenced has unknown member '$k'";
                }
            }
            $uri = self::m($h, 'uri');
            if (!is_string($uri) || $uri === '') {
                return "$at: holder sequenced needs a uri";
            }
            if (Pca::unb64u(self::m($h, 'root'), 32) === null) {
                return "$at: holder.root is not canonical base64url (32 bytes)";
            }
            if (($se = self::suiteError(self::m($h, 'root_alg'))) !== null) {
                return "$at: holder.root_alg: $se";
            }
            if ($h->has('root_pq_pk') && Pca::unb64u($h->get('root_pq_pk')) === null) {
                return "$at: holder.root_pq_pk is not canonical base64url";
            }
            if ($h->has('keys_uri') && (!is_string($h->get('keys_uri')) || $h->get('keys_uri') === '')) {
                return "$at: holder.keys_uri must be a non-empty string";
            }
        } else {
            return "$at: unknown holder kind";
        }
        $wallet = $hk === 'wallet';
        if ($wallet !== !self::isU($event)) {
            return "$at: wallet events are wallet-held and only wallet events are";
        }
        if (!$wallet) {
            if ($agg !== 'count' && self::isU($val) && self::isU($sai)) {
                return "$at: $agg needs val (or sel.accumulates_into for a sum)";
            }
            if ($agg !== 'sum' && $agg !== 'count' && self::isU($val)) {
                return "$at: $agg needs val";
            }
            if ($agg === 'count' && !self::isU($val)) {
                return "$at: count takes no val";
            }
        }
        return null;
    }

    /** Monitor declaration (rule 15). Null = well-formed. */
    public static function monitorDeclError(mixed $m): ?string
    {
        if (!($m instanceof Obj)) {
            return 'monitor must be an object';
        }
        foreach (self::jsKeys($m) as $k) {
            if (!in_array($k, ['id', 'kind', 'p', 'q', 'status', 'within'], true)) {
                return "monitor: unknown member '$k'";
            }
        }
        $id = self::m($m, 'id');
        if (!is_string($id) || preg_match(self::ACC_ID_RE, $id) !== 1 || in_array($id, self::RESERVED_NAMES, true)) {
            return 'monitor id must match [A-Za-z0-9_]{1,64} and not be __proto__ / constructor / prototype';
        }
        $at = "monitor '$id'";
        $kind = self::m($m, 'kind');
        if (!is_string($kind) || !in_array($kind, self::MONITOR_KINDS, true)) {
            return "$at: unknown kind";
        }
        if (!self::predicateShapeOk(self::m($m, 'p'))) {
            return "$at: p must be a predicate";
        }
        $needsQ = $kind === 'requires_prior' || $kind === 'precedes' || $kind === 'responds_within';
        if ($needsQ !== $m->has('q')) {
            return "$at: q is required exactly for requires_prior / precedes / responds_within";
        }
        if ($m->has('q') && !self::predicateShapeOk($m->get('q'))) {
            return "$at: q must be a predicate";
        }
        if ($m->has('status') && $m->get('status') !== 'admitted' && $m->get('status') !== 'committed') {
            return "$at: status must be admitted or committed";
        }
        if (($kind === 'responds_within') !== $m->has('within')) {
            return "$at: within is required exactly for responds_within";
        }
        $within = self::m($m, 'within');
        if (!self::isU($within) && !(self::isInt($within) && self::f($within) >= 1 && self::f($within) <= self::MAX_MONITOR_WITHIN)) {
            return "$at: within must be an integer in 1.." . self::MAX_MONITOR_WITHIN;
        }
        return null;
    }

    /** The state set Q of a monitor. @return list<string> */
    public static function monitorStates(mixed $m): array
    {
        $kind = self::m($m, 'kind');
        // strict, like the reference: a non-string `kind` must not loosely match a case (true == 'requires_prior')
        switch (is_string($kind) ? $kind : '') {
            case 'requires_prior':
            case 'precedes':
                return ['unmet', 'met'];
            case 'never':
                return ['clean', 'seen'];
            case 'always':
                return ['ok', 'broken'];
            case 'responds_within':
                $w = self::m($m, 'within');
                $out = ['idle'];
                for ($i = 1, $n = self::isInt($w) ? self::iv($w) : 0; $i <= $n; $i++) {
                    $out[] = "pending:$i";
                }
                $out[] = 'missed';
                return $out;
            default:
                return [];
        }
    }

    /** sessionRootShapeError (signed). Null = well-formed. Never throws. */
    public static function sessionRootShapeError(mixed $s): ?string
    {
        try {
            if (!($s instanceof Obj)) {
                return 'session root is not an object';
            }
            foreach (self::jsKeys($s) as $k) {
                if (!in_array($k, self::ROOT_KEYS, true)) {
                    return "session root: unknown member '$k'";
                }
            }
            if (!self::eq(self::m($s, 'v'), 1) || self::m($s, 'kind') !== self::INTENT_SESSION_KIND) {
                return 'not a pca-intent-session v1';
            }
            if (!self::b32(self::m($s, 'session')) || !self::b32(self::m($s, 'intent_ref'))) {
                return 'session and intent_ref must be canonical base64url (32 bytes)';
            }
            $principals = self::m($s, 'principals');
            if (!self::isList($principals) || count($principals) === 0 || count($principals) > self::MAX_SESSION_PRINCIPALS) {
                return 'principals must be 1..' . self::MAX_SESSION_PRINCIPALS . ' keys';
            }
            $keys = [];
            foreach ($principals as $p) {
                $ok = $p instanceof Obj && self::b32(self::m($p, 'key'));
                foreach ($ok ? self::jsKeys($p) : [] as $k) {
                    if (!in_array($k, ['key', 'alg', 'pq_pk'], true)) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok) {
                    return 'principals entries are {key, alg?, pq_pk?} with a 32-byte key';
                }
                if (($se = self::suiteKnownError(self::m($p, 'alg'))) !== null) {
                    return "principal alg: $se";
                }
                if ($p->has('pq_pk') && Pca::unb64u($p->get('pq_pk')) === null) {
                    return 'principal pq_pk is not canonical base64url';
                }
                if (isset($keys['k' . $p->get('key')])) {
                    return 'principal keys must be distinct';
                }
                $keys['k' . $p->get('key')] = true;
            }
            $schema = self::m($s, 'schema');
            if (!($schema instanceof Obj) || self::sortedJoin($schema) !== 'aud,digest' || !is_string(self::m($schema, 'aud'))
                || $schema->get('aud') === '' || !self::b32(self::m($schema, 'digest'))) {
                return 'schema must be {aud, digest}';
            }
            $L = self::m($s, 'layers');
            if (!($L instanceof Obj)) {
                return 'layers must be an object';
            }
            foreach (self::jsKeys($L) as $k) {
                if (!in_array($k, ['org', 'std', 'task'], true)) {
                    return "layers: unknown member '$k'";
                }
            }
            $task = self::m($L, 'task');
            if (!($task instanceof Obj) || implode(',', self::jsKeys($task)) !== 'map_digest' || !self::b32(self::m($task, 'map_digest'))) {
                return 'layers.task must be {map_digest}';
            }
            if ($L->has('org') && (!($L->get('org') instanceof Obj) || !self::b32(self::m($L->get('org'), 'digest')))) {
                return 'layers.org must be an object with a 32-byte digest (absent = no org layer; null is malformed)';
            }
            if ($L->has('std')) {
                $d = $L->get('std');
                $prof = self::m($d, 'profile');
                $ver = self::m($d, 'version');
                if (!($d instanceof Obj) || self::sortedJoin($d) !== 'digest,profile,version' || !is_string($prof) || $prof === ''
                    || strlen($prof) > 128 || !(self::isInt($ver) && self::f($ver) >= 1) || !self::b32(self::m($d, 'digest'))) {
                    return 'layers.std must be {profile, version >= 1, digest} (absent = no standing profile; null is malformed)';
                }
            }
            $accs = self::m($s, 'accumulators');
            if (!self::isList($accs) || count($accs) > self::MAX_SESSION_ACCUMULATORS) {
                return 'accumulators must be an array of at most ' . self::MAX_SESSION_ACCUMULATORS;
            }
            $ids = [];
            foreach ($accs as $a) {
                if (($e = self::accumulatorDeclError($a)) !== null) {
                    return $e;
                }
                if (isset($ids['k' . $a->get('id')])) {
                    return 'accumulator and monitor ids must be distinct';
                }
                $ids['k' . $a->get('id')] = true;
            }
            $mons = self::m($s, 'monitors');
            if (!self::isList($mons) || count($mons) > self::MAX_SESSION_MONITORS) {
                return 'monitors must be an array of at most ' . self::MAX_SESSION_MONITORS;
            }
            $mids = [];
            foreach ($mons as $mo) {
                if (($e = self::monitorDeclError($mo)) !== null) {
                    return $e;
                }
                if (isset($mids['k' . $mo->get('id')])) {
                    return 'monitor ids must be distinct';
                }
                $mids['k' . $mo->get('id')] = true;
            }
            $qu = self::m($s, 'question_uri');
            if (!is_string($qu) || $qu === '' || strlen($qu) > 2048) {
                return 'question_uri must be a non-empty string';
            }
            if ($s->has('revocation')) {
                $r = $s->get('revocation');
                $ok = $r instanceof Obj;
                foreach ($ok ? self::jsKeys($r) : [] as $k) {
                    if (!in_array($k, ['epoch_uri', 'max_age_s', 'key', 'pq_pk'], true)) {
                        $ok = false;
                        break;
                    }
                }
                if (!$ok) {
                    return 'revocation must be {epoch_uri, max_age_s, key, pq_pk?}';
                }
                $eu = self::m($r, 'epoch_uri');
                if (!is_string($eu) || $eu === '') {
                    return 'revocation.epoch_uri must be a non-empty string';
                }
                if (!self::isNonNeg(self::m($r, 'max_age_s'))) {
                    return 'revocation.max_age_s must be a non-negative safe integer';
                }
                if (!self::b32(self::m($r, 'key'))) {
                    return 'revocation.key (the dedicated revocation authority) is required: canonical base64url (32 bytes)';
                }
                if (isset($keys['k' . $r->get('key')])) {
                    return 'revocation.key must not be a session principal (a dedicated revocation authority)';
                }
                if ($r->has('pq_pk') && Pca::unb64u($r->get('pq_pk')) === null) {
                    return 'revocation.pq_pk must be canonical base64url';
                }
            }
            if ($s->has('flows') && !($s->get('flows') instanceof Obj)) {
                return 'flows must be an object';
            }
            if (!self::isNonNeg(self::m($s, 'expires_at'))) {
                return 'expires_at must be a non-negative safe integer (epoch ms)';
            }
            $signer = self::m($s, 'signer');
            if (!self::b32($signer)) {
                return 'signer must be canonical base64url (32 bytes)';
            }
            if (!isset($keys['k' . $signer])) {
                return 'signer is not one of the session principals';
            }
            if (($se = self::suiteKnownError(self::m($s, 'alg'))) !== null) {
                return "alg: $se";
            }
            if (self::suiteOf(self::m($s, 'alg')) === 'ed25519' && ($s->has('pq_pk') || $s->has('pq_sig'))) {
                return 'an ed25519 session root must not carry pq_pk / pq_sig';
            }
            if (!is_string(self::m($s, 'sig'))) {
                return 'sig must be a string';
            }
            self::canonicalize(self::sessionRootBody($s));
            return null;
        } catch (\Throwable $e) {
            return 'malformed session root: ' . $e->getMessage();
        }
    }

    private static function sessionRootBody(Obj $s): Obj
    {
        $o = new Obj();
        foreach (['v', 'kind', 'session', 'principals', 'intent_ref', 'schema', 'layers', 'accumulators', 'monitors', 'question_uri'] as $k) {
            $o->set($k, self::m($s, $k));
        }
        foreach (['revocation', 'flows'] as $k) {
            if ($s->has($k)) {
                $o->set($k, $s->get($k));
            }
        }
        $o->set('expires_at', self::m($s, 'expires_at'));
        return $o;
    }

    /**
     * verifySessionRoot: shape, signer listed, suite signature. R3-01 (fail closed): a non-ed25519 root verifies only under
     * the VERIFIER's pin for its signer (`$pins` = context session.pq_pins, an Obj; its own member for the signer must be a
     * string), never under the root's own principals[].pq_pk; the signer's own entry, when it declares a pq_pk, must agree.
     * An ed25519 root never consults the pins. @return array{ok:bool, reason?:string}
     */
    public static function verifySessionRoot(mixed $s, mixed $pins = null): array
    {
        try {
            $bad = self::sessionRootShapeError($s);
            if ($bad !== null) {
                return self::bad($bad);
            }
            /** @var Obj $s */
            $signer = $s->get('signer');
            $p = null;
            foreach ($s->get('principals') as $x) {
                if ($x->get('key') === $signer) {
                    $p = $x;
                    break;
                }
            }
            $body = self::sessionRootBody($s);
            $body->set('signer', $signer);
            $alg = self::m($s, 'alg');
            $pq = self::m($s, 'pq_pk');
            $pin = null;
            if (self::suiteOf($alg) !== 'ed25519') {
                $pin = $pins instanceof Obj && $pins->has($signer) ? $pins->get($signer) : null;
                if (!is_string($pin)) {
                    return self::bad("session root suite '" . self::suiteOf($alg) . "' needs the signer's PQ key pinned by the verifier (pq_pins); the root's own principals entry proves nothing about who signed it");
                }
                if ($pq !== $pin) {
                    return self::bad("session root pq_pk does not match the verifier's pin for the signer");
                }
                if ($p !== null && $p->has('pq_pk') && $p->get('pq_pk') !== $pq) {
                    return self::bad("session root pq_pk does not match the signer's principals entry");
                }
            }
            if (($se = self::suiteError($alg)) !== null) {
                return self::bad("alg: $se");
            }
            $msg = self::INTENT_SESSION_SIG_DOMAIN . self::canonicalize(self::bindSuite($body, $alg, $pq));
            if (!self::verifyPinned($alg, $signer, $pq, $msg, self::m($s, 'sig'), self::m($s, 'pq_sig'),
                $pin !== null ? $signer : null, $pin)) {
                return self::bad('session root signature invalid');
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return self::bad('malformed session root: ' . $e->getMessage());
        }
    }

    /** digest(S): the content address of the whole signed session root. */
    public static function sessionRootDigest(mixed $s): string
    {
        return self::hashCanonical(Obj::of(['d' => self::INTENT_SESSION_REF_DOMAIN, 's' => $s]));
    }

    // ==== rule 15: accumulators, monitors, receipts ===================================================================

    /** ω ∈ sel_ψ (action selectors only): the verb is listed, or the schema's verb entry has a parameter feeding the unit. */
    public static function accSelects(mixed $a, mixed $verb, mixed $schema): bool
    {
        $sel = self::m($a, 'sel');
        if ($sel instanceof Obj && $sel->has('event')) {
            return false;
        }
        $verbs = self::m($sel, 'verbs');
        if (self::isList($verbs) && in_array($verb, $verbs, true)) {
            return true;
        }
        $ai = self::m($sel, 'accumulates_into');
        if (!self::isU($ai) && $schema instanceof Obj) {
            $v = self::schemaVerb($schema, $verb);
            return !self::isU($v) && count(self::accumulationParams($v, $ai)) > 0;
        }
        return false;
    }

    /** The canonical key of a `distinct` value: the strict canonical JSON text of a string or a safe integer. */
    public static function distinctKey(mixed $x): ?string
    {
        if (is_string($x) || self::isInt($x)) {
            try {
                return self::canonicalize($x);
            } catch (\Throwable) {
                return null;
            }
        }
        return null;
    }

    /** val(ω) for a selected action. @return array{ok:bool, val?:int, key?:string, reason?:string} */
    public static function accValueOf(mixed $a, mixed $verb, Obj $params, mixed $schema): array
    {
        $read = fn(string $path) => self::m($params, self::paramName($path));
        $agg = self::m($a, 'agg');
        $val = self::m($a, 'val');
        if ($agg === 'count') {
            return ['ok' => true, 'val' => 1];
        }
        if ($agg === 'distinct') {
            $k = is_string($val) ? self::distinctKey($read($val)) : null;
            return $k === null ? self::bad(self::txt($val) . ' must be a string or a safe integer') : ['ok' => true, 'val' => 1, 'key' => $k];
        }
        if (is_string($val)) {
            $x = $read($val);
            return self::isNonNeg($x) ? ['ok' => true, 'val' => self::iv($x)] : self::bad("$val must be a non-negative safe integer");
        }
        $v = $schema instanceof Obj ? self::schemaVerb($schema, $verb) : self::undef();
        if (self::isU($v)) {
            return self::bad("no schema entry for '" . self::txt($verb) . "' to read accumulates_into");
        }
        $s = 0;
        foreach (self::accumulationParams($v, self::m(self::m($a, 'sel'), 'accumulates_into')) as $p) {
            $x = $read($p);
            if (self::isU($x)) {
                continue;
            }
            if (!self::isNonNeg($x)) {
                return self::bad("$p must be a non-negative safe integer");
            }
            $s += self::iv($x);
            if ($s > self::MAX_SAFE) {
                return self::bad('accumulated value exceeds 2^53-1');
            }
        }
        return ['ok' => true, 'val' => $s];
    }

    /** The pre-state shape of an accumulator group: {sum} / {count} / {max} (safe integers >= 0) or {values} (distinct strings). */
    public static function preStateError(mixed $a, mixed $s): ?string
    {
        if (!($s instanceof Obj)) {
            return 'pre-state must be an object';
        }
        $agg = self::m($a, 'agg');
        $want = $agg === 'sum' ? 'sum' : ($agg === 'count' ? 'count' : ($agg === 'max' ? 'max' : 'values'));
        if (implode(',', self::jsKeys($s)) !== $want) {
            return 'pre-state of a ' . self::txt($agg) . " accumulator is {{$want}}";
        }
        if ($want === 'values') {
            $vs = $s->get('values');
            if (!self::isList($vs) || count(array_filter($vs, 'is_string')) !== count($vs)) {
                return 'pre-state values must be strings';
            }
            if (!self::distinct($vs)) {
                return 'pre-state values must be distinct';
            }
            return null;
        }
        return self::isNonNeg($s->get($want)) ? null : "pre-state $want must be a non-negative safe integer";
    }

    /** The post-action value from a well-formed pre-state (null when it would leave the safe-integer range). */
    public static function combineAcc(mixed $a, Obj $pre, array $v): ?int
    {
        $post = match (self::m($a, 'agg')) {
            'sum' => self::iv($pre->get('sum')) + $v['val'],
            'count' => self::iv($pre->get('count')) + 1,
            'max' => max(self::iv($pre->get('max')), $v['val']),
            default => count($pre->get('values')) + (in_array($v['key'] ?? null, $pre->get('values'), true) ? 0 : 1),
        };
        return abs($post) <= self::MAX_SAFE ? $post : null;
    }

    /** The value of a group this action does NOT feed (post = pre). */
    public static function preValue(mixed $a, Obj $pre): int
    {
        return match (self::m($a, 'agg')) {
            'sum' => self::iv($pre->get('sum')),
            'count' => self::iv($pre->get('count')),
            'max' => self::iv($pre->get('max')),
            default => count($pre->get('values')),
        };
    }

    /** The digest a reservation binds: the PCActn without sig, pq_sig, threshold and intent_session. */
    public static function pcactnReservationDigest(Obj $p): string
    {
        return self::hashCanonical(Obj::of(['d' => self::ACC_RESERVE_DOMAIN, 'b' => $p->without('sig', 'pq_sig', 'threshold', 'intent_session')]));
    }

    public static function accReceiptShapeError(mixed $r): ?string
    {
        if (!($r instanceof Obj)) {
            return 'receipt is not an object';
        }
        foreach (self::jsKeys($r) as $k) {
            if (!in_array($k, self::RECEIPT_KEYS, true)) {
                return "receipt: unknown member '$k'";
            }
        }
        if (!self::eq(self::m($r, 'v'), 1) || self::m($r, 'kind') !== 'pca-acc-receipt') {
            return 'not a pca-acc-receipt v1';
        }
        if (Pca::unb64u(self::m($r, 'session'), 32) === null) {
            return 'receipt.session is not canonical base64url (32 bytes)';
        }
        $acc = self::m($r, 'acc');
        if (!is_string($acc) || preg_match(self::ACC_ID_RE, $acc) !== 1) {
            return 'receipt.acc is not an accumulator id';
        }
        $seq = self::m($r, 'seq');
        if (!(self::isInt($seq) && self::f($seq) >= 1)) {
            return 'receipt.seq must be a safe integer >= 1';
        }
        if (!self::isNonNeg(self::m($r, 'pre')) || !self::isNonNeg(self::m($r, 'delta')) || !self::isNonNeg(self::m($r, 'post'))) {
            return 'receipt pre / delta / post must be non-negative safe integers';
        }
        if (Pca::unb64u(self::m($r, 'pcactn_digest'), 32) === null) {
            return 'receipt.pcactn_digest is not canonical base64url (32 bytes)';
        }
        $aud = self::m($r, 'aud');
        if (!is_string($aud) || $aud === '') {
            return 'receipt.aud must be a non-empty string';
        }
        if (!self::isNonNeg(self::m($r, 'issued_at')) || !self::isNonNeg(self::m($r, 'expires_at'))) {
            return 'receipt.issued_at / expires_at must be non-negative safe integers';
        }
        $life = self::iv($r->get('expires_at')) - self::iv($r->get('issued_at'));
        if (!($life >= 0 && $life <= self::MAX_RECEIPT_LIFETIME_MS)) {
            return 'receipt.expires_at must be within ' . self::MAX_RECEIPT_LIFETIME_MS . ' ms after issued_at';
        }
        $kid = self::m($r, 'kid');
        if (!is_string($kid) || preg_match(self::KID_RE, $kid) !== 1) {
            return 'receipt.kid must match [A-Za-z0-9_.:-]{1,64}';
        }
        $l = self::m($r, 'ledger');
        if (!($l instanceof Obj) || self::sortedJoin($l) !== 'head,index' || !self::isNonNeg(self::m($l, 'index'))
            || Pca::unb64u(self::m($l, 'head'), 32) === null) {
            return 'receipt.ledger must be {index, head}';
        }
        if (Pca::unb64u(self::m($r, 'signer'), 32) === null) {
            return 'receipt.signer is not canonical base64url (32 bytes)';
        }
        if (($se = self::suiteError(self::m($r, 'alg'))) !== null) {
            return "receipt.alg: $se";
        }
        if (self::suiteOf(self::m($r, 'alg')) === 'ed25519' && ($r->has('pq_pk') || $r->has('pq_sig'))) {
            return 'an ed25519 receipt must not carry pq_pk / pq_sig';
        }
        if (!is_string(self::m($r, 'sig'))) {
            return 'receipt.sig must be a string';
        }
        return null;
    }

    private static function receiptBody(Obj $r): Obj
    {
        $o = new Obj();
        foreach (['v', 'kind', 'session', 'acc', 'seq', 'pre', 'delta', 'post', 'pcactn_digest', 'aud', 'issued_at', 'expires_at', 'kid'] as $k) {
            $o->set($k, $r->get($k));
        }
        $l = $r->get('ledger');
        $o->set('ledger', Obj::of(['index' => $l->get('index'), 'head' => $l->get('head')]));
        $o->set('signer', $r->get('signer'));
        return $o;
    }

    /** verifyAccReceiptSignature: shape, `signer == expectedSigner`, suite signature (PQ only as pinned). Never throws. */
    public static function verifyAccReceiptSignature(mixed $r, mixed $expectedSigner, ?string $pinKey = null, mixed $pinPq = null): bool
    {
        try {
            if (self::accReceiptShapeError($r) !== null || $r->get('signer') !== $expectedSigner) {
                return false;
            }
            $msg = self::ACC_RECEIPT_DOMAIN . self::canonicalize(self::bindSuite(self::receiptBody($r), self::m($r, 'alg'), self::m($r, 'pq_pk')));
            return self::verifyPinned(self::m($r, 'alg'), $r->get('signer'), self::m($r, 'pq_pk'), $msg, $r->get('sig'),
                self::m($r, 'pq_sig'), $pinKey, $pinPq);
        } catch (\Throwable) {
            return false;
        }
    }

    /** The receipt's content address (what `intent_session.acc[].receipt` carries). */
    public static function accReceiptDigest(mixed $r): string
    {
        return self::hashCanonical(Obj::of(['d' => self::ACC_RECEIPT_REF_DOMAIN, 'r' => $r]));
    }

    public static function sequencerKeySetShapeError(mixed $k): ?string
    {
        if (!($k instanceof Obj)) {
            return 'key set is not an object';
        }
        foreach (self::jsKeys($k) as $x) {
            if (!in_array($x, ['v', 'kind', 'sequencer', 'version', 'issued_at', 'keys', 'alg', 'pq_pk', 'sig', 'pq_sig'], true)) {
                return "key set: unknown member '$x'";
            }
        }
        if (!self::eq(self::m($k, 'v'), 1) || self::m($k, 'kind') !== 'pca-sequencer-keys') {
            return 'not a pca-sequencer-keys v1';
        }
        if (Pca::unb64u(self::m($k, 'sequencer'), 32) === null) {
            return 'sequencer is not canonical base64url (32 bytes)';
        }
        if (!(self::isNonNeg(self::m($k, 'version')) && self::f($k->get('version')) >= 1)) {
            return 'version must be a safe integer >= 1';
        }
        if (!self::isNonNeg(self::m($k, 'issued_at'))) {
            return 'issued_at must be a non-negative safe integer';
        }
        $keys = self::m($k, 'keys');
        if (!self::isList($keys) || count($keys) === 0 || count($keys) > 256) {
            return 'keys must be 1..256 entries';
        }
        $kids = [];
        foreach ($keys as $e) {
            $ok = $e instanceof Obj;
            foreach ($ok ? self::jsKeys($e) : [] as $x) {
                if (!in_array($x, ['kid', 'pk', 'alg', 'pq_pk', 'not_before', 'not_after'], true)) {
                    $ok = false;
                    break;
                }
            }
            if (!$ok) {
                return 'keys entries are {kid, pk, alg?, pq_pk?, not_before, not_after?}';
            }
            $kid = self::m($e, 'kid');
            if (!is_string($kid) || preg_match(self::KID_RE, $kid) !== 1 || isset($kids['k' . $kid])) {
                return 'key kids must match [A-Za-z0-9_.:-]{1,64} and be distinct';
            }
            $kids['k' . $kid] = true;
            if (Pca::unb64u(self::m($e, 'pk'), 32) === null) {
                return 'key pk is not canonical base64url (32 bytes)';
            }
            if (($se = self::suiteError(self::m($e, 'alg'))) !== null) {
                return "key alg: $se";
            }
            if ($e->has('pq_pk') && Pca::unb64u($e->get('pq_pk')) === null) {
                return 'key pq_pk is not canonical base64url';
            }
            $nb = self::m($e, 'not_before');
            $na = self::m($e, 'not_after');
            if (!self::isNonNeg($nb) || (!self::isU($na) && !(self::isNonNeg($na) && self::f($na) >= self::f($nb)))) {
                return 'key validity must be 0 <= not_before <= not_after';
            }
        }
        if (($se = self::suiteError(self::m($k, 'alg'))) !== null) {
            return "alg: $se";
        }
        if (self::suiteOf(self::m($k, 'alg')) === 'ed25519' && ($k->has('pq_pk') || $k->has('pq_sig'))) {
            return 'an ed25519 key set must not carry pq_pk / pq_sig';
        }
        if (!is_string(self::m($k, 'sig'))) {
            return 'sig must be a string';
        }
        return null;
    }

    /** Verify a `pca-sequencer-keys` set under the session's pinned root (and the root's pinned PQ key). Never throws. */
    public static function verifySequencerKeySet(mixed $k, mixed $root, mixed $rootPqPk = null): bool
    {
        try {
            if (self::sequencerKeySetShapeError($k) !== null || !is_string($root) || $k->get('sequencer') !== $root) {
                return false;
            }
            $body = Obj::of(['v' => $k->get('v'), 'kind' => $k->get('kind'), 'sequencer' => $k->get('sequencer'),
                'version' => $k->get('version'), 'issued_at' => $k->get('issued_at'), 'keys' => $k->get('keys')]);
            $msg = self::SEQUENCER_KEYS_DOMAIN . self::canonicalize(self::bindSuite($body, self::m($k, 'alg'), self::m($k, 'pq_pk')));
            $pinned = $rootPqPk !== null && !self::isU($rootPqPk);
            return self::verifyPinned(self::m($k, 'alg'), $root, self::m($k, 'pq_pk'), $msg, $k->get('sig'), self::m($k, 'pq_sig'),
                $pinned ? $root : null, $pinned ? $rootPqPk : null);
        } catch (\Throwable) {
            return false;
        }
    }

    /** A key set's content address: b64u(sha256(strictCanonical({"d":"atlas-pca/sequencer-keys-ref/v1","k":set}))), signature fields included. */
    public static function sequencerKeySetDigest(mixed $ks): string
    {
        return self::hashCanonical(Obj::of(['d' => self::SEQUENCER_KEYS_REF_DOMAIN, 'k' => $ks]));
    }

    /** `acc.keyset_versions[root]` is exactly {version, digest}: version a safe integer >= 1, digest 32-byte base64url. Null = well-formed. */
    public static function trackedKeySetError(mixed $t): ?string
    {
        if (!($t instanceof Obj)) {
            return 'a tracked key set must be an object {version, digest}';
        }
        foreach (self::jsKeys($t) as $k) {
            if ($k !== 'version' && $k !== 'digest') {
                return "a tracked key set has the unknown member '$k'";
            }
        }
        if (!self::isInt(self::m($t, 'version')) || self::f($t->get('version')) < 1) {
            return 'a tracked key set version must be a safe integer >= 1';
        }
        if (!is_string(self::m($t, 'digest')) || !self::b32($t->get('digest'))) {
            return 'a tracked key set digest must be canonical base64url (32 bytes)';
        }
        return null;
    }

    /**
     * Rule 15 (sequenced holder; intent-acc.ts verifyReceiptAgainstHolder). 'valid' only when ALL hold:
     *   - `now` is a safe integer and every bound is a non-negative safe integer; the key-set list is an array;
     *   - the receipt is well-formed (`issued_at <= expires_at <= issued_at + 15 min`), `issued_at <= now + 60 s` and
     *     `now - issued_at <= $maxReceiptAgeMs` (default 900000);
     *   - SOME presented key set verifies under `holder.root` (PQ: `holder.root_pq_pk`); when the verifier tracks
     *     `$tracked` = {version, digest} for the root, `version >= tracked.version` (no rollback) and, at an equal version,
     *     `sequencerKeySetDigest(set) == tracked.digest` (EQUIVOCATION otherwise); `version >= $minKeySetVersion` when a bare
     *     floor is given (version-only replayers); `issued_at <= now + 60 s` and `now - issued_at <= $maxKeySetAgeMs` (default 3600000), and lists
     *     `receipt.kid` with `pk == receipt.signer`, `not_before <= receipt.issued_at`, and, when `not_after` is set,
     *     `receipt.issued_at <= not_after` AND `not_after >= now - 60 s` (a retired key stops verifying once retired), the
     *     entry's suite equal to the receipt's;
     *   - the receipt verifies under that entry (PQ pinned by the entry's `pq_pk`).
     * 'unsupported' when it is not valid and the receipt or a presented key set names a suite this verifier does not
     * implement; else 'invalid'. Never throws.
     */
    public static function verifyReceiptAgainstHolder(mixed $r, mixed $holder, mixed $keySets, mixed $now, mixed $maxReceiptAgeMs = null,
                                                      mixed $maxKeySetAgeMs = null, mixed $minKeySetVersion = null, mixed $tracked = null): string
    {
        try {
            $maxAge = $maxReceiptAgeMs ?? self::DEFAULT_MAX_RECEIPT_AGE_MS;
            $maxSetAge = $maxKeySetAgeMs ?? self::DEFAULT_MAX_KEYSET_AGE_MS;
            if (!self::isInt($now) || !self::isNonNeg($maxAge) || !self::isNonNeg($maxSetAge)
                || ($tracked !== null && self::trackedKeySetError($tracked) !== null)
                || ($minKeySetVersion !== null && !self::isNonNeg($minKeySetVersion))) {
                return 'invalid';
            }
            if (!self::isList($keySets)) {
                return 'invalid';
            }
            $rs = self::accReceiptShapeError($r);
            if ($rs !== null) {
                return str_contains($rs, self::UNSUPPORTED_SUITE) ? 'unsupported' : 'invalid';
            }
            $now = self::iv($now);
            $ia = self::iv($r->get('issued_at'));
            if (!($ia <= $now + self::RECEIPT_SKEW_MS) || !($now - $ia <= self::iv($maxAge))) {
                return 'invalid';
            }
            $unsupported = false;
            foreach ($keySets as $k) {
                $ke = self::sequencerKeySetShapeError($k);
                if ($ke !== null && str_contains($ke, self::UNSUPPORTED_SUITE)) {
                    $unsupported = true;
                }
                if (!self::verifySequencerKeySet($k, self::m($holder, 'root'), self::m($holder, 'root_pq_pk'))) {
                    continue;
                }
                if ($minKeySetVersion !== null && self::iv($k->get('version')) < self::iv($minKeySetVersion)) {
                    continue;
                }
                if ($tracked !== null) {
                    $tv = self::iv($tracked->get('version'));
                    $kv = self::iv($k->get('version'));
                    if ($kv < $tv || ($kv === $tv && self::sequencerKeySetDigest($k) !== $tracked->get('digest'))) {
                        continue; // rollback, or two different sets under one version (equivocation)
                    }
                }
                $ksAt = self::iv($k->get('issued_at'));
                if (!($ksAt <= $now + self::RECEIPT_SKEW_MS) || !($now - $ksAt <= self::iv($maxSetAge))) {
                    continue;
                }
                $e = null;
                foreach ($k->get('keys') as $x) {
                    if ($x->get('kid') === $r->get('kid')) {
                        $e = $x;
                        break;
                    }
                }
                if ($e === null || $e->get('pk') !== $r->get('signer') || $ia < self::iv($e->get('not_before'))) {
                    continue;
                }
                if ($e->has('not_after') && ($ia > self::iv($e->get('not_after')) || self::iv($e->get('not_after')) < $now - self::RECEIPT_SKEW_MS)) {
                    continue;
                }
                if (self::suiteOf(self::m($e, 'alg')) !== self::suiteOf(self::m($r, 'alg'))) {
                    continue;
                }
                $pinned = $e->has('pq_pk');
                if (self::verifyAccReceiptSignature($r, $e->get('pk'), $pinned ? $e->get('pk') : null, $pinned ? $e->get('pq_pk') : null)) {
                    return 'valid';
                }
            }
            return $unsupported ? 'unsupported' : 'invalid';
        } catch (\Throwable) {
            return 'invalid';
        }
    }

    /** The arithmetic a receipt must satisfy for its accumulator (rule 15 step 5d). */
    public static function receiptArithmeticOk(mixed $a, Obj $r, int $val): bool
    {
        $pre = self::iv($r->get('pre'));
        $delta = self::iv($r->get('delta'));
        $post = self::iv($r->get('post'));
        return match (self::m($a, 'agg')) {
            'sum' => $delta === $val && $post === $pre + $delta,
            'count' => $delta === 1 && $post === $pre + 1,
            'max' => $delta === $val && $post === max($pre, $delta),
            'distinct' => ($delta === 0 || $delta === 1) && $post === $pre + $delta,
            default => false,
        };
    }

    // ==== rule 13 step 7: session revocation (dedicated authority, full revoked list, append-only) ======================

    private static function sha(string $b): string
    {
        return hash('sha256', $b, true);
    }

    /** revset_root(L): b64u(SHA-256("pca-revset/v1\0" || canonical({size, tree}))), tree the RFC 6962 root (empty: SHA-256("")). */
    public static function revsetRoot(array $ids): string
    {
        $tree = count($ids) === 0 ? Pca::b64u(self::sha('')) : Pca::merkleRoot($ids);
        return Pca::b64u(self::sha(self::REVSET_DOMAIN . self::canonicalize(Obj::of(['size' => count($ids), 'tree' => $tree]))));
    }

    /** Strict shape of a revocation epoch (intent-revocation.ts revocationEpochShapeError). */
    public static function revocationEpochShapeError(mixed $ep): ?string
    {
        if (!($ep instanceof Obj)) {
            return 'the revocation epoch must be an object';
        }
        foreach (['instance_id', 'grant_ref', 'root', 'guardian', 'sig'] as $k) {
            if (!is_string(self::m($ep, $k))) {
                return "revocation epoch $k must be a string";
            }
        }
        foreach (['epoch', 'set_size', 'issued_at', 'not_after'] as $k) {
            if (!self::isNonNeg(self::m($ep, $k))) {
                return "revocation epoch $k must be a non-negative safe integer";
            }
        }
        if ($ep->has('guardian_epoch') && !self::isNonNeg($ep->get('guardian_epoch'))) {
            return 'revocation epoch guardian_epoch must be a non-negative safe integer';
        }
        if (($se = self::suiteError(self::m($ep, 'alg'))) !== null) {
            return "revocation epoch alg: $se";
        }
        if ($ep->has('pq_pk') && !is_string($ep->get('pq_pk'))) {
            return 'revocation epoch pq_pk must be a string';
        }
        if ($ep->has('pq_sig') && !is_string($ep->get('pq_sig'))) {
            return 'revocation epoch pq_sig must be a string';
        }
        return null;
    }

    /**
     * checkRevocationEpoch of revocation.ts over a shape-checked epoch: guardian, suite signature over
     * "atlas-pca/revepoch/v1\0" || strictCanonical(body + bound suite fields) (a PQ epoch only under the pin `$pinPq` for
     * the guardian), grant_ref, now <= not_after, issued_at <= now + 60 s. @return array{ok:bool, reason?:string}
     */
    public static function checkRevocationEpoch(Obj $ep, string $guardian, int $now, mixed $grantRef, mixed $pinPq = null): array
    {
        try {
            if ($ep->get('guardian') !== $guardian) {
                return self::bad('revocation epoch not signed by the pinned guardian');
            }
            $body = new Obj();
            foreach (['instance_id', 'grant_ref', 'epoch', 'set_size', 'root', 'issued_at', 'not_after'] as $k) {
                $body->set($k, $ep->get($k));
            }
            $alg = self::m($ep, 'alg');
            $pq = self::m($ep, 'pq_pk');
            $msg = self::REVEPOCH_DOMAIN . self::canonicalize(self::bindSuite($body, $alg, $pq));
            if (!self::verifyPinned($alg, $guardian, $pq, $msg, $ep->get('sig'), self::m($ep, 'pq_sig'),
                $pinPq !== null ? $guardian : null, $pinPq)) {
                return self::bad('revocation epoch signature invalid');
            }
            if (!self::isU($grantRef) && $ep->get('grant_ref') !== $grantRef) {
                return self::bad('revocation epoch is for a different grant');
            }
            if (!($now <= self::iv($ep->get('not_after')))) {
                return self::bad('revocation epoch expired (stale revocation root)');
            }
            if (!(self::iv($ep->get('issued_at')) <= $now + self::REVOCATION_SKEW_MS)) {
                return self::bad('revocation epoch issued in the future');
            }
            return ['ok' => true];
        } catch (\Throwable) {
            return self::bad('revocation epoch check error');
        }
    }

    public static function sessionRevocationId(string $session): string
    {
        return 'pca-intent:session:' . $session;
    }

    public static function sessionRevocationScope(string $session): string
    {
        return 'pca-intent-session:' . $session;
    }

    /**
     * The revoked list is well-formed and is exactly what the epoch signs (intent-revocation.ts revokedListError): an array
     * of strings, strictly ascending in UTF-8 byte order, `length == set_size == epoch`, and its revset root == `root`.
     * `$ev` holds a shape-checked epoch.
     */
    private static function revokedListError(Obj $ev): ?string
    {
        $r = self::m($ev, 'revoked');
        if (!self::isList($r) || count(array_filter($r, 'is_string')) !== count($r)) {
            return 'revoked must be an array of ids';
        }
        for ($i = 1; $i < count($r); $i++) {
            if (!(self::compareUtf8($r[$i - 1], $r[$i]) < 0)) {
                return 'revoked must be sorted by UTF-8 bytes and distinct';
            }
        }
        $ep = $ev->get('epoch');
        $size = self::iv($ep->get('set_size'));
        if (count($r) !== $size || self::iv($ep->get('epoch')) !== $size) {
            return 'the epoch must be numbered by its set size and list exactly set_size ids';
        }
        if (self::revsetRoot($r) !== $ep->get('root')) {
            return 'the revoked list is not the signed set (root mismatch)';
        }
        return null;
    }

    /** The evidence is CLOSED (intent-revocation.ts closedEvidenceError): the first member, in key order, that is neither `epoch` nor `revoked`. */
    private static function closedEvidenceError(Obj $ev): ?string
    {
        foreach (self::jsKeys($ev) as $k) {
            if ($k !== 'epoch' && $k !== 'revoked') {
                return "has the unknown member '$k' (it is exactly {epoch, revoked})";
            }
        }
        return null;
    }

    /**
     * checkSessionRevocation (rule 13 step 7; intent-revocation.ts), first failure wins:
     *   a. `maxAgeMs` a safe integer >= 0, `now` a safe integer, `ids` an array, `authority` a string;
     *   b. the evidence is an object with no member but `epoch` and `revoked` (closed; so is `last`); the epoch is strictly
     *      typed and its `guardian` is the authority (a missing `revoked` fails at e);
     *   c. it verifies under the authority (a PQ epoch only under `pqPin`), `grant_ref` == the scope (`scope` ??
     *      "pca-intent-session:" + session), now <= not_after, issued_at <= now + 60 s;
     *   d. now - issued_at <= maxAgeMs;
     *   e. `revoked` is the full signed set (revokedListError);
     *   f. APPEND-ONLY when `last` (the tracked last accepted evidence) is given: itself well-formed, epoch >= last.epoch,
     *      every id of last.revoked is in revoked, epoch == last.epoch implies root == last.root;
     *   g. no id of `ids` is in `revoked`.
     * Never throws.
     * @param array{session:mixed, authority:mixed, ids:mixed, now:mixed, maxAgeMs:mixed, pqPin?:mixed, scope?:mixed, last?:mixed} $c
     *   (`pqPin` / `scope` / `last` absent = none; a `scope` of null takes the default like the reference's `??`)
     * @return array{ok:bool, reason?:string}
     */
    public static function checkSessionRevocation(mixed $ev, array $c): array
    {
        try {
            if (!self::isNonNeg($c['maxAgeMs'] ?? null)) {
                return self::bad('revocation max age misconfigured (fail closed)');
            }
            if (!self::isInt($c['now'] ?? null)) {
                return self::bad('the verifier clock is not a safe integer (fail closed)');
            }
            $now = self::iv($c['now']);
            $maxAge = self::iv($c['maxAgeMs']);
            $ids = $c['ids'] ?? null;
            $authority = $c['authority'] ?? null;
            if (!self::isList($ids) || !is_string($authority)) {
                return self::bad('ids must be an array and the authority a key');
            }
            if (!($ev instanceof Obj)) {
                return self::bad('no session revocation epoch supplied');
            }
            // the evidence is CLOSED: an extra member is malformed (a missing one fails at the epoch / revoked-list steps)
            if (($ce = self::closedEvidenceError($ev)) !== null) {
                return self::bad("the revocation evidence $ce");
            }
            $ep = self::m($ev, 'epoch');
            if (($shape = self::revocationEpochShapeError($ep)) !== null) {
                return self::bad($shape);
            }
            /** @var Obj $ep */
            if ($ep->get('guardian') !== $authority) {
                return self::bad('the revocation epoch is not signed by the session revocation authority');
            }
            $scope = array_key_exists('scope', $c) && $c['scope'] !== null && !self::isU($c['scope'])
                ? $c['scope'] : self::sessionRevocationScope(self::txt($c['session'] ?? ''));
            $pin = $c['pqPin'] ?? null;
            $r = self::checkRevocationEpoch($ep, $authority, $now, $scope, $pin);
            if (!$r['ok']) {
                return self::bad($r['reason'] ?? 'revocation epoch rejected');
            }
            if (!($now - self::iv($ep->get('issued_at')) <= $maxAge)) {
                return self::bad("the session revocation epoch is older than $maxAge ms");
            }
            if (($le = self::revokedListError($ev)) !== null) {
                return self::bad($le);
            }
            $revoked = [];
            foreach ($ev->get('revoked') as $id) {
                $revoked['k' . $id] = true;
            }
            if (array_key_exists('last', $c) && !self::isU($c['last'])) {
                $L = $c['last'];
                if (!($L instanceof Obj) || self::closedEvidenceError($L) !== null || self::revocationEpochShapeError(self::m($L, 'epoch')) !== null
                    || self::revokedListError($L) !== null) {
                    return self::bad('the tracked last epoch is malformed (fail closed)');
                }
                $le = $L->get('epoch');
                if (self::iv($ep->get('epoch')) < self::iv($le->get('epoch'))) {
                    return self::bad('revocation epoch rollback (older than the last accepted)');
                }
                foreach ($L->get('revoked') as $id) {
                    if (!isset($revoked['k' . $id])) {
                        return self::bad("the epoch drops '$id', revoked in the last accepted epoch (not append-only)");
                    }
                }
                if (self::iv($ep->get('epoch')) === self::iv($le->get('epoch')) && $ep->get('root') !== $le->get('root')) {
                    return self::bad('two different revocation sets under one epoch number (equivocation)');
                }
            }
            foreach ($ids as $id) {
                if (!is_string($id) || isset($revoked['k' . $id])) {
                    return self::bad("'" . self::txt($id) . "' is revoked");
                }
            }
            return ['ok' => true];
        } catch (\Throwable $e) {
            return self::bad('session revocation check error (fail closed): ' . $e->getMessage());
        }
    }

    // ==== rule 19: the committed map and Z0 disclosure (intent-map-commit.ts) =========================================

    private const MAP_TAGS = ['header' => self::MAP_TAG_HEADER, 'cell' => self::MAP_TAG_CELL, 'metrics' => self::MAP_TAG_METRICS,
        'learner' => self::MAP_TAG_LEARNER];

    /** A string without lone surrogates of at most `max` UTF-8 bytes (empty allowed). */
    private static function mapStr(mixed $v, int $max = self::MAX_MAP_STRING_BYTES): bool
    {
        return is_string($v) && !self::lone($v) && strlen($v) <= $max;
    }

    /** Keys within `allowed` and every `required` member own. */
    private static function closedObj(Obj $o, array $allowed, array $required): bool
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return false;
            }
        }
        foreach ($required as $k) {
            if (!$o->has($k)) {
                return false;
            }
        }
        return true;
    }

    /** SHA-256(TAG_kind || salt || strictCanonical(leaf)). Throws on a 32-byte-less salt or a leaf with no canonical form. */
    public static function mapLeafHash(string $kind, string $salt, mixed $leaf): string
    {
        if (!isset(self::MAP_TAGS[$kind])) {
            throw new \InvalidArgumentException('mapLeafHash: unknown leaf kind');
        }
        if (strlen($salt) !== 32) {
            throw new \InvalidArgumentException('mapLeafHash: the salt is 32 bytes');
        }
        return self::sha(self::MAP_TAGS[$kind] . $salt . self::canonicalize($leaf));
    }

    public static function mapNodeHash(string $l, string $r): string
    {
        return self::sha(self::MAP_TAG_NODE . $l . $r);
    }

    /** map_commit of a tree of `size` leaves with root `root`: b64u(SHA-256(TAG_COMMIT || u64be(size) || root)). */
    public static function mapCommitOf(int $size, string $root): string
    {
        return Pca::b64u(self::sha(self::MAP_TAG_COMMIT . pack('J', $size) . $root));
    }

    /** The RFC 6962 / 9162-shaped root over leaf hashes (split at the largest power of two < n). */
    public static function mapTreeRoot(array $hs): string
    {
        $n = count($hs);
        if ($n === 0) {
            throw new \InvalidArgumentException('mapTree: empty');
        }
        if ($n === 1) {
            return $hs[0];
        }
        $k = 1;
        while ($k * 2 < $n) {
            $k *= 2;
        }
        return self::mapNodeHash(self::mapTreeRoot(array_slice($hs, 0, $k)), self::mapTreeRoot(array_slice($hs, $k)));
    }

    /**
     * RFC 9162 §2.1.3.2 inclusion verification with the map node hash: the root the audit path of leaf `index` in a tree of
     * `size` leaves recomputes, or null when the path has the wrong length for (index, size).
     */
    public static function mapRootFromPath(int $index, int $size, string $leafHash, array $path): ?string
    {
        if (!($index >= 0 && $index < $size)) {
            return null;
        }
        $fn = $index;
        $sn = $size - 1;
        $r = $leafHash;
        foreach ($path as $p) {
            if ($sn === 0) {
                return null;
            }
            if ($fn % 2 === 1 || $fn === $sn) {
                $r = self::mapNodeHash($p, $r);
                if ($fn % 2 === 0) {
                    while ($fn % 2 === 0 && $fn !== 0) {
                        $fn = intdiv($fn, 2);
                        $sn = intdiv($sn, 2);
                    }
                }
            } else {
                $r = self::mapNodeHash($r, $p);
            }
            $fn = intdiv($fn, 2);
            $sn = intdiv($sn, 2);
        }
        return $sn === 0 ? $r : null;
    }

    /** The commitment of a full leaf list [{kind, salt, leaf}] (primitives.intent_map_commit). Throws on malformed input. */
    public static function mapCommitOfLeaves(mixed $leaves): string
    {
        if (!self::isList($leaves) || count($leaves) === 0) {
            throw new \InvalidArgumentException('leaves must be a non-empty array');
        }
        $hs = [];
        foreach ($leaves as $e) {
            $salt = Pca::unb64u(self::m($e, 'salt'), 32);
            $kind = self::m($e, 'kind');
            if ($salt === null || !is_string($kind) || !($e instanceof Obj) || !$e->has('leaf')) {
                throw new \InvalidArgumentException('a leaf entry is {kind, salt, leaf}');
            }
            $hs[] = self::mapLeafHash($kind, $salt, $e->get('leaf'));
        }
        return self::mapCommitOf(count($hs), self::mapTreeRoot($hs));
    }

    private static function isDimPath(mixed $p): bool
    {
        return $p === 'action.resource' || (is_string($p) && preg_match(self::PARAM_PATH_RE, $p) === 1);
    }

    /** The cells of a numeric dimension as inclusive [lo, hi] ranges (empty ranges dropped). @return list<array{0:int,1:int}> */
    public static function mapNumCells(Obj $d): array
    {
        $out = [];
        $cur = self::iv($d->get('lo'));
        foreach ($d->get('cuts') as $cv) {
            $c = self::iv($cv);
            if ($cur <= $c - 1) {
                $out[] = [$cur, $c - 1];
            }
            $out[] = [$c, $c];
            $cur = $c + 1;
        }
        if ($cur <= self::iv($d->get('hi'))) {
            $out[] = [$cur, self::iv($d->get('hi'))];
        }
        return $out;
    }

    private static function dimCells(Obj $d): int
    {
        return $d->get('kind') === 'num' ? count(self::mapNumCells($d)) : count($d->get('values'));
    }

    private static function dimError(mixed $d, int $j): ?string
    {
        if (!($d instanceof Obj)) {
            return "dims[$j] must be an object";
        }
        $kind = self::m($d, 'kind');
        if ($kind === 'num') {
            $all = ['kind', 'path', 'lo', 'hi', 'cuts'];
            if (!self::closedObj($d, $all, $all)) {
                return "dims[$j] must be exactly {kind, path, lo, hi, cuts}";
            }
            if (!self::isDimPath($d->get('path')) || $d->get('path') === 'action.resource') {
                return "dims[$j].path must be action.params.<name>";
            }
            $lo = $d->get('lo');
            $hi = $d->get('hi');
            if (!self::isInt($lo) || !self::isInt($hi) || self::f($lo) > self::f($hi)) {
                return "dims[$j] lo / hi must be safe integers with lo <= hi";
            }
            $cuts = $d->get('cuts');
            if (!self::isList($cuts) || count($cuts) > self::MAX_MAP_CUTS) {
                return "dims[$j].cuts must be an array of at most " . self::MAX_MAP_CUTS;
            }
            $prev = -INF;
            foreach ($cuts as $c) {
                if (!self::isInt($c) || self::f($c) <= $prev || self::f($c) < self::f($lo) || self::f($c) > self::f($hi)) {
                    return "dims[$j].cuts must be strictly increasing safe integers in [lo, hi]";
                }
                $prev = self::f($c);
            }
            return null;
        }
        if ($kind === 'cat') {
            $all = ['kind', 'path', 'values'];
            if (!self::closedObj($d, $all, $all)) {
                return "dims[$j] must be exactly {kind, path, values}";
            }
            if (!self::isDimPath($d->get('path'))) {
                return "dims[$j].path must be action.resource or action.params.<name>";
            }
            $vals = $d->get('values');
            if (!self::isList($vals) || count($vals) === 0 || count($vals) > self::MAX_MAP_VALUES) {
                return "dims[$j].values must be an array of 1.." . self::MAX_MAP_VALUES;
            }
            $seen = [];
            $last = count($vals) - 1;
            foreach ($vals as $i => $v) {
                if (!($v instanceof Obj) || !self::closedObj($v, ['kind', 'value'], ['kind', 'value'])) {
                    return "dims[$j].values[$i] must be exactly {kind, value}";
                }
                $vk = $v->get('kind');
                if ($vk !== 'exact' && $vk !== 'prefix' && $vk !== 'other') {
                    return "dims[$j].values[$i].kind must be exact, prefix or other";
                }
                $vv = $v->get('value');
                if (!self::mapStr($vv)) {
                    return "dims[$j].values[$i].value must be a string of at most " . self::MAX_MAP_STRING_BYTES . ' UTF-8 bytes';
                }
                if ($vk === 'other' ? ($i !== $last || $vv !== self::MAP_OTHER) : ($vk === 'prefix' && $vv === '')) {
                    return "dims[$j].values: exactly one other ('" . self::MAP_OTHER . "'), last; prefixes non-empty";
                }
                $key = "$vk:$vv";
                if (isset($seen['k' . $key])) {
                    return "dims[$j].values must be distinct";
                }
                $seen['k' . $key] = true;
            }
            if ($vals[$last]->get('kind') !== 'other') {
                return "dims[$j].values must end with the other value";
            }
            return null;
        }
        return "dims[$j].kind must be num or cat";
    }

    /** Shape of a header leaf (closed, typed; `cells` equals the product of the dimensions' cell counts). Null = well-formed. */
    public static function mapHeaderError(mixed $h): ?string
    {
        $all = ['verb', 'first', 'cells', 'dims'];
        if (!($h instanceof Obj) || !self::closedObj($h, $all, $all)) {
            return 'the header leaf must be exactly {verb, first, cells, dims}';
        }
        if (!self::mapStr($h->get('verb'), 128) || $h->get('verb') === '') {
            return 'header.verb must be a non-empty string of at most 128 UTF-8 bytes';
        }
        if (!self::isNonNeg($h->get('first')) || self::f($h->get('first')) >= self::MAX_MAP_LEAVES) {
            return 'header.first must be a leaf index';
        }
        $cells = $h->get('cells');
        if (!self::isInt($cells) || self::f($cells) < 1 || self::f($cells) > self::MAX_VERB_CELLS) {
            return 'header.cells must be a safe integer in [1, ' . self::MAX_VERB_CELLS . ']';
        }
        $dims = $h->get('dims');
        if (!self::isList($dims) || count($dims) > self::MAX_MAP_DIMS) {
            return 'header.dims must be an array of at most ' . self::MAX_MAP_DIMS;
        }
        $paths = [];
        $n = 1;
        foreach ($dims as $j => $d) {
            if (($e = self::dimError($d, $j)) !== null) {
                return "header.$e";
            }
            if (isset($paths['k' . $d->get('path')])) {
                return 'header.dims paths must be distinct';
            }
            $paths['k' . $d->get('path')] = true;
            $n *= self::dimCells($d);
            if ($n > self::MAX_VERB_CELLS) {
                return 'header: too many cells';
            }
        }
        if ($n !== self::iv($cells)) {
            return "header.cells is not the product of the dimensions' cell counts";
        }
        return null;
    }

    public static function mapCellError(mixed $c): ?string
    {
        $all = ['verb', 'cell', 'p_ppm', 'in_grant'];
        if (!($c instanceof Obj) || !self::closedObj($c, $all, $all)) {
            return 'the cell leaf must be exactly {verb, cell, p_ppm, in_grant}';
        }
        if (!self::mapStr($c->get('verb'), 128) || $c->get('verb') === '') {
            return 'cell.verb must be a non-empty string of at most 128 UTF-8 bytes';
        }
        $cell = $c->get('cell');
        $ok = self::isList($cell) && count($cell) <= self::MAX_MAP_DIMS;
        foreach ($ok ? $cell : [] as $x) {
            if (!self::isNonNeg($x)) {
                $ok = false;
                break;
            }
        }
        if (!$ok) {
            return 'cell.cell must be an array of non-negative safe integers';
        }
        if (!self::isNonNeg($c->get('p_ppm')) || self::f($c->get('p_ppm')) > 1000000) {
            return 'cell.p_ppm must be a safe integer in [0, 1000000]';
        }
        if (!is_bool($c->get('in_grant'))) {
            return 'cell.in_grant must be a boolean';
        }
        return null;
    }

    public static function mapMetricsError(mixed $m): ?string
    {
        $all = [...self::MAP_METRIC_FIELDS, 'log2_vs_mbits'];
        if (!($m instanceof Obj) || !self::closedObj($m, $all, self::MAP_METRIC_FIELDS)) {
            return 'the metrics leaf must be exactly {' . implode(', ', self::MAP_METRIC_FIELDS) . ', log2_vs_mbits?}';
        }
        foreach ($all as $k) {
            if ($k === 'log2_vs_mbits' && !$m->has($k)) {
                continue;
            }
            if (!self::isNonNeg($m->get($k))) {
                return "metrics.$k must be a non-negative safe integer";
            }
        }
        return null;
    }

    public static function mapLearnerError(mixed $l): ?string
    {
        if (!($l instanceof Obj) || !self::closedObj($l, ['learner_digest'], ['learner_digest'])) {
            return 'the learner leaf must be exactly {learner_digest}';
        }
        return self::b32($l->get('learner_digest')) ? null : 'learner.learner_digest must be canonical base64url (32 bytes)';
    }

    /**
     * Cell of ω under a well-formed header: per-dimension indices and the flat index, or ['error' => ...]. `resource` is
     * `action.resource`, `params` the plaintext params (own members). num: a safe integer in its cell; cat: exact, else the
     * longest prefix, else other. @return array{cell?: list<int>, flat?: int, error?: string}
     */
    public static function mapCellOf(Obj $header, mixed $resource, mixed $params): array
    {
        $cell = [];
        $flat = 0;
        foreach ($header->get('dims') as $d) {
            $path = $d->get('path');
            $x = $path === 'action.resource' ? $resource : self::m($params, self::paramName($path));
            $i = -1;
            if ($d->get('kind') === 'num') {
                if (self::isInt($x)) {
                    foreach (self::mapNumCells($d) as $k => [$lo, $hi]) {
                        if (self::f($x) >= $lo && self::f($x) <= $hi) {
                            $i = $k;
                            break;
                        }
                    }
                }
            } elseif (is_string($x) && !self::lone($x)) {
                $best = -1;
                $bestLen = -1;
                foreach ($d->get('values') as $k => $v) {
                    $vv = $v->get('value');
                    if ($v->get('kind') === 'exact' && $vv === $x) {
                        $best = $k;
                        break;
                    }
                    // prefixes of one string: the longer one is longer in UTF-16 units and in UTF-8 bytes alike
                    if ($v->get('kind') === 'prefix' && str_starts_with($x, $vv) && strlen($vv) > $bestLen) {
                        $best = $k;
                        $bestLen = strlen($vv);
                    }
                }
                $i = $best >= 0 ? $best : count($d->get('values')) - 1;
            }
            if ($i < 0) {
                return ['error' => "the action's $path lies outside the committed map's dimension"];
            }
            $cell[] = $i;
            $flat = $flat * self::dimCells($d) + $i;
        }
        return ['cell' => $cell, 'flat' => $flat];
    }

    private static function mapEntryShape(mixed $e, string $what): ?string
    {
        $all = ['index', 'salt', 'leaf', 'path'];
        if (!($e instanceof Obj) || !self::closedObj($e, $all, $all)) {
            return "disclosure.$what must be exactly {index, salt, leaf, path}";
        }
        if (!self::isNonNeg($e->get('index'))) {
            return "disclosure.$what.index must be a non-negative safe integer";
        }
        if (!self::b32($e->get('salt'))) {
            return "disclosure.$what.salt must be canonical base64url (32 bytes)";
        }
        $path = $e->get('path');
        $ok = self::isList($path) && count($path) <= 64;
        foreach ($ok ? $path : [] as $h) {
            if (!self::b32($h)) {
                $ok = false;
                break;
            }
        }
        return $ok ? null : "disclosure.$what.path must be an array of 32-byte digests";
    }

    /** Shape of a Z0 disclosure (closed, typed). Null = well-formed. */
    public static function mapDisclosureError(mixed $d): ?string
    {
        $all = ['size', 'header', 'cell', 'metrics'];
        if (!($d instanceof Obj) || !self::closedObj($d, $all, $all)) {
            return 'the disclosure must be exactly {size, header, cell, metrics}';
        }
        $size = $d->get('size');
        if (!self::isInt($size) || self::f($size) < 4 || self::f($size) > self::MAX_MAP_LEAVES) {
            return 'disclosure.size must be a safe integer in [4, ' . self::MAX_MAP_LEAVES . ']';
        }
        foreach (['header', 'cell', 'metrics'] as $k) {
            if (($e = self::mapEntryShape($d->get($k), $k)) !== null) {
                return $e;
            }
        }
        return self::mapHeaderError($d->get('header')->get('leaf')) ?? self::mapCellError($d->get('cell')->get('leaf'))
            ?? self::mapMetricsError($d->get('metrics')->get('leaf'));
    }

    /** Does the disclosed entry (kind `$kind`) open `$mapCommit` in a tree of `$size` leaves? */
    private static function mapOpens(string $kind, Obj $e, int $size, string $mapCommit): bool
    {
        try {
            $h = self::mapLeafHash($kind, Pca::unb64u($e->get('salt'), 32), $e->get('leaf'));
            $path = array_map(fn($x) => Pca::unb64u($x, 32), $e->get('path'));
            $root = self::mapRootFromPath(self::iv($e->get('index')), $size, $h, $path);
            return $root !== null && self::mapCommitOf($size, $root) === $mapCommit;
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Z0, the `map` check (rule 19; intent-map-commit.ts decideMapDisclosure). First failure wins: the disclosure is
     * well-formed; the commitment is a 32-byte digest; params (absent = {}) hash to `action.params_digest`; the header is the
     * action's verb and fits the layout; header, cell and metrics open the commitment; the cell is the action's cell;
     * `in_grant`; metrics at index size - 2 and, with ε (`$maxResidualRiskPpm`), residual_risk_ppm <= ε. Never throws.
     * `$params` absent = undefined. @return array{ok:bool, cell?: list<int>, p_ppm?: int, residual_risk_ppm?: int, reason?: string}
     */
    public static function decideMapDisclosure(mixed $mapCommit, mixed $action, mixed $params, mixed $disclosure, mixed $maxResidualRiskPpm = null): array
    {
        try {
            if (($de = self::mapDisclosureError($disclosure)) !== null) {
                return self::bad("map disclosure malformed: $de");
            }
            if (!self::b32($mapCommit)) {
                return self::bad('the PCActn carries no map commitment');
            }
            /** @var Obj $disclosure */
            if (!self::isU($params) && !($params instanceof Obj)) {
                return self::bad('params must be an object');
            }
            $pobj = self::isU($params) ? new Obj() : $params;
            if (self::hashCanonical($pobj) !== self::m($action, 'params_digest')) {
                return self::bad('the params do not hash to action.params_digest');
            }
            $size = self::iv($disclosure->get('size'));
            $he = $disclosure->get('header');
            $h = $he->get('leaf');
            if ($h->get('verb') !== self::m($action, 'verb')) {
                return self::bad("the disclosed header is not the action's verb");
            }
            $first = self::iv($h->get('first'));
            if (!(self::iv($he->get('index')) < $first) || !($first + self::iv($h->get('cells')) <= $size - 2)) {
                return self::bad('the disclosed header does not fit the committed layout');
            }
            foreach (['header' => 'the header leaf', 'cell' => 'the cell leaf', 'metrics' => 'the metrics leaf'] as $k => $what) {
                if (!self::mapOpens($k, $disclosure->get($k), $size, $mapCommit)) {
                    return self::bad("$what does not open the map commitment");
                }
            }
            $w = self::mapCellOf($h, self::m($action, 'resource'), $pobj);
            if (isset($w['error'])) {
                return self::bad($w['error']);
            }
            $ce = $disclosure->get('cell');
            $c = $ce->get('leaf');
            $cc = $c->get('cell');
            $same = self::iv($ce->get('index')) === $first + $w['flat'] && $c->get('verb') === $h->get('verb') && count($cc) === count($w['cell']);
            foreach ($same ? $cc : [] as $i => $x) {
                if (self::iv($x) !== $w['cell'][$i]) {
                    $same = false;
                    break;
                }
            }
            if (!$same) {
                return self::bad("the disclosed cell is not the action's cell");
            }
            if ($c->get('in_grant') !== true) {
                return self::bad("the action's cell is outside the committed grant");
            }
            $me = $disclosure->get('metrics');
            if (self::iv($me->get('index')) !== $size - 2) {
                return self::bad('the disclosed metrics leaf is not at its committed position');
            }
            $risk = self::iv($me->get('leaf')->get('residual_risk_ppm'));
            if ($maxResidualRiskPpm !== null && !self::isU($maxResidualRiskPpm)) {
                $eps = self::f($maxResidualRiskPpm);
                if (!($eps !== null && $risk <= $eps)) {
                    return self::bad("the committed residual risk $risk ppm exceeds \u{03B5} = " . self::txt($maxResidualRiskPpm));
                }
            }
            return ['ok' => true, 'cell' => array_map(fn($x) => self::iv($x), $cc), 'p_ppm' => self::iv($c->get('p_ppm')), 'residual_risk_ppm' => $risk];
        } catch (\Throwable $e) {
            return self::bad('map error (fail closed): ' . $e->getMessage());
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
                if ($k !== 'session' && $k !== 'schema' && $k !== 'acc' && $k !== 'map') {
                    return "policy: unknown member '$k'";
                }
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
        return ['checks' => $checks, 'env' => $env, 'schema' => $schemaOut];
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
                foreach (['scope' => 'scope', 'last' => 'last'] as $k => $ck) {
                    if (!self::isU($g($k))) {
                        $c[$ck] = $g($k);
                    }
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

    /** True iff any v2 check would be reported (the PCActn carries `intent_session` or a v2 policy is active). */
    public static function intentV2Active(mixed $p, mixed $ctx): bool
    {
        return ($p instanceof Obj && $p->has('intent_session'))
            || self::cg($ctx, 'policy', 'schema', 'closed_world') === true
            || self::cg($ctx, 'policy', 'session', 'require') === true
            || self::cg($ctx, 'policy', 'map', 'require') === true;
    }
}
