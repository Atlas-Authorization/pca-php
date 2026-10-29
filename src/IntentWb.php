<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** A JS `undefined` (an absent member). Never appears in an output. */
enum JsUndefined
{
    case U;
}

/**
 * Intent Layer v2 wire batch W-B: NORMATIVE conformance rules 16 (world facts, relational dimensions, offer sets), 17
 * (per-parameter provenance, label receipts, flow rules) and 18 (classifier verdicts), and their composition
 * `decideIntentWb` (the facts -> provenance -> classes unit of the v2 verification pipeline).
 *
 * Port of packages/pca/src oracle-facts.ts, offer-set.ts, param-provenance.ts, label-receipts.ts (verifier side),
 * intent-classifier.ts, intent-env.ts, the shared plumbing of intent-artifacts.ts and the label lattice of taint.ts. Step
 * order, boundaries and reason strings follow the TypeScript reference.
 *
 * VALUES. Every input is in the Json representation (Obj, list arrays, Num, string, bool, null) as from Json::parseLax;
 * inputs are Obj trees shaped like the TS inputs (the `input` objects of primitives.intent_world / intent_provenance /
 * intent_classifier in conformance/vectors.json). The semantics are those of the TS W-B sources (d63b36e6):
 *   - ABSENT VS NULL: an optional member that is ABSENT (JsUndefined::U internally) means empty / default; one PRESENT with
 *     JSON null or of the wrong JSON type is malformed and fails closed; lists must be real arrays (never iterated as a
 *     string); `action` must be an object; activity reads own members of plain objects only;
 *   - SUITES: every W-B artifact may carry `alg` / `pq_pk` / `pq_sig` (signed body = artifact without `sig` and `pq_sig`);
 *     an `alg` this verifier does not implement fails with `unsupported_suite` before anything else about the artifact;
 *     signatures go through the library's suite dispatch (Pca::verifyPinnedSuite), a PQ half only under the PQ key the
 *     verifier pinned for that signer;
 *   - every keyed lookup and tally is over own members only (prototype-free: `__proto__`, `constructor` are data);
 *   - numbers are judged by the binary64 VALUE of the Num lexeme (2 == 2.0, a safe integer is integral with
 *     |v| <= 2^53-1 and, per intent-artifacts.ts isSafeInt, never -0), never by lexeme; scalar equality is same JSON type
 *     and value (2 != "2", true != 1);
 *   - strict canonical JSON (hashes, references, signed bytes) is taken of the JS value: every Num is first rewritten to
 *     the ECMAScript Number::toString form of its value (1.0 -> 1), then Json::canonicalizeStrict applies the strict
 *     profile (so -0, exponent forms and unsafe integers still throw, as in the reference);
 *   - Object.keys order (canonical array-index keys ascending, then insertion order) wherever the reference iterates
 *     keys without sorting.
 * Every public decide function is total: an internal error fails closed where the TS try/catch does.
 */
final class IntentWb
{
    // ---- constants -------------------------------------------------------------------------------------------------

    public const FACT_DOMAIN = "atlas-pca/fact/v1\0";
    public const FACT_REF_DOMAIN = 'atlas-pca/fact-ref/v1';
    public const MAX_COMMITTED_FACTS = 16;
    public const MAX_WORLDS = 16;
    public const MAX_RELATIONAL = 16;
    public const DEFAULT_WORLD_SKEW_MS = 60000;

    public const OFFER_SET_DOMAIN = "atlas-pca/offer-set/v1\0";
    public const OFFER_SET_REF_DOMAIN = 'atlas-pca/offer-set-ref/v1';
    public const MAX_OFFERS = 256;
    public const MAX_OFFER_ATTRS = 32;
    public const MAX_QUERY_KEYS = 32;

    public const LABELS_DOMAIN = "atlas-pca/labels/v1\0";
    public const LABELS_REF_DOMAIN = 'atlas-pca/labels-ref/v1';
    public const MAX_LABEL_FIELDS = 64;
    public const PUBLIC_CLASS = 'public';

    public const LABEL_REF_PREFIX = 'pca-labels:';
    public const MAX_PROV_PATHS = 32;
    public const MAX_PROV_REFS = 8;
    public const MAX_COMMITTED_LABELS = 16;

    public const INTENT_CLASSIFIER_DOMAIN = "atlas-pca/intent-classifier/v1\0";
    public const INTENT_CLASSIFIER_REF_DOMAIN = 'atlas-pca/intent-classifier-ref/v1';
    public const MAX_COMMITTED_CLASSES = 8;
    public const MAX_CLASSIFIER_LABELS = 32;

    /** Names of world / relational / offer dimensions and classifier ids (D: `$` never matches before a final "\n"). */
    public const INTENT_NAME_RE = '/^[a-z][a-z0-9_]{0,63}$/D';
    public const DATA_CLASS_RE = '/^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$/D';
    public const PARAM_SEGMENT_RE = '/^[A-Za-z0-9_-]{1,64}$/D';
    public const PROV_PATH_RE = '/^action\.params\.[A-Za-z0-9_]{1,64}$/D';
    private const FORBIDDEN_SEGMENTS = ['__proto__', 'constructor', 'prototype'];

    /** taint.ts label lattice: trusted 0 < first_party 1 < tool 2 < web 3 < agent 4; TAINTED = rank >= tool. */
    public const TAINT_LEVELS = ['trusted', 'first_party', 'tool', 'web', 'agent'];
    private const MAX_RANK = 4;
    private const TAINTED_RANK = 2;
    private const MODES = ['allow', 'question', 'question_typed', 'deny'];
    private const MAX_SAFE = 9007199254740991;

    private const FACT_FIELDS = ['v', 'kind', 'name', 'subject', 'value', 't_obs', 'oracle', 'sig'];
    private const OFFER_SET_FIELDS = ['v', 'kind', 'site', 'session', 'query', 'rank', 'complete', 'offers', 'issued_at', 'kid', 'sig'];
    private const LABELS_FIELDS = ['v', 'kind', 'site', 'session', 'response_digest', 'fields', 'issued_at', 'kid', 'sig'];
    private const VERDICT_FIELDS = ['v', 'kind', 'classifier', 'session', 'content_digest', 'label', 'measurement', 'judge', 'sig'];
    /** The optional suite members every W-B artifact may carry. */
    public const SUITE_MEMBERS = ['alg', 'pq_pk', 'pq_sig'];

    // ---- JS value helpers ------------------------------------------------------------------------------------------

    /** `o?.[k]`: the own member, or JsUndefined::U (absent member, or `o` not an object). */
    private static function g(mixed $o, string $k): mixed
    {
        return $o instanceof Obj && $o->has($k) ? $o->get($k) : JsUndefined::U;
    }

    private static function present(mixed $v): bool
    {
        return $v !== JsUndefined::U;
    }

    /** `x === undefined ? d : x`: ABSENT means the default; a PRESENT value (JSON null included) is kept and judged. */
    private static function absentOr(mixed $v, mixed $d): mixed
    {
        return $v === JsUndefined::U ? $d : $v;
    }

    /** The binary64 value of a JSON number (Num, or a PHP int/float), else null. */
    private static function numVal(mixed $v): ?float
    {
        if ($v instanceof Num) {
            return $v->float();
        }
        if (is_int($v)) {
            return (float)$v;
        }
        return is_float($v) ? $v : null;
    }

    private static function isNegZero(float $f): bool
    {
        return $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    /** intent-artifacts.ts isSafeInt: a number, Number.isSafeInteger by VALUE, and not -0. */
    public static function isSafeInt(mixed $v): bool
    {
        if (is_int($v)) {
            return $v >= -self::MAX_SAFE && $v <= self::MAX_SAFE;
        }
        $f = self::numVal($v);
        return $f !== null && is_finite($f) && floor($f) === $f && abs($f) <= self::MAX_SAFE && !self::isNegZero($f);
    }

    /** A safe-integer JSON number as a PHP int (callers check isSafeInt first). */
    private static function intOf(mixed $v): int
    {
        return is_int($v) ? $v : (int)self::numVal($v);
    }

    private static function num(int $i): Num
    {
        return new Num((string)$i);
    }

    public static function isBoundedString(mixed $v, int $max): bool
    {
        return is_string($v) && $v !== '' && strlen($v) <= $max;
    }

    public static function isDigest(mixed $v): bool
    {
        return Pca::unb64u($v, 32) !== null;
    }

    private static function isScalar(mixed $v): bool
    {
        return is_string($v) || is_bool($v) || self::isSafeInt($v);
    }

    /** Scalar equality: same JSON type and value (2 == 2.0; 2 != "2"; true != 1). Objects / arrays: never equal. */
    public static function scalarEq(mixed $a, mixed $b): bool
    {
        $fa = self::numVal($a);
        $fb = self::numVal($b);
        if ($fa !== null || $fb !== null) {
            return $fa !== null && $fb !== null && $fa === $fb;
        }
        if (is_array($a) || is_array($b)) {
            return false; // distinct JS arrays are never ===
        }
        return $a === $b; // string, bool, null, Undef by value; Obj by identity
    }

    /** `v === 1` for a JSON number. */
    private static function isOne(mixed $v): bool
    {
        return self::numVal($v) === 1.0;
    }

    /** Object.keys order: canonical array-index keys ascending numerically, then the other keys in insertion order. */
    public static function jsKeys(Obj $o): array
    {
        $idx = [];
        $rest = [];
        foreach ($o->keys() as $k) {
            if (preg_match('/^(?:0|[1-9][0-9]{0,9})$/D', $k) === 1 && (int)$k <= 4294967294) {
                $idx[] = $k;
            } else {
                $rest[] = $k;
            }
        }
        usort($idx, static fn(string $a, string $b): int => (int)$a <=> (int)$b);
        return array_merge($idx, $rest);
    }

    /** Distinct list (JS `new Set(xs).size === xs.length`) for a list of strings. */
    private static function distinct(array $xs): bool
    {
        $seen = [];
        foreach ($xs as $x) {
            $k = 'k' . (is_string($x) ? $x : serialize($x));
            if (isset($seen[$k])) {
                return false;
            }
            $seen[$k] = true;
        }
        return true;
    }

    /** ECMAScript Number::toString of a binary64. */
    public static function jsNumStr(float $v): string
    {
        if (is_nan($v)) {
            return 'NaN';
        }
        if (is_infinite($v)) {
            return $v > 0 ? 'Infinity' : '-Infinity';
        }
        if ($v === 0.0) {
            return '0';
        }
        $sign = $v < 0 ? '-' : '';
        $a = abs($v);
        $s = '';
        for ($p = 1; $p <= 17; $p++) { // the SHORTEST round-tripping digit string (correctly rounded, so the closest)
            $s = sprintf('%.' . ($p - 1) . 'e', $a);
            if ((float)$s === $a) {
                break;
            }
        }
        [$mant, $exp] = explode('e', $s);
        $digits = rtrim(str_replace('.', '', $mant), '0');
        if ($digits === '') {
            $digits = '0';
        }
        $k = strlen($digits);
        $n = (int)$exp + 1; // value = 0.digits * 10^n
        if ($k <= $n && $n <= 21) {
            return $sign . $digits . str_repeat('0', $n - $k);
        }
        if (0 < $n && $n <= 21) {
            return $sign . substr($digits, 0, $n) . '.' . substr($digits, $n);
        }
        if (-6 < $n && $n <= 0) {
            return $sign . '0.' . str_repeat('0', -$n) . $digits;
        }
        $e = $n - 1;
        $es = ($e > 0 ? '+' : '-') . abs($e);
        return $sign . ($k === 1 ? $digits : $digits[0] . '.' . substr($digits, 1)) . 'e' . $es;
    }

    /** ECMAScript String(v) for JSON values (template-literal interpolation in reasons). */
    public static function jsStr(mixed $v): string
    {
        if ($v === JsUndefined::U) {
            return 'undefined';
        }
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (is_string($v)) {
            return $v;
        }
        $f = self::numVal($v);
        if ($f !== null) {
            return self::jsNumStr($f);
        }
        if (is_array($v)) {
            return implode(',', array_map(static fn(mixed $x): string => $x === null || $x === JsUndefined::U ? '' : self::jsStr($x), $v));
        }
        return '[object Object]';
    }

    // ---- canonical JSON of JS values -------------------------------------------------------------------------------

    /** Rewrite every Num to the Number::toString form of its value (the JS value JSON.parse yields), recursively. */
    private static function norm(mixed $v): mixed
    {
        if ($v instanceof Num || is_int($v) || is_float($v)) {
            $f = self::numVal($v);
            if (!is_finite($f)) {
                return $v instanceof Num ? $v : new Num('1e999'); // refused by the strict profile, as in the reference
            }
            if (self::isNegZero($f)) {
                return new Num('-0'); // refused: negative zero
            }
            return new Num(floor($f) === $f && abs($f) <= self::MAX_SAFE ? sprintf('%.0f', $f) : self::jsNumStr($f));
        }
        if (is_array($v)) {
            return array_map([self::class, 'norm'], $v);
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::norm($v->get($k)));
            }
            return $o;
        }
        return $v;
    }

    /** strictCanonical(value) of the JS value. Throws JsonError on any strict-profile violation. */
    public static function canon(mixed $v): string
    {
        return Json::canonicalizeStrict(self::norm($v));
    }

    /** b64u(sha256(strictCanonical(value))) of the JS value. Throws JsonError when not strictly canonical. */
    private static function hc(mixed $v): string
    {
        return Pca::hashCanonical(self::norm($v));
    }

    // ---- shared artifact plumbing (intent-artifacts.ts) ------------------------------------------------------------

    public static function isPathSegment(mixed $s): bool
    {
        return is_string($s) && preg_match(self::PARAM_SEGMENT_RE, $s) === 1 && !in_array($s, self::FORBIDDEN_SEGMENTS, true);
    }

    /** True iff `path` is a well-formed `action.params.*` path (1..8 segments). */
    public static function isParamPath(mixed $path): bool
    {
        if (!is_string($path) || !str_starts_with($path, 'action.params.')) {
            return false;
        }
        $segs = explode('.', substr($path, strlen('action.params.')));
        if (count($segs) < 1 || count($segs) > 8) {
            return false;
        }
        foreach ($segs as $s) {
            if (!self::isPathSegment($s)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Resolve `action.params.<a>.<b>…` inside `params` (own members only).
     * @return array{found: bool, value?: mixed}
     */
    public static function resolveParamPath(mixed $params, mixed $path): array
    {
        if (!is_string($path) || !str_starts_with($path, 'action.params.')) {
            return ['found' => false];
        }
        $cur = $params;
        foreach (explode('.', substr($path, strlen('action.params.'))) as $s) {
            if (!self::isPathSegment($s) || !($cur instanceof Obj) || !$cur->has($s)) {
                return ['found' => false];
            }
            $cur = $cur->get($s);
        }
        return ['found' => true, 'value' => $cur];
    }

    /** Set `value` at the dotted `path` under `root`; false (nothing usable changed) when it collides with a leaf or subtree. */
    private static function setNested(Obj $root, string $path, mixed $value): bool
    {
        $segs = explode('.', $path);
        $cur = $root;
        for ($i = 0; $i < count($segs) - 1; $i++) {
            $k = $segs[$i];
            if (!$cur->has($k)) {
                $cur->set($k, new Obj());
            }
            $next = $cur->get($k);
            if (!($next instanceof Obj)) {
                return false;
            }
            $cur = $next;
        }
        $last = $segs[count($segs) - 1];
        if ($cur->has($last)) {
            return false;
        }
        $cur->set($last, $value);
        return true;
    }

    /** Closed member set check: null when `o` has exactly the `required` members plus any of `optional`. */
    public static function closedMembers(Obj $o, array $required, array $optional = [], string $where = 'object'): ?string
    {
        foreach (self::jsKeys($o) as $k) {
            if (!in_array($k, $required, true) && !in_array($k, $optional, true)) {
                return "unknown member '$where.$k'";
            }
        }
        foreach ($required as $k) {
            if (!$o->has($k)) {
                return "missing member '$where.$k'";
            }
        }
        return null;
    }

    /** Validate a pin's optional `pq_pk` (absent, or a non-empty string; JSON null is malformed). */
    public static function pinPqOk(mixed $v): bool
    {
        return $v === JsUndefined::U || (is_string($v) && $v !== '');
    }

    /**
     * Suite capability and shape of an artifact's suite members (intent-artifacts.ts artifactSuiteError). Null = usable. A
     * non-string `alg` (null included) is malformed; an `alg` this verifier does not implement yields a reason containing
     * `unsupported_suite`; non-string `pq_pk` / `pq_sig` are malformed; an ed25519 artifact (alg absent or "ed25519") must
     * carry neither `pq_pk` nor `pq_sig`.
     */
    public static function artifactSuiteError(mixed $a): ?string
    {
        if (!($a instanceof Obj)) {
            return 'artifact must be an object';
        }
        $alg = self::g($a, 'alg');
        if ($alg !== JsUndefined::U) {
            if (!is_string($alg)) {
                return 'alg must be a string';
            }
            if (!Pca::suiteImplemented($alg)) {
                return Pca::UNSUPPORTED_SUITE . ": '$alg'";
            }
        }
        foreach (['pq_pk', 'pq_sig'] as $k) {
            $v = self::g($a, $k);
            if ($v !== JsUndefined::U && !is_string($v)) {
                return "$k must be a string";
            }
        }
        if (($alg === JsUndefined::U || $alg === 'ed25519') && ($a->has('pq_pk') || $a->has('pq_sig'))) {
            return 'an ed25519 artifact must not carry pq_pk / pq_sig';
        }
        return null;
    }

    /** utf8(domain) || strictCanonical(artifact without `sig` / `pq_sig`) (`alg` and `pq_pk` are signed). Throws on a non-canonical body. */
    public static function artifactMessage(string $domain, Obj $artifact): string
    {
        return $domain . self::canon($artifact->without('sig', 'pq_sig'));
    }

    /**
     * Verify an artifact's signature under a PINNED signer (the caller has checked artifactSuiteError): `$pin` is the pin
     * entry (an Obj with `pk` and optional `pq_pk`) or a bare b64u Ed25519 key. Ed25519 under the pin's `pk`; any other
     * suite only when the artifact's `pq_pk` equals the pin's `pq_pk` (through the library's suite dispatch,
     * Pca::verifyPinnedSuite). Total: false on any malformed input.
     */
    public static function verifyArtifactSig(string $domain, mixed $artifact, mixed $pin): bool
    {
        try {
            $pk = $pin instanceof Obj ? self::g($pin, 'pk') : $pin;
            $pinPq = $pin instanceof Obj ? self::g($pin, 'pq_pk') : JsUndefined::U;
            if (!($artifact instanceof Obj) || !is_string(self::g($artifact, 'sig')) || !is_string($pk)) {
                return false;
            }
            $alg = self::g($artifact, 'alg');
            $apq = self::g($artifact, 'pq_pk');
            $pqSig = self::g($artifact, 'pq_sig');
            return Pca::verifyPinnedSuite($alg === JsUndefined::U ? null : $alg, $pk, $apq === JsUndefined::U ? null : $apq,
                self::artifactMessage($domain, $artifact), $artifact->get('sig'), $pqSig === JsUndefined::U ? null : $pqSig,
                is_string($pinPq) ? $pinPq : null) === true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Content address (signature included): b64u(sha256(strictCanonical({d, [slot]: artifact}))). Throws when not canonical. */
    public static function artifactRef(string $refDomain, string $slot, mixed $artifact): string
    {
        $o = new Obj();
        $o->set('d', $refDomain);
        $o->set($slot, $artifact);
        return self::hc($o);
    }

    /** b64u(sha256(strictCanonical(value))): a label field's `value_digest`. Throws when not strictly canonical. */
    public static function valueDigest(mixed $value): string
    {
        return self::hc($value);
    }

    /** The content digest a classifier verdict binds (same construction as valueDigest). */
    public static function contentDigest(mixed $value): string
    {
        return self::hc($value);
    }

    public static function factRef(mixed $f): string
    {
        return self::artifactRef(self::FACT_REF_DOMAIN, 'f', $f);
    }

    public static function offerSetRef(mixed $o): string
    {
        return self::artifactRef(self::OFFER_SET_REF_DOMAIN, 'o', $o);
    }

    public static function labelReceiptRef(mixed $l): string
    {
        return self::artifactRef(self::LABELS_REF_DOMAIN, 'l', $l);
    }

    public static function classifierVerdictRef(mixed $v): string
    {
        return self::artifactRef(self::INTENT_CLASSIFIER_REF_DOMAIN, 'c', $v);
    }

    // ---- rule 16: oracle facts -------------------------------------------------------------------------------------

    /** Wire validation of a fact. Null = well-formed. */
    public static function validateFactWire(mixed $f): ?string
    {
        if (!($f instanceof Obj)) {
            return 'fact must be an object';
        }
        $m = self::closedMembers($f, self::FACT_FIELDS, self::SUITE_MEMBERS, 'fact');
        if ($m !== null) {
            return $m;
        }
        if (!self::isOne($f->get('v')) || $f->get('kind') !== 'pca-fact') {
            return 'fact must be {v: 1, kind: "pca-fact"}';
        }
        $name = $f->get('name');
        if (!is_string($name) || preg_match(self::INTENT_NAME_RE, $name) !== 1) {
            return "'fact.name' must match ^[a-z][a-z0-9_]{0,63}$";
        }
        if (!self::isBoundedString($f->get('subject'), 256)) {
            return "'fact.subject' must be a non-empty string (<= 256 bytes)";
        }
        if (!self::isSafeInt($f->get('value')) && !self::isBoundedString($f->get('value'), 256)) {
            return "'fact.value' must be a safe integer or a non-empty string (<= 256 bytes)";
        }
        if (!self::isSafeInt($f->get('t_obs')) || self::intOf($f->get('t_obs')) < 0) {
            return "'fact.t_obs' must be a non-negative safe integer";
        }
        if (!self::isBoundedString($f->get('oracle'), 64)) {
            return "'fact.oracle' must be a non-empty string (<= 64 bytes)";
        }
        if (!is_string($f->get('sig'))) {
            return "'fact.sig' must be a string";
        }
        return null;
    }

    /** The lower median of a non-empty list of integers (index floor((n-1)/2) ascending). */
    public static function lowerMedian(array $xs): int
    {
        if (count($xs) === 0) {
            throw new \RuntimeException('lowerMedian: empty');
        }
        sort($xs, SORT_NUMERIC);
        return $xs[intdiv(count($xs) - 1, 2)];
    }

    /** floor(a * 10^6 / b) in exact integer arithmetic, or null when b <= 0, a < 0 or the result is not a safe integer. */
    public static function ratioPpm(mixed $a, mixed $b): ?int
    {
        // total (45a1599e): only safe integers are divided (anything else has no exact ratio)
        if (!is_int($a) || !is_int($b) || abs($a) > self::MAX_SAFE || abs($b) > self::MAX_SAFE || !($b > 0) || $a < 0) {
            return null;
        }
        $q = intdiv($a, $b);
        $r = $a % $b;
        $frac = 0;
        for ($i = 0; $i < 6; $i++) { // long division: r < b <= 2^53, so 10*r never overflows
            $r *= 10;
            $frac = $frac * 10 + intdiv($r, $b);
            $r %= $b;
        }
        if ($q > intdiv(self::MAX_SAFE - $frac, 1000000)) {
            return null;
        }
        return $q * 1000000 + $frac;
    }

    /** Policy sanity for an offer policy. Null = well-formed. */
    public static function validateOfferPolicy(mixed $p): ?string
    {
        if (!($p instanceof Obj)) {
            return 'offers policy must be an object';
        }
        $cm = self::closedMembers($p, ['name', 'site_keys', 'max_age_ms', 'offer_param', 'filter'], [], 'offers');
        if ($cm !== null) {
            return $cm;
        }
        if (!is_string(self::g($p, 'name'))) {
            return 'offers policy needs a name';
        }
        $sk = self::g($p, 'site_keys');
        if (!is_array($sk) || count($sk) === 0) {
            return 'offers policy needs at least one pinned site key';
        }
        $kids = [];
        foreach ($sk as $k) {
            if (!($k instanceof Obj) || self::closedMembers($k, ['kid', 'pk'], ['pq_pk'], 'site_key') !== null
                || !self::isBoundedString(self::g($k, 'kid'), 64) || !self::isDigest(self::g($k, 'pk'))
                || !self::pinPqOk(self::g($k, 'pq_pk')) || isset($kids['k' . $k->get('kid')])) {
                return 'offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk';
            }
            $kids['k' . $k->get('kid')] = true;
        }
        $mx = self::g($p, 'max_age_ms');
        if (!self::isSafeInt($mx) || self::intOf($mx) < 0) {
            return 'offers policy: max_age_ms must be a non-negative safe integer';
        }
        $op = self::g($p, 'offer_param');
        if (!is_string($op) || !str_starts_with($op, 'action.params.')) {
            return 'offers policy: offer_param must be an action.params.* path';
        }
        $f = self::g($p, 'filter');
        if (!($f instanceof Obj) || self::closedMembers($f, ['query', 'offer'], [], 'filter') !== null
            || !(self::g($f, 'query') instanceof Obj) || !(self::g($f, 'offer') instanceof Obj)) {
            return 'offers policy: filter must be exactly {query: {}, offer: {}}';
        }
        foreach ([$f->get('query'), $f->get('offer')] as $part) {
            foreach (self::jsKeys($part) as $k) {
                if (!self::isScalar($part->get($k))) {
                    return 'offers policy: filter values must be scalars';
                }
            }
        }
        return null;
    }

    /** Rule 16 policy sanity (step 0). Null = well-formed. */
    public static function validateWorldPolicy(mixed $p): ?string
    {
        if (!($p instanceof Obj)) {
            return 'world policy must be an object';
        }
        // Closed member sets everywhere (README "closed and typed"): an unknown member is malformed.
        $cm = self::closedMembers($p, [], ['skew_ms', 'worlds', 'relational', 'offers'], 'policy');
        if ($cm !== null) {
            return $cm;
        }
        $skew = self::g($p, 'skew_ms');
        if (self::present($skew) && (!self::isSafeInt($skew) || self::intOf($skew) < 0)) {
            return 'skew_ms must be a non-negative safe integer';
        }
        $names = [];
        $claim = static function (mixed $n) use (&$names): ?string {
            if (!is_string($n) || preg_match(self::INTENT_NAME_RE, $n) !== 1) {
                return "dimension name '" . self::jsStr($n) . "' must match ^[a-z][a-z0-9_]{0,63}$";
            }
            if (isset($names['k' . $n])) {
                return "duplicate dimension name '$n'";
            }
            $names['k' . $n] = true;
            return null;
        };
        $worlds = self::absentOr(self::g($p, 'worlds'), []); // absent = []; null or any non-array is malformed
        if (!is_array($worlds) || count($worlds) > self::MAX_WORLDS) {
            return 'worlds must be a list of at most ' . self::MAX_WORLDS;
        }
        foreach ($worlds as $w) {
            if (!($w instanceof Obj)) {
                return 'world entry must be an object';
            }
            $wm = self::closedMembers($w, ['name', 'subject_path', 'oracles', 'freshness_ms', 'min_oracles', 'max_faulty'], [], 'world');
            if ($wm !== null) {
                return $wm;
            }
            $e = $claim(self::g($w, 'name'));
            if ($e !== null) {
                return $e;
            }
            $wn = $w->get('name');
            $sp = self::g($w, 'subject_path');
            if (!is_string($sp) || !str_starts_with($sp, 'action.')) {
                return "world '$wn': subject_path must be rooted at action.";
            }
            $fr = self::g($w, 'freshness_ms');
            if (!self::isSafeInt($fr) || self::intOf($fr) < 0) {
                return "world '$wn': freshness_ms must be a non-negative safe integer";
            }
            $mf = self::g($w, 'max_faulty');
            if (!self::isSafeInt($mf) || self::intOf($mf) < 0) {
                return "world '$wn': max_faulty must be a non-negative safe integer";
            }
            $mo = self::g($w, 'min_oracles');
            if (!self::isSafeInt($mo) || self::intOf($mo) < 2 * self::intOf($mf) + 1) {
                return "world '$wn': min_oracles must be a safe integer >= 2*max_faulty+1";
            }
            $ors = self::g($w, 'oracles');
            if (!is_array($ors) || count($ors) < self::intOf($mo)) {
                return "world '$wn': fewer pinned oracles than min_oracles";
            }
            $kids = [];
            foreach ($ors as $o) {
                if (!($o instanceof Obj) || self::closedMembers($o, ['kid', 'pk'], ['pq_pk'], 'oracle') !== null || !self::isBoundedString(self::g($o, 'kid'), 64) || !self::isDigest(self::g($o, 'pk'))
                    || !self::pinPqOk(self::g($o, 'pq_pk')) || isset($kids['k' . $o->get('kid')])) {
                    return "world '$wn': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk";
                }
                $kids['k' . $o->get('kid')] = true;
            }
        }
        $rel = self::absentOr(self::g($p, 'relational'), []);
        if (!is_array($rel) || count($rel) > self::MAX_RELATIONAL) {
            return 'relational must be a list of at most ' . self::MAX_RELATIONAL;
        }
        foreach ($rel as $r) {
            if (!($r instanceof Obj)) {
                return 'relational entry must be an object';
            }
            $rm = self::closedMembers($r, ['name', 'fn', 'a', 'b'], [], 'relational');
            if ($rm !== null) {
                return $rm;
            }
            $e = $claim(self::g($r, 'name'));
            if ($e !== null) {
                return $e;
            }
            $rn = $r->get('name');
            $fn = self::g($r, 'fn');
            if ($fn !== 'sub' && $fn !== 'ratio_ppm') {
                return "relational '$rn': fn must be \"sub\" or \"ratio_ppm\"";
            }
            foreach ([self::g($r, 'a'), self::g($r, 'b')] as $op) {
                $ok = self::isParamPath($op);
                if (!$ok && is_string($op) && str_starts_with($op, 'env.world.')) {
                    $ref = substr($op, strlen('env.world.'));
                    $ok = isset($names['k' . $ref]) && $ref !== $rn;
                }
                if (!$ok) {
                    return "relational '$rn': operand '" . self::jsStr($op) . "' must be an action.params path or an earlier env.world dimension";
                }
            }
        }
        $offers = self::g($p, 'offers');
        if (self::present($offers)) {
            $e = self::validateOfferPolicy($offers) ?? $claim($offers->get('name'));
            if ($e !== null) {
                return $e;
            }
        }
        return null;
    }

    /**
     * Is the rule-16 check active? Iff `committed.facts` is a non-empty ARRAY, `committed.offer_set` is a STRING,
     * `policy.worlds` or `policy.relational` is a non-empty ARRAY, or `policy.offers` is a plain object (strict typing:
     * an object with its own `length` member is not an array).
     */
    public static function intentWorldActive(mixed $input): bool
    {
        // own members of plain objects only: a container that is absent or not an object has no members
        $c = self::g($input, 'committed');
        $p = self::g($input, 'policy');
        $nonEmpty = static fn(mixed $x): bool => is_array($x) && count($x) > 0;
        return $nonEmpty(self::g($c, 'facts')) || is_string(self::g($c, 'offer_set')) || $nonEmpty(self::g($p, 'worlds'))
            || $nonEmpty(self::g($p, 'relational')) || self::g($p, 'offers') instanceof Obj;
    }

    private static function subjectOf(Obj $action, Obj $params, string $path): ?string
    {
        if ($path === 'action.resource') {
            $r = self::g($action, 'resource');
            return is_string($r) ? $r : null;
        }
        if ($path === 'action.verb') {
            $v = self::g($action, 'verb');
            return is_string($v) ? $v : null;
        }
        $r = self::resolveParamPath($params, $path);
        return $r['found'] && is_string($r['value']) ? $r['value'] : null;
    }

    /**
     * NORMATIVE rule 16 (`facts`): compute `env.world` for one action. First failure wins (see oracle-facts.ts
     * decideIntentWorld for the steps). Never throws.
     * @return array{ok: bool, world?: Obj, single_source?: list<string>, reason?: string}
     */
    public static function decideIntentWorld(mixed $input): array
    {
        $fail = static fn(string $reason): array => ['ok' => false, 'reason' => "facts: $reason"];
        try {
            if (!($input instanceof Obj)) {
                return $fail('input must be an object');
            }
            // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail closed.
            $policy = self::absentOr(self::g($input, 'policy'), new Obj());
            $pe = self::validateWorldPolicy($policy);
            if ($pe !== null) {
                return $fail("policy misconfigured (fail closed): $pe");
            }
            $skew = self::absentOr(self::g($policy, 'skew_ms'), self::DEFAULT_WORLD_SKEW_MS); // validated: never null
            $action = self::g($input, 'action');
            if (!($action instanceof Obj)) {
                return $fail('action must be an object');
            }
            $params = self::absentOr(self::g($action, 'params'), new Obj());
            if (!($params instanceof Obj)) {
                return $fail('action.params must be an object');
            }
            $committed = self::absentOr(self::g($input, 'committed'), new Obj());
            if (!($committed instanceof Obj)) {
                return $fail('committed must be an object');
            }
            $committedFacts = self::absentOr(self::g($committed, 'facts'), []);
            if (!is_array($committedFacts) || count($committedFacts) > self::MAX_COMMITTED_FACTS) {
                return $fail('committed facts must be a list of at most ' . self::MAX_COMMITTED_FACTS . ' digests');
            }
            $seen = [];
            foreach ($committedFacts as $d) {
                if (!self::isDigest($d)) {
                    return $fail('a committed fact digest is not canonical base64url (32 bytes)');
                }
                if (isset($seen['k' . $d])) {
                    return $fail('duplicate committed fact digest');
                }
                $seen['k' . $d] = true;
            }
            $committedOffer = self::g($committed, 'offer_set');
            if (self::present($committedOffer) && !self::isDigest($committedOffer)) {
                return $fail('the committed offer_set is not canonical base64url (32 bytes)');
            }

            $supplied = self::absentOr(self::g($input, 'facts'), []);
            if (!is_array($supplied)) {
                return $fail('facts must be an array');
            }
            $offerSet = self::g($input, 'offer_set');
            if ($offerSet !== JsUndefined::U && !($offerSet instanceof Obj)) {
                return $fail('offer_set must be an object');
            }
            $byRef = [];
            foreach ($supplied as $f) {
                if (self::validateFactWire($f) !== null) {
                    continue; // an unusable supplied fact can only matter if committed: caught below
                }
                try {
                    $byRef['k' . self::factRef($f)] = $f;
                } catch (\Throwable) {
                    // not strictly canonical: it has no reference, so it can never match a commitment
                }
            }
            $worlds = self::absentOr(self::g($policy, 'worlds'), []);
            $accepted = [];
            $pairs = [];
            foreach ($committedFacts as $d) {
                $fact = $byRef['k' . $d] ?? null;
                if ($fact === null) {
                    return $fail('a committed fact was not supplied (or is malformed)');
                }
                $se = self::artifactSuiteError($fact);
                if ($se !== null) {
                    return $fail("fact signature suite: $se");
                }
                $fname = $fact->get('name');
                $w = null;
                foreach ($worlds as $x) {
                    if ($x->get('name') === $fname) {
                        $w = $x;
                        break;
                    }
                }
                if ($w === null) {
                    return $fail("fact for undeclared world '$fname'");
                }
                $wn = $w->get('name');
                $oracle = $fact->get('oracle');
                $pin = null;
                foreach ($w->get('oracles') as $o) {
                    if ($o->get('kid') === $oracle) {
                        $pin = $o;
                        break;
                    }
                }
                if ($pin === null) {
                    return $fail("oracle '$oracle' is not pinned for world '$wn'");
                }
                if (!self::verifyArtifactSig(self::FACT_DOMAIN, $fact, $pin)) {
                    return $fail("bad oracle signature on a '$wn' fact");
                }
                $subject = self::subjectOf($action, $params, $w->get('subject_path'));
                if ($subject === null || $fact->get('subject') !== $subject) {
                    return $fail("a '$wn' fact names another subject");
                }
                $pair = 'k' . $wn . "\0" . $oracle;
                if (isset($pairs[$pair])) {
                    return $fail("two facts from oracle '$oracle' for world '$wn'");
                }
                $pairs[$pair] = true;
                $accepted[] = $fact;
            }

            $world = new Obj();
            $singleSource = [];
            $now = self::g($input, 'now');
            // A non-safe-integer `now` (a string, a fraction, null) is no clock: every fact is stale (never coerced).
            $clock = self::isSafeInt($now);
            foreach ($worlds as $w) {
                $wn = $w->get('name');
                $fresh = [];
                if ($clock) {
                    $n = self::intOf($now);
                    $sk = self::intOf($skew);
                    $fm = self::intOf($w->get('freshness_ms'));
                    foreach ($accepted as $f) {
                        $t = self::intOf($f->get('t_obs'));
                        if ($f->get('name') === $wn && $t <= $n + $sk && $n - $t <= $fm) {
                            $fresh[] = $f;
                        }
                    }
                }
                $mo = self::intOf($w->get('min_oracles'));
                if (count($fresh) < $mo) {
                    return $fail("world '$wn' has " . count($fresh) . " fresh fact(s), needs $mo");
                }
                $nums = [];
                foreach ($fresh as $f) {
                    if (!is_string($f->get('value'))) {
                        $nums[] = self::intOf($f->get('value'));
                    }
                }
                if (count($nums) === count($fresh)) {
                    $world->set($wn, self::num(self::lowerMedian($nums)));
                } elseif (count($nums) === 0) {
                    $v = $fresh[0]->get('value');
                    foreach ($fresh as $f) {
                        if ($f->get('value') !== $v) {
                            return $fail("world '$wn': string facts disagree");
                        }
                    }
                    $world->set($wn, $v);
                } else {
                    return $fail("world '$wn': facts mix integer and string values");
                }
                if ($mo === 1) {
                    $singleSource[] = $wn;
                }
            }

            $operand = static function (string $path) use ($world, $params): ?int {
                if (str_starts_with($path, 'env.world.')) {
                    $v = self::g($world, substr($path, strlen('env.world.')));
                    return self::isSafeInt($v) ? self::intOf($v) : null;
                }
                $r = self::resolveParamPath($params, $path);
                return $r['found'] && self::isSafeInt($r['value']) ? self::intOf($r['value']) : null;
            };
            foreach (self::absentOr(self::g($policy, 'relational'), []) as $r) {
                $rn = $r->get('name');
                $a = $operand($r->get('a'));
                $b = $operand($r->get('b'));
                if ($a === null || $b === null) {
                    return $fail("relational '$rn': an operand is missing or not a safe integer");
                }
                $v = $r->get('fn') === 'sub' ? $a - $b : self::ratioPpm($a, $b);
                if ($v === null || !self::isSafeInt($v)) {
                    return $fail("relational '$rn': result undefined or outside the safe integer range");
                }
                $world->set($rn, self::num($v));
            }

            $offers = self::g($policy, 'offers');
            if (self::present($offers)) {
                $od = self::decideOfferSet(
                    $offers,
                    $committedOffer,
                    $offerSet,
                    $params,
                    self::g($input, 'aud'),
                    self::g($input, 'session'),
                    $now,
                    $skew,
                );
                if (!$od['ok']) {
                    return $fail($od['reason']);
                }
                $world->set($offers->get('name'), self::num($od['excess']));
            }
            return ['ok' => true, 'world' => $world, 'single_source' => $singleSource];
        } catch (\Throwable $e) {
            return $fail('evaluation error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- rule 16 step 6: offer sets --------------------------------------------------------------------------------

    /** Wire validation of an offer set. Null = well-formed. */
    public static function validateOfferSetWire(mixed $o): ?string
    {
        if (!($o instanceof Obj)) {
            return 'offer set must be an object';
        }
        $m = self::closedMembers($o, self::OFFER_SET_FIELDS, self::SUITE_MEMBERS, 'offer_set');
        if ($m !== null) {
            return $m;
        }
        if (!self::isOne($o->get('v')) || $o->get('kind') !== 'pca-offer-set') {
            return 'offer set must be {v: 1, kind: "pca-offer-set"}';
        }
        if (!self::isBoundedString($o->get('site'), 256)) {
            return "'offer_set.site' must be a non-empty string (<= 256 bytes)";
        }
        if (!self::isDigest($o->get('session'))) {
            return "'offer_set.session' must be canonical base64url (32 bytes)";
        }
        $q = $o->get('query');
        if (!($q instanceof Obj) || count($q->keys()) > self::MAX_QUERY_KEYS) {
            return "'offer_set.query' must be an object with <= " . self::MAX_QUERY_KEYS . ' keys';
        }
        foreach (self::jsKeys($q) as $k) {
            if (!self::isBoundedString($k, 64) || !self::isScalar($q->get($k))) {
                return "'offer_set.query.$k' must be a scalar";
            }
        }
        if ($o->get('rank') !== 'price_asc') {
            return "'offer_set.rank' must be \"price_asc\"";
        }
        if (!is_bool($o->get('complete'))) {
            return "'offer_set.complete' must be a boolean";
        }
        $offers = $o->get('offers');
        if (!is_array($offers) || count($offers) === 0 || count($offers) > self::MAX_OFFERS) {
            return "'offer_set.offers' must hold 1.." . self::MAX_OFFERS . ' offers';
        }
        $ids = [];
        foreach ($offers as $i => $of) {
            if (!($of instanceof Obj)) {
                return "offer $i must be an object";
            }
            $oid = self::g($of, 'offer_id');
            if (!self::isBoundedString($oid, 128)) {
                return "offer $i: 'offer_id' must be a non-empty string (<= 128 bytes)";
            }
            if (isset($ids['k' . $oid])) {
                return "offer $i: duplicate offer_id";
            }
            $ids['k' . $oid] = true;
            $price = self::g($of, 'price');
            if (!self::isSafeInt($price) || self::intOf($price) < 0) {
                return "offer $i: 'price' must be a non-negative safe integer";
            }
            $attrs = array_values(array_filter(self::jsKeys($of), static fn(string $k): bool => $k !== 'offer_id' && $k !== 'price'));
            if (count($attrs) > self::MAX_OFFER_ATTRS) {
                return "offer $i: more than " . self::MAX_OFFER_ATTRS . ' attributes';
            }
            foreach ($attrs as $k) {
                if (!self::isBoundedString($k, 64) || !self::isScalar($of->get($k))) {
                    return "offer $i: attribute '$k' must be a scalar";
                }
            }
        }
        if (!self::isSafeInt($o->get('issued_at')) || self::intOf($o->get('issued_at')) < 0) {
            return "'offer_set.issued_at' must be a non-negative safe integer";
        }
        if (!self::isBoundedString($o->get('kid'), 64)) {
            return "'offer_set.kid' must be a non-empty string (<= 64 bytes)";
        }
        if (!is_string($o->get('sig'))) {
            return "'offer_set.sig' must be a string";
        }
        return null;
    }

    /** Does an offer satisfy the offer part of the intent filter (every key an own member and scalar-equal)? */
    public static function offerMatches(mixed $offer, mixed $f): bool
    {
        if (!($offer instanceof Obj) || !($f instanceof Obj)) {
            return false;
        }
        foreach (self::jsKeys($f) as $k) {
            if (!$offer->has($k) || !self::scalarEq($offer->get($k), $f->get($k))) {
                return false;
            }
        }
        return true;
    }

    /** Coverage: keys(query) within keys(filter.query) with scalar-equal values (the search was not narrowed). */
    public static function queryCovers(mixed $query, mixed $fq): bool
    {
        if (!($query instanceof Obj) || !($fq instanceof Obj)) {
            return false;
        }
        foreach (self::jsKeys($query) as $k) {
            if (!$fq->has($k) || !self::scalarEq($fq->get($k), $query->get($k))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Rule 16 step 6 (offer-set.ts decideOfferSet). `$committed` / `$o` are JsUndefined::U when absent. A policy that fails
     * validateOfferPolicy is refused first; any internal error is an `offers` refusal (never throws, 45a1599e).
     * @return array{ok: bool, excess?: int, chosen_price?: int, min_price?: int, reason?: string}
     */
    private static function decideOfferSet(mixed $policy, mixed $committed, mixed $o, mixed $params, mixed $aud, mixed $session, mixed $now, mixed $skewMs): array
    {
        try {
            $pe = self::validateOfferPolicy($policy);
            if ($pe !== null) {
                return ['ok' => false, 'reason' => "offers: policy misconfigured (fail closed): $pe"];
            }
            return self::decideOfferSetInner($policy, $committed, $o, $params, $aud, $session, $now, $skewMs);
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'offers: evaluation error (fail closed): ' . $e->getMessage()];
        }
    }

    private static function decideOfferSetInner(Obj $policy, mixed $committed, mixed $o, mixed $params, mixed $aud, mixed $session, mixed $now, mixed $skewMs): array
    {
        $no = static fn(string $r): array => ['ok' => false, 'reason' => "offers: $r"];
        if ($committed === JsUndefined::U) {
            return $no('the PCActn commits no offer set but the policy requires one');
        }
        if ($o === JsUndefined::U) {
            return $no('the committed offer set was not supplied');
        }
        $w = self::validateOfferSetWire($o);
        if ($w !== null) {
            return $no($w);
        }
        try {
            $ref = self::offerSetRef($o);
        } catch (\Throwable) {
            return $no('the offer set is not strictly canonical');
        }
        if ($ref !== $committed) {
            return $no('the supplied offer set does not match the committed reference');
        }
        $se = self::artifactSuiteError($o);
        if ($se !== null) {
            return $no("signature suite: $se");
        }
        $kid = $o->get('kid');
        $key = null;
        foreach ($policy->get('site_keys') as $k) {
            if ($k->get('kid') === $kid) {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            return $no("signing key '$kid' is not pinned");
        }
        if (!self::verifyArtifactSig(self::OFFER_SET_DOMAIN, $o, $key)) {
            return $no('bad site signature');
        }
        if ($o->get('site') !== $aud) {
            return $no('the offer set was issued for another audience');
        }
        if ($o->get('session') !== $session) {
            return $no('the offer set is bound to another session');
        }
        if (!self::isSafeInt($now) || !self::isSafeInt($skewMs)) {
            return $no('no usable clock (now must be a safe integer): the offer set counts as stale');
        }
        $n = self::intOf($now);
        $issued = self::intOf($o->get('issued_at'));
        if ($issued > $n + self::intOf($skewMs)) {
            return $no('the offer set is issued in the future');
        }
        if ($n - $issued > self::intOf($policy->get('max_age_ms'))) {
            return $no('the offer set is stale');
        }
        if ($o->get('complete') !== true) {
            return $no('the offer set is not declared complete');
        }
        $filter = $policy->get('filter');
        if (!self::queryCovers($o->get('query'), $filter->get('query'))) {
            return $no('the search was narrowed beyond the intent filter (coverage)');
        }
        $id = self::resolveParamPath($params, $policy->get('offer_param'));
        if (!$id['found'] || !is_string($id['value'])) {
            return $no('the action names no offer id at the declared parameter');
        }
        $chosen = null;
        foreach ($o->get('offers') as $x) {
            if ($x->get('offer_id') === $id['value']) {
                $chosen = $x;
                break;
            }
        }
        if ($chosen === null) {
            return $no('the chosen offer is not in the signed offer set');
        }
        $fo = $filter->get('offer');
        if (!self::offerMatches($chosen, $fo)) {
            return $no('the chosen offer does not satisfy the intent filter');
        }
        $cp = self::intOf($chosen->get('price'));
        $min = $cp;
        foreach ($o->get('offers') as $x) {
            $xp = self::intOf($x->get('price'));
            if (self::offerMatches($x, $fo) && $xp < $min) {
                $min = $xp;
            }
        }
        return ['ok' => true, 'excess' => $cp - $min, 'chosen_price' => $cp, 'min_price' => $min];
    }

    // ---- rule 17: label receipts and flow rules --------------------------------------------------------------------

    /** Wire validation of a label receipt. Null = well-formed. */
    public static function validateLabelsWire(mixed $l): ?string
    {
        if (!($l instanceof Obj)) {
            return 'label receipt must be an object';
        }
        $m = self::closedMembers($l, self::LABELS_FIELDS, self::SUITE_MEMBERS, 'labels');
        if ($m !== null) {
            return $m;
        }
        if (!self::isOne($l->get('v')) || $l->get('kind') !== 'pca-labels') {
            return 'label receipt must be {v: 1, kind: "pca-labels"}';
        }
        if (!self::isBoundedString($l->get('site'), 256)) {
            return "'labels.site' must be a non-empty string (<= 256 bytes)";
        }
        if (!self::isDigest($l->get('session'))) {
            return "'labels.session' must be canonical base64url (32 bytes)";
        }
        if (!self::isDigest($l->get('response_digest'))) {
            return "'labels.response_digest' must be canonical base64url (32 bytes)";
        }
        $fields = $l->get('fields');
        if (!($fields instanceof Obj)) {
            return "'labels.fields' must be an object";
        }
        $keys = self::jsKeys($fields);
        if (count($keys) === 0 || count($keys) > self::MAX_LABEL_FIELDS) {
            return "'labels.fields' must hold 1.." . self::MAX_LABEL_FIELDS . ' fields';
        }
        foreach ($keys as $k) {
            $f = $fields->get($k);
            if (!self::isBoundedString($k, 256)) {
                return 'label field paths must be non-empty strings (<= 256 bytes)';
            }
            if (!($f instanceof Obj) || self::closedMembers($f, ['class', 'value_digest']) !== null) {
                return "label field '$k' must be exactly {class, value_digest}";
            }
            $c = $f->get('class');
            if (!is_string($c) || strlen($c) > 128 || preg_match(self::DATA_CLASS_RE, $c) !== 1) {
                return "label field '$k': invalid data class";
            }
            if (!self::isDigest($f->get('value_digest'))) {
                return "label field '$k': value_digest must be canonical base64url (32 bytes)";
            }
        }
        if (!self::isSafeInt($l->get('issued_at')) || self::intOf($l->get('issued_at')) < 0) {
            return "'labels.issued_at' must be a non-negative safe integer";
        }
        if (!self::isBoundedString($l->get('kid'), 64)) {
            return "'labels.kid' must be a non-empty string (<= 64 bytes)";
        }
        if (!is_string($l->get('sig'))) {
            return "'labels.sig' must be a string";
        }
        return null;
    }

    /** Wire shape and signature under the key pinned for (site, kid). Null = valid. Total. */
    public static function verifyLabels(mixed $l, mixed $keys): ?string
    {
        $w = self::validateLabelsWire($l);
        if ($w !== null) {
            return $w;
        }
        if (!is_array($keys) || !array_is_list($keys)) {
            return 'label keys must be an array';
        }
        $se = self::artifactSuiteError($l);
        if ($se !== null) {
            return "signature suite: $se";
        }
        $site = $l->get('site');
        $kid = $l->get('kid');
        $key = null;
        foreach ($keys as $k) {
            if (self::g($k, 'site') === $site && self::g($k, 'kid') === $kid) {
                $key = $k;
                break;
            }
        }
        if ($key === null) {
            return "no pinned label key for site '$site' kid '$kid'";
        }
        return self::verifyArtifactSig(self::LABELS_DOMAIN, $l, $key) ? null : 'bad label receipt signature';
    }

    /** Most specific matching flow pattern for a class (exact > longest `prefix.*` > `*`), or null. */
    public static function flowRuleFor(mixed $rules, mixed $cls): ?string
    {
        if (!($rules instanceof Obj) || !is_string($cls)) {
            return null;
        }
        if ($rules->has($cls)) {
            return $cls;
        }
        $best = null;
        foreach (self::jsKeys($rules) as $p) {
            if (!str_ends_with($p, '.*')) {
                continue;
            }
            $prefix = substr($p, 0, -1); // keeps the dot: 'pii.' matches 'pii.contact', never 'piix'
            if (str_starts_with($cls, $prefix) && ($best === null || self::utf16Len($p) > self::utf16Len($best))) {
                $best = $p;
            }
        }
        if ($best !== null) {
            return $best;
        }
        return $rules->has('*') ? '*' : null;
    }

    private static function utf16Len(string $s): int
    {
        // UTF-16 code units: astral (4-byte) characters count 2; WTF-8 lone surrogates (3 bytes) count 1.
        return strlen($s) - preg_match_all('/[\x80-\xBF]/', $s) + preg_match_all('/[\xF0-\xF7]/', $s);
    }

    /** May a value of class `cls`, labelled by `origin`, reach the sink audience `aud`? */
    public static function flowAllowed(mixed $rules, mixed $cls, mixed $origin, mixed $aud): bool
    {
        if (!is_string($cls) || !is_string($origin) || !is_string($aud)) {
            return false;
        }
        if ($aud === $origin || $cls === self::PUBLIC_CLASS) {
            return true;
        }
        $p = self::flowRuleFor($rules, $cls);
        if ($p === null) {
            return false;
        }
        $sinks = $rules->get($p);
        return is_array($sinks) && is_string($aud) && in_array($aud, $sinks, true);
    }

    /** Validate a flow rule set. Null = well-formed. */
    public static function validateFlowRules(mixed $rules): ?string
    {
        if (!($rules instanceof Obj)) {
            return 'flows must be an object';
        }
        foreach (self::jsKeys($rules) as $p) {
            $sinks = $rules->get($p);
            $base = $p === '*' ? 'x' : (str_ends_with($p, '.*') ? substr($p, 0, -2) : $p);
            if (preg_match(self::DATA_CLASS_RE, $base) !== 1) {
                return "flow pattern '$p' is not a class, a 'prefix.*' or '*'";
            }
            if (!is_array($sinks)) {
                return "flow pattern '$p' needs a list of audiences";
            }
            foreach ($sinks as $s) {
                if (!self::isBoundedString($s, 256)) {
                    return "flow pattern '$p' needs a list of audiences";
                }
            }
        }
        return null;
    }

    /** A class covered by purpose patterns (a class, `p.*`, `*`); `public` is always covered. */
    private static function classCovered(array $patterns, string $cls): bool
    {
        if ($cls === self::PUBLIC_CLASS) {
            return true;
        }
        foreach ($patterns as $p) {
            if ($p === '*' || $p === $cls || (str_ends_with($p, '.*') && str_starts_with($cls, substr($p, 0, -1)))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Read cell decision (label-receipts.ts decideReadPurpose; README "READ PURPOSE", `primitives.intent_read_purpose`).
     * `$input` = {fields: [{path, class, optional?}], purpose, coverage: {purpose: [pattern]}, on_uncovered?}. Malformed
     * input (fields not an array of objects with string `path` / `class` and an absent or boolean `optional`, a non-string
     * purpose, coverage not an object of string arrays, on_uncovered present and not "question" / "deny"; JSON null
     * included) is deny with empty lists. `coverage[purpose]` is an OWN member; optional uncovered fields are minimised,
     * other uncovered ones make the outcome `on_uncovered` (default "question"); both lists de-duplicated and sorted in
     * UTF-8 BYTE order. Never throws.
     * @return array{outcome: string, minimise: list<string>, uncovered: list<string>}
     */
    public static function decideReadPurpose(mixed $input): array
    {
        $malformed = ['outcome' => 'deny', 'minimise' => [], 'uncovered' => []];
        $fields = self::g($input, 'fields');
        $purpose = self::g($input, 'purpose');
        $coverage = self::g($input, 'coverage');
        $on = self::absentOr(self::g($input, 'on_uncovered'), 'question');
        if (!is_array($fields) || !is_string($purpose) || !($coverage instanceof Obj) || ($on !== 'question' && $on !== 'deny')) {
            return $malformed;
        }
        foreach ($coverage->keys() as $k) {
            $pats = $coverage->get($k);
            if (!is_array($pats)) {
                return $malformed;
            }
            foreach ($pats as $x) {
                if (!is_string($x)) {
                    return $malformed;
                }
            }
        }
        foreach ($fields as $f) {
            if (!($f instanceof Obj) || !is_string(self::g($f, 'path')) || !is_string(self::g($f, 'class'))) {
                return $malformed;
            }
            $opt = self::g($f, 'optional');
            if ($opt !== JsUndefined::U && !is_bool($opt)) {
                return $malformed;
            }
        }
        $patterns = $coverage->has($purpose) ? $coverage->get($purpose) : [];
        $minimise = [];
        $uncovered = [];
        foreach ($fields as $f) {
            if (self::classCovered($patterns, $f->get('class'))) {
                continue;
            }
            $path = $f->get('path');
            if (self::g($f, 'optional') === true) {
                $minimise['k' . $path] = $path;
            } else {
                $uncovered['k' . $path] = $path;
            }
        }
        $sorted = static function (array $m): array {
            $xs = array_values($m);
            usort($xs, [self::class, 'compareUtf8']); // UTF-8 byte order (U+FFFD before U+1F600), never UTF-16 order
            return $xs;
        };
        return ['outcome' => count($uncovered) > 0 ? $on : 'allow', 'minimise' => $sorted($minimise), 'uncovered' => $sorted($uncovered)];
    }

    // ---- rule 17: provenance ---------------------------------------------------------------------------------------

    /** True only for the five real level names (own-key check: 'constructor', '__proto__', 'toString' are NOT levels). */
    public static function isTaintLevel(mixed $kind): bool
    {
        return is_string($kind) && in_array($kind, self::TAINT_LEVELS, true);
    }

    /** Rank of a level; an unknown kind is the WORST rank (fail closed). */
    public static function labelRank(mixed $kind): int
    {
        return self::isTaintLevel($kind) ? (int)array_search($kind, self::TAINT_LEVELS, true) : self::MAX_RANK;
    }

    /** The JOIN of a list of levels: the least trusted; the EMPTY lineage is `agent` (TOP). */
    public static function joinLabels(array $levels): string
    {
        $r = count($levels) === 0 ? self::MAX_RANK : 0;
        foreach ($levels as $l) {
            $r = max($r, self::labelRank($l));
        }
        return self::TAINT_LEVELS[$r];
    }

    /**
     * Independently classify ONE declared ref (taint.ts classifyRef with a registry and no resource graph): the level the
     * registry holds for it as an OWN key, else `agent`; a non-string / empty ref is `agent`.
     */
    public static function classifyRef(mixed $ref, Obj $registry): string
    {
        if (!is_string($ref) || $ref === '') {
            return 'agent';
        }
        $v = self::g($registry, $ref);
        return self::isTaintLevel($v) ? $v : 'agent';
    }

    public static function isProvPath(mixed $k): bool
    {
        return is_string($k) && preg_match(self::PROV_PATH_RE, $k) === 1
            && !in_array(substr($k, strlen('action.params.')), self::FORBIDDEN_SEGMENTS, true);
    }

    /** Is `$k` a well-formed pinned label key {site, kid, pk, pq_pk?}? */
    public static function isLabelKey(mixed $k): bool
    {
        return $k instanceof Obj && self::closedMembers($k, ['site', 'kid', 'pk'], ['pq_pk'], 'label_key') === null
            && self::isBoundedString(self::g($k, 'site'), 256) && self::isBoundedString(self::g($k, 'kid'), 64)
            && self::isDigest(self::g($k, 'pk')) && self::pinPqOk(self::g($k, 'pq_pk'));
    }

    /** Rule 17 policy sanity (step 0). Null = well-formed. */
    public static function validateProvenancePolicy(mixed $p): ?string
    {
        if (!($p instanceof Obj) || !(self::g($p, 'params') instanceof Obj)) {
            return 'provenance policy needs a params map';
        }
        $cm = self::closedMembers($p, ['params'], ['registry', 'label_keys', 'critical_max', 'material_tainted', 'critical_tainted', 'flows'], 'policy');
        if ($cm !== null) {
            return $cm;
        }
        $params = $p->get('params');
        foreach (self::jsKeys($params) as $k) {
            if (!self::isParamPath($k)) {
                return "policy param '$k' is not an action.params path";
            }
            $v = $params->get($k);
            if ($v !== 'material' && $v !== 'critical') {
                return "policy param '$k': sensitivity must be material or critical";
            }
        }
        $reg = self::g($p, 'registry');
        if (self::present($reg)) {
            if (!($reg instanceof Obj)) {
                return 'registry must be an object';
            }
            foreach (self::jsKeys($reg) as $k) {
                if (!self::isBoundedString($k, 256) || !self::isTaintLevel($reg->get($k))) {
                    return "registry entry '$k' must map to a taint level";
                }
            }
        }
        $lk = self::g($p, 'label_keys');
        if (self::present($lk)) {
            if (!is_array($lk)) {
                return 'label_keys must be a list';
            }
            foreach ($lk as $k) {
                if (!self::isLabelKey($k)) {
                    return 'every label key needs site, kid, a 32-byte pk and an optional string pq_pk';
                }
            }
        }
        $cm = self::g($p, 'critical_max');
        if (self::present($cm) && !self::isTaintLevel($cm)) {
            return 'critical_max must be a taint level';
        }
        $mt = self::g($p, 'material_tainted');
        if (self::present($mt) && !in_array($mt, self::MODES, true)) {
            return 'material_tainted must be allow | question | question_typed | deny';
        }
        $ct = self::g($p, 'critical_tainted');
        if (self::present($ct) && ($ct === 'allow' || !in_array($ct, self::MODES, true))) {
            return 'critical_tainted must be question | question_typed | deny';
        }
        $fl = self::g($p, 'flows');
        if (self::present($fl)) {
            $e = self::validateFlowRules($fl);
            if ($e !== null) {
                return $e;
            }
        }
        return null;
    }

    /** Validate the `intent_session.prov` member. Null = well-formed. */
    public static function validateProvWire(mixed $prov): ?string
    {
        if (!($prov instanceof Obj)) {
            return "'prov' must be an object";
        }
        $keys = self::jsKeys($prov);
        if (count($keys) > self::MAX_PROV_PATHS) {
            return "'prov' holds more than " . self::MAX_PROV_PATHS . ' paths';
        }
        foreach ($keys as $k) {
            if (!self::isProvPath($k)) {
                return "'prov' key '$k' is not action.params.<name> ([A-Za-z0-9_]{1,64}, not a prototype name)";
            }
            $refs = $prov->get($k);
            if (!is_array($refs) || count($refs) === 0 || count($refs) > self::MAX_PROV_REFS) {
                return "'prov.$k' must hold 1.." . self::MAX_PROV_REFS . ' refs';
            }
            foreach ($refs as $r) {
                if (!self::isBoundedString($r, 256)) {
                    return "'prov.$k' refs must be non-empty strings (<= 256 bytes)";
                }
            }
        }
        return null;
    }

    /**
     * Parse `pca-labels:<ref>#<field>` (split at the FIRST '#'); null when malformed.
     * @return array{receipt: string, field: string}|null
     */
    public static function parseLabelRef(mixed $ref): ?array
    {
        if (!is_string($ref) || !str_starts_with($ref, self::LABEL_REF_PREFIX)) {
            return null;
        }
        $rest = substr($ref, strlen(self::LABEL_REF_PREFIX));
        $i = strpos($rest, '#');
        if ($i === false) {
            return null;
        }
        $receipt = substr($rest, 0, $i);
        $field = substr($rest, $i + 1);
        return self::isDigest($receipt) && $field !== '' ? ['receipt' => $receipt, 'field' => $field] : null;
    }

    /**
     * hash.ts compareUtf8: UTF-8 BYTE order, a lone surrogate encoding as U+FFFD (TextEncoder); strings with equal UTF-8
     * bytes (only lone surrogates can do that) are ordered by UTF-16 code units, which on WTF-8 bytes is plain strcmp.
     */
    public static function compareUtf8(string $a, string $b): int
    {
        if ($a === $b) {
            return 0;
        }
        $fffd = static fn(string $x): string => preg_replace('/\xED[\xA0-\xBF][\x80-\xBF]/', "\xEF\xBF\xBD", $x);
        $c = strcmp($fffd($a), $fffd($b));
        return $c !== 0 ? $c : strcmp($a, $b);
    }

    /** Ascending compareUtf8 order (never UTF-16 code-unit order). */
    private static function sorted(array $xs): array
    {
        usort($xs, [self::class, 'compareUtf8']);
        return $xs;
    }

    private static function toObj(array $m): Obj
    {
        $o = new Obj();
        foreach ($m as $k => $v) {
            $o->set((string)$k, $v);
        }
        return $o;
    }

    /**
     * NORMATIVE rule 17 (`provenance`). Every failure is `deny`; first failure wins (see param-provenance.ts
     * decideParamProvenance for the steps). Never throws.
     * @return array{outcome: string, labels: Obj, classes: Obj, env: Obj, reason?: string, friction?: string}
     */
    public static function decideParamProvenance(mixed $input): array
    {
        /** @var array<string,string> $labels path => level (paths are never integer-like: they start "action.") */
        $labels = [];
        /** @var array<string,list<string>> $classes */
        $classes = [];
        $deny = static function (string $reason) use (&$labels, &$classes): array {
            return ['outcome' => 'deny', 'reason' => "provenance: $reason", 'labels' => self::toObj($labels),
                'classes' => self::toObj($classes), 'env' => new Obj()];
        };
        try {
            if (!($input instanceof Obj)) {
                return $deny('input must be an object');
            }
            $policy = self::g($input, 'policy');
            $pe = self::validateProvenancePolicy($policy);
            if ($pe !== null) {
                return $deny("policy misconfigured (fail closed): $pe");
            }
            // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) deny.
            $prov = self::absentOr(self::g($input, 'prov'), new Obj());
            $we = self::validateProvWire($prov);
            if ($we !== null) {
                return $deny($we);
            }
            $committed = self::absentOr(self::g($input, 'committed_labels'), []);
            if (!is_array($committed) || count($committed) > self::MAX_COMMITTED_LABELS) {
                return $deny('committed labels must be a list of at most ' . self::MAX_COMMITTED_LABELS . ' digests');
            }
            $committedSet = [];
            foreach ($committed as $d) {
                if (!self::isDigest($d) || isset($committedSet['k' . $d])) {
                    return $deny('committed labels must be distinct canonical 32-byte digests');
                }
                $committedSet['k' . $d] = true;
            }
            $action = self::g($input, 'action');
            if (!($action instanceof Obj)) {
                return $deny('action must be an object');
            }
            $params = self::absentOr(self::g($action, 'params'), new Obj());
            if (!($params instanceof Obj)) {
                return $deny('action.params must be an object');
            }
            $suppliedLabels = self::absentOr(self::g($input, 'labels'), []);
            if (!is_array($suppliedLabels)) {
                return $deny('labels must be an array');
            }
            $labelKeys = self::absentOr(self::g($policy, 'label_keys'), []);
            $reg = self::absentOr(self::g($policy, 'registry'), new Obj());
            $flows = self::absentOr(self::g($policy, 'flows'), new Obj());
            $paths = self::sorted($prov->keys());
            foreach ($paths as $p) {
                if (!self::resolveParamPath($params, $p)['found']) {
                    return $deny("prov names '$p', a parameter the action does not carry");
                }
            }
            foreach ($paths as $a) {
                foreach ($paths as $b) {
                    if ($a !== $b && str_starts_with($b, $a . '.')) {
                        return $deny("prov paths '$a' and '$b' overlap");
                    }
                }
            }

            $receipts = [];
            foreach ($suppliedLabels as $r) {
                try {
                    if (self::validateLabelsWire($r) === null) {
                        $receipts['k' . self::labelReceiptRef($r)] = $r;
                    }
                } catch (\Throwable) {
                    // not strictly canonical: no reference, never matches a commitment
                }
            }
            $aud = self::g($input, 'aud');
            $session = self::g($input, 'session');
            /** @var array<string,list<array{0:string,1:string}>> $origins path => [class, origin site] */
            $origins = [];

            foreach ($paths as $p) {
                $value = self::resolveParamPath($params, $p)['value'];
                $refLabels = [];
                foreach ($prov->get($p) as $ref) {
                    if (!str_starts_with($ref, self::LABEL_REF_PREFIX)) {
                        $refLabels[] = self::classifyRef($ref, $reg);
                        continue;
                    }
                    $lr = self::parseLabelRef($ref);
                    if ($lr === null) {
                        return $deny("malformed label ref on '$p'");
                    }
                    if (!isset($committedSet['k' . $lr['receipt']])) {
                        return $deny("label ref on '$p' names a receipt the PCActn does not commit");
                    }
                    $rc = $receipts['k' . $lr['receipt']] ?? null;
                    if ($rc === null) {
                        return $deny("label receipt for '$p' was not supplied");
                    }
                    $ve = self::verifyLabels($rc, $labelKeys);
                    if ($ve !== null) {
                        return $deny("label receipt for '$p': $ve");
                    }
                    if ($rc->get('session') !== $session) {
                        return $deny("label receipt for '$p' is bound to another session");
                    }
                    $fields = $rc->get('fields');
                    if (!$fields->has($lr['field'])) {
                        return $deny("label receipt for '$p' has no field '{$lr['field']}'");
                    }
                    $field = $fields->get($lr['field']);
                    try {
                        $match = self::hc($value) === $field->get('value_digest');
                    } catch (\Throwable) {
                        $match = false;
                    }
                    $site = $rc->get('site');
                    $refLabels[] = $match ? ($site === $aud ? 'first_party' : 'tool') : 'agent';
                    $origins[$p][] = [$field->get('class'), $site];
                }
                $labels[$p] = self::joinLabels($refLabels);
            }
            $polParams = $policy->get('params');
            foreach (self::sorted($polParams->keys()) as $p) {
                if (array_key_exists($p, $labels)) {
                    continue;
                }
                if (self::resolveParamPath($params, $p)['found']) {
                    $labels[$p] = 'agent';
                }
            }
            foreach (self::sorted(array_map('strval', array_keys($origins))) as $p) {
                $cls = [];
                foreach ($origins[$p] as [$c]) {
                    if (!in_array($c, $cls, true)) {
                        $cls[] = $c;
                    }
                }
                $classes[$p] = self::sorted($cls);
                foreach ($origins[$p] as [$c, $origin]) {
                    if (!self::flowAllowed($flows, $c, $origin, $aud)) {
                        return $deny("flow: class '$c' from '$origin' may not reach '" . self::jsStr($aud) . "' (parameter '$p')");
                    }
                }
            }
            $criticalMax = self::g($policy, 'critical_max');
            $capRank = self::labelRank(self::absentOr($criticalMax, 'agent'));
            $sens = static fn(string $p): mixed => $polParams->has($p) ? $polParams->get($p) : JsUndefined::U;
            $sortedLabels = self::sorted(array_map('strval', array_keys($labels)));
            foreach ($sortedLabels as $p) {
                if ($sens($p) === 'critical' && self::labelRank($labels[$p]) > $capRank) {
                    return $deny("critical parameter '$p' has provenance '{$labels[$p]}', above the policy maximum '" . self::jsStr($criticalMax) . "'");
                }
            }
            $question = false;
            $typed = false;
            foreach ($sortedLabels as $p) {
                $s = $sens($p);
                if ($s === JsUndefined::U || self::labelRank($labels[$p]) < self::TAINTED_RANK) {
                    continue;
                }
                $mode = $s === 'critical'
                    ? self::absentOr(self::g($policy, 'critical_tainted'), 'question_typed')
                    : self::absentOr(self::g($policy, 'material_tainted'), 'question');
                if ($mode === 'deny') {
                    return $deny("tainted $s parameter '$p' (provenance '{$labels[$p]}') is denied by policy");
                }
                if ($mode === 'question' || $mode === 'question_typed') {
                    $question = true;
                }
                if ($mode === 'question_typed') {
                    $typed = true;
                }
            }
            $env = new Obj();
            foreach ($sortedLabels as $p) {
                if (!self::setNested($env, $p, $labels[$p])) {
                    return $deny("provenance paths overlap at '$p'");
                }
            }
            if ($question) {
                return ['outcome' => 'question', 'reason' => 'provenance: a tainted value needs the principal (lazy question)',
                    'friction' => $typed ? 'typed' : 'tap', 'labels' => self::toObj($labels), 'classes' => self::toObj($classes), 'env' => $env];
            }
            return ['outcome' => 'pass', 'labels' => self::toObj($labels), 'classes' => self::toObj($classes), 'env' => $env];
        } catch (\Throwable $e) {
            return $deny('evaluation error (fail closed): ' . $e->getMessage());
        }
    }

    /**
     * Is the rule-17 check active? Iff `prov` is present (any value, null included), `labels` is a non-empty ARRAY, or a
     * provenance policy is a plain object. `$x` is an Obj with members `prov?`, `labels?`, `policy?`.
     */
    public static function intentProvenanceActive(mixed $x): bool
    {
        $labels = self::g($x, 'labels');
        return self::present(self::g($x, 'prov')) || (is_array($labels) && count($labels) > 0) || self::g($x, 'policy') instanceof Obj;
    }

    // ---- rule 18: classifier verdicts ------------------------------------------------------------------------------

    /** Wire validation of a classifier verdict. Null = well-formed. */
    public static function validateClassifierVerdictWire(mixed $v): ?string
    {
        if (!($v instanceof Obj)) {
            return 'verdict must be an object';
        }
        $m = self::closedMembers($v, self::VERDICT_FIELDS, self::SUITE_MEMBERS, 'verdict');
        if ($m !== null) {
            return $m;
        }
        if (!self::isOne($v->get('v')) || $v->get('kind') !== 'pca-intent-classification') {
            return 'verdict must be {v: 1, kind: "pca-intent-classification"}';
        }
        $c = $v->get('classifier');
        if (!is_string($c) || preg_match(self::INTENT_NAME_RE, $c) !== 1) {
            return "'verdict.classifier' must match ^[a-z][a-z0-9_]{0,63}$";
        }
        if (!self::isDigest($v->get('session'))) {
            return "'verdict.session' must be canonical base64url (32 bytes)";
        }
        if (!self::isDigest($v->get('content_digest'))) {
            return "'verdict.content_digest' must be canonical base64url (32 bytes)";
        }
        if (!self::isBoundedString($v->get('label'), 64)) {
            return "'verdict.label' must be a non-empty string (<= 64 bytes)";
        }
        if (!self::isBoundedString($v->get('measurement'), 256)) {
            return "'verdict.measurement' must be a non-empty string (<= 256 bytes)";
        }
        if (!self::isDigest($v->get('judge'))) {
            return "'verdict.judge' must be canonical base64url (32 bytes)";
        }
        if (!is_string($v->get('sig'))) {
            return "'verdict.sig' must be a string";
        }
        return null;
    }

    /** Rule 18 policy sanity (step 0). Null = well-formed. */
    public static function validateClassifierPolicy(mixed $p): ?string
    {
        if (!($p instanceof Obj) || !is_array(self::g($p, 'classifiers'))) {
            return 'classifier policy needs a classifiers list';
        }
        $cm = self::closedMembers($p, ['classifiers'], [], 'policy');
        if ($cm !== null) {
            return $cm;
        }
        $ids = [];
        foreach ($p->get('classifiers') as $c) {
            if (!($c instanceof Obj) || self::closedMembers($c, ['id', 'param', 'labels', 'keys', 'k'], ['measurements', 'pq_keys'], 'classifier') !== null) {
                return 'every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}';
            }
            $id = self::g($c, 'id');
            if (!is_string($id) || preg_match(self::INTENT_NAME_RE, $id) !== 1 || isset($ids['k' . $id])) {
                return 'every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$';
            }
            $ids['k' . $id] = true;
            if (!self::isParamPath(self::g($c, 'param'))) {
                return "classifier '$id': param must be an action.params path";
            }
            $labs = self::g($c, 'labels');
            if (!is_array($labs) || count($labs) === 0 || count($labs) > self::MAX_CLASSIFIER_LABELS) {
                return "classifier '$id': labels must hold 1.." . self::MAX_CLASSIFIER_LABELS . ' strings';
            }
            foreach ($labs as $l) {
                if (!self::isBoundedString($l, 64)) {
                    return "classifier '$id': labels must be distinct non-empty strings";
                }
            }
            if (!self::distinct($labs)) {
                return "classifier '$id': labels must be distinct non-empty strings";
            }
            $keys = self::g($c, 'keys');
            $keysOk = is_array($keys) && count($keys) > 0;
            if ($keysOk) {
                foreach ($keys as $k) {
                    if (!self::isDigest($k)) {
                        $keysOk = false;
                        break;
                    }
                }
            }
            if (!$keysOk || !self::distinct($keys)) {
                return "classifier '$id': keys must be distinct 32-byte keys";
            }
            $k = self::g($c, 'k');
            if (!self::isSafeInt($k) || self::intOf($k) < 1 || self::intOf($k) > count($keys)) {
                return "classifier '$id': k must be an integer in [1, " . count($keys) . ']';
            }
            $ms = self::g($c, 'measurements');
            if (self::present($ms)) {
                $msOk = is_array($ms);
                foreach ($msOk ? $ms : [] as $x) {
                    if (!is_string($x)) {
                        $msOk = false;
                        break;
                    }
                }
                if (!$msOk) {
                    return "classifier '$id': measurements must be a list of strings";
                }
            }
            $pqk = self::g($c, 'pq_keys');
            if ($pqk !== JsUndefined::U) {
                $pqOk = $pqk instanceof Obj;
                foreach ($pqOk ? self::jsKeys($pqk) : [] as $kk) {
                    $pv = $pqk->get($kk);
                    if (!in_array($kk, $keys, true) || !is_string($pv) || $pv === '') {
                        $pqOk = false;
                        break;
                    }
                }
                if (!$pqOk) {
                    return "classifier '$id': pq_keys must map allowlisted keys to PQ keys";
                }
            }
        }
        return null;
    }

    /** Is the rule-18 check active? Iff `committed` or `policy.classifiers` is a non-empty ARRAY. */
    public static function classifierCheckActive(mixed $input): bool
    {
        $nonEmpty = static fn(mixed $x): bool => is_array($x) && count($x) > 0;
        return $nonEmpty(self::g($input, 'committed')) || $nonEmpty(self::g(self::g($input, 'policy'), 'classifiers'));
    }

    /**
     * NORMATIVE rule 18 (`classes`): compute `env.class`. First failure wins (see intent-classifier.ts
     * decideClassifierDimensions for the steps). Tallies are prototype-free (every id and label is an ordinary key).
     * Never throws.
     * @return array{ok: bool, classes?: Obj, votes?: Obj, reason?: string}
     */
    public static function decideClassifierDimensions(mixed $input): array
    {
        $fail = static fn(string $reason): array => ['ok' => false, 'reason' => "classes: $reason"];
        try {
            if (!($input instanceof Obj)) {
                return $fail('input must be an object');
            }
            $policy = self::g($input, 'policy');
            $pe = self::validateClassifierPolicy($policy);
            if ($pe !== null) {
                return $fail("policy misconfigured (fail closed): $pe");
            }
            // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail.
            $committed = self::absentOr(self::g($input, 'committed'), []);
            if (!is_array($committed) || count($committed) > self::MAX_COMMITTED_CLASSES) {
                return $fail('committed verdicts must be a list of at most ' . self::MAX_COMMITTED_CLASSES . ' digests');
            }
            $seen = [];
            foreach ($committed as $d) {
                if (!self::isDigest($d) || isset($seen['k' . $d])) {
                    return $fail('committed verdicts must be distinct canonical 32-byte digests');
                }
                $seen['k' . $d] = true;
            }
            $supplied = self::absentOr(self::g($input, 'verdicts'), []);
            if (!is_array($supplied)) {
                return $fail('verdicts must be an array');
            }
            $action = self::g($input, 'action');
            if (!($action instanceof Obj)) {
                return $fail('action must be an object');
            }
            $params = self::absentOr(self::g($action, 'params'), new Obj());
            if (!($params instanceof Obj)) {
                return $fail('action.params must be an object');
            }
            $byRef = [];
            foreach ($supplied as $v) {
                if (self::validateClassifierVerdictWire($v) !== null) {
                    continue;
                }
                try {
                    $byRef['k' . self::classifierVerdictRef($v)] = $v;
                } catch (\Throwable) {
                    // not strictly canonical: no reference
                }
            }
            $session = self::g($input, 'session');
            $classifiers = $policy->get('classifiers');
            /** @var array<string,array{0:string,1:array<string,array{0:string,1:int}>}> $votes 'k'.id => [id, 'k'.label => [label, n]] */
            $votes = [];
            $pairs = [];
            foreach ($committed as $d) {
                $v = $byRef['k' . $d] ?? null;
                if ($v === null) {
                    return $fail('a committed verdict was not supplied (or is malformed)');
                }
                $se = self::artifactSuiteError($v);
                if ($se !== null) {
                    return $fail("verdict signature suite: $se");
                }
                $cid = $v->get('classifier');
                $c = null;
                foreach ($classifiers as $x) {
                    if ($x->get('id') === $cid) {
                        $c = $x;
                        break;
                    }
                }
                if ($c === null) {
                    return $fail("verdict for undeclared classifier '$cid'");
                }
                $judge = $v->get('judge');
                if (!in_array($judge, $c->get('keys'), true)) {
                    return $fail("classifier '$cid': judge key is not on the allowlist");
                }
                $pin = new Obj();
                $pin->set('pk', $judge);
                $pqk = self::g($c, 'pq_keys');
                $pq = $pqk === JsUndefined::U ? JsUndefined::U : self::g($pqk, $judge); // own member only
                if ($pq !== JsUndefined::U) {
                    $pin->set('pq_pk', $pq);
                }
                if (!self::verifyArtifactSig(self::INTENT_CLASSIFIER_DOMAIN, $v, $pin)) {
                    return $fail("classifier '$cid': bad verdict signature");
                }
                if ($v->get('session') !== $session) {
                    return $fail("classifier '$cid': verdict bound to another session");
                }
                $param = $c->get('param');
                $content = self::resolveParamPath($params, $param);
                if (!$content['found']) {
                    return $fail("classifier '$cid': the action carries no '$param'");
                }
                if (self::hc($content['value']) !== $v->get('content_digest')) { // throws on non-canonical content: fail closed
                    return $fail("classifier '$cid': verdict is about other content");
                }
                $label = $v->get('label');
                if (!in_array($label, $c->get('labels'), true)) {
                    return $fail("classifier '$cid': label '$label' is not in its label set");
                }
                if ($c->has('measurements') && !in_array($v->get('measurement'), $c->get('measurements'), true)) {
                    return $fail("classifier '$cid': measurement is not pinned");
                }
                $pair = 'k' . $cid . "\0" . $judge;
                if (isset($pairs[$pair])) {
                    return $fail("classifier '$cid': two verdicts from one judge");
                }
                $pairs[$pair] = true;
                $votes['k' . $cid] ??= [$cid, []];
                $votes['k' . $cid][1]['k' . $label] ??= [$label, 0];
                $votes['k' . $cid][1]['k' . $label][1]++;
            }
            $classes = new Obj();
            foreach ($classifiers as $c) {
                $id = $c->get('id');
                $t = $votes['k' . $id][1] ?? [];
                $k = self::intOf($c->get('k'));
                $winners = [];
                foreach ($c->get('labels') as $l) {
                    if (($t['k' . $l][1] ?? 0) >= $k) {
                        $winners[] = $l;
                    }
                }
                if (count($winners) === 0) {
                    return $fail("classifier '$id': no label reaches the quorum $k");
                }
                if (count($winners) > 1) {
                    return $fail("classifier '$id': ambiguous, " . count($winners) . ' labels reach the quorum');
                }
                $classes->set($id, $winners[0]);
            }
            $voteOut = new Obj();
            foreach ($votes as [$id, $t]) {
                $r = new Obj();
                foreach ($t as [$l, $n]) {
                    $r->set($l, self::num($n));
                }
                $voteOut->set($id, $r);
            }
            return ['ok' => true, 'classes' => $classes, 'votes' => $voteOut];
        } catch (\Throwable $e) {
            return $fail('evaluation error (fail closed): ' . $e->getMessage());
        }
    }

    // ---- composition (intent-env.ts) -------------------------------------------------------------------------------

    /** Set `o[k] = v` unless `v` is absent (an absent member stays absent; a present null is kept). */
    private static function put(Obj $o, string $k, mixed $v): void
    {
        if ($v !== JsUndefined::U) {
            $o->set($k, $v);
        }
    }

    /**
     * Which W-B checks a verifier reports for these members and policies (conformance `primitives.intent_wb_active`).
     * Activity reads OWN members of plain objects only (a container absent or not an object has no members) and never
     * coerces: decideIntentWb refuses malformed containers before activity.
     * @return array{facts: bool, provenance: bool, classes: bool}
     */
    public static function intentWbActive(mixed $input): array
    {
        $s = self::g($input, 'intent_session');
        $p = self::g($input, 'policy');
        $committed = new Obj();
        self::put($committed, 'facts', self::g($s, 'facts'));
        self::put($committed, 'offer_set', self::g($s, 'offer_set'));
        $wi = new Obj();
        $wi->set('committed', $committed);
        self::put($wi, 'policy', self::g($p, 'world'));
        $pi = new Obj();
        self::put($pi, 'prov', self::g($s, 'prov'));
        self::put($pi, 'labels', self::g($s, 'labels'));
        self::put($pi, 'policy', self::g($p, 'provenance'));
        $ci = new Obj();
        self::put($ci, 'committed', self::g($s, 'classes'));
        $cp = new Obj();
        self::put($cp, 'classifiers', self::g($p, 'classifiers'));
        $ci->set('policy', $cp);
        return [
            'facts' => self::intentWorldActive($wi),
            'provenance' => self::intentProvenanceActive($pi),
            'classes' => self::classifierCheckActive($ci),
        ];
    }

    /**
     * The shape rule for the W-B context (absent vs null; intent-env.ts intentWBContextError). `$input` is the decideIntentWb
     * input: `intent_session` a plain object; `artifacts` absent or a plain object whose `facts` / `labels` / `verdicts` are
     * absent or arrays and whose `offer_set` is absent or a plain object; `policy` absent or a plain object whose `world` /
     * `provenance` are absent or plain objects and whose `classifiers` is absent or an array. JSON `null` anywhere here is
     * malformed. Null = well-formed.
     */
    public static function intentWbContextError(mixed $input): ?string
    {
        if (!($input instanceof Obj)) {
            return 'input must be an object';
        }
        if (!(self::g($input, 'intent_session') instanceof Obj)) {
            return 'intent_session must be an object';
        }
        $a = self::g($input, 'artifacts');
        if ($a !== JsUndefined::U) {
            if (!($a instanceof Obj)) {
                return 'artifacts must be an object';
            }
            $am = self::closedMembers($a, [], ['facts', 'labels', 'verdicts', 'offer_set'], 'artifacts');
            if ($am !== null) {
                return $am;
            }
            foreach (['facts', 'labels', 'verdicts'] as $k) {
                if ($a->has($k) && !is_array($a->get($k))) {
                    return "artifacts.$k must be an array";
                }
            }
            if ($a->has('offer_set') && !($a->get('offer_set') instanceof Obj)) {
                return 'artifacts.offer_set must be an object';
            }
        }
        $p = self::g($input, 'policy');
        if ($p !== JsUndefined::U) {
            if (!($p instanceof Obj)) {
                return 'policy must be an object';
            }
            $pm = self::closedMembers($p, [], ['world', 'provenance', 'classifiers'], 'policy');
            if ($pm !== null) {
                return $pm;
            }
            foreach (['world', 'provenance'] as $k) {
                if ($p->has($k) && !($p->get($k) instanceof Obj)) {
                    return "policy.$k must be an object";
                }
            }
            if ($p->has('classifiers') && !is_array($p->get('classifiers'))) {
                return 'policy.classifiers must be an array';
            }
        }
        return null;
    }

    /**
     * Rules 16, 17 and 18 in order (spec §5); each check is reported only when active; the first failing check denies and
     * later checks are not reported; a rule-17 `question` does not end the unit. A malformed W-B context
     * (intentWbContextError) fails `facts`, the first check of the unit. Never throws.
     * @return array{outcome: string, checks: array<string,string>, env: array<string,Obj>, reason?: string, friction?: string, single_source?: list<string>}
     */
    public static function decideIntentWb(mixed $input): array
    {
        $out = ['outcome' => 'admit', 'checks' => [], 'env' => []];
        try {
            $ce = self::intentWbContextError($input);
            if ($ce !== null) {
                return array_merge($out, ['outcome' => 'deny', 'checks' => ['facts' => 'fail'], 'reason' => "facts: the W-B context is malformed: $ce"]);
            }
            $s = $input->get('intent_session');
            $a = self::absentOr(self::g($input, 'artifacts'), new Obj());
            $pol = self::absentOr(self::g($input, 'policy'), new Obj());
            $committed = new Obj();
            self::put($committed, 'facts', self::g($s, 'facts'));
            self::put($committed, 'offer_set', self::g($s, 'offer_set'));
            $worldPolicy = self::absentOr(self::g($pol, 'world'), new Obj());
            $wa = new Obj();
            $wa->set('committed', $committed);
            $wa->set('policy', $worldPolicy);
            if (self::intentWorldActive($wa)) {
                $wi = new Obj();
                self::put($wi, 'now', self::g($input, 'now'));
                self::put($wi, 'aud', self::g($input, 'aud'));
                self::put($wi, 'session', self::g($input, 'session'));
                self::put($wi, 'action', self::g($input, 'action'));
                $wi->set('committed', $committed);
                self::put($wi, 'facts', self::g($a, 'facts'));
                self::put($wi, 'offer_set', self::g($a, 'offer_set'));
                $wi->set('policy', $worldPolicy);
                $w = self::decideIntentWorld($wi);
                if (!$w['ok']) {
                    return array_merge($out, ['outcome' => 'deny', 'checks' => ['facts' => 'fail'], 'reason' => $w['reason']]);
                }
                $out['checks']['facts'] = 'pass';
                $out['env']['world'] = $w['world'];
                if (count($w['single_source']) > 0) {
                    $out['single_source'] = $w['single_source'];
                }
            }
            $pa = new Obj();
            self::put($pa, 'prov', self::g($s, 'prov'));
            self::put($pa, 'labels', self::g($s, 'labels'));
            self::put($pa, 'policy', self::g($pol, 'provenance'));
            if (self::intentProvenanceActive($pa)) {
                $pi = new Obj();
                self::put($pi, 'aud', self::g($input, 'aud'));
                self::put($pi, 'session', self::g($input, 'session'));
                self::put($pi, 'action', self::g($input, 'action'));
                self::put($pi, 'prov', self::g($s, 'prov'));
                self::put($pi, 'committed_labels', self::g($s, 'labels'));
                self::put($pi, 'labels', self::g($a, 'labels'));
                $pi->set('policy', self::absentOr(self::g($pol, 'provenance'), Obj::of(['params' => new Obj()])));
                $p = self::decideParamProvenance($pi);
                if ($p['outcome'] === 'deny') {
                    return array_merge($out, ['outcome' => 'deny', 'checks' => $out['checks'] + ['provenance' => 'fail'], 'reason' => $p['reason']]);
                }
                $out['checks']['provenance'] = $p['outcome'] === 'question' ? 'question' : 'pass';
                $out['env']['prov'] = $p['env'];
                if ($p['outcome'] === 'question') {
                    $out['outcome'] = 'question';
                    $out['reason'] = $p['reason'];
                    $out['friction'] = $p['friction'];
                }
            }
            $clsPolicy = Obj::of(['classifiers' => self::absentOr(self::g($pol, 'classifiers'), [])]);
            $ca = new Obj();
            self::put($ca, 'committed', self::g($s, 'classes'));
            $ca->set('policy', $clsPolicy);
            if (self::classifierCheckActive($ca)) {
                $ci = new Obj();
                self::put($ci, 'session', self::g($input, 'session'));
                self::put($ci, 'action', self::g($input, 'action'));
                self::put($ci, 'committed', self::g($s, 'classes'));
                self::put($ci, 'verdicts', self::g($a, 'verdicts'));
                $ci->set('policy', $clsPolicy);
                $c = self::decideClassifierDimensions($ci);
                if (!$c['ok']) {
                    return array_merge($out, ['outcome' => 'deny', 'checks' => $out['checks'] + ['classes' => 'fail'], 'reason' => $c['reason']]);
                }
                $out['checks']['classes'] = 'pass';
                $out['env']['class'] = $c['classes'];
            }
            return $out;
        } catch (\Throwable $e) {
            return ['outcome' => 'deny', 'checks' => ['facts' => 'fail'], 'env' => [], 'reason' => 'facts: evaluation error (fail closed): ' . $e->getMessage()];
        }
    }
}
