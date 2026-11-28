<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/SafeRegex.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/SignersMore.php';

/**
 * Agent-native authority primitives (the reference's `agentNative` namespace): uncertainty attestation, rationale binding, the
 * semantic firewall (tool-schema caveats), capability introspection and the authority lease.
 *
 *     $claim = AgentNative::signCaution(['action_digest' => $d, 'caution' => 0.4, 'holder' => $key->public], $key);
 *     AgentNative::combineSignedCaution($claim, $d, 0.2, $key->public); // effectiveRisk 0.4, honoured, escalated
 *
 * Pure and deterministic: no clocks (callers pass `$now`) and no randomness except the default rationale salt. The verifiers and
 * evaluators are total and fail closed (they never throw on malformed input); the AUTHORING helpers (signCaution, bindRationale,
 * toolSchemaCaveat, grantLease) throw on invalid input, so a bad artefact is never minted. Values are the verifier's value model
 * ({@see Obj}, lists, strings, {@see Num}, bool, null; a native int / float is read as a number too). Members carry the
 * reference's names (effectiveRisk, hasEnvelope, remainingBudgetHints, ...).
 *
 * `renewCapabilityLease` is the reference's pure `renewLease(lease, heartbeat, now)`; the grants LeaseRegistry renewal is a
 * different feature.
 */
final class AgentNative
{
    public const CAVEAT_ENVELOPE = 'envelope';
    public const CAVEAT_EXPIRES = 'expires';
    public const CAVEAT_NOT_BEFORE = 'not_before';
    public const CAVEAT_RATE = 'rate';
    public const CAVEAT_MAX_BLAST_RADIUS = 'max_blast_radius';
    public const CAVEAT_REVERSIBILITY_MAX = 'reversibility_max';
    public const CAVEAT_DELEGATION_DEPTH = 'delegation_depth';
    public const CAVEAT_PREDICATES = 'predicates';
    public const CAVEAT_TOOL_SCHEMA = 'tool_schema';
    public const CAVEAT_MAX_SPEND = 'max_spend';

    public const MAX_CAUTION_REASON_LEN = SignersMore::MAX_CAUTION_REASON_LEN;
    public const MIN_SALT_BYTES = 16;
    public const MIN_SALT_DISTINCT_BYTES = 8;
    public const MAX_RATIONALE_LEN = 8192;
    public const MAX_SCHEMA_DEPTH = Authorize::MAX_SCHEMA_DEPTH;
    public const MAX_SCHEMA_NODES = Authorize::MAX_SCHEMA_NODES;
    public const MAX_OBJECT_PROPS = Authorize::MAX_OBJECT_PROPS;
    public const MAX_ENUM_VALUES = Authorize::MAX_ENUM_VALUES;
    public const DEFAULT_MAX_ARRAY_ITEMS = Authorize::DEFAULT_MAX_ARRAY_ITEMS;
    public const ABSOLUTE_MAX_ARRAY_ITEMS = Authorize::ABSOLUTE_MAX_ARRAY_ITEMS;
    public const DEFAULT_MAX_STRING_LEN = Authorize::DEFAULT_MAX_STRING_LEN;
    public const ABSOLUTE_MAX_STRING_LEN = Authorize::ABSOLUTE_MAX_STRING_LEN;
    public const MAX_VALUE_NODES = Authorize::MAX_VALUE_NODES;
    public const HEARTBEAT_SKEW_MS = 30000;
    public const MAX_LEASE_TTL_MS = 604800000;

    private const SAFE_INT = 9007199254740991;
    private const CAUTION_KEYS = ['action_digest', 'caution', 'reason', 'holder', 'sig'];
    private const HB_KEYS = ['cap_id', 'seq', 'at', 'holder', 'lease_issued_at', 'sig'];
    private const REV = ['reversible', 'rate_limited', 'irreversible'];

    // ---- JS-shaped helpers ---------------------------------------------------------------------------------------------------

    /** A finite JSON number as a float (Num, or a native int / float), else null. A bool is never a number. */
    private static function fin(mixed $x): ?float
    {
        $f = match (true) {
            $x instanceof Num => $x->float(),
            is_int($x) => (float)$x,
            is_float($x) => $x,
            default => null,
        };
        return $f !== null && is_finite($f) ? $f : null;
    }

    private static function negZero(mixed $x): bool
    {
        $f = $x instanceof Num ? $x->float() : (is_float($x) ? $x : null);
        return $f !== null && $f === 0.0 && fdiv(1.0, $f) < 0;
    }

    /** Number.isInteger */
    private static function isInt(mixed $x): bool
    {
        $f = self::fin($x);
        return $f !== null && floor($f) === $f;
    }

    private static function nonEmpty(mixed $x): bool
    {
        return is_string($x) && $x !== '';
    }

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    /** A computed double as the caller's number: an integral value inside the safe range is an int (no -0). */
    private static function nz(float $x): int|float
    {
        return is_finite($x) && floor($x) === $x && abs($x) <= self::SAFE_INT ? (int)$x : $x;
    }

    private static function clamp01(float $x): float
    {
        return min(1.0, max(0.0, $x));
    }

    /** JavaScript truthiness of a JSON value. */
    private static function truthy(mixed $x): bool
    {
        if ($x === null || $x === false || $x === '') {
            return false;
        }
        $f = $x instanceof Num ? $x->float() : (is_int($x) || is_float($x) ? (float)$x : null);
        return !($f !== null && ($f === 0.0 || is_nan($f)));
    }

    /** JavaScript `===` for the scalars compared here (a bool is not a number). */
    private static function strictEq(mixed $a, mixed $b): bool
    {
        $fa = self::fin($a);
        $fb = self::fin($b);
        if ($fa !== null || $fb !== null) {
            return $fa !== null && $fb !== null && $fa === $fb;
        }
        return is_string($a) && is_string($b) && $a === $b;
    }

    private static function onlyKeys(Obj $o, array $allowed): bool
    {
        foreach ($o->keys() as $k) {
            if (!in_array($k, $allowed, true)) {
                return false;
            }
        }
        return true;
    }

    /** Sorted by UTF-8 bytes, duplicates dropped. @param list<string> $xs @return list<string> */
    private static function sortedUnique(array $xs): array
    {
        $xs = array_values(array_unique($xs, SORT_STRING));
        usort($xs, 'strcmp');
        return $xs;
    }

    private static function msg(string $domain, Obj $body): string
    {
        return Json::canonicalizeNative(Obj::of(['d' => $domain, 'b' => $body]));
    }

    /** JSON.parse(canonicalize(x)): the lenient canonical form, deep-cloned (a number by value, -0 becomes 0, a non-finite number throws). */
    private static function cloneLenient(mixed $v): mixed
    {
        if ($v instanceof Num || is_int($v) || is_float($v)) {
            return new Num(Json::canonicalizeLenient($v));
        }
        if (self::isList($v)) {
            return array_map(self::cloneLenient(...), $v);
        }
        if ($v instanceof Obj) {
            $keys = $v->keys();
            usort($keys, 'strcmp');
            $o = new Obj();
            foreach ($keys as $k) {
                $o->set($k, self::cloneLenient($v->get($k)));
            }
            return $o;
        }
        if ($v === null || is_bool($v) || is_string($v)) {
            return $v;
        }
        throw new JsonError('canonicalize: unsupported type ' . get_debug_type($v));
    }

    // ---- 1. uncertainty attestation ------------------------------------------------------------------------------------------

    /** The holder's signed caution claim about one action. Throws on an invalid body. */
    public static function signCaution(mixed $body, KeyPair $holder): Obj
    {
        return SignersMore::signCaution($body, $holder);
    }

    private static function cautionError(mixed $b): ?string
    {
        if (!($b instanceof Obj)) {
            return 'not an object';
        }
        if (!self::nonEmpty($b->get('action_digest'))) {
            return 'action_digest required';
        }
        if (!self::nonEmpty($b->get('holder'))) {
            return 'holder required';
        }
        $c = self::fin($b->get('caution'));
        if ($c === null || $c < 0 || $c > 1) {
            return 'caution must be a finite number in [0,1]';
        }
        if ($b->has('reason')) {
            $r = $b->get('reason');
            if (!is_string($r) || SafeRegex::utf16Len($r) > self::MAX_CAUTION_REASON_LEN || preg_match('/\A[A-Za-z0-9_.:-]+\z/D', $r) !== 1) {
                return 'invalid reason';
            }
        }
        return null;
    }

    /** @param bool $checkDigest / $checkHolder whether the expected values are given */
    private static function verifyCautionWith(mixed $claim, bool $checkDigest, mixed $digest, bool $checkHolder, mixed $holder): bool
    {
        try {
            if (!($claim instanceof Obj) || !is_string($claim->get('sig')) || !self::onlyKeys($claim, self::CAUTION_KEYS)) {
                return false;
            }
            if (self::cautionError($claim) !== null) {
                return false;
            }
            if ($checkDigest && $claim->get('action_digest') !== $digest) {
                return false;
            }
            if ($checkHolder && $claim->get('holder') !== $holder) {
                return false;
            }
            return Pca::verifyEd25519B64u($claim->get('holder'), self::msg(SignersMore::CAUTION_DOMAIN, $claim->without('sig')), $claim->get('sig'));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Verify a caution claim: strict shape (no smuggled member), caution in [0,1], a valid signature by `claim.holder`, bound to
     * `$expectedActionDigest` (when given) and signed by `$expectedHolder` (when given: production callers MUST pass the PCActn's
     * holder, otherwise any key may attest). null = not given. Total.
     */
    public static function verifyCaution(mixed $claim, mixed $expectedActionDigest = null, mixed $expectedHolder = null): bool
    {
        return self::verifyCautionWith($claim, $expectedActionDigest !== null, $expectedActionDigest, $expectedHolder !== null, $expectedHolder);
    }

    /**
     * max(declared, serverRisk) clamped to [0,1]: never below the server's figure, non-decreasing in the declaration; an unusable
     * declaration is ignored and an unusable server risk fails closed to 1.
     */
    public static function combineCaution(mixed $agentDeclaredCaution, mixed $serverRisk): float
    {
        $sr = self::fin($serverRisk);
        $s = $sr !== null ? self::clamp01($sr) : 1.0;
        $d = self::fin($agentDeclaredCaution);
        return $d === null ? $s : max(self::clamp01($d), $s);
    }

    /** The same, taking a signed claim: only a valid claim bound to THIS action (and, when given, THIS holder) is honoured. */
    public static function combineSignedCaution(mixed $claim, mixed $actionDigest, mixed $serverRisk, mixed $expectedHolder = null): Obj
    {
        $sr = self::fin($serverRisk);
        $s = $sr !== null ? self::clamp01($sr) : 1.0;
        $ok = $claim !== null && $actionDigest !== null && self::verifyCautionWith($claim, true, $actionDigest, $expectedHolder !== null, $expectedHolder);
        $eff = self::combineCaution($ok ? $claim->get('caution') : null, $s);
        return Obj::of(['effectiveRisk' => $eff, 'honoured' => $ok, 'escalated' => $eff > $s]);
    }

    /** Exhaustive-grid check of the monotonicity property (non-finite and non-number entries are dropped). */
    public static function checkCautionMonotone(mixed $grid): Obj
    {
        $g = array_values(array_filter(is_array($grid) ? $grid : [], static fn(mixed $x): bool => self::fin($x) !== null));
        foreach ($g as $s) {
            foreach ($g as $d) {
                $e = self::combineCaution($d, $s);
                if ($e < self::clamp01(self::fin($s))) {
                    return Obj::of(['ok' => false, 'counterexample' => [$d, $s]]);
                }
                foreach ($g as $d2) {
                    if (self::fin($d2) >= self::fin($d) && self::combineCaution($d2, $s) < $e) {
                        return Obj::of(['ok' => false, 'counterexample' => [$d2, $s]]);
                    }
                }
            }
        }
        return Obj::of(['ok' => true]);
    }

    // ---- 2. rationale binding ------------------------------------------------------------------------------------------------

    /** Entropy floor of a commitment salt: base64url of >= 16 bytes with >= 8 distinct byte values (at most 256 characters). */
    public static function isStrongSalt(mixed $salt): bool
    {
        if (!is_string($salt) || strlen($salt) > 256 || preg_match('/\A[A-Za-z0-9_-]+\z/D', $salt) !== 1) {
            return false;
        }
        $b = Pca::unb64u($salt);
        return $b !== null && strlen($b) >= self::MIN_SALT_BYTES && count(array_unique(str_split($b))) >= self::MIN_SALT_DISTINCT_BYTES;
    }

    private static function commitDigest(string $actionDigest, string $salt, string $rationale): string
    {
        return Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/rationale/v1', 'a' => $actionDigest, 's' => $salt, 'r' => $rationale]));
    }

    /**
     * The agent commits to its stated reason: publish `commitment`, KEEP `reveal`. The salt (b64u, >= 16 bytes with >= 8 distinct
     * values) defaults to 32 random bytes when the argument is omitted. Throws on a weak salt, a non-string or oversized rationale or
     * an action that cannot be canonicalized.
     */
    public static function bindRationale(mixed $action, mixed $rationale, mixed $salt = null): Obj
    {
        if (func_num_args() < 3) {
            $salt = Pca::b64u(random_bytes(32));
        }
        if (!is_string($rationale)) {
            throw new \InvalidArgumentException('bindRationale: rationale must be a string');
        }
        if (SafeRegex::utf16Len($rationale) > self::MAX_RATIONALE_LEN) {
            throw new \InvalidArgumentException('bindRationale: rationale too long');
        }
        if (!self::isStrongSalt($salt)) {
            throw new \InvalidArgumentException('bindRationale: salt must be b64u of >=' . self::MIN_SALT_BYTES . ' bytes with >=' . self::MIN_SALT_DISTINCT_BYTES . ' distinct values');
        }
        $actionDigest = Pca::hashCanonical($action);
        return Obj::of([
            'commitment' => Obj::of(['v' => 1, 'action_digest' => $actionDigest, 'commitment' => self::commitDigest($actionDigest, $salt, $rationale)]),
            'reveal' => Obj::of(['rationale' => $rationale, 'salt' => $salt]),
        ]);
    }

    private static function commitmentOk(mixed $c): bool
    {
        return $c instanceof Obj && self::fin($c->get('v')) === 1.0 && self::nonEmpty($c->get('action_digest')) && self::nonEmpty($c->get('commitment'));
    }

    /**
     * Does the revealed rationale open the commitment (and, when `$action` is passed, for that very action)? A salt below the
     * entropy floor is refused even if it hashes correctly. Total.
     */
    public static function verifyRationale(mixed $commitment, mixed $reveal, mixed $action = null): bool
    {
        try {
            if (!($commitment instanceof Obj) || !($reveal instanceof Obj) || !self::commitmentOk($commitment)) {
                return false;
            }
            $r = $reveal->get('rationale');
            if (!is_string($r) || SafeRegex::utf16Len($r) > self::MAX_RATIONALE_LEN || !self::isStrongSalt($reveal->get('salt'))) {
                return false;
            }
            if (func_num_args() > 2 && Pca::hashCanonical($action) !== $commitment->get('action_digest')) {
                return false;
            }
            return self::commitDigest($commitment->get('action_digest'), $reveal->get('salt'), $r) === $commitment->get('commitment');
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * After-the-fact audit with an auditor-supplied `$judge(rationale, action)`. Failing to open the commitment, or a rationale that
     * opens and is judged false, is slashable; a malformed commitment, the wrong action or a throwing judge is not. Total.
     */
    public static function auditRationale(mixed $commitment, mixed $action, mixed $reveal, callable $judge): Obj
    {
        $plain = $commitment instanceof Obj;
        $evidence = Obj::of([
            'commitment' => $plain && is_string($commitment->get('commitment')) ? $commitment->get('commitment') : '',
            'action_digest' => $plain && is_string($commitment->get('action_digest')) ? $commitment->get('action_digest') : '',
        ]);
        $out = static fn(string $verdict, bool $slashable, ?string $rationale = null): Obj => Obj::of([
            'verdict' => $verdict,
            'slashable' => $slashable,
            'evidence' => $rationale === null ? $evidence : Obj::of(['commitment' => $evidence->get('commitment'), 'action_digest' => $evidence->get('action_digest'), 'rationale' => $rationale]),
        ]);
        try {
            if (!self::commitmentOk($commitment)) {
                return $out('malformed', false);
            }
            if (Pca::hashCanonical($action) !== $commitment->get('action_digest')) {
                return $out('wrong_action', false);
            }
            if (!self::truthy($reveal) || !self::verifyRationale($commitment, $reveal, $action)) {
                return $out('unopened', true);
            }
            $text = $reveal->get('rationale');
            try {
                $good = $judge($text, $action) === true;
            } catch (\Throwable) {
                return $out('judge_error', false, $text);
            }
            return $out($good ? 'consistent' : 'false_rationale', !$good, $text);
        } catch (\Throwable) {
            return $out('malformed', false);
        }
    }

    // ---- 3. semantic firewall ------------------------------------------------------------------------------------------------

    /** Validate a `tool_schema` argument schema (closed; shape, depth, node count, bounds). null when valid. */
    public static function validateArgSchema(mixed $schema): ?string
    {
        return Authorize::validateArgSchema($schema);
    }

    private static function bindingOf(string $tool, string $signatureDigest, mixed $schema): string
    {
        return Pca::hashCanonical(Obj::of(['tool' => $tool, 'signature_digest' => $signatureDigest, 'schema' => $schema]));
    }

    /**
     * Build a `tool_schema` caveat: authority for exactly this tool + signature + closed argument schema. Throws when the signature
     * has no tool name, the schema is invalid or anything is not canonicalizable. The schema is deep-cloned.
     */
    public static function toolSchemaCaveat(mixed $toolSignature, mixed $argSchema): Obj
    {
        $tool = is_string($toolSignature) ? $toolSignature : ($toolSignature instanceof Obj && is_string($toolSignature->get('name')) ? $toolSignature->get('name') : '');
        if ($tool === '') {
            throw new \InvalidArgumentException('toolSchemaCaveat: tool name required');
        }
        $err = Authorize::validateArgSchema($argSchema);
        if ($err !== null) {
            throw new \InvalidArgumentException("toolSchemaCaveat: $err");
        }
        $schema = self::cloneLenient($argSchema);
        $sigDigest = Pca::hashCanonical($toolSignature);
        return Obj::of([
            'type' => 'tool_schema', 'tool' => $tool, 'signature_digest' => $sigDigest, 'schema' => $schema,
            'schema_digest' => Pca::hashCanonical($schema), 'binding_digest' => self::bindingOf($tool, $sigDigest, $schema),
        ]);
    }

    /** Evaluate a tool call `{tool, args, toolSignature?, toolSignatureDigest?}` against a `tool_schema` caveat: `{ok}` or `{ok: false, reason}`. Never throws. */
    public static function evaluateToolSchema(mixed $caveat, mixed $call): Obj
    {
        [$ok, $reason] = Authorize::evaluateToolSchema($caveat, $call);
        return $ok ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'reason' => $reason]);
    }

    /** The caveat-evaluator hook for `tool_schema`: `$ctx = {toolCall}`; other caveat types are unsatisfied here. */
    public static function toolSchemaEvaluator(mixed $caveat, mixed $ctx): bool
    {
        if (!($ctx instanceof Obj) || !($ctx->get('toolCall') instanceof Obj)) {
            return false;
        }
        return self::evaluateToolSchema($caveat, $ctx->get('toolCall'))->get('ok') === true;
    }

    /** The delegated-narrowing caveat `{type: 'predicates', allow}` (deep-cloned canonical form). */
    public static function predicatesCaveat(mixed $allow): Obj
    {
        return Obj::of(['type' => self::CAVEAT_PREDICATES, 'allow' => self::cloneLenient($allow)]);
    }

    /**
     * The action's spend in USD as `max_spend` reads it: the own `action.action.params.amount` (finite, >= 0) whose own `currency`,
     * when present, is "usd" or "USD". null = no readable spend. (Pca's internal reader takes the inner action.)
     */
    public static function actionSpendUsd(mixed $action): ?float
    {
        if (!($action instanceof Obj) || !($action->get('action') instanceof Obj)) {
            return null;
        }
        $params = $action->get('action')->get('params');
        if (!($params instanceof Obj) || !$params->has('amount')) {
            return null;
        }
        $amount = self::fin($params->get('amount'));
        if ($amount === null || $amount < 0) {
            return null;
        }
        if ($params->has('currency') && $params->get('currency') !== 'usd' && $params->get('currency') !== 'USD') {
            return null;
        }
        return $amount;
    }

    private static function maxSpendSatisfied(Obj $caveat, Obj $ctx): bool
    {
        $lim = self::fin($caveat->get('usd'));
        $spend = self::actionSpendUsd($ctx->get('action'));
        return $lim !== null && $spend !== null && $spend <= $lim;
    }

    private const STOCK_CTX = ['now' => 'now', 'blastRadius' => 'blast_radius', 'reversibilityClass' => 'reversibility_class',
        'delegationDepth' => 'delegation_depth', 'recentActionTimes' => 'recent_action_times'];

    /**
     * Superset of the stock envelope caveat evaluator: adds `predicates` (needs `ctx.action`), `max_spend` (needs `ctx.action`) and
     * `tool_schema` (needs `ctx.toolCall`). The context is the reference's: now, blastRadius, reversibilityClass, delegationDepth,
     * recentActionTimes, action, toolCall. Anything else defers to the stock types and fails closed. Total.
     */
    public static function agentNativeCaveatEvaluator(mixed $caveat, mixed $ctx): bool
    {
        try {
            if (!($caveat instanceof Obj) || !($ctx instanceof Obj)) {
                return false;
            }
            $t = $caveat->get('type');
            if ($t === self::CAVEAT_TOOL_SCHEMA) {
                return self::toolSchemaEvaluator($caveat, $ctx);
            }
            if ($t === self::CAVEAT_PREDICATES) {
                $a = $ctx->get('action');
                if (!($a instanceof Obj) || !self::isList($caveat->get('allow'))) {
                    return false;
                }
                foreach ($caveat->get('allow') as $p) {
                    if (Predicates::predicateMatches($p, $a)) {
                        return true;
                    }
                }
                return false;
            }
            if ($t === self::CAVEAT_MAX_SPEND) {
                return self::maxSpendSatisfied($caveat, $ctx);
            }
            $stock = new Obj();
            foreach (self::STOCK_CTX as $src => $dst) {
                if ($ctx->has($src)) {
                    $stock->set($dst, $ctx->get($src));
                }
            }
            return Pca::evaluateCaveats([$caveat], $stock)['ok'];
        } catch (\Throwable) {
            return false;
        }
    }

    // ---- 4. capability introspection -----------------------------------------------------------------------------------------

    /** @param list<string> $a @param list<string> $b @return list<string> */
    private static function intersectVerbs(array $a, array $b): array
    {
        if (in_array('*', $a, true)) {
            return self::sortedUnique($b);
        }
        if (in_array('*', $b, true)) {
            return self::sortedUnique($a);
        }
        return self::sortedUnique(array_values(array_filter($a, static fn(string $x): bool => in_array($x, $b, true))));
    }

    /** Intersect two resource patterns: the pattern, null = empty, false = cannot decide symbolically (regex). */
    private static function interRes(string $a, string $b): string|false|null
    {
        if ($a === $b) {
            return $a;
        }
        if (str_starts_with($a, 're:') || str_starts_with($b, 're:')) {
            return false;
        }
        if ($a === '*') {
            return $b;
        }
        if ($b === '*') {
            return $a;
        }
        $ap = str_ends_with($a, '*');
        $bp = str_ends_with($b, '*');
        if ($ap && $bp) {
            $pa = substr($a, 0, -1);
            $pb = substr($b, 0, -1);
            return str_starts_with($pb, $pa) ? $b : (str_starts_with($pa, $pb) ? $a : null);
        }
        if ($ap) {
            return str_starts_with($b, substr($a, 0, -1)) ? $b : null;
        }
        if ($bp) {
            return str_starts_with($a, substr($b, 0, -1)) ? $a : null;
        }
        return null;
    }

    /** Collapse a conjunction of resource patterns; null = unsatisfiable. @param list<string> $list @return list<string>|null */
    private static function collapseResources(array $list): ?array
    {
        $lit = null;
        $res = [];
        foreach ($list as $p) {
            if (str_starts_with($p, 're:')) {
                $res[$p] = true;
                continue;
            }
            if ($lit === null) {
                $lit = $p;
            } else {
                $r = self::interRes($lit, $p);
                if ($r === null || $r === false) {
                    return null;
                }
                $lit = $r;
            }
        }
        $names = array_map('strval', array_keys($res));
        usort($names, 'strcmp');
        $out = array_merge($lit !== null && $lit !== '*' ? [$lit] : [], $names);
        return $out === [] ? ['*'] : $out;
    }

    /** @return ?Obj {verbs, resources, where}: the predicate as a scope, or null when it is malformed */
    private static function scopeOfPredicate(mixed $p): ?Obj
    {
        if (!($p instanceof Obj)) {
            return null;
        }
        $v = $p->get('verb');
        if (is_string($v)) {
            $verbs = [$v];
        } elseif (self::isList($v) && array_reduce($v, static fn(bool $c, mixed $x): bool => $c && is_string($x), true)) {
            $verbs = $v;
        } else {
            return null;
        }
        if ($p->has('resource') && !is_string($p->get('resource'))) {
            return null;
        }
        $where = $p->has('where') ? $p->get('where') : [];
        if (!self::isList($where)) {
            return null;
        }
        return Obj::of(['verbs' => self::sortedUnique($verbs), 'resources' => [$p->has('resource') ? $p->get('resource') : '*'], 'where' => $where]);
    }

    /** @param list<Obj> $a @param list<Obj> $b @return list<Obj> */
    private static function intersectScopes(array $a, array $b): array
    {
        $out = [];
        foreach ($a as $x) {
            foreach ($b as $y) {
                $verbs = self::intersectVerbs($x->get('verbs'), $y->get('verbs'));
                if ($verbs === []) {
                    continue;
                }
                $resources = self::collapseResources(array_merge($x->get('resources'), $y->get('resources')));
                if ($resources === null) {
                    continue;
                }
                $s = Obj::of(['verbs' => $verbs, 'resources' => $resources, 'where' => array_merge($x->get('where'), $y->get('where'))]);
                $out[Pca::hashCanonical($s)] = $s;
            }
        }
        $keys = array_map('strval', array_keys($out));
        usort($keys, 'strcmp');
        return array_map(static fn(string $k): Obj => $out[$k], $keys);
    }

    private static function scopeMatches(mixed $s, mixed $verb, mixed $resource, mixed $params): bool
    {
        $verbs = $s->get('verbs');
        if (!in_array('*', $verbs, true) && !in_array($verb, $verbs, true)) {
            return false;
        }
        $action = new Obj();
        $action->set('verb', $verb);
        $action->set('resource', $resource);
        if (self::truthy($params)) {
            $action->set('params', $params);
        }
        $ctx = Obj::of(['action' => $action]);
        foreach ($s->get('resources') as $r) {
            if (!Predicates::predicateMatches(Obj::of(['verb' => '*', 'resource' => $r]), $ctx)) {
                return false;
            }
        }
        if ($params !== null && count($s->get('where')) > 0) {
            return Predicates::predicateMatches(Obj::of(['verb' => '*', 'where' => $s->get('where')]), $ctx);
        }
        return true;
    }

    /** Is this appended / envelope caveat one the verifier (stock + this module's superset) can satisfy at all? */
    private static function wellFormedCaveat(Obj $cv): bool
    {
        $t = $cv->get('type');
        if ($t === self::CAVEAT_EXPIRES || $t === self::CAVEAT_NOT_BEFORE) {
            return self::fin($cv->get('at')) !== null;
        }
        if ($t === self::CAVEAT_RATE) {
            $per = self::fin($cv->get('per_secs'));
            return self::fin($cv->get('max')) !== null && $per !== null && $per > 0;
        }
        if ($t === self::CAVEAT_MAX_BLAST_RADIUS || $t === self::CAVEAT_DELEGATION_DEPTH) {
            return self::fin($cv->get('max')) !== null;
        }
        if ($t === self::CAVEAT_REVERSIBILITY_MAX) {
            return is_string($cv->get('class')) && in_array($cv->get('class'), self::REV, true);
        }
        if ($t === self::CAVEAT_PREDICATES) {
            if (!self::isList($cv->get('allow'))) {
                return false;
            }
            foreach ($cv->get('allow') as $p) {
                if (self::scopeOfPredicate($p) === null) {
                    return false;
                }
            }
            return true;
        }
        if ($t === self::CAVEAT_TOOL_SCHEMA) {
            return self::nonEmpty($cv->get('tool'));
        }
        if ($t === 'budget_alloc') {
            $l = self::fin($cv->get('limit'));
            return $l !== null && $l >= 0;
        }
        if ($t === self::CAVEAT_MAX_SPEND) {
            $l = self::fin($cv->get('usd'));
            return $l !== null && $l >= 0;
        }
        return false;
    }

    private static function emptyEnvelope(): Obj
    {
        return Obj::of(['ok' => false, 'hasEnvelope' => false, 'scopes' => [], 'verbs' => [], 'resources' => [], 'opaqueResourceConstraints' => [],
            'tools' => [], 'toolSchemas' => [], 'unsatisfiable' => [], 'caveats' => [], 'remainingBudgetHints' => new Obj()]);
    }

    /**
     * What an attenuated chain permits NOW: the conjunction of the root `envelope` predicates and every appended caveat, derived with
     * the verifier's own vocabulary (never wider than reality). A chain that does not verify, or one carrying a caveat the verifier
     * cannot satisfy, permits nothing. Deterministic (`$now` supplied) and total. `$policy` takes allowedSuites, pqPins, trustedRoot.
     */
    public static function describeEnvelope(mixed $chain, mixed $now = null, mixed $expectedRootIssuer = null, mixed $policy = null): Obj
    {
        try {
            $pol = $policy instanceof Obj ? $policy : new Obj();
            $suites = self::isList($pol->get('allowedSuites')) ? $pol->get('allowedSuites') : null;
            $trusted = $pol->get('trustedRoot') instanceof Obj ? $pol->get('trustedRoot') : null;
            [$reason, $ok] = Pca::verifyChain($chain, $expectedRootIssuer, $expectedRootIssuer !== null, $suites, $pol->get('pqPins'), $trusted);
            if (!$ok) {
                $e = self::emptyEnvelope();
                $e->set('reason', $reason);
                return $e;
            }
            $root = $chain[0];
            $leaf = $chain[count($chain) - 1];
            $env0 = Authorize::readEnvelope($root);
            $env = self::emptyEnvelope();
            $env->set('ok', true);
            $env->set('hasEnvelope', $env0 !== null);
            $env->set('caveats', $leaf->get('caveats'));
            $h = $env->get('remainingBudgetHints');
            $bad = [];
            $scopes = null;
            $tools = null;
            $seen = false;
            $toolSchemas = [];
            $everything = [Obj::of(['verbs' => ['*'], 'resources' => ['*'], 'where' => []])];
            if ($env0 !== null) {
                $base = array_map(self::scopeOfPredicate(...), $env0->get('predicates'));
                if (in_array(null, $base, true)) {
                    $bad['envelope.predicates'] = true;
                }
                $scopes = self::intersectScopes(array_values(array_filter($base, static fn(?Obj $s): bool => $s !== null)), $everything);
            }
            $min = static fn(?float $cur, float $x): float => $cur === null ? $x : min($cur, $x);
            $fold = function (mixed $cv, bool $inEnvelope) use (&$bad, &$scopes, &$tools, &$seen, &$toolSchemas, $h, $everything, $chain, $min): void {
                if (!($cv instanceof Obj) || !is_string($cv->get('type'))) {
                    $bad['<malformed>'] = true;
                    return;
                }
                $t = $cv->get('type');
                if ($t === self::CAVEAT_ENVELOPE) {
                    if ($seen || $inEnvelope) {
                        $bad[self::CAVEAT_ENVELOPE] = true;
                    }
                    $seen = true;
                    return;
                }
                if (!self::wellFormedCaveat($cv)) {
                    $bad[$t] = true;
                    return;
                }
                if ($t === self::CAVEAT_PREDICATES) {
                    $scopes = self::intersectScopes($scopes ?? $everything, array_map(self::scopeOfPredicate(...), $cv->get('allow')));
                } elseif ($t === self::CAVEAT_TOOL_SCHEMA) {
                    $toolSchemas[] = $cv;
                    $sig = $cv->has('signature_digest') ? IntentWb::jsStr($cv->get('signature_digest')) : 'undefined';
                    $consistent = Authorize::validateArgSchema($cv->get('schema')) === null
                        && Pca::hashCanonical($cv->get('schema')) === $cv->get('schema_digest')
                        && self::bindingOf($cv->get('tool'), $sig, $cv->get('schema')) === $cv->get('binding_digest');
                    if (!$consistent) {
                        $tools = [];
                        $bad[self::CAVEAT_TOOL_SCHEMA] = true;
                    } else {
                        $tools = $tools === null ? [$cv->get('tool')] : array_values(array_filter($tools, static fn(string $x): bool => $x === $cv->get('tool')));
                    }
                } elseif ($t === self::CAVEAT_EXPIRES) {
                    $h->set('expiresAt', $min($h->has('expiresAt') ? $h->get('expiresAt') : null, self::fin($cv->get('at'))));
                } elseif ($t === self::CAVEAT_NOT_BEFORE) {
                    $a = self::fin($cv->get('at'));
                    $h->set('notBefore', $h->has('notBefore') ? max($h->get('notBefore'), $a) : $a);
                } elseif ($t === self::CAVEAT_RATE) {
                    $m = self::fin($cv->get('max'));
                    $p = self::fin($cv->get('per_secs'));
                    $cur = $h->get('maxRate');
                    if ($cur === null) {
                        $better = true;
                    } else {
                        $cm = self::fin($cur->get('max'));
                        $cp = self::fin($cur->get('per_secs'));
                        $better = $m / $p < $cm / $cp || ($m / $p === $cm / $cp && $m < $cm);
                    }
                    if ($better) {
                        $h->set('maxRate', Obj::of(['max' => $cv->get('max'), 'per_secs' => $cv->get('per_secs')]));
                    }
                } elseif ($t === self::CAVEAT_MAX_BLAST_RADIUS) {
                    $h->set('maxBlastRadius', $min($h->has('maxBlastRadius') ? $h->get('maxBlastRadius') : null, self::fin($cv->get('max'))));
                } elseif ($t === self::CAVEAT_REVERSIBILITY_MAX) {
                    $i = array_search($cv->get('class'), self::REV, true);
                    $j = $h->has('reversibilityMax') ? array_search($h->get('reversibilityMax'), self::REV, true) : count(self::REV);
                    if ($i < $j) {
                        $h->set('reversibilityMax', self::REV[$i]);
                    }
                } elseif ($t === self::CAVEAT_DELEGATION_DEPTH) {
                    $rem = self::nz(self::fin($cv->get('max')) - (count($chain) - 1));
                    $h->set('delegationDepthRemaining', $h->has('delegationDepthRemaining') ? min($h->get('delegationDepthRemaining'), $rem) : $rem);
                } elseif ($t === 'budget_alloc') {
                    $h->set('budgetAlloc', $min($h->has('budgetAlloc') ? $h->get('budgetAlloc') : null, self::fin($cv->get('limit'))));
                } elseif ($t === self::CAVEAT_MAX_SPEND) {
                    $h->set('maxSpendUsd', $min($h->has('maxSpendUsd') ? $h->get('maxSpendUsd') : null, self::fin($cv->get('usd'))));
                }
            };
            if ($env0 !== null) {
                foreach ($env0->get('caveats') as $cv) {
                    $fold($cv, true);
                }
            }
            foreach ($leaf->get('caveats') as $cv) {
                $fold($cv, false);
            }
            $env->set('toolSchemas', $toolSchemas);
            $env->set('scopes', $scopes);
            $opaque = [];
            if ($scopes !== null) {
                $vs = [];
                $rs = [];
                foreach ($scopes as $s) {
                    foreach ($s->get('verbs') as $x) {
                        $vs[] = $x;
                    }
                    foreach ($s->get('resources') as $r) {
                        $rs[] = $r;
                        if (str_starts_with($r, 're:')) {
                            $opaque[] = $r;
                        }
                    }
                }
                $env->set('verbs', self::sortedUnique($vs));
                $env->set('resources', self::sortedUnique($rs));
            } else {
                $env->set('verbs', null);
                $env->set('resources', null);
            }
            $env->set('opaqueResourceConstraints', self::sortedUnique($opaque));
            $env->set('tools', $tools === null ? null : self::sortedUnique($tools));
            $unsat = self::sortedUnique(array_map('strval', array_keys($bad)));
            $env->set('unsatisfiable', $unsat);
            if ($unsat !== []) {
                $env->set('scopes', []);
                $env->set('verbs', []);
                $env->set('resources', []);
                $env->set('tools', []);
                $env->set('reason', 'unsatisfiable caveat(s): ' . implode(', ', $unsat));
            }
            $now_ = self::fin($now);
            if ($h->has('expiresAt') && $now_ !== null) {
                $h->set('expiresIn', self::nz($h->get('expiresAt') - $now_));
            }
            return $env;
        } catch (\Throwable) {
            $e = self::emptyEnvelope();
            $e->set('reason', 'introspection error (fail closed)');
            return $e;
        }
    }

    /**
     * Cheap pre-flight an agent can run before attempting. false is DEFINITIVE (the verifier will refuse); true means the symbolic
     * envelope allows it. With `$params` the `where` conditions are evaluated too (fail closed); without, a conditional scope counts
     * as "may permit". null = not given. Total.
     */
    public static function envelopePermits(mixed $env, mixed $verb, mixed $resource, mixed $now = null, mixed $params = null): bool
    {
        try {
            if (!self::truthy($env->get('ok')) || count($env->get('unsatisfiable')) > 0) {
                return false;
            }
            $scopes = $env->get('scopes');
            if ($scopes !== null) {
                $any = false;
                foreach ($scopes as $s) {
                    if (self::scopeMatches($s, $verb, $resource, $params)) {
                        $any = true;
                        break;
                    }
                }
                if (!$any) {
                    return false;
                }
            }
            $h = $env->get('remainingBudgetHints');
            if ($h->has('delegationDepthRemaining') && !(($dr = self::fin($h->get('delegationDepthRemaining'))) !== null && $dr >= 0)) {
                return false;
            }
            if ($h->has('maxSpendUsd') && $params !== null) {
                $spend = self::actionSpendUsd(Obj::of(['action' => Obj::of(['params' => $params])]));
                $cap = Js::num($h->get('maxSpendUsd')); // an infinite cap is a legitimate ceiling
                if ($spend === null || !is_finite($spend) || $cap === null || !($spend <= $cap)) {
                    return false;
                }
            }
            if ($now !== null) {
                $n = self::fin($now);
                if ($n === null) {
                    return false;
                }
                if ($h->has('expiresAt') && !(($ex = self::fin($h->get('expiresAt'))) !== null && $n < $ex)) {
                    return false;
                }
                if ($h->has('notBefore') && !(($nb = self::fin($h->get('notBefore'))) !== null && $n >= $nb)) {
                    return false;
                }
            }
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Pre-flight for a tool call: the tool must be in `env.tools` and satisfy EVERY `tool_schema` caveat. Total. */
    public static function envelopePermitsToolCall(mixed $env, mixed $call): Obj
    {
        try {
            if (!self::truthy($env->get('ok')) || count($env->get('unsatisfiable')) > 0) {
                return Obj::of(['ok' => false, 'reason' => $env->get('reason') ?? 'envelope not usable']);
            }
            $tools = $env->get('tools');
            if ($tools !== null) { // the reference reads call.tool only here (a null call is a TypeError, caught below)
                if ($call === null) {
                    throw new \TypeError('cannot read property of null');
                }
                $has = $call instanceof Obj && $call->has('tool');
                $tool = $call instanceof Obj ? $call->get('tool') : null;
                if (!($has && in_array($tool, $tools, true))) {
                    return Obj::of(['ok' => false, 'reason' => 'tool ' . Authorize::show($has ? IntentWb::jsStr($tool) : 'undefined') . ' not authorized']);
                }
            }
            foreach ($env->get('toolSchemas') as $tc) {
                $r = self::evaluateToolSchema($tc, $call);
                if ($r->get('ok') !== true) {
                    return $r;
                }
            }
            return Obj::of(['ok' => true]);
        } catch (\Throwable) {
            return Obj::of(['ok' => false, 'reason' => 'evaluation error (fail closed)']);
        }
    }

    // ---- 5. authority lease --------------------------------------------------------------------------------------------------

    /**
     * Issue a lease `{cap_id, holder, now, ttl_ms, hard_expires_at?, max_renewals?}`. Throws unless the ids are non-empty, `now` is
     * finite, 0 < ttl_ms <= MAX_LEASE_TTL_MS, hard_expires_at (when present) is finite and after `now` and max_renewals (when
     * present) is a non-negative integer.
     */
    public static function grantLease(mixed $args): Obj
    {
        $a = Sign::n($args);
        if (!($a instanceof Obj)) {
            throw new \InvalidArgumentException('grantLease: cap_id and holder required');
        }
        if (!self::nonEmpty($a->get('cap_id')) || !self::nonEmpty($a->get('holder'))) {
            throw new \InvalidArgumentException('grantLease: cap_id and holder required');
        }
        $now = self::fin($a->get('now'));
        $ttl = self::fin($a->get('ttl_ms'));
        if ($now === null || $ttl === null || $ttl <= 0 || $ttl > self::MAX_LEASE_TTL_MS) {
            throw new \InvalidArgumentException('grantLease: invalid now/ttl_ms');
        }
        $hard = $a->has('hard_expires_at') ? self::fin($a->get('hard_expires_at')) : null;
        if ($a->has('hard_expires_at') && ($hard === null || $hard <= $now)) {
            throw new \InvalidArgumentException('grantLease: hard_expires_at must be finite and in the future');
        }
        $mr = $a->get('max_renewals');
        if ($a->has('max_renewals') && !(self::isInt($mr) && self::fin($mr) >= 0 && !self::negZero($mr))) {
            throw new \InvalidArgumentException('grantLease: invalid max_renewals');
        }
        $exp = $now + $ttl;
        if ($hard !== null) {
            $exp = min($exp, $hard);
        }
        $l = Obj::of(['cap_id' => $a->get('cap_id'), 'holder' => $a->get('holder'), 'issued_at' => self::nz($now), 'renewed_at' => self::nz($now),
            'ttl_ms' => self::nz($ttl), 'renewals' => 0, 'last_seq' => 0, 'expires_at' => self::nz($exp)]);
        if ($hard !== null) {
            $l->set('hard_expires_at', self::nz($hard));
        }
        if ($a->has('max_renewals')) {
            $l->set('max_renewals', self::nz(self::fin($mr)));
        }
        return $l;
    }

    private static function leaseError(mixed $l): ?string
    {
        if (!($l instanceof Obj) || !self::nonEmpty($l->get('cap_id')) || !self::nonEmpty($l->get('holder'))) {
            return 'malformed lease';
        }
        foreach (['issued_at', 'renewed_at', 'ttl_ms', 'expires_at'] as $k) {
            if (self::fin($l->get($k)) === null) {
                return 'malformed lease';
            }
        }
        $ttl = self::fin($l->get('ttl_ms'));
        if ($ttl <= 0 || $ttl > self::MAX_LEASE_TTL_MS) {
            return 'malformed lease';
        }
        foreach (['renewals', 'last_seq'] as $k) {
            if (!(self::isInt($l->get($k)) && self::fin($l->get($k)) >= 0) || self::negZero($l->get($k))) {
                return 'malformed lease';
            }
        }
        if ($l->has('max_renewals') && !(self::isInt($l->get('max_renewals')) && self::fin($l->get('max_renewals')) >= 0 && !self::negZero($l->get('max_renewals')))) {
            return 'malformed lease';
        }
        if ($l->has('hard_expires_at')) {
            $hard = self::fin($l->get('hard_expires_at'));
            if ($hard === null) {
                return 'malformed lease';
            }
            if (self::fin($l->get('expires_at')) > $hard) {
                return 'lease exceeds hard expiry';
            }
        }
        // a lease can never outlive one ttl past its last renewal: anything else is corruption or tampering
        if (self::fin($l->get('expires_at')) > self::fin($l->get('renewed_at')) + $ttl) {
            return 'malformed lease';
        }
        return null;
    }

    /**
     * Live iff the record is well-formed, the clock has not run back more than the skew window past the last renewal and
     * now < expires_at. Anything else is dead with a `reason` and `expiresIn` 0 (fail closed).
     */
    public static function leaseState(mixed $lease, mixed $now): Obj
    {
        $dead = static fn(string $reason): Obj => Obj::of(['live' => false, 'expiresIn' => 0, 'reason' => $reason]);
        $n = self::fin($now);
        if ($n === null) {
            return $dead('invalid clock');
        }
        $e = self::leaseError($lease);
        if ($e !== null) {
            return $dead($e);
        }
        if ($n < self::fin($lease->get('renewed_at')) - self::HEARTBEAT_SKEW_MS) {
            return $dead('clock before last renewal');
        }
        $expiresIn = self::fin($lease->get('expires_at')) - $n;
        if ($expiresIn <= 0) {
            return $dead('lease lapsed');
        }
        return Obj::of(['live' => true, 'expiresIn' => self::nz($expiresIn)]);
    }

    /** The lease holder's signed liveness proof ({cap_id, seq, at, holder, lease_issued_at}). */
    public static function signHeartbeat(mixed $body, KeyPair $holder): Obj
    {
        return SignersMore::signHeartbeat($body, $holder);
    }

    /**
     * The reference's pure renewLease: renew on a valid, fresh, in-order heartbeat signed by the lease holder for THIS lease grant. A
     * lease that has lapsed (or is malformed or clock-anomalous) is dead for good. Renewal never passes hard_expires_at, never
     * shortens the lease and spends the renewal budget. Returns `{ok: true, lease}` or `{ok: false, reason}`; total.
     */
    public static function renewCapabilityLease(mixed $lease, mixed $hb, mixed $now): Obj
    {
        $no = static fn(string $reason): Obj => Obj::of(['ok' => false, 'reason' => $reason]);
        try {
            $st = self::leaseState($lease, $now);
            if ($st->get('live') !== true) {
                return $no($st->get('reason') === 'lease lapsed' ? 'lease lapsed' : 'lease not live: ' . $st->get('reason'));
            }
            if (!($hb instanceof Obj) || !self::onlyKeys($hb, self::HB_KEYS) || !is_string($hb->get('sig'))) {
                return $no('malformed heartbeat');
            }
            if (!self::strictEq($hb->get('cap_id'), $lease->get('cap_id')) || !self::strictEq($hb->get('holder'), $lease->get('holder'))
                || !self::strictEq($hb->get('lease_issued_at'), $lease->get('issued_at'))) {
                return $no('heartbeat not for this lease');
            }
            $seq = self::fin($hb->get('seq'));
            if ($seq === null || floor($seq) !== $seq || abs($seq) > self::SAFE_INT || $seq <= self::fin($lease->get('last_seq'))) {
                return $no('stale or replayed heartbeat');
            }
            $n = self::fin($now);
            $at = self::fin($hb->get('at'));
            if ($at === null || $n === null || !(abs($at - $n) <= self::HEARTBEAT_SKEW_MS)) { // a non-finite clock never fits the window
                return $no('heartbeat outside skew window');
            }
            if (!Pca::verifyEd25519B64u($lease->get('holder'), self::msg(SignersMore::HEARTBEAT_DOMAIN, $hb->without('sig')), $hb->get('sig'))) {
                return $no('bad heartbeat signature');
            }
            if ($lease->has('max_renewals') && self::fin($lease->get('renewals')) >= self::fin($lease->get('max_renewals'))) {
                return $no('renewal budget exhausted');
            }
            $exp = $n + self::fin($lease->get('ttl_ms'));
            if ($lease->has('hard_expires_at')) {
                $exp = min($exp, self::fin($lease->get('hard_expires_at')));
            }
            if (!is_finite($exp)) {
                return $no('malformed lease');
            }
            $next = $lease->without();
            $next->set('renewals', self::nz(self::fin($lease->get('renewals')) + 1));
            $next->set('last_seq', $hb->get('seq'));
            $next->set('renewed_at', self::nz(max($n, self::fin($lease->get('renewed_at')))));
            $next->set('expires_at', self::nz(max($exp, self::fin($lease->get('expires_at')))));
            return Obj::of(['ok' => true, 'lease' => $next]);
        } catch (\Throwable) {
            return $no('malformed heartbeat');
        }
    }
}
