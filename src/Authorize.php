<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Predicates.php';
require_once __DIR__ . '/SafeRegex.php';
require_once __DIR__ . '/StateStore.php';
require_once __DIR__ . '/Decision.php';
require_once __DIR__ . '/Escalation.php';

/** The operation an allowing decision is bound to. `id` is the digest of the presented PCActn. */
final class AuthorizedOperation
{
    public function __construct(
        public readonly string $verb,
        public readonly string $resource,
        public readonly string $paramsDigest,
        public readonly string $id,
    ) {
    }
}

/**
 * Outcome of {@see Authorize::authorize}. `allow` is the one thing a caller must branch on.
 *
 * `status` is 200, 401 (no / undecodable / unauthenticated proof) or 403. `checks` maps each check to `pass`, `fail` or
 * `not-enforced`; `reason` is the decisive one (an `operation` failure first), null on success. `missing` names
 * configuration components that were absent (the call was refused before any verification). `verdict` is the core
 * verifier's verdict (when it ran).
 *
 * `decision` is `allow` (and `allow` is true), `escalate` (refused, 403: `escalation` is the request to put to the principal)
 * or `deny`. `allow` is exactly `decision === 'allow'`: an escalate is never an allow, so a caller that only reads `allow`
 * fails closed. On an allow admitted by a principal's answer `escalation` is `{answered_by: <principal>}`.
 * `legacyModelPolarity` is true when a grant reads model-derived paths under the compatibility mode `model_polarity: legacy`
 * (rule 21): the allow is degraded and a caller that needs the tighten-only guarantee must refuse it.
 */
final class AuthorizeResult
{
    public readonly string $decision;

    /**
     * @param array<string,string>  $checks
     * @param list<string>          $reasons
     * @param list<string>|null     $missing
     * @param array<string,mixed>|null $verdict
     */
    public function __construct(
        public readonly bool $allow,
        public readonly int $status,
        public readonly array $checks = [],
        public readonly array $reasons = [],
        public readonly ?string $reason = null,
        public readonly ?AuthorizedOperation $operation = null,
        public readonly ?Obj $pcactn = null,
        public readonly ?array $verdict = null,
        public readonly ?array $missing = null,
        ?string $decision = null,
        public readonly ?Obj $escalation = null,
        public readonly bool $legacyModelPolarity = false,
        public readonly array $degraded = [],
    ) {
        $this->decision = $allow ? 'allow' : ($decision === 'escalate' ? 'escalate' : 'deny');
    }
}

/**
 * The `authorize` components {@see PcaMiddleware} adds on top of its audience and grant resolver (the middleware opt-in).
 *
 * `operation` maps the request to the operation the handler WILL execute: `(ServerRequestInterface $request) =>
 * ['verb' => string, 'resource' => string, 'params' => Obj] | null`. It comes from the server's own routing and parsed
 * input, never from the PCActn. null (or a mapping that throws) denies.
 */
final class AuthorizeOptions
{
    /** @var \Closure|null */
    public readonly ?\Closure $operation;
    /** @var \Closure|null */
    public readonly ?\Closure $escalationAnswer;

    /**
     * @param mixed         $stateStore replay store with an atomic `claim(string $key, int $counter): ClaimResult`
     * @param callable|null $isRevoked  `(Obj $pcactn, Obj $grant): bool`; only `false` passes
     * @param callable|null $operation  `(ServerRequestInterface $request): array|Obj|null` (see the class doc)
     * @param string|null   $plan       `'single-step'` (default) or null (then `context` must supply the plan)
     * @param callable|null $context    `(Obj $pcactn): Obj|array|null` (see {@see Authorize::authorize})
     * @param list<string>  $require    extra check names that must pass
     * @param list<string|Obj>|null $escalationPrincipals pinned b64u Ed25519 keys (or pins `{pk, pq_pk?}`) whose signed
     *                                  EscalationAnswers count; with none every `escalate` is refused. Needs a state store
     *                                  with `last(string $key): ?int` ({@see LastStateStore}); a store without it is refused here
     * @param callable|null $escalationAnswer `(ServerRequestInterface $request): ?Obj` reading the answer from the
     *                                  request (default in {@see PcaMiddleware}: header `PCA-Escalation-Answer`, body `escalation_answer`)
     */
    public function __construct(
        public readonly mixed $stateStore = null,
        public readonly mixed $isRevoked = null,
        ?callable $operation = null,
        public readonly ?string $plan = Authorize::SINGLE_STEP,
        public readonly mixed $context = null,
        public readonly array $require = [],
        public readonly ?array $escalationPrincipals = null,
        ?callable $escalationAnswer = null,
    ) {
        $this->operation = $operation === null ? null : \Closure::fromCallable($operation);
        $this->escalationAnswer = $escalationAnswer === null ? null : \Closure::fromCallable($escalationAnswer);
        if ($escalationPrincipals !== null && $escalationPrincipals !== []
            && (!is_object($stateStore) || !is_callable([$stateStore, 'last']))) {
            throw new \InvalidArgumentException('escalationPrincipals needs a state store with last(string $key): ?int '
                . '(an answer is bound to the holder history; a store without it cannot admit an answered escalation)');
        }
    }
}

/**
 * `authorize()`: the full authorization pipeline for a PHP resource server or tool guard (0.5, additive).
 *
 * {@see Pca::verifyPcactnCore} answers "is this a validly signed PCActn for this audience". `authorize` answers "may THIS
 * operation run now", in the order of the TypeScript `authorize()`:
 *
 *  1. configuration: `audience`, `resolveGrant`, `stateStore` (with `claim`) and `isRevoked` are REQUIRED, and the call
 *     must name the `operation` it will execute (verb, resource, params). A missing one denies with its name.
 *  2. the core checks, then `revocation` (`isRevoked`), then `zk_compliance` (no verifier here: fail closed).
 *  3. `operation`: the signed verb / resource equal the operation's and the signed `params_digest` opens to exactly the
 *     operation's params. Those params are what the predicates and caveats read.
 *  4. `grant_ref`, `params_digest`, `plan_root_authorized`, `attestation` (a grant that pins the agent needs an
 *     attestation verifier this SDK does not have: fail closed), `reversibility`.
 *  5. policy: envelope predicates (default deny), envelope caveats and the root caveats outside the envelope (`policy`),
 *     and the caveats delegation hops appended (`delegated_caveats`); `predicates` and `tool_schema` caveats are
 *     enforced, unknown caveat types fail closed.
 *  6. replay: only when everything above passes, `stateStore->claim("<grant id>:<leaf holder>", counter)`.
 *
 * Not ported from the TypeScript policy VM: risk score, trust budget, threshold co-sign, revocation epochs and beacons.
 * Never throws: any internal error is a denial.
 */
final class Authorize
{
    public const SINGLE_STEP = 'single-step';

    /**
     * TEST SEAM: may return an edited core verdict (e.g. with an escalate-class failure injected) before the pipeline reads
     * it. Always null in production; the escalation guard tests are its only user.
     * @var \Closure|null
     */
    public static ?\Closure $coreHook = null;
    public const ENVELOPE_CAVEAT = 'envelope';

    /** The checks that must be `pass`; `require` can add names, never remove these. */
    public const DEFAULT_REQUIRED_CHECKS = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience',
        'validity', 'grant_ref_bound', 'operation', 'params_digest', 'policy'];

    /** A failing one of these is an authentication failure (401); anything else is insufficient authority (403). */
    public const AUTHN_CHECKS = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'leaf_signature',
        'malformed', 'grant_ref'];

    public const MAX_SCHEMA_DEPTH = 8;
    public const MAX_SCHEMA_NODES = 256;
    public const MAX_OBJECT_PROPS = 64;
    public const MAX_ENUM_VALUES = 256;
    public const DEFAULT_MAX_ARRAY_ITEMS = 256;
    public const ABSOLUTE_MAX_ARRAY_ITEMS = 4096;
    public const DEFAULT_MAX_STRING_LEN = 65536;
    public const ABSOLUTE_MAX_STRING_LEN = 1048576;
    public const MAX_VALUE_NODES = 10000;

    private const SPEC_KEYS = [
        'string' => ['type', 'enum', 'const', 'minLength', 'maxLength', 'prefix'],
        'number' => ['type', 'enum', 'const', 'min', 'max'],
        'integer' => ['type', 'enum', 'const', 'min', 'max'],
        'boolean' => ['type', 'enum', 'const'],
        'object' => ['type', 'props', 'required'],
        'array' => ['type', 'items', 'minItems', 'maxItems'],
    ];

    private const CLASS_RANK = ['reversible' => 0, 'rate_limited' => 1, 'costly' => 1, 'irreversible' => 2];

    // ---- small value helpers ------------------------------------------------------------------------------------------

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

    private static function isList(mixed $x): bool
    {
        return is_array($x) && array_is_list($x);
    }

    private static function isInt(mixed $x): bool
    {
        $f = self::fin($x);
        return $f !== null && floor($f) === $f;
    }

    private static function nonNegInt(mixed $x, int $max): bool
    {
        $f = self::fin($x);
        return $f !== null && floor($f) === $f && $f >= 0 && $f <= $max;
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

    /** JavaScript `===` on the scalars a schema can hold (numbers compare as doubles; a bool is never a number). */
    private static function jsEq(mixed $a, mixed $b): bool
    {
        $fa = self::fin($a);
        $fb = self::fin($b);
        if ($fa !== null || $fb !== null) {
            return $fa !== null && $fb !== null && $fa === $fb;
        }
        if (is_bool($a) || is_bool($b)) {
            return is_bool($a) && is_bool($b) && $a === $b;
        }
        if (is_string($a) && is_string($b)) {
            return $a === $b;
        }
        return false;
    }

    /** ECMAScript String(v) of a JSON value. */
    private static function jsString(mixed $v): string
    {
        return IntentWb::jsStr($v);
    }

    /** The first `$n` code points of `$s`. */
    private static function head(string $s, int $n): string
    {
        $cps = preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY);
        return is_array($cps) ? implode('', array_slice($cps, 0, $n)) : substr($s, 0, $n);
    }

    /** A JSON string literal of the (truncated) name, for reasons. */
    private static function show(string $k): string
    {
        $s = SafeRegex::utf16Len($k) > 48 ? self::head($k, 48) . '…' : $k;
        return json_encode($s, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS
            | JSON_INVALID_UTF8_SUBSTITUTE) ?: '""';
    }

    /**
     * Native PHP numbers inside a value become JSON numbers (their ECMAScript Number form), recursively, so the copy and
     * the digest are those of the JSON value TypeScript would see. Everything else is kept as is.
     */
    private static function normalize(mixed $v, int $depth = 0): mixed
    {
        if ($depth > Json::MAX_DEPTH + 1) {
            throw new JsonError('nesting too deep');
        }
        if (is_int($v)) {
            return new Num((string)$v);
        }
        if (is_float($v)) {
            if (!is_finite($v)) {
                return new Num('1e999'); // refused by the strict profile (JSON has no NaN / Infinity)
            }
            if ($v === 0.0) {
                return new Num('0'); // -0 serializes as 0 (JSON.stringify)
            }
            return new Num(floor($v) === $v && abs($v) <= 9007199254740991.0 ? sprintf('%.0f', $v) : IntentWb::jsStr($v));
        }
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::normalize($v->get($k), $depth + 1));
            }
            return $o;
        }
        if (is_array($v) && array_is_list($v)) {
            return array_map(static fn(mixed $x): mixed => self::normalize($x, $depth + 1), $v);
        }
        return $v;
    }

    /** A member of an operation given as a PHP array or an Obj. */
    private static function member(mixed $o, string $k): mixed
    {
        if ($o instanceof Obj) {
            return $o->get($k);
        }
        return is_array($o) && array_key_exists($k, $o) ? $o[$k] : null;
    }

    private static function validOperation(mixed $op): bool
    {
        if (!($op instanceof Obj) && !(is_array($op) && !array_is_list($op))) {
            return false;
        }
        $verb = self::member($op, 'verb');
        $resource = self::member($op, 'resource');
        return is_string($verb) && $verb !== '' && is_string($resource) && $resource !== ''
            && self::member($op, 'params') instanceof Obj;
    }

    // ---- the replay key ------------------------------------------------------------------------------------------------

    /** The store key of a holder's counter stream (the TypeScript `pcaStateKey` default scope). */
    public static function stateKey(string $grantId, string $leafHolder): string
    {
        return $grantId . ':' . $leafHolder;
    }

    // ---- the envelope (TypeScript envelope.ts readEnvelope / risk.ts validateRiskPolicy) -----------------------------------

    private static function riskPolicyError(mixed $p): ?string
    {
        if (!($p instanceof Obj)) {
            return 'risk_policy must be an object';
        }
        $w = $p->get('weights');
        if (!($w instanceof Obj)) {
            return 'risk_policy.weights missing';
        }
        foreach (['alpha', 'beta', 'gamma', 'delta', 'epsilon', 'zeta'] as $k) {
            $v = self::fin($w->get($k));
            if ($v === null || $v < 0) {
                return "risk_policy.weights.$k must be finite and >= 0";
            }
        }
        $vals = [];
        foreach (['theta1', 'theta2', 'kappa', 'lambda', 'rho', 'bMax'] as $k) {
            $vals[$k] = self::fin($p->get($k));
            if ($vals[$k] === null) {
                return "risk_policy.$k must be finite";
            }
        }
        if ($vals['theta1'] < 0 || $vals['theta2'] < $vals['theta1']) {
            return 'risk_policy requires 0 <= theta1 <= theta2';
        }
        if ($vals['kappa'] <= 0) {
            return 'risk_policy.kappa must be > 0';
        }
        if ($vals['lambda'] < 0 || $vals['rho'] < 0 || $vals['bMax'] < 0) {
            return 'risk_policy lambda/rho/bMax must be >= 0';
        }
        return null;
    }

    /** The grant's policy envelope: its FIRST `envelope` caveat without `type`, or null when absent or malformed. */
    public static function readEnvelope(mixed $grant): ?Obj
    {
        try {
            $cs = $grant instanceof Obj ? $grant->get('caveats') : null;
            if (!self::isList($cs)) {
                return null;
            }
            $cv = null;
            foreach ($cs as $c) {
                if ($c instanceof Obj && $c->get('type') === self::ENVELOPE_CAVEAT) {
                    $cv = $c;
                    break;
                }
            }
            if ($cv === null) {
                return null;
            }
            $e = $cv->without('type');
            if (!is_string($e->get('goal_commit'))) {
                return null;
            }
            if (!self::isList($e->get('predicates')) || !self::isList($e->get('caveats'))) {
                return null;
            }
            $ab = $e->get('agent_binding');
            if (!($ab instanceof Obj) && !self::isList($ab)) {
                return null;
            }
            if (self::riskPolicyError($e->get('risk_policy')) !== null) {
                return null;
            }
            return $e;
        } catch (\Throwable) {
            return null;
        }
    }

    /** Every root caveat except the first `envelope` one (TypeScript `rootCaveats`); a non-list is returned as is. */
    public static function rootCaveats(mixed $grant): mixed
    {
        $cs = $grant instanceof Obj ? $grant->get('caveats') : null;
        if (!self::isList($cs)) {
            return $cs;
        }
        $out = $cs;
        foreach ($out as $i => $c) {
            if ($c instanceof Obj && $c->get('type') === self::ENVELOPE_CAVEAT) {
                array_splice($out, $i, 1);
                break;
            }
        }
        return $out;
    }

    /** TypeScript `requiresAttestation`: any agent pin in `agent_binding` requires a bound attestation. */
    private static function requiresAttestation(mixed $binding): bool
    {
        $b = $binding instanceof Obj ? $binding : new Obj();
        $ne = static fn(mixed $x): bool => self::isList($x) && count($x) > 0;
        $hasMin = $b->has('min_measurement') && $b->get('min_measurement') !== '';
        $op = $b->get('operator');
        return $ne($b->get('model_allowlist')) || $hasMin || (is_string($op) && $op !== '')
            || $ne($b->get('weights_allowlist')) || $ne($b->get('system_prompt_allowlist'))
            || $ne($b->get('tool_manifest_allowlist')) || $b->get('require_hardware') === true
            || $b->get('require_measured_weights') === true;
    }

    // ---- the semantic firewall: `tool_schema` caveats (TypeScript agent-native.ts) --------------------------------------

    /** Validate a `tool_schema` argument schema (closed; shape, depth, node count, bounds). null when valid. */
    public static function validateArgSchema(mixed $schema): ?string
    {
        if (!($schema instanceof Obj)) {
            return 'schema must be an object';
        }
        if (!self::onlyKeys($schema, ['props', 'required'])) {
            return 'unknown schema key';
        }
        $nodes = 0;
        return self::objectSchemaError($schema->get('props'), $schema->has('required'), $schema->get('required'), 1, $nodes);
    }

    private static function objectSchemaError(mixed $props, bool $hasRequired, mixed $required, int $depth, int &$nodes): ?string
    {
        if ($depth > self::MAX_SCHEMA_DEPTH) {
            return 'schema too deep';
        }
        $nodes++;
        if ($nodes > self::MAX_SCHEMA_NODES) {
            return 'schema too large';
        }
        if (!($props instanceof Obj)) {
            return 'props must be an object';
        }
        if (count($props->keys()) > self::MAX_OBJECT_PROPS) {
            return 'too many props';
        }
        foreach ($props->keys() as $n) {
            if (preg_match('/\A[A-Za-z0-9_]{1,64}\z/D', $n) !== 1) {
                return "invalid property name '" . self::head($n, 32) . "'";
            }
            $e = self::specError($props->get($n), $depth + 1, $nodes);
            if ($e !== null) {
                return "$n: $e";
            }
        }
        if ($hasRequired) {
            if (!self::isList($required) || count($required) > self::MAX_OBJECT_PROPS) {
                return 'required must be a short array';
            }
            foreach ($required as $r) {
                if (!is_string($r) || !$props->has($r)) {
                    return 'required names an undeclared property';
                }
            }
        }
        return null;
    }

    private static function specError(mixed $spec, int $depth, int &$nodes): ?string
    {
        if ($depth > self::MAX_SCHEMA_DEPTH) {
            return 'schema too deep';
        }
        $nodes++;
        if ($nodes > self::MAX_SCHEMA_NODES) {
            return 'schema too large';
        }
        $t = $spec instanceof Obj ? $spec->get('type') : null;
        if (!is_string($t) || !array_key_exists($t, self::SPEC_KEYS)) {
            return 'unknown type';
        }
        /** @var Obj $spec */
        if (!self::onlyKeys($spec, self::SPEC_KEYS[$t])) {
            return 'unknown spec key';
        }
        if ($t === 'object') {
            $nodes--; // counted once by objectSchemaError
            return self::objectSchemaError($spec->get('props'), $spec->has('required'), $spec->get('required'), $depth, $nodes);
        }
        if ($t === 'array') {
            if ($spec->has('minItems') && !self::nonNegInt($spec->get('minItems'), self::ABSOLUTE_MAX_ARRAY_ITEMS)) {
                return 'bad minItems';
            }
            if ($spec->has('maxItems') && !self::nonNegInt($spec->get('maxItems'), self::ABSOLUTE_MAX_ARRAY_ITEMS)) {
                return 'bad maxItems';
            }
            if ($spec->has('minItems') && $spec->has('maxItems')
                && self::fin($spec->get('minItems')) > self::fin($spec->get('maxItems'))) {
                return 'minItems > maxItems';
            }
            return self::specError($spec->get('items'), $depth + 1, $nodes);
        }
        $ok = static function (mixed $v) use ($t): bool {
            if ($t === 'string') {
                return is_string($v) && SafeRegex::utf16Len($v) <= 1024;
            }
            if ($t === 'boolean') {
                return is_bool($v);
            }
            return self::fin($v) !== null && ($t === 'number' || self::isInt($v));
        };
        if ($spec->has('const') && !$ok($spec->get('const'))) {
            return 'bad const';
        }
        if ($spec->has('enum')) {
            $en = $spec->get('enum');
            if (!self::isList($en) || count($en) === 0 || count($en) > self::MAX_ENUM_VALUES) {
                return 'bad enum';
            }
            foreach ($en as $x) {
                if (!$ok($x)) {
                    return 'bad enum';
                }
            }
        }
        if ($t === 'string') {
            if ($spec->has('minLength') && !self::nonNegInt($spec->get('minLength'), self::ABSOLUTE_MAX_STRING_LEN)) {
                return 'bad minLength';
            }
            if ($spec->has('maxLength') && !self::nonNegInt($spec->get('maxLength'), self::ABSOLUTE_MAX_STRING_LEN)) {
                return 'bad maxLength';
            }
            if ($spec->has('minLength') && $spec->has('maxLength')
                && self::fin($spec->get('minLength')) > self::fin($spec->get('maxLength'))) {
                return 'minLength > maxLength';
            }
            if ($spec->has('prefix') && (!is_string($spec->get('prefix')) || SafeRegex::utf16Len($spec->get('prefix')) > 512)) {
                return 'bad prefix';
            }
        } elseif ($t === 'number' || $t === 'integer') {
            if ($spec->has('min') && self::fin($spec->get('min')) === null) {
                return 'bad min';
            }
            if ($spec->has('max') && self::fin($spec->get('max')) === null) {
                return 'bad max';
            }
            if ($spec->has('min') && $spec->has('max') && self::fin($spec->get('min')) > self::fin($spec->get('max'))) {
                return 'min > max';
            }
        }
        return null;
    }

    private static function checkValue(Obj $spec, mixed $v, string $path, int $depth, int &$n): ?string
    {
        if ($depth > self::MAX_SCHEMA_DEPTH + 1) {
            return "$path: too deep";
        }
        $n++;
        if ($n > self::MAX_VALUE_NODES) {
            return "$path: too many values";
        }
        $t = $spec->get('type');
        if ($t === 'object') {
            if (!($v instanceof Obj)) {
                return "$path: expected object";
            }
            return self::checkObject($spec->get('props'), $spec->get('required'), $v, $path, $depth, $n);
        }
        if ($t === 'array') {
            if (!self::isList($v)) {
                return "$path: expected array";
            }
            $mx = min($spec->has('maxItems') ? self::fin($spec->get('maxItems')) : self::DEFAULT_MAX_ARRAY_ITEMS,
                self::ABSOLUTE_MAX_ARRAY_ITEMS);
            if (count($v) > $mx) {
                return "$path: exceeds maxItems";
            }
            if ($spec->has('minItems') && count($v) < self::fin($spec->get('minItems'))) {
                return "$path: below minItems";
            }
            foreach ($v as $i => $x) {
                $e = self::checkValue($spec->get('items'), $x, "{$path}[$i]", $depth + 1, $n);
                if ($e !== null) {
                    return $e;
                }
            }
            return null;
        }
        if ($t === 'string') {
            if (!is_string($v)) {
                return "$path: wrong type (expected string)";
            }
            $len = SafeRegex::utf16Len($v);
            if ($len > min($spec->has('maxLength') ? self::fin($spec->get('maxLength')) : self::DEFAULT_MAX_STRING_LEN,
                    self::ABSOLUTE_MAX_STRING_LEN)) {
                return "$path: exceeds maxLength";
            }
            if ($spec->has('minLength') && $len < self::fin($spec->get('minLength'))) {
                return "$path: below minLength";
            }
            if ($spec->has('prefix') && !SafeRegex::startsWithUnits($v, $spec->get('prefix'))) {
                return "$path: violates prefix";
            }
        } elseif ($t === 'number' || $t === 'integer') {
            $f = self::fin($v);
            if ($f === null || ($t === 'integer' && floor($f) !== $f)) {
                return "$path: wrong type (expected $t)";
            }
            if ($spec->has('min') && $f < self::fin($spec->get('min'))) {
                return "$path: below min";
            }
            if ($spec->has('max') && $f > self::fin($spec->get('max'))) {
                return "$path: above max";
            }
        } elseif ($t === 'boolean') {
            if (!is_bool($v)) {
                return "$path: wrong type (expected boolean)";
            }
        } else {
            return "$path: unknown type";
        }
        if ($spec->has('const') && !self::jsEq($spec->get('const'), $v)) {
            return "$path: violates const";
        }
        if ($spec->has('enum')) {
            foreach ($spec->get('enum') as $e) {
                if (self::jsEq($e, $v)) {
                    return null;
                }
            }
            return "$path: violates enum";
        }
        return null;
    }

    private static function checkObject(Obj $props, mixed $required, Obj $obj, string $path, int $depth, int &$n): ?string
    {
        foreach ($obj->keys() as $k) {
            if (!$props->has($k)) {
                return "$path: unexpected argument " . self::show($k);
            }
        }
        foreach (self::isList($required) ? $required : [] as $r) {
            if (!$obj->has($r)) {
                return "$path: missing required argument '$r'";
            }
        }
        foreach ($obj->keys() as $k) {
            $e = self::checkValue($props->get($k), $obj->get($k), "$path.$k", $depth + 1, $n);
            if ($e !== null) {
                return $e;
            }
        }
        return null;
    }

    /** A member of a tool call given as a PHP array or an Obj: [present, value]. */
    private static function callMember(mixed $call, string $k): array
    {
        if ($call instanceof Obj) {
            return [$call->has($k), $call->get($k)];
        }
        return is_array($call) && array_key_exists($k, $call) ? [true, $call[$k]] : [false, null];
    }

    /**
     * Evaluate a tool call `['tool' => string, 'args' => Obj, 'toolSignatureDigest' => ?string]` against a `tool_schema`
     * caveat. Returns `[ok, reason]` (reason null when ok). Same rules as the TypeScript `evaluateToolSchema`. Never throws.
     *
     * @return array{0: bool, 1: ?string}
     */
    public static function evaluateToolSchema(mixed $caveat, mixed $call): array
    {
        try {
            if (!($caveat instanceof Obj) || $caveat->get('type') !== 'tool_schema'
                || !is_string($caveat->get('tool')) || $caveat->get('tool') === '') {
                return [false, 'malformed tool_schema caveat'];
            }
            $verr = self::validateArgSchema($caveat->get('schema'));
            if ($verr !== null) {
                return [false, "malformed tool_schema caveat: $verr"];
            }
            /** @var Obj $schema */
            $schema = $caveat->get('schema');
            if (Pca::hashCanonical($schema) !== $caveat->get('schema_digest')) {
                return [false, 'schema digest mismatch'];
            }
            $sig = $caveat->has('signature_digest') ? self::jsString($caveat->get('signature_digest')) : 'undefined';
            if (Pca::hashCanonical(Obj::of(['tool' => $caveat->get('tool'), 'signature_digest' => $sig, 'schema' => $schema]))
                !== $caveat->get('binding_digest')) {
                return [false, 'binding digest mismatch'];
            }
            [, $tool] = self::callMember($call, 'tool');
            [, $args] = self::callMember($call, 'args');
            if (!is_string($tool) || !($args instanceof Obj)) {
                return [false, 'malformed call'];
            }
            if ($tool !== $caveat->get('tool')) {
                return [false, 'tool ' . self::show($tool) . ' not authorized'];
            }
            [$hasSig, $callSig] = self::callMember($call, 'toolSignatureDigest');
            if ($hasSig && $callSig !== $caveat->get('signature_digest')) {
                return [false, 'signed tool_binding differs from the authorized tool signature'];
            }
            $n = 0;
            $e = self::checkObject($schema->get('props'), $schema->get('required'), $args, 'args', 1, $n);
            return $e !== null ? [false, $e] : [true, null];
        } catch (\Throwable) {
            return [false, 'evaluation error (fail closed)'];
        }
    }

    // ---- the agent-native caveat evaluator (TypeScript evaluateAgentCaveats) --------------------------------------------

    private static function agentCaveatSatisfied(mixed $cv, Obj $ctx, Obj $actionCtx, mixed $toolCall): bool
    {
        try {
            if (!($cv instanceof Obj)) {
                return false;
            }
            $t = $cv->get('type');
            if ($t === 'tool_schema') {
                return self::evaluateToolSchema($cv, $toolCall)[0];
            }
            if ($t === 'predicates') {
                $allow = $cv->get('allow');
                if (!self::isList($allow)) {
                    return false;
                }
                foreach ($allow as $p) {
                    if (Predicates::predicateMatches($p, $actionCtx)) {
                        return true;
                    }
                }
                return false;
            }
            // max_spend and the stock types: the 0.4.1 evaluator (unknown types fail closed there)
            return Pca::evaluateCaveats([$cv], $ctx)['ok'];
        } catch (\Throwable) {
            return false;
        }
    }

    /** An object context given as an Obj, a PHP string-keyed array, or null (= empty); anything else is null. */
    private static function asObj(mixed $v): ?Obj
    {
        if ($v === null) {
            return new Obj();
        }
        if ($v instanceof Obj) {
            return $v;
        }
        if (is_array($v) && ($v === [] || !array_is_list($v))) {
            return Obj::of($v);
        }
        return null;
    }

    /** A plan node given as an Obj or a PHP string-keyed array, else null. */
    private static function nodeObj(mixed $n): ?Obj
    {
        return $n instanceof Obj ? $n : (is_array($n) && $n !== [] && !array_is_list($n) ? Obj::of($n) : null);
    }

    /**
     * Evaluate caveats with the agent-native evaluator: the stock types of {@see Pca::evaluateCaveats}, plus `predicates`
     * (`allow`: the action must match one predicate; needs `$actionCtx` = `{action: {...}, subject?, env?}`) and
     * `tool_schema` (needs `$toolCall` = `['tool', 'args', 'toolSignatureDigest'?]`). `$ctx` is the stock context (`now`,
     * `action`, `blast_radius`, ...). Unknown types fail closed. Never throws.
     *
     * @return array{ok: bool, failed: list<string>}
     */
    public static function evaluateAgentCaveats(mixed $caveats, mixed $ctx, mixed $actionCtx = null, mixed $toolCall = null): array
    {
        try {
            return SafeRegex::withBudget(static function () use ($caveats, $ctx, $actionCtx, $toolCall): array {
                if (!self::isList($caveats)) {
                    return ['ok' => false, 'failed' => ['<malformed caveats>']];
                }
                $c = self::asObj($ctx);
                $a = $actionCtx instanceof Obj ? $actionCtx : new Obj();
                $failed = [];
                foreach ($caveats as $cv) {
                    if ($c === null || !self::agentCaveatSatisfied($cv, $c, $a, $toolCall ?? [])) {
                        $t = $cv instanceof Obj ? $cv->get('type') : null;
                        $failed[] = is_string($t) ? $t : '<malformed>';
                    }
                }
                return ['ok' => $failed === [], 'failed' => $failed];
            });
        } catch (\Throwable) {
            return ['ok' => false, 'failed' => ['<evaluation error>']];
        }
    }

    // ---- authorize -------------------------------------------------------------------------------------------------------

    private static function classRank(mixed $c): int
    {
        return is_string($c) ? (self::CLASS_RANK[$c] ?? 2) : 2;
    }

    /** @param list<string>|null $missing */
    private static function refuse(int $status, string $check, string $reason, ?array $missing = null, ?Obj $pcactn = null): AuthorizeResult
    {
        return new AuthorizeResult(false, $status, [$check => 'fail'], [$reason], $reason, null, $pcactn, null, $missing);
    }

    /**
     * Names of the required components that are absent (empty = complete), in this order: `audience`, `resolveGrant`,
     * `stateStore`, `isRevoked`.
     *
     * @return list<string>
     */
    public static function missingAuthorizeComponents(mixed $audience, mixed $resolveGrant, mixed $stateStore, mixed $isRevoked): array
    {
        $missing = [];
        if (!is_string($audience) || $audience === '') {
            $missing[] = 'audience';
        }
        if (!is_callable($resolveGrant)) {
            $missing[] = 'resolveGrant';
        }
        if (!is_object($stateStore) || !is_callable([$stateStore, 'claim'])) {
            $missing[] = 'stateStore';
        }
        if (!is_callable($isRevoked)) {
            $missing[] = 'isRevoked';
        }
        return $missing;
    }

    /** @param array<string,string> $checks @param list<string> $reasons */
    private static function decisive(array $checks, array $reasons): string
    {
        $names = array_keys($checks);
        usort($names, static fn(string $a, string $b): int => ($a === 'operation' ? 0 : 1) <=> ($b === 'operation' ? 0 : 1));
        foreach ($names as $n) {
            if ($checks[$n] !== 'fail') {
                continue;
            }
            foreach ($reasons as $r) {
                if (str_starts_with($r, $n . ':')) {
                    return $r;
                }
            }
        }
        return $reasons[0] ?? 'denied';
    }

    /** @return array{0: ?Obj, 1: ?string} [pcactn, error: absent | undecodable] */
    private static function coerce(mixed $pcactn): array
    {
        if ($pcactn instanceof Obj) {
            return [$pcactn, null];
        }
        if (is_string($pcactn)) {
            if (strlen($pcactn) > Pca::MAX_ARTIFACT_BYTES) {
                return [null, 'undecodable'];
            }
            try {
                $obj = Json::parseStrict($pcactn);
            } catch (JsonError) {
                return [null, 'undecodable'];
            }
            return $obj instanceof Obj ? [$obj, null] : [null, 'undecodable'];
        }
        return [null, $pcactn === null ? 'absent' : 'undecodable'];
    }

    private static function callableObject(mixed $f): bool
    {
        return $f instanceof \Closure || (is_object($f) && is_callable($f));
    }

    /**
     * Authorize ONE operation (see the class doc for the pipeline). Never throws.
     *
     * @param Obj|string|null $pcactn       the presented PCActn: a parsed Obj, or its JSON text (strict profile)
     * @param mixed           $operation    `['verb' => string, 'resource' => string, 'params' => Obj]` (or an Obj with these
     *                                      members): what the handler / tool WILL execute, from the server's own routing and
     *                                      parsed input, never from the PCActn. `params` must be a JSON object (an Obj; use
     *                                      `new Obj()` for none: a PHP `[]` is a JSON array and is refused)
     * @param mixed           $audience     this resource server's id (the PCActn's signed `aud` must equal it)
     * @param mixed           $resolveGrant `(string $grantRef): ?Obj` from your own store
     * @param mixed           $stateStore   replay store with an atomic `claim(string $key, int $counter): ClaimResult`
     * @param mixed           $isRevoked    `(Obj $pcactn, Obj $grant): bool`; only `false` passes (anything else, or a throw, denies)
     * @param int|null        $now          epoch milliseconds (default: the wall clock)
     * @param mixed           $plan         `'single-step'`: accept a one-node plan whose node is exactly this operation.
     *                                      Otherwise `context` must return the principal-authorized `plan` with
     *                                      `plan_authorized: true`
     * @param mixed           $context      `(Obj $pcactn): Obj|array|null` with optional `plan` (list of plan nodes),
     *                                      `plan_authorized`, `subject`, `env`, `blast_radius`, `recent_action_times`,
     *                                      `reversibility_class` (the server's authoritative class; the agent may only
     *                                      declare a stricter one)
     * @param mixed           $intentPolicy forwarded to {@see Pca::verifyPcactnCore}
     * @param mixed           $intentV2     an Obj, or a callable `(Obj $pcactn): ?Obj` (its `params` default to the operation's)
     * @param array|null      $allowedSuites forwarded to {@see Pca::verifyPcactnCore}
     * @param mixed           $require      extra check names that must pass (the defaults always apply)
     * @param list<string|Obj>|null $escalationPrincipals pinned principals whose signed EscalationAnswer admits an
     *                                      `escalate` decision (see {@see Escalation}); null / empty: every escalate is refused
     * @param mixed           $escalationAnswer the principal's signed answer for THIS action (an Obj, or its strict JSON text)
     */
    public static function authorize(
        mixed $pcactn,
        mixed $operation,
        mixed $audience,
        mixed $resolveGrant,
        mixed $stateStore,
        mixed $isRevoked,
        ?int $now = null,
        mixed $plan = null,
        mixed $context = null,
        mixed $intentPolicy = null,
        mixed $intentV2 = null,
        ?array $allowedSuites = null,
        mixed $require = [],
        ?array $escalationPrincipals = null,
        mixed $escalationAnswer = null,
    ): AuthorizeResult {
        try {
            return self::run($pcactn, $operation, $audience, $resolveGrant, $stateStore, $isRevoked, $now, $plan, $context,
                $intentPolicy, $intentV2, $allowedSuites, $require, $escalationPrincipals, $escalationAnswer);
        } catch (\Throwable $e) { // never throw: an internal error denies
            return self::refuse(403, 'authorize', 'authorize: error (fail closed): ' . get_class($e));
        }
    }

    private static function run(mixed $pcactn, mixed $operation, mixed $audience, mixed $resolveGrant, mixed $stateStore,
                                mixed $isRevoked, ?int $now, mixed $plan, mixed $context, mixed $intentPolicy,
                                mixed $intentV2, ?array $allowedSuites, mixed $require, ?array $escalationPrincipals,
                                mixed $escalationAnswer): AuthorizeResult
    {
        $missing = self::missingAuthorizeComponents($audience, $resolveGrant, $stateStore, $isRevoked);
        if ($escalationPrincipals !== null && $escalationPrincipals !== [] && is_object($stateStore)
            && !is_callable([$stateStore, 'last'])) {
            $missing[] = 'stateStore.last (escalation answers are bound to the holder history)';
        }
        if ($plan !== null && $plan !== self::SINGLE_STEP) {
            $missing[] = "plan (only 'single-step' or null)";
        }
        if ($missing !== []) {
            return self::refuse(403, 'authorize_config', 'authorize_config: missing required component(s): '
                . implode(', ', $missing) . ' (fail closed)', $missing);
        }
        if (!self::validOperation($operation)) {
            return self::refuse(403, 'operation', 'operation: authorize needs the operation to execute (verb, resource, params) '
                . '(fail closed)');
        }
        // a private copy: the params that are verified cannot change under the verifier
        $opVerb = self::member($operation, 'verb');
        $opResource = self::member($operation, 'resource');
        /** @var Obj $opParams */
        $opParams = Json::parseStrict(Json::canonicalizeStrict(self::normalize(self::member($operation, 'params'))));

        [$p, $err] = self::coerce($pcactn);
        if ($p === null) {
            return self::refuse(401, 'wire', $err === 'absent' ? 'wire: no PCActn presented' : 'wire: PCActn could not be decoded');
        }
        $grantRef = $p->get('grant_ref');
        if (!is_string($grantRef)) {
            return self::refuse(401, 'malformed', 'malformed: grant_ref is not a string', null, $p);
        }
        try {
            $grant = $resolveGrant($grantRef);
        } catch (\Throwable) {
            return self::refuse(403, 'resolve_grant', 'resolve_grant: grant resolution failed (fail closed)', null, $p);
        }
        if (!($grant instanceof Obj)) {
            return self::refuse(401, 'grant_ref', 'grant_ref: does not resolve to a known grant', null, $p);
        }

        $now ??= (int)(microtime(true) * 1000);
        $ctx = new Obj();
        if ($context !== null) {
            try {
                $raw = $context($p);
            } catch (\Throwable) {
                return self::refuse(403, 'context', 'context: the context callback failed (fail closed)', null, $p);
            }
            $ctx = self::asObj($raw);
            if ($ctx === null) {
                return self::refuse(403, 'context', 'context: the context callback must return an object (fail closed)', null, $p);
            }
        }

        $v2 = $intentV2;
        if (self::callableObject($intentV2)) {
            try {
                $v2 = $intentV2($p);
            } catch (\Throwable) {
                return self::refuse(403, 'intent_v2', 'intent_v2: verifier state unavailable (fail closed)', null, $p);
            }
        }
        if ($v2 !== null && !($v2 instanceof Obj)) {
            return self::refuse(403, 'intent_v2', 'intent_v2: verifier state unavailable (fail closed)', null, $p);
        }
        // the host's `context.env` feeds the `tighten` rules (rule 21) under the v2 context's own `env` (which wins member by member);
        // a null v2 `env` is absent, any other non-object stays and fails the v2 context check
        $hostEnv = $ctx->get('env');
        if ($hostEnv instanceof Obj || ($v2 instanceof Obj && $v2->has('env') && $v2->get('env') === null)) {
            $v2 = $v2 instanceof Obj ? $v2 : new Obj();
            $own = $v2->has('env') ? $v2->get('env') : null;
            if ($own === null || $own instanceof Obj) {
                $merged = new Obj();
                foreach ($hostEnv instanceof Obj ? $hostEnv->keys() : [] as $k) {
                    $merged->set($k, $hostEnv->get($k));
                }
                foreach ($own instanceof Obj ? $own->keys() : [] as $k) {
                    $merged->set($k, $own->get($k));
                }
                $v2 = $v2->without('env');
                if ($merged->keys() !== [] || $hostEnv instanceof Obj) {
                    $v2->set('env', $merged);
                }
            }
        }
        $v2 ??= new Obj(); // the rules read the operation's params
        if ($v2 instanceof Obj && $v2->get('params') === null) {
            $v2 = $v2->without('params');
            $v2->set('params', $opParams);
        }

        // ---- 1. the core checks
        $core = Pca::verifyPcactnCore($p, $grant, $now, $audience, $allowedSuites, $intentPolicy, $v2);
        if (self::$coreHook !== null) {
            $core = (self::$coreHook)($core);
        }
        if (($core['checks']['wire'] ?? null) === false) {
            $r = $core['reason'] !== '' ? $core['reason'] : 'wire: malformed PCActn';
            return new AuthorizeResult(false, 401, ['wire' => 'fail', 'malformed' => 'fail'], [$r], $r, null, $p, $core);
        }
        $checks = [];
        foreach ($core['checks'] as $k => $ok) {
            $checks[$k] = $ok ? 'pass' : 'fail';
        }
        $reasons = $core['allow'] ? [] : (is_array($core['reasons'] ?? null) && $core['reasons'] !== []
            ? $core['reasons'] : ($core['reason'] === '' ? [] : [$core['reason']]));
        $fail = static function (string $name, string $why) use (&$checks, &$reasons): void {
            $checks[$name] = 'fail';
            $reasons[] = "$name: $why";
        };

        // ---- 2. revocation (required) and a carried zk proof (no verifier here: fail closed)
        try {
            $revoked = $isRevoked($p, $grant);
        } catch (\Throwable) {
            $revoked = null;
        }
        if ($revoked === false) {
            $checks['revocation'] = 'pass';
        } else {
            $fail('revocation', $revoked === true ? 'the grant is revoked' : 'the revocation check failed (fail closed)');
        }
        if ($p->has('zk_compliance')) {
            $fail('zk_compliance', 'PCActn carries a zk_compliance proof but no zk verifier enforced it (fail closed)');
        }

        $action = $p->get('action') instanceof Obj ? $p->get('action') : new Obj();
        $signedDigest = $action->get('params_digest');
        $opDigest = Pca::paramsDigest($opParams);

        // ---- 3. the operation binding
        if ($action->get('verb') !== $opVerb || $action->get('resource') !== $opResource) {
            $fail('operation', 'the proof is for ' . self::jsString($action->get('verb')) . ' on '
                . self::jsString($action->get('resource')) . ", but this operation is $opVerb on $opResource");
        } elseif ($opDigest !== $signedDigest) {
            $fail('operation', "the proof's params_digest does not match the params of this $opVerb operation");
        } else {
            $checks['operation'] = 'pass';
        }

        // ---- 4. grant_ref, params, plan, attestation, reversibility
        if ($grantRef === $grant->get('id')) {
            $checks['grant_ref'] = 'pass';
        } else {
            $fail('grant_ref', 'does not reference the supplied grant');
        }
        if ($opDigest === $signedDigest) {
            $checks['params_digest'] = 'pass';
        } else {
            $fail('params_digest', 'supplied params do not hash to action.params_digest');
        }

        $pl = $p->get('plan') instanceof Obj ? $p->get('plan') : new Obj();
        $nodeId = $pl->get('node_id');
        $planNodes = $ctx->get('plan');
        $planAuthorized = $ctx->get('plan_authorized');
        if ($plan === self::SINGLE_STEP && $planNodes === null) {
            $planNodes = [Obj::of(['id' => self::jsString($nodeId), 'verb' => $opVerb, 'resource' => $opResource,
                'params_digest' => $opDigest, 'reversibility_class' => $action->get('reversibility_class')])];
            $planAuthorized = true;
        }
        if ($planNodes !== null) {
            try {
                $leaves = [];
                foreach (self::isList($planNodes) ? $planNodes : throw new \InvalidArgumentException('plan must be a list') as $n) {
                    $node = self::nodeObj($n) ?? throw new \InvalidArgumentException('plan node must be an object');
                    $leaves[] = Pca::planLeaf($node->get('id'), $node, Pca::conditionsDigest($node->get('pre'), $node->get('post')));
                }
                $known = Pca::merkleRoot($leaves);
            } catch (\Throwable) {
                $known = null;
            }
            if ($known === null || $known !== $pl->get('root')) {
                $fail('plan_root_authorized', 'known plan does not match plan.root');
            } elseif ($planAuthorized !== true) {
                $fail('plan_root_authorized', 'the plan root has not been authorized by the principal');
            } else {
                $checks['plan_root_authorized'] = 'pass';
            }
        } else {
            $checks['plan_root_authorized'] = 'not-enforced';
        }

        $env = self::readEnvelope($grant);
        if (self::requiresAttestation($env?->get('agent_binding'))) {
            $fail('attestation', 'the grant binds the agent (agent_binding) so a valid, bound attestation is REQUIRED '
                . '(no attestation verifier in this SDK: fail closed)');
        }

        $declared = $action->get('reversibility_class');
        $effective = $declared;
        $serverClass = $ctx->get('reversibility_class');
        if ($serverClass !== null) {
            $dr = self::classRank($declared);
            $sr = self::classRank($serverClass);
            if ($dr < $sr) {
                $fail('reversibility', "declared class '" . self::jsString($declared) . "' is less restrictive than the authoritative '"
                    . self::jsString($serverClass) . "'");
            } else {
                $checks['reversibility'] = 'pass';
            }
            $effective = $dr > $sr ? $declared : $serverClass;
        }

        // ---- 5. policy: envelope predicates + envelope caveats + root caveats; then the delegated caveats
        $chain = self::isList($p->get('cap_chain')) ? $p->get('cap_chain') : [];
        $depth = max(0, count($chain) - 1);
        $inner = Obj::of(['verb' => $action->get('verb'), 'resource' => $action->get('resource'), 'params' => $opParams]);
        if ($effective !== null) {
            $inner->set('reversibility_class', $effective);
        }
        $actionCtx = Obj::of(['action' => $inner]);
        if ($ctx->get('subject') !== null) {
            $actionCtx->set('subject', $ctx->get('subject'));
        }
        $predEnv = self::v2Env($p, $grant, $v2, $now, $ctx->get('env'));
        if ($predEnv !== null) {
            $actionCtx->set('env', $predEnv);
        }
        $toolCall = ['tool' => is_string($inner->get('verb')) ? $inner->get('verb') : '', 'args' => $opParams];
        if (is_string($p->get('tool_binding'))) {
            $toolCall['toolSignatureDigest'] = $p->get('tool_binding');
        }
        $revClass = $effective;
        if ($revClass === null && is_string($nodeId) && self::isList($planNodes)) {
            foreach ($planNodes as $n) {
                $node = self::nodeObj($n);
                if ($node !== null && $node->get('id') === $nodeId) {
                    $revClass = $node->get('reversibility_class');
                    break;
                }
            }
        }
        $cctx = Obj::of(['now' => $now, 'action' => $inner, 'delegation_depth' => $depth]);
        if ($ctx->get('blast_radius') !== null) {
            $cctx->set('blast_radius', $ctx->get('blast_radius'));
        }
        if ($revClass !== null) {
            $cctx->set('reversibility_class', $revClass);
        }
        if ($ctx->get('recent_action_times') !== null) {
            $cctx->set('recent_action_times', $ctx->get('recent_action_times'));
        }

        $policyStep = static function () use ($env, $grant, $actionCtx, $cctx, $toolCall): array {
            if ($env === null) {
                return ['grant carries no valid envelope'];
            }
            $why = [];
            $pr = Predicates::evaluatePredicates($env->get('predicates'), $actionCtx);
            if (($pr['allowed'] ?? false) !== true) {
                $why[] = $pr['reason'] ?? 'action not permitted by envelope predicates';
            }
            $r = self::evaluateAgentCaveats($env->get('caveats'), $cctx, $actionCtx, $toolCall);
            if (!$r['ok']) {
                $why[] = 'caveat(s) not satisfied: ' . implode(', ', $r['failed']);
            }
            $r = self::evaluateAgentCaveats(self::rootCaveats($grant), $cctx, $actionCtx, $toolCall);
            if (!$r['ok']) {
                $why[] = 'root caveat(s) not satisfied: ' . implode(', ', $r['failed']);
            }
            return $why;
        };

        if ($chain !== []) {
            $leaf = $chain[count($chain) - 1] instanceof Obj ? $chain[count($chain) - 1] : new Obj();
            $gcs = self::isList($grant->get('caveats')) ? $grant->get('caveats') : [];
            $extra = self::isList($leaf->get('caveats')) ? array_slice($leaf->get('caveats'), count($gcs)) : null;
            $r = self::evaluateAgentCaveats($extra, $cctx, $actionCtx, $toolCall);
            if ($r['ok']) {
                $checks['delegated_caveats'] = 'pass';
            } else {
                $fail('delegated_caveats', 'delegation caveat(s) not satisfied: ' . implode(', ', $r['failed']));
            }
        }

        try {
            $policyWhy = SafeRegex::withBudget($policyStep);
        } catch (\Throwable) {
            $policyWhy = ['policy evaluation error (fail closed)'];
        }
        if ($policyWhy !== []) {
            $checks['policy'] = 'fail';
            foreach ($policyWhy as $w) {
                $reasons[] = "policy: $w";
            }
        } else {
            $checks['policy'] = 'pass';
        }

        // ---- required checks (default-deny), then the replay counter
        $extraRequired = [];
        foreach (is_array($require) ? $require : [] as $n) {
            if (is_string($n)) {
                // `counter` is the documented alias of `replay` (it always meant the stateful check here)
                $extraRequired[] = $n === 'counter' ? 'replay' : $n;
            }
        }
        // pass tentatively; flips to fail below when the store refuses the claim (TypeScript order)
        $checks['replay'] = 'pass';
        foreach (array_merge(self::DEFAULT_REQUIRED_CHECKS, $extraRequired) as $name) {
            $st = $checks[$name] ?? null;
            if ($st !== 'pass' && $st !== 'fail') {
                $checks[$name] = 'fail';
                $reasons[] = "$name: required check is " . ($st ?? 'absent')
                    . ' (default-deny: not enforced by this resource server)';
            }
        }

        $escalation = null;
        $answeredBy = null;
        $legacyPolarity = ($core['legacy_model_polarity'] ?? false) === true;
        $deny = static function () use (&$checks, &$reasons, $p, $core, &$escalation, $legacyPolarity): AuthorizeResult {
            $status = 403;
            foreach (self::AUTHN_CHECKS as $c) {
                if (($checks[$c] ?? null) === 'fail') {
                    $status = 401;
                    break;
                }
            }
            return new AuthorizeResult(false, $status, $checks, $reasons, self::decisive($checks, $reasons), null, $p, $core, null,
                $escalation !== null ? 'escalate' : 'deny', $escalation, $legacyPolarity);
        };

        $last = $chain !== [] && $chain[count($chain) - 1] instanceof Obj ? $chain[count($chain) - 1] : null;
        $holder = $last?->get('holder');
        if (in_array('fail', $checks, true)) {
            // Ternary decision: when EVERY failing check is escalate-class the verdict is `escalate`, never admitted by
            // itself; a valid principal answer bound to this grant, this PCActn and the holder's history admits it.
            if (!is_string($holder) || !is_string($grant->get('id')) || Decision::decisionOf(false, $checks, $reasons) !== 'escalate') {
                return $deny();
            }
            $key = self::stateKey($grant->get('id'), $holder);
            $lastCounter = null;
            $headKnown = false;
            if (is_callable([$stateStore, 'last'])) {
                try {
                    $l = $stateStore->last($key);
                    $lastCounter = is_int($l) ? $l : null;
                    $headKnown = $l === null || is_int($l);
                } catch (\Throwable) {
                    $headKnown = false;
                }
            }
            $escalation = Escalation::buildRequest($audience, $grant, $p, $lastCounter, $reasons, $now);
            $answer = self::coerceAnswer($escalationAnswer);
            if ($escalationPrincipals !== null && $escalationPrincipals !== [] && $answer !== null && $headKnown) {
                $v = Escalation::verifyAnswer($answer, $escalationPrincipals, [
                    'policy_digest' => Escalation::policyDigest($grant),
                    'action_digest' => Escalation::actionDigest($p),
                    'history_head' => Escalation::historyHead($lastCounter),
                ], $now);
                if ($v['ok'] && $v['decision'] === 'allow') {
                    foreach ($checks as $n => $st) {
                        if ($st === 'fail') {
                            $checks[$n] = 'pass';
                        }
                    }
                    $checks['escalation'] = 'pass';
                    $reasons[] = 'escalation: answered allow by principal ' . substr($v['principal'], 0, 8);
                    $answeredBy = $v['principal'];
                    $escalation = null;
                } else {
                    $reasons[] = 'escalation: ' . ($v['ok'] ? 'the principal answered deny' : $v['reason']);
                }
            }
            if ($escalation !== null) {
                return $deny();
            }
        }

        $counterNum = $p->get('counter');
        if (!is_string($holder) || !is_string($grant->get('id')) || !($counterNum instanceof Num)) {
            $fail('replay', 'no counter stream for this proof (fail closed)');
            return $deny();
        }
        $counter = $counterNum->int();
        try {
            $claimed = $stateStore->claim(self::stateKey($grant->get('id'), $holder), $counter);
        } catch (\Throwable) {
            $claimed = null;
        }
        if (is_bool($claimed)) {
            $claimed = new ClaimResult($claimed);
        }
        if (!($claimed instanceof ClaimResult && $claimed->ok === true)) {
            $lastSeen = $claimed instanceof ClaimResult ? $claimed->lastCounter : null;
            if ($claimed === null) {
                $fail('replay', 'the replay store failed (fail closed)');
            } elseif ($lastSeen !== null) {
                $fail('replay', "$counter is not greater than last seen $lastSeen (replay)");
            } else {
                $fail('replay', "$counter was already claimed (replay)");
            }
            return $deny();
        }
        return new AuthorizeResult(true, 200, $checks, $reasons, null,
            new AuthorizedOperation($opVerb, $opResource, $signedDigest, Pca::hashCanonical($p)), $p, $core, null, 'allow',
            $answeredBy !== null ? Obj::of(['answered_by' => $answeredBy]) : null, $legacyPolarity, self::degradedOf($legacyPolarity));
    }

    /** The assurance the allow lost: under `model_polarity: legacy` a grant reads a model-derived value in its `where`. @return array<string,string> */
    private static function degradedOf(bool $legacy): array
    {
        return $legacy ? ['tighten' => "model_polarity 'legacy': a grant reads a model-derived value in where (rule 21)"] : [];
    }

    /** An answer given as an Obj or as its strict JSON text; anything else (or an unreadable text) is no answer. */
    private static function coerceAnswer(mixed $a): ?Obj
    {
        if ($a instanceof Obj) {
            return $a;
        }
        if (is_string($a) && strlen($a) <= Pca::MAX_ARTIFACT_BYTES) {
            try {
                $o = Json::parseStrict($a);
            } catch (JsonError) {
                return null;
            }
            return $o instanceof Obj ? $o : null;
        }
        return null;
    }

    /** The predicate `env`: the host's, with the verifier-computed Intent Layer v2 members (TypeScript `v2Env`). */
    private static function v2Env(Obj $p, Obj $grant, ?Obj $v2, int $now, mixed $env): mixed
    {
        if (!$p->has('intent_session')) {
            return $env;
        }
        $rest = $env instanceof Obj ? $env->without('acc', 'mon', 'canon', 'world', 'prov', 'class') : new Obj();
        $d = IntentV2::decideIntentV2($p, $grant, $v2, $now)['env'] ?? null;
        if ($d instanceof Obj) {
            foreach ($d->keys() as $k) {
                if ($d->get($k) !== null) {
                    $rest->set($k, $d->get($k));
                }
            }
        }
        return $rest;
    }

    /**
     * True only if `$result` allowed exactly this operation (verb, resource, params digest). Call it where the side effect
     * runs, with the values it is about to use. Never throws.
     */
    public static function isAuthorizedFor(mixed $result, mixed $operation): bool
    {
        try {
            $b = $result instanceof AuthorizeResult && $result->allow ? $result->operation : null;
            if ($b === null || !self::validOperation($operation)) {
                return false;
            }
            return $b->verb === self::member($operation, 'verb') && $b->resource === self::member($operation, 'resource')
                && $b->paramsDigest === Pca::paramsDigest(self::normalize(self::member($operation, 'params')));
        } catch (\Throwable) {
            return false;
        }
    }
}
