<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/Optimistic.php';
require_once __DIR__ . '/Decide.php';

/** Why a mandate was refused before any decision: verified_grant_required, mandate_grant_mismatch or mandate_terms_mismatch (in codeName). */
final class MandateGrantError extends \RuntimeException
{
    public function __construct(public readonly string $codeName, string $message)
    {
        parent::__construct($message);
    }
}

/** A missing or malformed budget store, or a co-sign that could not be committed. */
final class ChargeStoreError extends \RuntimeException
{
}

/**
 * Durable cumulative-budget state with an atomic compare-and-set. `get` returns null or a record {budget, version}; `compareAndSet`
 * succeeds only when the stored version still equals `$expected` (null = no record yet) and returns false otherwise.
 */
interface ChargeBudgetStore
{
    public function get(string $key): mixed;

    public function compareAndSet(string $key, ?int $expected, mixed $budget): bool;
}

/** Single-process reference store (tests); production needs a durable store with a conditional write. */
final class MemoryChargeBudgetStore implements ChargeBudgetStore
{
    /** @var array<string,array{budget:mixed,version:int}> */
    private array $m = [];

    public function get(string $key): mixed
    {
        return isset($this->m[$key]) ? Obj::of(['budget' => $this->m[$key]['budget'], 'version' => $this->m[$key]['version']]) : null;
    }

    public function compareAndSet(string $key, ?int $expected, mixed $budget): bool
    {
        if (($this->m[$key]['version'] ?? null) !== $expected) {
            return false;
        }
        $this->m[$key] = ['budget' => $budget, 'version' => ($expected ?? 0) + 1];
        return true;
    }
}

/** An agent payment network-token provider (issue / suspend). */
interface NetworkTokenProvider
{
    public function id(): string;

    /** @param mixed $req {controls, agentId}; returns {token_ref}. */
    public function issue(mixed $req): mixed;

    public function suspend(string $tokenRef, string $reason): void;
}

/** The generic mapping of PCA controls onto a partner's token API; the partner transport is injected (no network call here). */
final class PartnerNetworkTokenProvider implements NetworkTokenProvider
{
    /** @param \Closure(string,Obj):mixed $post */
    public function __construct(private string $providerId, private string $scopeKey, private \Closure $post)
    {
    }

    public function id(): string
    {
        return $this->providerId;
    }

    public function issue(mixed $req): mixed
    {
        $c = Js::get($req, 'controls');
        $scope = new Obj();
        $scope->set('currency', Js::get($c, 'currency'));
        $scope->set('per_authorization_max', Js::get($c, 'perAuthorizationMax'));
        $scope->set('total_max', Js::get($c, 'totalMax'));
        $scope->set('merchant_categories', Js::get($c, 'categories'));
        $scope->set('merchants', Js::get($c, 'merchants'));
        if (Js::has($c, 'expiresAt')) {
            $scope->set('expires_at', Js::get($c, 'expiresAt'));
        }
        $body = new Obj();
        $body->set('agent_id', Js::get($req, 'agentId'));
        $body->set($this->scopeKey, $scope);
        $body->set('metadata', Js::get($c, 'metadata'));
        $r = ($this->post)('/tokens', $body);
        $ref = Js::opt($r, 'token_ref');
        $e = Payments::tokenRefError($ref);
        if ($e !== null) {
            throw new \RuntimeException($this->providerId . ': provider returned ' . $e);
        }
        return Obj::of(['token_ref' => $ref]);
    }

    public function suspend(string $tokenRef, string $reason): void
    {
        ($this->post)('/tokens/' . Js::encodeURIComponent($tokenRef) . '/suspend', Obj::of(['reason' => $reason]));
    }
}

/**
 * Payments for PCA: a payment mandate as a Root Intent Grant, the charge decision, the charge PCActn, Shared Payment Token limits,
 * spend rails (card limits, a real-time authorization callback, settlement reconciliation), the Stripe Issuing adapter and agent
 * network tokens. Mirrors @atlasauth/pca-payments.
 *
 * Values are the parsed-JSON model (Obj, lists, strings, Num / int / float, bool, null); options accept an Obj or a PHP associative
 * array with the reference's camelCase names. Inputs follow JavaScript semantics where the reference does (missing members,
 * truthiness, coercing arithmetic), so a hostile mandate or charge is refused or priced exactly as the reference does. This package
 * carries no policy engine: the charge decision takes the policy decision function as an injected Closure
 * `decide(Obj $decideInput): mixed`. Secrets are raw 32-byte Ed25519 seeds (string or {@see Bytes}).
 */
final class Payments
{
    /** The action-kit trait a verb carries to name its merchant category (MCC_TRAIT_RE). */
    public const MCC_TRAIT_RE = '/\Amcc\.c([0-9]{4})\z/';
    public const CHARGE_REVERSIBILITY_CLASS = 'reversible';
    public const CHARGE_VERB = 'charge';
    public const AMOUNT_NOT_MINOR_UNITS = 'amount_not_integer_minor_units';
    public const MERCHANT_INVALID = 'merchant_invalid';
    public const STRIPE_WEBHOOK_TOLERANCE_SEC = 300;
    public const STRIPE_API_VERSION = '2025-03-31.basil';
    public const NETWORK_TOKEN_BINDING_KIND = 'pca.network_token_binding';
    /** An option that was not passed (the reference's `undefined`, distinct from null). */
    public const UNDEF = "\0\0undefined\0\0";
    private const MAX_CAS_ATTEMPTS = 8;
    private const MAX_SAFE = 9007199254740991;

    // ---- JavaScript semantics -----------------------------------------------------------------------------------------------

    /** o.k: a TypeError for null / undefined, UNDEF for an absent member or a primitive. */
    /** @internal shared JavaScript-semantics helper */
    public static function p(mixed $o, string $k): mixed
    {
        if ($o === null || $o === self::UNDEF) {
            throw new \TypeError("Cannot read properties of " . ($o === null ? 'null' : 'undefined') . " (reading '$k')");
        }
        return Js::has($o, $k) ? Js::opt($o, $k) : self::UNDEF;
    }

    /** o?.k */
    /** @internal shared JavaScript-semantics helper */
    public static function q(mixed $o, string $k): mixed
    {
        return $o === null || $o === self::UNDEF ? self::UNDEF : self::p($o, $k);
    }

    /** @internal shared JavaScript-semantics helper */
    public static function nullish(mixed $v): bool
    {
        return $v === null || $v === self::UNDEF;
    }

    /** @internal shared JavaScript-semantics helper */
    public static function truthy(mixed $v): bool
    {
        return $v !== self::UNDEF && Js::truthy($v);
    }

    /** Number(v) / the ToNumber of an arithmetic or relational operand. */
    /** @internal shared JavaScript-semantics helper */
    public static function n(mixed $x): float
    {
        if ($x === self::UNDEF) {
            return NAN;
        }
        if ($x === null) {
            return 0.0;
        }
        if (is_bool($x)) {
            return $x ? 1.0 : 0.0;
        }
        if (Js::isNum($x)) {
            return (float)Js::num($x);
        }
        if (is_string($x)) {
            return IntentWb::jsNumber($x);
        }
        return IntentWb::jsNumber(Js::str($x)); // a list or an object goes through its string form
    }

    /** @internal shared JavaScript-semantics helper */
    public static function fin(mixed $v): bool
    {
        return Js::isNum($v) && is_finite((float)Js::num($v));
    }

    /** @internal shared JavaScript-semantics helper */
    public static function safeInt(mixed $v): bool
    {
        if (!Js::isNum($v)) {
            return false;
        }
        $f = (float)Js::num($v);
        return is_finite($f) && floor($f) === $f && abs($f) <= self::MAX_SAFE;
    }

    /** An integral float as an int (a negative zero stays a float), so a whole number serialises as one. */
    /** @internal shared JavaScript-semantics helper */
    public static function num(float $f): int|float
    {
        if (is_finite($f) && floor($f) === $f && abs($f) < 9.0e15 && !($f === 0.0 && fdiv(1.0, $f) < 0)) {
            return (int)$f;
        }
        return $f;
    }

    /** @internal shared JavaScript-semantics helper */
    public static function jsMax(float $a, float $b): float
    {
        return IntentOmega::jsMax($a, $b); // Math.max, NaN and the order of 0 and -0 included
    }

    /** @internal shared JavaScript-semantics helper */
    public static function jsMin(float $a, float $b): float
    {
        return IntentOmega::jsMin($a, $b); // Math.min, NaN and the order of 0 and -0 included
    }

    /** @internal shared JavaScript-semantics helper */
    public static function jsRound(float $x): float
    {
        if (is_nan($x) || is_infinite($x)) {
            return $x;
        }
        $r = floor($x);
        return $x - $r >= 0.5 ? $r + 1 : $r;
    }

    /** @internal shared JavaScript-semantics helper */
    public static function jsFloor(float $x): float
    {
        return is_nan($x) || is_infinite($x) ? $x : floor($x);
    }

    /** `a > b` (strings compare by code unit when both are strings; shortcut: byte order, equal to UTF-16 order except for astral vs U+E000..U+FFFF). */
    /** @internal shared JavaScript-semantics helper */
    public static function gt(mixed $a, mixed $b): bool
    {
        if (is_string($a) && is_string($b) && $a !== self::UNDEF && $b !== self::UNDEF) {
            return strcmp($a, $b) > 0;
        }
        return self::n($a) > self::n($b);
    }

    /** a <= b (a NaN operand is false). */
    public static function le(mixed $a, mixed $b): bool
    {
        if (is_string($a) && is_string($b) && $a !== self::UNDEF && $b !== self::UNDEF) {
            return strcmp($a, $b) <= 0;
        }
        return self::n($a) <= self::n($b);
    }

    /** a === b for JSON values (numbers by value; an object or array is never equal to another). */
    /** @internal shared JavaScript-semantics helper */
    public static function seq(mixed $a, mixed $b): bool
    {
        if (Js::isNum($a) || Js::isNum($b)) {
            return Js::isNum($a) && Js::isNum($b) && (float)Js::num($a) === (float)Js::num($b);
        }
        if (is_bool($a) || is_bool($b)) {
            return $a === $b;
        }
        if (is_string($a) || is_string($b)) {
            return $a === $b;
        }
        return $a === null && $b === null;
    }

    /** String(v) as a template literal renders it. */
    /** @internal shared JavaScript-semantics helper */
    public static function s(mixed $v): string
    {
        return $v === self::UNDEF ? 'undefined' : Js::str($v);
    }

    /** v.length: a TypeError for null / undefined, UNDEF when there is none. */
    /** @internal shared JavaScript-semantics helper */
    public static function length(mixed $v): mixed
    {
        if ($v === null || $v === self::UNDEF) {
            throw new \TypeError("Cannot read properties of undefined (reading 'length')");
        }
        if (is_string($v)) {
            return Js::len($v);
        }
        if (is_array($v) && array_is_list($v)) {
            return count($v);
        }
        return Js::isObj($v) ? self::p($v, 'length') : self::UNDEF;
    }

    /** `[...v]`: a TypeError for null / undefined / a non-iterable. */
    /** @internal shared JavaScript-semantics helper */
    public static function spread(mixed $v): array
    {
        if ($v === null || $v === self::UNDEF) {
            throw new \TypeError('value is not iterable');
        }
        return Js::spread($v);
    }

    /** `{...v}` of a JSON value. */
    /** @internal shared JavaScript-semantics helper */
    public static function spreadObj(mixed $v): Obj
    {
        $o = new Obj();
        if ($v instanceof Obj) {
            foreach ($v->keys() as $k) {
                $o->set($k, $v->get($k));
            }
        } elseif (is_array($v) && !array_is_list($v)) {
            foreach ($v as $k => $x) {
                $o->set((string)$k, $x);
            }
        } elseif (is_array($v)) {
            foreach ($v as $i => $x) {
                $o->set((string)$i, $x);
            }
        } elseif (is_string($v) && $v !== self::UNDEF) {
            foreach (Js::spread($v) as $i => $c) {
                $o->set((string)$i, $c);
            }
        }
        return $o;
    }

    /** An object with the given members; UNDEF-valued ones are dropped (JSON.stringify and the canonical form never see them). */
    /** @internal shared JavaScript-semantics helper */
    public static function obj(array $a): Obj
    {
        $o = new Obj();
        foreach ($a as $k => $v) {
            if ($v !== self::UNDEF) {
                $o->set((string)$k, $v);
            }
        }
        return $o;
    }

    /** @internal shared JavaScript-semantics helper */
    public static function hash(mixed $v): string
    {
        if ($v === self::UNDEF) {
            throw new \TypeError('canonicalize: unsupported type undefined');
        }
        return Pca::hashCanonical(Sign::n($v));
    }

    /** @internal shared JavaScript-semantics helper */
    public static function now(): int
    {
        return (int)(microtime(true) * 1000);
    }

    private static function seed(mixed $s): string
    {
        $raw = $s instanceof Bytes ? $s->raw : $s;
        if (!is_string($raw) || $raw === self::UNDEF) {
            throw new \TypeError('a 32-byte Ed25519 seed is required');
        }
        return $raw;
    }

    private static function rawBytes(mixed $s): string
    {
        $raw = $s instanceof Bytes ? $s->raw : $s;
        if (!is_string($raw) || $raw === self::UNDEF) {
            throw new \TypeError('bytes are required');
        }
        return $raw;
    }

    /** @internal shared JavaScript-semantics helper */
    public static function isList(mixed $v): bool
    {
        return is_array($v) && array_is_list($v);
    }

    /** JS String.prototype.trim */
    /** @internal shared JavaScript-semantics helper */
    public static function trim(string $s): string
    {
        return (string)preg_replace('/\A(?:' . IntentWb::JS_WS . ')++|(?:' . IntentWb::JS_WS . ')++\z/', '', $s);
    }

    /** JS default Array.prototype.sort (string order). @param list<mixed> $xs @return list<mixed> */
    /** @internal shared JavaScript-semantics helper */
    public static function jsSort(array $xs): array
    {
        $k = array_map(static fn($x): string => Js::str($x), $xs);
        $idx = array_keys($xs);
        usort($idx, static fn($a, $b): int => strcmp($k[$a], $k[$b]));
        return array_map(static fn($i) => $xs[$i], $idx);
    }

    // ---- mandate ------------------------------------------------------------------------------------------------------------

    /** A merchant id that cannot act as a resource pattern: no `*`, no control characters. */
    public static function isPlainId(mixed $x): bool
    {
        return is_string($x) && $x !== self::UNDEF && $x !== '' && preg_match('/[*\x00-\x1f\x7f]/', $x) !== 1;
    }

    /** A non-negative safe integer (amounts are integer minor units). */
    public static function isMinorUnits(mixed $x): bool
    {
        if (!self::safeInt($x)) {
            return false;
        }
        $f = (float)Js::num($x);
        return $f >= 0 && !($f === 0.0 && fdiv(1.0, $f) < 0);
    }

    private static function validate(mixed $p): void
    {
        $g = static fn(string $k): mixed => self::p($p, $k);
        // -0 is a number the strict canonicalizer refuses: refuse it here too instead of signing it
        foreach (['perTransactionCap', 'autoApproveThreshold', 'cumulativeCap', 'replenishPerCosign', 'periodMs', 'maxTransactionsPerPeriod', 'periodStart', 'now'] as $k) {
            $v = $g($k);
            if (($v instanceof Num && $v->lexeme === '-0') || (is_float($v) && $v === 0.0 && fdiv(1, $v) < 0)) {
                throw new \InvalidArgumentException("buildPaymentMandate: $k must not be negative zero");
            }
        }
        if ($g('strictMinorUnits') !== false) {
            $rep = $g('replenishPerCosign');
            foreach ([['perTransactionCap', $g('perTransactionCap')], ['autoApproveThreshold', $g('autoApproveThreshold')],
                ['cumulativeCap', $g('cumulativeCap')], ['replenishPerCosign', self::nullish($rep) ? 0 : $rep]] as [$k, $v]) {
                if (!self::safeInt($v)) {
                    throw new \InvalidArgumentException("buildPaymentMandate: $k must be a safe integer in minor units (strictMinorUnits)");
                }
            }
        }
        $m = $g('merchants');
        if (!self::isList($m) || count($m) === 0) {
            throw new \InvalidArgumentException('buildPaymentMandate: at least one allowlisted merchant is required');
        }
        foreach ($m as $x) {
            if (!is_string($x) || $x === '') {
                throw new \InvalidArgumentException('buildPaymentMandate: merchant ids must be non-empty strings');
            }
        }
        foreach ($m as $x) {
            if (!self::isPlainId($x)) {
                throw new \InvalidArgumentException('buildPaymentMandate: merchant ids must not contain `*` or control characters');
            }
        }
        $cur = $g('currency');
        if (!is_string($cur) || $cur === '' || $cur === self::UNDEF) {
            throw new \InvalidArgumentException('buildPaymentMandate: currency is required');
        }
        [$x, $y, $cap] = [$g('perTransactionCap'), $g('autoApproveThreshold'), $g('cumulativeCap')];
        if (!self::fin($x) || !(self::n($x) > 0)) {
            throw new \InvalidArgumentException('buildPaymentMandate: perTransactionCap (X) must be a finite number > 0');
        }
        if (!self::fin($y) || self::n($y) < 0 || self::n($y) > self::n($x)) {
            throw new \InvalidArgumentException('buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 <= Y <= X');
        }
        if (!self::fin($cap) || self::n($cap) < self::n($x)) {
            throw new \InvalidArgumentException('buildPaymentMandate: cumulativeCap must be a finite number >= perTransactionCap (X)');
        }
        $pm = $g('periodMs');
        if ($pm !== self::UNDEF && (!self::fin($pm) || !(self::n($pm) > 0))) {
            throw new \InvalidArgumentException('buildPaymentMandate: periodMs must be a finite number > 0 when given');
        }
        $mx = $g('maxTransactionsPerPeriod');
        if ($mx !== self::UNDEF && (!(self::fin($mx) && floor(self::n($mx)) === self::n($mx)) || !(self::n($mx) > 0))) {
            throw new \InvalidArgumentException('buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given');
        }
        $rep = $g('replenishPerCosign');
        if ($rep !== self::UNDEF && (!self::fin($rep) || self::n($rep) < 0)) {
            throw new \InvalidArgumentException('buildPaymentMandate: replenishPerCosign must be a finite number >= 0 when given');
        }
    }

    /** One predicate per merchant, each carrying the currency, category and hard-ceiling guards. @return list<Obj> */
    public static function mandatePredicates(mixed $terms): array
    {
        $merchants = self::p($terms, 'merchants');
        if (!self::isList($merchants)) {
            throw new \TypeError('terms.merchants.map is not a function');
        }
        $out = [];
        foreach ($merchants as $m) {
            $cond = static fn(string $field, string $op, mixed $value): Obj => self::obj(['field' => $field, 'op' => $op, 'value' => $value]);
            $conds = [$cond('action.params.amount', 'lte', self::p($terms, 'perTransactionCap')),
                $cond('action.params.currency', 'eq', self::p($terms, 'currency')),
                $cond('action.params.amount', 'gte', 0)];
            $cats = self::p($terms, 'categories');
            $len = self::length($cats);
            if ($len !== self::UNDEF && self::n($len) > 0) {
                $conds[] = $cond('action.params.category', 'in', $cats);
            }
            $out[] = Obj::of(['verb' => 'charge', 'resource' => 'merchant:' . self::s($m), 'where' => $conds]);
        }
        return $out;
    }

    /** The envelope caveats: period window, velocity cap, and the bonded / refundable reversibility floor. @return list<Obj> */
    public static function mandateCaveats(mixed $terms): array
    {
        $cv = [];
        $ps = self::p($terms, 'periodStart');
        if (self::n($ps) > 0) {
            $cv[] = Obj::of(['type' => 'not_before', 'at' => $ps]);
        }
        $pe = self::p($terms, 'periodEnd');
        if ($pe !== self::UNDEF) {
            $cv[] = Obj::of(['type' => 'expires', 'at' => $pe]);
        }
        $mx = self::p($terms, 'maxTransactionsPerPeriod');
        if ($mx !== self::UNDEF && $pe !== self::UNDEF) {
            $per = self::jsMax(1.0, self::jsRound(fdiv(self::n($pe) - self::n($ps), 1000.0)));
            $cv[] = Obj::of(['type' => 'rate', 'max' => $mx, 'per_secs' => self::num($per)]);
        }
        $cv[] = Obj::of(['type' => 'reversibility_max', 'class' => 'reversible']);
        return $cv;
    }

    /** The risk policy that makes "spend = risk" exact: only blast radius weighs, theta1 = theta2 = Y/X, kappa = X, bMax = cap. */
    public static function mandateRiskPolicy(mixed $terms, mixed $replenishPerCosign = self::UNDEF): Obj
    {
        $a = self::p($terms, 'autoApproveThreshold');
        $x = self::p($terms, 'perTransactionCap');
        $th = self::num(fdiv(self::n($a), self::n($x)));
        return self::obj(['weights' => Obj::of(['alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0]),
            'theta1' => $th, 'theta2' => $th, 'kappa' => $x, 'lambda' => 0, 'rho' => $replenishPerCosign, 'bMax' => self::p($terms, 'cumulativeCap')]);
    }

    /** The most an agent can spend autonomously between two human co-signs: safetyBound * kappa (equals cumulativeCap). */
    public static function autoSpendBound(mixed $mandate): int|float
    {
        $p = self::p($mandate, 'policy');
        $kappa = self::n(self::p($p, 'kappa'));
        $bMax = self::n(self::p($p, 'bMax'));
        $bound = $kappa > 0 ? fdiv(self::jsMax(0.0, $bMax), $kappa) : 0.0;
        return self::num($bound * $kappa);
    }

    /**
     * Encode the params as a PCA Root Intent Grant envelope plus the initial trust budget. `principalSecret` is the 32-byte Ed25519
     * seed that signs the grant.
     */
    public static function buildPaymentMandate(mixed $params): Obj
    {
        self::validate($params);
        $g = static fn(string $k): mixed => self::p($params, $k);
        $now = self::fin($g('now')) ? $g('now') : self::now();
        $periodStart = self::fin($g('periodStart')) ? $g('periodStart') : $now;
        $cats = $g('categories');
        $terms = Obj::of(['merchants' => array_values($g('merchants')), 'categories' => self::truthy($cats) ? array_map(static fn($c) => $c instanceof Num && $c->lexeme === '-0' ? new Num('0') : $c, self::spread($cats)) : [], // a JS -0 is written as 0
            'currency' => $g('currency'), 'perTransactionCap' => $g('perTransactionCap'), 'autoApproveThreshold' => $g('autoApproveThreshold'),
            'cumulativeCap' => $g('cumulativeCap'), 'periodStart' => $periodStart]);
        if ($g('periodMs') !== self::UNDEF) {
            $terms->set('periodEnd', self::num(self::n($periodStart) + self::n($g('periodMs'))));
        }
        if ($g('maxTransactionsPerPeriod') !== self::UNDEF) {
            $terms->set('maxTransactionsPerPeriod', $g('maxTransactionsPerPeriod'));
        }
        $rep = $g('replenishPerCosign');
        $policy = self::mandateRiskPolicy($terms, self::nullish($rep) ? $terms->get('cumulativeCap') : $rep);
        $goal = $g('goal');
        if (self::nullish($goal)) {
            $goal = 'spend ≤ ' . self::s($terms->get('autoApproveThreshold')) . ' ' . self::s($terms->get('currency')) . ' autonomously / ≤ '
                . self::s($terms->get('perTransactionCap')) . ' with co-sign, ≤ ' . self::s($terms->get('cumulativeCap')) . ' cumulative, at ['
                . implode(', ', $terms->get('merchants')) . ']';
        }
        if (!is_string($goal)) {
            throw new \TypeError('buildPaymentMandate: goal must be a string');
        }
        $principal = new KeyPair(self::seed($g('principalSecret')));
        if ($g('principalPublic') !== $principal->public) {
            throw new \InvalidArgumentException('buildPaymentMandate: principalPublic is not the public key of principalSecret');
        }
        $holder = $g('agentPublic');
        if (!is_string($holder) || $holder === self::UNDEF) {
            throw new \TypeError('buildPaymentMandate: agentPublic must be a string');
        }
        $salt = $g('goalSalt');
        $minted = Sign::mintGrant($principal, $holder, [
            'predicates' => self::mandatePredicates($terms), 'caveats' => self::mandateCaveats($terms), 'agent_binding' => new Obj(),
            'risk_policy' => Sign::plain($policy),
        ], $goal, self::nullish($salt) ? null : (is_string($salt) ? $salt : throw new \TypeError('buildPaymentMandate: goalSalt must be a string')));
        return Obj::of(['grant' => $minted['grant'], 'policy' => $policy, 'budget' => Obj::of(['B' => $terms->get('cumulativeCap'), 'tau' => $now, 'asOf' => $now]),
            'terms' => $terms, 'goalCommit' => $minted['goal_commit'], 'goalSalt' => $minted['goal_salt']]);
    }

    // ---- charge decision ------------------------------------------------------------------------------------------------------

    private static function chargeParamsOf(mixed $mandate, mixed $charge): Obj
    {
        $cur = self::p($charge, 'currency');
        return self::obj(['amount' => self::p($charge, 'amount'),
            'currency' => $cur === self::UNDEF ? self::p(self::p($mandate, 'terms'), 'currency') : $cur,
            'category' => self::p($charge, 'category')]);
    }

    /** The charge params committed in both the plan node and the PCActn action. Only an ABSENT currency defaults to the mandate's. */
    public static function chargeParams(mixed $mandate, mixed $charge): Obj
    {
        return self::chargeParamsOf($mandate, $charge);
    }

    /** The action a charge denotes: the verb / resource / params the predicates and risk read. */
    public static function chargeActionContext(mixed $mandate, mixed $charge): Obj
    {
        return Obj::of(['action' => Obj::of(['verb' => 'charge', 'resource' => 'merchant:' . self::s(self::p($charge, 'merchant')),
            'params' => self::chargeParamsOf($mandate, $charge), 'reversibility_class' => self::CHARGE_REVERSIBILITY_CLASS])]);
    }

    private static function bindToVerifiedGrant(mixed $mandate, mixed $verifiedGrant): Obj
    {
        if ($verifiedGrant === null || $verifiedGrant === self::UNDEF || !(self::isList($verifiedGrant) || Js::isObj($verifiedGrant))) {
            throw new MandateGrantError('verified_grant_required', "a verified (or stored) grant is required; the mandate's own grant is never the authority");
        }
        if (!(self::isList($mandate) || Js::isObj($mandate)) || self::hash(self::p($mandate, 'grant')) !== self::hash($verifiedGrant)) {
            throw new MandateGrantError('mandate_grant_mismatch', 'the mandate grant is not the verified grant');
        }
        $env = Authorize::readEnvelope($verifiedGrant);
        $same = static fn(mixed $a, mixed $b): bool => self::hash($a) === self::hash($b);
        $terms = self::p($mandate, 'terms');
        $policy = self::p($mandate, 'policy');
        if ($env === null || !self::truthy($terms) || !self::truthy($policy) || !$same($env->get('predicates'), self::mandatePredicates($terms))
            || !$same($env->get('caveats'), self::mandateCaveats($terms)) || !$same($env->get('risk_policy'), $policy)) {
            throw new MandateGrantError('mandate_terms_mismatch', 'the mandate terms / policy are not the ones signed into the verified grant');
        }
        $bMax = self::n(self::p($env->get('risk_policy'), 'bMax'));
        $budget = self::q($mandate, 'budget');
        $b = $budget === self::UNDEF ? self::UNDEF : self::q($budget, 'B');
        $bb = self::fin($b) ? self::num(self::jsMax(0.0, self::jsMin(self::n($b), $bMax))) : 0;
        $out = self::spreadObj($mandate);
        $out->set('grant', $verifiedGrant);
        $nb = self::spreadObj($budget);
        $nb->set('B', $bb);
        $out->set('budget', $nb);
        return $out;
    }

    /**
     * The decide input for a charge: risk collapses to the normalised amount (spend = risk). A mandate whose grant, terms or policy
     * differ from `$verifiedGrant` is refused ({@see MandateGrantError}).
     */
    public static function chargeDecideInput(mixed $mandate0, mixed $charge, mixed $now, mixed $verifiedGrant): Obj
    {
        $mandate = self::bindToVerifiedGrant($mandate0, $verifiedGrant);
        $x = self::p(self::p($mandate, 'terms'), 'perTransactionCap');
        $amount = self::p($charge, 'amount');
        $amount = self::fin($amount) ? self::n($amount) : INF;
        $blast = self::n($x) > 0 ? fdiv($amount, self::n($x)) : 1;
        $ctx = new Obj();
        $ctx->set('reversibilityClass', self::CHARGE_REVERSIBILITY_CLASS);
        $recent = self::p($charge, 'recentChargeTimes');
        if ($recent !== self::UNDEF) {
            $ctx->set('recentActionTimes', $recent);
        }
        return Obj::of(['grant' => $verifiedGrant, 'action' => self::chargeActionContext($mandate, $charge),
            'risk' => Obj::of(['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => is_float($blast) ? self::num($blast) : $blast, 'taint' => 0, 'confidence' => 1, 'age' => 0]),
            'budget' => $mandate->get('budget'), 'now' => $now, 'caveatContext' => $ctx]);
    }

    /**
     * Run a charge through the PCA decision against the grant you VERIFIED (or loaded from your own store). Pure: reads the mandate
     * budget (clamped to the signed bMax) and returns the next one in `budgetAfter`. `$decide` is the PCA policy engine (the native Decide::decide when omitted).
     * @param \Closure(Obj):mixed $decide
     */
    public static function authorizeCharge(mixed $mandate0, mixed $charge, mixed $verifiedGrant, ?\Closure $decide = null): Obj
    {
        $decide ??= static fn(mixed $input): array => Decide::decide($input);
        $mandate = self::bindToVerifiedGrant($mandate0, $verifiedGrant);
        $now = self::p($charge, 'now');
        $now = self::fin($now) ? $now : self::now();
        $raw = $decide(self::chargeDecideInput($mandate, $charge, $now, $verifiedGrant));
        $amount = self::p($charge, 'amount');
        $merchant = self::p($charge, 'merchant');
        $refusal = !self::isMinorUnits($amount) ? self::AMOUNT_NOT_MINOR_UNITS : (!self::isPlainId($merchant) ? self::MERCHANT_INVALID : null);
        if ($refusal === null) {
            $decision = $raw;
        } else {
            $d = self::spreadObj($raw);
            $d->set('admit', false);
            $d->set('releaseGuardianShare', false);
            $d->set('reasons', [$refusal, ...self::spread(self::p($raw, 'reasons'))]);
            $d->set('budget', $mandate->get('budget'));
            $decision = $d;
        }
        if (!self::truthy(self::p($decision, 'releaseGuardianShare'))) {
            $outcome = 'deny';
        } elseif (self::truthy(self::p($decision, 'admit'))) {
            $outcome = 'auto';
        } else {
            $outcome = 'step_up';
        }
        $policy = $mandate->get('policy');
        $terms = $mandate->get('terms');
        $budget = $mandate->get('budget');
        $exact = $outcome === 'auto' && self::isMinorUnits($amount) && self::seq(self::p($policy, 'kappa'), self::p($terms, 'perTransactionCap'))
            && self::safeInt(self::q($budget, 'B'));
        $cost = $outcome !== 'auto' ? 0 : ($exact ? $amount
            : self::num(Risk::cost(self::n(self::p($decision, 'r')), self::n(self::p($policy, 'kappa')))));
        $rt = self::p($decision, 'requiredThreshold');
        $t = self::p($rt, 't');
        $r = self::p($decision, 'r');
        if ($exact) {
            $after = self::spreadObj(self::p($decision, 'budget'));
            $after->set('B', self::num(self::n(self::p($budget, 'B')) - self::n($amount)));
        } else {
            $after = self::p($decision, 'budget');
        }
        return self::obj(['outcome' => $outcome, 't' => $t, 'r' => $r, 'requiredThreshold' => $rt, 'cost' => $cost, 'budgetBefore' => $budget,
            'budgetAfter' => $after, 'reasons' => self::p($decision, 'reasons'), 'decision' => $decision]);
    }

    /** Advance the mandate's budget after a decision (functional). */
    public static function settleCharge(mixed $mandate, mixed $decision): Obj
    {
        $out = self::spreadObj($mandate);
        $after = self::p($decision, 'budgetAfter');
        if ($after === self::UNDEF) {
            return $out->without('budget');
        }
        $out->set('budget', $after);
        return $out;
    }

    /** @internal shared JavaScript-semantics helper */
    public static function nz(mixed $x): float
    {
        return self::fin($x) && self::n($x) > 0 ? self::n($x) : 0.0;
    }

    /**
     * Apply a human co-sign: restore autonomous budget by `rho`, or fully re-confirm to `bMax` with {"full": true}. The only way the
     * budget goes up.
     */
    public static function applyHumanCosign(mixed $mandate, mixed $now, mixed $opts = self::UNDEF): Obj
    {
        $opts = $opts === self::UNDEF ? new Obj() : $opts;
        $full = self::truthy(self::p($opts, 'full'));
        $policy = self::p($mandate, 'policy');
        if ($full) {
            $budget = Obj::of(['B' => self::num(self::nz(self::p($policy, 'bMax'))), 'tau' => $now, 'asOf' => $now]);
        } else {
            $bb = self::p(self::p($mandate, 'budget'), 'B');
            $rho = self::num(self::nz(self::p($policy, 'rho')));
            // `b.B + nz(rho)`: a string, list or object operand concatenates instead of adding
            $total = is_string($bb) || self::isList($bb) || $bb instanceof Obj ? self::n(self::s($bb) . Js::str($rho)) : self::n($bb) + self::n($rho);
            $budget = Obj::of(['B' => self::num(self::jsMin(self::nz(self::p($policy, 'bMax')), $total)), 'tau' => $now, 'asOf' => $now]);
        }
        $out = self::spreadObj($mandate);
        $out->set('budget', $budget);
        return $out;
    }

    private static function validRecord(mixed $r): bool
    {
        if (!Js::isObj($r)) {
            return false;
        }
        $v = Js::opt($r, 'version');
        $b = Js::opt($r, 'budget');
        return self::safeInt($v) && !(self::n($v) === 0.0 && fdiv(1.0, self::n($v)) < 0) && Js::isObj($b)
            && self::fin(Js::opt($b, 'B')) && self::fin(Js::opt($b, 'tau')) && self::fin(Js::opt($b, 'asOf'));
    }

    private static function version(mixed $rec): ?int
    {
        return $rec === null ? null : (int)self::n(Js::opt($rec, 'version'));
    }

    /**
     * authorizeCharge against the DURABLE cumulative budget in `$store` (the mandate's own budget is only the initial value). An auto
     * debit is committed with a compare-and-set before it is returned; losing the race re-reads and re-decides; persistent contention
     * returns a deny.
     * @param \Closure(Obj):mixed $decide
     */
    public static function authorizeChargeAtomic(mixed $mandate, mixed $charge, mixed $verifiedGrant, mixed $store, ?\Closure $decide = null, ?string $key = null): Obj
    {
        $decide ??= static fn(mixed $input): array => Decide::decide($input);
        if (!($store instanceof ChargeBudgetStore)) {
            throw new ChargeStoreError('a ChargeBudgetStore with get and compareAndSet is required');
        }
        $key ??= Pca::hashCanonical(Sign::n($verifiedGrant));
        for ($i = 0; $i < self::MAX_CAS_ATTEMPTS; $i++) {
            $rec = $store->get($key);
            if ($rec !== null && !self::validRecord($rec)) {
                throw new ChargeStoreError('the store returned a malformed budget record');
            }
            $m = $rec !== null ? self::withBudget($mandate, Js::opt($rec, 'budget')) : $mandate;
            $d = self::authorizeCharge($m, $charge, $verifiedGrant, $decide);
            if ($d->get('outcome') !== 'auto') {
                return $d;
            }
            if ($store->compareAndSet($key, self::version($rec), $d->get('budgetAfter'))) {
                return $d;
            }
        }
        $d = self::authorizeCharge($mandate, $charge, $verifiedGrant, $decide);
        $out = self::spreadObj($d);
        $out->set('outcome', 'deny');
        $out->set('t', 3);
        $out->set('cost', 0);
        $out->set('budgetAfter', $d->get('budgetBefore'));
        $out->set('reasons', ['budget_store_conflict', ...Js::spread($d->get('reasons'))]);
        return $out;
    }

    private static function withBudget(mixed $mandate, mixed $budget): Obj
    {
        $o = self::spreadObj($mandate);
        $o->set('budget', $budget);
        return $o;
    }

    /**
     * applyHumanCosign against the DURABLE budget, committed with a compare-and-set so a co-sign racing a charge is never lost or
     * applied twice. Call it only after verifying the human co-sign; persistent contention throws. `$opts`: full, key.
     */
    public static function applyHumanCosignAtomic(mixed $mandate, mixed $verifiedGrant, mixed $store, mixed $now, mixed $opts = null): mixed
    {
        if (!($store instanceof ChargeBudgetStore)) {
            throw new ChargeStoreError('a ChargeBudgetStore with get and compareAndSet is required');
        }
        $key = Js::opt($opts, 'key');
        $key = is_string($key) ? $key : Pca::hashCanonical(Sign::n($verifiedGrant));
        $full = Js::opt($opts, 'full') === true;
        for ($i = 0; $i < self::MAX_CAS_ATTEMPTS; $i++) {
            $rec = $store->get($key);
            if ($rec !== null && !self::validRecord($rec)) {
                throw new ChargeStoreError('the store returned a malformed budget record');
            }
            $bound = self::bindToVerifiedGrant($rec !== null ? self::withBudget($mandate, Js::opt($rec, 'budget')) : $mandate, $verifiedGrant);
            $next = self::applyHumanCosign($bound, $now, Obj::of(['full' => $full]))->get('budget');
            if ($store->compareAndSet($key, self::version($rec), $next)) {
                return $next;
            }
        }
        throw new ChargeStoreError('could not commit the co-sign: the budget record kept changing');
    }

    // ---- charge as a proof-carrying action ----------------------------------------------------------------------------------

    /** The committed plan node for a charge; params_digest is pinned to the charge params so the leaf reconciles with the PCActn. */
    public static function chargePlanNode(mixed $mandate, mixed $charge, mixed $id): Obj
    {
        return self::obj(['id' => $id, 'verb' => 'charge', 'resource' => 'merchant:' . self::s(self::p($charge, 'merchant')),
            'reversibility_class' => self::CHARGE_REVERSIBILITY_CLASS, 'params_digest' => Pca::paramsDigest(self::chargeParamsOf($mandate, $charge))]);
    }

    private static function intOf(mixed $v, string $what): int
    {
        if (!self::safeInt($v)) {
            throw new \InvalidArgumentException("chargeToPCActn: $what must be an integer");
        }
        return (int)self::n($v);
    }

    /**
     * A signed PCActn for a charge: {pcactn, node}. `$opts`: signerSecret (32-byte seed), aud, counter, optional chain, nodeId, now.
     */
    public static function chargeToPCActn(mixed $mandate, mixed $charge, mixed $opts): Obj
    {
        if (!self::isMinorUnits(self::p($charge, 'amount'))) {
            throw new \InvalidArgumentException('chargeToPCActn: amount must be a non-negative integer in minor units');
        }
        $nodeId = self::p($opts, 'nodeId');
        $counter = self::p($opts, 'counter');
        $nodeId = self::nullish($nodeId) ? 'charge:' . self::s(self::p($charge, 'merchant')) . ':' . self::s($counter) : $nodeId;
        $node = self::chargePlanNode($mandate, $charge, $nodeId);
        $x = self::p(self::p($mandate, 'terms'), 'perTransactionCap');
        $amount = self::p($charge, 'amount');
        $amount = self::fin($amount) ? self::n($amount) : self::n($x);
        $r = self::n($x) > 0 ? fdiv($amount, self::n($x)) : 1.0;
        $r = $r < 0 ? 0.0 : ($r > 1 ? 1.0 : $r);
        $params = self::chargeParamsOf($mandate, $charge);
        $chain = self::p($opts, 'chain');
        $chain = self::nullish($chain) ? [self::p($mandate, 'grant')] : $chain;
        if (!self::isList($chain) || $chain === [] || !($chain[0] instanceof Obj)) {
            throw new \InvalidArgumentException('chargeToPCActn: chain must be a non-empty list of capabilities');
        }
        $inputs = self::spreadObj($params);
        $inputs->set('blastRadius', self::num($r));
        $now = self::p($opts, 'now');
        $aud = self::p($opts, 'aud');
        if (!is_string($nodeId) || !is_string($aud) || $aud === self::UNDEF) {
            throw new \InvalidArgumentException('chargeToPCActn: nodeId and aud must be strings');
        }
        $pcactn = Sign::buildPcactn($chain[0], $chain, [$node], $nodeId, self::intOf($counter, 'counter'), new KeyPair(self::seed(self::p($opts, 'signerSecret'))),
            $aud, $params, self::nullish($now) ? null : self::intOf($now, 'now'), null, Sign::DEFAULT_TTL_MS,
            ['risk_claim' => Obj::of(['r' => self::num($r), 'inputs' => $inputs])]);
        return Obj::of(['pcactn' => $pcactn, 'node' => $node]);
    }

    // ---- Shared Payment Token limits, rails ---------------------------------------------------------------------------------

    /**
     * The usage_limits of a Stripe Shared Payment Token that fits what the mandate lets an agent spend WITHOUT a co-sign: at most the
     * auto-approve threshold and the remaining autonomous budget, lowercase currency, expiring with the mandate period.
     */
    public static function sharedPaymentTokenLimits(mixed $mandate, mixed $now): Obj
    {
        return Obj::of(self::sptLimits($mandate, $now));
    }

    /** @return array<string,mixed> */
    private static function sptLimits(mixed $mandate, mixed $now): array
    {
        if (!self::fin($now)) {
            throw new \TypeError('sharedPaymentTokenLimits: now must be an epoch-ms time');
        }
        $t = self::p($mandate, 'terms');
        $budget = self::jsFloor(self::n(self::p(self::p($mandate, 'budget'), 'B')));
        $max = self::jsMin(self::n(self::p($t, 'autoApproveThreshold')), $budget);
        if (!self::safeInt($max) || $max <= 0) {
            throw new \RangeException('sharedPaymentTokenLimits: no autonomous spend capacity is left; a human co-sign is needed');
        }
        $pe = self::p($t, 'periodEnd');
        if ($pe !== self::UNDEF && !self::fin($pe)) {
            throw new \TypeError('sharedPaymentTokenLimits: periodEnd must be an epoch-ms time');
        }
        if ($pe !== self::UNDEF && !(is_finite(self::n($now)) && self::n($now) < self::n($pe))) {
            throw new \RangeException('sharedPaymentTokenLimits: the mandate period has ended');
        }
        $cur = self::p($t, 'currency');
        if (!is_string($cur) || $cur === self::UNDEF) {
            throw new \TypeError('t.currency.toLowerCase is not a function');
        }
        $out = ['currency' => mb_strtolower($cur, 'UTF-8'), 'max_amount' => (int)$max];
        if ($pe !== self::UNDEF) {
            $out['expires_at'] = self::num(self::jsFloor(fdiv(self::n($pe), 1000.0)));
        }
        return $out;
    }

    /** Action-kit convention: a trait `mcc.c5734` says the verb may spend in MCC 5734. Traits only narrow. @return list<string> */
    public static function categoriesFromTraits(mixed $traits): array
    {
        $out = [];
        foreach (Js::spread($traits) as $t) {
            if (preg_match(self::MCC_TRAIT_RE, Js::str($t), $m) === 1) {
                $out[$m[1]] = true;
            }
        }
        $keys = array_map('strval', array_keys($out));
        sort($keys, SORT_STRING);
        return $keys;
    }

    /**
     * The limits an instrument for this mandate may carry (amounts from sharedPaymentTokenLimits; categories are the mandate's
     * allowlist narrowed by the action's mcc traits). `$opts`: actionTraits, allowAnyCategory.
     */
    public static function railLimits(mixed $mandate, mixed $now, mixed $opts = self::UNDEF): Obj
    {
        $opts = $opts === self::UNDEF ? new Obj() : $opts;
        $spt = self::sptLimits($mandate, $now);
        $total = self::num(self::jsFloor(self::n(self::p(self::p($mandate, 'budget'), 'B'))));
        $t = self::p($mandate, 'terms');
        $fromMandate = self::spread(self::p($t, 'categories'));
        $traits = self::p($opts, 'actionTraits');
        $fromTraits = self::categoriesFromTraits(self::nullish($traits) ? [] : $traits);
        if ($fromMandate !== [] && $fromTraits !== []) {
            $cats = self::jsSort(array_values(array_filter($fromMandate, static fn($c): bool => in_array($c, $fromTraits, true))));
            if ($cats === []) {
                throw new \RangeException('railLimits: the action traits and the mandate categories do not intersect; nothing may be spent');
            }
        } else {
            $cats = self::jsSort($fromMandate !== [] ? $fromMandate : $fromTraits);
        }
        if ($cats === [] && self::p($opts, 'allowAnyCategory') !== true) {
            throw new \RangeException('railLimits: no category control (mandate categories or mcc.* traits); pass allowAnyCategory to accept any merchant category');
        }
        $cur = self::p($t, 'currency');
        if (!is_string($cur) || $cur === self::UNDEF) {
            throw new \TypeError('mandate.terms.currency.toUpperCase is not a function');
        }
        $out = Obj::of(['currency' => mb_strtoupper($cur, 'UTF-8'), 'perAuthorizationMax' => $spt['max_amount'], 'totalMax' => $total,
            'categories' => $cats, 'merchants' => self::spread(self::p($t, 'merchants'))]);
        if (isset($spt['expires_at'])) {
            $out->set('expiresAt', self::num(self::n($spt['expires_at']) * 1000));
        }
        return $out;
    }

    private static function decline(string ...$reasons): Obj
    {
        return Obj::of(['approved' => false, 'reasons' => array_values($reasons)]);
    }

    /**
     * A real-time authorization callback that answers from authorizeChargeAtomic inside a latency budget. Total: a step-up, a deny, an
     * unknown card, a timeout, an exception are all declines. `$opts`: instruments(string $instrumentId) -> {mandate, grant, budgetKey?}
     * | null, store, decide, latencyBudgetMs (default 1500), now() -> ms, onStepUp(authorization, decision).
     * shortcut: PHP cannot preempt a running decision, so a decision that overruns the budget is discarded after it returns (its debit,
     * if any, stays: an under-spend, the safe direction); wrap the store calls in your own timeout for a hard bound.
     * @return \Closure(mixed):Obj
     */
    public static function createRailAuthorizer(mixed $opts): \Closure
    {
        $b = Js::opt($opts, 'latencyBudgetMs');
        $budgetMs = $b === null ? 1500 : $b;
        if (!self::fin($budgetMs) || !(self::n($budgetMs) > 0)) {
            throw new \RangeException('createRailAuthorizer: latencyBudgetMs must be positive');
        }
        $clock = Js::opt($opts, 'now');
        $clock = $clock instanceof \Closure ? $clock : static fn(): int => self::now();
        $instruments = Js::opt($opts, 'instruments');
        $store = Js::opt($opts, 'store');
        $decide = Js::opt($opts, 'decide');
        $onStepUp = Js::opt($opts, 'onStepUp');
        $one = static function (mixed $a) use ($instruments, $store, $decide, $onStepUp, $clock): Obj {
            if (!Js::isObj($a) || !is_string(Js::opt($a, 'id')) || !is_string(Js::opt($a, 'instrumentId')) || Js::opt($a, 'id') === '') {
                return self::decline('malformed_authorization');
            }
            $amount = Js::opt($a, 'amount');
            if (!self::safeInt($amount) || !(self::n($amount) > 0)) {
                return self::decline('amount_not_positive_minor_units');
            }
            $cur = Js::opt($a, 'currency');
            if (!is_string($cur) || $cur === '') {
                return self::decline('currency_missing');
            }
            $merchant = Js::opt($a, 'merchantId');
            if (!is_string($merchant) || $merchant === '') {
                return self::decline('merchant_unknown');
            }
            $inst = $instruments(Js::opt($a, 'instrumentId'));
            if ($inst === null) {
                return self::decline('instrument_unknown');
            }
            $charge = Obj::of(['merchant' => $merchant, 'amount' => $amount, 'currency' => mb_strtoupper($cur, 'UTF-8')]);
            if (Js::has($a, 'mcc')) {
                $charge->set('category', Js::opt($a, 'mcc'));
            }
            $charge->set('now', $clock());
            $bk = Js::opt($inst, 'budgetKey');
            $d = self::authorizeChargeAtomic(Js::opt($inst, 'mandate'), $charge, Js::opt($inst, 'grant'), $store, $decide, is_string($bk) ? $bk : null);
            $out = $d->get('outcome');
            if ($out === 'auto') {
                return Obj::of(['approved' => true, 'reasons' => [], 'decision' => $d]);
            }
            if ($out === 'step_up') {
                try {
                    if ($onStepUp instanceof \Closure) {
                        $onStepUp($a, $d);
                    }
                } catch (\Throwable) {
                    // a failing notifier must not change the answer
                }
                return Obj::of(['approved' => false, 'reasons' => ['step_up_required', ...$d->get('reasons')], 'decision' => $d]);
            }
            $rs = $d->get('reasons');
            return Obj::of(['approved' => false, 'reasons' => $rs !== [] ? $rs : ['denied'], 'decision' => $d]);
        };
        $limit = self::n($budgetMs) / 1000.0;
        return static function (mixed $a) use ($one, $limit): Obj {
            $t0 = self::clock();
            try {
                $v = $one($a);
            } catch (\Throwable) {
                return self::decline('authorizer_error');
            }
            return self::clock() - $t0 > $limit ? self::decline('latency_budget_exceeded') : $v;
        };
    }

    /** Compare what settled with what PCA approved: commit only on an exact fit; anything else says freeze the grant. */
    public static function reconcileSettlement(mixed $approved, mixed $s): Obj
    {
        $reasons = [];
        if (!self::seq(self::p($s, 'authorizationId'), self::p($approved, 'id'))) {
            $reasons[] = 'authorization_id_mismatch';
        }
        if (self::gt(self::p($s, 'amount'), self::p($approved, 'amount'))) {
            $reasons[] = 'settled_more_than_approved';
        }
        $sc = self::p($s, 'currency');
        $ac = self::p($approved, 'currency');
        if (!is_string($sc) || $sc === self::UNDEF || !is_string($ac) || $ac === self::UNDEF) {
            throw new \TypeError('currency.toUpperCase is not a function');
        }
        if (mb_strtoupper($sc, 'UTF-8') !== mb_strtoupper($ac, 'UTF-8')) {
            $reasons[] = 'currency_mismatch';
        }
        if (!self::seq(self::p($s, 'merchantId'), self::p($approved, 'merchantId'))) {
            $reasons[] = 'merchant_mismatch';
        }
        if (self::gt(self::p($s, 'captures'), 1)) {
            $reasons[] = 'second_capture';
        }
        return $reasons === [] ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'reasons' => $reasons, 'action' => 'freeze_grant']);
    }

    // ---- Stripe Issuing adapter ---------------------------------------------------------------------------------------------

    /**
     * The form parameters for POST /v1/issuing/cards (virtual, active) that carry the rail limits. `$opts`: categoryNames (MCC ->
     * Stripe category), cardholder, metadata. Throws when an MCC has no Stripe category name.
     */
    public static function stripeCardParams(mixed $limits, mixed $opts): Obj
    {
        $cur = self::p($limits, 'currency');
        if (!is_string($cur) || $cur === self::UNDEF) {
            throw new \TypeError('limits.currency.toLowerCase is not a function');
        }
        $p = self::obj(['cardholder' => self::p($opts, 'cardholder'), 'type' => 'virtual', 'status' => 'active', 'currency' => mb_strtolower($cur, 'UTF-8'),
            'spending_controls[spending_limits][0][amount]' => self::s(self::p($limits, 'perAuthorizationMax')),
            'spending_controls[spending_limits][0][interval]' => 'per_authorization',
            'spending_controls[spending_limits][1][amount]' => self::s(self::p($limits, 'totalMax')),
            'spending_controls[spending_limits][1][interval]' => 'all_time']);
        $names = self::p($opts, 'categoryNames');
        foreach (self::spread(self::p($limits, 'categories')) as $i => $mcc) {
            $name = Js::isObj($names) ? self::p($names, Js::str($mcc)) : self::UNDEF;
            if ($name === self::UNDEF) {
                throw new \RangeException('stripeCardParams: no Stripe category name for MCC ' . Js::str($mcc));
            }
            $p->set("spending_controls[allowed_categories][$i]", $name);
        }
        $md = self::p($opts, 'metadata');
        if (self::truthy($md) && $md !== self::UNDEF) {
            foreach (Js::isObj($md) ? Js::ownKeys($md instanceof Obj ? $md->keys() : array_map('strval', array_keys($md))) : [] as $k) {
                $p->set("metadata[$k]", Js::opt($md, $k));
            }
        }
        return $p;
    }

    /** The header Stripe would send (tests and local tooling). */
    public static function signStripePayload(mixed $rawBody, mixed $secret, mixed $tSec): string
    {
        if (!is_string($rawBody) || !is_string($secret)) {
            throw new \TypeError('signStripePayload: rawBody and secret must be strings');
        }
        $t = self::s($tSec);
        return 't=' . $t . ',v1=' . hash_hmac('sha256', Js::utf8($t . '.' . $rawBody), Js::utf8($secret));
    }

    /** Verify a `Stripe-Signature` header over the RAW body. Total: false on anything malformed, stale or mismatched. */
    public static function verifyStripeSignature(mixed $rawBody, mixed $header, mixed $secret, mixed $nowSec, mixed $toleranceSec = self::STRIPE_WEBHOOK_TOLERANCE_SEC): bool
    {
        try {
            if (!is_string($header) || !is_string($secret) || $secret === '' || !(is_finite(self::n($toleranceSec)) && self::n($toleranceSec) > 0)) {
                return false;
            }
            $t = null;
            $v1 = [];
            foreach (explode(',', $header) as $part) {
                $i = strpos($part, '=');
                if ($i === false) {
                    continue;
                }
                $k = self::trim(substr($part, 0, $i));
                $v = self::trim(substr($part, $i + 1));
                if ($k === 't') {
                    $t = $v;
                } elseif ($k === 'v1') {
                    $v1[] = $v;
                }
            }
            if ($t === null || preg_match('/\A[0-9]{1,12}\z/', $t) !== 1 || $v1 === []) {
                return false;
            }
            if (!(abs(self::n($nowSec) - (float)$t) <= self::n($toleranceSec))) {
                return false;
            }
            if (!is_string($rawBody)) {
                return false;
            }
            $want = hash_hmac('sha256', Js::utf8($t . '.' . $rawBody), Js::utf8($secret), true);
            foreach ($v1 as $sig) {
                if (preg_match('/\A[0-9a-f]{64}\z/', $sig) === 1 && hash_equals($want, (string)hex2bin($sig))) {
                    return true;
                }
            }
            return false;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Normalise an `issuing_authorization.request` event; null when it is not a well-formed request with a pending amount. */
    public static function stripeAuthorizationFromEvent(mixed $event): ?Obj
    {
        $o = static fn(mixed $v): mixed => Js::isObj($v) ? $v : null;
        if (!Js::isObj($event) || Js::opt($event, 'type') !== 'issuing_authorization.request') {
            return null;
        }
        $data = $o(Js::opt($event, 'data'));
        $a = $o($data === null ? null : Js::opt($data, 'object'));
        $pending = $o($a === null ? null : Js::opt($a, 'pending_request'));
        $card = $o($a === null ? null : Js::opt($a, 'card'));
        $merchant = $o($a === null ? null : Js::opt($a, 'merchant_data'));
        if ($a === null || $pending === null || !is_string(Js::opt($a, 'id')) || $card === null || !is_string(Js::opt($card, 'id'))) {
            return null;
        }
        $amount = Js::opt($pending, 'amount');
        $currency = Js::opt($pending, 'currency');
        if (!Js::isNum($amount) || !is_string($currency)) {
            return null;
        }
        $out = Obj::of(['id' => Js::opt($a, 'id'), 'instrumentId' => Js::opt($card, 'id'), 'amount' => $amount, 'currency' => $currency]);
        $nid = $merchant === null ? null : Js::opt($merchant, 'network_id');
        if (is_string($nid) && $nid !== '') {
            $out->set('merchantId', $nid);
        }
        $cc = $merchant === null ? null : Js::opt($merchant, 'category_code');
        if (is_string($cc)) {
            $out->set('mcc', $cc);
        }
        return $out;
    }

    private static function reply(int $status, Obj $body, string $version): Obj
    {
        return Obj::of(['status' => $status, 'headers' => Obj::of(['Stripe-Version' => $version, 'Content-Type' => 'application/json']), 'body' => Js::stringify($body)]);
    }

    /**
     * The HTTP handler body for the `issuing_authorization.request` endpoint. Bad signature: 400 (nothing is decided). A request
     * event gets 200 {approved} from the PCA decision; any other event type gets 200 {}. `amount` is never sent. `$opts`: secret,
     * authorize(authorization) -> verdict, stripeVersion, nowSec(), toleranceSec. REQUIRED OPERATOR SETTING: set the Issuing
     * authorization timeout response to DECLINE and turn Autopilot off. The returned handler takes {rawBody, signature}.
     * @return \Closure(mixed):Obj
     */
    public static function createStripeIssuingWebhook(mixed $opts): \Closure
    {
        $version = Js::opt($opts, 'stripeVersion');
        $version = is_string($version) && $version !== '' ? $version : self::STRIPE_API_VERSION;
        $nowSec = Js::opt($opts, 'nowSec');
        $nowSec = $nowSec instanceof \Closure ? $nowSec : static fn(): int => time();
        $authorize = Js::opt($opts, 'authorize');
        $secret = Js::opt($opts, 'secret');
        $tol = Js::opt($opts, 'toleranceSec');
        return static function (mixed $req) use ($version, $nowSec, $authorize, $secret, $tol): Obj {
            $raw = Js::opt($req, 'rawBody');
            if (!self::verifyStripeSignature($raw, Js::opt($req, 'signature'), $secret, $nowSec(), $tol ?? self::STRIPE_WEBHOOK_TOLERANCE_SEC)) {
                return self::reply(400, Obj::of(['error' => 'bad_signature']), $version);
            }
            try {
                $event = Js::parseNoDuplicates($raw) /* a repeated member: JSON.parse keeps the last, the signer saw the first */;
            } catch (\Throwable) {
                return self::reply(400, Obj::of(['error' => 'bad_json']), $version);
            }
            if (!Js::isObj($event) || Js::opt($event, 'type') !== 'issuing_authorization.request') {
                return self::reply(200, new Obj(), $version);
            }
            $auth = self::stripeAuthorizationFromEvent($event);
            if ($auth === null) {
                return self::reply(200, Obj::of(['approved' => false]), $version);
            }
            $v = $authorize($auth);
            return self::reply(200, Obj::of(['approved' => Js::opt($v, 'approved') === true]), $version);
        };
    }

    /** Normalise an `issuing_transaction.created` capture into a settlement (a capture's amount is negative in Stripe's ledger). */
    public static function stripeSettlementFromTransaction(mixed $txn): ?Obj
    {
        if (!Js::isObj($txn)) {
            return null;
        }
        $m = Js::opt($txn, 'merchant_data');
        $amount = Js::opt($txn, 'amount');
        if (Js::opt($txn, 'type') !== 'capture' || !is_string(Js::opt($txn, 'authorization')) || !Js::isNum($amount) || !is_string(Js::opt($txn, 'currency'))) {
            return null;
        }
        $out = Obj::of(['authorizationId' => Js::opt($txn, 'authorization'), 'amount' => self::num(-self::n($amount)), 'currency' => Js::opt($txn, 'currency')]);
        if (Js::isObj($m) && is_string(Js::opt($m, 'network_id'))) {
            $out->set('merchantId', Js::opt($m, 'network_id'));
        }
        $out->set('captures', 1);
        return $out;
    }

    // ---- agent network tokens -----------------------------------------------------------------------------------------------

    private static function luhn(string $d): bool
    {
        $sum = 0;
        $dbl = false;
        for ($i = strlen($d) - 1; $i >= 0; $i--) {
            $n = ord($d[$i]) - 48;
            if ($dbl) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $dbl = !$dbl;
        }
        return $sum % 10 === 0;
    }

    /** True when a maximal digit run (spaces and hyphens removed) is 13..19 long and Luhn-valid. Whole runs only: no sliding windows. */
    public static function looksLikePan(mixed $s): bool
    {
        if (!is_string($s)) {
            throw new \TypeError('s.replace is not a function');
        }
        $t = (string)preg_replace('/(?:' . IntentWb::JS_WS . '|-)/', '', $s);
        preg_match_all('/[0-9]+/', $t, $m);
        foreach ($m[0] as $r) {
            if (strlen($r) >= 13 && strlen($r) <= 19 && self::luhn($r)) {
                return true;
            }
        }
        return false;
    }

    /** null = a well-formed opaque handle: 8..128 chars of [A-Za-z0-9_.:-], never PAN-shaped. */
    public static function tokenRefError(mixed $ref): ?string
    {
        if (!is_string($ref) || $ref === self::UNDEF || preg_match('/\A[A-Za-z0-9_.:-]{8,128}\z/', $ref) !== 1) {
            return 'token_ref_malformed';
        }
        return self::looksLikePan($ref) ? 'token_ref_looks_like_pan' : null;
    }

    private static function bodyOf(mixed $b): Obj
    {
        $body = [];
        foreach (['provider', 'token_ref', 'grant_digest', 'issuer_nonce', 'holder'] as $k) {
            $v = self::p($b, $k);
            if ($v === self::UNDEF) {
                throw new \TypeError('canonicalize: unsupported type undefined');
            }
            $body[$k] = $v;
        }
        return Obj::of(['kind' => self::NETWORK_TOKEN_BINDING_KIND, 'v' => 1, ...$body]);
    }

    /** The exact bytes the holder signs: utf8 of the canonical-JSON digest of the binding body (raw bytes). */
    public static function bindingMessage(mixed $b): string
    {
        return Js::utf8(self::hash(self::bodyOf($b)));
    }

    /**
     * Tie a grant holder to an OPAQUE network-token reference (never a PAN). `$opts`: provider, tokenRef, grant, issuerNonce,
     * holderSecret (32-byte seed), holderPublic (32 bytes).
     */
    public static function bindNetworkToken(mixed $opts): Obj
    {
        $e = self::tokenRefError(self::p($opts, 'tokenRef'));
        if ($e !== null) {
            throw new \RangeException("bindNetworkToken: $e");
        }
        $n = self::length(self::p($opts, 'issuerNonce'));
        if ($n !== self::UNDEF && self::n($n) < 16) {
            throw new \RangeException('bindNetworkToken: issuer nonce must be at least 16 chars');
        }
        $core = self::obj(['provider' => self::p($opts, 'provider'), 'token_ref' => self::p($opts, 'tokenRef'),
            'grant_digest' => self::hash(self::p($opts, 'grant')), 'issuer_nonce' => self::p($opts, 'issuerNonce'),
            'holder' => Pca::b64u(self::rawBytes(self::p($opts, 'holderPublic')))]);
        $proof = (new KeyPair(self::seed(self::p($opts, 'holderSecret'))))->sign(self::bindingMessage($core));
        $out = Obj::of(['kind' => self::NETWORK_TOKEN_BINDING_KIND]);
        foreach ($core->keys() as $k) {
            $out->set($k, $core->get($k));
        }
        $out->set('binding_proof', Pca::b64u($proof));
        return $out;
    }

    /** Total. null = valid. `$expect`: grant (the one the caller verified), holder (b64u), issuerNonce, optional provider. */
    public static function verifyNetworkTokenBinding(mixed $b, mixed $expect): ?string
    {
        try {
            if (!(self::isList($b) || Js::isObj($b)) || self::p($b, 'kind') !== self::NETWORK_TOKEN_BINDING_KIND) {
                return 'binding_malformed';
            }
            $e = self::tokenRefError(self::p($b, 'token_ref'));
            if ($e !== null) {
                return $e;
            }
            $prov = self::p($b, 'provider');
            $expProv = self::p($expect, 'provider');
            if (!is_string($prov) || $prov === self::UNDEF || $prov === '' || ($expProv !== self::UNDEF && !self::seq($prov, $expProv))) {
                return 'provider_mismatch';
            }
            if (!self::seq(self::p($b, 'grant_digest'), self::hash(self::p($expect, 'grant')))) {
                return 'grant_digest_mismatch';
            }
            if (!self::seq(self::p($b, 'holder'), self::p($expect, 'holder'))) {
                return 'holder_mismatch';
            }
            if (!self::seq(self::p($b, 'issuer_nonce'), self::p($expect, 'issuerNonce'))) {
                return 'issuer_nonce_mismatch';
            }
            $holder = self::p($b, 'holder');
            $proof = self::p($b, 'binding_proof');
            if (Pca::unb64u($holder) === null || Pca::unb64u($proof) === null) {
                return 'binding_malformed';
            }
            return Pca::verifyEd25519B64u($holder, self::bindingMessage($b), $proof) ? null : 'binding_proof_invalid';
        } catch (\Throwable) {
            return 'binding_malformed';
        }
    }

    /** The network-side controls: always an upper-bounded copy of the rail limits. */
    public static function controlsFromLimits(mixed $limits, mixed $grant): Obj
    {
        $c = self::obj(['currency' => self::p($limits, 'currency'), 'perAuthorizationMax' => self::p($limits, 'perAuthorizationMax'),
            'totalMax' => self::p($limits, 'totalMax'), 'categories' => self::spread(self::p($limits, 'categories')),
            'merchants' => self::spread(self::p($limits, 'merchants'))]);
        $exp = self::p($limits, 'expiresAt');
        if ($exp !== self::UNDEF) {
            $c->set('expiresAt', $exp);
        }
        $c->set('metadata', Obj::of(['grant_digest' => self::hash($grant)]));
        return $c;
    }

    /** The metadata a charge / authorization carries: fixed keys, digest values (no PII, no PAN). */
    public static function settlementMetadata(mixed $b, mixed $pcactnDigest): Obj
    {
        return self::obj(['pca_grant' => self::p($b, 'grant_digest'), 'pca_pcactn' => $pcactnDigest, 'pca_token_ref' => self::p($b, 'token_ref')]);
    }

    /** A network settlement record joins the ledger entry only if all three echoed values match exactly. */
    public static function reconcileNetworkSettlement(mixed $expected, mixed $record): Obj
    {
        $md = $record === null || $record === self::UNDEF ? self::UNDEF : self::p($record, 'metadata');
        $m = self::nullish($md) ? new Obj() : $md;
        $reasons = [];
        $ped = self::p($m, 'pca_pcactn');
        if (!is_string($ped) || $ped === self::UNDEF || $ped === '' || self::seq(self::length(self::p($expected, 'pcactnDigest')), 0)) {
            $reasons[] = 'pcactn_digest_missing';
        }
        if (!self::seq(self::p($m, 'pca_grant'), self::p($expected, 'grantDigest'))) {
            $reasons[] = 'grant_digest_mismatch';
        }
        if (!self::seq($ped, self::p($expected, 'pcactnDigest'))) {
            $reasons[] = 'pcactn_digest_mismatch';
        }
        if (!self::seq(self::p($m, 'pca_token_ref'), self::p($expected, 'tokenRef'))) {
            $reasons[] = 'token_ref_mismatch';
        }
        return $reasons === [] ? Obj::of(['ok' => true]) : Obj::of(['ok' => false, 'reasons' => $reasons]);
    }

    /**
     * Build the PCActn for the charge and return the metadata for the network request, derived from THAT PCActn's digest: there is no
     * way to carry a digest that is not of a PCActn this call built. Returns {pcactn, node, metadata, pcactnDigest}.
     */
    public static function chargeWithNetworkToken(mixed $binding, mixed $mandate, mixed $charge, mixed $opts): Obj
    {
        if (self::tokenRefError(self::p($binding, 'token_ref')) !== null) {
            throw new \RangeException('chargeWithNetworkToken: bad binding');
        }
        if (!self::seq(self::p($binding, 'grant_digest'), self::hash(self::p($mandate, 'grant')))) {
            throw new \RangeException('chargeWithNetworkToken: binding is for another grant');
        }
        $built = self::chargeToPCActn($mandate, $charge, $opts);
        $digest = Pca::hashCanonical($built->get('pcactn'));
        return Obj::of(['pcactn' => $built->get('pcactn'), 'node' => $built->get('node'), 'metadata' => self::settlementMetadata($binding, $digest), 'pcactnDigest' => $digest]);
    }

    /** Visa Intelligent Commerce, generic mapping (partner-gated; unverified field names). @param \Closure(string,Obj):mixed $post */
    public static function visaIntelligentCommerceAdapter(\Closure $post): NetworkTokenProvider
    {
        return new PartnerNetworkTokenProvider('visa_ic', 'instructions', $post);
    }

    /** Mastercard Agent Pay (agentic tokens over MDES), generic mapping (partner-gated; unverified field names). @param \Closure(string,Obj):mixed $post */
    public static function mastercardAgentPayAdapter(\Closure $post): NetworkTokenProvider
    {
        return new PartnerNetworkTokenProvider('mastercard_agent_pay', 'session_scope', $post);
    }

    /**
     * Issuance gate: issue a token whose controls equal the rail limits, then bind it to the grant holder. `$opts`: provider, limits,
     * grant, agentId, holderSecret, holderPublic, issuerNonce. Returns {binding, controls}.
     */
    public static function issueBoundNetworkToken(mixed $opts): Obj
    {
        $provider = self::p($opts, 'provider');
        if (!($provider instanceof NetworkTokenProvider)) {
            throw new \TypeError('a NetworkTokenProvider is required');
        }
        $controls = self::controlsFromLimits(self::p($opts, 'limits'), self::p($opts, 'grant'));
        $res = $provider->issue(Obj::of(['controls' => $controls, 'agentId' => self::p($opts, 'agentId')]));
        $binding = self::bindNetworkToken(Obj::of(['provider' => $provider->id(), 'tokenRef' => Js::opt($res, 'token_ref'), 'grant' => self::p($opts, 'grant'),
            'issuerNonce' => self::p($opts, 'issuerNonce'), 'holderSecret' => self::p($opts, 'holderSecret'), 'holderPublic' => self::p($opts, 'holderPublic')]));
        return Obj::of(['binding' => $binding, 'controls' => $controls]);
    }

    /** Grant revoked => suspend. Provider errors propagate (a failed suspend is not a success). */
    public static function suspendOnRevoke(NetworkTokenProvider $provider, mixed $binding): void
    {
        $ref = self::p($binding, 'token_ref');
        $provider->suspend(is_string($ref) ? $ref : Js::str($ref), 'grant_revoked');
    }

    // ---- the bonded claim ---------------------------------------------------------------------------------------------------

    private static function windowError(mixed $issuedAt, mixed $windowMs, mixed $serverNow, mixed $policy): ?string
    {
        if (!self::fin($serverNow)) {
            return 'server time is not finite';
        }
        if (!self::fin($issuedAt) || !self::fin($windowMs)) {
            return 'malformed challenge window';
        }
        if (abs(self::n($issuedAt) - self::n($serverNow)) > self::n(self::p($policy, 'maxSkewMs'))) {
            return 'issued_at is outside the allowed skew of server time';
        }
        if (self::n($windowMs) < self::n(self::p($policy, 'minWindowMs'))) {
            return 'challenge window is below the minimum';
        }
        if (self::n($windowMs) > self::n(self::p($policy, 'maxWindowMs'))) {
            return 'challenge window exceeds the maximum';
        }
        return null;
    }

    /**
     * Open the optimistic bonded claim for a charge (the dispute / refund window): a signed, bonded claim of compliance a watchtower can
     * challenge. Refuses an irreversible charge. `$opts`: bondRef, claimedR, challengeWindowMs?, issuedAt?, serverNow?, windowPolicy?.
     */
    public static function openChargeBond(mixed $pcactn, mixed $opts, mixed $signerSecret): Obj
    {
        $rc = Js::opt(Js::opt($pcactn, 'action'), 'reversibility_class');
        if ($rc === Optimistic::IRREVERSIBLE_CLASS) {
            throw new \InvalidArgumentException('openOptimistic: irreversible actions cannot use the optimistic fast-path (§9A)');
        }
        $claimedR = self::p($opts, 'claimedR');
        if (!self::fin($claimedR)) {
            throw new \InvalidArgumentException('openOptimistic: claimedR must be finite');
        }
        $policy = self::p($opts, 'windowPolicy');
        $policy = self::nullish($policy) ? Obj::of(Optimistic::DEFAULT_WINDOW_POLICY) : $policy;
        $serverNow = self::p($opts, 'serverNow');
        $serverNow = self::fin($serverNow) ? $serverNow : self::now();
        $issuedAt = self::p($opts, 'issuedAt');
        $issuedAt = self::fin($issuedAt) ? $issuedAt : $serverNow;
        $windowMs = self::p($opts, 'challengeWindowMs');
        $windowMs = $windowMs === self::UNDEF ? self::p($policy, 'defaultWindowMs') : $windowMs;
        $bad = self::windowError($issuedAt, $windowMs, $serverNow, $policy);
        if ($bad !== null) {
            throw new \InvalidArgumentException("openOptimistic: $bad");
        }
        $bond = self::p($opts, 'bondRef');
        $body = Obj::of(['pcactn_digest' => Pca::hashCanonical($pcactn), 'bond_ref' => $bond === self::UNDEF ? null : $bond, 'claimed_r' => $claimedR,
            'reversibility_class' => is_string($rc) ? $rc : 'unknown', 'issued_at' => $issuedAt, 'challenge_window_ms' => $windowMs]);
        $sig = (new KeyPair(self::seed($signerSecret)))->sign(Optimistic::CLAIM_DOMAIN . Json::canonicalizeLenient($body));
        $out = self::spreadObj($body);
        $out->set('sig', Pca::b64u($sig));
        return $out;
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
