<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Risk.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/IntentWb.php';

/**
 * Attest the mediator, not the weights. The trusted computing base is this small orchestration harness, not an opaque model: the model
 * is an UNTRUSTED ORACLE that proposes a candidate action, and the harness enforces plan inclusion, the taint fold and the trust
 * budget before any candidate becomes a signed PCActn. The oracle holds no signing key (the reference's pca-harness), including the
 * resource-server hook that admits an allowlisted harness measurement. `step` takes a plain callable returning the candidate.
 */
final class Harness
{
    /** The ordered manifest of checks the harness enforces before signing; folded into the measurement. */
    public const ENFORCED_CHECKS = ['plan_inclusion_before_signing', 'taint_provenance_fold', 'trust_budget_debit', 'pcactn_sign'];
    public const HARNESS_VERSION = '0.1.0';
    /** The model id stamped into an emitted PCActn's attestation.model_id when attestation is enabled (the mediator, not an LLM). */
    public const HARNESS_MODEL_ID = '@atlasauth/pca-harness';
    private const DEFAULT_BASE_RISK = ['semanticDistance' => 0.1, 'reversibility' => 1, 'blastRadius' => 0.1, 'taint' => 0, 'confidence' => 1, 'age' => 0];

    /** Pure self-measurement over the harness version, the enforced-checks manifest and the risk-policy identity (weights, theta1, theta2, kappa). A policy missing one of those throws. */
    public static function computeHarnessMeasurement(mixed $version, mixed $enforcedChecks, mixed $policy): string
    {
        if (!($policy instanceof Obj)) {
            throw new \TypeError('computeHarnessMeasurement: policy is not an object');
        }
        $rp = new Obj();
        foreach (['weights', 'theta1', 'theta2', 'kappa'] as $k) {
            if (!$policy->has($k)) {
                throw new \InvalidArgumentException('canonicalize: unsupported type undefined');
            }
            $rp->set($k, $policy->get($k));
        }
        return Pca::hashCanonical(Obj::of(['harness' => self::HARNESS_MODEL_ID, 'version' => $version, 'enforces' => $enforcedChecks, 'risk_policy' => $rp]));
    }

    private static function member(mixed $v, string $k): mixed
    {
        return $v instanceof Obj && $v->has($k) ? $v->get($k) : Jsx::$U;
    }

    /**
     * The resource-server hook: ctx -> {enforced, ok?, reason?} over ctx.pcactn.attestation. Fail closed: an empty allowlist accepts
     * nothing; an absent measurement fails unless `required` is false (then not enforced); a pinned `expectedModelId` must match; a
     * present measurement outside the allowlist ALWAYS fails.
     */
    public static function createHarnessAttestationVerifier(mixed $config): \Closure
    {
        if ($config === null) {
            throw new \TypeError('config is null');
        }
        $ms = self::member($config, 'measurements');
        $allow = [];
        if (is_array($ms) && array_is_list($ms)) {
            foreach ($ms as $m) {
                if (is_string($m) && $m !== '') {
                    $allow[$m] = true;
                }
            }
        }
        $required = self::member($config, 'required') !== false;
        $em = self::member($config, 'expectedModelId');
        $expected = $em === true ? self::HARNESS_MODEL_ID : (is_string($em) && $em !== '' ? $em : null);
        return static function (mixed $ctx) use ($allow, $required, $expected): Obj {
            if ($allow === []) {
                return Obj::of(['enforced' => true, 'ok' => false, 'reason' => 'harness attestation configured with an empty measurement allowlist (fail closed)']);
            }
            $att = self::member(self::member($ctx, 'pcactn'), 'attestation');
            $m = self::member($att, 'measurement');
            $measurement = is_string($m) ? $m : '';
            if ($measurement === '') {
                if ($required) {
                    return Obj::of(['enforced' => true, 'ok' => false, 'reason' => 'harness attestation required but the PCActn carries no harness measurement (fail closed)']);
                }
                return Obj::of(['enforced' => false]);
            }
            if ($expected !== null) {
                $mid = self::member($att, 'model_id');
                if ($mid !== $expected) {
                    return Obj::of(['enforced' => true, 'ok' => false, 'reason' => sprintf("attestation.model_id '%s' is not the required harness identity '%s'", Jsx::str($mid), $expected)]);
                }
            }
            if (!isset($allow[$measurement])) {
                return Obj::of(['enforced' => true, 'ok' => false, 'reason' => 'harness measurement is not in the allowlisted set (unattested or unknown mediator)']);
            }
            return Obj::of(['enforced' => true, 'ok' => true]);
        };
    }

    private static function fin(mixed $x): bool
    {
        $f = Js::isNum($x) ? Js::num($x) : null;
        return $f !== null && is_finite($f);
    }

    private static function f(mixed $x): float
    {
        return (float)Js::num($x);
    }

    private static function jsRound(float $x): float
    {
        $f = floor($x);
        return $x - $f >= 0.5 ? $f + 1 : $f;
    }

    private static function toFixed(float $x, int $digits): string
    {
        if (!is_finite($x) || abs($x) >= 1e21) {
            return IntentWb::jsNumStr($x);
        }
        return sprintf('%.' . $digits . 'F', $x);
    }

    private static function refuse(string $reason, string $detail): Obj
    {
        return Obj::of(['ok' => false, 'reason' => $reason, 'detail' => $detail]);
    }

    private Obj $grant;
    /** @var list<mixed> */
    private array $chain;
    private KeyPair $signer;
    /** @var list<Obj> */
    private array $plan;
    /** @var array<string,Obj> */
    private array $planIndex = [];
    private Obj $committed;
    private string $audience;
    private mixed $policy;
    /** @var array<string,mixed> */
    private array $baseRisk;
    private \Closure $now;
    private ?int $ttlMs;
    private mixed $manifest;
    private \Closure $nonce;
    private ?Obj $attest;
    private Obj $budgetState;
    private int $counterValue = 0;

    /**
     * @param Obj $grant the principal-signed root capability; @param string $agentSecret the 32-byte Ed25519 seed of the leaf holder;
     * @param list<Obj> $plan the committed plan nodes (non-empty); @param Obj $budget {B, tau, asOf}; @param ?list<mixed> $chain default [grant];
     * @param mixed $policy a risk policy (default the standard one); @param ?Obj $baseRisk overrides of the base risk inputs;
     * @param ?\Closure $now epoch-ms clock; @param ?\Closure $nonce nonce supplier (default 16 random bytes as hex);
     * @param ?Obj $attestation {operator, epoch?} to stamp this harness's self-measurement into every emitted PCActn
     */
    public function __construct(Obj $grant, string $agentSecret, array $plan, string $audience, Obj $budget, ?array $chain = null, mixed $policy = null,
                                ?Obj $baseRisk = null, ?\Closure $now = null, ?int $ttlMs = null, mixed $measurementManifest = null, ?\Closure $nonce = null, ?Obj $attestation = null)
    {
        if ($audience === '') {
            throw new \InvalidArgumentException('Harness: `audience` is required (the resource-server / instance id PCActns are for)');
        }
        if (strlen($agentSecret) !== 32) {
            throw new \InvalidArgumentException('Harness: `agent_secret` must be a 32-byte Ed25519 secret key');
        }
        if (!array_is_list($plan) || $plan === []) {
            throw new \InvalidArgumentException('Harness: `plan` must be a non-empty array (an empty plan authorises nothing)');
        }
        $ids = [];
        foreach ($plan as $n) {
            if (!($n instanceof Obj) || !$n->has('id')) {
                throw new \TypeError('plan node without an id');
            }
            $ids[Js::stringify($n->get('id'))] = true;
        }
        if (count($ids) !== count($plan)) {
            throw new \InvalidArgumentException('Harness: plan node ids must be unique');
        }
        if (!self::fin($budget->get('B')) || self::f($budget->get('B')) < 0 || !self::fin($budget->get('tau')) || !self::fin($budget->get('asOf'))) {
            throw new \InvalidArgumentException('Harness: `budget` must have finite B >= 0, tau and asOf');
        }
        $this->grant = $grant;
        $this->chain = $chain ?? [$grant];
        $this->signer = new KeyPair($agentSecret);
        $this->plan = $plan;
        foreach ($plan as $n) {
            if (is_string($n->get('id'))) {
                $this->planIndex[$n->get('id')] = $n;
            }
        }
        // commit the principal-authorised plan ONCE; every emitted action carries an inclusion proof under this root
        $this->committed = Sign::commitPlan($plan);
        $this->audience = $audience;
        $this->policy = $policy ?? Sign::n(Sign::defaultRiskPolicy());
        $this->baseRisk = self::DEFAULT_BASE_RISK;
        if ($baseRisk !== null) {
            foreach ($baseRisk->keys() as $k) {
                $v = $baseRisk->get($k);
                $this->baseRisk[$k] = Js::isNum($v) ? self::f($v) : $v;
            }
        }
        $this->now = $now ?? static fn(): int => (int)(self::clock() * 1000);
        $this->ttlMs = $ttlMs;
        $this->manifest = $measurementManifest ?? self::ENFORCED_CHECKS;
        $this->nonce = $nonce ?? static fn(): string => bin2hex(random_bytes(16));
        $this->attest = $attestation;
        $this->budgetState = $budget;
    }

    /** The committed plan root the principal authorised. */
    public function planRoot(): string
    {
        return $this->committed->get('root');
    }

    /** The current (leaked-to-last-touch) trust budget. */
    public function budget(): Obj
    {
        return $this->budgetState;
    }

    /** Monotonic action counter: the number of PCActns this harness has emitted. */
    public function counter(): int
    {
        return $this->counterValue;
    }

    /** What a remote attestation of the MEDIATOR would cover, in place of the unmeasurable model weights. */
    public function harnessMeasurement(): string
    {
        return self::computeHarnessMeasurement(self::HARNESS_VERSION, $this->manifest, $this->policy);
    }

    /**
     * Ask the untrusted oracle for a candidate {verb, resource, params?, nodeId, inputs?} and, only if it survives the gate, emit a
     * signed PCActn: {ok: true, pcactn, inclusionProof, risk, budget}, or a refusal {ok: false, reason: out_of_plan | over_budget |
     * bad_candidate, detail, requiredT?, budget?}. An oracle that throws, or returns a malformed candidate, is a refusal.
     */
    public function step(callable $proposeAction): Obj
    {
        try {
            $candidate = $proposeAction();
        } catch (\Throwable $e) { // the oracle is a model call: any failure is a refusal
            return self::refuse('bad_candidate', 'oracle failed: ' . $e->getMessage());
        }
        // (0) the oracle is untrusted: validate the shape before use
        if (!($candidate instanceof Obj) || !is_string($candidate->get('nodeId')) || !is_string($candidate->get('verb')) || !is_string($candidate->get('resource'))) {
            return self::refuse('bad_candidate', 'oracle returned a malformed candidate');
        }
        // (1) PLAN INCLUSION: reject out-of-plan BEFORE signing
        $node = $this->planIndex[$candidate->get('nodeId')] ?? null;
        if ($node === null) {
            return self::refuse('out_of_plan', sprintf("node '%s' is not in the committed plan", $candidate->get('nodeId')));
        }
        if ($node->get('verb') !== $candidate->get('verb') || $node->get('resource') !== $candidate->get('resource')) {
            return self::refuse('out_of_plan', sprintf("action %s %s does not match committed node '%s' (%s %s)", $candidate->get('verb'), $candidate->get('resource'), $node->get('id'),
                Jsx::str($node->has('verb') ? $node->get('verb') : Jsx::$U), Jsx::str($node->has('resource') ? $node->get('resource') : Jsx::$U)));
        }
        $inclusionProof = $this->committed->get('proofs')->get($node->get('id'));

        // (2) TAINT FOLD: only a well-formed 'trusted' input is trusted; anything else counts as untrusted lineage
        if ($candidate->has('inputs') && !(is_array($candidate->get('inputs')) && array_is_list($candidate->get('inputs')))) {
            return self::refuse('bad_candidate', 'candidate.inputs is not an array');
        }
        $inputs = [];
        foreach ($candidate->has('inputs') ? $candidate->get('inputs') : [] as $i) {
            if ($i instanceof Obj && $i->get('provenance') === 'trusted' && is_string($i->get('ref'))) {
                $inputs[] = Obj::of(['ref' => $i->get('ref'), 'provenance' => 'trusted']);
            } else {
                $ref = $i instanceof Obj ? $i->get('ref') : null;
                $inputs[] = Obj::of(['ref' => is_string($ref) ? $ref : '', 'provenance' => 'untrusted']);
            }
        }
        $taint = 0;
        $trustedRefs = [];
        foreach ($inputs as $i) {
            if ($i->get('provenance') === 'untrusted') {
                $taint = 1;
            } else {
                $trustedRefs[] = $i->get('ref');
            }
        }
        $riskInputs = array_merge($this->baseRisk, ['taint' => $taint]);
        $p = Risk::policyOf($this->policy);
        if (!(self::member($this->policy, 'weights') instanceof Obj)) {
            throw new \TypeError('policy.weights is not an object');
        }
        // rounded to 6 d.p. so the reported r, the signed risk_claim.r and the budget cost agree and stay canonical
        $r = self::jsRound(Risk::score($riskInputs, $p['weights']) * 1e6) / 1e6;
        $rt = Risk::requiredThreshold($r, $p['theta1'], $p['theta2'], $node->get('reversibility_class') === 'irreversible');

        // (3) TRUST BUDGET: meter machine-only actions, leaking to now first
        $nowMs = ($this->now)();
        $b = ['B' => self::f($this->budgetState->get('B')), 'tau' => self::f($this->budgetState->get('tau')), 'asOf' => self::f($this->budgetState->get('asOf'))];
        $leaked = Risk::leak($b, (float)$nowMs, $p['lambda']);
        $c = Risk::cost($r, $p['kappa']);
        if ($rt['t'] < 3 && !(is_finite((float)$leaked['B']) && $leaked['B'] >= $c)) {
            // the budget cannot cover even a low-risk in-plan action: escalate to a human, debit nothing, produce no PCActn
            $this->budgetState = self::budgetObj($leaked);
            $out = self::refuse('over_budget', sprintf('budget %s < cost %s; step up to a human co-sign', self::toFixed($leaked['B'], 4), self::toFixed($c, 4)));
            $out->set('requiredT', 3);
            $out->set('budget', $this->budgetState);
            return $out;
        }

        // (4) SIGN
        $provenance = Obj::of(['causal_hash' => Pca::hashCanonical($inputs), 'taint_level' => $taint, 'trusted_refs' => $trustedRefs]);
        $extra = ['nonce' => ($this->nonce)(), 'provenance' => $provenance, 'risk_claim' => Obj::of(['r' => $r, 'inputs' => Obj::of($riskInputs)])];
        if ($this->attest !== null) {
            $ep = $this->attest->get('epoch');
            $extra['attestation'] = Obj::of(['quote_digest' => '', 'epoch' => $ep ?? 0, 'model_id' => self::HARNESS_MODEL_ID, 'measurement' => $this->harnessMeasurement(), 'operator' => $this->attest->get('operator')]);
        }
        try {
            $pcactn = Sign::buildPcactn($this->grant, $this->chain, $this->plan, $node->get('id'), $this->counterValue + 1, $this->signer, $this->audience,
                $candidate->get('params'), (int)$nowMs, null, $this->ttlMs ?? Sign::DEFAULT_TTL_MS, $extra);
        } catch (\Throwable $e) {
            // any build failure (e.g. params that do not match the node's committed params_digest, or cannot be serialised) is a
            // refusal, as in the reference: still never emits an out-of-plan action
            $msg = $e->getMessage();
            if (str_starts_with($msg, 'buildPcactn:')) {
                $msg = 'buildPCActn:' . substr($msg, strlen('buildPcactn:'));
            }
            return self::refuse('bad_candidate', 'could not build PCActn: ' . $msg);
        }

        // debit only a metered (machine-only, t < 3) action; commit the counter
        $this->budgetState = self::budgetObj($rt['t'] < 3 ? Risk::debit($leaked, $c) : $leaked);
        $this->counterValue++;
        return Obj::of(['ok' => true, 'pcactn' => $pcactn, 'inclusionProof' => $inclusionProof,
            'risk' => Obj::of(['r' => $r, 'inputs' => Obj::of($riskInputs), 'taint' => $taint, 't' => $rt['t']]), 'budget' => $this->budgetState]);
    }

    /** @param array{B:float,tau:float,asOf:?float} $b */
    private static function budgetObj(array $b): Obj
    {
        return Obj::of(['B' => $b['B'], 'tau' => $b['tau'], 'asOf' => $b['asOf']]);
    }

    /** @internal Test seam: when set, the default wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }
}
