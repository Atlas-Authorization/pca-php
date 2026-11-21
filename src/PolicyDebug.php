<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/BudgetTree.php';
require_once __DIR__ . '/Decide.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Risk.php';

/**
 * The replayable policy debugger: the pure decision core ({@see Decide::decide}) re-run and decomposed. `explainRisk` splits the risk score
 * into its six weighted terms, `explainDecision` explains a decide input (risk terms, required threshold, the budget trajectory),
 * `applyDelta` and `counterfactual` re-run the core under single hypothetical edits and name the ones that flip the outcome or move the
 * threshold, `auditPCActn` adds the verifier's per-check table. A decide input is the parsed-JSON object of {@see Decide::decide}.
 */
final class PolicyDebug
{
    private const WORST = ['semanticDistance' => 1.0, 'reversibility' => 0.0, 'blastRadius' => 1.0, 'taint' => 1.0, 'confidence' => 0.0, 'age' => 1.0];

    private static function clamp01(float $x): float
    {
        return $x < 0 ? 0.0 : ($x > 1 ? 1.0 : $x);
    }

    /** A finite number (no coercion) as a float, else null. */
    private static function fin(mixed $x): ?float
    {
        $f = Js::num($x);
        return $f !== null && is_finite($f) ? $f : null;
    }

    private static function wt(mixed $x): float
    {
        $f = self::fin($x);
        return $f !== null && $f > 0 ? $f : 0.0;
    }

    private static function term(string $name, mixed $weight, mixed $raw, bool $inverted): Obj
    {
        $f = self::fin($raw); // a non-finite input is the worst case for its term, never NaN and never the safe end of an inverted term
        $input = $f !== null ? self::clamp01($f) : self::WORST[$name];
        $effective = $inverted ? 1 - $input : $input;
        $w = self::wt($weight);
        return Obj::of(['term' => $name, 'weight' => $w, 'input' => $input, 'effective' => $effective, 'contribution' => $w * $effective, 'inverted' => $inverted]);
    }

    /** Decompose the risk score into its six additive terms; `rFloor` (default 0) is the signed caution floor. */
    public static function explainRisk(mixed $inputs, mixed $weights, mixed $rFloorIn = 0): Obj
    {
        $rf = self::fin($rFloorIn) ?? 0.0;
        $terms = [self::term('semanticDistance', Jsx::rd($weights, 'alpha'), Jsx::rd($inputs, 'semanticDistance'), false),
            self::term('reversibility', Jsx::get($weights, 'beta'), Jsx::get($inputs, 'reversibility'), true),
            self::term('blastRadius', Jsx::get($weights, 'gamma'), Jsx::get($inputs, 'blastRadius'), false),
            self::term('taint', Jsx::get($weights, 'delta'), Jsx::get($inputs, 'taint'), false),
            self::term('confidence', Jsx::get($weights, 'epsilon'), Jsx::get($inputs, 'confidence'), true),
            self::term('age', Jsx::get($weights, 'zeta'), Jsx::get($inputs, 'age'), false)];
        $raw = 0.0;
        foreach ($terms as $t) {
            $raw += $t->get('contribution');
        }
        $score = self::clamp01($raw);
        return Obj::of(['inputs' => $inputs, 'weights' => $weights, 'terms' => $terms, 'rawSum' => $raw, 'rScore' => $score,
            'rFloor' => self::clamp01($rf), 'r' => max($score, self::clamp01($rf))]);
    }

    /** The trust budget of an input as the typed float form. @return array{B:float,tau:float,asOf:?float} */
    private static function budgetOf(mixed $b): array
    {
        return ['B' => Jsx::toNum(Jsx::rd($b, 'B')), 'tau' => Jsx::toNum(Jsx::get($b, 'tau')),
            'asOf' => ($a = Jsx::get($b, 'asOf')) === null || $a instanceof Undef ? null : Jsx::toNum($a)];
    }

    private static function policyOf(mixed $grant): array
    {
        $env = Authorize::readEnvelope($grant);
        return Risk::policyOf($env !== null ? $env->get('risk_policy') : Sign::defaultRiskPolicy());
    }

    /**
     * Explain one decision: replay `decide`, then decompose it (risk terms, required threshold, the leak and debit trajectory).
     * Never throws on an input that `decide` itself accepts or refuses.
     */
    public static function explainDecision(mixed $input): Obj
    {
        $in = $input instanceof Obj ? $input : new Obj();
        $decision = Decide::decide($in);
        $env = Authorize::readEnvelope($in->get('grant'));
        $pol = Risk::policyOf($env !== null ? $env->get('risk_policy') : Sign::defaultRiskPolicy());
        if ($env !== null) {
            $now = Jsx::toNum($in->get('now'));
            $leaked = Risk::leak(self::budgetOf($in->get('budget')), $now, $pol['lambda']);
            $risk = Jsx::get($in, 'risk');
            $inputs = self::WORST;
            foreach (self::WORST as $k => $_) {
                $v = self::fin(Jsx::get($risk, $k));
                if ($v !== null) {
                    $inputs[$k] = $v;
                }
            }
            $plan = $in->get('plan');
            if (is_array($plan) && array_is_list($plan) && Jsx::get($risk, 'semanticDistance') instanceof Undef) {
                $nodeId = $in->get('nodeId');
                $goal = $in->get('goalNodeId') ?? ($plan === [] ? null : Jsx::get($plan[count($plan) - 1], 'id'));
                $inputs['semanticDistance'] = is_string($nodeId) && is_string($goal) ? Risk::planGeodesic($plan, $nodeId, $goal) : 1.0;
            }
            if (Jsx::get($risk, 'age') instanceof Undef) {
                $inputs['age'] = Risk::ageSinceTouch($leaked, $now, $in->has('ageHorizonMs') ? (self::fin($in->get('ageHorizonMs')) ?? NAN) : 3600000.0);
            }
            $rf = self::fin($in->get('rFloor'));
            $explained = self::explainRisk(Obj::of($inputs), Obj::of($pol['weights']), $rf === null ? 0.0 : min(1.0, max(0.0, $rf)));
        } else { // no envelope: the fail-closed denial (r = 1); keep the shape coherent
            $leaked = $in->get('budget');
            $explained = Obj::of(['inputs' => Obj::of(self::WORST), 'weights' => Obj::of(['alpha' => 0, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0]),
                'terms' => [], 'rawSum' => $decision['r'], 'rScore' => $decision['r'], 'rFloor' => 0, 'r' => $decision['r']]);
        }
        $kappa = $pol['kappa'];
        return Obj::of(['decision' => $decision, 'risk' => $explained, 'requiredThreshold' => $decision['requiredThreshold'], 't' => $decision['requiredThreshold']['t'],
            'autoAllow' => $decision['admit'], 'needStepUp' => $decision['needStepUp'], 'releaseGuardianShare' => $decision['releaseGuardianShare'],
            'budget' => Obj::of(['before' => $in->get('budget'), 'leaked' => $leaked, 'after' => $decision['budget'], 'cost' => Risk::cost((float)$decision['r'], $kappa),
                'safetyBound' => $kappa > 0 ? max(0.0, $pol['bMax']) / $kappa : 0]),
            'reasons' => $decision['reasons'], 'envelopeValid' => $env !== null]);
    }

    /** The hypothetical decide input a delta `{label?, risk?, budget?, rFloor?, now?, caveatContext?, humanCosign?}` denotes; `$input` is not changed. */
    public static function applyDelta(mixed $input, mixed $d): Obj
    {
        $in = Jsx::spread($input);
        $dn = Jsx::get($d, 'now');
        $now = $dn === null || $dn instanceof Undef ? $in->get('now') : $dn;
        $budget = Jsx::spread(Jsx::get($input, 'budget'));
        foreach (Jsx::keys(Jsx::get($d, 'budget')) as $k) {
            $budget->set($k, Jsx::get(Jsx::get($d, 'budget'), $k));
        }
        $hc = Jsx::get($d, 'humanCosign');
        if (Jsx::truthy($hc)) {
            $pol = self::policyOf(Jsx::get($input, 'grant'));
            if ($hc instanceof Obj && $hc->get('full') === true) {
                $b = BudgetTree::rechargeFull($pol['bMax'], $now);
            } else {
                $r = Risk::recharge(self::budgetOf($budget), $pol['rho'], $pol['bMax'], Jsx::toNum($now));
                $b = Obj::of($r);
            }
            $budget = $b;
        }
        $in->set('now', $now);
        $in->set('budget', $budget);
        $in->set('risk', self::merge(Jsx::get($input, 'risk'), Jsx::get($d, 'risk')));
        $in->set('caveatContext', self::merge(Jsx::get($input, 'caveatContext'), Jsx::get($d, 'caveatContext')));
        $rf = Jsx::get($d, 'rFloor');
        if (!($rf instanceof Undef)) {
            $in->set('rFloor', $rf);
        }
        return $in;
    }

    /** `{...a, ...b}`. */
    private static function merge(mixed $a, mixed $b): Obj
    {
        $o = Jsx::spread($a);
        foreach (Jsx::keys($b) as $k) {
            $o->set($k, Jsx::get($b, $k));
        }
        return $o;
    }

    private static function describe(mixed $d): string
    {
        $label = Jsx::get($d, 'label');
        if (Jsx::truthy($label)) {
            return Jsx::str($label);
        }
        $parts = [];
        $hc = Jsx::get($d, 'humanCosign');
        if (Jsx::truthy($hc)) {
            $parts[] = $hc instanceof Obj && Jsx::truthy($hc->get('full')) ? 'human re-confirms goal (B←Bmax)' : 'human co-signs (B+ρ)';
        }
        foreach (['risk' => '', 'budget' => 'budget.'] as $key => $prefix) {
            $m = Jsx::get($d, $key);
            if (Jsx::truthy($m)) {
                foreach (Jsx::keys($m) as $k) {
                    $parts[] = $prefix . $k . '=' . Jsx::str(Jsx::get($m, $k));
                }
            }
        }
        $rf = Jsx::get($d, 'rFloor');
        if (!($rf instanceof Undef)) {
            $parts[] = 'caution=' . Jsx::str($rf);
        }
        $n = Jsx::get($d, 'now');
        if (!($n instanceof Undef)) {
            $parts[] = 'now=' . Jsx::str($n);
        }
        $cc = Jsx::get($d, 'caveatContext');
        if (Jsx::truthy($cc)) {
            foreach (Jsx::keys($cc) as $k) {
                $parts[] = 'ctx.' . $k . '=' . Js::stringify(Jsx::get($cc, $k));
            }
        }
        return $parts === [] ? 'no-op' : implode(', ', $parts);
    }

    /** Replay the decision under each single change and report which flips allow and which moves the threshold. @param list<mixed> $deltas */
    public static function counterfactual(mixed $input, array $deltas): Obj
    {
        $base = self::explainDecision($input);
        $outcomes = [];
        foreach ($deltas as $d) {
            $ex = self::explainDecision(self::applyDelta($input, $d));
            $dir = $ex->get('t') > $base->get('t') ? 'raised' : ($ex->get('t') < $base->get('t') ? 'lowered' : 'same');
            $outcomes[] = Obj::of(['label' => self::describe($d), 'delta' => $d, 'explanation' => $ex,
                'flipsAllow' => $ex->get('autoAllow') !== $base->get('autoAllow'), 'allow' => $ex->get('autoAllow'),
                'thresholdDirection' => $dir, 'changesThreshold' => $dir !== 'same', 't' => $ex->get('t'),
                'rDelta' => (float)$ex->get('risk')->get('r') - (float)$base->get('risk')->get('r')]);
        }
        $labels = static fn(string $flag): array => array_values(array_map(static fn(Obj $o) => $o->get('label'), array_filter($outcomes, static fn(Obj $o): bool => $o->get($flag) === true)));
        return Obj::of(['baseline' => $base, 'outcomes' => $outcomes, 'flipping' => $labels('flipsAllow'), 'thresholdChanging' => $labels('changesThreshold')]);
    }

    private const CHECKS = ['wire', 'version', 'audience', 'validity', 'cap_chain', 'grant_ref_bound', 'plan_inclusion', 'plan_root_authorized',
        'leaf_signature', 'counter_format', 'taint_gate', 'attestation', 'threshold', 'revocation'];

    /**
     * The verifier's per-check table (`pass`, `fail`, `not-enforced`) for a PCActn plus the decision explanation for `$input`.
     * `$audience`: a string, null = the audience was not given, {@see Audience::Any} = the explicit opt-out.
     * @return array{verify:array<string,mixed>,explanation:Obj}
     */
    public static function auditPCActn(mixed $p, mixed $input, mixed $grant, int $nowEpoch, string|Audience|null $audience = null, bool $insecureSkipPlanRootCheck = false): array
    {
        $v = Pca::verifyPcactnCore($p, $grant, $nowEpoch, $audience, null, null, null, null, null, $insecureSkipPlanRootCheck);
        $native = $v['checks'];
        if (($native['wire'] ?? false) !== true) {
            $checks = Obj::of(['wire' => 'fail']);
        } else {
            $native['cap_chain'] = $native['chain'] ?? false;
            $checks = new Obj();
            foreach (self::CHECKS as $name) {
                $checks->set($name, in_array($name, $v['not_enforced'] ?? [], true) || !array_key_exists($name, $native) ? 'not-enforced' : ($native[$name] === true ? 'pass' : 'fail'));
            }
        }
        $verify = Obj::of(['allow' => $v['allow'], 'checks' => $checks]);
        if (!$v['allow'] && ($v['reason'] ?? '') !== '') {
            $verify->set('reason', VerifyVerdict::text($v['reason']));
        }
        return ['verify' => $verify, 'explanation' => self::explainDecision($input)];
    }
}
