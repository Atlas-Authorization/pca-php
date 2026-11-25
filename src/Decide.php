<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * The Policy VM decision `decide(input)`: the release decision of one party's own policy (envelope predicates, caveats over the
 * delegation chain, risk score, trust budget, threshold band). Total: any internal error is a fail-closed denial. Input is a parsed
 * JSON object (an Obj): `grant`, `chain?`, `action`, `plan?`, `risk`, `budget`, `now`, `nodeId?`, `goalNodeId?`, `caveatContext?`,
 * `rFloor?`, `ageHorizonMs?`, `chainVerified?`, `pqPins?`, `trustedRoot?`, `k1?`. The result is an array with `releaseGuardianShare`,
 * `requiredThreshold`, `r`, `admit`, `needStepUp`, `reasons`, `budget` (and `k1Bound` when the caveat language ran).
 */
final class Decide
{
    private static function fin(mixed $x): ?float
    {
        $f = match (true) {
            $x instanceof Num => $x->float(),
            is_int($x) => (float) $x,
            is_float($x) => $x,
            default => null,
        };
        return $f !== null && is_finite($f) ? $f : null;
    }

    private static function obj(mixed $o): Obj
    {
        return $o instanceof Obj ? $o : new Obj();
    }

    private static function denied(string $reason, mixed $budget): array
    {
        return ['releaseGuardianShare' => false, 'requiredThreshold' => ['t' => 3, 'proof' => 'strong', 'optimisticAllowed' => false], 'r' => 1, 'admit' => false,
            'needStepUp' => true, 'reasons' => [$reason], 'budget' => $budget];
    }

    /** Decides $input; never throws. */
    public static function decide(mixed $input): array
    {
        $in = self::obj($input);
        $fallback = $in->get('budget') ?? ['B' => 0, 'tau' => 0, 'asOf' => 0];
        try {
            return SafeRegex::withBudget(static fn(): array => self::inner($in, $fallback));
        } catch (\Throwable $e) {
            return self::denied('policy evaluation error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage()), $fallback);
        }
    }

    private static function noK1(mixed $cs): array
    {
        return is_array($cs) && array_is_list($cs) ? array_values(array_filter($cs, static fn(mixed $c): bool => !CaveatLang::isK1Caveat($c))) : [];
    }

    private static function inner(Obj $in, mixed $fallbackBudget): array
    {
        $budgetIn = $in->get('budget');
        $grantO = $in->get('grant');
        $env = Authorize::readEnvelope($grantO);
        if ($env === null) {
            return self::denied('grant carries no valid envelope', $budgetIn);
        }
        $grant = self::obj($grantO);
        $now = self::fin($in->get('now'));
        if ($now === null) {
            return self::denied('invalid decision time', $budgetIn);
        }
        $hasChain = $in->has('chain');
        $chainO = $in->get('chain');

        // an unverified capability chain is DENIED here: unless the caller vouches it was verified, decide re-verifies it
        if ($in->get('chainVerified') !== true) {
            $toVerify = is_array($chainO) && array_is_list($chainO) && $chainO !== [] ? $chainO : [$grant];
            $issuer = $grant->get('issuer');
            [$why, $ok] = Pca::verifyChain($toVerify, is_string($issuer) ? $issuer : null, is_string($issuer), null,
                $in->get('pqPins') instanceof Obj ? $in->get('pqPins') : null, $in->get('trustedRoot') instanceof Obj ? $in->get('trustedRoot') : null);
            if (!$ok) {
                return self::denied('capability chain unverified: ' . $why, $budgetIn);
            }
        }

        $pol = Risk::policyOf($env->get('risk_policy'));
        $reasons = [];
        $actionCtx = self::obj($in->get('action'));
        $inner = self::obj($actionCtx->get('action'));

        // 1. semantic predicates (default deny)
        $pr = Predicates::evaluatePredicates($env->get('predicates'), $actionCtx);
        $prOk = ($pr['allowed'] ?? false) === true;
        if (!$prOk) {
            $reasons[] = $pr['reason'] ?? 'action not permitted by envelope predicates';
        }

        $nodeId = $in->get('nodeId');
        $plan = is_array($in->get('plan')) && array_is_list($in->get('plan')) ? $in->get('plan') : null;
        $risk = self::obj($in->get('risk'));

        // the class the action is bound to: its own, else the plan node it names, else unknown (fail closed)
        $revClass = $inner->get('reversibility_class');
        if ($revClass === null && is_string($nodeId) && $plan !== null) {
            foreach ($plan as $n) {
                if ($n instanceof Obj && $n->get('id') === $nodeId) {
                    $revClass = $n->get('reversibility_class');
                    break;
                }
            }
        }

        // 2. envelope caveats
        $nowV = $now === floor($now) && abs($now) < 9.0e15 ? (int) $now : $now;
        $cctx = Obj::of(['now' => $nowV, 'action' => $inner]);
        foreach ([['blast_radius', $risk->get('blastRadius')], ['reversibility_class', $revClass]] as [$k, $v]) {
            if ($v !== null) {
                $cctx->set($k, $v);
            }
        }
        $over = self::obj($in->get('caveatContext'));
        foreach (['blastRadius' => 'blast_radius', 'reversibilityClass' => 'reversibility_class', 'delegationDepth' => 'delegation_depth', 'recentActionTimes' => 'recent_action_times'] as $camel => $snake) {
            if ($over->has($camel)) {
                $cctx->set($snake, $over->get($camel));
            }
        }
        $toolCall = ['tool' => is_string($inner->get('verb')) ? $inner->get('verb') : '', 'args' => $inner->get('params') instanceof Obj ? $inner->get('params') : new Obj()];
        if (is_string($actionCtx->get('toolBinding'))) {
            $toolCall['toolSignatureDigest'] = $actionCtx->get('toolBinding');
        }

        $chainOk = true;
        $extra = [];
        $gcs = is_array($grant->get('caveats')) && array_is_list($grant->get('caveats')) ? $grant->get('caveats') : [];
        $chain = is_array($chainO) && array_is_list($chainO) ? $chainO : null;
        if ($hasChain) {
            if ($chain === null || $chain === []) {
                $chainOk = false;
                $reasons[] = 'delegation chain is empty or malformed';
            } else {
                $cctx->set('delegation_depth', count($chain) - 1);
                $lcs = self::obj($chain[count($chain) - 1])->get('caveats');
                $extra = is_array($lcs) && array_is_list($lcs) ? array_slice($lcs, min(count($gcs), count($lcs))) : [];
            }
        }
        $ecv = Authorize::evaluateAgentCaveats($env->get('caveats'), $cctx, $actionCtx, $toolCall);
        if (!$ecv['ok']) {
            $reasons[] = 'caveat(s) not satisfied: ' . implode(', ', $ecv['failed']);
        }

        // root caveats outside the envelope are signed authority too; the caveat-language (K1) types are evaluated over the whole chain
        $leafHop = $chain !== null && $chain !== [] ? self::obj($chain[count($chain) - 1]) : $grant;
        $leafCaveats = $leafHop->get('caveats');
        $k1In = $in->get('k1');
        $useK1 = $k1In instanceof Obj && $k1In->has('narrow');
        if (is_array($leafCaveats) && array_is_list($leafCaveats)) {
            foreach ($leafCaveats as $c) {
                if (CaveatLang::isK1Caveat($c)) {
                    $useK1 = true;
                }
            }
        }
        $k1 = null;
        if ($useK1) {
            $k1 = CaveatLang::evaluateK1($grant, $chainO, $k1In instanceof Obj ? $k1In : null, Obj::of(['now' => (int) $now, 'action' => $inner]));
        }
        $rcv = Authorize::evaluateAgentCaveats(self::noK1(Authorize::rootCaveats($grant)), $cctx, $actionCtx, $toolCall);
        if (!$rcv['ok']) {
            $reasons[] = 'root caveat(s) not satisfied: ' . implode(', ', $rcv['failed']);
        }
        $cvOk = $ecv['ok'] && $rcv['ok'];
        $dl = self::noK1($extra);
        if ($k1 !== null) {
            $dl = array_merge($dl, $k1['plain']);
        }
        $dcv = Authorize::evaluateAgentCaveats($dl, $cctx, $actionCtx, $toolCall);
        $dcvOk = $dcv['ok'];
        if (!$dcv['ok']) {
            $reasons[] = 'delegated caveat(s) not satisfied: ' . implode(', ', $dcv['failed']);
        }
        if ($k1 !== null && !$k1['ok']) {
            $dcvOk = false;
            foreach ($k1['reasons'] as $i => $why) {
                $reasons[] = 'caveat language: ' . $k1['failed'][$i] . ': ' . $why;
            }
        }

        // 3. risk
        // the reference reads the budget by JS arithmetic and never throws on its shape: a null B is 0, a missing / non-numeric B or a
        // budget that is not an object has nothing to spend (0), a missing / non-numeric tau is NaN (age = 1), a non-numeric asOf is absent
        $b = $budgetIn instanceof Obj ? $budgetIn : null;
        $bB = $b !== null && $b->has('B') && $b->get('B') === null ? 0.0 : (self::fin($b?->get('B')) ?? 0.0);
        $bTau = Js::num($b?->get('tau')) ?? NAN; // an infinite stamp is carried through unchanged (the leak depletes the budget on it)
        $hasAsOf = $b !== null && $b->has('asOf');
        $bAsOf = $b?->get('asOf') === null ? null : self::fin($b->get('asOf'));
        $leaked = Risk::leak(['B' => $bB, 'tau' => $bTau, 'asOf' => $bAsOf], $now, $pol['lambda']);
        $inputs = Risk::inputsOf([]);
        $missing = [];
        foreach (Risk::INPUTS as $i => $key) {
            $v = self::fin($risk->get($key));
            if ($v !== null) {
                $inputs[$key] = $v;
            } elseif ($i !== 5) {
                $missing[] = $key;
            }
        }
        if ($plan !== null && !$risk->has('semanticDistance')) { // the reference tests for `undefined`: an explicit null counts as supplied
            $goal = $in->get('goalNodeId') ?? ($plan === [] ? null : self::obj($plan[count($plan) - 1])->get('id'));
            $inputs['semanticDistance'] = is_string($nodeId) && is_string($goal) ? Risk::planGeodesic($plan, $nodeId, $goal) : 1.0;
            $missing = array_values(array_filter($missing, static fn(string $k): bool => $k !== 'semanticDistance'));
        }
        if (!$risk->has('age')) {
            // a default parameter applies only to undefined: any other non-number horizon (null, a string) is not > 0, so the age is the worst case
            $horizon = $in->has('ageHorizonMs') ? (Js::num($in->get('ageHorizonMs')) ?? NAN) : 3600000.0; // an infinite horizon is a number: no age at all
            $inputs['age'] = Risk::ageSinceTouch($leaked, $now, $horizon);
        }
        if ($missing !== []) {
            $reasons[] = 'risk input(s) missing, assumed worst case: ' . implode(', ', $missing);
        }
        $rf = self::fin($in->get('rFloor'));
        $rFloor = $rf === null ? 0.0 : min(1.0, max(0.0, $rf));
        $r = max(Risk::score($inputs, $pol['weights']), $rFloor);

        $irreversible = !Risk::fastPathClass($cctx->get('reversibility_class'));
        $rt = Risk::requiredThreshold($r, $pol['theta1'], $pol['theta2'], $irreversible);

        // 4. budget admission
        $adm = Risk::admission(Risk::requiredThreshold($r, $pol['theta1'], $pol['theta2'], false)['t'], is_finite((float)$leaked['B']) && $leaked['B'] >= Risk::cost($r, $pol['kappa']));
        if ($adm['needStepUp']) {
            $reasons[] = $rt['t'] < 3 && $adm['t'] === 3 ? 'trust budget depleted: human recharge required'
                : 'risk ' . sprintf('%.3f', $r) . ' exceeds auto threshold: step-up to t=' . $adm['t'];
        }

        // 5. guardian release: policy AND caveats AND a well-formed chain; the human / step-up path stays available otherwise
        $dec = Risk::decideCore($prOk, $cvOk, $dcvOk, $chainOk, $rt, $adm);
        $out = $dec['debit'] ? Risk::debit($leaked, Risk::cost($r, $pol['kappa'])) : $leaked;
        $res = ['releaseGuardianShare' => $dec['release'], 'requiredThreshold' => ['t' => $dec['threshold']['t'], 'proof' => $dec['threshold']['proof'],
            'optimisticAllowed' => $dec['threshold']['optimisticAllowed']], 'r' => $r, 'admit' => $dec['admit'], 'needStepUp' => $dec['needStepUp'],
            'reasons' => $reasons, 'budget' => ['B' => $out['B'], 'tau' => $out['tau'], 'asOf' => $out['asOf'] ?? null]];
        if ($b === null || !$b->has('tau')) {
            unset($res['budget']['tau']); // a budget without a stamp carries none out (undefined is not part of the reference's JSON)
        }
        if (!$hasAsOf && ($out['asOf'] ?? null) === null) {
            unset($res['budget']['asOf']); // an undefined stamp is not part of the result, as it is not in the reference's JSON
        }
        if ($k1 !== null) {
            $res['k1Bound'] = array_map(static fn(array $x): array => ['caveat' => $x['caveat'], 'hop' => $x['hop'], 'capHash' => $x['cap_hash']], $k1['bound']);
        }
        return $res;
    }

    /**
     * Assembles the decide input from a PCActn plus the verifier's own context (`grant` REQUIRED: the grant from the verifier's own store,
     * never the presented chain root; it is also the chain's trustedRoot), so caller and verifier derive action / nodeId / chain identically.
     * The action context is the PCActn's own action with `params` from the context (the caller must have checked them against params_digest).
     * $ctx is an Obj or an assoc array: grant, params?, risk, budget, now, chain?, plan?, pqPins?, goalNodeId?, subject?, env?, caveatContext?,
     * ageHorizonMs?. Throws \InvalidArgumentException when there is no grant.
     */
    /**
     * THE reversibility class of an action, shared by every path that evaluates `reversibility_max` caveats: the action's own class, else
     * the class of the plan node the action is bound to (`$nodeId`, the SIGNED `pcactn.plan.node_id`), else null, which no `reversibility_max`
     * caveat accepts and which is not fast-path eligible (fail closed). `$action` is the inner action Obj; `$plan` a list of plan nodes.
     */
    public static function resolveReversibilityClass(mixed $action, mixed $plan, mixed $nodeId): mixed
    {
        $own = $action instanceof Obj ? $action->get('reversibility_class') : null;
        if ($own !== null) {
            return $own;
        }
        if (!is_string($nodeId) || !is_array($plan)) {
            return null; // no node named: never a guess
        }
        foreach ($plan as $n) {
            if ($n instanceof Obj && $n->get('id') === $nodeId) {
                return $n->get('reversibility_class');
            }
        }
        return null;
    }

    public static function deriveDecideInput(mixed $p, mixed $ctx): Obj
    {
        if ($ctx === null) {
            throw new \TypeError('deriveDecideInput: no context');
        }
        $grant = Js::opt($ctx, 'grant');
        if (!($grant instanceof Obj) && !is_array($grant)) { // an array is an object to the reference too; decide then denies it
            throw new DecideInputGrantRequired();
        }
        if ($p === null) {
            throw new \TypeError('deriveDecideInput: no PCActn');
        }
        // a member a parsed JSON object carries with value null is present (the reference keeps it); a PHP array option that is null is absent
        $has = static fn(mixed $o, string $k): bool => $o instanceof Obj ? $o->has($k) : Js::opt($o, $k) !== null;
        $copy = static function (Obj $out, string $as, mixed $o, string $k) use ($has): void {
            if ($has($o, $k)) {
                $out->set($as, Js::opt($o, $k));
            }
        };
        $act = Js::opt($p, 'action');
        $inner = new Obj();
        $copy($inner, 'verb', $act, 'verb');
        $copy($inner, 'resource', $act, 'resource');
        $inner->set('params', Js::opt($ctx, 'params') ?? new Obj());
        $copy($inner, 'reversibility_class', $act, 'reversibility_class');
        $action = Obj::of(['action' => $inner]);
        foreach (['subject', 'env'] as $k) {
            $v = Js::opt($ctx, $k);
            if ($v instanceof Obj || is_array($v) || Js::truthy($v)) { // an empty object or array counts, as in the reference
                $action->set($k, $v);
            }
        }
        $out = Obj::of(['grant' => $grant, 'trustedRoot' => $grant]);
        $copy($out, 'pqPins', $ctx, 'pqPins');
        $copy($out, 'chain', Js::opt($ctx, 'chain') !== null ? $ctx : $p, Js::opt($ctx, 'chain') !== null ? 'chain' : 'cap_chain');
        $out->set('action', $action);
        $copy($out, 'plan', $ctx, 'plan');
        $copy($out, 'nodeId', Js::opt($p, 'plan'), 'node_id');
        foreach (['goalNodeId', 'risk', 'budget', 'now', 'caveatContext', 'ageHorizonMs'] as $k) {
            $copy($out, $k, $ctx, $k);
        }
        return $out;
    }
}

/** `deriveDecideInput` was called without the verifier's own stored grant (`$errorCode` = `grant_required`). It is never defaulted from the artifact. */
final class DecideInputGrantRequired extends \InvalidArgumentException
{
    public string $errorCode = 'grant_required';

    public function __construct()
    {
        parent::__construct('deriveDecideInput: ctx.grant (the grant from your own store) is required; the presented chain root is never used as the grant');
    }
}
