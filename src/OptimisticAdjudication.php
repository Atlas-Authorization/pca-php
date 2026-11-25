<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Optimistic.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/AnalyzerJs.php';
require_once __DIR__ . '/Js.php';

/**
 * Fraud proofs and one-shot dispute adjudication for bonded optimistic claims: `verifyFraudProof` RE-RUNS the policy VM on the
 * server-held frozen open-time snapshot under the grant the verifier trusts, and `adjudicateDispute` re-adjudicates with an objective
 * oracle's authoritative value substituted for the single disputed input; `adjudicateDisputeGame` narrows a multi-step dispute to its
 * first contested step by refereed bisection. A slash is never authorized by a challenger's assertion. Every verdict function is
 * total (never throws) and FAILS CLOSED. Snapshots are decide inputs ({@see Decide}); claims, proofs and disputes are Obj.
 */
final class OptimisticAdjudication
{
    public const DEFAULT_R_MARGIN = 1e-9;
    private const INPUTS = ['reversibility_class', 'reversibility', 'blastRadius', 'semanticDistance'];

    private static function fin(mixed $x): ?float
    {
        $f = $x instanceof Num ? $x->float() : (is_int($x) ? (float)$x : (is_float($x) ? $x : null));
        return $f !== null && is_finite($f) ? $f : null;
    }

    private static function g(mixed $o, string $k): mixed
    {
        return $o instanceof Obj ? $o->get($k) : (is_array($o) && !array_is_list($o) ? ($o[$k] ?? null) : null);
    }

    /** A copy of `$o` with the given members set (an existing member keeps its position). @param array<string,mixed> $set */
    private static function with(mixed $o, array $set): Obj
    {
        $c = $o instanceof Obj ? $o->without() : new Obj();
        foreach ($set as $k => $v) {
            $c->set((string)$k, $v);
        }
        return $c;
    }

    private static function margin(mixed $m): float
    {
        $f = self::fin($m);
        return $f !== null ? max(0.0, $f) : self::DEFAULT_R_MARGIN;
    }

    private static function fixed3(float $x): string
    {
        return AnalyzerJs::toFixed($x, 3);
    }

    private static function numS(mixed $x): string
    {
        return IntentWb::jsStr($x instanceof Num ? $x->float() : $x);
    }

    /** @return array{releaseGuardianShare:bool,r:float,optimisticAllowed:bool} */
    private static function summarize(array $d): array
    {
        return ['releaseGuardianShare' => $d['releaseGuardianShare'], 'r' => (float)$d['r'], 'optimisticAllowed' => $d['requiredThreshold']['optimisticAllowed']];
    }

    /**
     * File a fraud proof against `$claim` for `$pcactn`, given the grant and the FROZEN open-time snapshot (the verdict is re-derived by
     * replaying the policy VM on it, never trusted from the caller). Returns the proof Obj if the claim was false, else null.
     * @param array{claim:mixed,pcactn:mixed,grant:mixed,openSnapshot?:mixed,decideInput?:mixed,rMargin?:mixed} $a
     */
    public static function fileFraudProof(array $a): ?Obj
    {
        $claim = $a['claim'];
        $input = $a['openSnapshot'] ?? $a['decideInput'] ?? null;
        if (!($input instanceof Obj)) {
            return null;
        }
        $actual = Decide::decide(self::with($input, ['grant' => $a['grant']]));
        if (self::g($claim, 'pcactn_digest') !== Pca::hashCanonical($a['pcactn'])) {
            return null;
        }
        $margin = self::margin($a['rMargin'] ?? null);
        $summary = self::summarize($actual);
        $evidence = $input->without('grant');
        $irr = self::g($claim, 'reversibility_class') === Optimistic::IRREVERSIBLE_CLASS
            || self::g(self::g($a['pcactn'], 'action'), 'reversibility_class') === Optimistic::IRREVERSIBLE_CLASS;
        $claimedR = self::g($claim, 'claimed_r');
        $kind = null;
        $reason = '';
        if ($irr) {
            [$kind, $reason] = ['irreversible', 'irreversible action took the optimistic path'];
        } elseif (!$summary['releaseGuardianShare']) {
            [$kind, $reason] = ['policy-denied', 'Policy VM denied the action: ' . (implode('; ', $actual['reasons']) ?: 'not compliant')];
        } elseif (!$summary['optimisticAllowed']) {
            [$kind, $reason] = ['optimistic-not-allowed', 'optimistic path not allowed at real r=' . self::fixed3($summary['r']) . ' (t=' . $actual['requiredThreshold']['t'] . ')'];
        } elseif ($summary['r'] > (float)self::fin($claimedR) + $margin) {
            [$kind, $reason] = ['risk-understated', 'claimed r=' . self::numS($claimedR) . ' but real r=' . self::fixed3($summary['r'])];
        }
        if ($kind === null) {
            return null;
        }
        return Obj::of(['pcactn_digest' => self::g($claim, 'pcactn_digest'), 'bond_ref' => self::g($claim, 'bond_ref'), 'claimed_r' => $claimedR,
            'decision' => Sign::n($summary), 'evidence' => $evidence, 'r_margin' => Sign::n($margin), 'kind' => $kind, 'reason' => $reason]);
    }

    /**
     * Independently verify a fraud proof against a bonded claim: `['fraudulent' => bool, 'slashBondRef' => ?, 'reason' => string]`.
     * @return array{fraudulent:bool,slashBondRef?:mixed,reason:string}
     */
    public static function verifyFraudProof(mixed $claim, mixed $proof, mixed $grant, mixed $openSnapshot): array
    {
        try {
            if (!($proof instanceof Obj)) {
                return ['fraudulent' => false, 'reason' => 'malformed fraud proof'];
            }
            if (!self::same($proof->get('pcactn_digest'), self::g($claim, 'pcactn_digest'))) {
                return ['fraudulent' => false, 'reason' => 'fraud proof targets a different PCActn than the claim'];
            }
            if (!self::same($proof->get('bond_ref'), self::g($claim, 'bond_ref'))) {
                return ['fraudulent' => false, 'reason' => 'fraud proof names a different bond than the claim'];
            }
            if (!($openSnapshot instanceof Obj)) {
                return ['fraudulent' => false, 'reason' => 'no frozen open-time snapshot supplied; cannot judge the claim'];
            }
            $rec = Decide::decide(self::with($openSnapshot, ['grant' => $grant]));
            $s = self::summarize($rec);
            $d = $proof->get('decision');
            $dr = self::fin(self::g($d, 'r'));
            if ($s['releaseGuardianShare'] !== self::g($d, 'releaseGuardianShare') || $s['optimisticAllowed'] !== self::g($d, 'optimisticAllowed')
                || $dr === null || !(abs($s['r'] - $dr) <= 1e-9)) {
                return ['fraudulent' => false, 'reason' => 'proof decision does not match an independent recomputation'];
            }
            $margin = self::margin($proof->get('r_margin'));
            $snapClass = self::g(self::g(self::g($openSnapshot, 'action'), 'action'), 'reversibility_class');
            $ref = self::g($claim, 'bond_ref');
            if (self::g($claim, 'reversibility_class') === Optimistic::IRREVERSIBLE_CLASS || $snapClass === Optimistic::IRREVERSIBLE_CLASS) {
                return ['fraudulent' => true, 'slashBondRef' => $ref, 'reason' => 'irreversible action is ineligible for the optimistic path'];
            }
            if (!$s['releaseGuardianShare']) {
                return ['fraudulent' => true, 'slashBondRef' => $ref, 'reason' => 'Policy VM denies the action: ' . (implode('; ', $rec['reasons']) ?: 'not compliant')];
            }
            if (!$s['optimisticAllowed']) {
                return ['fraudulent' => true, 'slashBondRef' => $ref, 'reason' => 'optimistic path not allowed at real r=' . self::fixed3($s['r'])];
            }
            $cr = self::g($claim, 'claimed_r');
            if ($s['r'] > (float)self::fin($cr) + $margin) {
                return ['fraudulent' => true, 'slashBondRef' => $ref, 'reason' => 'risk understated: claimed ' . self::numS($cr) . ', real ' . self::fixed3($s['r'])];
            }
            return ['fraudulent' => false, 'reason' => 'claim is compliant under independent recomputation; bond stands'];
        } catch (\Throwable $e) {
            return ['fraudulent' => false, 'reason' => 'fraud-proof verification error: ' . ($e->getMessage() ?: 'unknown')];
        }
    }

    /** JS strict equality of two JSON scalars (a missing member is undefined and equals only another missing one, here null). */
    private static function same(mixed $a, mixed $b): bool
    {
        $x = self::fin($a);
        $y = self::fin($b);
        if ($x !== null || $y !== null) {
            return $x !== null && $y !== null && $x === $y;
        }
        return $a === $b;
    }

    /** @param array{releaseGuardianShare:bool,r:float,optimisticAllowed:bool} $s */
    private static function fastPathAdmits(array $s, float $claimedR, float $margin): bool
    {
        return $s['releaseGuardianShare'] && $s['optimisticAllowed'] && $s['r'] <= $claimedR + $margin;
    }

    private static function snapshotValue(Obj $snap, string $input): mixed
    {
        if ($input === 'reversibility_class') {
            return self::g(self::g($snap, 'caveatContext'), 'reversibilityClass') ?? self::g(self::g(self::g($snap, 'action'), 'action'), 'reversibility_class');
        }
        return self::g(self::g($snap, 'risk'), $input);
    }

    /** The oracle's authoritative value substituted for the disputed input into a COPY of `$snap`; throws when the resolution lacks what it needs. */
    private static function substitute(Obj $snap, Obj $res): Obj
    {
        $input = $res->get('input');
        $cc = self::g($snap, 'caveatContext');
        if ($input === 'reversibility_class') {
            $cls = $res->get('class');
            if (!is_string($cls) || $cls === '') {
                throw new \RuntimeException('oracle reversibility_class resolution carries no class');
            }
            $action = self::with(self::g($snap, 'action'), []);
            $action->set('action', self::with(self::g($action, 'action'), ['reversibility_class' => $cls]));
            $out = self::with($snap, ['action' => $action]);
            if (self::g($cc, 'reversibilityClass') !== null) {
                $out->set('caveatContext', self::with($cc, ['reversibilityClass' => $cls]));
            }
            return $out;
        }
        if (self::fin($res->get('value')) === null) {
            throw new \RuntimeException('oracle ' . IntentWb::jsStr($input) . ' resolution carries no finite value');
        }
        $out = self::with($snap, ['risk' => self::with(self::g($snap, 'risk'), [(string)$input => $res->get('value')])]);
        if ($input === 'blastRadius' && self::g($cc, 'blastRadius') !== null) {
            $out->set('caveatContext', self::with($cc, ['blastRadius' => $res->get('value')]));
        }
        return $out;
    }

    private static function js(mixed $v): string
    {
        return $v === null ? 'undefined' : Js::stringify($v);
    }

    /** @return mixed the oracle's resolution as an Obj (or null) */
    private static function resolve(mixed $oracle, string $input, Obj $snap): mixed
    {
        $r = is_object($oracle) && method_exists($oracle, 'resolve') ? $oracle->resolve($input, $snap) : (is_callable($oracle) ? $oracle($input, $snap) : null);
        return $r === null ? null : Sign::n($r);
    }

    private static function hasOracle(mixed $oracle): bool
    {
        return $oracle !== null && ((is_object($oracle) && method_exists($oracle, 'resolve')) || is_callable($oracle));
    }

    /** @return array<string,mixed> */
    private static function indeterminate(string $input, string $reason, array $extra = []): array
    {
        $worst = ['releaseGuardianShare' => false, 'r' => 1, 'optimisticAllowed' => false];
        return array_merge(['outcome' => 'indeterminate', 'fraudulent' => false, 'slashCounterBond' => false, 'input' => $input, 'agentValue' => null,
            'oracleValue' => null, 'baseline' => $worst, 'adjudicated' => $worst, 'reason' => $reason], $extra);
    }

    /**
     * Adjudicate a contestable dispute: RE-RUN the policy VM on the frozen open-time snapshot with the ORACLE's authoritative value
     * substituted for the single disputed input (`$oracle->resolve($input, $snapshot)` returns `{input, value?, class?, valid, reason?}`).
     * `outcome`: `agent-fraud` (slash the agent's bond), `claim-upheld` (slash the challenger's counter-bond) or `indeterminate` (slash
     * neither). The challenger's asserted value is never read for the verdict.
     * @return array<string,mixed>
     */
    public static function adjudicateDispute(mixed $claim, mixed $dispute, mixed $grant, mixed $openSnapshot, mixed $oracle, mixed $rMargin = null): array
    {
        $margin = self::margin($rMargin);
        try {
            if (!($dispute instanceof Obj)) {
                return self::indeterminate('reversibility_class', 'malformed dispute');
            }
            $input = $dispute->get('input');
            if (!is_string($input) || !in_array($input, self::INPUTS, true)) {
                return self::indeterminate('reversibility_class', 'unknown disputed input: ' . ($input === null ? 'undefined' : IntentWb::jsStr($input)));
            }
            if (!self::same($dispute->get('pcactn_digest'), self::g($claim, 'pcactn_digest'))) {
                return self::indeterminate($input, 'dispute targets a different PCActn than the claim');
            }
            if (!self::same($dispute->get('bond_ref'), self::g($claim, 'bond_ref'))) {
                return self::indeterminate($input, 'dispute names a different bond than the claim');
            }
            if (!($openSnapshot instanceof Obj)) {
                return self::indeterminate($input, 'no frozen open-time snapshot supplied; cannot adjudicate');
            }
            if (!self::hasOracle($oracle)) {
                return self::indeterminate($input, 'no objective oracle supplied');
            }
            $snap = self::with($openSnapshot, ['grant' => $grant]);
            $baseline = self::summarize(Decide::decide($snap));
            $agentValue = self::snapshotValue($snap, $input);
            $res = self::resolve($oracle, $input, $snap);
            if (!($res instanceof Obj) || $res->get('input') !== $input || !Js::truthy($res->get('valid'))) {
                $why = $res instanceof Obj && Js::truthy($res->get('reason')) ? ': ' . IntentWb::jsStr($res->get('reason')) : '';
                return self::indeterminate($input, "objective oracle could not authoritatively resolve $input$why", ['baseline' => $baseline, 'agentValue' => $agentValue]);
            }
            $oracleValue = $res->get('class') ?? $res->get('value');
            $adj = self::summarize(Decide::decide(self::substitute($snap, $res)));
            $claimedR = (float)self::fin(self::g($claim, 'claimed_r'));
            if (!self::fastPathAdmits($adj, $claimedR, $margin)) {
                $why = !$adj['releaseGuardianShare'] ? 'the Policy VM denies the action'
                    : (!$adj['optimisticAllowed'] ? 'the optimistic path is not allowed (higher threshold) at r=' . self::fixed3($adj['r'])
                        : 'the real r=' . self::fixed3($adj['r']) . ' exceeds the claimed r=' . self::numS(self::g($claim, 'claimed_r')));
                return ['outcome' => 'agent-fraud', 'fraudulent' => true, 'slashBondRef' => self::g($claim, 'bond_ref'), 'slashCounterBond' => false, 'input' => $input,
                    'agentValue' => $agentValue, 'oracleValue' => $oracleValue, 'baseline' => $baseline, 'adjudicated' => $adj,
                    'reason' => "understated $input: agent relied on " . self::js($agentValue) . ', oracle says ' . self::js($oracleValue) . " \u{2014} $why"];
            }
            return ['outcome' => 'claim-upheld', 'fraudulent' => false, 'slashCounterBond' => true, 'input' => $input, 'agentValue' => $agentValue,
                'oracleValue' => $oracleValue, 'baseline' => $baseline, 'adjudicated' => $adj,
                'reason' => "the objective oracle upholds the agent's $input (" . self::js($oracleValue) . '); fast-path admission survives \u{2014} the dispute is frivolous'];
        } catch (\Throwable $e) {
            $in = $dispute instanceof Obj && is_string($dispute->get('input')) && in_array($dispute->get('input'), self::INPUTS, true) ? $dispute->get('input') : 'reversibility_class';
            return self::indeterminate($in, 'dispute adjudication error (fail closed): ' . ($e->getMessage() ?: 'unknown'));
        }
    }

    /** Exact equality of two step assertions `{value?, class?}` (NaN-safe, as Object.is). */
    private static function assertionEquals(mixed $a, mixed $b): bool
    {
        $av = self::g($a, 'value');
        $bv = self::g($b, 'value');
        $af = $av === null ? null : ($av instanceof Num ? $av->float() : $av);
        $bf = $bv === null ? null : ($bv instanceof Num ? $bv->float() : $bv);
        $valueEq = ($af === null && $bf === null) || ((is_int($af) || is_float($af)) && (is_int($bf) || is_float($bf)) && (float)$af === (float)$bf);
        return $valueEq && self::g($a, 'class') === self::g($b, 'class');
    }

    private static function applyAssertion(Obj $snap, string $input, mixed $a): Obj
    {
        return self::substitute($snap, Obj::of(['input' => $input, 'valid' => true, 'value' => self::g($a, 'value'), 'class' => self::g($a, 'class')]));
    }

    /** @return array{releaseGuardianShare:bool,r:float,optimisticAllowed:bool} */
    private static function stateAfter(Obj $snap, array $steps, array $assertions, int $j): array
    {
        $s = $snap;
        for ($i = 0; $i < $j; $i++) {
            if (!isset($steps[$i]) || !isset($assertions[$i])) {
                throw new \RuntimeException('dispute game trace is shorter than its step list');
            }
            $s = self::applyAssertion($s, $steps[$i], $assertions[$i]);
        }
        return self::summarize(Decide::decide($s));
    }

    /**
     * Adjudicate an INTERACTIVE multi-round dispute game by refereed bisection: narrow the two parties' committed traces to the ONE step
     * on which they first diverge, then resolve that step (only) with the objective oracle via {@see adjudicateDispute} against the
     * mutually agreed pre-state. Fails CLOSED to `indeterminate` on any malformed input, binding mismatch, missing snapshot or oracle, no
     * genuine admission dispute, non-convergence or error. `$game`: `{pcactn_digest, bond_ref, steps, defender, challenger}`.
     * @return array{verdict:array<string,mixed>,converged:bool,contestedStep:int,contestedInput?:string,transcript:list<array<string,mixed>>,rounds:int}
     */
    public static function adjudicateDisputeGame(mixed $claim, mixed $game, mixed $grant, mixed $openSnapshot, mixed $oracle, mixed $rMargin = null): array
    {
        $margin = self::margin($rMargin);
        $isInput = static fn(mixed $x): bool => is_string($x) && in_array($x, self::INPUTS, true);
        $steps0 = self::g($game, 'steps');
        $fail = static fn(string $reason, ?string $input = null): array => [
            'verdict' => self::indeterminate($input ?? (is_array($steps0) && isset($steps0[0]) && $isInput($steps0[0]) ? $steps0[0] : 'reversibility_class'), $reason),
            'converged' => false, 'contestedStep' => -1, 'transcript' => [], 'rounds' => 0,
        ];
        try {
            if (!($game instanceof Obj)) {
                return $fail('malformed dispute game');
            }
            if (!self::same($game->get('pcactn_digest'), self::g($claim, 'pcactn_digest'))) {
                return $fail('dispute game targets a different PCActn than the claim');
            }
            if (!self::same($game->get('bond_ref'), self::g($claim, 'bond_ref'))) {
                return $fail('dispute game names a different bond than the claim');
            }
            $steps = $game->get('steps');
            $def = $game->get('defender');
            $chal = $game->get('challenger');
            if (!is_array($steps) || !array_is_list($steps) || count($steps) < 1) {
                return $fail('dispute game has no steps');
            }
            foreach ($steps as $s) {
                if (!$isInput($s)) {
                    return $fail('unknown disputed input: ' . IntentWb::jsStr($s));
                }
            }
            $n = count($steps);
            if (!is_array($def) || !is_array($chal) || !array_is_list($def) || !array_is_list($chal) || count($def) !== $n || count($chal) !== $n) {
                return $fail('party assertions do not cover every step');
            }
            if (!($openSnapshot instanceof Obj)) {
                return $fail('no frozen open-time snapshot supplied; cannot adjudicate');
            }
            if (!self::hasOracle($oracle)) {
                return $fail('no objective oracle supplied');
            }
            $snap = self::with($openSnapshot, ['grant' => $grant]);
            $claimedR = (float)self::fin(self::g($claim, 'claimed_r'));
            // the genuine-dispute gate: the defender's full trace still admits the fast path and the challenger's does not
            if (!self::fastPathAdmits(self::stateAfter($snap, $steps, $def, $n), $claimedR, $margin)) {
                return $fail('defender does not defend the fast-path admission; nothing to adjudicate');
            }
            if (self::fastPathAdmits(self::stateAfter($snap, $steps, $chal, $n), $claimedR, $margin)) {
                return $fail('the parties do not disagree on admission; no genuine dispute to bisect');
            }
            $prefixAgrees = static function (int $m) use ($def, $chal): bool {
                for ($i = 0; $i < $m; $i++) {
                    if (!isset($def[$i]) || !isset($chal[$i]) || !self::assertionEquals($def[$i], $chal[$i])) {
                        return false;
                    }
                }
                return true;
            };
            if ($prefixAgrees($n)) {
                return $fail('the parties committed identical traces; no contested step to bisect');
            }
            $lo = 0;
            $hi = $n;
            $transcript = [];
            while ($hi - $lo > 1) {
                $mid = intdiv($lo + $hi, 2);
                $agreed = $prefixAgrees($mid);
                $transcript[] = ['lo' => $lo, 'hi' => $hi, 'mid' => $mid, 'agreedAtMid' => $agreed];
                if ($agreed) {
                    $lo = $mid;
                } else {
                    $hi = $mid;
                }
            }
            $contested = $steps[$lo];
            $pre = $snap;
            for ($i = 0; $i < $lo; $i++) {
                if (!self::assertionEquals($def[$i], $chal[$i])) {
                    return $fail('agreed prefix is not actually agreed; cannot reconstruct the pre-state', $contested);
                }
                $pre = self::applyAssertion($pre, $steps[$i], $def[$i]);
            }
            $cm = $chal[$lo];
            $verdict = self::adjudicateDispute($claim, Obj::of(['pcactn_digest' => self::g($claim, 'pcactn_digest'), 'bond_ref' => self::g($claim, 'bond_ref'),
                'input' => $contested, 'asserted_value' => self::g($cm, 'value'), 'asserted_class' => self::g($cm, 'class')]), $grant, $pre, $oracle, $margin);
            return ['verdict' => $verdict, 'converged' => true, 'contestedStep' => $lo, 'contestedInput' => $contested, 'transcript' => $transcript, 'rounds' => count($transcript)];
        } catch (\Throwable $e) {
            return $fail('dispute game adjudication error (fail closed): ' . ($e->getMessage() ?: 'unknown'));
        }
    }

    /** A deep, JSON-normalized copy of a decide input captured at claim open (store it with the claim). */
    public static function freezeOpenSnapshot(mixed $input): mixed
    {
        return Json::parseLax(Js::stringify($input));
    }
}
