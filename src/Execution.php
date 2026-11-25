<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Authorize.php';

/**
 * `authorizeExecution`: the full-policy check for one local execution (an agent framework tool call, a gateway request), for verifiers that have the
 * PCActn in hand rather than an HTTP request. {@see Pca::verifyPcactnCore} alone checks that a proof is genuine; it does not read the grant's limits, so a
 * validly signed $400 payment under a $100 grant passes it. This runs, in order: (1) the configuration (the audience, a grant source, the replay / budget
 * store and the revocation check are REQUIRED: a missing one denies every call), (2) the operation binding (the signed verb, and resource when the caller
 * names one, must be the operation about to execute; checked before any state is read or written) and (3) the full server verifier through
 * {@see Authorize::authorize}, the one pipeline: the grant from the caller's store, the params against the signed digest, the grant's predicates, limits and
 * caveats, revocation, the replay counter and the trust budget, with risk priced from server-side inputs.
 */
final class Execution
{
    /** The checks a full-policy decision must PASS: the stateful profile plus the params digest and the policy itself (`authorize` adds `operation`). */
    public const EXECUTION_REQUIRED_CHECKS = ['counter_format', 'replay', 'revocation', 'plan_root_authorized', 'audience', 'validity', 'grant_ref_bound', 'params_digest', 'policy'];

    /** The options this port cannot run (refused, never silently ignored). */
    private const UNSUPPORTED = ['multiInstance', 'replayScope', 'claimRetries'];

    /** The required components `$opts` lacks (empty when the configuration is complete). @param array<string,mixed>|null $opts @return list<string> */
    public static function missingExecutionComponents(?array $opts): array
    {
        return Authorize::missingExecutionComponents($opts);
    }

    /**
     * The server's risk inputs for a money-moving operation: `blastRadius = amount / kappa` from the verified `params[amountField]` and the grant's own risk
     * policy. null when there is no numeric amount (the verifier then prices the missing inputs at the worst case).
     * @return array{blastRadius:float}|null
     */
    public static function amountRisk(mixed $grant, mixed $params, string $amountField = 'amount'): ?array
    {
        $amount = Js::num(Js::opt($params, $amountField));
        $rp = Authorize::readEnvelope($grant)?->get('risk_policy');
        $kappa = Js::num($rp instanceof Obj ? $rp->get('kappa') : null);
        if ($amount === null || !is_finite($amount) || $kappa === null || !is_finite($kappa) || !($kappa > 0)) {
            return null;
        }
        return ['blastRadius' => min(1.0, max(0.0, $amount / $kappa))];
    }

    /** The reason of the first failing check (the verifier also lists context such as worst-case risk inputs); a failing `operation` is ranked last. */
    private static function decisiveReason(array $checks, array $reasons): string
    {
        $noise = static fn(string $x): bool => preg_match('/risk input\(s\) missing/', $x) === 1;
        $names = array_keys($checks);
        usort($names, static fn(string $a, string $b): int => (int)($a === 'operation') <=> (int)($b === 'operation'));
        foreach ($names as $n) {
            if ($checks[$n] !== 'fail') {
                continue;
            }
            foreach ($reasons as $x) {
                if (str_starts_with($x, "$n:") && !$noise($x)) {
                    return $x;
                }
            }
        }
        foreach ($reasons as $x) {
            if (!$noise($x)) {
                return $x;
            }
        }
        return $reasons[0] ?? 'denied';
    }

    /**
     * Authorize one execution completely. `$operation`: `['verb' => string, 'resource'? => string, 'params' => Obj, 'provenance'? => mixed]`. `$opts`: audience,
     * grant | resolveGrant `(string $grantRef, Obj $pcactn): ?Obj`, state (the replay / budget store, with `claim`), isRevoked `(Obj $grant, Obj $pcactn): bool`,
     * isPlanAuthorized? `(string $grantRef, string $planRoot): bool`, risk? `(Obj $grant, Obj $params, Obj $pcactn): ?array`, hooks? (attestation / threshold /
     * zk), require?, k1?, usesStore?, allowedSuites? (default ['ed25519']), pqPins?, now? `(): int`, requireAssurance?, enforce? (freshness), provenance?
     * (mediators, actions, observed). Never throws.
     * @param array<string,mixed> $operation
     * @param array<string,mixed> $opts
     * @return array<string,mixed> `['allow' => true, 'pcactn', 'grant', 'verdict', 'assurance']` or `['allow' => false, 'kind' => config|binding|authn|policy|replay|revoked,
     *                             'status' => 401|403, 'reason', 'checks'?, 'verdict'?, 'assurance'?]`
     */
    public static function authorizeExecution(mixed $pcactn, array $operation, array $opts): array
    {
        $missing = self::missingExecutionComponents($opts);
        if ($missing !== []) {
            return ['allow' => false, 'kind' => 'config', 'status' => 403, 'reason' => 'full policy mode is missing ' . implode(', ', $missing) . ' (fail closed)'];
        }
        foreach (self::UNSUPPORTED as $k) {
            if (array_key_exists($k, $opts)) {
                return ['allow' => false, 'kind' => 'config', 'status' => 403, 'reason' => "the option '$k' is not supported by this port (fail closed)"];
            }
        }
        foreach (array_keys(is_array($opts['enforce'] ?? null) ? $opts['enforce'] : []) as $k) {
            if ($k !== 'freshness') {
                return ['allow' => false, 'kind' => 'config', 'status' => 403, 'reason' => "the $k enforcement gate is not supported by this port (fail closed)"];
            }
        }
        try {
            $p = $pcactn instanceof Obj ? $pcactn : null;
            $action = $p?->get('action');
            $verb = $action instanceof Obj ? $action->get('verb') : null;
            $resource = $action instanceof Obj ? $action->get('resource') : null;
            $opRes = $operation['resource'] ?? null;
            if ($verb !== $operation['verb'] || ($opRes !== null && $resource !== $opRes)) {
                $want = $opRes !== null ? "{$operation['verb']} on $opRes" : (string)$operation['verb'];
                return ['allow' => false, 'kind' => 'binding', 'status' => 403,
                    'reason' => 'the proof is for ' . IntentWb::jsStr($verb) . ' on ' . IntentWb::jsStr($resource) . ", but this call is $want"];
            }
            $grant = $opts['grant'] ?? ($opts['resolveGrant'])($p->get('grant_ref'), $p);
            if (!($grant instanceof Obj)) {
                return ['allow' => false, 'kind' => 'authn', 'status' => 401, 'reason' => 'unknown grant_ref'];
            }
            $now = isset($opts['now']) && is_callable($opts['now']) ? (int)($opts['now'])() : (int)(microtime(true) * 1000);
            $params = $operation['params'];
            $isRevoked = $opts['isRevoked'];
            $isPlan = $opts['isPlanAuthorized'] ?? null;
            $riskFn = $opts['risk'] ?? null;
            $hooks = is_array($opts['hooks'] ?? null) ? $opts['hooks'] : [];
            $prov = $opts['provenance'] ?? null;
            $args = [
                'audience' => $opts['audience'], 'resolveGrant' => static fn($ref = null, $x = null) => $grant, 'stateStore' => $opts['state'],
                'isRevoked' => static fn(Obj $pc, Obj $g): bool => $isRevoked($g, $pc) === true, 'now' => $now,
                'allowedSuites' => $opts['allowedSuites'] ?? ['ed25519'],
                'require' => array_merge(self::EXECUTION_REQUIRED_CHECKS, (array)($opts['require'] ?? [])),
                'requireAssurance' => $opts['requireAssurance'] ?? null, 'k1' => $opts['k1'] ?? null, 'usesStore' => $opts['usesStore'] ?? null,
                'provenance' => $operation['provenance'] ?? null,
                'provenanceMediators' => $prov['mediators'] ?? null, 'provenanceActions' => $prov['actions'] ?? null, 'provenanceObserved' => $prov['observed'] ?? null,
                'pqPins' => $opts['pqPins'] ?? null,
                'assuranceHooks' => array_intersect_key($hooks, ['attestation' => 1, 'zk' => 1]) ?: null,
                'enforceFreshness' => ($opts['enforce'] ?? null)['freshness'] ?? null,
                'hard' => ['seedBudget' => true, 'thresholdHook' => $hooks['threshold'] ?? null,
                    'risk' => static fn(mixed $op, mixed $g, mixed $pc): mixed => is_callable($riskFn) ? $riskFn($g, $params, $pc) : self::amountRisk($g, $params)],
            ];
            if (is_callable($isPlan)) {
                $args['context'] = static function (Obj $pc) use ($isPlan): Obj {
                    $a = $pc->get('action');
                    $node = Obj::of(['id' => $pc->get('plan')->get('node_id'), 'verb' => $a->get('verb'), 'resource' => $a->get('resource'),
                        'params_digest' => $a->get('params_digest'), 'reversibility_class' => $a->get('reversibility_class')]);
                    return Obj::of(['plan' => [$node], 'plan_authorized' => $isPlan($pc->get('grant_ref'), $pc->get('plan')->get('root')) === true]);
                };
            } else {
                $args['plan'] = Authorize::SINGLE_STEP;
            }
            $r = Authorize::authorize($p, ['verb' => $operation['verb'], 'resource' => $opRes ?? $resource, 'params' => $params], ...$args);
            if ($r->allow) {
                return ['allow' => true, 'pcactn' => $r->pcactn, 'grant' => $grant, 'verdict' => $r->verdict, 'assurance' => $r->assurance];
            }
            $kind = $r->status === 401 ? 'authn' : (($r->checks['revocation'] ?? null) === 'fail' ? 'revoked' : (($r->checks['replay'] ?? null) === 'fail' ? 'replay' : 'policy'));
            return ['allow' => false, 'kind' => $kind, 'status' => $r->status, 'reason' => self::decisiveReason($r->checks, $r->reasons), 'checks' => $r->checks,
                'verdict' => $r->verdict, 'assurance' => $r->assurance];
        } catch (\Throwable $e) {
            return ['allow' => false, 'kind' => 'policy', 'status' => 403, 'reason' => 'authorization error (fail closed): ' . ($e->getMessage() === '' ? 'unknown' : $e->getMessage())];
        }
    }
}
