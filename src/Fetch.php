<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Runtime-neutral request guard for Proof-Carrying Authority, shaped like the Web Fetch guard of the reference (pca-fetch): wrap a handler so
 * the inbound PCActn is verified first; on success the handler runs with the verdict and PCActn, otherwise a 401 / 403 response array with a
 * WWW-Authenticate challenge is returned. It adds no verification of its own: it joins the core verifier (signature only) or the full
 * {@see Authorize} pipeline (the default). A request is {method, url, headers (assoc array or Obj), body?}; a response is
 * {status, headers, body}. Default-deny: a missing or unreadable proof, an unknown grant or a throwing resolver all refuse.
 *
 * Options (assoc array): audience (required), resolveGrant (callable (ref): grant|null), now (int ms or callable), intentPolicy, intentV2,
 * authorize (AuthorizeOptions), operation (callable (headers, body): array|Obj|null), signatureOnly, freshAt, allowedSuites,
 * insecureAllowUnboundOperation, denyBody (callable (result): mixed), hooks (with signatureOnly: the verifier hooks ['attestation' => callable,
 * 'zk' => callable] of Pca::verifyPcactnCore; the authorize path takes them in AuthorizeOptions::$assuranceHooks).
 *
 * shortcut: the AuthorizeOptions closures that the PSR-15 middleware calls with a PSR-7 request (escalationAnswer, revocationState, passport,
 * provenanceBundle, forbidCertificate, workflowCall, undo gates keyed on the request) are not called here, and k1 is the host's value as given
 * (presented PCA-Discharges / PCA-Narrow headers are merged under it, as the middleware does); use PcaMiddleware when those are needed.
 */
final class Fetch
{
    public const PCA_HEADER = 'PCA-Action';
    public const REALM = 'pca';
    public const FRESH_AT_HEADER = 'pca-fresh-at';

    /** @return array{ok:bool,status:int,verdict:mixed,pcactn:?Obj,error:?string,wwwAuthenticate:?string,authorization:?AuthorizeResult,decision:string,escalation:?Obj} */
    private static function result(bool $ok, int $status, array $x = []): array
    {
        return $x + ['ok' => $ok, 'status' => $status, 'verdict' => null, 'pcactn' => null, 'error' => null, 'wwwAuthenticate' => null,
            'authorization' => null, 'decision' => $ok ? 'allow' : 'deny', 'escalation' => null];
    }

    /** An auth-param quoted-string: escape backslash and double-quote (RFC 7235). */
    private static function quote(string $v): string
    {
        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $v) . '"';
    }

    /** A WWW-Authenticate challenge value built only from fixed tokens and the operator's own audience. */
    public static function challenge(?string $audience, ?string $error = null, ?string $description = null): string
    {
        $parts = ['realm=' . self::quote(self::REALM)];
        foreach (['audience' => $audience, 'error' => $error, 'error_description' => $description] as $k => $v) {
            if ($v !== null) {
                $parts[] = $k . '=' . self::quote($v);
            }
        }
        return 'PCA ' . implode(', ', $parts);
    }

    /** @return list<array{0:string,1:mixed}> */
    private static function entries(mixed $h): array
    {
        $r = [];
        if ($h instanceof Obj) {
            foreach ($h->keys() as $k) {
                $r[] = [$k, $h->get($k)];
            }
        } elseif (is_array($h) && !array_is_list($h)) {
            foreach ($h as $k => $v) {
                $r[] = [(string)$k, $v];
            }
        }
        return $r;
    }

    /** Case-insensitive lookup: every spelling is read; case variants with DIFFERENT values make the credential ambiguous (absent -> denied). */
    public static function getHeader(mixed $headers, string $name): ?string
    {
        $low = strtolower($name);
        $found = null;
        foreach (self::entries($headers) as [$k, $raw]) {
            if (strtolower($k) !== $low) {
                continue;
            }
            $v = is_array($raw) ? ($raw[0] ?? null) : $raw;
            if (!is_string($v)) {
                continue;
            }
            if ($found !== null && $found !== $v) {
                return null;
            }
            $found = $v;
        }
        return $found;
    }

    private static function text(mixed $body): ?string
    {
        return is_string($body) && $body !== '' && preg_match('//u', $body) === 1 ? $body : null;
    }

    /** @return array{0:?Obj,1:?string,2:?string} [pcactn, raw header text, absent|undecodable] */
    private static function extract(mixed $headers, mixed $body): array
    {
        $raw = self::getHeader($headers, self::PCA_HEADER);
        if ($raw !== null && $raw !== '') { // an empty header is no header: the body is read
            $t = Pca::decodePcaHeader($raw);
            if ($t === null || strlen($t) > Pca::MAX_ARTIFACT_BYTES) {
                return [null, null, 'undecodable'];
            }
            try {
                $o = Json::parseLax($t);
            } catch (\Throwable) {
                return [null, null, 'undecodable'];
            }
            return $o instanceof Obj ? [$o, $t, null] : [null, null, 'undecodable'];
        }
        $t = self::text($body);
        if ($t === null) {
            return [null, null, 'absent'];
        }
        try {
            $env = Json::parseStrict($t, true);
        } catch (\Throwable) {
            return [null, null, 'undecodable'];
        }
        if (!$env->has('pcactn')) {
            return [null, null, 'absent'];
        }
        return $env->get('pcactn') instanceof Obj ? [$env->get('pcactn'), null, null] : [null, null, 'undecodable'];
    }

    /** The caveat language input, only when `k1` is configured: the presented discharge / narrow headers merged under the host's own members. */
    private static function k1Of(mixed $headers, mixed $body, Obj|string $pcactn, mixed $k1): mixed
    {
        if ($k1 === null) {
            return null;
        }
        if ($k1 instanceof \Closure) {
            try {
                $k1 = $k1(Obj::of(['headers' => $headers, 'body' => $body]), $pcactn);
            } catch (\Throwable) {
                $k1 = new Obj(); // a throw is an empty own input: the K1 caveats fail closed
            }
        }
        return CaveatLang::mergePresentedK1($headers, $k1);
    }

    /**
     * The framework-agnostic guard: `(headers, body = null, operation = null) -> result array`, default-deny. Throws TypeError when the
     * configuration is unsafe (no audience; neither an operation mapping, `authorize`, `signatureOnly` nor the explicit opt-in).
     *
     * @param array<string,mixed> $o
     * @return \Closure(mixed, mixed=, mixed=): array<string,mixed>
     */
    public static function createPcaFetchGuard(array $o): \Closure
    {
        $audience = $o['audience'] ?? null;
        if (!is_string($audience) || $audience === '') {
            throw new \TypeError("pca-fetch: `audience` (this resource server's id) is required");
        }
        $unbound = ($o['insecureAllowUnboundOperation'] ?? false) === true;
        $authorize = $o['authorize'] ?? null;
        $sigOnly = ($o['signatureOnly'] ?? false) === true;
        if (!isset($o['operation']) && $authorize === null && !$unbound && !$sigOnly) {
            throw new \TypeError('pca-fetch: `operation` is required: map each request to the operation it will execute so the proof is bound to it, '
                . 'or use `authorize`; set insecureAllowUnboundOperation only to migrate');
        }
        if ($unbound && !isset($o['operation']) && !array_key_exists('signatureOnly', $o)) {
            $sigOnly = true;
        }
        if ($sigOnly && $authorize !== null) {
            throw new \InvalidArgumentException('signatureOnly and authorize are mutually exclusive');
        }
        $hooks = $o['hooks'] ?? null;
        if ($hooks !== null && (!is_array($hooks) || !$sigOnly)) {
            throw new \InvalidArgumentException('pca-fetch: hooks is an array for signatureOnly; give the attestation / zk hooks in authorize (assuranceHooks)');
        }
        $az = $sigOnly ? null : ($authorize ?? new AuthorizeOptions());
        $resolve = $o['resolveGrant'] ?? static fn(string $ref): mixed => null;
        $clock = static function () use ($o): int {
            $n = $o['now'] ?? null;
            $n = is_callable($n) ? $n() : $n;
            return $n === null ? (int)(microtime(true) * 1000) : (int)$n;
        };
        $suites = isset($o['allowedSuites']) ? array_values($o['allowedSuites']) : null;
        $opMap = $o['operation'] ?? null;

        return static function (mixed $headers, mixed $body = null, mixed $operation = null) use ($o, $audience, $az, $resolve, $clock, $suites, $opMap, $hooks): array {
            [$pcactn, $text, $why] = self::extract($headers, $body);
            if ($pcactn === null) {
                $desc = $why === 'absent' ? 'no PCActn presented' : 'PCActn could not be decoded';
                return self::result(false, 401, ['error' => $why, 'wwwAuthenticate' => self::challenge($audience, $why === 'absent' ? 'missing_pcactn' : 'invalid_pcactn', $desc)]);
            }
            $freshAt = $o['freshAt'] ?? null;
            if ($freshAt instanceof \Closure || (is_callable($freshAt) && !($freshAt instanceof Obj))) {
                try {
                    $freshAt = $freshAt($pcactn);
                } catch (\Throwable) {
                    return self::result(false, 403, ['pcactn' => $pcactn, 'error' => 'fresh_at_context_error',
                        'wwwAuthenticate' => self::challenge($audience, 'insufficient_authority', 'fresh_at verifier state unavailable (fail closed)')]);
                }
            }
            $freshAt = FreshAt::withSideCarried($freshAt instanceof Obj ? $freshAt : null, $pcactn, self::getHeader($headers, self::FRESH_AT_HEADER) ?? '');
            $intentV2 = $o['intentV2'] ?? null;
            if (!($intentV2 instanceof Obj) && is_callable($intentV2)) {
                try {
                    $intentV2 = $intentV2($pcactn);
                } catch (\Throwable) {
                    return self::result(false, 403, ['pcactn' => $pcactn, 'error' => 'intent_v2_context_error',
                        'wwwAuthenticate' => self::challenge($audience, 'insufficient_authority', 'intent v2 verifier state unavailable (fail closed)')]);
                }
            }
            $intentV2 = $intentV2 instanceof Obj ? $intentV2 : null;
            $now = $clock();
            if ($az !== null) {
                if ($operation === null) {
                    $m = $opMap ?? $az->operation;
                    try {
                        $operation = $m !== null ? $m($headers, $body) : null;
                    } catch (\Throwable) {
                        $operation = null; // a mapping that fails names no operation: denied below
                    }
                }
                $args = ['audience' => $audience, 'resolveGrant' => $resolve, 'stateStore' => $az->stateStore, 'isRevoked' => $az->isRevoked, 'now' => $now,
                    'plan' => $az->plan, 'context' => $az->context, 'intentPolicy' => $o['intentPolicy'] ?? null, 'intentV2' => $intentV2, 'allowedSuites' => $suites,
                    'require' => $az->require, 'escalationPrincipals' => $az->escalationPrincipals, 'revocationStaleness' => $az->revocationStaleness,
                    'guardianPublic' => $az->guardianPublic, 'guardianPins' => $az->guardianPins, 'plans' => $az->plans, 'requireAssurance' => $az->requireAssurance,
                    'assuranceHooks' => $az->assuranceHooks, 'k1' => self::k1Of($headers, $body, $text ?? $pcactn, $az->k1),
                    'usesStore' => $az->usesStore, 'freshAt' => $freshAt, 'escalationRender' => $az->escalationRender,
                    'insecureUnboundApproval' => $az->insecureUnboundApproval, 'workflow' => $az->workflow, 'provenanceMediators' => $az->provenanceMediators,
                    'undo' => null, 'pqPins' => $az->pqPins, 'resolvePrincipal' => $az->resolvePrincipal, 'requireVerifiedPrincipal' => $az->requireVerifiedPrincipal,
                    'enforceFreshness' => $az->enforceFreshness,
                    'hard' => ['risk' => $az->risk, 'thresholdHook' => $az->thresholdHook, 'seedBudget' => $az->seedBudget, 'requireRiskInputs' => $az->requireRiskInputs,
                        'requirePassport' => $az->requirePassport, 'requireLinkedTemplate' => $az->requireLinkedTemplate, 'adaptivePolicy' => $az->adaptivePolicy,
                        'forbid' => $az->forbid, 'enforceTaint' => $az->enforceTaint, 'beacon' => $az->beacon, 'contracts' => $az->contracts]];
                if ($az->escalationPrincipals !== null && $az->escalationPrincipals !== []) {
                    $h = self::getHeader($headers, 'PCA-Escalation-Answer');
                    try {
                        $raw = $h === null ? null : Pca::decodePcaHeader($h);
                        $a = $raw === null ? null : Json::parseStrict($raw);
                        $args['escalationAnswer'] = $a instanceof Obj ? $a : null;
                    } catch (\Throwable) {
                        $args['escalationAnswer'] = null; // an unreadable answer is no answer
                    }
                }
                $r = Authorize::authorize($text ?? $pcactn, $operation, ...$args);
                if ($r->allow) {
                    return self::result(true, 200, ['verdict' => $r->verdict, 'pcactn' => $pcactn, 'authorization' => $r, 'escalation' => $r->escalation]);
                }
                return self::result(false, $r->status, ['verdict' => $r->verdict, 'pcactn' => $pcactn, 'error' => $r->reason, 'authorization' => $r, 'decision' => $r->decision,
                    'escalation' => $r->escalation, 'wwwAuthenticate' => self::challenge($audience, $r->status === 401 ? 'invalid_pcactn' : 'insufficient_authority')]);
            }
            // signature only: the grant ref must be a string; the resolver's failure or a missing grant refuses
            $ref = $pcactn->get('grant_ref');
            if (!is_string($ref) || $ref === '') {
                return self::result(false, 401, ['pcactn' => $pcactn, 'error' => 'malformed', 'wwwAuthenticate' => self::challenge($audience, 'invalid_pcactn', 'malformed PCActn')]);
            }
            try {
                $grant = $resolve($ref);
            } catch (\Throwable) {
                return self::result(false, 403, ['pcactn' => $pcactn, 'error' => 'resolve_grant_error',
                    'wwwAuthenticate' => self::challenge($audience, 'insufficient_authority', 'grant resolution failed (fail closed)')]);
            }
            if ($grant === null) {
                return self::result(false, 401, ['pcactn' => $pcactn, 'error' => 'unknown_grant',
                    'wwwAuthenticate' => self::challenge($audience, 'unknown_grant', 'grant_ref does not resolve to a known grant')]);
            }
            $verdict = $text !== null
                ? Pca::verifyJson($text, $grant, $now, $audience, $suites, $o['intentPolicy'] ?? null, $intentV2, $freshAt, insecureSkipPlanRootCheck: true, hooks: $hooks)
                : Pca::verifyPcactnCore($pcactn, $grant, $now, $audience, $suites, $o['intentPolicy'] ?? null, $intentV2, $freshAt, insecureSkipPlanRootCheck: true, hooks: $hooks);
            if ($verdict['allow'] === true && $pcactn->has('bond_ref')) { // the core never verifies a bond; a guard never lets one through
                return self::result(false, 403, ['verdict' => $verdict, 'pcactn' => $pcactn, 'error' => Authorize::BOND_UNSUPPORTED,
                    'wwwAuthenticate' => self::challenge($audience, 'insufficient_authority')]);
            }
            if ($verdict['allow'] === true) {
                return self::result(true, 200, ['verdict' => $verdict, 'pcactn' => $pcactn]);
            }
            $reason = (string)($verdict['reason'] ?? '');
            // never echo the reason into the header: it can carry attacker-controlled text (CR/LF -> header injection)
            return self::result(false, 403, ['verdict' => $verdict, 'pcactn' => $pcactn, 'error' => $reason === '' ? 'insufficient_authority' : $reason,
                'wwwAuthenticate' => self::challenge($audience, 'insufficient_authority')]);
        };
    }

    /**
     * The 401 / 403 response for a refusal: JSON body {error, verdict, decision, escalation?} (or `$denyBody($result)`), content-type
     * application/json and the WWW-Authenticate challenge.
     *
     * @param array<string,mixed> $r @return array{status:int,headers:array<string,string>,body:string}
     */
    public static function denyResponse(array $r, ?callable $denyBody = null): array
    {
        if ($denyBody !== null) {
            $body = $denyBody($r);
        } else {
            $az = $r['authorization'];
            $v = $r['verdict'];
            if ($az instanceof AuthorizeResult) {
                $verdict = ['allow' => false, 'checks' => $az->checks === [] ? new Obj() : Obj::of($az->checks), 'reasons' => $az->reasons];
            } elseif (is_array($v)) {
                $reasons = $v['reasons'] ?? (($v['reason'] ?? '') === '' ? [] : [$v['reason']]);
                $verdict = ['allow' => ($v['allow'] ?? false) === true, 'checks' => Obj::of($v['checks'] ?? []), 'reasons' => $reasons];
            } else {
                $verdict = ['allow' => false, 'checks' => new Obj(), 'reasons' => ($r['error'] ?? '') === '' ? [] : [$r['error']]];
            }
            $body = Obj::of(['error' => $verdict['reasons'] === [] ? 'forbidden' : $verdict['reasons'][0], 'verdict' => Obj::of($verdict), 'decision' => $r['decision'] ?? 'deny']);
            if ($r['escalation'] !== null) {
                $body->set('escalation', $r['escalation']);
            }
        }
        $headers = ['content-type' => 'application/json'];
        if (is_string($r['wwwAuthenticate'] ?? null) && $r['wwwAuthenticate'] !== '') {
            $headers['WWW-Authenticate'] = $r['wwwAuthenticate'];
        }
        return ['status' => $r['status'], 'headers' => $headers, 'body' => Js::stringify($body)];
    }

    /**
     * Wrap `$handler(request, ['pca' => ['verdict', 'pcactn', 'operation'?]])` so the inbound PCActn is verified first; a refusal returns
     * {@see denyResponse} and the handler never runs.
     *
     * @param array<string,mixed> $options
     * @return \Closure(mixed): mixed
     */
    public static function withPca(array $options, callable $handler): \Closure
    {
        $deny = $options['denyBody'] ?? null;
        $guard = self::createPcaFetchGuard($options);
        return static function (mixed $req) use ($guard, $handler, $deny): mixed {
            $r = $guard(Js::opt($req, 'headers') ?? [], Js::opt($req, 'body'));
            if ($r['ok']) {
                $pca = ['verdict' => $r['verdict'], 'pcactn' => $r['pcactn']];
                if ($r['authorization'] instanceof AuthorizeResult && $r['authorization']->operation !== null) {
                    $pca['operation'] = $r['authorization']->operation;
                }
                return $handler($req, ['pca' => $pca]);
            }
            return self::denyResponse($r, $deny);
        };
    }
}
