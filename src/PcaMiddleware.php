<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Authorize.php';
require_once __DIR__ . '/Executor.php';
require_once __DIR__ . '/FreshAt.php';
require_once __DIR__ . '/Refusals.php';

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware for Proof-Carrying Authority. It layers the transport concerns — where the PCActn
 * comes from, how a failure surfaces — on top of the existing offline verifier ({@see Pca::verifyJson}
 * / {@see Pca::verifyPcactnCore}). There is NO second copy of the canonicalization, Ed25519/ML-DSA or
 * chain logic here: this file only reads the PCActn off the PSR-7 message, hands it to the verifier, and
 * branches on the verdict.
 *
 * The PCActn is read from the `PCA-Action` request header (strict unpadded base64url of the UTF-8 JSON text, see
 * {@see Pca::decodePcaHeader}; padding, the standard alphabet or whitespace are a 401) or, failing a header, from a
 * strict-JSON request body of the shape `{"pcactn": {...}}`. The `grant_ref` is pulled from the PCActn and
 * resolved to its root grant capability through a caller-supplied resolver; the verifier then runs the eight
 * offline checks (wire, version, audience vs signed `aud`, validity, chain rooted at the grant, plan
 * inclusion, leaf signature, counter_format).
 *
 * On success the verdict array (`['allow'=>true,'checks'=>[...],'reason'=>'']`) is attached to the request
 * as the `pca` attribute (configurable) and the next handler runs — read it downstream with
 * `$request->getAttribute('pca')`. On failure the handler never runs and a PSR-7 response is returned with a
 * JSON body and an `RFC 6750`-shaped `WWW-Authenticate: PCA realm="pca", ...` challenge:
 *
 *   - 401 when no PCActn is presented, it cannot be decoded, or its `grant_ref` is unknown;
 *   - 403 when the grant resolver throws (fail closed), or a well-formed PCActn resolves a grant but the verdict denies.
 *
 * Caveats are NOT evaluated on the signature-only path (`signatureOnly: true`, nor by the core verifier). A resource server
 * that uses it and enforces the grant's caveats calls {@see Pca::evaluateCaveats}(Pca::policyCaveats($grant, $pcactn->get('cap_chain')), $ctx) with its own
 * action params (the root grant's caveats outside the envelope included: the 0.4.1 policy-layer security fix).
 *
 * By default (the `$authorize` option, {@see AuthorizeOptions}) the middleware runs the full {@see Authorize::authorize}
 * pipeline: the operation the route will execute (`$authorize->operation`, mapped from the request; null denies),
 * the operation binding, predicates and caveats, revocation, plan and the atomic replay claim. The handler runs only on
 * `allow`; it then finds the core verdict under the `pca` attribute (as on the default path), the bound
 * {@see AuthorizedOperation} under `pca.operation` and the {@see AuthorizeResult} under `pca.authorization` (the attribute
 * name is configurable). A denial answers 401 (`invalid_pcactn`) or 403 (`insufficient_authority`) with the decisive
 * reason and the checks in the JSON body.
 */
final class PcaMiddleware implements MiddlewareInterface
{
    /** The request header carrying a base64url(JSON) PCActn. */
    public const HEADER = 'PCA-Action';

    /** @var \Closure(string):mixed grant_ref -> grant capability (an Obj tree) | null */
    private readonly \Closure $resolveGrant;

    /** @var \Closure():int current time in epoch milliseconds */
    private readonly \Closure $clock;

    private readonly ResponseFactoryInterface $responseFactory;
    private readonly StreamFactoryInterface $streamFactory;

    /** @var Obj|\Closure(Obj):?Obj|null Intent Layer v2 verifier state, or its per-request resolver */
    private readonly Obj|\Closure|null $intentV2;

    /** @var Obj|\Closure(Obj):?Obj|null the `fresh_at` policy, or its per-request resolver */
    private readonly Obj|\Closure|null $freshAt;

    /** null only in signature-only mode */
    private readonly ?AuthorizeOptions $authorize;

    /**
     * @param string                        $audience        this resource server / instance id, checked against the PCActn's signed `aud`
     * @param callable(string):mixed        $resolveGrant    maps a PCActn's `grant_ref` to its root grant capability (null = unknown grant)
     * @param (callable():int)|null         $clock           returns the current time in epoch milliseconds; defaults to the wall clock
     * @param ResponseFactoryInterface|null $responseFactory PSR-17 factory for the error response; guzzlehttp/psr7 is auto-discovered when null
     * @param StreamFactoryInterface|null   $streamFactory   PSR-17 factory for the error body; guzzlehttp/psr7 is auto-discovered when null
     * @param string                        $attribute       the request attribute the verdict is stored under on success
     * @param array<string,mixed>|null      $intentPolicy    optional Intent Layer M2 policy (['require' => bool, 'min_fidelity_ppm' => int,
     *                                                       'max_residual_risk_ppm' => int]) forwarded to the verifier; an active policy
     *                                                       denies a PCActn without a bound `intent`
     * @param Obj|callable|null             $intentV2        optional Intent Layer v2 verifier state + policy (see Pca::verifyPcactnCore):
     *                                                       an Obj, or a callable `(Obj $pcactn): ?Obj` evaluated per request (the
     *                                                       host's store lookup: session root, held grants, accumulator pre-state
     *                                                       under its row lock, receipts, plaintext params). A callable that throws or
     *                                                       returns anything but an Obj / null fails closed (403
     *                                                       `intent_v2_context_error`, no verdict)
     * @param AuthorizeOptions|null         $authorize       the components of the full authorize pipeline (see the class doc). The
     *                                                       default: with none (and not `$signatureOnly`) every request is refused with a
     *                                                       403 `authorize_config` naming what is missing
     * @param bool                          $signatureOnly   opt in to verifying the signature and chain only (no caveats, replay,
     *                                                       revocation or operation binding); cannot be combined with `$authorize`
     * @param Obj|callable|null             $freshAt         optional `fresh_at` policy {signer, scope, local, max_token_age_ms?, require?}
     *                                                       (see FreshAt::decide), or a callable `(Obj $pcactn): ?Obj` evaluated per
     *                                                       request (the verifier's counters move). A token in the `pca-fresh-at` header
     *                                                       is read when the PCActn has no `fresh_at` member (unparseable = bad token)
     */
    public function __construct(
        private readonly string $audience,
        callable $resolveGrant,
        ?callable $clock = null,
        ?ResponseFactoryInterface $responseFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        private readonly string $attribute = 'pca',
        private readonly ?array $intentPolicy = null,
        mixed $intentV2 = null,
        ?AuthorizeOptions $authorize = null,
        bool $signatureOnly = false,
        mixed $freshAt = null,
    ) {
        if ($freshAt !== null && !($freshAt instanceof Obj) && !is_callable($freshAt)) {
            throw new \InvalidArgumentException('freshAt must be an Obj, a callable (Obj $pcactn): ?Obj, or null');
        }
        $this->freshAt = $freshAt instanceof Obj || $freshAt === null ? $freshAt : \Closure::fromCallable($freshAt);
        if ($signatureOnly && $authorize !== null) {
            throw new \InvalidArgumentException('signatureOnly and authorize are mutually exclusive (signatureOnly skips the checks authorize enforces)');
        }
        // the default is the full authorize path; with no options it refuses every request (403 authorize_config)
        $this->authorize = $signatureOnly ? null : ($authorize ?? new AuthorizeOptions());
        if ($intentV2 !== null && !($intentV2 instanceof Obj) && !is_callable($intentV2)) {
            throw new \InvalidArgumentException('intentV2 must be an Obj, a callable (Obj $pcactn): ?Obj, or null');
        }
        $this->intentV2 = $intentV2 instanceof Obj || $intentV2 === null ? $intentV2 : \Closure::fromCallable($intentV2);
        $this->resolveGrant = \Closure::fromCallable($resolveGrant);
        $this->clock = $clock !== null
            ? \Closure::fromCallable($clock)
            : static fn (): int => (int)(microtime(true) * 1000);
        if ($responseFactory === null || $streamFactory === null) {
            $factory = self::discoverFactory();
            $responseFactory ??= $factory;
            $streamFactory ??= $factory;
        }
        $this->responseFactory = $responseFactory;
        $this->streamFactory = $streamFactory;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        // 1. Read the PCActn off the request. `$text` is non-null only for the header carrier, where the
        //    authoritative strict-JSON wire check is left to Pca::verifyJson on the original bytes.
        // 0. workflow required and no step: refused before the PCActn is even decoded (needs no PCActn), as authorize does
        $wfCall = null;
        if ($this->authorize !== null && $this->authorize->workflow !== null) {
            try {
                $wfCall = $this->workflowCallOf($request, $this->authorize);
            } catch (\Throwable) {
                return $this->workflowRefusal('workflow: error (fail closed)');
            }
            if ($wfCall === null && self::requiredOf($this->authorize->workflow)) {
                return $this->workflowRefusal('workflow: this call carries no workflow step (fail closed)');
            }
        }
        [$pcactn, $text, $reason] = $this->extract($request);
        if ($pcactn === null) {
            return $this->error(401, 'invalid_request', $reason);
        }

        $freshAt = $this->freshAt;
        if ($freshAt instanceof \Closure) {
            try {
                $freshAt = ($freshAt)($pcactn);
            } catch (\Throwable) {
                return $this->error(403, 'fresh_at_context_error', 'fresh_at policy unavailable (fail closed)');
            }
            if ($freshAt !== null && !($freshAt instanceof Obj)) {
                return $this->error(403, 'fresh_at_context_error', 'fresh_at policy unavailable (fail closed)');
            }
        }
        $freshAt = FreshAt::withSideCarried($freshAt, $pcactn, $request->getHeaderLine('pca-fresh-at'));

        if ($this->authorize !== null) {
            return $this->processAuthorize($request, $handler, $text ?? $pcactn, $this->authorize, $freshAt, $wfCall);
        }

        // 2. Resolve the grant the chain must be rooted at.
        $grantRef = $pcactn->get('grant_ref');
        if (!is_string($grantRef) || $grantRef === '') {
            return $this->error(401, 'invalid_request', 'PCActn has no grant_ref');
        }
        try {
            $grant = ($this->resolveGrant)($grantRef);
        } catch (\Throwable) {
            // The host's resolver failed: fail closed as TS requirePCA does (403, guard error), never an uncaught 500.
            return $this->error(403, 'insufficient_authority', 'grant resolution failed (fail closed)');
        }
        if ($grant === null) {
            return $this->error(401, 'unknown_grant', 'grant_ref does not resolve to a known grant');
        }

        // 3. Run the existing offline verifier (eight checks). Prefer the raw-bytes entrypoint for the
        //    header carrier so the signed canonical form is checked against exactly what arrived.
        // 3a. Intent Layer v2 verifier state for THIS request (fail closed when the host's lookup fails).
        $v2 = $this->intentV2;
        if ($v2 instanceof \Closure) {
            try {
                $v2 = ($v2)($pcactn);
            } catch (\Throwable) {
                return $this->error(403, 'intent_v2_context_error', 'intent v2 verifier state unavailable (fail closed)');
            }
            if ($v2 !== null && !($v2 instanceof Obj)) {
                return $this->error(403, 'intent_v2_context_error', 'intent v2 verifier state unavailable (fail closed)');
            }
        }
        $now = ($this->clock)();
        $verdict = $text !== null
            ? Pca::verifyJson($text, $grant, $now, $this->audience, null, $this->intentPolicy, $v2, $freshAt)
            : Pca::verifyPcactnCore($pcactn, $grant, $now, $this->audience, null, $this->intentPolicy, $v2, $freshAt);

        if ($verdict['allow'] !== true) {
            return $this->error(403, 'insufficient_authority', $verdict['reason'], $verdict);
        }

        return $handler->handle($request->withAttribute($this->attribute, $verdict));
    }

    /**
     * The caveat language input, only when `k1` is configured: the presented `PCA-Discharges` / `PCA-Narrow` headers merged under
     * the host's own members (`{...presented, ...own}`, own wins). `k1` is a value or a closure `(request, pcactn)` (a throw = an
     * empty own input, K1 caveats fail closed). Unreadable headers are no discharges. Null = off (K1 caveats are refused).
     */
    private function k1Of(ServerRequestInterface $request, Obj|string $pcactn, AuthorizeOptions $opts): mixed
    {
        if ($opts->k1 === null) {
            return null;
        }
        $own = $opts->k1;
        if ($own instanceof \Closure) {
            try {
                $own = $own($request, $pcactn);
            } catch (\Throwable) {
                $own = new Obj();
            }
        }
        return CaveatLang::mergePresentedK1($request->getHeaders(), $own);
    }

    /** The opt-in authorize path: the handler runs only when the operation this request executes is authorized. */
    private function processAuthorize(ServerRequestInterface $request, RequestHandlerInterface $handler, Obj|string $pcactn,
                                      AuthorizeOptions $opts, ?Obj $freshAt, mixed $wfCall = null): ResponseInterface
    {
        try {
            $operation = $opts->operation !== null ? ($opts->operation)($request) : null;
        } catch (\Throwable) {
            $operation = null; // a mapping that fails names no operation: denied below
        }
        $policy = $this->intentPolicy;
        if ($opts->approvedGoal !== null) {
            $policy = ($policy ?? []) + [];
            $policy['approved_goal'] = $opts->approvedGoal;
        }
        $args = [
            'audience' => $this->audience, 'resolveGrant' => $this->resolveGrant, 'stateStore' => $opts->stateStore,
            'isRevoked' => $opts->isRevoked, 'now' => ($this->clock)(), 'plan' => $opts->plan, 'context' => $opts->context,
            'intentPolicy' => $policy, 'intentV2' => $this->intentV2, 'require' => $opts->require,
            'escalationPrincipals' => $opts->escalationPrincipals,
            'escalationAnswer' => $opts->escalationPrincipals ? $this->escalationAnswerOf($request, $opts) : null,
            'revocationStaleness' => $opts->revocationStaleness,
            'revocationState' => $opts->revocationState === null ? null : static fn(Obj $p, Obj $g): ?RevocationState => ($opts->revocationState)($request, $p, $g),
            'guardianPublic' => $opts->guardianPublic, 'guardianPins' => $opts->guardianPins, 'plans' => $opts->plans,
            'requireAssurance' => $opts->requireAssurance, 'assuranceHooks' => $opts->assuranceHooks,
            'k1' => $this->k1Of($request, $pcactn, $opts), 'usesStore' => $opts->usesStore,
            'freshAt' => $freshAt,
            'escalationRender' => $opts->escalationRender, 'insecureUnboundApproval' => $opts->insecureUnboundApproval,
            'workflow' => $opts->workflow, 'workflowCall' => $wfCall,
            // provenance by default: the host's reader, else header `PCA-Provenance` / body `pca_provenance`
            'provenanceMediators' => $opts->provenanceMediators, 'provenanceActions' => $opts->provenanceActions,
            'provenanceObserved' => $opts->provenanceObserved,
            'provenanceBundle' => fn (Obj $p, array $op): mixed => $opts->provenanceBundle !== null
                ? ($opts->provenanceBundle)($request, $p, $op) : $this->provenanceOf($request),
            'undo' => $opts->undo,
        ];
        if ($opts->executor !== null) {
            return $this->processExecutor($request, $handler, $pcactn, $operation, $opts->executor, $args);
        }
        $result = Authorize::authorize($pcactn, $operation, ...$args);
        if (!$result->allow) {
            return $this->denial($result);
        }
        return $handler->handle($request
            ->withAttribute($this->attribute, $result->verdict)
            ->withAttribute($this->attribute . '.operation', $result->operation)
            ->withAttribute($this->attribute . '.authorization', $result));
    }

    /** The call's workflow step: the host's reader, else the body member `workflow` when the PCActn came in the JSON body. */
    private function workflowCallOf(ServerRequestInterface $request, AuthorizeOptions $opts): mixed
    {
        if ($opts->workflowCall !== null) {
            return ($opts->workflowCall)($request);
        }
        if ($request->getHeaderLine(self::HEADER) !== '') {
            return null;
        }
        $text = $this->readBody($request);
        if ($text === '') {
            return null;
        }
        try {
            $body = Json::parseStrict($text);
        } catch (\Throwable) {
            return null; // the PCActn extraction refuses an unreadable body
        }
        $w = $body instanceof Obj ? $body->get('workflow') : null;
        return $w instanceof Obj ? $w : null;
    }

    private static function requiredOf(mixed $workflow): bool
    {
        return ($workflow instanceof Obj ? $workflow->get('required') : (is_array($workflow) ? ($workflow['required'] ?? null) : null)) === true;
    }

    private function workflowRefusal(string $reason): ResponseInterface
    {
        return $this->respond(403, 'insufficient_authority', $reason, ['reason' => $reason, 'checks' => ['workflow' => 'fail'], 'decision' => 'deny']);
    }

    private function denial(AuthorizeResult $result): ResponseInterface
    {
        $extra = ['reason' => $result->reason ?? 'denied', 'checks' => $result->checks, 'decision' => $result->decision];
        if ($result->escalation !== null) {
            $extra['escalation'] = self::plain($result->escalation);
        }
        if ($result->missing !== null) {
            $extra['missing'] = $result->missing;
        }
        return $this->respond($result->status, $result->status === 401 ? 'invalid_pcactn' : 'insufficient_authority',
            $result->reason ?? 'denied', $extra);
    }

    private const MAX_RECORDED_BODY = 4194304;

    /**
     * The `executor` path: the handler runs at most once per authorization, with a durable operation record. The response is
     * recorded (status, content type, body; a body over 4 MiB is recorded as omitted) and a retry of the same PCActn is answered
     * from the record with `PCA-Replayed: true`. The handler finds the operation under `<attribute>.operation` and the idempotency
     * key under `<attribute>.idempotency_key`.
     *
     * @param array<string,mixed> $args the named arguments of {@see Authorize::authorize}
     */
    private function processExecutor(ServerRequestInterface $request, RequestHandlerInterface $handler, Obj|string $pcactn, mixed $operation,
                                     ExecutorOptions $eo, array $args): ResponseInterface
    {
        $now = $this->clock;
        $executor = new Executor($eo->operations, $args, $eo->recheck, $eo->recheckFor, $eo->reversibilityClassOf, $eo->pendingTimeoutMs, $now);
        $out = $executor->run($pcactn, $operation, function (ExecutionHandle $h) use ($request, $handler): array {
            $resp = $handler->handle($request
                ->withAttribute($this->attribute . '.operation', $h->operation)
                ->withAttribute($this->attribute . '.idempotency_key', $h->idempotencyKey));
            $body = (string)$resp->getBody();
            $rec = ['status' => $resp->getStatusCode(), 'content_type' => $resp->getHeaderLine('Content-Type')];
            if (strlen($body) <= self::MAX_RECORDED_BODY) {
                $rec['body_b64'] = base64_encode($body);
            } else {
                $rec['body_omitted'] = true;
            }
            return $rec;
        });
        switch ($out->status) {
            case 'denied':
                return $this->denial($out->authorization);
            case 'committed':
                $r = $out->result;
                $resp = $this->responseFactory->createResponse($r instanceof Obj && $r->get('status') instanceof Num ? $r->get('status')->int() : 200);
                if ($r instanceof Obj && is_string($r->get('content_type')) && $r->get('content_type') !== '') {
                    $resp = $resp->withHeader('Content-Type', $r->get('content_type'));
                }
                $body = $r instanceof Obj && is_string($r->get('body_b64')) ? (string)base64_decode($r->get('body_b64'), true) : '';
                $resp = $resp->withBody($this->streamFactory->createStream($body));
                return $out->replayed ? $resp->withHeader('PCA-Replayed', 'true') : $resp;
            case 'failed':
                return $this->respond(500, 'execution_failed', $out->error, ['operation_id' => $out->operationId]);
            case 'aborted':
                return $this->respond(409, 'operation_aborted', $out->reason, ['operation_id' => $out->operationId]);
            case 'pending':
                return $this->respond(409, 'operation_in_progress', 'another execution of this authorization is in flight', ['operation_id' => $out->operationId]);
            case 'uncertain':
                return $this->respond(409, 'operation_uncertain', $out->reason, ['operation_id' => $out->operationId]);
            default:
                return $this->respond(403, 'insufficient_authority', $out->reason, []);
        }
    }

    /**
     * The principal's EscalationAnswer for this request: the host's reader, else the header `PCA-Escalation-Answer` (strict
     * unpadded base64url of the JSON), else the JSON body member `escalation_answer`. An unreadable answer is no answer: the
     * decision stays `escalate` (refused).
     */
    private function escalationAnswerOf(ServerRequestInterface $request, AuthorizeOptions $opts): ?Obj
    {
        try {
            if ($opts->escalationAnswer !== null) {
                $a = ($opts->escalationAnswer)($request);
                return $a instanceof Obj ? $a : null;
            }
            $h = $request->getHeaderLine('PCA-Escalation-Answer');
            if ($h !== '') {
                $raw = Pca::decodePcaHeader($h);
                $o = $raw === null || strlen($raw) > Pca::MAX_ARTIFACT_BYTES ? null : Json::parseStrict($raw);
                return $o instanceof Obj ? $o : null;
            }
            $text = $this->readBody($request);
            if ($text === '') {
                return null;
            }
            $body = Json::parseStrict($text);
            $a = $body instanceof Obj ? $body->get('escalation_answer') : null;
            return $a instanceof Obj ? $a : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The provenance bundle presented with this request: header `PCA-Provenance` (strict unpadded base64url of the JSON; one that
     * does not decode or parse THROWS, which the gate refuses as unreadable), else the JSON body member `pca_provenance` (an
     * unparsable body carries none). Null = none.
     */
    private function provenanceOf(ServerRequestInterface $request): mixed
    {
        $h = $request->getHeaderLine(ArgProvenance::HEADER);
        if ($h !== '') {
            $raw = Pca::decodePcaHeader($h);
            if ($raw === null) {
                throw new \UnexpectedValueException('the PCA-Provenance header is not base64url of UTF-8');
            }
            return Json::parseStrict($raw);
        }
        $text = $this->readBody($request);
        if ($text === '') {
            return null;
        }
        try {
            $body = Json::parseStrict($text);
        } catch (\Throwable) {
            return null;
        }
        return $body instanceof Obj ? $body->get(ArgProvenance::BODY_MEMBER) : null;
    }

    /** A library JSON value as plain PHP for json_encode (Obj -> object, Num -> int|float). */
    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            $o = new \stdClass();
            foreach ($v->keys() as $k) {
                $o->{$k} = self::plain($v->get($k));
            }
            return $o;
        }
        if ($v instanceof Num) {
            return $v->isInt() ? $v->int() : $v->float();
        }
        return is_array($v) ? array_map(self::plain(...), $v) : $v;
    }

    /**
     * Laravel-style wrapper over {@see process()}: adapts the `(request, next)` pipeline convention onto the
     * PSR-15 entrypoint by wrapping `$next` in a one-shot handler. Works in any Laravel/Lumen pipeline that
     * passes a PSR-7 {@see ServerRequestInterface} (e.g. via the symfony/psr-http-message bridge) and whose
     * `$next` returns a PSR-7 {@see ResponseInterface}.
     *
     * @param \Closure(ServerRequestInterface):ResponseInterface $next
     */
    public function handle(ServerRequestInterface $request, \Closure $next): ResponseInterface
    {
        return $this->process($request, new class ($next) implements RequestHandlerInterface {
            public function __construct(private readonly \Closure $next)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return ($this->next)($request);
            }
        });
    }

    // ---- carriers -----------------------------------------------------------------------

    /**
     * Pull the PCActn from the `PCA-Action` header (base64url -> JSON) or a `{"pcactn":...}` body.
     *
     * @return array{0:?Obj,1:?string,2:string} [pcactn | null, raw header JSON text | null, failure reason]
     */
    private function extract(ServerRequestInterface $request): array
    {
        $header = $request->getHeaderLine(self::HEADER);
        if ($header !== '') {
            $raw = Pca::decodePcaHeader($header); // 0.4.1: strict unpadded base64url of strict UTF-8
            if ($raw === null) {
                return [null, null, 'PCA-Action header is not valid base64url'];
            }
            if (strlen($raw) > Pca::MAX_ARTIFACT_BYTES) {
                return [null, null, 'PCA-Action header is not a valid PCActn JSON object'];
            }
            try {
                $p = Json::parseLax($raw);
            } catch (\Throwable) {
                return [null, null, 'PCA-Action header is not a valid PCActn JSON object'];
            }
            if (!($p instanceof Obj)) {
                return [null, null, 'PCA-Action header is not a valid PCActn JSON object'];
            }
            return [$p, $raw, ''];
        }

        $text = $this->readBody($request);
        if ($text === '') {
            return [null, null, 'no PCActn presented (missing PCA-Action header and request body)'];
        }
        try {
            $body = Json::parseStrict($text, true);
        } catch (\Throwable) {
            return [null, null, 'request body is not valid strict JSON'];
        }
        /** @var Obj $body */
        if (!$body->has('pcactn')) {
            return [null, null, "request body has no 'pcactn' field"];
        }
        $p = $body->get('pcactn');
        if (!($p instanceof Obj)) {
            return [null, null, "'pcactn' is not a JSON object"];
        }
        // The body sub-tree has no isolated raw text, so verification runs on the parsed tree.
        return [$p, null, ''];
    }

    /** Read the request body as a string without disturbing it for downstream handlers. */
    private function readBody(ServerRequestInterface $request): string
    {
        try {
            $body = $request->getBody();
            $contents = (string)$body;
            if ($body->isSeekable()) {
                $body->rewind();
            }
            return $contents;
        } catch (\Throwable) {
            return '';
        }
    }

    // ---- responses ----------------------------------------------------------------------

    /**
     * Emit a JSON error body plus an RFC 6750-shaped `WWW-Authenticate: PCA realm="pca", error="<code>"` challenge. The
     * description is NOT put in the header: it can carry request-derived text (the verdict reason, a parse error) with CR/LF
     * (header injection; a PSR-7 implementation then throws, i.e. a 500); TS requirePCA puts no reason in its challenge
     * either. The description stays in the JSON body.
     *
     * @param array{allow:bool,checks:array<string,bool>,reason:string}|null $verdict
     */
    private function error(int $status, string $code, string $description, ?array $verdict = null): ResponseInterface
    {
        $extra = [];
        if ($verdict !== null) {
            if ($verdict['reason'] !== '') {
                $extra['reason'] = $verdict['reason'];
            }
            $extra['checks'] = $verdict['checks'];
        }
        return $this->respond($status, $code, $description, $extra);
    }

    /** @param array<string,mixed> $extra members appended to the JSON body */
    private function respond(int $status, string $code, string $description, array $extra): ResponseInterface
    {
        $challenge = sprintf('PCA realm="pca", error="%s"', $code);

        $payload = ['error' => $code];
        if ($description !== '') {
            $payload['error_description'] = $description;
        }
        $payload += $extra;
        // where to read about this refusal; the reason strings themselves are pinned and unchanged
        $payload['doc'] = Refusals::explainRefusal($extra['reason'] ?? $description)['docs'];

        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        return $this->responseFactory->createResponse($status)
            ->withHeader('WWW-Authenticate', $challenge)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream($body));
    }

    private static function discoverFactory(): ResponseFactoryInterface&StreamFactoryInterface
    {
        if (class_exists(\GuzzleHttp\Psr7\HttpFactory::class)) {
            return new \GuzzleHttp\Psr7\HttpFactory();
        }
        if (class_exists(\Nyholm\Psr7\Factory\Psr17Factory::class)) {
            return new \Nyholm\Psr7\Factory\Psr17Factory();
        }
        throw new \RuntimeException(
            'No PSR-17 factories were provided to PcaMiddleware and none of guzzlehttp/psr7 or nyholm/psr7 '
            . 'is installed. Install one or pass your own response/stream factories to the constructor.'
        );
    }
}
