<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';

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
 * inclusion, leaf signature, counter).
 *
 * On success the verdict array (`['allow'=>true,'checks'=>[...],'reason'=>'']`) is attached to the request
 * as the `pca` attribute (configurable) and the next handler runs — read it downstream with
 * `$request->getAttribute('pca')`. On failure the handler never runs and a PSR-7 response is returned with a
 * JSON body and an `RFC 6750`-shaped `WWW-Authenticate: PCA realm="pca", ...` challenge:
 *
 *   - 401 when no PCActn is presented, it cannot be decoded, or its `grant_ref` is unknown;
 *   - 403 when the grant resolver throws (fail closed), or a well-formed PCActn resolves a grant but the verdict denies.
 *
 * Caveats are NOT evaluated here (nor by the core verifier). A resource server that enforces the grant's caveats calls
 * {@see Pca::evaluateCaveats}(Pca::policyCaveats($grant, $pcactn->get('cap_chain')), $ctx) with its own action params
 * (the root grant's caveats outside the envelope included: the 0.4.1 policy-layer security fix).
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
    ) {
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
        [$pcactn, $text, $reason] = $this->extract($request);
        if ($pcactn === null) {
            return $this->error(401, 'invalid_request', $reason);
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
            ? Pca::verifyJson($text, $grant, $now, $this->audience, null, $this->intentPolicy, $v2)
            : Pca::verifyPcactnCore($pcactn, $grant, $now, $this->audience, null, $this->intentPolicy, $v2);

        if ($verdict['allow'] !== true) {
            return $this->error(403, 'insufficient_authority', $verdict['reason'], $verdict);
        }

        return $handler->handle($request->withAttribute($this->attribute, $verdict));
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
        $challenge = sprintf('PCA realm="pca", error="%s"', $code);

        $payload = ['error' => $code];
        if ($description !== '') {
            $payload['error_description'] = $description;
        }
        if ($verdict !== null) {
            if ($verdict['reason'] !== '') {
                $payload['reason'] = $verdict['reason'];
            }
            $payload['checks'] = $verdict['checks'];
        }

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
