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
 * The PCActn is read from the `PCA-Action` request header (base64url(JSON)) or, failing a header, from a
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
 *   - 403 when a well-formed PCActn resolves a grant but the verdict denies.
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

    /**
     * @param string                        $audience        this resource server / instance id, checked against the PCActn's signed `aud`
     * @param callable(string):mixed        $resolveGrant    maps a PCActn's `grant_ref` to its root grant capability (null = unknown grant)
     * @param (callable():int)|null         $clock           returns the current time in epoch milliseconds; defaults to the wall clock
     * @param ResponseFactoryInterface|null $responseFactory PSR-17 factory for the error response; guzzlehttp/psr7 is auto-discovered when null
     * @param StreamFactoryInterface|null   $streamFactory   PSR-17 factory for the error body; guzzlehttp/psr7 is auto-discovered when null
     * @param string                        $attribute       the request attribute the verdict is stored under on success
     */
    public function __construct(
        private readonly string $audience,
        callable $resolveGrant,
        ?callable $clock = null,
        ?ResponseFactoryInterface $responseFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        private readonly string $attribute = 'pca',
    ) {
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
        $grant = ($this->resolveGrant)($grantRef);
        if ($grant === null) {
            return $this->error(401, 'unknown_grant', 'grant_ref does not resolve to a known grant');
        }

        // 3. Run the existing offline verifier (eight checks). Prefer the raw-bytes entrypoint for the
        //    header carrier so the signed canonical form is checked against exactly what arrived.
        $now = ($this->clock)();
        $verdict = $text !== null
            ? Pca::verifyJson($text, $grant, $now, $this->audience)
            : Pca::verifyPcactnCore($pcactn, $grant, $now, $this->audience);

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
            $raw = self::decodeB64u($header);
            if ($raw === null) {
                return [null, null, 'PCA-Action header is not valid base64url'];
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

    /** Accepts the unpadded or padded base64url alphabet; null when neither decodes. */
    private static function decodeB64u(string $s): ?string
    {
        foreach ([SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING, SODIUM_BASE64_VARIANT_URLSAFE] as $variant) {
            try {
                return sodium_base642bin($s, $variant);
            } catch (\Throwable) {
                // try the next variant
            }
        }
        return null;
    }

    // ---- responses ----------------------------------------------------------------------

    /**
     * Emit a JSON error body plus an RFC 6750-shaped `WWW-Authenticate: PCA ...` challenge.
     *
     * @param array{allow:bool,checks:array<string,bool>,reason:string}|null $verdict
     */
    private function error(int $status, string $code, string $description, ?array $verdict = null): ResponseInterface
    {
        $challenge = sprintf('PCA realm="pca", error="%s"', $code);
        if ($description !== '') {
            $challenge .= sprintf(', error_description="%s"', self::quote($description));
        }

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

    /** Make a string safe inside a quoted WWW-Authenticate auth-param value. */
    private static function quote(string $s): string
    {
        return str_replace(['\\', '"'], ['\\\\', '\\"'], $s);
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
