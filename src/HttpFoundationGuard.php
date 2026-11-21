<?php
declare(strict_types=1);

namespace Atlas\Pca;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

require_once __DIR__ . '/PcaMiddleware.php';

/**
 * Runs the PSR-15 {@see PcaMiddleware} against a Symfony HttpFoundation request (Symfony, and Laravel, whose Request extends it), so
 * both frameworks share the one verifier pipeline. `check` answers [denial, verdict]: a denial is the middleware's own error
 * response converted to HttpFoundation; on success the verdict is what the middleware stored under its request attribute.
 * Fail closed: the request passes only when the middleware reached its inner handler AND returned that handler's response
 * unchanged; anything else (including a post-processing failure) is returned as the denial.
 * Needs symfony/psr-http-message-bridge and a PSR-17 implementation (nyholm/psr7 or guzzlehttp/psr7).
 */
final class HttpFoundationGuard
{
    private readonly PsrHttpFactory $toPsr;
    private readonly HttpFoundationFactory $fromPsr;
    private readonly ResponseFactoryInterface $responses;

    public function __construct(private readonly PcaMiddleware $middleware, private readonly string $attribute = 'pca', ?PsrHttpFactory $toPsr = null,
                                ?HttpFoundationFactory $fromPsr = null, ?ResponseFactoryInterface $responses = null)
    {
        $f = null;
        if ($toPsr === null || $responses === null) {
            $f = class_exists(\Nyholm\Psr7\Factory\Psr17Factory::class) ? new \Nyholm\Psr7\Factory\Psr17Factory()
                : (class_exists(\GuzzleHttp\Psr7\HttpFactory::class) ? new \GuzzleHttp\Psr7\HttpFactory()
                    : throw new \RuntimeException('HttpFoundationGuard needs a PSR-17 implementation: install nyholm/psr7 or guzzlehttp/psr7, or pass the factories'));
        }
        $this->toPsr = $toPsr ?? new PsrHttpFactory($f, $f, $f, $f);
        $this->fromPsr = $fromPsr ?? new HttpFoundationFactory();
        $this->responses = $responses ?? $f;
    }

    /** @return array{0: ?Response, 1: mixed} [the denial, or null; the verdict on success] */
    public function check(Request $request): array
    {
        $sentinel = $this->responses->createResponse(204);
        $inner = new class ($sentinel, $this->attribute) implements RequestHandlerInterface {
            public bool $reached = false;
            public mixed $verdict = null;

            public function __construct(private readonly ResponseInterface $sentinel, private readonly string $attribute)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->reached = true;
                $this->verdict = $request->getAttribute($this->attribute);
                return $this->sentinel;
            }
        };
        $out = $this->middleware->process($this->toPsr->createRequest($request), $inner);
        if ($inner->reached && $out === $sentinel) {
            return [null, $inner->verdict];
        }
        return [$this->fromPsr->createResponse($out), null];
    }
}
