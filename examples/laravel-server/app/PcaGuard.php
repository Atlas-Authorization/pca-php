<?php

namespace App;

use Atlas\Pca\Protect;
use Closure;
use Illuminate\Http\Request;
use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpFoundation\Response;

/** Runs the PSR-15 PCA middleware inside Laravel's pipeline. */
final class PcaGuard
{
    public function __construct(private readonly Protect $protect)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $f = new Psr17Factory();
        $psr = (new PsrHttpFactory($f, $f, $f, $f))->createRequest($request);
        $handler = new class ($next, $request, $f) implements RequestHandlerInterface {
            public ?Response $response = null;

            public function __construct(private readonly Closure $next, private readonly Request $request, private readonly Psr17Factory $f)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->response = ($this->next)($this->request);
                return $this->f->createResponse($this->response->getStatusCode());
            }
        };
        $out = $this->protect->middleware->process($psr, $handler);
        // allowed: Laravel's own response; refused: the PCA refusal (status, WWW-Authenticate, JSON body with `doc`)
        return $handler->response ?? (new HttpFoundationFactory())->createResponse($out);
    }
}
