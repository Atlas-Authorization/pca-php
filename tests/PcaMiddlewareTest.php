<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The PSR-15 (and Laravel-style) middleware: a genuinely-signed, in-audience PCActn flows through to the
 * handler with the verdict attached; an absent, undecodable or unknown-grant PCActn short-circuits with a
 * 401, and a well-formed PCActn whose verdict denies short-circuits with a 403. The verifier underneath is
 * the real {@see Pca} offline verifier — the valid PCActn is loaded from the shared conformance vectors, so
 * its Ed25519 leaf signature, capability chain and plan-inclusion proof are all real.
 */
final class PcaMiddlewareTest extends TestCase
{
    private const VECTOR = 'valid-raw-json-format-insensitive';

    /** Raw signed PCActn JSON text from the conformance vector. */
    private string $pcactnJson;
    /** The root grant capability the chain is rooted at (an Obj tree). */
    private mixed $grant;
    /** The `grant_ref` carried by the signed PCActn. */
    private string $grantRef;
    private string $audience;
    private int $now;

    protected function setUp(): void
    {
        $dir = __DIR__ . '/../conformance/';
        $doc = Json::parseLax(file_get_contents($dir . 'vectors.json'));
        foreach ($doc->get('vectors') as $v) {
            if ($v->get('name') === self::VECTOR) {
                $this->pcactnJson = $v->get('pcactn_json');
                $this->grant = $v->get('grant');
                $this->audience = $v->get('context')->get('aud');
                $this->now = $v->get('context')->get('now')->int();
                $this->grantRef = Json::parseLax($this->pcactnJson)->get('grant_ref');
                return;
            }
        }
        self::fail('conformance vector ' . self::VECTOR . ' not found');
    }

    /** A resolver that hands back the vector's grant for its own grant_ref, and null for anything else. */
    private function resolver(): callable
    {
        return fn (string $ref): mixed => $ref === $this->grantRef ? $this->grant : null;
    }

    private function middleware(?string $audience = null, ?callable $resolver = null): PcaMiddleware
    {
        $factory = new HttpFactory();
        return new PcaMiddleware(
            $audience ?? $this->audience,
            $resolver ?? $this->resolver(),
            fn (): int => $this->now,
            $factory,
            $factory,
            signatureOnly: true,
        );
    }

    /** A handler that records whether it ran and the request it was handed, then returns a 200. */
    private function recordingHandler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public bool $called = false;
            public ?ServerRequestInterface $received = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;
                $this->received = $request;
                return new Response(200, [], 'ok');
            }
        };
    }

    private function header(): string
    {
        return Pca::b64u($this->pcactnJson);
    }

    public function testValidHeaderRunsHandlerAndAttachesVerdict(): void
    {
        $handler = $this->recordingHandler();
        $request = new ServerRequest('POST', '/resource', [PcaMiddleware::HEADER => $this->header()]);

        $response = $this->middleware()->process($request, $handler);

        $this->assertTrue($handler->called, 'the handler should run for a valid PCActn');
        $this->assertSame(200, $response->getStatusCode());

        $verdict = $handler->received?->getAttribute('pca');
        $this->assertIsArray($verdict);
        $this->assertTrue($verdict['allow']);
        $this->assertSame('', $verdict['reason']);
        $this->assertTrue($verdict['checks']['leaf_signature']);
    }

    public function testValidBodyRunsHandlerAndAttachesVerdict(): void
    {
        $handler = $this->recordingHandler();
        $request = (new ServerRequest('POST', '/resource'))
            ->withBody(Utils::streamFor('{"pcactn":' . $this->pcactnJson . '}'));

        $response = $this->middleware()->process($request, $handler);

        $this->assertTrue($handler->called, 'the handler should run for a valid PCActn in the body');
        $this->assertSame(200, $response->getStatusCode());
        $this->assertTrue($handler->received?->getAttribute('pca')['allow']);
    }

    /**
     * R6-01 parity: body mode strict-parses the WHOLE {"pcactn":...} envelope like the reference defaultExtract, so the
     * envelope counts toward MAX_JSON_DEPTH (32) and a duplicate key anywhere is refused before verification.
     */
    public function testBodyEnvelopeIsStrictWithTheDepthCapOverTheWholeEnvelope(): void
    {
        $body = fn (int $n): string => '{"x":' . str_repeat('[', $n) . str_repeat(']', $n) . ',"pcactn":' . $this->pcactnJson . '}';
        $run = function (string $text): array {
            $handler = $this->recordingHandler();
            $response = $this->middleware()->process((new ServerRequest('POST', '/r'))->withBody(Utils::streamFor($text)), $handler);
            return [$handler->called, $response->getStatusCode(), json_decode((string)$response->getBody(), true)];
        };
        [$called, $status] = $run($body(31)); // envelope depth 32
        $this->assertTrue($called);
        $this->assertSame(200, $status);
        foreach ([
            $body(32), // envelope depth 33
            $body(100000),
            '{"pcactn":' . $this->pcactnJson . ',"pcactn":' . $this->pcactnJson . '}',
            '{"pcactn":' . substr($this->pcactnJson, 0, -1) . ',"aud":"evil"}}',
        ] as $i => $text) {
            [$called, $status, $err] = $run($text);
            $this->assertFalse($called, "case $i");
            $this->assertSame(401, $status, "case $i");
            $this->assertSame('request body is not valid strict JSON', $err['error_description'], "case $i");
        }
    }

    public function testMissingPcactnIsUnauthorizedWithChallenge(): void
    {
        $handler = $this->recordingHandler();
        $request = new ServerRequest('GET', '/resource');

        $response = $this->middleware()->process($request, $handler);

        $this->assertFalse($handler->called, 'the handler must not run without a PCActn');
        $this->assertSame(401, $response->getStatusCode());
        $this->assertStringStartsWith('PCA realm="pca"', $response->getHeaderLine('WWW-Authenticate'));
        $body = json_decode((string)$response->getBody(), true);
        $this->assertSame('invalid_request', $body['error']);
    }

    public function testUndecodableHeaderIsUnauthorized(): void
    {
        $handler = $this->recordingHandler();
        $request = new ServerRequest('POST', '/resource', [PcaMiddleware::HEADER => 'not valid base64url!!']);

        $response = $this->middleware()->process($request, $handler);

        $this->assertFalse($handler->called);
        $this->assertSame(401, $response->getStatusCode());
        $this->assertStringContainsString('error="invalid_request"', $response->getHeaderLine('WWW-Authenticate'));
    }

    public function testUnknownGrantIsUnauthorized(): void
    {
        $handler = $this->recordingHandler();
        $request = new ServerRequest('POST', '/resource', [PcaMiddleware::HEADER => $this->header()]);

        // A resolver that knows no grants at all.
        $response = $this->middleware(null, fn (string $ref): mixed => null)->process($request, $handler);

        $this->assertFalse($handler->called, 'the handler must not run when the grant is unknown');
        $this->assertSame(401, $response->getStatusCode());
        $body = json_decode((string)$response->getBody(), true);
        $this->assertSame('unknown_grant', $body['error']);
    }

    public function testThrowingResolverFailsClosed(): void
    {
        $handler = $this->recordingHandler();
        $request = new ServerRequest('POST', '/resource', [PcaMiddleware::HEADER => $this->header()]);

        // 0.4.2 audit: a resolver that throws must fail closed (403), never escape as an uncaught 500.
        $response = $this->middleware(null, fn (string $ref): mixed => throw new \RuntimeException('db down'))->process($request, $handler);

        $this->assertFalse($handler->called);
        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame('PCA realm="pca", error="insufficient_authority"', $response->getHeaderLine('WWW-Authenticate'));
        $body = json_decode((string)$response->getBody(), true);
        $this->assertSame('grant resolution failed (fail closed)', $body['error_description']);
    }

    public function testWrongAudienceIsForbidden(): void
    {
        $handler = $this->recordingHandler();
        $request = new ServerRequest('POST', '/resource', [PcaMiddleware::HEADER => $this->header()]);

        $response = $this->middleware('some-other-resource-server')->process($request, $handler);

        $this->assertFalse($handler->called, 'the handler must not run for the wrong audience');
        $this->assertSame(403, $response->getStatusCode());
        $this->assertStringContainsString('error="insufficient_authority"', $response->getHeaderLine('WWW-Authenticate'));
        $body = json_decode((string)$response->getBody(), true);
        $this->assertSame('insufficient_authority', $body['error']);
        $this->assertFalse($body['checks']['audience']);
        $this->assertStringContainsString('audience', $body['reason']);
    }

    public function testLaravelStyleHandleRunsNextOnSuccess(): void
    {
        $ran = false;
        $request = new ServerRequest('POST', '/resource', [PcaMiddleware::HEADER => $this->header()]);

        $response = $this->middleware()->handle($request, function (ServerRequestInterface $req) use (&$ran): ResponseInterface {
            $ran = true;
            $this->assertTrue($req->getAttribute('pca')['allow']);
            return new Response(204);
        });

        $this->assertTrue($ran, 'Closure $next should run on a valid PCActn');
        $this->assertSame(204, $response->getStatusCode());
    }

    public function testLaravelStyleHandleShortCircuitsOnFailure(): void
    {
        $ran = false;
        $request = new ServerRequest('GET', '/resource');

        $response = $this->middleware()->handle($request, function () use (&$ran): ResponseInterface {
            $ran = true;
            return new Response(200);
        });

        $this->assertFalse($ran, 'Closure $next must not run without a PCActn');
        $this->assertSame(401, $response->getStatusCode());
    }
}
