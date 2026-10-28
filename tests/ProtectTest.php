<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ClaimResult;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\Protect;
use Atlas\Pca\Refusals;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** `Protect::protect()` secure defaults, caller overrides, revocation, and the `doc` member of refusal bodies. */
final class ProtectTest extends TestCase
{
    private Obj $fix;
    private Obj $case;
    private string $header;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $this->case = $this->fix->get('cases')[0];
        $this->header = Pca::b64u(Json::canonicalizeStrict($this->case->get('steps')[0]->get('pcactn')));
    }

    private function opts(array $o = []): array
    {
        $f = new HttpFactory();
        $op = $this->case->get('steps')[0]->get('operation');
        $now = $this->fix->get('now')->int();
        return $o + [
            'audience' => $this->fix->get('audience'),
            'grants' => [$this->case->get('grant')],
            'operation' => fn () => $op,
            'clock' => fn () => $now,
            'responseFactory' => $f,
            'streamFactory' => $f,
        ];
    }

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public int $calls = 0;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                return new Response(201);
            }
        };
    }

    private function send(PcaMiddleware $mw, RequestHandlerInterface $h): ResponseInterface
    {
        return $mw->process(new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => $this->header]), $h);
    }

    public function testAllowsOnceThenRefusesTheReplayWithADocLink(): void
    {
        $p = Protect::protect($this->opts());
        $h = $this->handler();
        $this->assertSame(201, $this->send($p->middleware, $h)->getStatusCode());
        $r = $this->send($p->middleware, $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame(1, $h->calls);
        $body = json_decode((string)$r->getBody(), true);
        $this->assertSame(Refusals::explainRefusal($body['reason'])['docs'], $body['doc']);
        $this->assertStringStartsWith(Refusals::DOCS . '/reference/refusals.md#', $body['doc']);
    }

    public function testRevokeRefusesTheGrantAndAnExtraSourceAlsoCounts(): void
    {
        $id = $this->case->get('grant')->get('id');
        $p = Protect::protect($this->opts());
        $p->revoke($id);
        $h = $this->handler();
        $this->assertSame(403, $this->send($p->middleware, $h)->getStatusCode());
        $q = Protect::protect($this->opts(['isRevoked' => fn () => true]));
        $this->assertSame(403, $this->send($q->middleware, $h)->getStatusCode());
        $this->assertSame(0, $h->calls);
        // an extra source that does not answer false is a revocation (fail closed)
        $z = Protect::protect($this->opts(['isRevoked' => fn () => null]));
        $this->assertSame(403, $this->send($z->middleware, $h)->getStatusCode());
        $ok = Protect::protect($this->opts(['isRevoked' => fn () => false]));
        $this->assertSame(201, $this->send($ok->middleware, $h)->getStatusCode());
    }

    public function testGrantsCallableAndUnknownGrantNeverRuns(): void
    {
        $grant = $this->case->get('grant');
        $h = $this->handler();
        $a = Protect::protect($this->opts(['grants' => fn (string $ref) => $ref === $grant->get('id') ? $grant : null]));
        $this->assertSame(201, $this->send($a->middleware, $h)->getStatusCode());
        $b = Protect::protect($this->opts(['grants' => []]));
        $this->assertGreaterThanOrEqual(400, $this->send($b->middleware, $h)->getStatusCode());
        $this->assertSame(1, $h->calls);
    }

    public function testCallerOptionsWin(): void
    {
        $deny = new class {
            public function claim(string $key, int $counter): ClaimResult
            {
                return new ClaimResult(false, 0);
            }
        };
        $p = Protect::protect($this->opts(['stateStore' => $deny]));
        $h = $this->handler();
        $this->assertSame(403, $this->send($p->middleware, $h)->getStatusCode());
        $this->assertSame(0, $h->calls);
    }

    public function testBadOptionsThrow(): void
    {
        foreach (['audience', 'grants', 'operation'] as $k) {
            $o = $this->opts();
            unset($o[$k]);
            try {
                Protect::protect($o);
                $this->fail("missing $k");
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->expectException(\InvalidArgumentException::class);
        Protect::protect($this->opts(['grants' => ['not a grant']]));
    }

    public function testUnknownOptionIsAnError(): void
    {
        $this->expectException(\Error::class);
        Protect::protect($this->opts(['stateStoer' => 1]));
    }

    public function testEveryMiddlewareRefusalCarriesADoc(): void
    {
        $p = Protect::protect($this->opts());
        $r = $p->middleware->process(new ServerRequest('GET', '/pay'), $this->handler());
        $this->assertSame(401, $r->getStatusCode());
        $this->assertStringStartsWith(Refusals::DOCS . '/reference/refusals.md', json_decode((string)$r->getBody(), true)['doc']);
    }
}
