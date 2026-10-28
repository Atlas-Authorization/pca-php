<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AssuranceRequirement;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\ExecutorOptions;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\RevocationState;
use Atlas\Pca\RevocationStalenessPolicy;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The 0.5 options of the PSR-15 middleware (`AuthorizeOptions`): the approved goal (goal binding v3), revocation staleness, a
 * high-assurance requirement and the executor, with the same guard semantics as the other natives: a refusal never reaches the
 * handler and never advances the replay counter, a misconfiguration denies, and the executor answers a retry from the record.
 */
final class MiddlewareOptionsTest extends TestCase
{
    private Obj $fix;
    private Obj $case;
    private string $header;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $this->case = $this->fix->get('cases')[0]; // a signed irreversible payment
        $this->header = Pca::b64u(Json::canonicalizeStrict($this->case->get('steps')[0]->get('pcactn')));
    }

    private function mw(array $o = []): PcaMiddleware
    {
        $f = new HttpFactory();
        $grant = $this->case->get('grant');
        $op = $this->case->get('steps')[0]->get('operation');
        $now = $this->fix->get('now')->int();
        return new PcaMiddleware($this->fix->get('audience'), fn ($ref) => $grant, fn () => $now, $f, $f,
            authorize: new AuthorizeOptions(...($o + ['stateStore' => new MemoryStateStore(), 'isRevoked' => fn () => false, 'operation' => fn () => $op])));
    }

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public int $calls = 0;
            public ?ServerRequestInterface $got = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                $this->got = $request;
                return new Response(201, ['Content-Type' => 'application/json'], '{"done":true}');
            }
        };
    }

    private function send(PcaMiddleware $mw, RequestHandlerInterface $h): ResponseInterface
    {
        return $mw->process(new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => $this->header]), $h);
    }

    public function testApprovedGoalMisconfiguredFailsClosed(): void
    {
        $h = $this->handler();
        $r = $this->send($this->mw(['approvedGoal' => ['goal_digest' => 'AAAA', 'policy_digest' => 'AAAA']]), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame(0, $h->calls);
        $this->assertStringContainsString('approved_goal digests must be canonical base64url', json_decode((string)$r->getBody(), true)['error_description']);
    }

    public function testApprovedGoalTheGrantDoesNotOpenToDenies(): void
    {
        $g = Pca::b64u(str_repeat("\x01", 32));
        $h = $this->handler();
        $r = $this->send($this->mw(['approvedGoal' => ['goal_digest' => $g, 'policy_digest' => $g]]), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame(0, $h->calls);
    }

    public function testRevocationStalenessNeedsASourceAndDeniesStaleOrMissingState(): void
    {
        $h = $this->handler();
        $r = $this->send($this->mw(['revocationStaleness' => new RevocationStalenessPolicy(300000.0)]), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame(['revocationState (required by revocationStaleness)'], json_decode((string)$r->getBody(), true)['missing']);
        // the source returns nothing for an irreversible action: denied
        $r = $this->send($this->mw(['revocationStaleness' => new RevocationStalenessPolicy(300000.0),
            'revocationState' => fn (ServerRequestInterface $req, Obj $p, Obj $g): ?RevocationState => null]), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertStringContainsString('no verifiable (guardian-signed) revocation state', json_decode((string)$r->getBody(), true)['error_description']);
        $this->assertSame(0, $h->calls);
    }

    public function testRequireAssuranceDeniesBeforeTheCounterIsClaimed(): void
    {
        $store = new MemoryStateStore();
        $h = $this->handler();
        $r = $this->send($this->mw(['stateStore' => $store, 'requireAssurance' => new AssuranceRequirement(signature: 'pq')]), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertSame(0, $h->calls);
        $this->assertStringContainsString('post-quantum signatures required', json_decode((string)$r->getBody(), true)['error_description']);
        // the same PCActn is still unspent: it passes under no requirement
        $this->assertSame(201, $this->send($this->mw(['stateStore' => $store]), $h)->getStatusCode());
    }

    public function testExecutorRunsTheHandlerOnceAndAnswersARetryFromTheRecord(): void
    {
        $ops = new MemoryOperationStore();
        $mw = $this->mw(['executor' => new ExecutorOptions($ops)]);
        $h = $this->handler();
        $r1 = $this->send($mw, $h);
        $this->assertSame([201, '{"done":true}', ''], [$r1->getStatusCode(), (string)$r1->getBody(), $r1->getHeaderLine('PCA-Replayed')]);
        $this->assertNotNull($h->got->getAttribute('pca.idempotency_key'));
        $r2 = $this->send($mw, $h);
        $this->assertSame([201, '{"done":true}', 'true', 'application/json'],
            [$r2->getStatusCode(), (string)$r2->getBody(), $r2->getHeaderLine('PCA-Replayed'), $r2->getHeaderLine('Content-Type')]);
        $this->assertSame(1, $h->calls, 'the handler ran once');
        // without an executor the same retry is a replay denial
        $plain = $this->mw();
        $this->send($plain, $this->handler());
        $this->assertSame(403, $this->send($plain, $this->handler())->getStatusCode());
    }

    public function testExecutorRevokedBetweenAuthorizeAndExecuteAborts(): void
    {
        $answers = [false, true]; // authorize sees "not revoked", the pre-execution re-check sees "revoked"
        $h = $this->handler();
        $r = $this->send($this->mw(['executor' => new ExecutorOptions(new MemoryOperationStore()),
            'isRevoked' => function () use (&$answers) { return array_shift($answers) ?? true; }]), $h);
        $this->assertSame(409, $r->getStatusCode());
        $this->assertSame(0, $h->calls);
        $this->assertSame('operation_aborted', json_decode((string)$r->getBody(), true)['error']);
    }
}
