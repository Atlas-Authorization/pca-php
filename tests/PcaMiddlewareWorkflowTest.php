<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** The workflow option through PcaMiddleware (body member `workflow`, a per-request callback, required, absent), from authorize-workflow-fixtures.json. */
final class PcaMiddlewareWorkflowTest extends TestCase
{
    private Obj $F;

    protected function setUp(): void
    {
        $this->F = Json::parseLax(file_get_contents(__DIR__ . '/../conformance/authorize-workflow-fixtures.json'));
    }

    private function step(string $case, int $i = 0): Obj
    {
        foreach ($this->F->get('cases') as $c) {
            if ($c->get('name') === $case) {
                return $c->get('steps')[$i];
            }
        }
        self::fail("fixture case $case");
    }

    /** @param bool|callable $call true: the body member `workflow`; callable: the per-request reader; false: no workflow option */
    private function mw(Obj $s, bool $required, mixed $call, ?MemoryStateStore $store = null): PcaMiddleware
    {
        $grant = $this->F->get('grant');
        $f = new HttpFactory();
        $opts = new AuthorizeOptions(
            $store ?? new MemoryStateStore(), static fn () => false, static fn () => $s->get('operation'), null,
            fn () => Obj::of(['plan' => $this->F->get('plan'), 'plan_authorized' => true]),
            workflow: $call === false ? null : Obj::of(['principal' => $this->F->get('principal'), 'rsSigner' => $this->F->get('rs_signer'), 'required' => $required]),
            workflowCall: is_callable($call) ? $call : null,
            provenanceMediators: [ProvHarness::pin()],
            provenanceBundle: ProvHarness::reader(),
        );
        return new PcaMiddleware($this->F->get('audience'), static fn ($ref) => $ref === $grant->get('id') ? $grant : null,
            fn (): int => \Atlas\Pca\Workflow::iv($this->F->get('now')), $f, $f, authorize: $opts);
    }

    private function req(Obj $s, bool $withWorkflow = true): ServerRequestInterface
    {
        $m = ['pcactn' => $s->get('pcactn')];
        if ($withWorkflow && $s->get('workflow') !== null) {
            $m['workflow'] = $s->get('workflow');
        }
        return new ServerRequest('POST', '/r', [], Json::canonicalizeStrict(Obj::of($m)));
    }

    private function handler(): object
    {
        return new class implements RequestHandlerInterface {
            public bool $called = false;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->called = true;
                return new Response(200);
            }
        };
    }

    public function testBodyStepValidPasses(): void
    {
        $s = $this->step('pay-after-quote');
        $store = new MemoryStateStore();
        $h = $this->handler();
        $r = $this->mw($s, false, true, $store)->process($this->req($s), $h);
        $this->assertSame(200, $r->getStatusCode());
        $this->assertTrue($h->called);
    }

    public function testCallbackStepValidPasses(): void
    {
        $s = $this->step('pay-after-quote');
        $h = $this->handler();
        $r = $this->mw($s, true, static fn () => $s->get('workflow'))->process($this->req($s, false), $h);
        $this->assertSame(200, $r->getStatusCode());
        $this->assertTrue($h->called);
    }

    public function testEdgeViolationIs403(): void
    {
        $s = $this->step('amount-over-the-quote');
        $h = $this->handler();
        $r = $this->mw($s, false, true)->process($this->req($s), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertFalse($h->called);
        $this->assertSame('workflow: edge_relation (step pay)', json_decode((string)$r->getBody(), true)['reason']);
    }

    public function testRequiredAndAbsentIs403(): void
    {
        $s = $this->step('workflow-required-but-absent');
        $h = $this->handler();
        $r = $this->mw($s, true, true)->process($this->req($s), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertFalse($h->called);
        $this->assertSame('workflow: this call carries no workflow step (fail closed)', json_decode((string)$r->getBody(), true)['reason']);
    }

    public function testRequiredAndAbsentComesBeforeDecoding(): void
    {
        $s = $this->step('workflow-required-but-absent');
        $r = $this->mw($s, true, true)->process(new ServerRequest('POST', '/r', [PcaMiddleware::HEADER => 'not valid base64url!!']), $this->handler());
        $this->assertSame(403, $r->getStatusCode());
    }

    public function testUndecodableWithAStepIsTheWireRefusal(): void
    {
        $s = $this->step('pay-after-quote');
        $r = $this->mw($s, true, static fn () => $s->get('workflow'))->process(new ServerRequest('POST', '/r', [PcaMiddleware::HEADER => 'not valid base64url!!']), $this->handler());
        $this->assertSame(401, $r->getStatusCode());
        $this->assertSame('invalid_request', json_decode((string)$r->getBody(), true)['error']);
    }

    public function testThrowingCallbackFailsClosed(): void
    {
        $s = $this->step('pay-after-quote');
        $h = $this->handler();
        $r = $this->mw($s, false, static fn () => throw new \RuntimeException('x'))->process($this->req($s), $h);
        $this->assertSame(403, $r->getStatusCode());
        $this->assertFalse($h->called);
    }

    public function testNoWorkflowOptionIsUnchanged(): void
    {
        $s = $this->step('amount-over-the-quote'); // the edge violation is the gate's alone: without the option the call passes
        $h = $this->handler();
        $r = $this->mw($s, false, false)->process($this->req($s), $h);
        $this->assertSame(200, $r->getStatusCode());
        $this->assertTrue($h->called);
    }
}
