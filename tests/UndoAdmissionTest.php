<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Obligations;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The undo admission hook of authorize (undo windows): called only for an unanswered escalation that is not a provenance
 * escalation; an admission turns it into an allow under a veto window with the `undo_window` obligation. The escalate-class
 * failure is injected through the Authorize::$coreHook seam over a genuinely signed fixture.
 */
final class UndoAdmissionTest extends TestCase
{
    private Obj $fix;
    private Obj $case;
    /** @var list<array{0: Obj, 1: Obj, 2: array}> */
    private array $calls = [];

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $this->case = $c;
            }
        }
        $this->calls = [];
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    private function now(): int
    {
        return $this->fix->get('now')->int();
    }

    /** Inject a failing core check `$check` with an escalate-class reason (and, with $hard, a hard failure). */
    private static function inject(string $check = 'intent', bool $hard = false): void
    {
        Authorize::$coreHook = static function (array $core) use ($check, $hard): array {
            $core['allow'] = false;
            $core['checks'][$check] = false;
            $core['reasons'][] = "$check: escalate: asked for a confirmation";
            if ($hard) {
                $core['checks']['chain'] = false;
                $core['reasons'][] = 'chain: bad hop';
            }
            $core['reason'] = $core['reasons'][0];
            return $core;
        };
    }

    /** A hook that records its calls and admits (after the record is durably opened, in a real coordinator). */
    private function admitting(): \Closure
    {
        return function (Obj $p, Obj $grant, array $op): array {
            $this->calls[] = [$p, $grant, $op];
            return ['id' => 'op_1', 'window_end' => $this->now() + 900000, 'compensation' => ['verb' => 'payments.refund', 'resource' => 'payments/acme']];
        };
    }

    private function az(mixed $undo, bool $bundle = true, mixed $answer = null): AuthorizeResult
    {
        $s = $this->case->get('steps')[0];
        $g = $this->case->get('grant');
        $prov = $bundle ? ProvHarness::args($s->get('operation')) : [];
        return Authorize::authorize($s->get('pcactn'), $s->get('operation'), $this->fix->get('audience'),
            fn ($ref) => $ref === $g->get('id') ? $g : null, new MemoryStateStore(), fn () => false, $this->now(), 'single-step',
            ...$prov, escalationAnswer: $answer, undo: $undo);
    }

    public function testAdmissionAllowsUnderAVetoWindowWithTheObligation(): void
    {
        self::inject();
        $r = $this->az($this->admitting());
        $we = $this->now() + 900000;
        $this->assertSame([true, 'allow', 200, null], [$r->allow, $r->decision, $r->status, $r->escalation]);
        $this->assertSame(['pass', 'pass', 'pass'], [$r->checks['intent'], $r->checks['undo_window'], $r->checks['provenance_flow']]);
        $this->assertNotContains('fail', $r->checks);
        $this->assertContains("undo_window: runs now under a veto window until $we (compensation payments.refund)", $r->reasons);
        $this->assertSame(['op_1', $we, 'payments.refund'], [$r->undo->get('id'), $r->undo->get('window_end')->int(), $r->undo->get('compensation')->get('verb')]);
        $this->assertCount(1, $r->obligations);
        $ob = $r->obligations[0];
        $this->assertSame('{"due":' . $we . ',"kind":"undo_window","params":{"id":"op_1","window_end":' . $we . '}}', Json::canonicalizeStrict($ob));
        $this->assertNull(Obligations::error($ob));
        $this->assertCount(1, $this->calls);
        [$p, $grant, $op] = $this->calls[0];
        $this->assertSame($this->case->get('grant')->get('id'), $grant->get('id'));
        $this->assertSame($this->case->get('steps')[0]->get('pcactn')->get('nonce'), $p->get('nonce'));
        $this->assertSame(['payments.send', 'payments/acme', 50], [$op['verb'], $op['resource'], $op['params']->get('amount')->int()]);
    }

    public function testAProvenanceFlowEscalationNeverCallsTheHook(): void
    {
        $r = $this->az($this->admitting(), false);
        $this->assertSame([false, 'escalate', 'fail'], [$r->allow, $r->decision, $r->checks['provenance_flow']]);
        $this->assertSame([], $this->calls);
        $this->assertNull($r->undo);
        $this->assertArrayNotHasKey('undo_window', $r->checks);
    }

    public function testAnIntentRule17ProvenanceFailureNeverCallsTheHook(): void
    {
        self::inject('provenance');
        $r = $this->az($this->admitting());
        $this->assertSame([false, 'escalate', 'fail', 'pass'], [$r->allow, $r->decision, $r->checks['provenance'], $r->checks['provenance_flow']]);
        $this->assertSame([], $this->calls);
    }

    public function testAPresentedAnswerNeverCallsTheHook(): void
    {
        self::inject();
        $r = $this->az($this->admitting(), true, Obj::of(['kind' => 'pca-escalation-answer']));
        $this->assertSame([false, 'escalate'], [$r->allow, $r->decision]);
        $this->assertSame([], $this->calls);
    }

    public function testAHookThatThrowsOrDoesNotAdmitLeavesTheEscalation(): void
    {
        self::inject();
        $throws = function (): never {
            $this->calls[] = [];
            throw new \RuntimeException('the ledger is down');
        };
        foreach ([$throws, fn () => null, fn () => ['id' => 'op_1', 'window_end' => -1, 'compensation' => ['verb' => 'v', 'resource' => 'r']],
                     fn () => ['id' => str_repeat('i', 129), 'window_end' => 1, 'compensation' => ['verb' => 'v', 'resource' => 'r']],
                     fn () => ['id' => 'op_1', 'window_end' => 1], fn () => 'yes'] as $i => $hook) {
            $r = $this->az($hook);
            $this->assertSame([false, 'escalate', null, []], [$r->allow, $r->decision, $r->undo, $r->obligations], "hook $i");
            $this->assertSame('fail', $r->checks['intent']);
        }
        $this->assertCount(1, $this->calls);
    }

    public function testADenyNeverCallsTheHook(): void
    {
        self::inject('intent', true);
        $r = $this->az($this->admitting());
        $this->assertSame([false, 'deny'], [$r->allow, $r->decision]);
        $this->assertSame([], $this->calls);
    }

    public function testAnAllowNeverCallsTheHook(): void
    {
        $r = $this->az($this->admitting());
        $this->assertSame([true, null, []], [$r->allow, $r->undo, $r->obligations]);
        $this->assertSame([], $this->calls);
    }

    public function testTheMiddlewarePassesTheHook(): void
    {
        self::inject();
        $f = new HttpFactory();
        $g = $this->case->get('grant');
        $opts = new AuthorizeOptions(
            stateStore: new MemoryStateStore(),
            isRevoked: fn () => false,
            operation: fn (ServerRequestInterface $r) => ['verb' => 'payments.send', 'resource' => 'payments/acme',
                'params' => Obj::of(['amount' => 50, 'currency' => 'usd'])],
            provenanceMediators: [ProvHarness::pin()],
            provenanceBundle: ProvHarness::reader(),
            undo: $this->admitting(),
        );
        $mw = new PcaMiddleware($this->fix->get('audience'), fn ($ref) => $ref === $g->get('id') ? $g : null, fn () => $this->now(), $f, $f,
            authorize: $opts);
        $h = new class implements RequestHandlerInterface {
            public ?ServerRequestInterface $got = null;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->got = $request;
                return new Response(200, [], 'ok');
            }
        };
        $p = $this->case->get('steps')[0]->get('pcactn');
        $res = $mw->process(new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))]), $h);
        $this->assertSame(200, $res->getStatusCode());
        $az = $h->got->getAttribute('pca.authorization');
        $this->assertInstanceOf(AuthorizeResult::class, $az);
        $this->assertSame('op_1', $az->undo->get('id'));
        $this->assertSame('undo_window', $az->obligations[0]->get('kind'));
        $this->assertCount(1, $this->calls);
    }
}
