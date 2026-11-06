<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizedOperation;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\Escalation;
use Atlas\Pca\ExecutorOptions;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\OperationStore;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\Refusals;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * k05 mutation kills for PcaMiddleware: the fresh_at option (constructor validation, per-request resolver), the workflow
 * pre-check, the authorize-path wiring (raw header text to the pipeline, intent policy merge, 401 code), the executor outcomes
 * (fresh and answered from the record) and the escalation answer readers.
 */
final class K05KillPcaMiddlewareTest extends TestCase
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

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    public function noFresh(Obj $p): ?Obj
    {
        return null;
    }

    private function now(): int
    {
        return $this->fix->get('now')->int();
    }

    /** The full authorize path over fixture case 0 (MiddlewareOptionsTest's setup), with extra options / constructor args. */
    private function mw(array $o = [], ?callable $resolveGrant = null, ?array $intentPolicy = null): PcaMiddleware
    {
        $f = new HttpFactory();
        $grant = $this->case->get('grant');
        $op = $this->case->get('steps')[0]->get('operation');
        $now = $this->now();
        return new PcaMiddleware($this->fix->get('audience'), $resolveGrant ?? (fn ($ref) => $grant), fn () => $now, $f, $f,
            intentPolicy: $intentPolicy,
            authorize: new AuthorizeOptions(...($o + ['stateStore' => new MemoryStateStore(), 'isRevoked' => fn () => false, 'operation' => fn () => $op]
                + ProvHarness::options())));
    }

    private function handler(string $body = '{"done":true}'): RequestHandlerInterface
    {
        return new class ($body) implements RequestHandlerInterface {
            public int $calls = 0;
            public ?ServerRequestInterface $got = null;

            public function __construct(private readonly string $body)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                $this->got = $request;
                return new Response(201, ['Content-Type' => 'application/json'], $this->body);
            }
        };
    }

    private function send(PcaMiddleware $mw, RequestHandlerInterface $h): ResponseInterface
    {
        return $mw->process(new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => $this->header]), $h);
    }

    private static function body(ResponseInterface $r): array
    {
        return json_decode((string)$r->getBody(), true);
    }

    // ---- fresh_at ---------------------------------------------------------------------------------------------------

    private function sigMw(mixed $freshAt): PcaMiddleware
    {
        $f = new HttpFactory();
        return new PcaMiddleware('aud', fn ($ref) => null, fn () => 0, $f, $f, signatureOnly: true, freshAt: $freshAt);
    }

    /** `{}` decodes to a PCActn object without grant_ref: the signature-only path answers 401 after the fresh_at step. */
    private function sendEmpty(PcaMiddleware $mw): ResponseInterface
    {
        return $mw->process(new ServerRequest('POST', '/x', [PcaMiddleware::HEADER => Pca::b64u('{}')]), $this->handler());
    }

    private function assertNoGrantRef(ResponseInterface $r): void
    {
        $this->assertSame(401, $r->getStatusCode());
        $b = self::body($r);
        $this->assertSame('invalid_request', $b['error']);
        $this->assertSame('PCActn has no grant_ref', $b['error_description']);
    }

    private function assertFreshAtRefused(ResponseInterface $r): void
    {
        $this->assertSame(403, $r->getStatusCode());
        $b = self::body($r);
        $this->assertSame('fresh_at_context_error', $b['error']);
        $this->assertSame('fresh_at policy unavailable (fail closed)', $b['error_description']);
    }

    public function testFreshAtConstructorAcceptsObjCallableNullAndRefusesAnythingElse(): void
    {
        foreach ([5, 'not-a-function-name', [1, 2]] as $bad) {
            try {
                $this->sigMw($bad);
                $this->fail('freshAt ' . json_encode($bad) . ' must be refused');
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('freshAt must be an Obj, a callable (Obj $pcactn): ?Obj, or null', $e->getMessage());
            }
        }
        // a static policy, a non-Closure callable (converted to a Closure), a Closure and none all construct and run
        $this->assertNoGrantRef($this->sendEmpty($this->sigMw(Obj::of(['signer' => 'x']))));
        $this->assertNoGrantRef($this->sendEmpty($this->sigMw([$this, 'noFresh'])));
        $this->assertNoGrantRef($this->sendEmpty($this->sigMw(fn (Obj $p) => null)));
        $this->assertNoGrantRef($this->sendEmpty($this->sigMw(null)));
    }

    public function testFreshAtResolverResultIsObjOrNullElseFailsClosed(): void
    {
        $seen = [];
        $this->assertNoGrantRef($this->sendEmpty($this->sigMw(function (Obj $p) use (&$seen) {
            $seen[] = $p;
            return Obj::of(['signer' => 'x']);
        })));
        $this->assertCount(1, $seen, 'the resolver runs once per request');
        $this->assertSame([], $seen[0]->keys());
        $this->assertNoGrantRef($this->sendEmpty($this->sigMw(fn (Obj $p) => null)));
        $this->assertFreshAtRefused($this->sendEmpty($this->sigMw(fn (Obj $p) => 'x')));
        $this->assertFreshAtRefused($this->sendEmpty($this->sigMw(fn (Obj $p) => ['signer' => 'x'])));
        $this->assertFreshAtRefused($this->sendEmpty($this->sigMw(function (Obj $p) {
            throw new \RuntimeException('store down');
        })));
    }

    // ---- workflow pre-check -----------------------------------------------------------------------------------------

    public function testWorkflowRequiredAsAnArrayRefusesACallWithoutAStep(): void
    {
        $mw = $this->mw(['workflow' => ['required' => true]]);
        $h = $this->handler();
        $r = $mw->process(new ServerRequest('POST', '/pay'), $h);
        $this->assertSame(403, $r->getStatusCode());
        $reason = 'workflow: this call carries no workflow step (fail closed)';
        $b = self::body($r);
        $this->assertSame('insufficient_authority', $b['error']);
        $this->assertSame($reason, $b['error_description']);
        $this->assertSame($reason, $b['reason']);
        $this->assertSame(['workflow' => 'fail'], $b['checks']);
        $this->assertSame('deny', $b['decision']);
        // a body that is not an object, or whose `workflow` is not an object, carries no step either
        foreach (['[1]', '{"workflow":5}', '{"workflow":[1]}'] as $text) {
            $r = $mw->process(new ServerRequest('POST', '/pay', [], $text), $h);
            $this->assertSame(403, $r->getStatusCode(), $text);
            $this->assertSame($reason, self::body($r)['reason'], $text);
        }
        $this->assertSame(0, $h->calls);
        // not required: the request goes on (here: no PCActn in the body)
        $r = $this->mw(['workflow' => ['required' => false]])->process(new ServerRequest('POST', '/pay'), $h);
        $this->assertSame(401, $r->getStatusCode());
    }

    // ---- authorize-path wiring --------------------------------------------------------------------------------------

    public function testTheHeaderCarrierHandsTheRawTextToThePipeline(): void
    {
        $seen = [];
        $mw = $this->mw(['k1' => function (ServerRequestInterface $r, mixed $p) use (&$seen) {
            $seen[] = $p;
            return new Obj();
        }]);
        $mw->process(new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => Pca::b64u('{}')]), $this->handler());
        $this->assertSame(['{}'], $seen);
    }

    public function testK1OwnValueIsMergedAsIs(): void
    {
        $m = (new \ReflectionClass(PcaMiddleware::class))->newInstanceWithoutConstructor();
        $k1Of = new \ReflectionMethod($m, 'k1Of');
        $k = $k1Of->invoke($m, new ServerRequest('GET', '/'), new Obj(), new AuthorizeOptions(k1: Obj::of(['narrow' => 'mine'])));
        $this->assertSame('mine', $k->get('narrow'));
    }

    public function testAnUnknownGrantIs401InvalidPcactn(): void
    {
        $h = $this->handler();
        $r = $this->send($this->mw([], fn ($ref) => null), $h);
        $this->assertSame(401, $r->getStatusCode());
        $this->assertSame('invalid_pcactn', self::body($r)['error']);
        $this->assertSame(0, $h->calls);
    }

    public function testApprovedGoalIsMergedIntoTheIntentPolicyNotOverIt(): void
    {
        $r = $this->send($this->mw(['approvedGoal' => ['goal_digest' => 'AAAA', 'policy_digest' => 'AAAA']], null,
            ['min_fidelity_ppm' => -1]), $this->handler());
        $this->assertSame(403, $r->getStatusCode());
        $this->assertStringContainsString('thresholds must be non-negative safe integers', (string)$r->getBody());
    }

    // ---- executor -----------------------------------------------------------------------------------------------------

    public function testExecutorHandsTheOperationToTheHandler(): void
    {
        $ops = new MemoryOperationStore();
        $h = $this->handler();
        $r = $this->send($this->mw(['executor' => new ExecutorOptions($ops)]), $h);
        $this->assertSame(201, $r->getStatusCode());
        $this->assertInstanceOf(AuthorizedOperation::class, $h->got->getAttribute('pca.operation'));
        $this->assertNull($h->got->getAttribute('pca'));
        $id = $h->got->getAttribute('pca.idempotency_key');
        $this->assertIsString($id);
        $this->assertNotNull($ops->get($id));
    }

    public function testExecutorRecordsABodyOfExactly4MiBAndOmitsALargerOne(): void
    {
        $ops = new MemoryOperationStore();
        $h = $this->handler(str_repeat('a', 4194304));
        $r = $this->send($this->mw(['executor' => new ExecutorOptions($ops)]), $h);
        $this->assertSame(201, $r->getStatusCode());
        $this->assertSame(4194304, strlen((string)$r->getBody()));
        $res = $ops->get($h->got->getAttribute('pca.idempotency_key'))->result;
        $this->assertTrue($res->has('body_b64'));
        $this->assertFalse($res->has('body_omitted'));

        $ops = new MemoryOperationStore();
        $h = $this->handler(str_repeat('a', 4194305));
        $r = $this->send($this->mw(['executor' => new ExecutorOptions($ops)]), $h);
        $this->assertSame(201, $r->getStatusCode());
        $this->assertSame('', (string)$r->getBody());
        $res = $ops->get($h->got->getAttribute('pca.idempotency_key'))->result;
        $this->assertFalse($res->has('body_b64'));
        $this->assertTrue($res->get('body_omitted'));
    }

    /** A first call commits, the record is rewritten, the retry is answered from it. @return array{0:ResponseInterface,1:string} */
    private function replayWith(array $changes): array
    {
        $ops = new MemoryOperationStore();
        $mw = $this->mw(['executor' => new ExecutorOptions($ops)]);
        $h = $this->handler();
        $this->assertSame(201, $this->send($mw, $h)->getStatusCode());
        $id = $h->got->getAttribute('pca.idempotency_key');
        $rec = $ops->get($id);
        $this->assertTrue($ops->transition($id, OperationRecord::COMMITTED, $rec->with($changes)));
        $r = $this->send($mw, $h);
        $this->assertSame(1, $h->calls, 'never re-run');
        return [$r, $id];
    }

    public function testExecutorOutcomesAnsweredFromTheRecord(): void
    {
        $cases = [
            [['state' => OperationRecord::FAILED, 'error' => 'boom'], 500, 'execution_failed', 'boom'],
            [['state' => OperationRecord::ABORTED, 'error' => 'stopped'], 409, 'operation_aborted', 'stopped'],
            [['state' => OperationRecord::UNCERTAIN, 'error' => 'unknown outcome'], 409, 'operation_uncertain', 'unknown outcome'],
            [['state' => OperationRecord::EXECUTING, 'executingAt' => $this->now()], 409, 'operation_in_progress',
                'another execution of this authorization is in flight'],
        ];
        foreach ($cases as [$changes, $status, $code, $desc]) {
            [$r, $id] = $this->replayWith($changes);
            $this->assertSame($status, $r->getStatusCode(), $code);
            $b = self::body($r);
            $this->assertSame($code, $b['error']);
            $this->assertSame($desc, $b['error_description']);
            $this->assertArrayHasKey('operation_id', $b, $code);
            $this->assertSame($id, $b['operation_id']);
        }
    }

    public function testACommittedRecordWithoutStatusContentTypeOrValidBodyAnswers200Empty(): void
    {
        foreach ([null, Obj::of(['body_b64' => '!!!']), Obj::of(['status' => 'x', 'content_type' => new Num('1')])] as $result) {
            [$r] = $this->replayWith(['result' => $result]);
            $this->assertSame(200, $r->getStatusCode());
            $this->assertFalse($r->hasHeader('Content-Type'));
            $this->assertSame('', (string)$r->getBody());
            $this->assertSame('true', $r->getHeaderLine('PCA-Replayed'));
        }
        [$r] = $this->replayWith(['result' => Obj::of(['status' => new Num('202'), 'content_type' => 'text/plain',
            'body_b64' => base64_encode('hi')])]);
        $this->assertSame([202, 'text/plain', 'hi'], [$r->getStatusCode(), $r->getHeaderLine('Content-Type'), (string)$r->getBody()]);
    }

    public function testAnOperationStoreFailureIsA403(): void
    {
        $ops = new class implements OperationStore {
            public function create(OperationRecord $rec): array
            {
                throw new \RuntimeException('down');
            }

            public function get(string $id): ?OperationRecord
            {
                return null;
            }

            public function transition(string $id, string $from, OperationRecord $next): bool
            {
                return false;
            }
        };
        $h = $this->handler();
        $r = $this->send($this->mw(['executor' => new ExecutorOptions($ops)]), $h);
        $this->assertSame(403, $r->getStatusCode());
        $b = self::body($r);
        $this->assertSame('insufficient_authority', $b['error']);
        $this->assertSame('executeAuthorized: the operation store failed (fail closed): down', $b['error_description']);
        $this->assertSame(0, $h->calls);
    }

    // ---- escalation answers (EscalationGuardTest's setup) -------------------------------------------------------------

    private function escCase(): Obj
    {
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                return $c;
            }
        }
        throw new \RuntimeException('fixture case missing');
    }

    /** @return array{0:string,1:string} [sk, pk b64u] */
    private static function principal(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca/escalation-guard-test', true));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private function injectEscalate(): void
    {
        Authorize::$coreHook = static function (array $core): array {
            $core['allow'] = false;
            $core['checks']['intent'] = false;
            $core['reasons'][] = 'intent: intent_required: a question must be answered';
            $core['reason'] = $core['reasons'][0];
            return $core;
        };
    }

    private function escMw(MemoryStateStore $store, ?\Closure $reader = null): PcaMiddleware
    {
        $f = new HttpFactory();
        $g = $this->escCase()->get('grant');
        $opts = new AuthorizeOptions(
            stateStore: $store,
            isRevoked: fn () => false,
            operation: fn (ServerRequestInterface $r) => ['verb' => 'payments.send', 'resource' => 'payments/acme',
                'params' => Obj::of(['amount' => 50, 'currency' => 'usd'])],
            escalationPrincipals: [self::principal()[1]],
            escalationAnswer: $reader,
            insecureUnboundApproval: true,
            provenanceMediators: [ProvHarness::pin()],
            provenanceBundle: ProvHarness::reader(),
        );
        return new PcaMiddleware($this->fix->get('audience'), fn ($ref) => $ref === $g->get('id') ? $g : null, fn () => $this->now(), $f, $f,
            authorize: $opts);
    }

    private function escRequest(?string $answerHeader = null): ServerRequestInterface
    {
        $p = $this->escCase()->get('steps')[0]->get('pcactn');
        $req = new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))]);
        return $answerHeader === null ? $req : $req->withHeader('PCA-Escalation-Answer', $answerHeader);
    }

    /** The refused escalate: the request in the body has plain JSON numbers. Returns the principal's signed allow answer to it. */
    private function escalateAndAnswer(PcaMiddleware $mw, RequestHandlerInterface $h): Obj
    {
        $res = $mw->process($this->escRequest(), $h);
        $this->assertSame(403, $res->getStatusCode());
        $b = self::body($res);
        $this->assertSame('escalate', $b['decision']);
        $this->assertSame(1, $b['escalation']['v']);
        $this->assertSame($this->now() + 3600000, $b['escalation']['expires_at']);
        [$sk, $pk] = self::principal();
        $body = Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-escalation-answer', 'principal' => $pk,
            'policy_digest' => $b['escalation']['policy_digest'], 'action_digest' => $b['escalation']['action_digest'],
            'history_head' => $b['escalation']['history_head'], 'decision' => 'allow',
            'iat' => new Num((string)($this->now() - 1000)), 'expires_at' => new Num((string)($this->now() + 60000)),
            'nonce' => Pca::b64u(str_repeat("\x07", 16)),
        ]);
        $signed = Escalation::signAnswer($body, $sk);
        $this->assertNotNull($signed);
        return $signed;
    }

    public function testTheHostAnswerReaderIsUsed(): void
    {
        $this->injectEscalate();
        $answer = null;
        $mw = $this->escMw(new MemoryStateStore(), function (ServerRequestInterface $r) use (&$answer) {
            return $answer;
        });
        $h = $this->handler();
        $answer = $this->escalateAndAnswer($mw, $h);
        $this->assertSame(201, $mw->process($this->escRequest(), $h)->getStatusCode());
        $this->assertSame(1, $h->calls);
    }

    public function testAHeaderAnswerUpToTheArtifactLimitIsRead(): void
    {
        $this->injectEscalate();
        foreach ([Pca::MAX_ARTIFACT_BYTES => 201, Pca::MAX_ARTIFACT_BYTES + 1 => 403] as $size => $status) {
            $mw = $this->escMw(new MemoryStateStore());
            $h = $this->handler();
            $text = Json::canonicalizeStrict($this->escalateAndAnswer($mw, $h));
            $text .= str_repeat(' ', $size - strlen($text));
            $this->assertSame($size, strlen($text));
            $res = $mw->process($this->escRequest(Pca::b64u($text)), $h);
            $this->assertSame($status, $res->getStatusCode(), "answer of $size bytes");
            $this->assertSame($status === 201 ? 1 : 0, $h->calls);
        }
    }

    private static function bareMw(): PcaMiddleware
    {
        $f = new HttpFactory();
        return new PcaMiddleware('aud', fn ($ref) => null, fn () => 0, $f, $f);
    }

    public function testAProvenanceHeaderThatDoesNotDecodeThrowsItsOwnError(): void
    {
        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage('the PCA-Provenance header is not base64url of UTF-8');
        (new \ReflectionMethod(PcaMiddleware::class, 'provenanceOf'))
            ->invoke(self::bareMw(), new ServerRequest('POST', '/x', ['PCA-Provenance' => '!!']));
    }

    public function testPlainConvertsTheMembersOfAList(): void
    {
        $out = (new \ReflectionMethod(PcaMiddleware::class, 'plain'))->invoke(null, [new Num('5'), Obj::of(['a' => 'x'])]);
        $this->assertSame(5, $out[0]);
        $this->assertInstanceOf(\stdClass::class, $out[1]);
        $this->assertSame('x', $out[1]->a);
    }

    public function testTheDocLinkFollowsTheReasonMemberBeforeTheDescription(): void
    {
        $res = (new \ReflectionMethod(PcaMiddleware::class, 'respond'))
            ->invoke(self::bareMw(), 403, 'insufficient_authority', 'not a table reason', ['reason' => 'replay: counter reused']);
        $b = json_decode((string)$res->getBody(), true);
        $this->assertSame('not a table reason', $b['error_description']);
        $this->assertSame(Refusals::DOCS . '/reference/refusals.md#replay', $b['doc']);
    }
}
