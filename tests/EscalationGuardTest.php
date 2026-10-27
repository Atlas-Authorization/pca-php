<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Decision;
use Atlas\Pca\Escalation;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use Atlas\Pca\PdoStateStore;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The ternary decision of the guard (security contract C-50 / C-51): a verdict whose EVERY failing check is escalate-class is
 * `escalate` (refused, never `allow`); a principal-signed EscalationAnswer bound to this grant, this exact PCActn and the
 * holder's history admits it once (the replay claim spends it); an answer never upgrades a deny. The escalate-class failure
 * is injected into the core verdict through the Authorize::$coreHook test seam over a genuinely signed fixture.
 */
final class EscalationGuardTest extends TestCase
{
    private Obj $fix;
    private Obj $case;
    private string $principalSk;
    private string $principalPk;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $this->case = $c;
            }
        }
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca/escalation-guard-test', true));
        $this->principalSk = sodium_crypto_sign_secretkey($kp);
        $this->principalPk = Pca::b64u(sodium_crypto_sign_publickey($kp));
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    private function now(): int
    {
        return $this->fix->get('now')->int();
    }

    /** Inject an escalate-class failure (and, with $hard, a hard failure) into the core verdict. */
    private function inject(bool $hard = false): void
    {
        Authorize::$coreHook = static function (array $core) use ($hard): array {
            $core['allow'] = false;
            $core['checks']['intent'] = false;
            $core['reasons'][] = 'intent: intent_required: a question must be answered';
            if ($hard) {
                $core['checks']['chain'] = false;
                $core['reasons'][] = 'chain: bad hop';
            }
            $core['reason'] = $core['reasons'][0];
            return $core;
        };
    }

    private function az(?object $store = null, mixed $principals = null, mixed $answer = null, ?string $caseName = null): AuthorizeResult
    {
        $c = $this->case;
        $s = $c->get('steps')[0];
        $g = $c->get('grant');
        return Authorize::authorize($s->get('pcactn'), $s->get('operation'), $this->fix->get('audience'),
            fn ($ref) => $ref === $g->get('id') ? $g : null, $store ?? new MemoryStateStore(), fn () => false, $this->now(), 'single-step',
            null, null, null, null, [], $principals, $answer);
    }

    /** The principal's signed answer to the request the guard put out. */
    private function answerTo(Obj $request, string $decision = 'allow', array $over = []): Obj
    {
        $body = Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-escalation-answer', 'principal' => $this->principalPk,
            'policy_digest' => $request->get('policy_digest'), 'action_digest' => $request->get('action_digest'),
            'history_head' => $request->get('history_head'), 'decision' => $decision,
            'iat' => new Num((string)($this->now() - 1000)), 'expires_at' => new Num((string)($this->now() + 60000)),
            'nonce' => Pca::b64u(str_repeat("\x07", 16)),
        ]);
        foreach ($over as $k => $v) {
            $body->set($k, $v);
        }
        $signed = Escalation::signAnswer($body, $this->principalSk);
        $this->assertNotNull($signed, 'the test answer is well-formed');
        return $signed;
    }

    public function testEscalateIsSurfacedAndNeverAnAllow(): void
    {
        $this->inject();
        $r = $this->az();
        $this->assertSame([false, 'escalate', 403], [$r->allow, $r->decision, $r->status]);
        $this->assertInstanceOf(Obj::class, $r->escalation);
        $this->assertSame('pca-escalation-request', $r->escalation->get('kind'));
        $this->assertSame(Escalation::policyDigest($this->case->get('grant')), $r->escalation->get('policy_digest'));
        $this->assertSame('payments.send', $r->escalation->get('verb'));
        $this->assertSame('payments/acme', $r->escalation->get('resource'));
        $this->assertSame(['intent: intent_required: a question must be answered'], $r->escalation->get('reasons'));
        $this->assertSame('fail', $r->checks['intent']);
    }

    public function testNoAnswerOrNoPrincipalStaysEscalate(): void
    {
        $this->inject();
        $this->assertSame('escalate', $this->az(new MemoryStateStore(), [$this->principalPk], null)->decision);
        $req = $this->az()->escalation;
        $ans = $this->answerTo($req);
        $r = $this->az(new MemoryStateStore(), null, $ans); // an answer but no pinned principal
        $this->assertSame([false, 'escalate'], [$r->allow, $r->decision]);
        $r = $this->az(new MemoryStateStore(), [], $ans);
        $this->assertSame('escalate', $r->decision);
    }

    public function testABoundAnswerAdmitsOnceAndTheCounterSpendsIt(): void
    {
        $this->inject();
        $store = new MemoryStateStore();
        $req = $this->az($store)->escalation;
        $ans = $this->answerTo($req);
        $r = $this->az($store, [$this->principalPk], $ans);
        $this->assertSame([true, 'allow', 200], [$r->allow, $r->decision, $r->status]);
        $this->assertSame($this->principalPk, $r->escalation->get('answered_by'));
        $this->assertSame('pass', $r->checks['escalation']);
        $this->assertSame('pass', $r->checks['intent']);
        $this->assertStringContainsString('escalation: answered allow by principal ' . substr($this->principalPk, 0, 8), implode("\n", $r->reasons));
        $this->assertSame('payments.send', $r->operation->verb);
        // the counter is spent: the same answer cannot admit the same PCActn again (history head moved on)
        $again = $this->az($store, [$this->principalPk], $ans);
        $this->assertSame([false, 'escalate'], [$again->allow, $again->decision]);
        $this->assertStringContainsString('another state of the history', implode("\n", $again->reasons));
    }

    public function testTheAnswerMayArriveAsJsonText(): void
    {
        $this->inject();
        $store = new MemoryStateStore();
        $ans = $this->answerTo($this->az($store)->escalation);
        $r = $this->az($store, [$this->principalPk], Json::canonicalizeStrict($ans));
        $this->assertSame('allow', $r->decision);
        $r = $this->az(new MemoryStateStore(), [$this->principalPk], '{"not":json');
        $this->assertSame('escalate', $r->decision);
    }

    public function testWrongBindingsAndWindowsAreRefused(): void
    {
        $this->inject();
        $req = $this->az()->escalation;
        $other = Pca::b64u(str_repeat("\x01", 32));
        $cases = [
            'another policy' => $this->answerTo($req, 'allow', ['policy_digest' => $other]),
            'another action' => $this->answerTo($req, 'allow', ['action_digest' => $other]),
            'another state of the history' => $this->answerTo($req, 'allow', ['history_head' => $other]),
            'the answer has expired' => $this->answerTo($req, 'allow', ['iat' => new Num((string)($this->now() - 5000)),
                'expires_at' => new Num((string)($this->now() - 1))]),
            'from the future' => $this->answerTo($req, 'allow', ['iat' => new Num((string)($this->now() + 1000)),
                'expires_at' => new Num((string)($this->now() + 2000))]),
        ];
        foreach ($cases as $why => $ans) {
            $r = $this->az(new MemoryStateStore(), [$this->principalPk], $ans);
            $this->assertSame([false, 'escalate'], [$r->allow, $r->decision], $why);
            $this->assertStringContainsString($why, implode("\n", $r->reasons), $why);
        }
        $r = $this->az(new MemoryStateStore(), [Pca::b64u(str_repeat("\x02", 32))], $this->answerTo($req));
        $this->assertSame('escalate', $r->decision);
        $this->assertStringContainsString('not pinned', implode("\n", $r->reasons));
    }

    public function testADenyAnswerNeverAdmits(): void
    {
        $this->inject();
        $store = new MemoryStateStore();
        $ans = $this->answerTo($this->az($store)->escalation, 'deny');
        $r = $this->az($store, [$this->principalPk], $ans);
        $this->assertSame([false, 'escalate'], [$r->allow, $r->decision]);
        $this->assertStringContainsString('the principal answered deny', implode("\n", $r->reasons));
    }

    public function testAHardFailureIsADenyEvenWithAValidAnswer(): void
    {
        $this->inject(true);
        $store = new MemoryStateStore();
        $r = $this->az($store);
        $this->assertSame([false, 'deny', null], [$r->allow, $r->decision, $r->escalation]);
        $this->inject();
        $ans = $this->answerTo($this->az($store)->escalation);
        $this->inject(true);
        $r = $this->az($store, [$this->principalPk], $ans);
        $this->assertSame([false, 'deny', null], [$r->allow, $r->decision, $r->escalation]);
    }

    public function testAStoreWithoutLastCannotAdmitAnAnswer(): void
    {
        $this->inject();
        $store = new class {
            public function claim(string $key, int $counter): \Atlas\Pca\ClaimResult
            {
                return new \Atlas\Pca\ClaimResult(true);
            }
        };
        $r = $this->az($store, [$this->principalPk], null);
        $this->assertSame([false, 'deny', 403], [$r->allow, $r->decision, $r->status]);
        $this->assertSame(['stateStore.last (escalation answers are bound to the holder history)'], $r->missing);
        $threw = false;
        try {
            new AuthorizeOptions($store, fn () => false, escalationPrincipals: [$this->principalPk]);
        } catch (\InvalidArgumentException) {
            $threw = true;
        }
        $this->assertTrue($threw, 'refused at construction');
        $ok = new AuthorizeOptions(new MemoryStateStore(), fn () => false, escalationPrincipals: [$this->principalPk]);
        $this->assertSame([$this->principalPk], $ok->escalationPrincipals);
    }

    public function testThePdoStoreCarriesTheHistoryHead(): void
    {
        $this->inject();
        $store = new PdoStateStore(new \PDO('sqlite::memory:'));
        $store->createTable();
        $ans = $this->answerTo($this->az($store)->escalation);
        $this->assertSame('allow', $this->az($store, [$this->principalPk], $ans)->decision);
        $this->assertSame(1, $store->last(Authorize::stateKey($this->case->get('grant')->get('id'),
            $this->case->get('steps')[0]->get('pcactn')->get('cap_chain')[0]->get('holder'))) ?? 1);
    }

    public function testAnAnswerUnderAnUnsupportedSuiteIsRefused(): void
    {
        $r = Escalation::verifyAnswer(Obj::of(['alg' => 'no-such-suite']), [$this->principalPk], [], $this->now());
        $this->assertFalse($r['ok']);
        $req = $this->answerTo(Obj::of(['policy_digest' => Pca::b64u(str_repeat("\x03", 32)),
            'action_digest' => Pca::b64u(str_repeat("\x04", 32)), 'history_head' => Pca::b64u(str_repeat("\x05", 32))]));
        $weird = $req->without('sig');
        $weird->set('alg', 'no-such-suite');
        $weird->set('sig', $req->get('sig'));
        $r = Escalation::verifyAnswer($weird, [$this->principalPk], [], $this->now());
        $this->assertSame(['ok' => false, 'reason' => "malformed escalation answer: unsupported_suite: 'no-such-suite'"], $r);
    }

    public function testNoEscalationWithoutTheInjectedFailure(): void
    {
        $r = $this->az();
        $this->assertSame([true, 'allow', null], [$r->allow, $r->decision, $r->escalation]);
    }

    // ---- the middleware: header / body carriers and the refusal body ----------------------------------------------------

    private function middleware(MemoryStateStore $store): PcaMiddleware
    {
        $f = new HttpFactory();
        $g = $this->case->get('grant');
        $opts = new AuthorizeOptions(
            stateStore: $store,
            isRevoked: fn () => false,
            operation: fn (ServerRequestInterface $r) => ['verb' => 'payments.send', 'resource' => 'payments/acme',
                'params' => Obj::of(['amount' => 50, 'currency' => 'usd'])],
            escalationPrincipals: [$this->principalPk],
        );
        return new PcaMiddleware($this->fix->get('audience'), fn ($ref) => $ref === $g->get('id') ? $g : null, fn () => $this->now(), $f, $f,
            authorize: $opts);
    }

    private function request(?Obj $answer = null, bool $inBody = false): ServerRequestInterface
    {
        $p = $this->case->get('steps')[0]->get('pcactn');
        $headers = [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))];
        $req = new ServerRequest('POST', '/pay', $headers);
        if ($answer !== null && !$inBody) {
            $req = $req->withHeader('PCA-Escalation-Answer', Pca::b64u(Json::canonicalizeStrict($answer)));
        }
        if ($answer !== null && $inBody) {
            $req = $req->withBody(Utils::streamFor('{"escalation_answer":' . Json::canonicalizeStrict($answer) . '}'));
        }
        return $req;
    }

    private function handler(): RequestHandlerInterface
    {
        return new class implements RequestHandlerInterface {
            public int $calls = 0;

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->calls++;
                return new Response(200, [], 'ok');
            }
        };
    }

    public function testMiddlewareRefusalBodyCarriesDecisionAndEscalation(): void
    {
        $this->inject();
        $h = $this->handler();
        $res = $this->middleware(new MemoryStateStore())->process($this->request(), $h);
        $b = json_decode((string)$res->getBody(), true);
        $this->assertSame(403, $res->getStatusCode());
        $this->assertSame('escalate', $b['decision']);
        $this->assertSame('pca-escalation-request', $b['escalation']['kind']);
        $this->assertSame(0, $h->calls);
    }

    public function testMiddlewareAcceptsTheAnswerFromHeaderAndBodyOnce(): void
    {
        $this->inject();
        foreach ([false, true] as $inBody) {
            $store = new MemoryStateStore();
            $h = $this->handler();
            $mw = $this->middleware($store);
            $b = json_decode((string)$mw->process($this->request(), $h)->getBody(), true);
            $req = Obj::of([]);
            foreach (['policy_digest', 'action_digest', 'history_head'] as $k) {
                $req->set($k, $b['escalation'][$k]);
            }
            $res = $mw->process($this->request($this->answerTo($req), $inBody), $h);
            $this->assertSame(200, $res->getStatusCode(), $inBody ? 'body' : 'header');
            $this->assertSame(1, $h->calls);
            $res = $mw->process($this->request($this->answerTo($req), $inBody), $h);
            $this->assertSame(403, $res->getStatusCode());
            $this->assertSame(1, $h->calls);
        }
    }

    public function testDecisionOfTheCoreVerdictIsOverTheWholeCheckSet(): void
    {
        $esc = ['intent' => 'fail', 'wire' => 'pass'];
        $r = ['intent: intent_required: q'];
        $this->assertSame('escalate', Decision::decisionOf(false, $esc, $r));
        $this->assertSame('deny', Decision::decisionOf(false, $esc + ['chain' => 'fail'], $r));
        $this->assertSame('deny', Decision::decisionOf(false, $esc + ['chain' => 'fail'], array_merge($r, ['chain: x'])));
        $this->assertSame('escalate', Decision::decisionOf(false, $esc + ['tighten' => 'fail'], array_merge($r, ['tighten: escalate: asked by tighten rule \'r\''])));
    }
}
