<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\ForbidCertificate;
use Atlas\Pca\InMemoryTaintRegistry;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
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

/** Every hardening option of AuthorizeOptions must reach the guard through PcaMiddleware (each is observed by its own effect). */
final class PcaMiddlewareHardOptionsKillTest extends TestCase
{
    private Obj $fix;
    private Obj $grant;
    private Obj $p;
    private Obj $op;

    private const NONE = ['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $this->grant = $c->get('grant');
                $this->p = $c->get('steps')[0]->get('pcactn');
                $this->op = $c->get('steps')[0]->get('operation');
            }
        }
        $all = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];
        Authorize::$coreHook = static fn(array $c): array => ['allow' => true, 'checks' => array_fill_keys($all, true), 'reason' => '', 'reasons' => []];
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    private function weighted(): Obj
    {
        $g = Json::parseLax(Json::canonicalizeStrict($this->grant));
        foreach ($g->get('caveats') as $cv) {
            if ($cv->get('type') === 'envelope') {
                $cv->set('risk_policy', Json::parseLax('{"bMax":1,"kappa":1,"lambda":0.0005,"rho":0.5,"theta1":0.25,"theta2":0.6,'
                    . '"weights":{"alpha":0.25,"beta":0.2,"delta":0.2,"epsilon":0.1,"gamma":0.2,"zeta":0.05}}'));
            }
        }
        return $g;
    }

    private function mw(Obj $grant, array $o = []): PcaMiddleware
    {
        $f = new HttpFactory();
        $op = $this->op;
        $now = $this->fix->get('now')->int();
        return new PcaMiddleware($this->fix->get('audience'), fn ($ref) => $grant, fn () => $now, $f, $f,
            authorize: new AuthorizeOptions(...($o + ['stateStore' => new MemoryStateStore(), 'isRevoked' => fn () => false, 'operation' => fn () => $op,
                'plan' => 'single-step'] + ProvHarness::options())));
    }

    /** @return array{0:int,1:array<string,mixed>} the status and the decoded body (a 201 is the handler's) */
    private function dispatch(PcaMiddleware $mw, ?Obj $p = null): array
    {
        $h = new class implements RequestHandlerInterface {
            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response(201, ['Content-Type' => 'application/json'], '{"done":true}');
            }
        };
        $p ??= $this->p;
        $r = $mw->process(new ServerRequest('POST', '/pay', [PcaMiddleware::HEADER => Pca::b64u(Json::canonicalizeStrict($p))]), $h);
        return [$r->getStatusCode(), json_decode((string)$r->getBody(), true)];
    }

    private function clauses(string $forbidVerb = 'nothing.here'): array
    {
        return [Obj::of(['id' => 'p-all', 'kind' => 'permit', 'signer' => 'user', 'when' => Obj::of(['verb' => $this->op->get('verb')])]),
            Obj::of(['id' => 'f-block', 'kind' => 'forbid', 'signer' => 'org', 'when' => Obj::of(['verb' => $forbidVerb])])];
    }

    public function testTheBaselineIsAllowed(): void
    {
        $this->assertSame(201, $this->dispatch($this->mw($this->grant))[0]);
    }

    public function testRiskReachesTheGuard(): void
    {
        $this->assertSame(201, $this->dispatch($this->mw($this->weighted(), ['risk' => static fn() => self::NONE]))[0]);
        [$status, $b] = $this->dispatch($this->mw($this->weighted()));
        $this->assertSame(403, $status, 'without a risk source every input is its worst case');
        $this->assertSame('fail', $b['checks']['threshold']);
    }

    public function testTheThresholdHookReachesTheGuard(): void
    {
        $p = Json::parseLax(Json::canonicalizeStrict($this->p));
        $p->set('caution', new Num('0.9'));
        $risk = static fn() => self::NONE;
        [$status, $b] = $this->dispatch($this->mw($this->weighted(), ['risk' => $risk]), $p);
        $this->assertSame(403, $status);
        $this->assertSame('fail', $b['checks']['threshold']);
        $hook = static fn() => ['enforced' => true, 'ok' => true, 't' => 3];
        $this->assertSame(201, $this->dispatch($this->mw($this->weighted(), ['risk' => $risk, 'thresholdHook' => $hook]), $p)[0]);
    }

    public function testSeedBudgetReachesTheGuard(): void
    {
        $risk = static fn() => ['semanticDistance' => 0.4] + self::NONE; // r = 0.1, cost 0.1
        $this->assertSame(201, $this->dispatch($this->mw($this->weighted(), ['risk' => $risk]))[0], 'the default seeds the full budget');
        $this->assertSame(201, $this->dispatch($this->mw($this->weighted(), ['risk' => $risk, 'seedBudget' => true]))[0]);
        [$status, $b] = $this->dispatch($this->mw($this->weighted(), ['risk' => $risk, 'seedBudget' => false]));
        $this->assertSame(403, $status, 'an unseeded holder has no budget');
        $this->assertSame('fail', $b['checks']['threshold']);
    }

    public function testRequireRiskInputsReachesTheGuard(): void
    {
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['requireRiskInputs' => ['taint', 'confidence']]));
        $this->assertSame(403, $status);
        $this->assertSame('fail', $b['checks']['risk_inputs']);
        $this->assertSame(201, $this->dispatch($this->mw($this->grant, ['requireRiskInputs' => ['taint'], 'risk' => static fn() => ['taint' => 0.2]]))[0]);
    }

    public function testRequirePassportAndThePresentedPassportReachTheGuard(): void
    {
        $req = ['trustedIssuers' => []];
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['requirePassport' => $req]));
        $this->assertSame(403, $status);
        $this->assertSame('fail', $b['checks']['passport']);
        $this->assertStringContainsString('passport: malformed', $b['reason']);
        $sp = Obj::of(['typ' => 'atlas-pca/passport', 'passport' => Obj::of([]), 'ver' => new Num('2')]);
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['requirePassport' => $req, 'passport' => static fn(ServerRequestInterface $r) => $sp]));
        $this->assertSame(403, $status);
        $this->assertStringContainsString('passport: unsupported_version', $b['reason'], 'the presented passport is the one verified');
    }

    public function testRequireLinkedTemplateReachesTheGuard(): void
    {
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['requireLinkedTemplate' => Obj::of([])]));
        $this->assertSame(403, $status);
        $this->assertSame('fail', $b['checks']['template']);
        $this->assertStringContainsString('template:', $b['reason']);
    }

    public function testAdaptivePolicyReachesTheGuard(): void
    {
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['adaptivePolicy' => static fn(int $now) => 'x']));
        $this->assertSame(403, $status);
        $this->assertSame('adaptive: invalid policy (risk_policy must be an object)', $b['reason']);
    }

    public function testForbidReachesTheGuard(): void
    {
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['forbid' => ['clauses' => fn() => $this->clauses($this->op->get('verb'))]]));
        $this->assertSame(403, $status);
        $this->assertSame('forbid: deny by forbid f-block', $b['reason']);
        $this->assertSame(201, $this->dispatch($this->mw($this->grant, ['forbid' => ['clauses' => fn() => $this->clauses()]]))[0]);
    }

    public function testTheForbidCertificateOfTheRequestReachesTheGuard(): void
    {
        $forbid = ['clauses' => fn() => $this->clauses(), 'requireCertificate' => true];
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['forbid' => $forbid]));
        $this->assertSame(403, $status);
        $this->assertSame('forbid: the call carries no certificate (fail closed)', $b['reason']);
        $ctx = Obj::of(['action' => Obj::of(['verb' => $this->op->get('verb'), 'resource' => $this->op->get('resource'), 'params' => $this->op->get('params')])]);
        $cert = ForbidCertificate::certify($this->clauses(), $ctx);
        $this->assertSame(201, $this->dispatch($this->mw($this->grant, ['forbid' => $forbid, 'forbidCertificate' => static fn(ServerRequestInterface $r) => $cert]))[0]);
    }

    public function testEnforceTaintReachesTheGuard(): void
    {
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['enforceTaint' => ['registry' => new InMemoryTaintRegistry(), 'maxTaint' => 0]]));
        $this->assertSame(403, $status);
        $this->assertSame('fail', $b['checks']['taint_gate']);
    }

    public function testBeaconReachesTheGuard(): void
    {
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['beacon' => static fn(string $ref, Obj $p) => null]));
        $this->assertSame(403, $status, 'an unavailable beacon denies (dead-man)');
        $this->assertSame('fail', $b['checks']['beacon']);
    }

    public function testContractsReachTheGuard(): void
    {
        $c = new class {
            public function peek(Obj $action): array
            {
                return ['allow' => false, 'reason' => 'violated', 'violated' => ['no-spend']];
            }

            public function check(Obj $action, bool $permitted): array
            {
                return ['allow' => false, 'reason' => 'violated', 'violated' => ['no-spend']];
            }
        };
        [$status, $b] = $this->dispatch($this->mw($this->grant, ['contracts' => $c]));
        $this->assertSame(403, $status);
        $this->assertSame('fail', $b['checks']['contract']);
    }
}
