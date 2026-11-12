<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** F3: the gates that refuse before the guard (passport, linked template, adaptive policy) and never spend the replay counter. */
final class K05HardGatesTest extends TestCase
{
    private Obj $fix;
    private Obj $grant;
    private Obj $p;
    private Obj $op;

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

    /** The fixture grant with the default risk policy (non-zero weights) in its envelope. */
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

    private function az(Obj $grant, array $o = [], ?MemoryStateStore $store = null, ?Obj $pcactn = null): AuthorizeResult
    {
        return Authorize::authorize(...array_merge(['pcactn' => $pcactn ?? Json::parseLax(Json::canonicalizeStrict($this->p)), 'operation' => $this->op,
            'audience' => $this->fix->get('audience'), 'resolveGrant' => static fn($ref) => $grant, 'stateStore' => $store ?? new MemoryStateStore(),
            'isRevoked' => static fn() => false, 'now' => $this->fix->get('now')->int(), 'plan' => 'single-step', 'provenance' => ProvHarness::bundle($this->op),
            'provenanceMediators' => [ProvHarness::pin()], 'hard' => CalmRisk::hard()], $o, ['hard' => ($o['hard'] ?? []) + CalmRisk::hard()]));
    }

    private const NONE = ['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];

    public function testAPassportGateRefusesAMissingPassportBeforeTheCounterIsSpent(): void
    {
        $store = new MemoryStateStore();
        $gate = ['requirePassport' => ['trustedIssuers' => ['x'], 'revocation' => static fn() => false]];
        $r = $this->az($this->grant, ['hard' => $gate], $store);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['passport']);
        $this->assertSame('passport: malformed', $r->reason);
        $this->assertTrue($this->az($this->grant, [], $store)->allow, 'the refused call did not consume the counter');
    }

    public function testNoGateNoChange(): void
    {
        $this->assertTrue($this->az($this->grant)->allow);
    }

    public function testALinkedTemplateIsRequired(): void
    {
        $store = new MemoryStateStore();
        $r = $this->az($this->grant, ['hard' => ['requireLinkedTemplate' => Obj::of(['templates' => new Obj(), 'trusted' => []])]], $store);
        $this->assertFalse($r->allow);
        $this->assertSame('template: the grant carries no template_ref', $r->reason);
        $this->assertTrue($this->az($this->grant, [], $store)->allow);
        $noEnv = Json::parseLax(Json::canonicalizeStrict($this->grant));
        $noEnv->set('caveats', []);
        $r = $this->az($noEnv, ['hard' => ['requireLinkedTemplate' => static fn() => Obj::of(['templates' => new Obj(), 'trusted' => []])]]);
        $this->assertSame('template: the grant has no readable envelope', $r->reason);
    }

    public function testAnAdaptivePolicyCanOnlyNarrow(): void
    {
        $pol = static fn(float $t1, float $t2): array => ['bMax' => 1, 'kappa' => 1, 'lambda' => 0, 'rho' => 0, 'theta1' => $t1, 'theta2' => $t2,
            'weights' => ['alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05]];
        $weighted = Json::parseLax(Json::canonicalizeStrict($this->grant));
        foreach ($weighted->get('caveats') as $cv) {
            if ($cv->get('type') === 'envelope') {
                $cv->set('risk_policy', Json::parseLax('{"bMax":1,"kappa":1,"lambda":0,"rho":0,"theta1":0.25,"theta2":0.6,"weights":{"alpha":0.25,"beta":0.2,"delta":0.2,"epsilon":0.1,"gamma":0.2,"zeta":0.05}}'));
            }
        }
        $some = static fn() => ['semanticDistance' => 0.4] + self::NONE; // r = 0.1
        $with = static fn(?array $adaptive): array => ['hard' => ['risk' => $some, 'adaptivePolicy' => static fn(int $now) => $adaptive]];
        $this->assertTrue($this->az($weighted, $with(null))->allow);
        $this->assertTrue($this->az($weighted, $with($pol(0.5, 0.9)))->allow, 'a looser policy is ignored');
        $store = new MemoryStateStore();
        $r = $this->az($weighted, $with($pol(0.05, 0.5)), $store);
        $this->assertFalse($r->allow);
        $this->assertSame('adaptive: tightened policy requires threshold t=2 (grant policy: t=1)', $r->reason);
        $this->assertTrue($this->az($weighted, $with(null), $store)->allow, 'the early refusal did not spend the counter');
        $bad = $this->az($weighted, $with($pol(0.9, 0.1)));
        $this->assertFalse($bad->allow);
        $this->assertSame('adaptive: invalid policy (risk_policy requires 0 <= theta1 <= theta2)', $bad->reason);
    }

    private function clauses(array $over = []): array
    {
        $verb = $this->op->get('verb');
        return [Obj::of(['id' => 'p-all', 'kind' => 'permit', 'signer' => 'user', 'when' => Obj::of(['verb' => $verb])]),
            Obj::of(['id' => 'f-block', 'kind' => 'forbid', 'signer' => 'org', 'when' => Obj::of(['verb' => $over['forbidVerb'] ?? 'nothing.here'])])];
    }

    public function testAForbidRefusesBeforeTheCounterIsSpent(): void
    {
        $store = new MemoryStateStore();
        $deny = ['forbid' => ['clauses' => fn() => $this->clauses(['forbidVerb' => $this->op->get('verb')])]];
        $r = $this->az($this->grant, ['hard' => $deny], $store);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['forbid']);
        $this->assertSame('forbid: deny by forbid f-block', $r->reason);
        $allow = ['forbid' => ['clauses' => fn() => $this->clauses()]];
        $this->assertTrue($this->az($this->grant, ['hard' => $allow], $store)->allow, 'permit with no forbid matching');
    }

    public function testADefaultDenyNamesNothing(): void
    {
        $r = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => static fn() => []]]]);
        $this->assertSame('forbid: deny by none', $r->reason);
        $m = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => static fn() => 'x']]]);
        $this->assertSame('forbid: deny by malformed', $m->reason);
    }

    public function testACertificateIsRecomputedNotTrusted(): void
    {
        $hard = ['forbid' => ['clauses' => fn() => $this->clauses(), 'requireCertificate' => true]];
        $none = $this->az($this->grant, ['hard' => $hard]);
        $this->assertSame('forbid: the call carries no certificate (fail closed)', $none->reason);
        $ctx = Obj::of(['action' => Obj::of(['verb' => $this->op->get('verb'), 'resource' => $this->op->get('resource'), 'params' => $this->op->get('params')])]);
        $cert = \Atlas\Pca\ForbidCertificate::certify($this->clauses(), $ctx);
        $ok = $this->az($this->grant, ['hard' => $hard + ['forbidCertificate' => $cert]]);
        $this->assertTrue($ok->allow, implode('; ', $ok->reasons));
        $other = \Atlas\Pca\ForbidCertificate::certify($this->clauses(['forbidVerb' => 'zzz']), Obj::of(['action' => Obj::of(['verb' => 'other', 'resource' => 'r'])]));
        $bad = $this->az($this->grant, ['hard' => $hard + ['forbidCertificate' => $other]]);
        $this->assertFalse($bad->allow);
        $this->assertStringStartsWith('forbid: certificate refused (', $bad->reason);
    }
}
