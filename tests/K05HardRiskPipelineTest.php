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

/** F2 in the pipeline: the risk score, the budget admission, the threshold check and the signed caution floor. */
final class K05HardRiskPipelineTest extends TestCase
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
            'provenanceMediators' => [ProvHarness::pin()]], $o));
    }

    private const NONE = ['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];

    public function testAZeroWeightPolicyIsRiskFree(): void
    {
        $r = $this->az($this->grant);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertArrayNotHasKey('threshold', $r->checks);
    }

    public function testNoRiskInputsAreAssumedWorstAndAskForAStepUp(): void
    {
        $r = $this->az($this->weighted());
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['threshold']);
        $this->assertContains('policy: risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence', $r->reasons);
        $this->assertContains('threshold: t=3 (strong) required but no threshold verifier is enforced', $r->reasons);
        $this->assertContains('policy: risk 0.700 exceeds auto threshold: step-up to t=3', $r->reasons);
    }

    public function testServerRiskAtZeroIsMachineAdmitted(): void
    {
        $r = $this->az($this->weighted(), ['hard' => ['risk' => static fn() => self::NONE]]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertArrayNotHasKey('threshold', $r->checks);
    }

    public function testTheContextRiskAndTheServerRiskMergeRiskierPerInput(): void
    {
        $ctx = static fn() => ['risk' => Obj::of(['taint' => new Num('1')])];
        $r = $this->az($this->weighted(), ['context' => $ctx, 'hard' => ['risk' => static fn() => self::NONE]]);
        // taint 1 (the context's, riskier than the server's 0) adds delta 0.2 = 0.2 <= theta1: still machine-admitted
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $ctx2 = static fn() => ['risk' => Obj::of(['taint' => new Num('1'), 'blastRadius' => new Num('1')])];
        $r = $this->az($this->weighted(), ['context' => $ctx2, 'hard' => ['risk' => static fn() => self::NONE]]);
        $this->assertFalse($r->allow, 'r = 0.4 > theta1: t=2 needs a threshold verifier');
        $this->assertContains('threshold: t=2 (standard) required but no threshold verifier is enforced', $r->reasons);
    }

    public function testASignedCautionIsAFloorOnTheRisk(): void
    {
        $p = Json::parseLax(Json::canonicalizeStrict($this->p));
        $p->set('caution', new Num('0.9'));
        $risk = ['hard' => ['risk' => static fn() => self::NONE]];
        $r = $this->az($this->weighted(), $risk, null, $p);
        $this->assertFalse($r->allow);
        $this->assertContains('threshold: t=3 (strong) required but no threshold verifier is enforced', $r->reasons);
        $p->set('caution', new Num('0.1'));
        $this->assertTrue($this->az($this->weighted(), $risk, null, $p)->allow, 'a caution below the risk changes nothing');
    }

    public function testAnEnforcedThresholdHookAdmitsAStepUp(): void
    {
        $p = Json::parseLax(Json::canonicalizeStrict($this->p));
        $p->set('caution', new Num('0.9'));
        $mk = static fn(array $h): array => ['hard' => ['risk' => static fn() => self::NONE, 'thresholdHook' => static fn() => $h]];
        $ok = $this->az($this->weighted(), $mk(['enforced' => true, 'ok' => true, 't' => 3]), null, $p);
        $this->assertTrue($ok->allow, implode('; ', $ok->reasons));
        $this->assertSame('pass', $ok->checks['threshold']);
        $below = $this->az($this->weighted(), $mk(['enforced' => true, 'ok' => true, 't' => 2]), null, $p);
        $this->assertFalse($below->allow);
        $this->assertContains('threshold: threshold hook enforced t=2 but the server requires t=3 (below the server-derived threshold; derive t from server-held data)', $below->reasons);
        $unreported = $this->az($this->weighted(), $mk(['enforced' => true, 'ok' => true]), null, $p);
        $this->assertContains('threshold: threshold hook enforced t=unreported but the server requires t=3 (below the server-derived threshold; derive t from server-held data)', $unreported->reasons);
        $rejected = $this->az($this->weighted(), $mk(['enforced' => true, 'ok' => false, 't' => 3]), null, $p);
        $this->assertContains('threshold: t=3 required and the threshold proof was rejected', $rejected->reasons);
        $silent = $this->az($this->weighted(), $mk(['enforced' => false, 'ok' => true, 't' => 3]), null, $p);
        $this->assertContains('threshold: t=3 (strong) required but no threshold verifier is enforced', $silent->reasons);
    }

    public function testTheBudgetDepletesAcrossCallsAndAReplayIsFree(): void
    {
        $store = new MemoryStateStore();
        $g = $this->weighted();
        $holder = $this->p->get('cap_chain')[count($this->p->get('cap_chain')) - 1]->get('holder');
        $key = Authorize::stateKey($g->get('id'), $holder);
        $store->claimWithBudget($key, 0, null, ['B' => 0.25, 'tau' => (float)$this->fix->get('now')->int(), 'asOf' => null]);
        $some = ['hard' => ['risk' => static fn() => ['semanticDistance' => 0.4] + self::NONE, 'seedBudget' => false]]; // r = 0.1, cost 0.1
        $mkp = function (int $counter): Obj {
            $p = Json::parseLax(Json::canonicalizeStrict($this->p));
            $p->set('counter', new Num((string)$counter));
            return $p;
        };
        $this->assertTrue($this->az($g, $some, $store, $mkp(1))->allow);
        $this->assertEqualsWithDelta(0.15, $store->budget($key)['B'], 1e-9);
        $replay = $this->az($g, $some, $store, $mkp(1));
        $this->assertFalse($replay->allow);
        $this->assertEqualsWithDelta(0.15, $store->budget($key)['B'], 1e-9, 'a replay spends nothing');
        $this->assertTrue($this->az($g, $some, $store, $mkp(2))->allow);
        $this->assertEqualsWithDelta(0.05, $store->budget($key)['B'], 1e-9);
        $out = $this->az($g, $some, $store, $mkp(3));
        $this->assertFalse($out->allow, 'the budget no longer covers 0.1');
        $this->assertContains('policy: trust budget depleted: human recharge required', $out->reasons);
        $this->assertEqualsWithDelta(0.05, $store->budget($key)['B'], 1e-9, 'a refused action spends nothing');
    }

    public function testRequiredRiskInputs(): void
    {
        $r = $this->az($this->grant, ['hard' => ['requireRiskInputs' => ['semanticDistance']]]);
        $this->assertSame('pass', $r->checks['risk_inputs'], 'the committed plan fills semanticDistance');
    }

    public function testAMissingRiskInputIsRefusedWhenRequired(): void
    {
        $r = $this->az($this->grant, ['hard' => ['requireRiskInputs' => ['taint', 'confidence']]]);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['risk_inputs']);
        $this->assertContains('risk_inputs: required risk input(s) not supplied by the server: taint, confidence', $r->reasons);
        $ok = $this->az($this->grant, ['hard' => ['requireRiskInputs' => ['taint'], 'risk' => static fn() => ['taint' => 0.2]]]);
        $this->assertSame('pass', $ok->checks['risk_inputs']);
    }
}
