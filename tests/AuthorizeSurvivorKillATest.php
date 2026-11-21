<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\AssuranceLabeler;
use Atlas\Pca\ForbidCertificate;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PolicyLink;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A store that only reports a scope. */
final class AuthorizeSurvivorKillAScopedStore
{
    public function __construct(private string $scope)
    {
    }

    public function scope(): string
    {
        return $this->scope;
    }
}

final class AuthorizeSurvivorKillAPinOnly
{
    public function pin(): void
    {
    }
}

final class AuthorizeSurvivorKillARaiseOnly
{
    public function raisePin(): void
    {
    }
}

final class AuthorizeSurvivorKillAStaticPins
{
    public static function pin(): void
    {
    }

    public static function raisePin(): void
    {
    }
}

final class AuthorizeSurvivorKillAStaticContracts
{
    public static function peek(Obj $a): mixed
    {
        return null;
    }

    public static function check(Obj $a, bool $permitted): mixed
    {
        return null;
    }
}

/** A built-in-style hardware verifier: it labels itself and hands out the attest callable. */
final class AuthorizeSurvivorKillAHardwareVerifier implements AssuranceLabeler
{
    public function __construct(private AssuranceLabel $label, private \Closure $attest)
    {
    }

    public function assurance(): AssuranceLabel
    {
        return $this->label;
    }

    public function attest(int $now): \Closure
    {
        return $this->attest;
    }
}

/** Exact-outcome tests for the options helpers, the risk decision, and the gates that refuse before the guard. */
final class AuthorizeSurvivorKillATest extends TestCase
{
    private Obj $fix;
    private Obj $grant;
    private Obj $p;
    private Obj $op;
    private int $coreCalls = 0;

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
        $this->coreCalls = 0;
        $all = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];
        Authorize::$coreHook = function (array $c) use ($all): array {
            $this->coreCalls++;
            return ['allow' => true, 'checks' => array_fill_keys($all, true), 'reason' => '', 'reasons' => []];
        };
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    private const NONE = ['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0];

    private function weighted(?Obj $base = null): Obj
    {
        $g = Json::parseLax(Json::canonicalizeStrict($base ?? $this->grant));
        foreach ($g->get('caveats') as $cv) {
            if ($cv->get('type') === 'envelope') {
                $cv->set('risk_policy', Json::parseLax('{"bMax":1,"kappa":1,"lambda":0,"rho":0,"theta1":0.25,"theta2":0.6,'
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

    // ------------------------------------------------------------------ options helpers

    public function testHoldsPinsNeedsAnObjectWithBothMethods(): void
    {
        $this->assertTrue(AuthorizeOptions::holdsPins(new MemoryStateStore()));
        $this->assertFalse(AuthorizeOptions::holdsPins(new AuthorizeSurvivorKillAPinOnly()));
        $this->assertFalse(AuthorizeOptions::holdsPins(new AuthorizeSurvivorKillARaiseOnly()));
        $this->assertFalse(AuthorizeOptions::holdsPins(AuthorizeSurvivorKillAStaticPins::class), 'a class name is not a store object');
        $this->assertFalse(AuthorizeOptions::holdsPins(null));
    }

    public function testMultiInstanceOptionWinsOverTheStoreScope(): void
    {
        $shared = new AuthorizeSurvivorKillAScopedStore('shared');
        $proc = new AuthorizeSurvivorKillAScopedStore('process');
        $this->assertFalse((new AuthorizeOptions(stateStore: $shared, multiInstance: false))->multiInstanceOn());
        $this->assertTrue((new AuthorizeOptions(stateStore: $shared, multiInstance: true))->multiInstanceOn());
        $this->assertTrue((new AuthorizeOptions(stateStore: $shared))->multiInstanceOn());
        $this->assertFalse((new AuthorizeOptions(stateStore: $proc))->multiInstanceOn());
        $this->assertFalse((new AuthorizeOptions())->multiInstanceOn());
    }

    public function testTheBudgetIsSeededByDefault(): void
    {
        $this->assertTrue((new AuthorizeOptions())->seedBudget);
    }

    // ------------------------------------------------------------------ risk decision (called directly)

    private function env(array $w = [], float $t1 = 0.25, float $t2 = 0.6): Obj
    {
        $weights = ['alpha' => 0, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0];
        foreach ($w as $k => $v) {
            $weights[$k] = $v;
        }
        return Obj::of(['risk_policy' => Obj::of(['bMax' => 1, 'kappa' => 1, 'lambda' => 0, 'rho' => 0, 'theta1' => $t1, 'theta2' => $t2,
            'weights' => Obj::of($weights)])]);
    }

    /** @return array<string,mixed> */
    private function rd(array $o = []): array
    {
        $d = $o + ['env' => $this->env(), 'ctx' => new Obj(), 'p' => new Obj(), 'grant' => Obj::of(['id' => 'g']), 'holder' => null, 'store' => null,
            'now' => 1000000, 'plan' => null, 'node' => null, 'rev' => 'reversible', 'policyOk' => true, 'delegated' => true, 'chain' => true,
            'server' => [], 'seed' => true];
        return (new \ReflectionMethod(Authorize::class, 'riskDecision'))->invoke(null, $d['env'], $d['ctx'], $d['p'], $d['grant'], $d['holder'],
            $d['store'], $d['now'], $d['plan'], $d['node'], $d['rev'], $d['policyOk'], $d['delegated'], $d['chain'], $d['server'], $d['seed']);
    }

    public function testASuppliedBudgetIsReadAsFloats(): void
    {
        $ctx = Obj::of(['budget' => Obj::of(['B' => new Num('0.5'), 'tau' => new Num('900000'), 'asOf' => new Num('950000')])]);
        $out = $this->rd(['ctx' => $ctx]);
        $this->assertSame(['B' => 0.5, 'tau' => 900000.0, 'asOf' => 950000.0], $out['before']);
        $noAsOf = Obj::of(['budget' => Obj::of(['B' => new Num('0.5'), 'tau' => new Num('900000')])]);
        $this->assertSame(['B' => 0.5, 'tau' => 900000.0, 'asOf' => null], $this->rd(['ctx' => $noAsOf])['before']);
    }

    public function testAnIncompleteSuppliedBudgetIsIgnored(): void
    {
        $this->assertNull($this->rd()['before'], 'no budget member');
        $badB = Obj::of(['budget' => Obj::of(['B' => 'x', 'tau' => new Num('1')])]);
        $this->assertNull($this->rd(['ctx' => $badB])['before']);
        $badTau = Obj::of(['budget' => Obj::of(['B' => new Num('1'), 'tau' => 'x'])]);
        $this->assertNull($this->rd(['ctx' => $badTau])['before']);
        $notObj = Obj::of(['budget' => 'x']);
        $this->assertNull($this->rd(['ctx' => $notObj])['before']);
    }

    public function testTheSeededBudgetIsFloatTyped(): void
    {
        $out = $this->rd();
        $this->assertNull($out['before']);
        $this->assertSame(1000000.0, $out['after']['tau']);
        $this->assertSame(1.0, $out['after']['B']);
        $this->assertNotContains('budget: no budget supplied', array_map(static fn(string $r): string => substr($r, 0, 26), $out['reasons']));
    }

    public function testTheDenyMeteredBudgetIsFloatTypedAndSaysSo(): void
    {
        $out = $this->rd(['seed' => false]);
        $this->assertSame(1000000.0, $out['after']['tau']);
        $this->assertSame(0.0, $out['after']['B']);
        $this->assertContains('budget: no budget supplied ' . "\u{2014}" . ' fail-closed default (B=0, DENY-METERED): any machine-only (t<3) action must step-up / recharge', $out['reasons']);
    }

    public function testTheRiskierInputWinsPerInput(): void
    {
        $beta = $this->env(['beta' => 1.0]);
        $ctxLow = Obj::of(['risk' => Obj::of(['reversibility' => new Num('0.2')])]);
        $this->assertEqualsWithDelta(0.8, $this->rd(['env' => $beta, 'ctx' => $ctxLow, 'server' => ['reversibility' => 0.9]])['r'], 1e-12);
        $ctxHigh = Obj::of(['risk' => Obj::of(['reversibility' => new Num('0.9')])]);
        $this->assertEqualsWithDelta(0.8, $this->rd(['env' => $beta, 'ctx' => $ctxHigh, 'server' => ['reversibility' => 0.2]])['r'], 1e-12);
        $eps = $this->env(['epsilon' => 1.0]);
        $ctxC = Obj::of(['risk' => Obj::of(['confidence' => new Num('0.3')])]);
        $this->assertEqualsWithDelta(0.7, $this->rd(['env' => $eps, 'ctx' => $ctxC, 'server' => ['confidence' => 0.8]])['r'], 1e-12);
        $delta = $this->env(['delta' => 1.0]);
        $ctxT = Obj::of(['risk' => Obj::of(['taint' => new Num('0.3')])]);
        $this->assertEqualsWithDelta(0.8, $this->rd(['env' => $delta, 'ctx' => $ctxT, 'server' => ['taint' => 0.8]])['r'], 1e-12);
    }

    public function testANonNumericServerRiskInputCountsAsMissing(): void
    {
        $delta = $this->env(['delta' => 1.0]);
        $out = $this->rd(['env' => $delta, 'server' => ['taint' => '0.1']]);
        $this->assertEqualsWithDelta(1.0, $out['r'], 1e-12);
        $this->assertContains('risk input(s) missing, assumed worst case: semanticDistance, reversibility, blastRadius, taint, confidence', $out['reasons']);
        $this->assertEqualsWithDelta(0.0, $this->rd(['env' => $delta, 'server' => ['taint' => 0]])['r'], 1e-12, 'an int is a number');
        $this->assertEqualsWithDelta(0.25, $this->rd(['env' => $delta, 'server' => ['taint' => 0.25]])['r'], 1e-12);
    }

    public function testThePlanGeodesicFillsTheSemanticDistance(): void
    {
        $nodes = [Obj::of(['id' => 'a']), Obj::of(['id' => 'b']), Obj::of(['id' => 'c'])];
        $alpha = $this->env(['alpha' => 1.0]);
        $out = $this->rd(['env' => $alpha, 'plan' => $nodes, 'node' => 'b']);
        $this->assertEqualsWithDelta(0.5, $out['r'], 1e-12);
        $this->assertContains('risk input(s) missing, assumed worst case: reversibility, blastRadius, taint, confidence', $out['reasons']);
        $this->assertEqualsWithDelta(1.0, $this->rd(['env' => $alpha, 'plan' => $nodes, 'node' => 'a'])['r'], 1e-12);
        $this->assertEqualsWithDelta(0.0, $this->rd(['env' => $alpha, 'plan' => $nodes, 'node' => 'c'])['r'], 1e-12);
    }

    public function testThePlanGeodesicFailsClosedWithoutAStringNodeOrGoal(): void
    {
        $nodes = [Obj::of(['id' => 'a']), Obj::of(['id' => 'b']), Obj::of(['id' => 'c'])];
        $alpha = $this->env(['alpha' => 1.0]);
        $this->assertEqualsWithDelta(1.0, $this->rd(['env' => $alpha, 'plan' => $nodes, 'node' => null])['r'], 1e-12, 'no node id');
        $this->assertEqualsWithDelta(1.0, $this->rd(['env' => $alpha, 'plan' => $nodes, 'node' => 7])['r'], 1e-12, 'a non-string node id');
        $badGoal = [Obj::of(['id' => 'a']), 'not-a-node'];
        $this->assertEqualsWithDelta(1.0, $this->rd(['env' => $alpha, 'plan' => $badGoal, 'node' => 'a'])['r'], 1e-12, 'the last plan node is not an object');
        $this->assertEqualsWithDelta(1.0, $this->rd(['env' => $alpha, 'plan' => [], 'node' => 'a'])['r'], 1e-12, 'an empty plan has no goal');
    }

    public function testOnlyARecognisedReversibleClassMayTakeTheOptimisticPath(): void
    {
        $this->assertTrue($this->rd(['rev' => 'reversible'])['threshold']['optimisticAllowed']);
        $this->assertFalse($this->rd(['rev' => 'irreversible'])['threshold']['optimisticAllowed']);
        $this->assertFalse($this->rd(['rev' => null])['threshold']['optimisticAllowed']);
        $this->assertFalse($this->rd(['rev' => 'something-else'])['threshold']['optimisticAllowed']);
        $this->assertSame(1, $this->rd(['rev' => 'reversible'])['threshold']['t']);
    }

    // ------------------------------------------------------------------ passport gate

    private function passportRow(string $name): Obj
    {
        foreach (Vectors::load('passport-vectors.json')->get('passport_vectors') as $r) {
            if ($r->get('name') === $name) {
                return $r;
            }
        }
        $this->fail("passport vector $name is missing");
    }

    private function pcactnFor(string $holder): Obj
    {
        $p = Json::parseLax(Json::canonicalizeStrict($this->p));
        $chain = $p->get('cap_chain');
        $chain[count($chain) - 1]->set('holder', $holder);
        return $p;
    }

    /** @return array<string,mixed> */
    private function gate(Obj $row, array $over = []): array
    {
        return ['requirePassport' => $over + ['trustedIssuers' => $row->get('trustedIssuers'), 'revocation' => static fn() => false,
            'now' => static fn() => 1800000000000], 'passport' => $row->get('signed')];
    }

    private function assertPassportNotRefused(AuthorizeResult $r): void
    {
        $this->assertNotSame('fail', $r->checks['passport'] ?? null, implode('; ', $r->reasons));
    }

    public function testAMatchingPassportPassesTheGate(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $this->assertPassportNotRefused($this->az($this->grant, ['hard' => $this->gate($row)], null, $p));
    }

    public function testTheGateClockFallsBackToTheCallClock(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $hard = $this->gate($row);
        unset($hard['requirePassport']['now']);
        $this->assertPassportNotRefused($this->az($this->grant, ['hard' => $hard, 'now' => 1800000000000], null, $p));
        $stale = $this->az($this->grant, ['hard' => $hard], null, $p);
        $this->assertSame('fail', $stale->checks['passport'], 'the call clock is outside the passport validity');
    }

    public function testThePassportMustBeForTheLeafHolder(): void
    {
        $row = $this->passportRow('ok');
        $r = $this->az($this->grant, ['hard' => $this->gate($row)]);
        $this->assertFalse($r->allow);
        $this->assertSame(403, $r->status);
        $this->assertSame('fail', $r->checks['passport']);
        $this->assertSame('passport: subject_mismatch', $r->reason);
    }

    public function testAnAllowUnderTheGateCarriesThePassportAssurance(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $r = $this->az($this->grant, ['hard' => $this->gate($row)], null, $p);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertSame(['outcome' => 'pass', 'level' => 'software'], $r->assurance['passport']);
        $this->assertTrue($r->passport['ok']);
        $this->assertSame($row->get('signed')->get('sub'), $r->passport['sub']);
        $this->assertArrayNotHasKey('passport', $this->az($this->grant, [], null, $p)->assurance);
    }

    public function testAnUnreadableLeafNeverAllowsUnderTheGate(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $p->get('cap_chain')[count($p->get('cap_chain')) - 1]->set('holder', 7);
        $r = $this->az($this->grant, ['hard' => $this->gate($row)], null, $p);
        $this->assertFalse($r->allow);
        $this->assertNull($r->passport);
        $this->assertArrayNotHasKey('passport', $r->assurance);
    }

    public function testThePassportRefusalCarriesTheVerifierReasonAndStatus(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $r = $this->az($this->grant, ['hard' => $this->gate($row, ['trustedIssuers' => []])], null, $p);
        $this->assertFalse($r->allow);
        $this->assertSame(403, $r->status);
        $this->assertSame('passport: unknown_issuer', $r->reason);
        $none = $this->az($this->grant, ['hard' => ['requirePassport' => $this->gate($row)['requirePassport']]], null, $p);
        $this->assertSame(403, $none->status);
        $this->assertSame('passport: malformed', $none->reason);
    }

    public function testAHardwareRequirementNeedsVerifiedHardwareEvidence(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $r = $this->az($this->grant, ['hard' => $this->gate($row, ['hardware' => true])], null, $p);
        $this->assertFalse($r->allow);
        $this->assertSame(403, $r->status);
        $this->assertSame('passport: hardware_evidence_missing', $r->reason);
        $this->assertPassportNotRefused($this->az($this->grant, ['hard' => $this->gate($row, ['hardware' => false])], null, $p));
        $this->assertPassportNotRefused($this->az($this->grant, ['hard' => $this->gate($row)], null, $p));
    }

    public function testAVerifiedHardwarePassportSatisfiesTheHardwareRequirement(): void
    {
        $row = $this->passportRow('hardware-rooted-evidence-no-verifier');
        $pp = $row->get('signed')->get('passport');
        $attest = static function (Obj $doc, array $expected) use ($pp): array {
            $m = [];
            foreach (['model_id', 'operator', 'weights_digest', 'runtime_measurement', 'system_prompt_digest', 'tool_manifest_digest', 'weights_measured'] as $k) {
                if ($pp->get($k) !== null) {
                    $m[$k] = $pp->get($k);
                }
            }
            return ['ok' => true, 'bound' => true, 'measured' => $m];
        };
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $r = $this->az($this->grant, ['hard' => $this->gate($row, ['hardware' => true, 'attest' => $attest])], null, $p);
        $this->assertPassportNotRefused($r);
    }

    private function hardwareAttest(Obj $row): \Closure
    {
        $pp = $row->get('signed')->get('passport');
        return static function (Obj $doc, array $expected) use ($pp): array {
            $m = [];
            foreach (['model_id', 'operator', 'weights_digest', 'runtime_measurement', 'system_prompt_digest', 'tool_manifest_digest', 'weights_measured'] as $k) {
                if ($pp->get($k) !== null) {
                    $m[$k] = $pp->get($k);
                }
            }
            return ['ok' => true, 'bound' => true, 'measured' => $m];
        };
    }

    /** @return array<string,mixed> the passport assurance of an allow under a hardware gate with these over-rides */
    private function hardwarePassportAssurance(array $over): array
    {
        $row = $this->passportRow('hardware-rooted-evidence-no-verifier');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $r = $this->az($this->grant, ['hard' => $this->gate($row, ['hardware' => true] + $over)], null, $p);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertTrue($r->passport['hardware_verified']);
        return $r->assurance['passport'];
    }

    public function testAHardwarePassportCarriesTheVerifierLabelAndVendor(): void
    {
        $row = $this->passportRow('hardware-rooted-evidence-no-verifier');
        $attest = Assurance::setLabel($this->hardwareAttest($row), new AssuranceLabel('hardware', 'amd-sev-snp'));
        $this->assertSame(['outcome' => 'pass', 'level' => 'hardware', 'vendor' => 'amd-sev-snp'],
            $this->hardwarePassportAssurance(['attest' => $attest]));
    }

    public function testTheAttestCallableLabelWinsOverTheDefaultHardwareLabel(): void
    {
        $row = $this->passportRow('hardware-rooted-evidence-no-verifier');
        $attest = Assurance::setLabel($this->hardwareAttest($row), new AssuranceLabel('hardware', 'vendor-attest'));
        $dh = new AuthorizeSurvivorKillAHardwareVerifier(new AssuranceLabel('multi_root', 'vendor-default'), $this->hardwareAttest($row));
        $this->assertSame(['outcome' => 'pass', 'level' => 'hardware', 'vendor' => 'vendor-attest'],
            $this->hardwarePassportAssurance(['attest' => $attest, 'defaultHardware' => $dh]));
        $plain = $this->hardwareAttest($row);
        $this->assertSame(['outcome' => 'pass', 'level' => 'unknown'],
            $this->hardwarePassportAssurance(['attest' => $plain, 'defaultHardware' => $dh]), 'an unlabelled attest callable is not replaced by the default verifier label');
    }

    public function testTheDefaultHardwareLabelIsUsedWhenThereIsNoAttestCallable(): void
    {
        $row = $this->passportRow('hardware-rooted-evidence-no-verifier');
        $dh = new AuthorizeSurvivorKillAHardwareVerifier(new AssuranceLabel('hardware', 'vendor-default'), $this->hardwareAttest($row));
        $this->assertSame(['outcome' => 'pass', 'level' => 'hardware', 'vendor' => 'vendor-default'],
            $this->hardwarePassportAssurance(['defaultHardware' => $dh]));
    }

    public function testAnUnlabelledHardwareVerifierYieldsLevelUnknownWithoutAVendor(): void
    {
        $row = $this->passportRow('hardware-rooted-evidence-no-verifier');
        $this->assertSame(['outcome' => 'pass', 'level' => 'unknown'], $this->hardwarePassportAssurance(['attest' => $this->hardwareAttest($row)]));
    }

    public function testAnEmptyVendorIsNotReported(): void
    {
        $row = $this->passportRow('hardware-rooted-evidence-no-verifier');
        $attest = Assurance::setLabel($this->hardwareAttest($row), new AssuranceLabel('hardware', ''));
        $this->assertSame(['outcome' => 'pass', 'level' => 'hardware'], $this->hardwarePassportAssurance(['attest' => $attest]));
    }

    public function testASoftwarePassportReportsTheSoftwareLevel(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $r = $this->az($this->grant, ['hard' => $this->gate($row)], null, $p);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        $this->assertFalse($r->passport['hardware_verified']);
        $this->assertSame(['outcome' => 'pass', 'level' => 'software'], $r->assurance['passport']);
    }

    public function testALeafSwappedAfterThePassportCheckIsRefusedAsASubjectMismatch(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $inner = Authorize::$coreHook;
        Authorize::$coreHook = static function (array $c) use ($inner, $p): array {
            $chain = $p->get('cap_chain');
            $chain[count($chain) - 1]->set('holder', 'a-different-leaf-key');
            return $inner($c);
        };
        $r = $this->az($this->grant, ['hard' => $this->gate($row)], null, $p);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['passport']);
        $this->assertContains('passport: subject_mismatch', $r->reasons);
        $this->assertNull($r->passport);
    }

    public function testALeafUnreadableAtTheGateButReadableLaterIsRefusedAsASubjectMismatch(): void
    {
        $row = $this->passportRow('ok');
        $p = $this->pcactnFor($row->get('signed')->get('sub'));
        $p->get('cap_chain')[count($p->get('cap_chain')) - 1]->set('holder', 7);
        $inner = Authorize::$coreHook;
        Authorize::$coreHook = static function (array $c) use ($inner, $p): array {
            $chain = $p->get('cap_chain');
            $chain[count($chain) - 1]->set('holder', 'a-later-leaf-key');
            return $inner($c);
        };
        $r = $this->az($this->grant, ['hard' => $this->gate($row)], null, $p);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['passport']);
        $this->assertContains('passport: subject_mismatch', $r->reasons);
    }

    public function testAnUnreadableLeafSkipsThePassportGateWithoutAnError(): void
    {
        $row = $this->passportRow('ok');
        foreach ([null, [], ['not-a-hop']] as $chain) {
            $p = Json::parseLax(Json::canonicalizeStrict($this->p));
            $p->set('cap_chain', $chain);
            $r = $this->az($this->grant, ['hard' => $this->gate($row)], null, $p);
            $this->assertPassportNotRefused($r);
            $this->assertFalse(str_starts_with((string)$r->reason, 'authorize: error'), (string)$r->reason);
        }
    }

    // ------------------------------------------------------------------ forbid gate

    private function clauses(array $over = []): array
    {
        $verb = $this->op->get('verb');
        return [Obj::of(['id' => 'p-all', 'kind' => 'permit', 'signer' => 'user', 'when' => Obj::of(['verb' => $verb])]),
            Obj::of(['id' => 'f-block', 'kind' => 'forbid', 'signer' => 'org', 'when' => Obj::of(['verb' => $over['forbidVerb'] ?? 'nothing.here'])])];
    }

    private function fctx(array $extra = []): Obj
    {
        $c = Obj::of(['action' => Obj::of(['verb' => $this->op->get('verb'), 'resource' => $this->op->get('resource'), 'params' => $this->op->get('params')])]);
        foreach ($extra as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    public function testTheForbidCallbacksReceiveTheOperation(): void
    {
        $ctxArg = null;
        $clArg = null;
        $grantArg = null;
        $hard = ['forbid' => [
            'context' => function (array $a) use (&$ctxArg) {
                $ctxArg = $a;
                return null;
            },
            'clauses' => function (array $a, $g) use (&$clArg, &$grantArg) {
                $clArg = $a;
                $grantArg = $g;
                return $this->clauses();
            },
        ]];
        $r = $this->az($this->grant, ['hard' => $hard]);
        $this->assertTrue($r->allow, implode('; ', $r->reasons));
        foreach ([$ctxArg, $clArg] as $a) {
            $this->assertIsArray($a);
            $this->assertSame(['verb', 'resource', 'params'], array_keys($a));
            $this->assertSame($this->op->get('verb'), $a['verb']);
            $this->assertSame($this->op->get('resource'), $a['resource']);
            $this->assertInstanceOf(Obj::class, $a['params']);
        }
        $this->assertSame($this->grant, $grantArg);
    }

    /** @return array<string, array{0: callable}> */
    public static function contextShapes(): array
    {
        return [
            'objects' => [static fn(Obj $s, Obj $e) => Obj::of(['subject' => $s, 'env' => $e])],
            'arrays' => [static fn(Obj $s, Obj $e) => ['subject' => $s, 'env' => $e]],
        ];
    }

    #[DataProvider('contextShapes')]
    public function testTheForbidContextSubjectAndEnvAreBoundIntoTheCertificate(callable $shape): void
    {
        $subject = Obj::of(['id' => 'u1']);
        $env = Obj::of(['region' => 'eu']);
        $mk = fn(bool $withSubject, bool $withEnv): array => ['forbid' => ['clauses' => fn() => $this->clauses(), 'requireCertificate' => true,
            'context' => static fn() => $shape($subject, $env)], 'forbidCertificate' => ForbidCertificate::certify($this->clauses(),
            $this->fctx(($withSubject ? ['subject' => $subject] : []) + ($withEnv ? ['env' => $env] : [])))];
        $ok = $this->az($this->grant, ['hard' => $mk(true, true)]);
        $this->assertTrue($ok->allow, implode('; ', $ok->reasons));
        $noSubject = $this->az($this->grant, ['hard' => $mk(false, true)]);
        $this->assertFalse($noSubject->allow, 'the subject is part of the evaluated context');
        $this->assertSame('fail', $noSubject->checks['forbid']);
        $noEnv = $this->az($this->grant, ['hard' => $mk(true, false)]);
        $this->assertFalse($noEnv->allow, 'the env is part of the evaluated context');
        $this->assertSame('fail', $noEnv->checks['forbid']);
    }

    public function testTheForbidSignerPrecedenceAndPermitSignersReachTheDecision(): void
    {
        $verb = $this->op->get('verb');
        $cl = static fn(): array => [
            Obj::of(['id' => 'p-all', 'kind' => 'permit', 'signer' => 'user', 'when' => Obj::of(['verb' => $verb])]),
            Obj::of(['id' => 'a-f', 'kind' => 'forbid', 'signer' => 's1', 'when' => Obj::of(['verb' => $verb])]),
            Obj::of(['id' => 'z-f', 'kind' => 'forbid', 'signer' => 's2', 'when' => Obj::of(['verb' => $verb])]),
        ];
        $plain = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => $cl]]]);
        $this->assertSame('forbid: deny by forbid a-f', $plain->reason);
        $ranked = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => $cl, 'precedence' => ['s2', 's1']]]]);
        $this->assertSame('forbid: deny by forbid z-f', $ranked->reason);
        $this->assertSame(403, $ranked->status);

        $permitOnly = fn(): array => [$this->clauses()[0]];
        $inactive = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => $permitOnly, 'permitSigners' => ['other']]]]);
        $this->assertSame('forbid: deny by none', $inactive->reason);
        $active = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => $permitOnly, 'permitSigners' => ['user']]]]);
        $this->assertTrue($active->allow, implode('; ', $active->reasons));
    }

    public function testTheForbidRefusalsCarryTheirStatusAndText(): void
    {
        $deny = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => fn() => $this->clauses(['forbidVerb' => $this->op->get('verb')])]]]);
        $this->assertSame(403, $deny->status);
        $this->assertSame('forbid: deny by forbid f-block', $deny->reason);

        $hard = ['forbid' => ['clauses' => fn() => $this->clauses(), 'requireCertificate' => true]];
        $none = $this->az($this->grant, ['hard' => $hard]);
        $this->assertSame(403, $none->status);
        $this->assertSame('forbid: the call carries no certificate (fail closed)', $none->reason);

        $other = ForbidCertificate::certify($this->clauses(['forbidVerb' => 'zzz']), Obj::of(['action' => Obj::of(['verb' => 'other', 'resource' => 'r'])]));
        $c = ForbidCertificate::check($other, $this->clauses(), $this->fctx(), []);
        $this->assertFalse($c['ok']);
        $bad = $this->az($this->grant, ['hard' => $hard + ['forbidCertificate' => $other]]);
        $this->assertSame(403, $bad->status);
        $this->assertSame('forbid: certificate refused (' . ($c['reason'] ?? 'mismatch') . ')', $bad->reason);

        $boom = $this->az($this->grant, ['hard' => ['forbid' => ['clauses' => static function (): array {
            throw new \RuntimeException('boom');
        }]]]);
        $this->assertSame(403, $boom->status);
        $this->assertSame('forbid: error (fail closed)', $boom->reason);
    }

    // ------------------------------------------------------------------ linked template gate

    private function linkedGrant(): Obj
    {
        $g = Json::parseLax(Json::canonicalizeStrict($this->grant));
        foreach ($g->get('caveats') as $cv) {
            if ($cv->get('type') === 'envelope') {
                $cv->set('template_ref', Obj::of(['template_id' => 't1', 'version_digest' => 'd1', 'slots' => new Obj()]));
            }
        }
        return $g;
    }

    public function testALinkedTemplateRefusalNamesTheVerifierReason(): void
    {
        $g = $this->linkedGrant();
        $reg = Obj::of(['templates' => new Obj(), 'trusted' => []]);
        $env = Authorize::readEnvelope($g);
        $this->assertInstanceOf(Obj::class, $env);
        $v = PolicyLink::verifyLinkedPolicy($env, $reg);
        $this->assertFalse($v['ok']);
        $failClosed = 'template: link verification error (fail closed)';
        $expected = 'template: ' . $v['reason'];
        $this->assertNotSame($failClosed, $expected);
        foreach ([$reg, static fn() => $reg] as $registry) {
            $r = $this->az($g, ['hard' => ['requireLinkedTemplate' => $registry]]);
            $this->assertFalse($r->allow);
            $this->assertSame(403, $r->status);
            $this->assertSame('fail', $r->checks['template']);
            $this->assertSame($expected, $r->reason);
        }
    }

    public function testAnUnusableRegistryFailsClosed(): void
    {
        $g = $this->linkedGrant();
        foreach (['nope', static fn() => null, static fn() => 'nope', []] as $registry) {
            $r = $this->az($g, ['hard' => ['requireLinkedTemplate' => $registry]]);
            $this->assertFalse($r->allow);
            $this->assertSame(403, $r->status);
            $this->assertSame('template: link verification error (fail closed)', $r->reason);
        }
    }

    // ------------------------------------------------------------------ adaptive policy gate

    private function adaptivePolicy(float $t1, float $t2, bool $weights = true): array
    {
        $p = ['bMax' => 1, 'kappa' => 1, 'lambda' => 0, 'rho' => 0, 'theta1' => $t1, 'theta2' => $t2];
        if ($weights) {
            $p['weights'] = ['alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05];
        }
        return $p;
    }

    /** @return array<string, array{0: callable}> */
    public static function riskShapes(): array
    {
        $vals = ['semanticDistance' => '0.4', 'reversibility' => '1', 'blastRadius' => '0', 'taint' => '0', 'confidence' => '1', 'age' => '0'];
        return [
            'array of floats' => [static fn() => ['semanticDistance' => 0.4] + self::NONE],
            'object of numbers' => [static function () use ($vals): Obj {
                $o = new Obj();
                foreach ($vals as $k => $v) {
                    $o->set($k, new Num($v));
                }
                return $o;
            }],
        ];
    }

    #[DataProvider('riskShapes')]
    public function testATightenedAdaptivePolicyRefusesBeforeTheCoreRuns(callable $risk): void
    {
        $args = [];
        $hard = ['risk' => function (array $a, $g, $p) use ($risk, &$args) {
            $args[] = $a;
            return $risk();
        }, 'adaptivePolicy' => fn(int $now) => $this->adaptivePolicy(0.05, 0.5)];
        $r = $this->az($this->weighted(), ['hard' => $hard]);
        $this->assertFalse($r->allow);
        $this->assertSame(403, $r->status);
        $this->assertSame(['adaptive' => 'fail'], $r->checks, 'the early refusal, not the post-guard one');
        $this->assertSame('adaptive: tightened policy requires threshold t=2 (grant policy: t=1)', $r->reason);
        $this->assertSame(0, $this->coreCalls, 'the guard never ran');
        $this->assertSame(['verb', 'resource', 'params'], array_keys($args[0]));
        $this->assertSame($this->op->get('verb'), $args[0]['verb']);
        $this->assertSame($this->op->get('resource'), $args[0]['resource']);
    }

    public function testAnInvalidAdaptivePolicyRefusesWithItsReason(): void
    {
        $bad = $this->az($this->weighted(), ['hard' => ['adaptivePolicy' => fn() => $this->adaptivePolicy(0.9, 0.1)]]);
        $this->assertSame(403, $bad->status);
        $this->assertSame('adaptive: invalid policy (risk_policy requires 0 <= theta1 <= theta2)', $bad->reason);
        $this->assertSame(0, $this->coreCalls);
        $noWeights = $this->az($this->weighted(), ['hard' => ['adaptivePolicy' => fn() => $this->adaptivePolicy(0.1, 0.5, false)]]);
        $this->assertSame('adaptive: invalid policy (risk_policy.weights missing)', $noWeights->reason);
        $this->assertSame(403, $noWeights->status);
    }

    public function testTheEarlyAdaptiveCheckNeedsAnEnvelopeAndARiskSource(): void
    {
        $noEnv = Json::parseLax(Json::canonicalizeStrict($this->grant));
        $noEnv->set('caveats', []);
        $calls = 0;
        $hard = ['risk' => function () use (&$calls): array {
            $calls++;
            return self::NONE;
        }, 'adaptivePolicy' => fn() => $this->adaptivePolicy(0.5, 0.9)];
        $this->az($noEnv, ['hard' => $hard]);
        $this->assertSame(0, $calls, 'a grant without an envelope never asks for the risk');
    }

    // ------------------------------------------------------------------ contracts configuration

    public function testAContractEnforcerMustHaveBothMethods(): void
    {
        $peekOnly = new class {
            public function peek(Obj $a): mixed
            {
                return null;
            }
        };
        $checkOnly = new class {
            public function check(Obj $a, bool $p): mixed
            {
                return null;
            }
        };
        foreach ([$peekOnly, $checkOnly, AuthorizeSurvivorKillAStaticContracts::class, 'x', 5] as $bad) {
            $r = $this->az($this->grant, ['hard' => ['contracts' => $bad]]);
            $this->assertFalse($r->allow);
            $this->assertSame('fail', $r->checks['authorize_config'] ?? null);
            $this->assertSame(['contracts (must have peek() and check())'], $r->missing);
            $this->assertSame('authorize_config: missing required component(s): contracts (must have peek() and check()) (fail closed)', $r->reason);
        }
        $both = new class {
            public function peek(Obj $a): mixed
            {
                return ['allow' => true, 'reason' => '', 'violated' => []];
            }

            public function check(Obj $a, bool $p): mixed
            {
                return ['allow' => true, 'reason' => '', 'violated' => []];
            }
        };
        $ok = $this->az($this->grant, ['hard' => ['contracts' => $both]]);
        $this->assertArrayNotHasKey('authorize_config', $ok->checks);
        $absent = $this->az($this->grant);
        $this->assertArrayNotHasKey('authorize_config', $absent->checks);
    }
}
