<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Execution.php';

use Atlas\Pca\AssuranceLabel;
use Atlas\Pca\AssuranceLabeler;
use Atlas\Pca\Authorize;
use Atlas\Pca\Execution;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24) for src/Execution.php: exact refusals, the clock, the plan context, the hooks, the budget seed and the decisive reason. */
final class PolicySurvivorKill24ExecutionTest extends TestCase
{
    private Obj $fix;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax((string)file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
    }

    protected function tearDown(): void
    {
        Execution::$clockHook = null;
    }

    private function case(string $name): Obj
    {
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === $name) {
                return $c;
            }
        }
        $this->fail("no fixture $name");
    }

    /** @return array<string,mixed> */
    private function opts(Obj $c, array $more = []): array
    {
        $now = $this->fix->get('now')->int();
        return $more + ['audience' => $this->fix->get('audience'), 'resolveGrant' => static fn($ref, $p) => $c->get('grant'), 'state' => new MemoryStateStore(),
            'isRevoked' => static fn($g, $p): bool => false, 'now' => static fn(): int => $now, 'provenance' => ['mediators' => [ProvHarness::pin()]]];
    }

    private function operation(Obj $step): array
    {
        $op = $step->get('operation');
        return ['verb' => $op->get('verb'), 'resource' => $op->get('resource'), 'params' => $op->get('params'), 'provenance' => ProvHarness::bundle($op)];
    }

    /** @return array{0:Obj,1:array<string,mixed>,2:Obj} the within case's PCActn, its operation and the case */
    private function within(): array
    {
        $c = $this->case('envelope-predicate-within');
        $step = $c->get('steps')[0];
        return [$step->get('pcactn'), $this->operation($step), $c];
    }

    private static function reason(array $checks, array $reasons): string
    {
        return (new \ReflectionMethod(Execution::class, 'decisiveReason'))->invoke(null, $checks, $reasons);
    }

    /** The public component probe is the one Authorize applies. */
    public function testMissingComponentsIsPublic(): void
    {
        $this->assertSame(['audience', 'grant or resolveGrant', 'state', 'isRevoked'], Execution::missingExecutionComponents(null));
        [, , $c] = $this->within();
        $this->assertSame([], Execution::missingExecutionComponents($this->opts($c)));
    }

    /** An unsupported option and an unknown enforcement gate are refused with the exact config refusal. */
    public function testUnsupportedOptionsAreExactConfigRefusals(): void
    {
        [$pc, $op, $c] = $this->within();
        $this->assertSame(['allow' => false, 'kind' => 'config', 'status' => 403, 'reason' => "the option 'replayScope' is not supported by this port (fail closed)"],
            Execution::authorizeExecution($pc, $op, $this->opts($c, ['replayScope' => 'x'])));
        $this->assertSame(['allow' => false, 'kind' => 'config', 'status' => 403, 'reason' => 'the bogus enforcement gate is not supported by this port (fail closed)'],
            Execution::authorizeExecution($pc, $op, $this->opts($c, ['enforce' => ['bogus' => true]])));
        $this->assertTrue(Execution::authorizeExecution($pc, $op, $this->opts($c, ['enforce' => []]))['allow'], 'control');
    }

    /** A PCActn that is not an object (or has no action object) is a binding refusal, never an internal error. */
    public function testANonObjectProofIsABindingRefusal(): void
    {
        [, $op, $c] = $this->within();
        $want = ['allow' => false, 'kind' => 'binding', 'status' => 403, 'reason' => 'the proof is for null on null, but this call is payments.send on payments/acme'];
        foreach (['garbage', null, Obj::of(['x' => 1]), Obj::of(['action' => 'str'])] as $bad) {
            $this->assertSame($want, Execution::authorizeExecution($bad, $op, $this->opts($c)));
        }
    }

    /** A verb mismatch is the exact binding refusal; an unknown grant the exact authn refusal. */
    public function testExactBindingAndAuthnRefusals(): void
    {
        [$pc, $op, $c] = $this->within();
        $this->assertSame(['allow' => false, 'kind' => 'binding', 'status' => 403, 'reason' => 'the proof is for payments.send on payments/acme, but this call is other.verb'],
            Execution::authorizeExecution($pc, ['verb' => 'other.verb', 'params' => $op['params']], $this->opts($c)));
        $this->assertSame(['allow' => false, 'kind' => 'authn', 'status' => 401, 'reason' => 'unknown grant_ref'],
            Execution::authorizeExecution($pc, $op, $this->opts($c, ['resolveGrant' => static fn($r, $p) => null])));
    }

    /** A throwing grant source is the fail-closed policy refusal naming the error (or 'unknown' for an empty message). */
    public function testAThrowingGrantSourceFailsClosed(): void
    {
        [$pc, $op, $c] = $this->within();
        $this->assertSame(['allow' => false, 'kind' => 'policy', 'status' => 403, 'reason' => 'authorization error (fail closed): boom'],
            Execution::authorizeExecution($pc, $op, $this->opts($c, ['resolveGrant' => static fn($r, $p) => throw new \RuntimeException('boom')])));
        $this->assertSame(['allow' => false, 'kind' => 'policy', 'status' => 403, 'reason' => 'authorization error (fail closed): unknown'],
            Execution::authorizeExecution($pc, $op, $this->opts($c, ['resolveGrant' => static fn($r, $p) => throw new \RuntimeException('')])));
    }

    /** Without a callable `now` the wall clock in milliseconds is used: at the fixture's instant the call is admitted. */
    public function testTheWallClockIsReadInMilliseconds(): void
    {
        [$pc, $op, $c] = $this->within();
        $sec = $this->fix->get('now')->int() / 1000;
        Execution::$clockHook = static fn(): float => (float)$sec;
        $o = $this->opts($c);
        unset($o['now']);
        $r = Execution::authorizeExecution($pc, $op, $o);
        $this->assertTrue($r['allow'], (string)($r['reason'] ?? ''));
        $this->assertSame(['allow', 'pcactn', 'grant', 'verdict', 'assurance'], array_keys($r));
        // a non-callable `now` is ignored, the clock still decides
        [$pc2, $op2, $c2] = $this->within();
        $this->assertTrue(Execution::authorizeExecution($pc2, $op2, $this->opts($c2, ['now' => 5]))['allow']);
        // an hour later the proof (20 minutes) has expired
        Execution::$clockHook = static fn(): float => (float)$sec + 3600.0;
        [$pc3, $op3, $c3] = $this->within();
        $o3 = $this->opts($c3);
        unset($o3['now']);
        $this->assertFalse(Execution::authorizeExecution($pc3, $op3, $o3)['allow']);
    }

    /** A float from `now` is truncated to integer milliseconds (never handed on as a float). */
    public function testAFloatNowIsTruncated(): void
    {
        [$pc, $op, $c] = $this->within();
        $now = (float)$this->fix->get('now')->int() + 0.5;
        $this->assertTrue(Execution::authorizeExecution($pc, $op, $this->opts($c, ['now' => static fn(): float => $now]))['allow']);
    }

    /** `allowedSuites` is honoured: an empty list refuses the Ed25519 proof. */
    public function testAllowedSuitesIsHonoured(): void
    {
        [$pc, $op, $c] = $this->within();
        $this->assertFalse(Execution::authorizeExecution($pc, $op, $this->opts($c, ['allowedSuites' => []]))['allow']);
    }

    /** An extra required check is enforced; a string `require` is one name. */
    public function testRequireAddsChecks(): void
    {
        [$pc, $op, $c] = $this->within();
        $r = Execution::authorizeExecution($pc, $op, $this->opts($c, ['require' => ['no_such_check']]));
        $this->assertFalse($r['allow']);
        $this->assertSame('fail', $r['checks']['no_such_check']);
        $this->assertSame(['allow', 'kind', 'status', 'reason', 'checks', 'verdict', 'assurance'], array_keys($r));
        [$pc2, $op2, $c2] = $this->within();
        $this->assertTrue(Execution::authorizeExecution($pc2, $op2, $this->opts($c2, ['require' => 'policy']))['allow']);
    }

    /** The attestation hook reaches the verifier core: a rejecting one denies. */
    public function testTheAttestationHookIsEnforced(): void
    {
        [$pc, $op, $c] = $this->within();
        $hook = static fn(array $a): array => ['enforced' => true, 'ok' => false, 'reason' => 'quote refused'];
        $r = Execution::authorizeExecution($pc, $op, $this->opts($c, ['hooks' => ['attestation' => $hook]]));
        $this->assertFalse($r['allow']);
        $this->assertSame('fail', $r['checks']['attestation']);
    }

    /** Only the attestation and zk hooks are assurance hooks: a labelled revocation hook does not label the revocation check. */
    public function testOnlyAttestationAndZkAreAssuranceHooks(): void
    {
        [$pc, $op, $c] = $this->within();
        $lab = new class implements AssuranceLabeler {
            public function assurance(): AssuranceLabel
            {
                return new AssuranceLabel('vendor_x', 'acme');
            }
        };
        $r = Execution::authorizeExecution($pc, $op, $this->opts($c, ['hooks' => ['revocation' => $lab]]));
        $this->assertTrue($r['allow']);
        $this->assertArrayNotHasKey('level', $r['assurance']['revocation'] ?? []);
    }

    /** A holder with no stored budget is seeded with the full bMax (1000), and that is what the store keeps after the call. */
    public function testTheBudgetIsSeededFull(): void
    {
        [$pc, $op, $c] = $this->within();
        $store = new MemoryStateStore();
        $this->assertTrue(Execution::authorizeExecution($pc, $op, $this->opts($c, ['state' => $store]))['allow']);
        $chain = $pc->get('cap_chain');
        $b = $store->budget(Authorize::stateKey($c->get('grant')->get('id'), $chain[count($chain) - 1]->get('holder')));
        $this->assertSame(1000.0, $b['B']);
    }

    /** With isPlanAuthorized the one-node plan is rebuilt from the signed action and the principal's answer decides. */
    public function testIsPlanAuthorizedDecidesThePlanRoot(): void
    {
        [$pc, $op, $c] = $this->within();
        $seen = [];
        $r = Execution::authorizeExecution($pc, $op, $this->opts($c, ['isPlanAuthorized' => static function ($ref, $root) use (&$seen): bool {
            $seen = [$ref, $root];
            return true;
        }]));
        $this->assertTrue($r['allow'], (string)($r['reason'] ?? ''));
        $this->assertSame([$pc->get('grant_ref'), $pc->get('plan')->get('root')], $seen);
        [$pc2, $op2, $c2] = $this->within();
        $r = Execution::authorizeExecution($pc2, $op2, $this->opts($c2, ['isPlanAuthorized' => static fn($ref, $root): bool => false]));
        $this->assertFalse($r['allow']);
        $this->assertSame('fail', $r['checks']['plan_root_authorized']);
    }

    /** A failure with status 401 (wrong audience) is reported as authn. */
    public function testA401IsAuthn(): void
    {
        $c = $this->case('wrong-audience');
        $step = $c->get('steps')[0];
        $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $this->opts($c));
        $this->assertSame(['authn', 401], [$r['kind'], $r['status']]);
    }

    /** blastRadius is amount / kappa (kappa 4: 1 / 4 = 0.25). */
    public function testAmountRiskDividesByKappa(): void
    {
        $raw = json_decode((string)file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'), true);
        $g = null;
        foreach ($raw['cases'] as $cc) {
            if ($cc['name'] === 'envelope-predicate-within') {
                $g = $cc['grant'];
            }
        }
        $g['caveats'][0]['risk_policy']['kappa'] = 4;
        $grant = Json::parseLax((string)json_encode($g));
        $this->assertSame(['blastRadius' => 0.25], Execution::amountRisk($grant, Obj::of(['amount' => 1])));
    }

    /** The decisive reason: a failing `operation` ranks last; the first failing check's own non-noise reason wins. */
    public function testDecisiveReasonRanksOperationLast(): void
    {
        $this->assertSame('policy: b', self::reason(['operation' => 'fail', 'policy' => 'fail'], ['operation: a', 'policy: b']));
    }

    /** The worst-case-inputs note is noise, and a reason of another check is skipped. */
    public function testDecisiveReasonSkipsNoiseAndOtherChecks(): void
    {
        $this->assertSame('policy: b', self::reason(['policy' => 'fail'], ['other: x', 'policy: risk input(s) missing, assumed worst case: a', 'policy: b']));
    }

    /** A passing check before the failing one is skipped, not a stop. */
    public function testDecisiveReasonSkipsPassingChecks(): void
    {
        $this->assertSame('policy: b', self::reason(['audience' => 'pass', 'policy' => 'fail'], ['audience: x', 'policy: b']));
    }

    /** With no failing check the first non-noise reason wins; with only noise the first reason; with none 'denied'. */
    public function testDecisiveReasonFallbacks(): void
    {
        $this->assertSame('budget: y', self::reason(['policy' => 'pass'], ['risk input(s) missing, x', 'budget: y']));
        $this->assertSame('risk input(s) missing, x', self::reason([], ['risk input(s) missing, x']));
        $this->assertSame('denied', self::reason([], []));
    }
}
