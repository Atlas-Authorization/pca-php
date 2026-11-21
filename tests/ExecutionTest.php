<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Execution.php';

use Atlas\Pca\Authorize;
use Atlas\Pca\Execution;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Execution::authorize (`authorizeExecution` of the reference) over the signed authorize fixtures: the configuration, the operation binding, the grant source and the
 * full policy (a validly signed $400 payment under a smaller grant is refused), plus the amount-priced risk.
 */
final class ExecutionTest extends TestCase
{
    private Obj $fix;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax((string)file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
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
        $a = ['verb' => $op->get('verb'), 'resource' => $op->get('resource'), 'params' => $op->get('params')];
        return $a + ['provenance' => ProvHarness::bundle($op)];
    }

    public function testAMissingComponentDeniesEveryCall(): void
    {
        $c = $this->case('envelope-predicate-within');
        $step = $c->get('steps')[0];
        $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), ['audience' => 'x']);
        $this->assertFalse($r['allow']);
        $this->assertSame(['config', 403], [$r['kind'], $r['status']]);
        $this->assertSame('full policy mode is missing grant or resolveGrant, state, isRevoked (fail closed)', $r['reason']);
        $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $this->opts($c, ['multiInstance' => true]));
        $this->assertSame('config', $r['kind']);
        $this->assertStringContainsString("'multiInstance' is not supported", $r['reason']);
    }

    public function testAProofForAnotherOperationIsNotSpent(): void
    {
        $c = $this->case('envelope-predicate-within');
        $step = $c->get('steps')[0];
        $op = $this->operation($step);
        $store = new MemoryStateStore();
        $r = Execution::authorizeExecution($step->get('pcactn'), ['verb' => 'other.verb'] + $op, $this->opts($c, ['state' => $store]));
        $this->assertSame(['binding', 403], [$r['kind'], $r['status']]);
        $this->assertSame('the proof is for payments.send on payments/acme, but this call is other.verb on payments/acme', $r['reason']);
        $r = Execution::authorizeExecution($step->get('pcactn'), ['resource' => 'payments/other'] + $op, $this->opts($c, ['state' => $store]));
        $this->assertSame('the proof is for payments.send on payments/acme, but this call is payments.send on payments/other', $r['reason']);
    }

    public function testAnUnknownGrantIsUnauthenticated(): void
    {
        $c = $this->case('envelope-predicate-within');
        $step = $c->get('steps')[0];
        $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $this->opts($c, ['resolveGrant' => static fn($ref, $p) => null]));
        $this->assertSame(['authn', 401, 'unknown grant_ref'], [$r['kind'], $r['status'], $r['reason']]);
    }

    public function testASigned400UnderTheGrantsLimitIsRefusedByThePolicy(): void
    {
        $c = $this->case('envelope-predicate-400-refused');
        $step = $c->get('steps')[0];
        $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $this->opts($c));
        $this->assertFalse($r['allow']);
        $this->assertSame(['policy', 403], [$r['kind'], $r['status']]);
        $this->assertStringStartsWith('policy:', $r['reason']);
        $this->assertSame('fail', $r['checks']['policy']);
    }

    public function testARevokedGrantIsReportedAsRevoked(): void
    {
        $c = $this->case('envelope-predicate-within');
        $step = $c->get('steps')[0];
        $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $this->opts($c, ['isRevoked' => static fn($g, $p): bool => true]));
        $this->assertFalse($r['allow']);
        $this->assertSame('revoked', $r['kind']);
        $this->assertStringStartsWith('revocation:', $r['reason']);
    }

    public function testAmountRiskPricesBlastRadiusFromTheVerifiedAmount(): void
    {
        $c = $this->case('envelope-predicate-within');
        $kappa = Authorize::readEnvelope($c->get('grant'))->get('risk_policy')->get('kappa')->float();
        $r = Execution::amountRisk($c->get('grant'), Obj::of(['amount' => 50]));
        $this->assertEqualsWithDelta(min(1.0, 50 / $kappa), $r['blastRadius'], 1e-12);
        $this->assertSame(1.0, Execution::amountRisk($c->get('grant'), Obj::of(['amount' => 1e12]))['blastRadius']);
        $this->assertSame(0.0, Execution::amountRisk($c->get('grant'), Obj::of(['amount' => -5]))['blastRadius']);
        $this->assertNull(Execution::amountRisk($c->get('grant'), Obj::of(['amount' => '50'])));
        $this->assertNull(Execution::amountRisk($c->get('grant'), new Obj()));
        $this->assertNull(Execution::amountRisk(null, Obj::of(['amount' => 50])));
        $this->assertEqualsWithDelta(min(1.0, 7 / $kappa), Execution::amountRisk($c->get('grant'), Obj::of(['cost' => 7]), 'cost')['blastRadius'], 1e-12);
    }

    public function testAnExecutionThePolicyAdmitsIsAllowedEndToEnd(): void
    {
        $admitted = 0;
        foreach (['envelope-predicate-within', 'envelope-max-spend-within', 'root-max-spend-within', 'delegated-predicates-within'] as $name) {
            $c = $this->case($name);
            $step = $c->get('steps')[0];
            $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $this->opts($c));
            $this->assertTrue($r['allow'], $name . ': ' . ($r['reason'] ?? '') . ' ' . json_encode($r['checks'] ?? null));
            $this->assertSame($c->get('grant'), $r['grant']);
            $admitted++;
        }
        $this->assertSame(4, $admitted);
    }

    public function testTheSameProofIsRefusedAsAReplayTheSecondTime(): void
    {
        $c = $this->case('envelope-predicate-within');
        $step = $c->get('steps')[0];
        $opts = $this->opts($c);
        $this->assertTrue(Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $opts)['allow']);
        $r = Execution::authorizeExecution($step->get('pcactn'), $this->operation($step), $opts);
        $this->assertFalse($r['allow']);
        $this->assertSame('replay', $r['kind']);
    }
}
