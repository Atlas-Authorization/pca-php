<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * stateful-vectors.json: 20 sequences of presentations and revocations against ONE store (replay counters, revocation mid-sequence, the
 * trust budget depleting across calls, expiry, separate holder streams). The reference is requirePCA; the outcome compared is `allow` and the
 * sorted names of the checks that FAILED, restricted to the checks the reference has (the PHP pipeline also runs the provenance gate).
 */
final class K05HardStatefulVectorsTest extends TestCase
{
    private const PHP_ONLY = ['provenance_flow'];

    public function testEverySequence(): void
    {
        $doc = Vectors::load('stateful-vectors.json');
        $seqs = $doc->get('stateful');
        $this->assertCount(20, $seqs);
        foreach ($seqs as $seq) {
            $this->run1($seq);
        }
    }

    private function run1(Obj $seq): void
    {
        $setup = $seq->get('setup');
        $grants = [];
        foreach ($setup->get('grants') as $g) {
            $grants[$g->get('id')] = $g;
        }
        $store = new MemoryStateStore();
        $revoked = $setup->get('revoked') ?? [];
        if ($setup->has('initial_budget') && $setup->get('initial_budget') instanceof Obj) {
            $b = $setup->get('initial_budget');
            foreach ($seq->get('steps') as $s) {
                if ($s->get('op') !== 'present') {
                    continue;
                }
                $chain = $s->get('pcactn')->get('cap_chain');
                $key = Authorize::stateKey($s->get('pcactn')->get('grant_ref'), $chain[count($chain) - 1]->get('holder'));
                $store->claimWithBudget($key, 0, null, ['B' => $b->get('B')->float(), 'tau' => $b->get('tau')->float(), 'asOf' => null]);
            }
        }
        $risk = $setup->get('risk');
        foreach ($seq->get('steps') as $i => $s) {
            $name = $seq->get('name') . " step $i";
            if ($s->get('op') === 'revoke') {
                $revoked[] = $s->get('id');
                continue;
            }
            $p = $s->get('pcactn');
            $action = $p->get('action');
            $op = ['verb' => $action->get('verb'), 'resource' => $action->get('resource'), 'params' => $s->get('params')];
            $r = Authorize::authorize(pcactn: $p, operation: $op,
                audience: $setup->get('audience'), resolveGrant: static fn($ref) => $grants[$ref] ?? null, stateStore: $store,
                isRevoked: static function (Obj $pc, Obj $g) use (&$revoked): bool {
                    foreach ($pc->get('cap_chain') as $c) {
                        if (in_array($c->get('id'), $revoked, true)) {
                            return true;
                        }
                    }
                    return false;
                },
                now: $s->get('now')->int(), plan: null, context: static fn(Obj $pc) => ['plan' => $setup->get('plan_nodes'), 'plan_authorized' => true, 'risk' => $risk],
                provenance: ProvHarness::bundle($op), provenanceMediators: [ProvHarness::pin()], hard: ['seedBudget' => false]);
            $failed = [];
            foreach ($r->checks as $n => $st) {
                $n = $n === 'chain' ? 'cap_chain' : $n;
                if ($st === 'fail' && !in_array($n, self::PHP_ONLY, true)) {
                    $failed[] = $n;
                }
            }
            sort($failed);
            $want = $s->get('expect');
            $this->assertSame($want->get('failed'), $failed, "$name failed checks (reasons: " . implode('; ', $r->reasons) . ')');
            $this->assertSame($want->get('allow'), $failed === [], "$name allow");
        }
    }
}
