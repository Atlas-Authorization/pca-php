<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Approvals.php';
require_once __DIR__ . '/../src/PolicyTemplates.php';

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Approvals;
use Atlas\Pca\KeyPair;
use Atlas\Pca\PolicyTemplates;
use Atlas\Pca\Risk;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** approvals.ts: goal lineage, review / batch / pending, standing class approvals, the co-sign recharge and the time box. */
final class ApprovalsTest extends TestCase
{
    private const NOW = 1800000000000;

    private function agent(): AgentHandle
    {
        return PolicyTemplates::fromTemplate('finance-bot', new KeyPair(str_repeat("\1", 32)), 'refund orders', 'rs', new KeyPair(str_repeat("\2", 32)), self::NOW, [], );
    }

    public function testLineageVerifiesTheRevealedGoalAgainstTheCommitment(): void
    {
        $a = PolicyTemplates::fromTemplate('finance-bot', new KeyPair(str_repeat("\1", 32)), 'refund orders', 'rs', null, self::NOW);
        $l = Approvals::buildGoalLineage($a, 'stripe.refund', 'ch_1', ['amount' => 250], 'refund orders');
        self::assertTrue($l['goalVerified']);
        self::assertSame('Approving stripe.refund on ch_1 because you asked to “refund orders”.', $l['because']);
        self::assertSame(['goal', 'authority', 'action'], array_column($l['chain'], 'kind'));
        self::assertSame('Delegated authority to stripe.refund (up to $500/1d)', $l['chain'][1]['label']);
        self::assertSame('amount=250', $l['chain'][2]['detail']);
        self::assertFalse(Approvals::buildGoalLineage($a, 'stripe.refund', 'ch_1', null, 'something else')['goalVerified']);
        $none = Approvals::buildGoalLineage($a, 'stripe.refund', 'ch_1');
        self::assertArrayNotHasKey('goal', $none);
        self::assertFalse($none['goalVerified']);
        self::assertSame('Approving stripe.refund on ch_1, authorized under the grant’s committed goal.', $none['because']);
        $lines = Approvals::describeGoalLineage($none);
        self::assertCount(3, $lines);
        self::assertSame('Pursue the grant’s committed goal — committed as ' . $none['goalCommit'], $lines[0]);
        self::assertSame('stripe.refund ch_1', $lines[2]);
    }

    public function testReviewKinds(): void
    {
        $a = $this->agent();
        self::assertSame('deny', Approvals::reviewAction($a, 'gmail.send', 'x', null, self::NOW)['kind']);
        $r = Approvals::reviewAction($a, 'stripe.refund', 'ch_12345678', ['amount' => 250], self::NOW);
        self::assertSame('deny', $r['kind']);
        self::assertStringStartsWith('approval render required', $r['reason']);
        $bad = Approvals::reviewAction($a, 'stripe.refund', 'ch_12345678', ['amount' => 250], self::NOW, null, null, static fn() => throw new \RuntimeException('boom'));
        self::assertSame(['kind' => 'deny', 'reason' => 'approval render failed (fail closed): boom'], $bad);
        $s = Approvals::reviewAction($a, 'stripe.refund', 'ch_12345678', ['amount' => 250], self::NOW, 'refund orders', null, null, true);
        self::assertSame('step_up', $s['kind']);
        $req = $s['request'];
        self::assertSame(2, $req['tier']);
        self::assertSame(0.5, $req['r']);
        self::assertSame(self::NOW, $req['requestedAt']);
        self::assertSame('refund orders', $req['goal']);
        self::assertTrue($req['lineage']['goalVerified']);
        self::assertArrayNotHasKey('render', $req);
        self::assertSame(43, strlen($req['id']));
        self::assertSame($req['id'], Approvals::reviewAction($a, 'stripe.refund', 'ch_12345678', ['amount' => 250], self::NOW, 'x', null, null, true)['request']['id']);
        self::assertSame([$req], Approvals::pendingRequests([$s, ['kind' => 'auto'], $bad]));
        $batch = Approvals::batchReview($a, [['verb' => 'stripe.refund', 'resource' => 'ch_12345678', 'params' => ['amount' => 250]], ['verb' => 'gmail.send', 'resource' => 'x']],
            ['now' => self::NOW, 'insecureUnboundApproval' => true]);
        self::assertSame(['step_up', 'deny'], array_column($batch, 'kind'));
    }

    public function testStandingApprovalCoversAndExpires(): void
    {
        $c = Approvals::approveClass(['stripe.refund', 'gmail.send'], 4 * 3600000, 'ops', self::NOW, 'ch_*');
        self::assertSame(['id', 'verbs', 'resource', 'grantedAt', 'ttlMs', 'by'], array_keys($c));
        self::assertTrue(Approvals::classApprovalCovers($c, 'stripe.refund', 'ch_12345678', self::NOW));
        self::assertFalse(Approvals::classApprovalCovers($c, 'stripe.refund', 'in_1', self::NOW));
        self::assertFalse(Approvals::classApprovalCovers($c, 'stripe.payout', 'ch_1', self::NOW));
        self::assertFalse(Approvals::classApprovalCovers($c, 'stripe.refund', 'ch_1', self::NOW - 1));
        self::assertFalse(Approvals::classApprovalCovers($c, 'stripe.refund', 'ch_1', self::NOW + 4 * 3600000));
        self::assertTrue(Approvals::coveredByAny([$c], 'gmail.send', 'ch_9', self::NOW + 1));
        self::assertFalse(Approvals::coveredByAny([], 'gmail.send', 'ch_9', self::NOW));
        self::assertSame($c['id'], Approvals::approveClass(['gmail.send', 'stripe.refund'], 4 * 3600000, 'ops', self::NOW, 'ch_*')['id'], 'verb order does not matter');
        $any = Approvals::approveClass(['stripe.refund'], 1000, 'ops', self::NOW);
        self::assertArrayNotHasKey('resource', $any);
        self::assertTrue(Approvals::classApprovalCovers($any, 'stripe.refund', 'whatever', self::NOW));
        $a = $this->agent();
        $std = Approvals::reviewAction($a, 'stripe.refund', 'ch_12345678', ['amount' => 250], self::NOW, null, [$c], null, true);
        self::assertSame(['kind' => 'auto'], $std);
    }

    public function testDecisionCosignAndTimeBox(): void
    {
        self::assertSame(['requestId' => 'r1', 'decision' => 'approve', 'by' => 'me', 'at' => 5], Approvals::recordDecision(['id' => 'r1'], 'approve', 'me', 5));
        $b = ['B' => 0.2, 'tau' => 1.0, 'asOf' => 1.0];
        self::assertSame(['B' => 0.7, 'tau' => 9.0, 'asOf' => 9.0], Approvals::applyCosign($b, ['rho' => 0.5, 'bMax' => 1.0], 9));
        self::assertSame(['B' => 1.0, 'tau' => 9.0, 'asOf' => 9.0], Approvals::applyCosign($b, ['rho' => 0.5, 'bMax' => 1.0], 9, true));
        self::assertSame(1.0, Risk::recharge($b, 5.0, 1.0, 9.0)['B']);
        $holder = new KeyPair(str_repeat("\3", 32));
        $grant = Sign::mintRoot(new KeyPair(str_repeat("\1", 32)), $holder->public, []);
        $boxed = Approvals::timeBox($grant, $holder, 1000, self::NOW);
        self::assertSame(1, count($boxed->get('caveats')));
        self::assertSame('expires', $boxed->get('caveats')[0]->get('type'));
    }

    public function testBudgetTree(): void
    {
        $p = ['B' => 10.0, 'tau' => 1.0, 'asOf' => 2.0];
        self::assertSame(['ok' => false, 'reason' => 'allocation exceeds parent remaining budget'], Risk::subBudget($p, 11));
        self::assertSame(['ok' => false, 'reason' => 'allocation must be finite and >= 0'], Risk::subBudget($p, -1));
        $s = Risk::subBudget($p, 4)['sub'];
        self::assertSame(['B' => 4.0, 'tau' => 1.0, 'asOf' => 2.0], $s);
        $d = Risk::debitConsolidated($p, $s, 3.0);
        self::assertSame([7.0, 1.0], [$d['parent']['B'], $d['sub']['B']]);
        self::assertSame('sub-agent budget insufficient', Risk::debitConsolidated($p, $s, 5.0)['reason']);
        self::assertSame('parent budget insufficient', Risk::debitConsolidated(['B' => 1.0, 'tau' => 0.0], $s, 2.0)['reason']);
        $path = Risk::debitConsolidatedPath([$p, $s], 3.0);
        self::assertSame([7.0, 1.0], array_column($path['nodes'], 'B'));
        self::assertSame('budget node at depth 1 insufficient (need 5, have 4)', Risk::debitConsolidatedPath([$p, $s], 5.0)['reason']);
    }
}
