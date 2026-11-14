<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Facade.php';

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Catalog;
use Atlas\Pca\Facade;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Exact outcomes of the agent facade: limit edges, a caller catalog, the derived risk policy, riskFor, dryRun, act and sub-agents. */
final class FacadeKillTest extends TestCase
{
    private static function kp(int $b = 7): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    /** A caller catalog: a reversible verb with an amount field and its own resource, and a verb of an unknown class. */
    private static function shop(): Catalog
    {
        return new Catalog([
            ['connector' => 'shop', 'action' => 'tip', 'verb' => 'shop.tip', 'reversibility' => 'reversible', 'blastRadius' => 0.3,
                'amountField' => 'amount', 'resource' => 'tips/*', 'description' => 'Tips a courier.'],
            ['connector' => 'shop', 'action' => 'odd', 'verb' => 'shop.odd', 'reversibility' => 'weird', 'blastRadius' => 0.1,
                'description' => 'A verb whose class is not a known reversibility class.'],
        ]);
    }

    /** A handle over a hand-made policy (the grant and chain are placeholders: dryRun reads only the chain length). */
    private static function handle(array $caveats, array $rp = [], ?array $predicates = null, int $hops = 1, string $model = 'risk',
                                   ?Catalog $catalog = null): AgentHandle
    {
        $policy = ['predicates' => $predicates ?? [['verb' => 'files.read', 'resource' => '*']], 'caveats' => $caveats,
            'riskPolicy' => $rp + Sign::defaultRiskPolicy(), 'budgetModel' => $model];
        $chain = [];
        for ($i = 0; $i < $hops; $i++) {
            $chain[] = new Obj();
        }
        return new AgentHandle(new Obj(), $chain, 's', $policy, self::kp(), 'pk', $catalog ?? new Catalog(), 'rs', 0, null);
    }

    public function testLimitEdges(): void
    {
        // exactly 64 characters (60 of them white space) is accepted; the reference counts the untrimmed string
        self::assertSame(['amount' => 1234, 'unit' => 'count'], Facade::parseLimit(str_repeat(' ', 60) . '1234'));
        // the largest safe integer stays an int; one more is a float
        self::assertSame(['amount' => 9007199254740991, 'unit' => 'count'], Facade::parseLimit('9007199254740991'));
        self::assertSame(['amount' => 9007199254740992.0, 'unit' => 'count'], Facade::parseLimit('9007199254740992'));
        // one rate caveat per count limit, per_secs = round(period / 1000) and at least 1
        $c = Facade::compilePolicy(['slack' => ['post_message']], ['post_message' => '5/s'], now: 0);
        self::assertSame([['type' => 'reversibility_max', 'class' => 'irreversible'], ['type' => 'expires', 'at' => 1000],
            ['type' => 'rate', 'max' => 5, 'per_secs' => 1]], $c['caveats']);
    }

    public function testApproximationPrintsTheAmountAsJavaScriptDoes(): void
    {
        $tail = '/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap';
        self::assertSame(["stripe.refund: \$1e-7$tail"],
            Facade::compilePolicy(['stripe' => ['refund']], ['refund' => '$0.0000001/day'], now: 0)['approximations']);
        self::assertSame(["stripe.refund: \$100000000000000000$tail"],
            Facade::compilePolicy(['stripe' => ['refund']], ['refund' => '$99999999999999999/day'], now: 0)['approximations']);
        self::assertSame(["stripe.refund: \$2.5$tail"],
            Facade::compilePolicy(['stripe' => ['refund']], ['refund' => '$2.5/week'], now: 0)['approximations']);
    }

    public function testCallerCatalog(): void
    {
        $c = self::shop();
        self::assertSame('shop.tip', $c->get('shop.tip')['verb']);
        self::assertNull($c->get('stripe.refund'));

        $p = Facade::compilePolicy(['shop' => ['tip']], ['tip' => '$0'], $c, now: 0);
        self::assertSame([['verb' => 'shop.tip', 'resource' => 'tips/*', 'where' => [['field' => 'action.params.amount', 'op' => 'lte', 'value' => 0],
            ['field' => 'action.params.amount', 'op' => 'gte', 'value' => 0]]]], $p['predicates']);
        self::assertSame([['type' => 'reversibility_max', 'class' => 'reversible']], $p['caveats']);
        self::assertSame('dollars', $p['budgetModel']);
        // nothing granted is irreversible: within-cap actions auto-approve (theta 1); a zero cap is kappa = bMax = 1
        self::assertSame(['weights' => ['alpha' => 0, 'beta' => 0, 'gamma' => 1, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0],
            'theta1' => 1, 'theta2' => 1, 'kappa' => 1, 'lambda' => 0, 'rho' => 0.5, 'bMax' => 1], $p['riskPolicy']);

        $half = Facade::compilePolicy(['shop' => ['tip']], ['tip' => '$0.5'], $c, now: 0)['riskPolicy'];
        self::assertSame([0.5, 0.5, 1, 1], [$half['kappa'], $half['bMax'], $half['theta1'], $half['theta2']]);

        // an unknown class never counts as stricter than 'reversible'
        self::assertSame([['type' => 'reversibility_max', 'class' => 'reversible']], Facade::compilePolicy(['shop' => ['odd']], null, $c, now: 0)['caveats']);
        self::assertSame([['type' => 'reversibility_max', 'class' => 'reversible']], Facade::compilePolicy(['shop' => ['odd', 'tip']], null, $c, now: 0)['caveats']);

        $h = Facade::createAgent(self::kp(1), 'tip couriers', ['shop' => ['tip']], ['tip' => '$5'], catalog: $c, aud: 'rs', now: 0);
        self::assertSame('tips/*', $h->policy['predicates'][0]['resource']);
    }

    public function testRiskPolicyOverrideMergesWeights(): void
    {
        $rp = Facade::compilePolicy(['gmail' => ['draft']], null, null, null, ['weights' => ['alpha' => 0.5], 'kappa' => 3], 0)['riskPolicy'];
        self::assertSame(['alpha' => 0.5, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05], $rp['weights']);
        self::assertSame(3, $rp['kappa']);
        self::assertSame(0.25, $rp['theta1']);
    }

    public function testDefaultClocks(): void
    {
        $before = (int)(microtime(true) * 1000);
        $c = Facade::compilePolicy(['slack' => ['post_message']], ['post_message' => '5/hour']);
        $h = Facade::createAgent(self::kp(1), 'g', ['stripe' => ['refund']], ['refund' => '$5/day'], aud: 'rs');
        $after = (int)(microtime(true) * 1000);
        $at = $c['caveats'][1]['at'];
        self::assertIsInt($at);
        self::assertGreaterThanOrEqual($before + 3600000, $at);
        self::assertLessThanOrEqual($after + 3600000, $at);
        self::assertGreaterThanOrEqual($before, $h->budget['tau']);
        self::assertLessThanOrEqual($after, $h->budget['tau']);
        $exp = $h->grant->get('caveats')[0]->get('caveats')[1]->get('at')->int();
        self::assertGreaterThanOrEqual($before + 86400000, $exp);
        self::assertLessThanOrEqual($after + 86400000, $exp);
    }

    public function testRiskForReadsTheAmountLikeJavaScriptNumber(): void
    {
        $pol = ['budgetModel' => 'dollars', 'riskPolicy' => ['kappa' => 100]];
        $spec = ['amountField' => 'amount', 'blastRadius' => 0.9];
        $cases = [
            [null, 0], [true, 0.01], [false, 0], [42, 0.42], [42.5, 0.425], [new Num('42'), 0.42], ['42', 0.42], [' 42 ', 0.42],
            ["\u{A0}42\n", 0.42], ['', 0], ['   ', 0], ['abc', 0.9], ['0x10', 0.16], ['4e1', 0.4], [[5], 0.05], [['7'], 0.07], [[], 0],
            [[1, 2], 0.9], [['k' => 1], 0.9], [Obj::of(['a' => 1]), 0.9], [250, 1],
        ];
        foreach ($cases as $i => [$amt, $want]) {
            $got = Facade::riskFor($pol, $spec, ['amount' => $amt]);
            self::assertFalse(is_nan((float)$got), "case $i");
            self::assertEquals($want, $got, "case $i");
        }
        self::assertSame(0.9, Facade::riskFor($pol, $spec, ['other' => 1]));
        self::assertSame(0.42, Facade::riskFor($pol, $spec, Obj::of(['amount' => new Num('42')])));
        // the risk budget model ignores the amount; a zero kappa falls back to the blast radius (no division)
        self::assertSame(0.9, Facade::riskFor(['budgetModel' => 'risk', 'riskPolicy' => ['kappa' => 100]], $spec, ['amount' => 42]));
        self::assertSame(0.9, Facade::riskFor(['budgetModel' => 'dollars', 'riskPolicy' => ['kappa' => 0]], $spec, ['amount' => 42]));
        self::assertSame(0.9, Facade::riskFor($pol, ['blastRadius' => 0.9], ['amount' => 42]));
        // an override wins and is clamped to [0, 1]
        self::assertSame(0.3, Facade::riskFor($pol, $spec, ['amount' => 42], 0.3));
        self::assertEquals(0, Facade::riskFor($pol, $spec, ['amount' => 42], -0.5));
        self::assertEquals(1, Facade::riskFor($pol, $spec, ['amount' => 42], 1.5));
        self::assertEquals(0, Facade::riskFor($pol, ['blastRadius' => -0.2], null));
    }

    public function testAutonomyBound(): void
    {
        self::assertEquals(10, self::handle([], ['kappa' => 2, 'bMax' => 10])->autonomyBound);
        self::assertEquals(0.5, self::handle([], ['kappa' => 1, 'bMax' => 0.5])->autonomyBound);
        self::assertEquals(0, self::handle([], ['kappa' => 1, 'bMax' => -0.5])->autonomyBound);
        self::assertEquals(0, self::handle([], ['kappa' => 0, 'bMax' => 10])->autonomyBound);
        self::assertEquals(0, self::handle([], ['kappa' => -2, 'bMax' => 10])->autonomyBound);
        self::assertSame(['B' => 10, 'tau' => 0, 'asOf' => 0], self::handle([], ['kappa' => 2, 'bMax' => 10])->budget);
    }

    public function testDryRunOutcomes(): void
    {
        self::assertSame(['allowed' => false, 'reason' => 'envelope grants no predicates'], self::handle([], [], [])->dryRun('files.read', 'f', null, 0));
        $exp = self::handle([['type' => 'expires', 'at' => 1000]]);
        self::assertSame(['allowed' => true, 't' => 1], $exp->dryRun('files.read', 'f', null, 999));
        self::assertSame(['allowed' => false, 'reason' => 'caveat(s) failed: expires'], $exp->dryRun('files.read', 'f', null, 1000));
        // delegation depth = hops - 1
        $d0 = [['type' => 'delegation_depth', 'max' => 0]];
        self::assertSame(['allowed' => true, 't' => 1], self::handle($d0)->dryRun('files.read', 'f', null, 0));
        self::assertSame(['allowed' => false, 'reason' => 'caveat(s) failed: delegation_depth'], self::handle($d0, [], null, 2)->dryRun('files.read', 'f', null, 0));
        self::assertSame(['allowed' => true, 't' => 1], self::handle([['type' => 'delegation_depth', 'max' => 1]], [], null, 2)->dryRun('files.read', 'f', null, 0));
        self::assertSame(['allowed' => false, 'reason' => 'caveat(s) failed: expires, delegation_depth'],
            self::handle([['type' => 'expires', 'at' => 0], ...$d0], [], null, 2)->dryRun('files.read', 'f', null, 5));
    }

    public function testDryRunDefaultClockIsNowInMilliseconds(): void
    {
        $real = (int)(microtime(true) * 1000);
        $failed = ['allowed' => false, 'reason' => 'caveat(s) failed: expires'];
        self::assertSame($failed, self::handle([['type' => 'expires', 'at' => $real - 10000000]])->dryRun('files.read', 'f'));
        self::assertSame(['allowed' => true, 't' => 1], self::handle([['type' => 'expires', 'at' => $real + 10000000]])->dryRun('files.read', 'f'));
        self::assertSame(['allowed' => true, 't' => 1], self::handle([['type' => 'not_before', 'at' => $real - 10000000]])->dryRun('files.read', 'f'));
    }

    public function testDryRunDefaultClockIsWholeMilliseconds(): void
    {
        // an expiry 0.005 ms into the current millisecond: the whole-millisecond clock is still before it, a fractional one is past it.
        // A try counts only when the dry run starts and ends inside one millisecond, at least 0.05 ms into it.
        for ($i = 0; $i < 5000; $i++) {
            $start = microtime(true) * 1000;
            $ms = floor($start);
            if ($start - $ms < 0.05) {
                continue;
            }
            $h = self::handle([['type' => 'expires', 'at' => $ms + 0.005]]);
            $r = $h->dryRun('files.read', 'f');
            if (floor(microtime(true) * 1000) !== $ms) {
                continue;
            }
            self::assertSame(['allowed' => true, 't' => 1], $r);
            return;
        }
        self::fail('no dry run finished inside one millisecond');
    }

    public function testDryRunReadsNumericStringThresholdsAsNumbers(): void
    {
        // like the reference's comparisons, a policy number given as a numeric string still counts as that number
        $h = self::handle([], ['theta1' => '0.5', 'theta2' => '0.75', 'kappa' => '2']);
        self::assertSame(['allowed' => true, 't' => 1], $h->dryRun('files.read', 'f', null, 0));
    }

    public function testDryRunBudgetCoversExactCost(): void
    {
        // r = 500 / 500 = 1 is tier 1 under theta 1; its cost 500 equals the budget B = 500, which covers it
        $h = self::handle([], ['theta1' => 1, 'theta2' => 1, 'kappa' => 500, 'bMax' => 500], [['verb' => 'shop.tip', 'resource' => '*']], 1, 'dollars', self::shop());
        self::assertSame(['allowed' => true, 't' => 1], $h->dryRun('shop.tip', 't', ['amount' => 500], 0));
        self::assertSame(['allowed' => true, 't' => 1], $h->dryRun('shop.tip', 't', ['amount' => 250], 0));
        $low = self::handle([], ['theta1' => 1, 'theta2' => 1, 'kappa' => 500, 'bMax' => 499], [['verb' => 'shop.tip', 'resource' => '*']], 1, 'dollars', self::shop());
        self::assertSame(['allowed' => true, 't' => 3], $low->dryRun('shop.tip', 't', ['amount' => 500], 0));
    }

    public function testActAudienceTtlBindingProvenanceAndSubAgents(): void
    {
        $h = Facade::createAgent(self::kp(1), 'g', ['files' => ['read']], agentBinding: ['model' => 'm1'], aud: 'rs', now: 1000);
        self::assertSame('m1', $h->grant->get('caveats')[0]->get('agent_binding')->get('model'));
        self::assertSame(Json::canonicalizeLenient($h->grant), $h->encodeGrant());

        $r = $h->act('files.read', 'f', ['x' => 1], aud: 'other', now: 1000, ttlMs: 5000);
        self::assertSame('other', $r['pcactn']->get('aud'));
        self::assertSame(6000, $r['pcactn']->get('exp')->int());
        self::assertSame('rs', $h->act('files.read', 'f', ['x' => 1], now: 1000)['pcactn']->get('aud'));

        // a handle without a provenance recorder acts with no bundle and no PCA-Provenance header
        $bare = new AgentHandle($h->grant, $h->chain, $h->goalSalt, $h->policy, $h->holder, $h->principalPublic, new Catalog(), 'rs', 1000, null);
        $b = $bare->act('files.read', 'f', ['x' => 1], now: 1000);
        self::assertNull($b['provenance']);
        self::assertSame(['PCA-Action'], array_keys($b['headers']));

        $s1 = $h->subAgent();
        $s2 = $s1->subAgent();
        self::assertCount(3, $s2->chain);
        self::assertSame($h->chain[0], $s2->chain[0]);
        self::assertSame($s1->chain[1], $s2->chain[1]);
    }
}
