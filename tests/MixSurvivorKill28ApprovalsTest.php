<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Approvals.php';
require_once __DIR__ . '/../src/PolicyTemplates.php';

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Approvals;
use Atlas\Pca\Catalog;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PolicyTemplates;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in Approvals: limit wording, goal lineage without an envelope, review risk, the clock and class approvals. */
final class MixSurvivorKill28ApprovalsTest extends TestCase
{
    private const NOW = 1800000000000;

    protected function tearDown(): void
    {
        Approvals::$clockHook = null;
    }

    private function agent(): AgentHandle
    {
        return PolicyTemplates::fromTemplate('finance-bot', new KeyPair(str_repeat("\1", 32)), 'refund orders', 'rs', new KeyPair(str_repeat("\2", 32)), self::NOW);
    }

    private static function rootGrant(): Obj
    {
        return Sign::mintRoot(new KeyPair(str_repeat("\1", 32)), (new KeyPair(str_repeat("\2", 32)))->public, []);
    }

    /** An agent handle carrying exactly `$policy` (no constructor, so a malformed risk policy can be held). */
    private static function bare(array $policy): AgentHandle
    {
        $h = (new \ReflectionClass(AgentHandle::class))->newInstanceWithoutConstructor();
        $grant = self::rootGrant();
        \Closure::bind(function () use ($policy, $grant): void {
            $this->policy = $policy;
            $this->grant = $grant;
            $this->goalSalt = '';
        }, $h, AgentHandle::class)();
        return $h;
    }

    private static function risk(AgentHandle $a, string $verb, mixed $params): float
    {
        return (new \ReflectionMethod(Approvals::class, 'riskForReview'))->invoke(null, $a, $verb, $params);
    }

    private static function limitLabel(int $periodMs): string
    {
        $a = self::bare(['actions' => [['verb' => 'pay.send']], 'limits' => ['pay.send' => ['amount' => 5, 'unit' => 'count', 'periodMs' => $periodMs]]]);
        return Approvals::buildGoalLineage($a, 'pay.send', 'r')['chain'][1]['label'];
    }

    /** A sub-hour limit period reads in rounded minutes (half a minute rounds up), and a zero period is 0m, not 0d. */
    public function testSubHourPeriodsRoundToMinutes(): void
    {
        self::assertSame('Delegated authority to pay.send (up to 5/1m)', self::limitLabel(89999));
        self::assertSame('Delegated authority to pay.send (up to 5/2m)', self::limitLabel(90000));
        self::assertSame('Delegated authority to pay.send (up to 5/0m)', self::limitLabel(0));
        self::assertSame('Delegated authority to pay.send (up to 5/1d)', self::limitLabel(86400000));
    }

    /** An action spec without a description adds no detail to the authority node (and raises no warning). */
    public function testAuthorityNodeWithoutDescriptionHasNoDetail(): void
    {
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            $warnings[] = $msg;
            return true;
        });
        try {
            $l = Approvals::buildGoalLineage(self::bare(['actions' => [['verb' => 'pay.send']]]), 'pay.send', 'r');
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $warnings);
        self::assertSame(['kind' => 'authority', 'label' => 'Delegated authority to pay.send'], $l['chain'][1]);
        $d = Approvals::buildGoalLineage(self::bare(['actions' => [['verb' => 'pay.send', 'description' => 'Send money']]]), 'pay.send', 'r');
        self::assertSame('Send money', $d['chain'][1]['detail']);
    }

    /** A grant with no envelope gives an empty goal commitment in the lineage and in a step-up request, never an error. */
    public function testNoEnvelopeMeansEmptyGoalCommit(): void
    {
        $l = Approvals::buildGoalLineage(self::bare(['actions' => []]), 'pay.send', 'r');
        self::assertSame('', $l['goalCommit']);
        self::assertFalse($l['goalVerified']);
        self::assertSame(['kind' => 'goal', 'label' => 'Pursue the grant’s committed goal'], $l['chain'][0]);
        $real = $this->agent();
        $root = self::rootGrant();
        $h = new AgentHandle($root, [$root], $real->goalSalt, $real->policy, $real->holder, $real->principalPublic, new Catalog(), 'rs', self::NOW, null);
        $r = Approvals::reviewAction($h, 'stripe.refund', 'ch_12345678', ['amount' => 250], self::NOW, null, null, null, true);
        self::assertSame('step_up', $r['kind']);
        self::assertSame('', $r['request']['goalCommit']);
        self::assertSame('', $r['request']['lineage']['goalCommit']);
    }

    /** A malformed lineage node throws the engine-style TypeError naming null or a non-object. */
    public function testDescribeRefusesMalformedNodes(): void
    {
        foreach ([[null, "Cannot read properties of null (reading 'detail')"], ['x', "Cannot read properties of a non-object (reading 'detail')"]] as [$node, $msg]) {
            try {
                Approvals::describeGoalLineage(['chain' => [$node]]);
                self::fail('expected a TypeError');
            } catch (\TypeError $e) {
                self::assertSame($msg, $e->getMessage());
            }
        }
    }

    /** Under the dollars model the review risk is amount / kappa for a finite numeric amount, else the spec's blast radius. */
    public function testReviewRiskFromAmount(): void
    {
        $p = ['budgetModel' => 'dollars', 'actions' => [['verb' => 'pay.send', 'amountField' => 'amount', 'blastRadius' => 0.3]], 'riskPolicy' => ['kappa' => 100.0]];
        $a = self::bare($p);
        self::assertSame(0.5, self::risk($a, 'pay.send', ['amount' => 50]));
        self::assertSame(0.505, self::risk($a, 'pay.send', ['amount' => 50.5]));
        self::assertSame(0.5, self::risk($a, 'pay.send', ['amount' => '50']));
        self::assertSame(0.25, self::risk($a, 'pay.send', ['amount' => new Num('25')]));
        self::assertSame(0.3, self::risk($a, 'pay.send', ['amount' => 'abc']), 'a non-numeric string is not an amount');
        self::assertSame(0.3, self::risk($a, 'pay.send', ['other' => 1]), 'a missing amount is not zero');
        self::assertSame(1.0, self::risk($a, 'pay.send', ['amount' => 500]));
    }

    /** A zero or non-numeric kappa, or the risk model, falls back to the blast radius (default 0.8) instead of dividing. */
    public function testReviewRiskFallsBackToBlastRadius(): void
    {
        $spec = ['verb' => 'pay.send', 'amountField' => 'amount', 'blastRadius' => 0.3];
        self::assertSame(0.3, self::risk(self::bare(['budgetModel' => 'dollars', 'actions' => [$spec], 'riskPolicy' => ['kappa' => 0.0]]), 'pay.send', ['amount' => 50]));
        self::assertSame(0.3, self::risk(self::bare(['budgetModel' => 'dollars', 'actions' => [$spec], 'riskPolicy' => ['kappa' => 'abc']]), 'pay.send', ['amount' => 50]));
        self::assertSame(0.3, self::risk(self::bare(['budgetModel' => 'risk', 'actions' => [$spec], 'riskPolicy' => ['kappa' => 100.0]]), 'pay.send', ['amount' => 50]));
        self::assertSame(0.8, self::risk(self::bare(['budgetModel' => 'risk', 'actions' => [['verb' => 'pay.send']]]), 'pay.send', null));
        self::assertSame(0.3, self::risk(self::bare(['budgetModel' => 'risk', 'actions' => [['verb' => 'pay.send', 'blastRadius' => '0.3']]]), 'pay.send', null));
    }

    /** With no explicit time every record is stamped with the clock in whole milliseconds. */
    public function testDefaultTimeIsTheClockInWholeMilliseconds(): void
    {
        Approvals::$clockHook = static fn(): float => 1800000000.0005;
        self::assertSame(self::NOW, Approvals::recordDecision(['id' => 'r1'], 'approve', 'me')['at']);
        self::assertSame(self::NOW, Approvals::approveClass(['a.b'], 1000, 'ops')['grantedAt']);
        $holder = new KeyPair(str_repeat("\3", 32));
        $grant = Sign::mintRoot(new KeyPair(str_repeat("\1", 32)), $holder->public, []);
        self::assertSame('1800000001000', Approvals::timeBox($grant, $holder, 1000)->get('caveats')[0]->get('at')->lexeme);
        $r = Approvals::reviewAction($this->agent(), 'stripe.refund', 'ch_12345678', ['amount' => 250], null, null, null, null, true);
        self::assertSame('step_up', $r['kind']);
        self::assertSame(self::NOW, $r['request']['requestedAt']);
    }

    /** A class approval lists its verbs as a list in the order given, whatever keys the caller's array had. */
    public function testClassApprovalVerbsAreAList(): void
    {
        self::assertSame(['b.v', 'a.v'], Approvals::approveClass([3 => 'b.v', 7 => 'a.v'], 1000, 'ops', self::NOW)['verbs']);
    }

    /** A co-sign policy given as numeric strings recharges exactly as the numbers would. */
    public function testCosignAcceptsNumericStringPolicy(): void
    {
        $b = ['B' => 0.2, 'tau' => 1.0, 'asOf' => 1.0];
        self::assertSame(['B' => 0.7, 'tau' => 9.0, 'asOf' => 9.0], Approvals::applyCosign($b, ['rho' => '0.5', 'bMax' => '1'], 9));
        self::assertSame(['B' => 1.0, 'tau' => 9.0, 'asOf' => 9.0], Approvals::applyCosign($b, ['rho' => '0.5', 'bMax' => '1'], 9, true));
    }
}
