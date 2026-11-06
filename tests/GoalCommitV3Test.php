<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Goal binding v3 (`approved_goal`): the shared goal-commit-vectors.json plus the misconfiguration and floor cases. A missing
 * vector file fails the test.
 */
final class GoalCommitV3Test extends TestCase
{
    private const G = 'B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw';
    private const P = '9U7dBfYHPTNYZ84mWFHOiddEAPc7IEQ1AMEVp13dqSo';

    public function testSharedVectors(): void
    {
        [$n, $fails] = NativeParityVectors::goal();
        $this->assertSame([], $fails);
        $this->assertSame(27, $n);
    }

    private static function intent(string $salt = 's', int $fid = 900000, int $risk = 10): Obj
    {
        return Obj::of(['ref' => Pca::b64u(str_repeat("\x01", 32)), 'map_digest' => Pca::b64u(str_repeat("\x02", 32)),
            'goal_salt' => $salt, 'fidelity_ppm' => new \Atlas\Pca\Num((string)$fid), 'residual_risk_ppm' => new \Atlas\Pca\Num((string)$risk)]);
    }

    private static function grant(string $commit): Obj
    {
        return Obj::of(['caveats' => [Obj::of(['type' => 'envelope', 'goal_commit' => $commit])]]);
    }

    /** a misconfigured approved_goal activates the policy and fails closed, never "absent" */
    public function testMisconfiguredApprovedGoalFailsClosed(): void
    {
        $g = self::G;
        $bad = [
            'extra' => ['goal_digest' => $g, 'policy_digest' => $g, 'x' => 1],
            'missing' => ['goal_digest' => $g],
            'non-string' => ['goal_digest' => $g, 'policy_digest' => 5],
            'null' => null,
            'list' => [],
            'short' => ['goal_digest' => 'AAAA', 'policy_digest' => $g],
            'empty' => ['goal_digest' => '', 'policy_digest' => $g],
            'padded' => ['goal_digest' => $g . '=', 'policy_digest' => $g],
        ];
        foreach ($bad as $name => $ag) {
            $d = Pca::decideIntentBinding(null, new Obj(), ['approved_goal' => $ag]);
            $this->assertSame('fail', $d['status'], $name);
            $this->assertStringContainsString('misconfigured', $d['reason'], $name);
        }
    }

    public function testV3OpensOnlyTheApprovedPair(): void
    {
        $ref = ['goal_digest' => self::G, 'policy_digest' => self::P];
        $grant = self::grant(Pca::intentGoalCommitV3($ref, 's'));
        $this->assertSame('pass', Pca::decideIntentBinding(self::intent(), $grant, ['approved_goal' => $ref])['status']);
        $swapped = ['goal_digest' => self::P, 'policy_digest' => self::G];
        $this->assertSame('fail', Pca::decideIntentBinding(self::intent(), $grant, ['approved_goal' => $swapped])['status']);
        $this->assertSame('fail', Pca::decideIntentBinding(self::intent('other'), $grant, ['approved_goal' => $ref])['status']);
        // a v3 grant does not open under a verifier without approved_goal
        $this->assertSame('fail', Pca::decideIntentBinding(self::intent(), $grant, ['require' => true])['status']);
        // a v1 grant does not open under a v3 policy
        $i = self::intent();
        $v1 = self::grant(Pca::intentGoalCommit($i->get('ref'), $i->get('map_digest'), 's'));
        $this->assertSame('pass', Pca::decideIntentBinding($i, $v1, ['require' => true])['status']);
        $this->assertSame('fail', Pca::decideIntentBinding($i, $v1, ['approved_goal' => $ref])['status']);
        // absent intent and absent commitment fail
        $this->assertSame('fail', Pca::decideIntentBinding(null, $grant, ['approved_goal' => $ref])['status']);
        $this->assertSame('fail', Pca::decideIntentBinding($i, new Obj(), ['approved_goal' => $ref])['status']);
    }

    public function testFloorsStillApplyUnderV3(): void
    {
        $ref = ['goal_digest' => self::G, 'policy_digest' => self::P];
        $grant = self::grant(Pca::intentGoalCommitV3($ref, 's'));
        $i = self::intent('s', 900000, 10);
        $this->assertSame('fail', Pca::decideIntentBinding($i, $grant, ['approved_goal' => $ref, 'min_fidelity_ppm' => 900001])['status']);
        $this->assertSame('fail', Pca::decideIntentBinding($i, $grant, ['approved_goal' => $ref, 'max_residual_risk_ppm' => 9])['status']);
        $this->assertSame('pass', Pca::decideIntentBinding($i, $grant, ['approved_goal' => $ref, 'min_fidelity_ppm' => 900000, 'max_residual_risk_ppm' => 10])['status']);
    }

    public function testIntentGoalV3RefusesGarbage(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Pca::intentGoalV3(['goal_digest' => 'AAAA', 'policy_digest' => self::P]);
    }
}
