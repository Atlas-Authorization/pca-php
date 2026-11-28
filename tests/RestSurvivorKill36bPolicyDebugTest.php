<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PolicyDebug.php';

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\PolicyDebug;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** PolicyDebug: explainRisk defaults and signed zeros, explainDecision on edge inputs, auditPCActn's plan-root default. */
final class RestSurvivorKill36bPolicyDebugTest extends TestCase
{
    private static function grant(array $policy = []): Obj
    {
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => $policy + Sign::defaultRiskPolicy()];
        return Sign::mintGrant(new KeyPair(str_repeat("\x01", 32)), (new KeyPair(str_repeat("\x02", 32)))->public, $env, 'refund an order', 'c2FsdA')['grant'];
    }

    private static function zeros(): Obj
    {
        return Obj::of(['alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05]);
    }

    /** Without an rFloor argument the caution floor is 0, so r is the score itself. */
    public function testDefaultFloorIsZero(): void
    {
        $in = Obj::of(['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0]);
        $r = PolicyDebug::explainRisk($in, self::zeros());
        self::assertSame(0.0, $r->get('rFloor'));
        self::assertSame(0.0, $r->get('r'));
        self::assertSame(1.0, PolicyDebug::explainRisk($in, self::zeros(), 1)->get('r'));
    }

    /** A -0 input is kept as given (the reference's clamp), a -0 weight is no weight (+0). */
    public function testSignedZeros(): void
    {
        $in = Obj::of(['semanticDistance' => -0.0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0]);
        $w = Obj::of(['alpha' => -0.0, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05]);
        $t = PolicyDebug::explainRisk($in, $w, 0)->get('terms')[0];
        self::assertSame('semanticDistance', $t->get('term'));
        self::assertSame(-INF, fdiv(1.0, $t->get('input')));
        self::assertSame(INF, fdiv(1.0, $t->get('weight')));
    }

    /** A non-object input is explained as the empty input (no envelope), not a crash. */
    public function testNonObjectInput(): void
    {
        $e = PolicyDebug::explainDecision('not an input');
        self::assertFalse($e->get('envelopeValid'));
        self::assertFalse($e->get('autoAllow'));
    }

    /** The safety bound is bMax / kappa: 1 under the default policy, 0.5 for bMax 0.5. */
    public function testSafetyBound(): void
    {
        self::assertSame(1.0, PolicyDebug::explainDecision(null)->get('budget')->get('safetyBound'));
        $in = Obj::of(['grant' => self::grant(['bMax' => 0.5]), 'budget' => Obj::of(['B' => 0.5, 'tau' => 0]), 'now' => 0]);
        $e = PolicyDebug::explainDecision($in);
        self::assertTrue($e->get('envelopeValid'));
        self::assertSame(0.5, $e->get('budget')->get('safetyBound'));
    }

    /** A plan with a non-string node id prices the semantic distance at the worst case (1), never calls the geodesic with it. */
    public function testNonStringNodeId(): void
    {
        $in = Obj::of(['grant' => self::grant(), 'budget' => Obj::of(['B' => 1, 'tau' => 0]), 'now' => 0,
            'plan' => [Obj::of(['id' => 'n1'])], 'nodeId' => 5,
            'risk' => Obj::of(['reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1, 'age' => 0])]);
        $e = PolicyDebug::explainDecision($in);
        self::assertTrue($e->get('envelopeValid'));
        self::assertSame(1.0, $e->get('risk')->get('inputs')->get('semanticDistance'));
    }

    /** A given finite ageHorizonMs is used for the age: half the horizon since the stamp is age 0.5. */
    public function testAgeHorizon(): void
    {
        $in = Obj::of(['grant' => self::grant(), 'budget' => Obj::of(['B' => 1, 'tau' => 0]), 'now' => 500, 'ageHorizonMs' => 1000,
            'risk' => Obj::of(['semanticDistance' => 0, 'reversibility' => 1, 'blastRadius' => 0, 'taint' => 0, 'confidence' => 1])]);
        $e = PolicyDebug::explainDecision($in);
        self::assertTrue($e->get('envelopeValid'));
        self::assertSame(0.5, $e->get('risk')->get('inputs')->get('age'));
    }

    /** auditPCActn enforces the plan-root check by default: without authorized roots it fails, and only the explicit opt-out reports not-enforced. */
    public function testPlanRootEnforcedByDefault(): void
    {
        $key = new KeyPair(str_repeat("\x02", 32));
        $grant = self::grant();
        $p = (new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/7')->pcactn;
        $now = $p->get('iat')->int();
        $r = PolicyDebug::auditPCActn($p, null, $grant, $now, 'rs-test');
        self::assertFalse($r['verify']->get('allow'));
        self::assertSame('fail', $r['verify']->get('checks')->get('plan_root_authorized'));
        self::assertSame('plan_root_authorized: no authorized plan is configured for this verifier (set authorizedPlanRoots, or the explicit insecureSkipPlanRootCheck)',
            $r['verify']->get('reason'));
        $skip = PolicyDebug::auditPCActn($p, null, $grant, $now, 'rs-test', true);
        self::assertSame('not-enforced', $skip['verify']->get('checks')->get('plan_root_authorized'));
        self::assertTrue($skip['verify']->get('allow'));
    }
}
