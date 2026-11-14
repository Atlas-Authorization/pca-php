<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentV2.php';

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for src/IntentV2.php (decideIntentV2 core): rule 21 (`tighten`) evaluates over the VERIFIER-computed
 * env (env.acc from rule 15) merged into the context env, not only the host's. Signed fixtures are IntentV2KillTest's own
 * (called through reflection).
 */
final class K05KillIntentV2CoreTest extends TestCase
{
    private const RISK = '"risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,"theta2":1,'
        . '"kappa":1,"lambda":0,"rho":0,"bMax":0}';

    private static function kt(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(IntentV2KillTest::class, $m))->invokeArgs(null, $a);
    }

    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    public function testTightenSeesTheVerifierComputedAccEnv(): void
    {
        // the base PCActn passes rule 15, so env.acc.trip_spend.post = 38900; a deny rule reading it fires only when the
        // verifier env is merged into rule 21's context (without it the path is missing: "could not be decided")
        [$g, $p] = self::kt('base');
        $env = $g->get('caveats')[0];
        $env->set('predicates', self::j('[{"verb":"*","where":[]}]'));
        $env->set('caveats', []);
        $env->set('agent_binding', self::j('{}'));
        $env->set('risk_policy', self::j('{' . self::RISK . '}')->get('risk_policy'));
        $env->set('tighten', self::j('[{"id":"r1","when":{"field":"env.acc.trip_spend.post","op":"gt","value":1},"signal":"deny"}]'));
        $r = self::kt('v2', $p, $g, self::kt('ctx'));
        $this->assertTrue($r['accumulators']);
        $this->assertSame("denied by tighten rule 'r1'", $r['tighten']);
    }
}
