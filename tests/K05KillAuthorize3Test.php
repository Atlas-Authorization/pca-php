<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\Assurance;
use Atlas\Pca\Authorize;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills from the full run where every mutant executed: readEnvelope on a host object that only looks like a grant,
 * the per-caveat fail-closed catch of the agent-native evaluator (through the Authorize::$evalHook seam), and Assurance::report's
 * default (pure PQ, not unbound PQ).
 */
final class K05KillAuthorize3Test extends TestCase
{
    private const GRANT = '{"id":"g1","caveats":[{"type":"envelope","goal_commit":"x","predicates":[{"verb":"*","where":[]}],"caveats":[],'
        . '"agent_binding":{},"risk_policy":{"weights":{"alpha":0,"beta":0,"gamma":0,"delta":0,"epsilon":0,"zeta":0},"theta1":0,'
        . '"theta2":1,"kappa":1,"lambda":0,"rho":0,"bMax":0}}]}';

    public function testReadEnvelopeNeedsAnObjGrant(): void
    {
        $grant = Json::parseLax(self::GRANT);
        $this->assertInstanceOf(Obj::class, Authorize::readEnvelope($grant), 'control: the real grant has an envelope');
        $fake = new class ($grant) {
            public function __construct(private readonly Obj $g)
            {
            }

            public function get(string $k): mixed
            {
                return $this->g->get($k);
            }

            public function has(string $k): bool
            {
                return $this->g->has($k);
            }
        };
        $this->assertNull(Authorize::readEnvelope($fake));
    }

    public function testAnErrorInsideOneCaveatFailsThatCaveat(): void
    {
        $pass = Obj::of(['type' => 'predicates', 'allow' => [Obj::of(['verb' => '*'])]]);
        $act = Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r'])]);
        $this->assertSame(['ok' => true, 'failed' => []], Authorize::evaluateAgentCaveats([$pass], null, $act), 'control');
        Authorize::$evalHook = static function (string $at): void {
            if ($at === 'agent_caveat') {
                throw new \RuntimeException('boom');
            }
        };
        try {
            $r = Authorize::evaluateAgentCaveats([$pass], null, $act);
        } finally {
            Authorize::$evalHook = null;
        }
        $this->assertSame(['ok' => false, 'failed' => ['predicates']], $r);
    }

    public function testReportDefaultsToPurePq(): void
    {
        $r = Assurance::report(['leaf_signature' => 'pass'], Obj::of(['alg' => 'ml-dsa-65']));
        $this->assertSame('pq', $r['leaf_signature']['level']);
    }
}
