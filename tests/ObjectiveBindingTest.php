<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ObjectiveBinding.php';

use Atlas\Pca\InMemoryInverseRegistry;
use Atlas\Pca\NativeHashEmbedder;
use Atlas\Pca\Obj;
use Atlas\Pca\ObjectiveBinding;
use Atlas\Pca\ObjectiveRisk;
use Atlas\Pca\ResourceGraph;
use PHPUnit\Framework\TestCase;

/** The binding of the objective-risk functional to a grant's signed envelope: nothing committed, malformed commitments, mismatches and a reproduced commitment. */
final class ObjectiveBindingTest extends TestCase
{
    private static function instance(): Obj
    {
        return Obj::of([
            'registry' => Obj::of(['trusted_verifiers' => ['v1'], 'entries' => [Obj::of(['verb' => 'files.write', 'inverse_kind' => 'files.restore', 'fidelity' => 'exact',
                'verification' => Obj::of(['verifier_id' => 'v1', 'evidence_digest' => 'e'])])]]),
            'graph' => Obj::of(['nodes' => [Obj::of(['id' => 'doc1', 'kind' => 'file']), Obj::of(['id' => 'doc2', 'kind' => 'file'])],
                'edges' => [Obj::of(['from' => 'doc1', 'to' => 'doc2', 'kind' => 'links'])]]),
        ]);
    }

    private static function commitment(?Obj $inst = null): Obj
    {
        $inst ??= self::instance();
        $reg = new InMemoryInverseRegistry(['v1']);
        $reg->register('files.write', Obj::of(['inverseKind' => 'files.restore', 'fidelity' => 'exact',
            'verification' => Obj::of(['verifierId' => 'v1', 'evidenceDigest' => 'e'])]));
        $g = new ResourceGraph();
        foreach ($inst->get('graph')->get('nodes') as $n) {
            $g->addNode($n);
        }
        foreach ($inst->get('graph')->get('edges') as $e) {
            $g->addEdge($e);
        }
        $cfg = ObjectiveRisk::defaultNativeConfig();
        $embedder = new NativeHashEmbedder($cfg);
        return Obj::of(['v' => 1, 'embedder' => Obj::of(['scheme' => 'native', 'model_id' => $embedder->modelId(), 'config' => $cfg]),
            'goal' => ObjectiveRisk::commitGoal($embedder, Obj::of(['verb' => 'files.read', 'resource' => 'doc1', 'params' => new Obj()])),
            'registry_digest' => $reg->digest(), 'graph_digest' => $g->digest(), 'authorized_kinds' => ['files.restore']]);
    }

    private static function grant(?Obj $objective): Obj
    {
        $env = Obj::of(['type' => 'envelope', 'goal_commit' => 'g', 'predicates' => [], 'caveats' => [], 'agent_binding' => new Obj(),
            'risk_policy' => Obj::of(['bMax' => 1, 'kappa' => 1, 'lambda' => 0.0005, 'rho' => 0.5, 'theta1' => 0.25, 'theta2' => 0.6,
                'weights' => Obj::of(['alpha' => 0.25, 'beta' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'gamma' => 0.2, 'zeta' => 0.05])])]);
        if ($objective !== null) {
            $env->set('objective_risk', $objective);
        }
        return Obj::of(['id' => 'g1', 'caveats' => [$env]]);
    }

    private static function action(): Obj
    {
        return Obj::of(['verb' => 'files.read', 'resource' => 'doc1', 'params' => new Obj()]);
    }

    public function testAGrantThatCommitsNothingIsUnaffected(): void
    {
        $this->assertSame([], ObjectiveBinding::readObjectiveCommitment(self::grant(null)));
        $this->assertSame(['mode' => 'none'], ObjectiveBinding::resolveObjectiveRisk(self::grant(null), self::action(), self::instance()));
        $this->assertSame([], ObjectiveBinding::readObjectiveCommitment(null));
    }

    public function testMalformedCommitmentsAreRefusedWithTheirReason(): void
    {
        $bad = [
            'objective_risk: unsupported shape/version' => static fn(Obj $c) => $c->set('v', 2),
            'objective_risk.embedder must be { scheme: "native", model_id, config }' => static fn(Obj $c) => $c->set('embedder', Obj::of(['scheme' => 'byo'])),
            'objective_risk.goal must be a goal commitment' => static fn(Obj $c) => $c->set('goal', 'x'),
            'objective_risk needs registry_digest and graph_digest' => static fn(Obj $c) => $c->set('graph_digest', ''),
            'objective_risk.calibration_digest must be a string' => static fn(Obj $c) => $c->set('calibration_digest', 5),
            'objective_risk.authorized_kinds must be string[]' => static fn(Obj $c) => $c->set('authorized_kinds', [1]),
            'objective_risk.denominations must be an array' => static fn(Obj $c) => $c->set('denominations', 'usd'),
            'objective_risk.on_mismatch must be "deny" or "heuristic"' => static fn(Obj $c) => $c->set('on_mismatch', 'allow'),
        ];
        foreach ($bad as $why => $mut) {
            $c = self::commitment();
            $mut($c);
            $r = ObjectiveBinding::resolveObjectiveRisk(self::grant($c), self::action(), self::instance());
            $this->assertSame(['mode' => 'mismatch', 'reasons' => [$why], 'onMismatch' => 'deny'], $r, $why);
        }
    }

    public function testACommitmentTheInstanceCannotReproduceIsAMismatch(): void
    {
        $r = ObjectiveBinding::resolveObjectiveRisk(self::grant(self::commitment()), self::action(), null);
        $this->assertSame('mismatch', $r['mode']);
        $this->assertSame(['the grant commits objective-risk facts but the instance holds no objective-risk config'], $r['reasons']);
        $c = self::commitment();
        $c->set('registry_digest', 'AAAA');
        $r = ObjectiveBinding::resolveObjectiveRisk(self::grant($c), self::action(), self::instance());
        $this->assertSame(['registry digest does not match the committed digest'], $r['reasons']);
        $c = self::commitment();
        $c->get('embedder')->set('model_id', 'other-model');
        $r = ObjectiveBinding::resolveObjectiveRisk(self::grant($c), self::action(), self::instance());
        $this->assertSame(['embedder model_id does not match the committed one'], $r['reasons']);
    }

    public function testAGrantCannotDowngradeToTheHeuristicOnItsOwn(): void
    {
        $c = self::commitment();
        $c->set('on_mismatch', 'heuristic');
        $c->set('registry_digest', 'AAAA');
        $this->assertSame('deny', ObjectiveBinding::resolveObjectiveRisk(self::grant($c), self::action(), self::instance())['onMismatch']);
        $inst = self::instance();
        $inst->set('allow_heuristic_fallback', true);
        $this->assertSame('heuristic', ObjectiveBinding::resolveObjectiveRisk(self::grant($c), self::action(), $inst)['onMismatch']);
    }

    public function testAReproducedCommitmentGivesTheObjectiveInputs(): void
    {
        $r = ObjectiveBinding::resolveObjectiveRisk(self::grant(self::commitment()), self::action(), self::instance());
        $this->assertSame('objective', $r['mode'], json_encode($r['reasons'] ?? null));
        $this->assertSame(['reversibility', 'blastRadius', 'semanticDistance'], $r['inputs']->keys());
        $this->assertIsString($r['evidenceDigest']);
        $this->assertGreaterThanOrEqual(0.0, (float)$r['r']);
        $this->assertLessThanOrEqual(1.0, (float)$r['r']);
        // the same facts give the same evidence
        $again = ObjectiveBinding::resolveObjectiveRisk(self::grant(self::commitment()), self::action(), self::instance());
        $this->assertSame($r['evidenceDigest'], $again['evidenceDigest']);
        // a different action is a different piece of evidence
        $other = ObjectiveBinding::resolveObjectiveRisk(self::grant(self::commitment()), Obj::of(['verb' => 'files.write', 'resource' => 'doc2', 'params' => new Obj()]), self::instance());
        $this->assertSame('objective', $other['mode']);
        $this->assertNotSame($r['evidenceDigest'], $other['evidenceDigest']);
    }
}
