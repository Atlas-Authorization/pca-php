<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\InMemoryInverseRegistry;
use Atlas\Pca\NativeHashEmbedder;
use Atlas\Pca\Obj;
use Atlas\Pca\ObjectiveBinding;
use Atlas\Pca\ObjectiveRisk;
use Atlas\Pca\ResourceGraph;
use PHPUnit\Framework\TestCase;

/** Mutation kills for ObjectiveBinding: commitment shape refusals, instance config handling, calibration binding, scope, taint and age. */
final class SigSurvivorKill29ObjectiveBindingTest extends TestCase
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

    private static function commitment(): Obj
    {
        $reg = new InMemoryInverseRegistry(['v1']);
        $reg->register('files.write', Obj::of(['inverseKind' => 'files.restore', 'fidelity' => 'exact',
            'verification' => Obj::of(['verifierId' => 'v1', 'evidenceDigest' => 'e'])]));
        $g = new ResourceGraph();
        foreach (self::instance()->get('graph')->get('nodes') as $n) {
            $g->addNode($n);
        }
        foreach (self::instance()->get('graph')->get('edges') as $e) {
            $g->addEdge($e);
        }
        $cfg = ObjectiveRisk::defaultNativeConfig();
        $embedder = new NativeHashEmbedder($cfg);
        return Obj::of(['v' => 1, 'embedder' => Obj::of(['scheme' => 'native', 'model_id' => $embedder->modelId(), 'config' => $cfg]),
            'goal' => ObjectiveRisk::commitGoal($embedder, Obj::of(['verb' => 'files.read', 'resource' => 'doc1', 'params' => new Obj()])),
            'registry_digest' => $reg->digest(), 'graph_digest' => $g->digest(), 'authorized_kinds' => ['files.restore']]);
    }

    private static function grant(mixed $objective): Obj
    {
        $env = Obj::of(['type' => 'envelope', 'goal_commit' => 'g', 'predicates' => [], 'caveats' => [], 'agent_binding' => new Obj(),
            'risk_policy' => Obj::of(['bMax' => 1, 'kappa' => 1, 'lambda' => 0.0005, 'rho' => 0.5, 'theta1' => 0.25, 'theta2' => 0.6,
                'weights' => Obj::of(['alpha' => 0.25, 'beta' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'gamma' => 0.2, 'zeta' => 0.05])])]);
        $env->set('objective_risk', $objective);
        return Obj::of(['id' => 'g1', 'caveats' => [$env]]);
    }

    private static function action(): Obj
    {
        return Obj::of(['verb' => 'files.read', 'resource' => 'doc1', 'params' => new Obj()]);
    }

    private static function with(Obj $o, array $set): Obj
    {
        $c = $o->without();
        foreach ($set as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    private static function resolve(Obj $c, ?Obj $inst = null, mixed $taint = null, mixed $age = null): array
    {
        return ObjectiveBinding::resolveObjectiveRisk(self::grant($c), self::action(), $inst ?? self::instance(), $taint, $age);
    }

    private function objective(array $r): array
    {
        $this->assertSame('objective', $r['mode'], json_encode($r['reasons'] ?? null));
        return $r;
    }

    private function reasons(array $r): array
    {
        $this->assertSame('mismatch', $r['mode']);
        return $r['reasons'];
    }

    /** Shape refusals that must stay refusals (never a throw, never an accepted commitment). */
    public function testCommitmentShapeRefusals(): void
    {
        $read = static fn (mixed $raw): array => ObjectiveBinding::readObjectiveCommitment(self::grant($raw));
        $this->assertSame(['malformed' => 'objective_risk: unsupported shape/version'], $read('x'));
        $emb = 'objective_risk.embedder must be { scheme: "native", model_id, config }';
        $cfg = ObjectiveRisk::defaultNativeConfig();
        $this->assertSame(['malformed' => $emb], $read(self::with(self::commitment(), ['embedder' => 'x'])));
        $this->assertSame(['malformed' => $emb], $read(self::with(self::commitment(), ['embedder' => Obj::of(['scheme' => 'byo', 'model_id' => 'm', 'config' => $cfg])])));
        $this->assertSame(['malformed' => $emb], $read(self::with(self::commitment(), ['embedder' => Obj::of(['scheme' => 'native', 'config' => $cfg])])));
        $kinds = 'objective_risk.authorized_kinds must be string[]';
        $this->assertSame(['malformed' => $kinds], $read(self::with(self::commitment(), ['authorized_kinds' => 'files.restore'])));
        $this->assertSame(['malformed' => $kinds], $read(self::with(self::commitment(), ['authorized_kinds' => ['a' => 'files.restore']])));
        $this->assertSame(['malformed' => 'objective_risk.denominations must be an array'],
            $read(self::with(self::commitment(), ['denominations' => ['a' => 1]])));
        $ok = self::with(self::commitment(), ['denominations' => []]);
        $this->assertSame(['commitment' => $ok], $read($ok));
    }

    /** Non-string trusted verifiers are dropped; an entry's verb is read as a string (so a numeric verb changes the registry digest). */
    public function testInstanceRegistryConfig(): void
    {
        $inst = self::instance();
        $inst->get('registry')->set('trusted_verifiers', [5, 'v1']);
        $this->objective(self::resolve(self::commitment(), $inst));
        $inst = self::instance();
        $inst->get('registry')->set('entries', [...$inst->get('registry')->get('entries'), Obj::of(['verb' => 5, 'inverse_kind' => 'k', 'fidelity' => 'exact'])]);
        $this->assertSame(['registry digest does not match the committed digest'], $this->reasons(self::resolve(self::commitment(), $inst)));
    }

    /** A throw while building the instance config fails closed with the cause in the reason. */
    public function testAnEvaluationErrorFailsClosedWithItsCause(): void
    {
        $inst = self::instance();
        $inst->get('graph')->set('edges', [Obj::of(['from' => 'doc1', 'to' => 'nowhere', 'kind' => 'links'])]);
        $this->assertSame(['objective risk evaluation error (fail closed): edge endpoints must exist'], $this->reasons(self::resolve(self::commitment(), $inst)));
    }

    /** A committed calibration set binds: the matching set calibrates r, a different or absent set is a mismatch, an uncommitted one is ignored. */
    public function testTheCalibrationBinding(): void
    {
        $plain = $this->objective(self::resolve(self::commitment()));
        $c = self::with(self::commitment(), ['calibration_digest' => ObjectiveRisk::calibrationDigest([0.5, 0.9])]);
        $inst = self::instance();
        $inst->set('calibration', [0.9, 0.5]);
        $cal = $this->objective(self::resolve($c, $inst));
        $this->assertSame(ObjectiveRisk::calibrate($plain['r'], [0.9, 0.5]), $cal['r']);
        $this->assertNotSame($plain['evidenceDigest'], $cal['evidenceDigest']);

        $why = ['calibration set does not match the committed digest'];
        $other = self::instance();
        $other->set('calibration', [0.1]);
        $this->assertSame($why, $this->reasons(self::resolve($c, $other)));
        $this->assertSame($why, $this->reasons(self::resolve($c)));
        // the set is digested as given: a non-number entry is not read as 0
        $zero = self::with(self::commitment(), ['calibration_digest' => ObjectiveRisk::calibrationDigest([0, 0.9])]);
        $odd = self::instance();
        $odd->set('calibration', ['zz', 0.9]);
        $this->assertSame($why, $this->reasons(self::resolve($zero, $odd)));

        // a calibration set the grant never committed to is not used
        $loose = $this->objective(self::resolve(self::commitment(), $inst));
        $this->assertSame($plain['r'], $loose['r']);
        $this->assertSame($plain['evidenceDigest'], $loose['evidenceDigest']);
    }

    /** A committed scope object enters the evidence; a non-object scope is no scope; duplicate kinds count once. */
    public function testScopeAndAuthorizedKinds(): void
    {
        $plain = $this->objective(self::resolve(self::commitment()));
        $scoped = $this->objective(self::resolve(self::with(self::commitment(), ['scope' => Obj::of(['edgeKinds' => ['links'], 'maxDepth' => 1])])));
        $this->assertNotSame($plain['evidenceDigest'], $scoped['evidenceDigest']);
        $junk = $this->objective(self::resolve(self::with(self::commitment(), ['scope' => 'x'])));
        $this->assertSame($plain['evidenceDigest'], $junk['evidenceDigest']);
        $dup = $this->objective(self::resolve(self::with(self::commitment(), ['authorized_kinds' => ['files.restore', 'files.restore']])));
        $this->assertSame($plain['evidenceDigest'], $dup['evidenceDigest']);
    }

    /** taint and age default to 1 and, when supplied, are what the evidence records. */
    public function testTaintAndAgeDefaultToOne(): void
    {
        $d = $this->objective(self::resolve(self::commitment()))['evidenceDigest'];
        $this->assertSame($d, $this->objective(self::resolve(self::commitment(), null, 1, 1))['evidenceDigest']);
        $this->assertNotSame($d, $this->objective(self::resolve(self::commitment(), null, 0.5))['evidenceDigest']);
        $this->assertNotSame($d, $this->objective(self::resolve(self::commitment(), null, null, 0.5))['evidenceDigest']);
    }
}
