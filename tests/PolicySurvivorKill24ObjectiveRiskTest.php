<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ByoEmbedder;
use Atlas\Pca\EmbeddingError;
use Atlas\Pca\InMemoryInverseRegistry;
use Atlas\Pca\NativeHashEmbedder;
use Atlas\Pca\Obj;
use Atlas\Pca\ObjEmbedder;
use Atlas\Pca\ObjectiveRisk;
use Atlas\Pca\ObjectiveRiskContext;
use Atlas\Pca\ResourceGraph;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24) for src/ObjectiveRisk.php: registry and graph copies and digests, embedder config limits, vectors, harm, the oracle's fail-closed reason. */
final class PolicySurvivorKill24ObjectiveRiskTest extends TestCase
{
    private static function priv(string $class, string $m): \ReflectionMethod
    {
        $r = new \ReflectionMethod($class, $m);
        $r->setAccessible(true);
        return $r;
    }

    /** A registered verification is copied, not shared with the caller. */
    public function testRegisterCopiesTheVerification(): void
    {
        $ver = Obj::of(['verifierId' => 't']);
        $reg = (new InMemoryInverseRegistry(['t']))->register('v', Obj::of(['inverseKind' => 'k', 'fidelity' => 'exact', 'verification' => $ver]));
        $ver->set('verifierId', 'x');
        $this->assertSame('t', $reg->lookup('v')->get('verification')->get('verifierId'));
    }

    /** Re-adding a node keeps its outgoing edges. */
    public function testReAddingANodeKeepsItsEdges(): void
    {
        $g = (new ResourceGraph())->addNode(Obj::of(['id' => 'a']))->addNode(Obj::of(['id' => 'b']));
        $g->addEdge(Obj::of(['from' => 'a', 'to' => 'b', 'kind' => 'k']));
        $g->addNode(Obj::of(['id' => 'a']));
        $this->assertSame(['a', 'b'], $g->reachable('a'));
    }

    /** The graph digest sorts edges by from, to and kind kept apart, so insertion order never matters. */
    public function testGraphDigestIsOrderIndependent(): void
    {
        $nodes = ['a', 'ab', 'b', 'bc', 'c'];
        $edges = [['a', 'bc', 'k'], ['ab', 'c', 'k'], ['a', 'b', 'ck']];
        $build = static function (array $nodes, array $edges): string {
            $g = new ResourceGraph();
            foreach ($nodes as $n) {
                $g->addNode(Obj::of(['id' => $n]));
            }
            foreach ($edges as [$f, $t, $k]) {
                $g->addEdge(Obj::of(['from' => $f, 'to' => $t, 'kind' => $k]));
            }
            return $g->digest();
        };
        $this->assertSame($build($nodes, $edges), $build(array_reverse($nodes), array_reverse($edges)));
    }

    private static function cfg(array $over = []): Obj
    {
        $c = ObjectiveRisk::defaultNativeConfig();
        foreach ($over as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    /** Config limits: a non-number dims is a range error, ngramMin = ngramMax = 8 is allowed, the weights are copied. */
    public function testNativeConfig(): void
    {
        try {
            new NativeHashEmbedder(self::cfg(['dims' => 'x']));
            $this->fail('accepted dims x');
        } catch (\RangeException $e) {
            $this->assertSame('native config: dims must be an integer in [8, 65536]', $e->getMessage());
        }
        $this->assertSame(8, (new NativeHashEmbedder(self::cfg(['ngramMin' => 8, 'ngramMax' => 8])))->config()->get('ngramMin'));
        $c = self::cfg();
        $e = new NativeHashEmbedder($c);
        $w = $e->config()->get('fieldWeights')->get('verb');
        $c->get('fieldWeights')->set('verb', $w + 1);
        $this->assertSame($w, $e->config()->get('fieldWeights')->get('verb'));
    }

    /** Words are lowercased with Unicode rules; array leaves are numbered from 0; object leaves are sorted. */
    public function testFeaturesAndLeaves(): void
    {
        $e = new NativeHashEmbedder(self::cfg());
        $f = self::priv(NativeHashEmbedder::class, 'textFeatures')->invoke($e, 'r:', "\u{C9}");
        $this->assertSame("r:w:\u{E9}", $f[count($f) - 1]);
        $leaves = self::priv(NativeHashEmbedder::class, 'leaves');
        $out = [];
        $leaves->invokeArgs(null, [[5 => 'x'], '', &$out]);
        $this->assertSame(['[0]="x"'], $out);
        $out = [];
        $leaves->invokeArgs(null, [Obj::of(['b' => 1, 'a' => 2]), '', &$out]);
        $this->assertSame(['a=2', 'b=1'], $out);
    }

    private static function byo(mixed $dims, mixed $bits): ByoEmbedder
    {
        return new ByoEmbedder(Obj::of(['dims' => $dims, 'quantization' => Obj::of(['bits' => $bits, 'scale' => 1]), 'inputEncoding' => 'pca-canonical-action-json-v1']),
            static fn(string $j): array => [1]);
    }

    /** BYO limits: dims 1 and bits 2 are allowed, dims 0 is refused. */
    public function testByoLimits(): void
    {
        $this->assertSame(1, self::byo(1, 3)->dims());
        $this->assertSame([1], self::byo(1, 2)->embed(Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => new Obj()])));
        $this->expectException(\RangeException::class);
        $this->expectExceptionMessage('byo: dims must be a positive integer');
        self::byo(0, 3);
    }

    /** canonicalAction: exact refusals, and strings inside list params are NFC. */
    public function testCanonicalAction(): void
    {
        foreach ([[['verb' => 'v', 'resource' => 5], 'canonicalAction: verb/resource must be strings'], [['verb' => "\xFF", 'resource' => 'r'], 'canonicalAction: empty verb/resource']] as [$a, $msg]) {
            try {
                ObjectiveRisk::canonicalAction(Obj::of($a));
                $this->fail($msg);
            } catch (\TypeError $e) {
                $this->assertSame($msg, $e->getMessage());
            }
        }
        $c = ObjectiveRisk::canonicalAction(Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['a' => ["e\u{301}"]])]));
        $this->assertSame(["\u{E9}"], $c->get('params')->get('a'));
    }

    /** validateVector: exact errors, a null dims means 0, components come back as ints. */
    public function testValidateVector(): void
    {
        foreach ([['x', 8, 'vector must have exactly 8 components'], [['x'], 1, 'vector components must be safe integers'],
            [[9007199254740991], 1, 'vector component out of range']] as [$v, $d, $msg]) {
            try {
                ObjectiveRisk::validateVector($v, $d);
                $this->fail($msg);
            } catch (EmbeddingError $e) {
                $this->assertSame($msg, $e->getMessage());
            }
        }
        $this->assertSame([], ObjectiveRisk::validateVector([], null));
        $this->assertSame([1, -2], ObjectiveRisk::validateVector([1.0, -2.0], 2));
    }

    /** conformanceCheck compares by position, whatever the array keys. */
    public function testConformanceCheckByPosition(): void
    {
        $emb = static fn(array $v): ObjEmbedder => new class ($v) implements ObjEmbedder {
            public function __construct(private array $v)
            {
            }

            public function modelId(): mixed
            {
                return 'm';
            }

            public function config(): mixed
            {
                return null;
            }

            public function dims(): mixed
            {
                return 1;
            }

            public function embed(Obj $action): mixed
            {
                return $this->v;
            }
        };
        $case = static fn(array $want): array => [Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r']), 'vector' => $want])];
        $this->assertTrue(ObjectiveRisk::conformanceCheck($emb([1 => 5]), $case([5])));
        $this->assertTrue(ObjectiveRisk::conformanceCheck($emb([5]), $case([1 => 5])));
    }

    /** A goal whose vector has the wrong length fails verification even with a matching commit. */
    public function testGoalVectorIsValidated(): void
    {
        $e = new NativeHashEmbedder(self::cfg());
        $g = ObjectiveRisk::commitGoal($e, Obj::of(['verb' => 'v', 'resource' => 'r']));
        $this->assertNull(ObjectiveRisk::verifyGoalCommitment($g, $e), 'control');
        $g->set('goalVector', [1]);
        $g->set('commit', ObjectiveRisk::hash(self::priv(ObjectiveRisk::class, 'goalInput')->invoke(null, $g)));
        $this->assertStringStartsWith('vector must have exactly ', (string)ObjectiveRisk::verifyGoalCommitment($g, $e));
    }

    /** clamp01 keeps -0 (as the reference does); subCmp is the sign of the difference. */
    public function testClampAndSubCmp(): void
    {
        $this->assertSame(-INF, fdiv(1, self::priv(ObjectiveRisk::class, 'clamp01')->invoke(null, -0.0)));
        $s = self::priv(ObjectiveRisk::class, 'subCmp');
        $this->assertSame([-1, 1, 0, 0], [$s->invoke(null, 1.0, 2.0), $s->invoke(null, 2.0, 1.0), $s->invoke(null, 1.0, 1.0), $s->invoke(null, NAN, 1.0)]);
    }

    /** harmReport skips zero weights and zero ceilings, reads only an Obj of units, and never reads a missing id. */
    public function testHarmReport(): void
    {
        $ok = Obj::of(['id' => 'e', 'weight' => 1, 'ceiling' => 10]);
        $units = Obj::of(['e' => 5, 'd' => 'x', 'undefined' => 10]);
        $this->assertSame(0.5, ObjectiveRisk::harmReport($units, [$ok])->get('normalized'));
        $this->assertSame(0.5, ObjectiveRisk::harmReport($units, [$ok, Obj::of(['id' => 'd', 'weight' => 0, 'ceiling' => 1])])->get('normalized'));
        $this->assertSame(0.5, ObjectiveRisk::harmReport($units, [$ok, Obj::of(['id' => 'e', 'weight' => 1, 'ceiling' => 0])])->get('normalized'));
        $this->assertSame(0.25, ObjectiveRisk::harmReport($units, [$ok, Obj::of(['weight' => 1, 'ceiling' => 10])])->get('normalized'));
        $this->assertSame(0.0, ObjectiveRisk::harmReport(null, [$ok])->get('normalized'));
    }

    private static function ctx(array $denoms, array $auth = ['a', 'b']): ObjectiveRiskContext
    {
        $reg = new InMemoryInverseRegistry([]);
        $g = (new ResourceGraph())->addNode(Obj::of(['id' => 'res']));
        $e = new NativeHashEmbedder(self::cfg());
        $goal = ObjectiveRisk::commitGoal($e, Obj::of(['verb' => 'pay', 'resource' => 'res']));
        $w = Obj::of(['alpha' => 1, 'beta' => 1, 'gamma' => 1, 'delta' => 1, 'epsilon' => 1, 'zeta' => 1]);
        return new ObjectiveRiskContext($reg, $auth, $g, null, $e, $goal, Obj::of(['registryDigest' => $reg->digest(), 'graphDigest' => $g->digest()]),
            $denoms, $w, 0, 0);
    }

    /** The evidence digest does not depend on the order of the authorized kinds. */
    public function testEvidenceSortsAuthorizedKinds(): void
    {
        $a = Obj::of(['verb' => 'pay', 'resource' => 'res']);
        $x = ObjectiveRisk::objectiveRisk($a, self::ctx([], ['a', 'b']));
        $this->assertTrue($x->get('valid'));
        $this->assertSame($x->get('evidenceDigest'), ObjectiveRisk::objectiveRisk($a, self::ctx([], ['b', 'a']))->get('evidenceDigest'));
    }

    /** The oracle turns an error into an invalid result naming it. */
    public function testOracleErrorReason(): void
    {
        $snap = Obj::of(['action' => Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => 'res'])])]);
        $this->assertTrue(ObjectiveRisk::objectiveRiskOracle(self::ctx([]), 'blastRadius', $snap)->get('valid'), 'control');
        $r = ObjectiveRisk::objectiveRiskOracle(self::ctx([null]), 'blastRadius', $snap);
        $this->assertSame(['input' => 'blastRadius', 'valid' => false, 'reason' => "objective oracle error (fail closed): Cannot read properties of null (reading 'weight')"],
            ['input' => $r->get('input'), 'valid' => $r->get('valid'), 'reason' => $r->get('reason')]);
        $this->assertSame(['input', 'valid', 'reason'], $r->keys());
    }
}
