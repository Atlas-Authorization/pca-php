<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Progress.php';

use Atlas\Pca\AttestedStateSource;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PotentialRegistry;
use Atlas\Pca\Pq;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Progress;
use Atlas\Pca\ProgressError;
use Atlas\Pca\ProgressTracker;
use Atlas\Pca\TransparencyLedger;
use Atlas\Pca\Undef;
use PHPUnit\Framework\TestCase;

/** Proof of progress: potential refusals, the set identity, goal and step validation, state attestations, the verifier hook, guards, trajectories. */
final class ToolSurvivorKill26ProgressTest extends TestCase
{
    private static function j(string $s): mixed
    {
        return Json::parseStrict($s);
    }

    private static function call(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Progress::class, $m))->invoke(null, ...$a);
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    private static function goal(): Obj
    {
        return self::j('{"objective":{"target":[0]},"potential":"l1-feature-v1","embedder":"","metric":"l1","epsilon":1,"explorationBudget":5}');
    }

    private static function kp(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/progress-kill26', true));
    }

    /** One tracked step from x=[2] to x=[1]. @return array{0:Obj,1:string,2:Obj} [goal, commitment, step] */
    private static function stepped(): array
    {
        $g = self::goal();
        $c = Progress::commitGoal($g)['commitment'];
        $t = new ProgressTracker($g, $c, self::j('{"x":[2]}'));
        $r = $t->step(self::j('{"x":[1]}'), 'A');
        self::assertTrue($r['ok']);
        return [$g, $c, $r['step']];
    }

    // ---- registry and potentials --------------------------------------------------------------------------------------------

    public function testRegistryRefusesNonCallable(): void
    {
        self::assertSame('TypeError: potential must be a function', self::thrown(fn() => (new PotentialRegistry())->register('a', 5)));
    }

    public function testDefaultPotentialsCached(): void
    {
        self::assertSame(Progress::defaultPotentials(), Progress::defaultPotentials());
    }

    public function testL1(): void
    {
        self::assertSame(3, Progress::l1FeaturePotential(self::j('{"target":[0,0]}'), self::j('{"x":[1,2]}')));
        self::assertSame('TypeError: l1-feature-v1: bad shape', self::thrown(fn() => Progress::l1FeaturePotential(self::j('{"target":"x"}'), self::j('{"x":[1]}'))));
        self::assertSame('TypeError: l1-feature-v1: bad shape', self::thrown(fn() => Progress::l1FeaturePotential(self::j('{"target":[1]}'), self::j('{"x":"x"}'))));
        self::assertSame('TypeError: x: safe integer required', self::thrown(fn() => Progress::l1FeaturePotential(self::j('{"target":[0]}'), self::j('{"x":[1.5]}'))));
    }

    public function testDagRemaining(): void
    {
        $o = self::j('{"tasks":[{"id":"a","cost":2},{"id":"b","cost":3}]}');
        self::assertSame(3, Progress::dagRemainingPotential($o, self::j('{"done":["a"]}')));
        self::assertSame('TypeError: dag-remaining-v1: bad shape', self::thrown(fn() => Progress::dagRemainingPotential(self::j('{"tasks":"x"}'), self::j('{"done":[]}'))));
        self::assertSame('TypeError: dag-remaining-v1: unknown task zz', self::thrown(fn() => Progress::dagRemainingPotential($o, self::j('{"done":["zz"]}'))));
    }

    public function testDagWeighted(): void
    {
        $w = static fn(string $tasks, string $done = '[]'): string => self::thrown(fn() => Progress::dagWeightedPotential(self::j('{"tasks":' . $tasks . '}'), self::j('{"done":' . $done . '}')));
        self::assertSame(2, Progress::dagWeightedPotential(self::j('{"tasks":[{"id":"a","cost":1},{"id":"b","cost":2,"deps":["a"]}]}'), self::j('{"done":["a"]}')));
        self::assertSame('TypeError: dag-weighted-v1: bad shape', $w('"x"'));
        self::assertSame('TypeError: dag-weighted-v1: bad task',
            self::thrown(fn() => Progress::dagWeightedPotential(Obj::of(['tasks' => [Obj::of(['id' => 5, 'cost' => 1])]]), self::j('{"done":[]}'))));
        self::assertSame('TypeError: cost: safe integer required', $w('[{"id":"a","cost":1.5}]'));
        self::assertSame('TypeError: dag-weighted-v1: bad deps', $w('[{"id":"a","cost":1,"deps":"x"}]'));
        self::assertSame('TypeError: dag-weighted-v1: bad deps', $w('[{"id":"a","cost":1,"deps":[5]}]'));
        self::assertSame('TypeError: dag-weighted-v1: bad dependency a', $w('[{"id":"a","cost":1,"deps":["a"]}]'));
        self::assertSame('TypeError: dag-weighted-v1: bad dependency zz', $w('[{"id":"a","cost":1,"deps":["zz"]}]'));
        self::assertSame('TypeError: dag-weighted-v1: unknown task zz', $w('[{"id":"a","cost":1}]', '["zz"]'));
    }

    /** The Set identity: strings, numbers (both zeros one), NaN, booleans, null, undefined, and objects by identity. */
    public function testSetKey(): void
    {
        self::assertSame('sa', self::call('setKey', 'a'));
        self::assertSame('n5', self::call('setKey', new Num('5')));
        self::assertSame('n1', self::call('setKey', 1));
        self::assertSame('n1.5', self::call('setKey', 1.5));
        self::assertSame('n0', self::call('setKey', new Num('-0')));
        self::assertSame('nNaN', self::call('setKey', NAN));
        self::assertSame('b1', self::call('setKey', true));
        self::assertSame('b0', self::call('setKey', false));
        self::assertSame('null', self::call('setKey', null));
        self::assertSame('undef', self::call('setKey', new Undef()));
        $o = new Obj();
        self::assertSame('o' . spl_object_id($o), self::call('setKey', $o));
    }

    // ---- goals, potentials in use, charge -----------------------------------------------------------------------------------

    public function testGoalMustBeObject(): void
    {
        self::assertSame('TypeError: goal must be an object', self::thrown(fn() => Progress::goalDigest(5)));
    }

    public function testUnknownPotentialMessage(): void
    {
        $g = self::goal();
        $g->set('potential', 'zz');
        try {
            Progress::potentialIn($g, Progress::defaultPotentials(), self::j('{"x":[1]}'));
            self::fail('accepted');
        } catch (ProgressError $e) {
            self::assertSame('unknown-potential', $e->denial);
            self::assertSame('unknown potential zz', $e->getMessage());
        }
    }

    /** An absent embedder is the empty one. */
    public function testAbsentEmbedder(): void
    {
        self::assertSame(1, Progress::potentialIn(self::goal()->without('embedder'), Progress::defaultPotentials(), self::j('{"x":[1]}')));
    }

    /** A charge past the safe range is a bad potential. */
    public function testChargeMustBeSafe(): void
    {
        $max = new Num('9007199254740991');
        try {
            Progress::classifyIn(0, 9007199254740991, $max);
            self::fail('accepted');
        } catch (ProgressError $e) {
            self::assertSame('bad-potential', $e->denial);
            self::assertSame('charge: safe integer required', $e->getMessage());
        }
    }

    /** A registry that cannot be built is a bad potential for an empty trajectory's initial state. */
    public function testEmptyTrajectoryBadRegistry(): void
    {
        $g = self::goal();
        $c = Progress::commitGoal($g)['commitment'];
        $r = Progress::verifyTrajectory($g, $c, [], Obj::of(['initial' => self::j('{"x":[1]}'), 'registry' => [[5, 5]]]));
        self::assertSame(['ok' => false, 'reason' => 'bad-potential', 'at' => -1], $r);
    }

    public function testAnchorSaltIs16Bytes(): void
    {
        $r = Progress::anchorTrajectoryHead(new TransparencyLedger('p'), []);
        self::assertSame(16, strlen((string)Pca::unb64u($r['salt'])));
        self::assertSame(22, strlen($r['salt']));
    }

    // ---- attested sources and attestations ----------------------------------------------------------------------------------

    public function testAttestedSourceRefusals(): void
    {
        self::assertSame('RuntimeException: AttestedStateSource: observeState must be a function', self::thrown(fn() => new AttestedStateSource('s', self::kp(), 5)));
        self::assertSame("RuntimeException: AttestedStateSource: unknown signature alg 'zz'", self::thrown(fn() => new AttestedStateSource('s', self::kp(), static fn() => 1, 'zz')));
    }

    /** An Ed25519 attestation of statement $f (source s, A, B to C), signed over the message the verifier rebuilds. */
    private static function att(array $f = [], array $extra = []): Obj
    {
        $a = Obj::of(array_merge(['source' => 's', 'goal_commitment' => 'g', 'action_digest' => 'A', 'prior_digest' => 'B', 'state_digest' => 'C'], $f));
        $a->set('sig', Pca::b64u(self::kp()->sign(Progress::attestationMessage($a, null, null))));
        foreach ($extra as $k => $v) {
            $a->set($k, $v);
        }
        return $a;
    }

    public function testVerifyStateAttestation(): void
    {
        $pub = self::kp()->public;
        self::assertTrue(Progress::verifyStateAttestation(self::att(), $pub), 'control');
        self::assertFalse(Progress::verifyStateAttestation(self::att(['source' => 5]), $pub));
        self::assertFalse(Progress::verifyStateAttestation(self::att([], ['alg' => null]), $pub));
        self::assertFalse(Progress::verifyStateAttestation(self::att([], ['alg' => 'zz']), $pub));
    }

    /** A pure post-quantum attestation verifies under its pinned key, never under an empty source key even if a pin names it. */
    public function testPqAttestationNeedsSourceKey(): void
    {
        $pq = new PqKeyPair('ML-DSA-65');
        $a = Obj::of(['source' => 's', 'goal_commitment' => 'g', 'action_digest' => 'A', 'prior_digest' => 'B', 'state_digest' => 'C', 'alg' => 'ml-dsa-65', 'pq_pk' => $pq->public]);
        $a->set('sig', Pq::signSuiteArtifact('ml-dsa-65', null, $pq, Progress::attestationMessage($a, 'ml-dsa-65', $pq->public))['sig']);
        self::assertTrue(Progress::verifyStateAttestation($a, 'id1', Obj::of(['pqPins' => Obj::of(['id1' => $pq->public])])), 'control');
        self::assertFalse(Progress::verifyStateAttestation($a, '', Obj::of(['pqPins' => Obj::of(['' => $pq->public])])));
    }

    private static function hookStep(Obj $att, mixed $a, mixed $b, mixed $c, string $source = 's'): Obj
    {
        return Obj::of(['state_source' => $source, 'action_digest' => $a, 'before_digest' => $b, 'after_digest' => $c,
            'evidence_digest' => Pca::hashCanonical(Obj::of(['t' => 'pca-evidence', 'e' => $att]))]);
    }

    public function testAttestedStateVerifier(): void
    {
        $pub = self::kp()->public;
        $v = static fn(Obj $att): \Closure => Progress::attestedStateVerifier(Obj::of(['trustedKeys' => Obj::of(['s' => $pub]), 'attestations' => [$att]]));
        $ok = self::att();
        self::assertTrue($v($ok)(self::hookStep($ok, 'A', 'B', 'C')), 'control');
        // only string digests select an attestation (an empty digest is not a missing one)
        $noPrior = self::att(['prior_digest' => '']);
        self::assertFalse($v($noPrior)(self::hookStep($noPrior, 'A', null, 'C')));
        $noAction = self::att(['action_digest' => '']);
        self::assertFalse($v($noAction)(self::hookStep($noAction, null, 'B', 'C')));
        // the attestation must come from the step's own source
        $other = self::att(['source' => 'x']);
        self::assertFalse($v($other)(self::hookStep($other, 'A', 'B', 'C')));
        // no attestations at all is an empty set, not an error
        self::assertFalse(Progress::attestedStateVerifier(Obj::of(['trustedKeys' => new Obj()]))(5));
    }

    // ---- step verification --------------------------------------------------------------------------------------------------

    public function testIsStepAndSameNum(): void
    {
        [, , $step] = self::stepped();
        self::assertTrue(self::call('isStep', $step), 'control');
        self::assertFalse(self::call('isStep', 5));
        $s = Json::parseStrict(Js::stringify($step));
        $s->set('goal_commitment', 5);
        self::assertFalse(self::call('isStep', $s));
        $s = Json::parseStrict(Js::stringify($step));
        $s->set('seq', 1.5);
        self::assertFalse(self::call('isStep', $s));
        self::assertFalse(self::call('sameNum', 'x', 0));
    }

    /** No options at all: attested state is required, so an unattested step is from an untrusted source. */
    public function testVerifyStepWithoutOptions(): void
    {
        [$g, $c, $step] = self::stepped();
        self::assertSame(['ok' => false, 'reason' => 'untrusted-state-source'], Progress::verifyProgressStep($g, $c, $step));
    }

    /** The guard sees exactly {seq, before, after, action_digest}. */
    public function testGuardTransition(): void
    {
        [$g, $c, $step] = self::stepped();
        $want = Js::stringify(Obj::of(['seq' => $step->get('seq'), 'before' => $step->get('before'), 'after' => $step->get('after'), 'action_digest' => $step->get('action_digest')]));
        $guard = static fn(Obj $t): bool => Js::stringify($t) === $want;
        $r = Progress::verifyProgressStep($g, $c, $step, Obj::of(['requireAttestedState' => false, 'guard' => $guard]));
        self::assertTrue($r['ok']);
        $t = new ProgressTracker($g, $c, self::j('{"x":[2]}'), null, $guard);
        self::assertTrue($t->step(self::j('{"x":[1]}'), 'A')['ok']);
    }

    /** A state that cannot be snapshotted is a bad potential for the tracker. */
    public function testTrackerUnsnapshottableState(): void
    {
        [$g, $c] = self::stepped();
        $t = new ProgressTracker($g, $c, self::j('{"x":[2]}'));
        self::assertSame(['ok' => false, 'reason' => 'bad-potential', 'stepUp' => false], $t->step(INF, 'A'));
    }

    public function testTrajectoryShapes(): void
    {
        [$g, $c] = self::stepped();
        self::assertSame(['ok' => false, 'reason' => 'malformed', 'at' => -1], Progress::verifyTrajectory($g, $c, 'x'));
        self::assertSame(['ok' => false, 'reason' => 'malformed', 'at' => 0], Progress::verifySignedTrajectory($g, $c, [5], Obj::of(['expectedActionDigests' => ['A']])));
        self::assertSame('TypeError: expectedActionDigests is required', self::thrown(fn() => Progress::verifySignedTrajectory($g, $c, [], null)));
        self::assertSame('TypeError: expectedActionDigests is required', self::thrown(fn() => Progress::verifySignedTrajectory($g, $c, [], Obj::of(['expectedActionDigests' => 'x']))));
    }
}
