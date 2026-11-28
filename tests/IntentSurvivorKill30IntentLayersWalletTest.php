<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\HarmModel;
use Atlas\Pca\IntentLayersWallet;
use Atlas\Pca\IntentLearner;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\Js;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentLayersWallet.php: the lattice view, the layered decision, owner risk and quorum approvals. */
final class IntentSurvivorKill30IntentLayersWalletTest extends TestCase
{
    private const S = 'action.params.s';

    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function cat(array $exacts): Obj
    {
        $values = array_map(static fn($v) => Obj::of(['kind' => 'exact', 'value' => $v]), $exacts);
        $values[] = Obj::of(['kind' => 'other', 'value' => IntentOmega::OTHER]);
        return Obj::of(['kind' => 'cat', 'path' => self::S, 'values' => $values]);
    }

    private static function vs(array $dims = [], mixed $weight = 1): Obj
    {
        return Obj::of(['verb' => 'x.do', 'reversibility' => 'reversible', 'weight' => $weight, 'dims' => $dims]);
    }

    private static function omega(Obj ...$verbs): Obj
    {
        return Obj::of(['v' => 1, 'approximate' => [], 'verbs' => $verbs]);
    }

    /** Three cells (a, b, other): a confirmed (p = 1, in grant), b refused (p = 0, not vetoed), other uncertain (0 < p < 1). */
    private static function learnerA(): array
    {
        $vs = self::vs([self::cat(['a', 'b'])]);
        $l = new IntentLearner(self::omega($vs));
        $l->observe(IntentOmega::cellRep($vs, [0]), 1);
        $l->observe(IntentOmega::cellRep($vs, [1]), 0);
        return [$l, $vs];
    }

    /** One cell whose acceptance is exactly 1e-12 (null mass 1, then a population prior of weight 1e-12 on the cell). */
    private static function learnerTiny(): array
    {
        $vs = self::vs();
        $l = new IntentLearner(self::omega($vs), ['nullMass' => 1, 'priorMix' => ['beta' => 0.5,
            'weight' => static fn($v, \Closure $contains) => $contains(0) ? 2e-12 : 1.0 - 2e-12]]);
        return [$l, $vs];
    }

    private static function admitter(\Closure $f): object
    {
        return new class ($f) {
            public function __construct(private \Closure $f)
            {
            }

            public function admits(mixed $vs, mixed $o): bool
            {
                return ($this->f)($o);
            }
        };
    }

    private static function notA(): object
    {
        return self::admitter(static fn($o) => Js::opt(Js::opt($o, 'values'), self::S) !== 'a');
    }

    /** A present-as-null ceiling set is refused with the reference's TypeError text. */
    public function testNullLayersRefused(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('Cannot convert undefined or null to object');
        IntentLayersWallet::ceilingAdmitters(null);
    }

    /** The lattice: the confirmed cell is effective, the refused one is nowhere, the open one is uncertain. */
    public function testLatticeViewSplitsCells(): void
    {
        [$l] = self::learnerA();
        $this->assertSame([
            'effective' => [['verb' => 'x.do', 'cell' => [0]]],
            'uncertain' => [['verb' => 'x.do', 'cell' => [2]]],
            'ceiling' => [],
        ], IntentLayersWallet::latticeView($l, []));
    }

    /** A cell outside a ceiling is reported with its layer, and the cells after it are still classified. */
    public function testLatticeViewCeilingThenContinues(): void
    {
        [$l] = self::learnerA();
        $this->assertSame([
            'effective' => [],
            'uncertain' => [['verb' => 'x.do', 'cell' => [2]]],
            'ceiling' => [['verb' => 'x.do', 'cell' => [0], 'layer' => 'org']],
        ], IntentLayersWallet::latticeView($l, ['org' => self::notA()]));
    }

    /** A vetoed cell is skipped and the cells after it are still classified. */
    public function testLatticeViewVetoThenContinues(): void
    {
        $vs = self::vs([self::cat(['a', 'b'])]);
        $l = new IntentLearner(self::omega($vs));
        $l->observe(IntentOmega::cellRep($vs, [0]), 0, 'runtime');
        $this->assertTrue($l->isVetoed(IntentOmega::cellRep($vs, [0])), 'control');
        $this->assertSame([
            'effective' => [],
            'uncertain' => [['verb' => 'x.do', 'cell' => [1]], ['verb' => 'x.do', 'cell' => [2]]],
            'ceiling' => [],
        ], IntentLayersWallet::latticeView($l, []));
    }

    /** A cell whose acceptance is exactly 1e-12 is not uncertain (the bound is strict). */
    public function testLatticeViewTinyAcceptanceIsNotUncertain(): void
    {
        [$l, $vs] = self::learnerTiny();
        $this->assertSame(1e-12, $l->acceptance(IntentOmega::cellRep($vs, [])), 'control');
        $this->assertSame(['effective' => [], 'uncertain' => [], 'ceiling' => []], IntentLayersWallet::latticeView($l, []));
    }

    /** Every branch of the layered decision returns its exact shape. */
    public function testDecideOutcomeLayers(): void
    {
        [$l, $vs] = self::learnerA();
        $this->assertSame(['decision' => 'intent_denied'], IntentLayersWallet::decideOutcomeLayers($l, [], Obj::of(['verb' => 'nope', 'values' => new Obj()])));
        $this->assertSame(['decision' => 'ceiling', 'layer' => 'org'], IntentLayersWallet::decideOutcomeLayers($l, ['org' => self::notA()], IntentOmega::cellRep($vs, [0])));
        $this->assertSame(['decision' => 'intent_required'], IntentLayersWallet::decideOutcomeLayers($l, ['org' => self::notA()], IntentOmega::cellRep($vs, [2])), 'control: an open cell inside the ceiling');
        $this->assertSame(['decision' => 'admit', 'by' => 0], IntentLayersWallet::decideOutcomeLayers($l, [], IntentOmega::cellRep($vs, [0])));
        $this->assertSame(['decision' => 'intent_denied'], IntentLayersWallet::decideOutcomeLayers($l, [], IntentOmega::cellRep($vs, [1])));
        $this->assertSame(['decision' => 'intent_required'], IntentLayersWallet::decideOutcomeLayers($l, [], IntentOmega::cellRep($vs, [2])));
    }

    /** An acceptance of exactly 1e-12 is denied (the bound is inclusive). */
    public function testDecideTinyAcceptanceDenied(): void
    {
        [$l, $vs] = self::learnerTiny();
        $this->assertSame(['decision' => 'intent_denied'], IntentLayersWallet::decideOutcomeLayers($l, [], IntentOmega::cellRep($vs, [])));
    }

    /** A vetoed cell is denied even while its acceptance is still positive (noisy learner). */
    public function testDecideVetoedDenied(): void
    {
        $vs = self::vs([self::cat(['a', 'b'])]);
        $l = new IntentLearner(self::omega($vs), ['eta' => 0.1]);
        $o = IntentOmega::cellRep($vs, [1]);
        $l->observe($o, 0, 'runtime');
        $this->assertGreaterThan(1e-12, $l->acceptance($o), 'control');
        $this->assertSame(['decision' => 'intent_denied'], IntentLayersWallet::decideOutcomeLayers($l, [], $o));
    }

    /** The refusal text names the cell as verb|i,j. */
    public function testAssertAskableMessage(): void
    {
        IntentLayersWallet::assertAskable(['uncertain' => [['verb' => 'a', 'cell' => [1, 2]]]], ['verb' => 'a', 'cell' => [1, 2]]);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('layers: cell a|1,2 is not an uncertain cell inside every ceiling (never a question)');
        IntentLayersWallet::assertAskable(['uncertain' => [['verb' => 'a1', 'cell' => [2]]]], ['verb' => 'a', 'cell' => [1, 2]]);
    }

    private static function harm7(mixed $verbHarm = 7.0): HarmModel
    {
        return new HarmModel(static fn($vs) => $verbHarm, static fn($d, $x) => 1.0);
    }

    /** Owner risk uses the given harm model and skips (not stops at) a cell of an unknown verb. */
    public function testOwnerRiskUsesHarmAndSkipsUnknownVerbs(): void
    {
        $omega = self::omega(self::vs());
        $cells = [['verb' => 'nope', 'cell' => []], ['verb' => 'x.do', 'cell' => []]];
        $this->assertSame(3.5, IntentLayersWallet::ownerRisk($omega, $cells, static fn($vs, $o) => 0.5, self::harm7()));
        $this->assertSame(0.5, IntentLayersWallet::ownerRisk($omega, $cells, static fn($vs, $o) => 0.5), 'control: default harm 1');
        $this->assertSame(5.25, IntentLayersWallet::ownerRisk($omega, $cells, static fn($vs, $o) => new Num('0.25'), self::harm7()));
    }

    /** A non-number acceptability, weight or harm is NaN (the reference's number coercion), never 0 and never an error. */
    public function testOwnerRiskNonNumbersAreNaN(): void
    {
        $omega = self::omega(self::vs());
        $cells = [['verb' => 'x.do', 'cell' => []]];
        $this->assertNan(IntentLayersWallet::ownerRisk($omega, $cells, static fn($vs, $o) => 'abc'));
        $this->assertNan(IntentLayersWallet::ownerRisk(self::omega(self::vs([], 'abc')), $cells, static fn($vs, $o) => 0.5));
        $this->assertNan(IntentLayersWallet::ownerRisk($omega, $cells, static fn($vs, $o) => 0.5, self::harm7('abc')));
    }

    /** A cell key encodes the cell against the FIRST verb space of that name; an unknown verb joins the indices. */
    public function testCellKeyOfFirstVerbSpace(): void
    {
        $a = Obj::of(['verb' => 'k.v', 'reversibility' => 'reversible', 'weight' => 1, 'dims' => [self::cat(['a']), self::cat(['a'])]]);
        $b = Obj::of(['verb' => 'k.v', 'reversibility' => 'reversible', 'weight' => 1, 'dims' => [self::cat(['a', 'b']), self::cat(['a', 'b'])]]);
        $omega = self::omega($a, $b);
        $this->assertSame('k.v|3', IntentLayersWallet::cellKeyOf($omega, ['verb' => 'k.v', 'cell' => [1, 1]]));
        $this->assertSame('nope|1,1', IntentLayersWallet::cellKeyOf($omega, ['verb' => 'nope', 'cell' => [1, 1]]));
    }

    /** An org layer from maps carries both the aggregate map and its grant as the policy. */
    public function testOrgLayerFromMaps(): void
    {
        $map = IntentMapKit::emitIntentMap(IntentMapKit::createLearner(self::omega(self::vs([self::cat(['a'])]))), 'p1');
        $r = IntentLayersWallet::orgLayerFromMaps([$map], ['kind' => 'unanimity']);
        $this->assertSame(['map', 'policy'], array_keys($r));
        $this->assertInstanceOf(Obj::class, $r['map']);
        $this->assertSame($r['map']->get('grant'), $r['policy']);
    }

    private static function member(string $label): array
    {
        $seed = hash('sha256', 'atlas-pca-conformance/' . $label, true);
        return [$seed, Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)))];
    }

    private static function statement(array $extra = []): array
    {
        return ['layer' => 'org', 'session' => 's1', 'seq' => 1, 'map_digest' => 'd1', 'prev' => null] + $extra;
    }

    /** A statement with an undefined member cannot be signed: the strict canonical form refuses it by name. */
    public function testSignRefusesUndefinedMember(): void
    {
        [$seed] = self::member('g30-layer-a');
        $s = self::statement();
        unset($s['prev']);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('canonicalBytesStrict: undefined member prev');
        IntentLayersWallet::signLayerApproval($s, $seed);
    }

    /** Both sides missing a member match field by field, but the message cannot be built: a bad signature, never counted. */
    public function testBothUndefinedIsABadSignature(): void
    {
        [, $pk] = self::member('g30-layer-a');
        $s = self::statement();
        unset($s['prev']);
        $a = Obj::of(['v' => 1, 'kind' => 'pca-intent-layer-approval', 'layer' => 'org', 'session' => 's1', 'seq' => 1, 'map_digest' => 'd1', 'signer' => $pk, 'sig' => 'AAAA']);
        $r = IntentLayersWallet::verifyQuorumApprovals([$a], [$pk], ['kind' => 'unanimity'], $s);
        $this->assertSame(['ok' => false, 'signers' => [], 'ignored' => [['index' => 0, 'reason' => 'bad signature']]], $r);
    }

    /** An approval missing a member the expected statement has (as null) is for another statement. */
    public function testMissingVersusNullIsAnotherStatement(): void
    {
        [, $pk] = self::member('g30-layer-a');
        $a = Obj::of(['v' => 1, 'kind' => 'pca-intent-layer-approval', 'layer' => 'org', 'session' => 's1', 'seq' => 1, 'map_digest' => 'd1', 'signer' => $pk, 'sig' => 'AAAA']);
        $r = IntentLayersWallet::verifyQuorumApprovals([$a], [$pk], ['kind' => 'unanimity'], self::statement());
        $this->assertSame(['ok' => false, 'signers' => [], 'ignored' => [['index' => 0, 'reason' => 'approval is for another (layer, session, seq, map_digest, prev)']]], $r);
    }

    /** A signed approval counts; an object-valued member matches when it is the same object. */
    public function testSignedApprovalCounts(): void
    {
        [$seed, $pk] = self::member('g30-layer-a');
        $s = self::statement();
        $s['layer'] = Obj::of(['name' => 'org']);
        $a = IntentLayersWallet::signLayerApproval($s, $seed);
        $r = IntentLayersWallet::verifyQuorumApprovals([$a], [$pk], ['kind' => 'unanimity'], $s);
        $this->assertSame(['ok' => true, 'signers' => [$pk], 'ignored' => []], $r);
        $plain = IntentLayersWallet::signLayerApproval(self::statement(), $seed);
        $this->assertSame(['ok' => true, 'signers' => [$pk], 'ignored' => []], IntentLayersWallet::verifyQuorumApprovals([$plain], [$pk], ['kind' => 'unanimity'], self::statement()), 'control');
    }
}
