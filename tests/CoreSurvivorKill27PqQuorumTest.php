<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PqQuorum.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\PqQuorum;
use PHPUnit\Framework\TestCase;

/** An object that answers get/has like an Obj without being one. */
final class K27PqDuck
{
    public function __construct(private readonly Obj $o)
    {
    }

    public function get(string $k): mixed
    {
        return $this->o->get($k);
    }

    public function has(string $k): bool
    {
        return $this->o->has($k);
    }
}

/** PQ quorum refusal paths: set building and loading, share signing, proof assembly, verification shapes, rotation and size accounting. */
final class CoreSurvivorKill27PqQuorumTest extends TestCase
{
    private const BAD = ['ok' => false, 'reason' => 'bad-set'];
    private const SLH = 'slh-dsa-sha2-128f';

    private static function throws(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [get_class($e), $e->getMessage()];
        }
        return ['none', ''];
    }

    private static function k(int $b): string
    {
        return Pca::b64u(str_repeat(chr($b), 32));
    }

    private static function slh(int $b): Obj
    {
        return Obj::of(['alg' => self::SLH, 'keys' => Obj::of(['slhDsaPub' => self::k($b)])]);
    }

    /** A 1-of-1 hash-based set (SLH-DSA keys are 32 bytes, so no key generation is needed to build one). */
    private static function set(): Obj
    {
        return PqQuorum::buildQuorumSet([self::slh(1)], 1)['set'];
    }

    private static function wire(Obj $s, array $over): Obj
    {
        $o = ['t' => $s->get('t'), 'minHashBased' => $s->get('minHashBased'), 'signers' => $s->get('signers'), 'id' => $s->get('id')];
        foreach ($over as $k => $v) {
            $o[$k] = $v;
        }
        return Obj::of($o);
    }

    private static function verify(array $in): array
    {
        return PqQuorum::verifyQuorum(Obj::of($in + ['epoch' => new Num('0'), 'actionDigest' => 'a']));
    }

    /** Hybrid signers are ordered by their Ed25519 key before their PQ key. */
    public function testOrderUsesTheEdKey(): void
    {
        $alg = 'hybrid-ed25519-slh-dsa-sha2-128f';
        $a = Obj::of(['alg' => $alg, 'keys' => Obj::of(['edPub' => self::k(0x00), 'slhDsaPub' => self::k(0xfe)])]);
        $b = Obj::of(['alg' => $alg, 'keys' => Obj::of(['edPub' => self::k(0xff), 'slhDsaPub' => self::k(0x01)])]);
        $r = PqQuorum::buildQuorumSet([$b, $a], 2);
        $this->assertTrue($r['ok']);
        $this->assertSame([self::k(0x00), self::k(0xff)], array_map(static fn(Obj $e): mixed => $e->get('ed'), $r['set']->get('signers')));
    }

    /** Building refuses a non-list signer collection and keys that are not an Obj. */
    public function testBuildRefusals(): void
    {
        $this->assertSame(self::BAD, PqQuorum::buildQuorumSet(['a' => self::slh(1)], 1));
        $this->assertSame(self::BAD, PqQuorum::buildQuorumSet([Obj::of(['alg' => self::SLH, 'keys' => new K27PqDuck(Obj::of(['slhDsaPub' => self::k(1)]))])], 1));
    }

    /** Loading refuses a non-Obj set, non-list signers and non-Obj entries, even when their contents are those of a valid set. */
    public function testLoadRefusals(): void
    {
        $s = self::set();
        $this->assertTrue(PqQuorum::loadQuorumSet($s)['ok']);
        $this->assertSame(self::BAD, PqQuorum::loadQuorumSet(new K27PqDuck($s)));
        $this->assertSame(self::BAD, PqQuorum::loadQuorumSet(self::wire($s, ['signers' => ['a' => $s->get('signers')[0]]])));
        $this->assertSame(self::BAD, PqQuorum::loadQuorumSet(self::wire($s, ['signers' => [new K27PqDuck($s->get('signers')[0])]])));
    }

    /** signQuorumShare refuses a non-Obj or unknown slot and a set without an id before any key is used. */
    public function testSignShareRefusals(): void
    {
        $s = self::set();
        $slot = [\RangeException::class, 'signQuorumShare: no such signer index'];
        $this->assertSame($slot, self::throws(static fn() => PqQuorum::signQuorumShare(Obj::of(['signers' => [new K27PqDuck(Obj::of(['alg' => 'ml-dsa-65']))], 'id' => 'x']), new Num('0'), new Num('0'), 'a')));
        $this->assertSame($slot, self::throws(static fn() => PqQuorum::signQuorumShare($s, new Num('5'), new Num('0'), 'a')));
        $this->assertSame([\InvalidArgumentException::class, 'signQuorumShare: the set has no id'],
            self::throws(static fn() => PqQuorum::signQuorumShare(Obj::of(['signers' => $s->get('signers')]), new Num('0'), new Num('0'), 'a')));
    }

    /** Of several PQ key pairs the first of the slot's family signs; a diversity demand at the largest safe integer is a valid demand. */
    public function testRealSharePaths(): void
    {
        $k65 = new PqKeyPair('ML-DSA-65', hash('sha256', 'atlas-pca-conformance/k27-pq-quorum/65', true));
        $k87 = new PqKeyPair('ML-DSA-87', hash('sha256', 'atlas-pca-conformance/k27-pq-quorum/87', true));
        $set = PqQuorum::buildQuorumSet([Obj::of(['alg' => 'ml-dsa-65', 'keys' => Obj::of(['mlDsaPub' => $k65->public])])], 1)['set'];
        $share = PqQuorum::signQuorumShare($set, new Num('0'), new Num('0'), 'a', null, $k65, $k87);
        $proof = PqQuorum::assembleQuorumProof($set, [$share]);
        $this->assertTrue(self::verify(['set' => $set, 'proof' => $proof])['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'diversity-unmet'], self::verify(['set' => $set, 'proof' => $proof, 'requireHashBased' => new Num('9007199254740991')]));
    }

    /** The largest safe integer is a valid epoch; non-Obj inputs, proofs and shares are malformed; a non-list sigs collection is malformed. */
    public function testVerifyShapes(): void
    {
        $s = self::set();
        $id = $s->get('id');
        $this->assertSame(['ok' => false, 'reason' => 'below-threshold'],
            self::verify(['set' => $s, 'proof' => Obj::of(['set_id' => $id, 'sigs' => []]), 'epoch' => new Num('9007199254740991')]));
        $m = ['ok' => false, 'reason' => 'malformed'];
        $this->assertSame($m, PqQuorum::verifyQuorum(new K27PqDuck(new Obj())));
        $this->assertSame($m, self::verify(['set' => $s, 'proof' => new K27PqDuck(Obj::of(['set_id' => $id, 'sigs' => []]))]));
        $share = Obj::of(['sig' => 's', 'i' => new Num('99')]);
        $this->assertSame($m, self::verify(['set' => $s, 'proof' => Obj::of(['set_id' => $id, 'sigs' => ['a' => $share]])]));
        $this->assertSame($m, self::verify(['set' => $s, 'proof' => Obj::of(['set_id' => $id, 'sigs' => [new K27PqDuck($share)]])]));
        $this->assertFalse(PqQuorum::verifyQuorumApproval($s, Obj::of(['set_id' => $id, 'sigs' => []]), 5, new Num('0')));
    }

    /** A proof names the set id only when there is one; a string of shares spreads into characters; a non-list is refused. */
    public function testAssembleProof(): void
    {
        $s = self::set();
        $this->assertSame(['sigs'], PqQuorum::assembleQuorumProof('x', [])->keys());
        $this->assertSame(['sigs'], PqQuorum::assembleQuorumProof(new Obj(), [])->keys());
        $this->assertSame(['a', 'é'], PqQuorum::assembleQuorumProof($s, 'aé')->get('sigs'));
        $refused = [\InvalidArgumentException::class, 'assembleQuorumProof: shares is not a list'];
        $this->assertSame($refused, self::throws(static fn() => PqQuorum::assembleQuorumProof($s, ['a' => 1])));
        $this->assertSame($refused, self::throws(static fn() => PqQuorum::assembleQuorumProof($s, 5)));
    }

    /** The next epoch is "x + 1" as the reference evaluates it; a rotation needs a new set id; a non-list chain is malformed at -1. */
    public function testRotation(): void
    {
        $s = self::set();
        $this->assertSame('[object Object]1', PqQuorum::buildRotationCert($s, new Obj(), $s, [])->get('to_epoch'));
        $this->assertSame('51', PqQuorum::buildRotationCert($s, '5', $s, [])->get('to_epoch'));
        $this->assertSame([\InvalidArgumentException::class, 'signRotationShare: the new set has no id'],
            self::throws(static fn() => PqQuorum::signRotationShare($s, 0, new Num('0'), new Obj())));
        $this->assertSame(['ok' => false, 'reason' => 'malformed', 'at' => -1], PqQuorum::verifyRotationChain($s, new Num('0'), [1 => 'x']));
    }

    /** A fork needs both from-members equal by JS ===: absent equals only absent, numbers by value, lists never; a non-Obj next set is no fork. */
    public function testRotationFork(): void
    {
        $x = Obj::of(['id' => 'x']);
        $y = Obj::of(['id' => 'y']);
        $one = new Num('1');
        $fork = static fn(array $a, array $b): bool => PqQuorum::isRotationFork(Obj::of($a + ['to_set' => $x]), Obj::of($b + ['to_set' => $y]));
        $this->assertFalse($fork(['from_set_id' => null, 'from_epoch' => $one], ['from_epoch' => $one]));
        $this->assertTrue($fork(['from_epoch' => $one], ['from_epoch' => $one]));
        $this->assertFalse($fork(['from_set_id' => 's', 'from_epoch' => 'x'], ['from_set_id' => 's', 'from_epoch' => $one]));
        $this->assertFalse($fork(['from_set_id' => ['p'], 'from_epoch' => $one], ['from_set_id' => ['p'], 'from_epoch' => $one]));
        $this->assertTrue($fork(['from_set_id' => 's', 'from_epoch' => $one], ['from_set_id' => 's', 'from_epoch' => $one]));
        $this->assertFalse(PqQuorum::isRotationFork(Obj::of(['from_set_id' => 's', 'to_set' => $x]), Obj::of(['from_set_id' => 's', 'to_set' => 'x'])));
    }

    /** Size accounting refuses non-Obj entries, a non-list signer or index collection and a missing threshold; a zero threshold is zero bytes. */
    public function testProofSize(): void
    {
        $e = Obj::of(['alg' => 'ml-dsa-65']);
        $notSet = [\InvalidArgumentException::class, 'quorumProofSize: not a quorum set'];
        $this->assertSame([\InvalidArgumentException::class, 'quorumProofSize: unknown suite'], self::throws(static fn() => PqQuorum::quorumProofSize(Obj::of(['signers' => ['x'], 't' => new Num('1')]))));
        $this->assertSame(0, PqQuorum::quorumProofSize(Obj::of(['signers' => [$e], 't' => new Num('0')]))['minBytes']);
        $this->assertSame($notSet, self::throws(static fn() => PqQuorum::quorumProofSize(Obj::of(['signers' => ['a' => $e], 't' => new Num('1')]))));
        $this->assertSame($notSet, self::throws(static fn() => PqQuorum::quorumProofSize(Obj::of(['signers' => 'x', 't' => new Num('1')]))));
        $this->assertSame($notSet, self::throws(static fn() => PqQuorum::quorumProofSize(Obj::of(['signers' => [$e]]))));
        $idx = [\InvalidArgumentException::class, 'quorumProofSize: indices is not a list'];
        $set = Obj::of(['signers' => [$e], 't' => new Num('1')]);
        $this->assertSame($idx, self::throws(static fn() => PqQuorum::quorumProofSize($set, ['a' => 0])));
        $this->assertSame($idx, self::throws(static fn() => PqQuorum::quorumProofSize($set, 'x')));
    }
}
