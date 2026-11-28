<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ed25519Core;
use Atlas\Pca\MpcEndemicOt;
use Atlas\Pca\MpcLweLattice;
use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCodec;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetOt;
use Atlas\Pca\MpcNetWire;
use Atlas\Pca\MpcOt;
use Atlas\Pca\MpcOtRandom;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use PHPUnit\Framework\TestCase;

/**
 * An in-memory stand-in for the TLS mesh: every payload goes through the real wire JSON (stringify + parse) to the paired mesh, where an
 * optional tamper hook may replace the parsed value. recv() yields the running Fiber while nothing is queued (or throws outside one).
 */
final class Kill17OtMesh extends MpcNetMesh
{
    /** @var list<array{0:string,1:mixed}> */
    public array $inbox = [];
    /** @var list<array{0:int,1:string,2:mixed}> */
    public array $sent = [];
    /** @var list<MpcNetAbort> */
    public array $fails = [];
    public int $finishes = 0;
    public ?Kill17OtMesh $peer = null;
    /** @var ?\Closure(string, mixed): mixed applied to what THIS mesh sends */
    public ?\Closure $tamper = null;

    public function __construct(int $self)
    {
        \Closure::bind(function () use ($self): void {
            $this->selfId = $self;
        }, $this, MpcNetMesh::class)();
    }

    public static function wire(mixed $v): mixed
    {
        return (new Parser(MpcNetWire::stringify($v), 512, true))->run();
    }

    public function sessionId(): string
    {
        return 'kill17-ot-session';
    }

    public function send(int $to, string $round, mixed $payload): void
    {
        $this->sent[] = [$to, $round, $payload];
        if ($this->peer !== null) {
            $v = self::wire($payload);
            if ($this->tamper !== null) {
                $v = ($this->tamper)($round, $v);
            }
            $this->peer->inbox[] = [$round, $v];
        }
    }

    public function recv(int $from, string $round, ?int $timeoutMs = null): mixed
    {
        while ($this->inbox === []) {
            if (\Fiber::getCurrent() === null) {
                throw new \RuntimeException("kill17: no '$round' message queued");
            }
            \Fiber::suspend();
        }
        [$rd, $v] = array_shift($this->inbox);
        if ($rd !== $round) {
            throw new \RuntimeException("kill17: expected '$round', got '$rd'");
        }
        return $v;
    }

    public function fail(MpcNetAbort $err, ?int $skipPeer = null): void
    {
        $this->fails[] = $err;
    }

    public function finish(): void
    {
        $this->finishes++;
    }

    public function close(): void
    {
    }
}

/**
 * Mutation kills for the networked base OT: the exact transcript of an honest ec run (pads, choices, digests, timing), every refusal of
 * a malformed ot-R / ot-verify / ot-S / ot-recv message with its stage and blame, the commitment abort on a forged Schnorr proof, the
 * receiver's revealed-bit reader and the ciphertext-pair parser. Two meshes in one process (Fibers); seeded entropy and a fixed clock.
 */
final class ProtoSurvivorKill17MpcNetOtTest extends TestCase
{
    private const SEED_S = 1701;
    private const SEED_R = 23; // SplitMix64: the receiver's first two bits are 0, 1

    protected function setUp(): void
    {
        MpcNetOt::$rngHook = static fn(string $role): MpcOtRandom => MpcOtRandom::fromSeed(gmp_init($role === 'sender' ? self::SEED_S : self::SEED_R));
        $calls = 0;
        MpcNetOt::$clockHook = static function () use (&$calls): float {
            return $calls++ < 2 ? 100.0 : 100.25;
        };
    }

    protected function tearDown(): void
    {
        MpcNetOt::$rngHook = null;
        MpcNetOt::$clockHook = null;
    }

    private function needEc(): void
    {
        if (!Ed25519Core::available()) {
            $this->markTestSkipped('needs ext-sodium with the Ed25519 core functions');
        }
    }

    /**
     * Sender (node 0) and receiver (node 1) as two Fibers. $fromSender / $fromReceiver tamper with what that side sends.
     * @return array{s:?array,r:?array,sm:Kill17OtMesh,rm:Kill17OtMesh}
     */
    private static function pair(string $kind, int $count, ?\Closure $fromSender = null, ?\Closure $fromReceiver = null): array
    {
        $s = new Kill17OtMesh(0);
        $r = new Kill17OtMesh(1);
        $s->peer = $r;
        $r->peer = $s;
        $s->tamper = $fromSender;
        $r->tamper = $fromReceiver;
        $out = ['s' => null, 'r' => null];
        $fs = new \Fiber(static function () use ($s, $kind, $count, &$out): void {
            try {
                $out['s'] = ['ok' => true, 'v' => MpcNetOt::runOtSender($s, 1, $kind, $count)];
            } catch (\Throwable $e) {
                $out['s'] = ['ok' => false, 'e' => $e];
            }
        });
        $fr = new \Fiber(static function () use ($r, $kind, $count, &$out): void {
            try {
                $out['r'] = ['ok' => true, 'v' => MpcNetOt::runOtReceiver($r, 0, $kind, $count)];
            } catch (\Throwable $e) {
                $out['r'] = ['ok' => false, 'e' => $e];
            }
        });
        $fs->start();
        $fr->start();
        for ($guard = 0; $guard < 64; $guard++) {
            $moved = false;
            foreach ([[$fs, $s], [$fr, $r]] as [$f, $m]) {
                if ($f->isSuspended() && $m->inbox !== []) {
                    $f->resume();
                    $moved = true;
                }
            }
            if (!$moved) {
                break;
            }
        }
        return ['s' => $out['s'], 'r' => $out['r'], 'sm' => $s, 'rm' => $r];
    }

    /** @return list<array{0:int,1:string}> (peer, round) of every message the mesh sent */
    private static function rounds(Kill17OtMesh $m): array
    {
        return array_map(static fn(array $x): array => [$x[0], $x[1]], $m->sent);
    }

    private function abortOf(?array $res): MpcNetAbort
    {
        $this->assertNotNull($res, 'the side never finished');
        $this->assertFalse($res['ok'], 'expected an abort');
        $this->assertInstanceOf(MpcNetAbort::class, $res['e']);
        return $res['e'];
    }

    /** The binding names the hashed session, both ends and the round, in that shape. */
    public function testNetBindingHashesTheSessionAndNamesBothEnds(): void
    {
        $m = new Kill17OtMesh(0);
        $this->assertSame(['sessionId' => hash('sha256', 'atlas-pca-mpc/net-session/v2kill17-ot-session', true), 'senderIndex' => 3,
            'receiverIndex' => 5, 'round' => 'r9'], MpcNetOt::netBinding($m, 3, 5, 'r9'));
    }

    /** An honest ec run: both sides finish matched, with exactly the pads, revealed bits, digests and timing of the OT itself. */
    public function testHonestEcRunHasTheExactTranscript(): void
    {
        $this->needEc();
        $run = self::pair('ec', 2);
        $this->assertTrue($run['s']['ok'] ?? false, isset($run['s']['e']) ? $run['s']['e']->getMessage() : 'sender unfinished');
        $this->assertTrue($run['r']['ok'] ?? false, isset($run['r']['e']) ? $run['r']['e']->getMessage() : 'receiver unfinished');

        $bind = MpcNetOt::netBinding($run['sm'], 0, 1, 'ot-ec');
        $setup = MpcOt::malBaseOtSenderSetup(MpcOtRandom::fromSeed(gmp_init(self::SEED_S)), $bind);
        $rr = MpcOtRandom::fromSeed(gmp_init(self::SEED_R));
        $choices = [ord($rr->bytes(1)) & 1, ord($rr->bytes(1)) & 1];
        $this->assertSame([0, 1], $choices);
        $res = MpcOt::malBaseOtReceiverRespond($setup['S'], $setup['proof'], $choices, $rr, $bind);
        $pads = MpcOt::malBaseOtSenderDerive($setup['y'], $setup['T'], $res['R'], $setup['S'], $bind);
        $flat = $pads[0][0] . $pads[0][1] . $pads[1][0] . $pads[1][1];

        $this->assertSame(['kind' => 'ec', 'role' => 'sender', 'count' => 2, 'ms' => 250.0, 'matched' => true, 'padDigest' => hash('sha256', $flat)], $run['s']['v']);
        $this->assertSame(['kind' => 'ec', 'role' => 'receiver', 'count' => 2, 'ms' => 250.0, 'matched' => true,
            'padDigest' => hash('sha256', implode('', $res['recvPads']))], $run['r']['v']);
        $this->assertSame([[1, 'ot-S'], [1, 'ot-done']], self::rounds($run['sm']));
        $this->assertSame([[0, 'ot-R'], [0, 'ot-verify']], self::rounds($run['rm']));
        $this->assertSame(['choices' => [0, 1], 'padHashes' => [hash('sha256', $res['recvPads'][0]), hash('sha256', $res['recvPads'][1])]], $run['rm']->sent[1][2]);
        $this->assertSame($pads[0][0], $res['recvPads'][0]);
        $this->assertSame($pads[1][1], $res['recvPads'][1]);
        $this->assertSame(['matched' => true], $run['sm']->sent[1][2]);
        $this->assertSame([], $run['sm']->fails);
        $this->assertSame([], $run['rm']->fails);
        $this->assertSame(1, $run['sm']->finishes);
        $this->assertSame(1, $run['rm']->finishes);
    }

    /** ot-R must be a list of exactly `count` points: a string, a short list and a keyed map are each a malformed abort blaming the receiver. */
    public function testOtRMustBeAListOfCountPoints(): void
    {
        $this->needEc();
        $tampers = [
            static fn(array $r): mixed => 'x',
            static fn(array $r): mixed => [$r[0]],
            static fn(array $r): mixed => ['a' => $r[0], 'b' => $r[1]],
        ];
        foreach ($tampers as $i => $t) {
            $run = self::pair('ec', 2, null, static fn(string $rd, mixed $v): mixed => $rd === 'ot-R' ? $t($v) : $v);
            $e = $this->abortOf($run['s']);
            $this->assertSame("[malformed] blamed=1 reporter=0: round 'ot-R': bad R array", $e->getMessage(), "case $i");
            $this->assertSame('malformed', $e->kind);
            $this->assertSame(1, $e->blamed);
            $this->assertCount(1, $run['sm']->fails);
            $this->assertSame($e, $run['sm']->fails[0]);
            $this->assertSame([[1, 'ot-S']], self::rounds($run['sm']));
        }
    }

    /** A revealed pad hash that does not match is a clean "not matched" on both sides, never a pass. */
    public function testAWrongPadHashIsNotMatched(): void
    {
        $this->needEc();
        $run = self::pair('ec', 2, null, static function (string $rd, mixed $v): mixed {
            if ($rd === 'ot-verify') {
                $h = $v->get('padHashes');
                $h[0] = str_repeat('0', 64);
                $v->set('padHashes', $h);
            }
            return $v;
        });
        $this->assertTrue($run['s']['ok'] ?? false);
        $this->assertFalse($run['s']['v']['matched']);
        $this->assertSame(['matched' => false], $run['sm']->sent[1][2]);
        $this->assertTrue($run['r']['ok'] ?? false);
        $this->assertFalse($run['r']['v']['matched']);
    }

    /** ot-verify must be an object with `count` choices and `count` hashes: each other shape is a malformed abort at that round. */
    public function testOtVerifyShapeIsChecked(): void
    {
        $this->needEc();
        $tampers = [
            static fn(Obj $v): mixed => [],
            static function (Obj $v): mixed {
                $v->set('choices', 'x');
                return $v;
            },
            static function (Obj $v): mixed {
                $v->set('padHashes', 'x');
                return $v;
            },
            static function (Obj $v): mixed {
                $v->set('choices', array_slice($v->get('choices'), 0, 1));
                return $v;
            },
            static function (Obj $v): mixed {
                $v->set('padHashes', array_slice($v->get('padHashes'), 0, 1));
                return $v;
            },
        ];
        foreach ($tampers as $i => $t) {
            $run = self::pair('ec', 2, null, static fn(string $rd, mixed $v): mixed => $rd === 'ot-verify' ? $t($v) : $v);
            $e = $this->abortOf($run['s']);
            $this->assertSame("[malformed] blamed=1 reporter=0: round 'ot-verify': bad verify message", $e->getMessage(), "case $i");
            $this->assertSame([$e], $run['sm']->fails);
            $this->assertSame([[1, 'ot-S']], self::rounds($run['sm']));
        }
    }

    /** The receiver counts as matched only on an object whose `matched` is exactly true. */
    public function testOtDoneMustSayTrue(): void
    {
        $this->needEc();
        foreach ([static fn(Obj $v): mixed => Obj::of(['matched' => false]), static fn(Obj $v): mixed => []] as $i => $t) {
            $run = self::pair('ec', 2, static fn(string $rd, mixed $v): mixed => $rd === 'ot-done' ? $t($v) : $v);
            $this->assertTrue($run['s']['ok'] ?? false, "case $i");
            $this->assertTrue($run['s']['v']['matched']);
            $this->assertTrue($run['r']['ok'] ?? false, "case $i");
            $this->assertFalse($run['r']['v']['matched'], "case $i");
        }
    }

    /** ot-S that is not an object is a malformed abort blaming the sender, before the receiver answers. */
    public function testOtSMustBeAnObject(): void
    {
        $this->needEc();
        $run = self::pair('ec', 2, static fn(string $rd, mixed $v): mixed => $rd === 'ot-S' ? [] : $v);
        $e = $this->abortOf($run['r']);
        $this->assertSame("[malformed] blamed=0 reporter=1: round 'ot-S': bad S message", $e->getMessage());
        $this->assertSame([$e], $run['rm']->fails);
        $this->assertSame([], $run['rm']->sent);
    }

    /** A forged Schnorr proof is a commitment abort (the sender cheated), with the base OT's own reason. */
    public function testForgedProofIsACommitmentAbort(): void
    {
        $this->needEc();
        $run = self::pair('ec', 2, static function (string $rd, mixed $v): mixed {
            if ($rd === 'ot-S') {
                $v->set('z', '1');
            }
            return $v;
        });
        $e = $this->abortOf($run['r']);
        $this->assertSame('[commitment] blamed=0 reporter=1: base OT: sender Schnorr proof-of-knowledge of S=y*B failed; aborting', $e->getMessage());
        $this->assertSame('commitment', $e->kind);
        $this->assertSame([$e], $run['rm']->fails);
        $this->assertSame([], $run['rm']->sent);
    }

    /** Any other failure of the receiver's response (here: a binding naming one party at both ends) is malformed, not commitment. */
    public function testOtherReceiverFailureIsMalformed(): void
    {
        $this->needEc();
        $m = new Kill17OtMesh(1);
        $setup = MpcOt::malBaseOtSenderSetup(MpcOtRandom::fromSeed(gmp_init(5)), MpcNetOt::netBinding($m, 0, 1, 'ot-ec'));
        $m->inbox[] = ['ot-S', Kill17OtMesh::wire(['S' => MpcNetCodec::ptJ($setup['S']), 'U' => MpcNetCodec::ptJ($setup['proof']['U']),
            'z' => MpcNetWire::hx($setup['proof']['z'])])];
        try {
            MpcNetOt::runOtReceiver($m, 1, 'ec', 1);
            $this->fail('expected an abort');
        } catch (MpcNetAbort $e) {
            $this->assertSame('[malformed] blamed=1 reporter=1: base-OT binding: sender and receiver must be different parties', $e->getMessage());
            $this->assertSame([$e], $m->fails);
            $this->assertSame([], $m->sent);
        }
    }

    /** An unknown OT kind is refused before either side sends or receives anything (the default clock and entropy). */
    public function testUnknownKindIsRefusedUpFront(): void
    {
        MpcNetOt::$rngHook = null;
        MpcNetOt::$clockHook = null;
        foreach (['sender', 'receiver'] as $role) {
            $m = new Kill17OtMesh($role === 'sender' ? 0 : 1);
            try {
                $role === 'sender' ? MpcNetOt::runOtSender($m, 1, 'bogus', 1) : MpcNetOt::runOtReceiver($m, 0, 'bogus', 1);
                $this->fail("$role: expected a refusal");
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('unknown OT kind', $e->getMessage(), $role);
            }
            $this->assertSame([], $m->sent, $role);
            $this->assertSame([], $m->fails, $role);
        }
    }

    /** The revealed bit is the JSON number 0 or 1 and nothing else (another number or an object carrying a lexeme is -1). */
    public function testRevealedBitReader(): void
    {
        $bit = new \ReflectionMethod(MpcNetOt::class, 'bit');
        $this->assertSame(0, $bit->invoke(null, new Num('0')));
        $this->assertSame(1, $bit->invoke(null, new Num('1')));
        $this->assertSame(-1, $bit->invoke(null, new Num('2')));
        $this->assertSame(-1, $bit->invoke(null, (object)['lexeme' => '0']));
        $this->assertSame(-1, $bit->invoke(null, (object)['lexeme' => '1']));
        $this->assertSame(-1, $bit->invoke(null, null));
    }

    /** The LWE ciphertext reply is a list of exactly `count` two-element lists of strict base64, decoded in order. */
    public function testCiphertextPairParser(): void
    {
        $p = new \ReflectionMethod(MpcNetOt::class, 'parseCtPairs');
        $a = base64_encode('ab');
        $b = base64_encode('cde');
        $this->assertSame([['ab', 'cde']], $p->invoke(null, [[$a, $b]], 1));
        $refusal = static function (mixed $raw, int $count) use ($p): string {
            try {
                $p->invoke(null, $raw, $count);
            } catch (\InvalidArgumentException $e) {
                return $e->getMessage();
            }
            return 'accepted';
        };
        $this->assertSame('bad ciphertext array', $refusal('x', 1));
        $this->assertSame('bad ciphertext array', $refusal(['k' => [$a, $b]], 1));
        $this->assertSame('bad ciphertext array', $refusal([[$a, $b]], 2));
        $this->assertSame('bad ct pair', $refusal(['x'], 1));
        $this->assertSame('bad ct pair', $refusal([['p' => $a, 'q' => $b]], 1));
        $this->assertSame('bad ct pair', $refusal([[$a, $b, $a]], 1));
        $this->assertSame('bad ct pair', $refusal([[$a]], 1));
    }

    /** @param array<string,mixed> $over */
    private static function lweMessage(array $over): array
    {
        $tv = base64_encode(str_repeat("\x01", MpcLweLattice::TVEC_BYTES));
        $rho = base64_encode(str_repeat("\x05", 32));
        return $over + ['rn' => base64_encode(str_repeat("\x07", 32)), 'points' => [[$tv, $tv], [$tv, $tv]], 'rhos' => [$rho, $rho]];
    }

    private function lweSenderRefusal(mixed $message): string
    {
        $m = new Kill17OtMesh(0);
        $m->inbox[] = ['ot-recv', Kill17OtMesh::wire($message)];
        try {
            MpcNetOt::runOtSender($m, 1, 'lwe', 2);
        } catch (MpcNetAbort $e) {
            $this->assertSame([$e], $m->fails);
            $this->assertSame([], $m->sent);
            return $e->getMessage();
        }
        return 'accepted';
    }

    /** The LWE receiver message is parsed strictly (shape, counts, pair shape, 32-byte nonce and rhos) before the endemic OT validates it. */
    public function testLweReceiverMessageParsing(): void
    {
        $tv = base64_encode(str_repeat("\x01", MpcLweLattice::TVEC_BYTES));
        $short = base64_encode("\x02\x03");
        $pre = '[malformed] blamed=1 reporter=0: ';
        $this->assertSame($pre . 'lwe sender: endemic LWE OT: malformed point pair at index 1',
            $this->lweSenderRefusal(self::lweMessage(['points' => [[$tv, $tv], [$tv, $short]]])));
        $this->assertSame($pre . 'lwe sender: endemic LWE OT: malformed point pair at index 1',
            $this->lweSenderRefusal(self::lweMessage(['points' => [[$tv, $tv], [$short, $tv]]])));
        $bad = $pre . "round 'ot-recv': bad receiver message";
        $this->assertSame($bad, $this->lweSenderRefusal([]));
        $this->assertSame($bad, $this->lweSenderRefusal(self::lweMessage(['rhos' => 'x'])));
        $this->assertSame($bad, $this->lweSenderRefusal(self::lweMessage(['points' => 'x'])));
        $this->assertSame($bad, $this->lweSenderRefusal(self::lweMessage(['points' => [[$tv, $tv], [$tv, $tv], [$tv, $tv]]])));
        $pair = $pre . "round 'ot-recv': bad point pair";
        $this->assertSame($pair, $this->lweSenderRefusal(self::lweMessage(['points' => ['x', [$tv, $tv]]])));
        $this->assertSame($pair, $this->lweSenderRefusal(self::lweMessage(['points' => [[$tv, $tv, $tv], [$tv, $tv]]])));
    }

    /** An honest LWE run (needs liblweot): matched, with exactly the endemic OT's pads, bits and digests. */
    public function testHonestLweRunHasTheExactTranscript(): void
    {
        if (!MpcLweLattice::available()) {
            $this->markTestSkipped('needs ext-ffi + liblweot (ATLAS_PCA_LIBLWEOT)');
        }
        $run = self::pair('lwe', 2);
        $this->assertTrue($run['s']['ok'] ?? false, isset($run['s']['e']) ? $run['s']['e']->getMessage() : 'sender unfinished');
        $this->assertTrue($run['r']['ok'] ?? false, isset($run['r']['e']) ? $run['r']['e']->getMessage() : 'receiver unfinished');

        $rr = MpcOtRandom::fromSeed(gmp_init(self::SEED_R));
        $choices = [ord($rr->bytes(1)) & 1, ord($rr->bytes(1)) & 1];
        $rcv = MpcEndemicOt::receive($choices, $rr);
        $sm = MpcEndemicOt::sendRandom($rcv['message'], MpcOtRandom::fromSeed(gmp_init(self::SEED_S)));
        $pads = $sm['senderPads'];
        $recv = MpcEndemicOt::recoverRandom($rcv['state'], ['ciphertexts' => $sm['ciphertexts'], 'senderPads' => []]);

        $this->assertSame(['kind' => 'lwe', 'role' => 'sender', 'count' => 2, 'ms' => 250.0, 'matched' => true,
            'padDigest' => hash('sha256', $pads[0][0] . $pads[0][1] . $pads[1][0] . $pads[1][1])], $run['s']['v']);
        $this->assertSame(['kind' => 'lwe', 'role' => 'receiver', 'count' => 2, 'ms' => 250.0, 'matched' => true,
            'padDigest' => hash('sha256', implode('', $recv))], $run['r']['v']);
        $this->assertSame($pads[0][0], $recv[0]);
        $this->assertSame($pads[1][1], $recv[1]);
        $this->assertSame([[1, 'ot-ct'], [1, 'ot-done']], self::rounds($run['sm']));
        $this->assertSame([[0, 'ot-recv'], [0, 'ot-verify']], self::rounds($run['rm']));
        $this->assertSame([0, 1], $run['rm']->sent[1][2]['choices']);
        $this->assertSame(1, $run['sm']->finishes);
        $this->assertSame(1, $run['rm']->finishes);
    }
}
