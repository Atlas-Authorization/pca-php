<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\MpcFieldRng;
use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCodec;
use Atlas\Pca\MpcNetExchanger;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetOffline;
use Atlas\Pca\MpcNetWire;
use Atlas\Pca\MpcOt;
use Atlas\Pca\MpcOtExtReceiver;
use Atlas\Pca\MpcOtExtSender;
use Atlas\Pca\MpcOtRandom;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** A socket-free mesh for party 0: a fixed session id; aborts it is asked to broadcast are recorded. */
final class Sig29bMesh extends MpcNetMesh
{
    /** @var list<MpcNetAbort> */
    public array $failures = [];

    public function __construct()
    {
        \Closure::bind(function (): void {
            $this->selfId = 0;
        }, $this, MpcNetMesh::class)();
    }

    public function __destruct()
    {
    }

    public function sessionId(): string
    {
        return 'sig29b-offline-session';
    }

    public function fail(MpcNetAbort $err, ?int $skipPeer = null): void
    {
        $this->failures[] = $err;
    }
}

/** Raised by the scripted exchanger on a round the test did not script: the run stops there. */
final class Sig29bStop extends \RuntimeException
{
}

/** Answers each scripted round for peer 1 with what the round's callable returns, given the caller's own mine/parse closures. */
final class Sig29bScript implements MpcNetExchanger
{
    /** @var list<string> */
    public array $rounds = [];

    /** @param array<string,callable(callable,callable):mixed> $script */
    public function __construct(private readonly array $script)
    {
    }

    public function exchange(string $rd, callable $mine, callable $parse, ?int $timeoutMs = null): array
    {
        $this->rounds[] = $rd;
        $f = $this->script[$rd] ?? throw new Sig29bStop($rd);
        return [1 => $f($mine, $parse)];
    }

    public function bad(int $p, string $what): never
    {
        throw new \LogicException("$p: $what");
    }
}

/** Records the u tamper hook the offline phase installs, and stands in for the OT extension receiver's first round. */
final class Sig29bReceiver
{
    public mixed $tamperU = null;

    public function begin(array $choiceBits): array
    {
        return ['msg' => ['u' => [], 'x' => gmp_init(0), 'tComb' => gmp_init(0)]];
    }
}

/** Mutation kills for MpcNetOffline (follow-up): the exact `ot-u-lie` matrix lie, and the input chain count check after a scripted base OT. */
final class SigSurvivorKill29bMpcNetOfflineTest extends TestCase
{
    private static function set(object $o, array $props): void
    {
        foreach ($props as $k => $v) {
            (new \ReflectionProperty(MpcNetOffline::class, $k))->setValue($o, $v);
        }
    }

    /** Run one OT layer of one item with behaviour `$beh` up to the u exchange, where the script stops it; return the receiver stand-in. */
    private function layerUpToU(string $beh): Sig29bReceiver
    {
        $o = (new \ReflectionClass(MpcNetOffline::class))->newInstanceWithoutConstructor();
        $recv = new Sig29bReceiver();
        $io = new Sig29bScript([]);
        self::set($o, ['mesh' => new Sig29bMesh(), 'io' => $io, 'id' => 0, 'n' => 2, 'others' => [1], 'beh' => $beh, 'frng' => MpcFieldRng::secure(),
            'recvCh' => [1 => $recv], 'sendCh' => []]);
        try {
            (new \ReflectionMethod(MpcNetOffline::class, 'otRows'))->invoke($o, '1', [['bits' => [1], 'gad' => [gmp_init(1)], 'y' => gmp_init(2)]]);
            $this->fail('expected the script to stop the layer');
        } catch (Sig29bStop $e) {
            $this->assertSame('ox1.0.u', $e->getMessage());
        }
        return $recv;
    }

    /** `ot-u-lie` flips the low bit of the first 64 of the 128 u columns and leaves the rest; an honest party installs no tamper. */
    public function testTheOtULieFlipsTheFirstRowInHalfTheColumns(): void
    {
        if (!extension_loaded('gmp')) {
            $this->markTestSkipped('needs ext-gmp');
        }
        $this->assertNull($this->layerUpToU('')->tamperU, 'honest');
        $lie = $this->layerUpToU('ot-u-lie')->tamperU;
        $this->assertInstanceOf(\Closure::class, $lie);
        $u = [];
        for ($i = 0; $i < MpcOt::KAPPA; $i++) {
            $u[] = gmp_init(1000 + 2 * $i); // even: the flip sets bit 0
        }
        $want = [];
        for ($i = 0; $i < MpcOt::KAPPA; $i++) {
            $want[] = (string) (1000 + 2 * $i + ($i < 64 ? 1 : 0));
        }
        $this->assertSame($want, array_map('gmp_strval', $lie($u, 0)));
    }

    /**
     * Party 0 runs the offline phase against a scripted peer 1 whose base-OT frames are computed honestly with the same OT functions; the
     * gadget rounds are answered without their signature checks (the parsers are the peer-side validation, not under test here). With a
     * chain count that is not 1 + T_M + Q, the run stops on the local count check before any input is shared.
     */
    public function testAMismatchedInputChainCountIsALocalAbort(): void
    {
        if (($why = RefMpcNetSupport::otUnavailable()) !== null || !extension_loaded('gmp')) {
            $this->markTestSkipped($why ?? 'needs ext-gmp');
        }
        $mesh = new Sig29bMesh();
        $sid = hash('sha256', 'atlas-pca-mpc/net-session/v2' . Js::utf8($mesh->sessionId()), true);
        $chan = static fn (int $recv, int $send, string $round): array => ['sessionId' => $sid, 'senderIndex' => $recv, 'receiverIndex' => $send, 'round' => $round];
        $rng = MpcOtRandom::secure();
        $peerSetup = MpcOt::malBaseOtSenderSetup($rng, $chan(1, 0, 'offline-kappa'));
        $peerSeeds = (new MpcOtExtReceiver($rng, MpcOt::bindingBytes($chan(1, 0, 'iknp-kos'))))->makeSeeds();
        $peerSelector = (new MpcOtExtSender($rng, MpcOt::bindingBytes($chan(0, 1, 'iknp-kos'))))->makeSelector();
        $pairs = static fn (array $ps): array => array_map(static fn (array $p): array => [MpcNetCodec::b64($p[0]), MpcNetCodec::b64($p[1])], $ps);
        $mine = [];
        $signed = static fn (string $hex): Obj => Obj::of(['v' => $hex, 's' => str_repeat('0', 16)]);
        $io = new Sig29bScript([
            'ob-S' => static function (callable $out, callable $parse) use (&$mine, $peerSetup): mixed {
                $mine['S'] = $out(1);
                return $parse(1, Obj::of(['S' => MpcNetCodec::ptJ($peerSetup['S']), 'U' => MpcNetCodec::ptJ($peerSetup['proof']['U']),
                    'z' => MpcNetWire::hx($peerSetup['proof']['z'])]));
            },
            'ob-R' => static function (callable $out, callable $parse) use (&$mine, $peerSelector, $rng, $chan): mixed {
                $mine['R'] = array_map(MpcNetCodec::jPt(...), $out(1));
                $s = $mine['S'];
                $resp = MpcOt::malBaseOtReceiverRespond(MpcNetCodec::jPt($s['S']), ['U' => MpcNetCodec::jPt($s['U']), 'z' => MpcNetCodec::hexBig($s['z'])],
                    $peerSelector, $rng, $chan(0, 1, 'offline-kappa'));
                return $parse(1, array_map(MpcNetCodec::ptJ(...), $resp['R']));
            },
            'ob-C' => static function (callable $out, callable $parse) use (&$mine, $peerSetup, $peerSeeds, $chan, $pairs): mixed {
                $pads = MpcOt::malBaseOtSenderDerive($peerSetup['y'], $peerSetup['T'], $mine['R'], $peerSetup['S'], $chan(1, 0, 'offline-kappa'));
                [$ct, $com] = MpcOt::baseOtSenderEncrypt($peerSeeds, $pads);
                return $parse(1, Obj::of(['ct' => $pairs($ct), 'com' => $pairs($com)]));
            },
            'gd-c' => static fn (): Obj => $signed(str_repeat('a', 64)),
            'gd-o' => static fn (): Obj => $signed(str_repeat('b', 64)),
        ]);
        try {
            MpcNetOffline::run(['mesh' => $mesh, 'io' => $io, 'id' => 0, 'n' => 2, 'C' => 1, 'keys' => 1, 'partners' => 1, 'sessionId' => $mesh->sessionId(),
                'input' => ['allow' => 1, 't' => 1, 'rQuant' => 1], 'Q' => 3, 'behavior' => null, 'crashIf' => static fn (): bool => false]);
            $this->fail('expected the count check to abort');
        } catch (MpcNetAbort $e) {
            $this->assertSame('local', $e->kind);
            $this->assertNull($e->blamed);
            $this->assertSame(0, $e->reporter);
            $this->assertStringContainsString('input chain count mismatch', $e->getMessage());
        }
        $this->assertSame(['ob-S', 'ob-R', 'ob-C', 'gd-c', 'gd-o'], $io->rounds);
        $this->assertSame([], $mesh->failures);
    }
}
