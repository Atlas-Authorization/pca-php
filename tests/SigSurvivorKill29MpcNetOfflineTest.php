<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\MpcBaseOtAbort;
use Atlas\Pca\MpcMalOtAbort;
use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCodec;
use Atlas\Pca\MpcNetExchanger;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetOffline;
use Atlas\Pca\MpcNetWire;
use Atlas\Pca\MpcOt;
use Atlas\Pca\MpcOtRandom;
use Atlas\Pca\MpcPointError;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** A socket-free mesh: a fixed session id, and the aborts it was asked to broadcast. */
final class Sig29OfflineMesh extends MpcNetMesh
{
    /** @var list<MpcNetAbort> */
    public array $failures = [];

    public function __construct()
    {
    }

    public function __destruct()
    {
    }

    public function sessionId(): string
    {
        return 'sig29-offline-session';
    }

    public function fail(MpcNetAbort $err, ?int $skipPeer = null): void
    {
        $this->failures[] = $err;
    }
}

/** Raised by the scripted exchanger's bad(): the parser refused a peer's frame. */
final class Sig29Bad extends \RuntimeException
{
}

/** Answers each round for peer 1 from a script of raw frames, through the caller's own parser. */
final class Sig29Exchanger implements MpcNetExchanger
{
    /** @param array<string,mixed> $raw round => peer 1's raw frame */
    public function __construct(private readonly array $raw)
    {
    }

    public function exchange(string $rd, callable $mine, callable $parse, ?int $timeoutMs = null): array
    {
        if (!array_key_exists($rd, $this->raw)) {
            throw new \LogicException("unscripted round $rd");
        }
        return [1 => $parse(1, $this->raw[$rd])];
    }

    public function bad(int $p, string $what): never
    {
        throw new Sig29Bad("$p: $what");
    }
}

/** Mutation kills for MpcNetOffline: the OT error guard, the strict frame parsers, the empty OT layer and the base-OT R frame refusal. */
final class SigSurvivorKill29MpcNetOfflineTest extends TestCase
{
    private static function bare(Sig29OfflineMesh $mesh): MpcNetOffline
    {
        $o = (new \ReflectionClass(MpcNetOffline::class))->newInstanceWithoutConstructor();
        foreach (['mesh' => $mesh, 'id' => 0, 'n' => 2, 'others' => [1]] as $k => $v) {
            (new \ReflectionProperty(MpcNetOffline::class, $k))->setValue($o, $v);
        }
        return $o;
    }

    private static function call(?object $o, string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(MpcNetOffline::class, $method))->invoke($o, ...$args);
    }

    private function guarded(\Throwable $thrown): array
    {
        $mesh = new Sig29OfflineMesh();
        try {
            self::call(self::bare($mesh), 'otGuard', 1, 'step', static fn () => throw $thrown);
        } catch (\Throwable $e) {
            return [$e, $mesh->failures];
        }
        $this->fail('expected the guard to throw');
    }

    /** An OT check failure is an `ot-check` abort naming the peer, anything else `malformed`; it is broadcast and thrown. */
    public function testTheOtGuardClassifiesAndBroadcasts(): void
    {
        foreach ([[new MpcBaseOtAbort('b'), 'ot-check'], [new MpcMalOtAbort('b'), 'ot-check'], [new MpcPointError('b'), 'ot-check'],
                  [new \RuntimeException('b'), 'malformed']] as [$thrown, $kind]) {
            [$e, $failures] = $this->guarded($thrown);
            $this->assertInstanceOf(MpcNetAbort::class, $e);
            $this->assertSame($kind, $e->kind, get_class($thrown));
            $this->assertSame(1, $e->blamed);
            $this->assertSame(0, $e->reporter);
            $this->assertStringContainsString('step: b', $e->getMessage());
            $this->assertSame([$e], $failures);
        }
    }

    /** An abort raised inside the guarded step passes through unchanged and is not broadcast again. */
    public function testTheOtGuardPassesAnAbortThrough(): void
    {
        $abort = new MpcNetAbort('dealer', 1, 0, 'x');
        [$e, $failures] = $this->guarded($abort);
        $this->assertSame($abort, $e);
        $this->assertSame([], $failures);
    }

    public function testTheFrameParsersAreStrict(): void
    {
        $refused = function (string $message, string $method, mixed ...$args): void {
            try {
                self::call(null, $method, ...$args);
                $this->fail("expected: $message");
            } catch (\InvalidArgumentException $e) {
                $this->assertSame($message, $e->getMessage());
            }
        };
        $refused('bad 128-bit value', 'hex128', 'zz');
        $refused('bad pair array', 'parsePairs', 'x', 1, 16);
        $refused('bad pair', 'parsePairs', ['x'], 1, 16);
    }

    /** An empty layer still answers every member, with an empty row per peer. */
    public function testAnEmptyOtLayer(): void
    {
        $r = self::call(self::bare(new Sig29OfflineMesh()), 'otRows', '1', []);
        $this->assertSame(['recv', 'sendSum', 'kept'], array_keys($r));
        $this->assertSame([1 => []], $r['recv']);
    }

    /** A peer's base-OT R frame that is not a list of KAPPA points is refused through the exchanger, before any point is read. */
    public function testABadRFrameIsRefused(): void
    {
        if (($why = RefMpcNetSupport::otUnavailable()) !== null || !extension_loaded('gmp')) {
            $this->markTestSkipped($why ?? 'needs ext-gmp');
        }
        $mesh = new Sig29OfflineMesh();
        $sid = hash('sha256', 'atlas-pca-mpc/net-session/v2' . Js::utf8($mesh->sessionId()), true);
        $st = MpcOt::malBaseOtSenderSetup(MpcOtRandom::secure(), ['sessionId' => $sid, 'senderIndex' => 1, 'receiverIndex' => 0, 'round' => 'offline-kappa']);
        $s = Obj::of(['S' => MpcNetCodec::ptJ($st['S']), 'U' => MpcNetCodec::ptJ($st['proof']['U']), 'z' => MpcNetWire::hx($st['proof']['z'])]);
        $io = new Sig29Exchanger(['ob-S' => $s, 'ob-R' => 'x']);
        try {
            MpcNetOffline::run(['mesh' => $mesh, 'io' => $io, 'id' => 0, 'n' => 2, 'C' => 1, 'keys' => 1, 'partners' => 1, 'sessionId' => $mesh->sessionId(),
                'input' => [], 'Q' => 3, 'behavior' => null, 'crashIf' => static fn (): bool => false]);
            $this->fail('expected a refusal');
        } catch (Sig29Bad $e) {
            $this->assertSame('1: bad R array', $e->getMessage());
        }
    }
}
