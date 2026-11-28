<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetFaultProxy;
use Atlas\Pca\MpcNetFaults;
use Atlas\Pca\MpcNetWire;
use PHPUnit\Framework\TestCase;

/**
 * Group 28 survivors in MpcNetFaults: every frame fault of tamperFor on crafted events, and the proxy's byte pipe driven directly
 * over in-memory streams with a fixed monotonic clock (no sockets except the one listen-collision check).
 */
final class MixSurvivorKill28MpcNetFaultsTest extends TestCase
{
    private const FRAME = ['v' => 1, 'ty' => 'msg', 'sid' => 's1', 'seq' => 3, 'rd' => 'r', 'd' => ['x' => 1]];

    protected function tearDown(): void
    {
        MpcNetFaultProxy::$monoHook = null;
    }

    private static function ev(string $raw, string $rd = 'r', int $to = 1): array
    {
        return ['frame' => ['rd' => $rd] + self::FRAME, 'raw' => $raw, 'to' => $to];
    }

    private static function one(array $spec, string $raw): array
    {
        return (MpcNetFaults::tamperFor($spec + ['round' => 'r']))(self::ev($raw));
    }

    /** reorder holds the hit frame and releases it after the next frame to the same peer; other frames pass. */
    public function testReorder(): void
    {
        $t = MpcNetFaults::tamperFor(['kind' => 'reorder', 'round' => 'r']);
        self::assertSame([], $t(self::ev('A', 'r', 1)));
        self::assertSame(['B'], $t(self::ev('B', 'x', 2)));
        self::assertSame(['C', 'A'], $t(self::ev('C', 'x', 1)));
    }

    /** A fault fires only on its round and, when `to` is set, only towards that peer. */
    public function testHitNeedsRoundAndPeer(): void
    {
        $to1 = MpcNetFaults::tamperFor(['kind' => 'duplicate', 'round' => 'r', 'to' => 1]);
        self::assertSame(['A', 'A'], $to1(self::ev('A', 'r', 1)));
        self::assertSame(['A'], $to1(self::ev('A', 'r', 2)));
        self::assertSame(['A'], $to1(self::ev('A', 'q', 1)));
        $any = MpcNetFaults::tamperFor(['kind' => 'duplicate', 'round' => 'r']);
        self::assertSame(['A'], $any(self::ev('A', 'q', 1)));
        self::assertSame(['A', 'A'], $any(self::ev('A', 'r', 7)));
    }

    /** The byte-level frame faults rewrite exactly as documented. */
    public function testFrameRewrites(): void
    {
        $f = self::FRAME;
        self::assertSame([MpcNetWire::encodeFrame(['seq' => 4] + $f)], self::one(['kind' => 'skip-seq'], 'raw'));
        self::assertSame([pack('N', 16) . str_repeat('Z', 16)], self::one(['kind' => 'garbage'], str_repeat('q', 20)));
        self::assertSame(['abcde'], self::one(['kind' => 'truncate'], 'abcdefgh'));
        self::assertSame(['0123456789'], self::one(['kind' => 'truncate'], '0123456789abcdefghij'));
        self::assertSame([MpcNetWire::encodeFrame(['rd' => 'zzz-r'] + $f)], self::one(['kind' => 'wrong-round'], 'raw'));
        self::assertSame([pack('N', 0x7fffffff)], self::one(['kind' => 'oversize'], 'raw'));
        self::assertSame([], self::one(['kind' => 'drop'], 'raw'));
        $abort = static fn(int $b): array => [MpcNetWire::encodeFrame(['ty' => 'abort', 'rd' => 'abort',
            'd' => ['kind' => 'timeout', 'blamed' => $b, 'detail' => 'forged accusation']] + $f)];
        self::assertSame($abort(2), self::one(['kind' => 'false-accuse', 'accuse' => 2], 'raw'));
        self::assertSame($abort(0), self::one(['kind' => 'false-accuse'], 'raw'));
        $body = substr(MpcNetWire::stringify($f), 0, -1) . ',"x":1}';
        self::assertStringEndsWith('}', MpcNetWire::stringify($f));
        self::assertSame([pack('N', strlen($body)) . $body], self::one(['kind' => 'extra-field'], 'raw'));
    }

    /** bitflip flips bit 2 of the byte at floor(60%) of the frame, with no warning. */
    public function testBitflip(): void
    {
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            $warnings[] = $msg;
            return true;
        });
        try {
            $out = self::one(['kind' => 'bitflip'], 'ABCDEFGHIJK');
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $warnings);
        self::assertSame(['ABCDEFCHIJK'], $out);
    }

    /** silent-from swallows the hit frame and everything after it, on any round. */
    public function testSilentFrom(): void
    {
        $t = MpcNetFaults::tamperFor(['kind' => 'silent-from', 'round' => 'r']);
        self::assertSame(['A'], $t(self::ev('A', 'x')));
        self::assertSame([], $t(self::ev('B', 'r')));
        self::assertSame([], $t(self::ev('C', 'x')));
    }

    /** An unknown fault kind is refused when it fires. */
    public function testUnknownKind(): void
    {
        try {
            self::one(['kind' => 'bogus'], 'raw');
            self::fail('expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('unknown frame fault bogus', $e->getMessage());
        }
    }

    // ---- the proxy ----

    private static function proxy(array $fault): MpcNetFaultProxy
    {
        return new MpcNetFaultProxy(0, ['host' => '127.0.0.1', 'port' => 9], $fault + ['dir' => 'c2s', 'afterBytes' => 0]);
    }

    private static function st(array $over = []): array
    {
        return $over + ['seen' => 0, 'fired' => false, 'done' => false, 'held' => null, 'out' => '', 'delayed' => [], 'ended' => false, 'shut' => false];
    }

    /** Run one pipe() step reading `$in` (then end of stream); returns what was written. */
    private static function pipe(MpcNetFaultProxy $p, string $in, array &$st): string
    {
        $from = fopen('php://memory', 'w+');
        fwrite($from, $in);
        rewind($from);
        $to = fopen('php://memory', 'w+');
        (new \ReflectionMethod(MpcNetFaultProxy::class, 'pipe'))->invokeArgs($p, [$from, $to, &$st, 'c2s']);
        rewind($to);
        $out = (string) stream_get_contents($to);
        fclose($from);
        fclose($to);
        return $out;
    }

    /** port() is -1 before listen; listening on a port already held fails closed. */
    public function testPortAndListenCollision(): void
    {
        $a = self::proxy(['kind' => 'none']);
        self::assertSame(-1, $a->port());
        $a->listen();
        $b = new MpcNetFaultProxy($a->port(), ['host' => '127.0.0.1', 'port' => 9], ['kind' => 'none', 'dir' => 'c2s', 'afterBytes' => 0]);
        try {
            $b->listen();
            self::fail('expected the second listen to fail');
        } catch (\RuntimeException $e) {
            self::assertStringStartsWith('fault proxy: cannot listen: ', $e->getMessage());
        } finally {
            $b->close();
            $a->close();
        }
    }

    /** Delayed bytes are released in order once due, and a held chunk is appended at end of stream. */
    public function testDelayedAndHeldBytesAreAppended(): void
    {
        MpcNetFaultProxy::$monoHook = static fn(): int => 10;
        $st = self::st(['delayed' => [[5, 'D1'], [10, 'D2'], [50, 'D3']]]);
        self::assertSame('D1D2', self::pipe(self::proxy(['kind' => 'none']), '', $st));
        self::assertSame([[50, 'D3']], $st['delayed']);
        $st = self::st(['out' => 'X', 'held' => 'H']);
        self::assertSame('XH', self::pipe(self::proxy(['kind' => 'none']), '', $st));
        self::assertNull($st['held']);
    }

    /** A delay fault queues the chunk for now + ms (default 1000). */
    public function testDelayQueuesWithItsDueTime(): void
    {
        MpcNetFaultProxy::$monoHook = static fn(): int => 1000;
        $st = self::st();
        self::assertSame('', self::pipe(self::proxy(['kind' => 'delay', 'ms' => 50]), 'hello', $st));
        self::assertSame([[1050, 'hello']], $st['delayed']);
        $st = self::st();
        self::pipe(self::proxy(['kind' => 'delay']), 'hello', $st);
        self::assertSame([[2000, 'hello']], $st['delayed']);
    }

    /** Once a drop fault has fired the link stays a black hole, and end of stream is still seen. */
    public function testFiredDropStaysBlack(): void
    {
        $st = self::st(['fired' => true]);
        self::assertSame('', self::pipe(self::proxy(['kind' => 'drop', 'afterBytes' => 100]), 'hello', $st));
        self::assertTrue($st['ended']);
    }

    /** truncate forwards half of the chunk that crosses the threshold, then ends the direction. */
    public function testTruncate(): void
    {
        $st = self::st(['out' => 'X']);
        $out = self::pipe(self::proxy(['kind' => 'truncate']), 'c' . str_repeat('a', 65535) . 'bbbbbbbbbb', $st);
        self::assertSame('X' . 'c' . str_repeat('a', 32767), $out);
        self::assertTrue($st['done']);
        self::assertTrue($st['ended']);
    }

    /** duplicate repeats only the chunk that crosses the threshold. */
    public function testDuplicate(): void
    {
        $c1 = str_repeat('a', 65536);
        $st = self::st(['out' => 'X']);
        self::assertSame('X' . $c1 . $c1 . 'bbbbbbbbbb', self::pipe(self::proxy(['kind' => 'duplicate']), $c1 . 'bbbbbbbbbb', $st));
        self::assertTrue($st['done']);
    }

    /** reorder swaps the crossing chunk with the next one, once: later chunks keep their order. */
    public function testReorderSwapsTwoChunks(): void
    {
        [$c1, $c2, $c3] = [str_repeat('a', 65536), str_repeat('b', 65536), str_repeat('c', 65536)];
        $st = self::st(['out' => 'X']);
        self::assertSame('X' . $c2 . $c1 . $c3 . 'dddd', self::pipe(self::proxy(['kind' => 'reorder']), $c1 . $c2 . $c3 . 'dddd', $st));
        self::assertTrue($st['done']);
        self::assertNull($st['held']);
    }

    /** A connection whose upstream refuses is closed and the next pending connection is still accepted in the same pump. */
    public function testRefusedUpstreamDoesNotStopAccepting(): void
    {
        $tmp = stream_socket_server('tcp://127.0.0.1:0');
        self::assertNotFalse($tmp);
        $name = (string) stream_socket_get_name($tmp, false);
        fclose($tmp);
        $closed = (int) substr($name, (int) strrpos($name, ':') + 1);
        $p = new MpcNetFaultProxy(0, ['host' => '127.0.0.1', 'port' => $closed], ['kind' => 'none', 'dir' => 'c2s', 'afterBytes' => 0]);
        $p->listen();
        try {
            $c1 = stream_socket_client('tcp://127.0.0.1:' . $p->port());
            $c2 = stream_socket_client('tcp://127.0.0.1:' . $p->port());
            self::assertNotFalse($c1);
            self::assertNotFalse($c2);
            $p->pump();
            $server = (new \ReflectionProperty(MpcNetFaultProxy::class, 'server'))->getValue($p);
            self::assertFalse(@stream_socket_accept($server, 0), 'a pending connection was left unaccepted');
            self::assertSame([], $p->log);
            fclose($c1);
            fclose($c2);
        } finally {
            $p->close();
        }
    }

    /** An unrecognised wire fault passes bytes through, appending to what is pending. */
    public function testUnknownWireFaultPassesThrough(): void
    {
        $st = self::st(['out' => 'X']);
        self::assertSame('Xhello', self::pipe(self::proxy(['kind' => 'weird']), 'hello', $st));
    }
}
