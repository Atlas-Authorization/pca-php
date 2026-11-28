<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetLink;
use Atlas\Pca\MpcNetMesh;
use PHPUnit\Framework\TestCase;

/**
 * Group 25b kills for src/MpcNetMesh.php: the ext-openssl guard, the dial and handshake pacing on a fake monotonic clock (each limit
 * is held at the limit and acted on one millisecond past it), and the write-failure path of flush. No test waits on the real clock.
 */
final class SysSurvivorKill25bMpcNetMeshTest extends TestCase
{
    private int $t = 0;
    private static ?array $ids = null;
    /** @var list<MpcNetMesh> */
    private array $meshes = [];

    protected function tearDown(): void
    {
        MpcNetMesh::$extensionHook = null;
        MpcNetMesh::$monoHook = null;
        MpcNetMesh::$writeHook = null;
        MpcNetMesh::$eofHook = null;
        RefMpcNetSupport::closeAll($this->meshes);
        $this->meshes = [];
    }

    private function needMesh(): void
    {
        $why = RefMpcNetSupport::meshUnavailable();
        if ($why !== null) {
            $this->markTestSkipped($why);
        }
        MpcNetMesh::$monoHook = fn(): int => $this->t;
    }

    private function mesh(int $self, ?array $nodes = null): MpcNetMesh
    {
        $c = self::$ids ??= RefMpcNetSupport::identities(2);
        return $this->meshes[] = new MpcNetMesh(RefMpcNetSupport::cfg($self, $nodes ?? $c['nodes'], $c['ids'][$self], 600000, 600000));
    }

    private static function dial(MpcNetMesh $m, int $id, array &$d): void
    {
        (new \ReflectionMethod(MpcNetMesh::class, 'dialStep'))->invokeArgs($m, [$id, &$d]);
    }

    private static function priv(MpcNetMesh $m, string $prop): mixed
    {
        return (new \ReflectionProperty(MpcNetMesh::class, $prop))->getValue($m);
    }

    /** @return array{0:resource,1:resource,2:resource} a listener, a connected client end (non-blocking) and its accepted peer */
    private static function tcpPair(): array
    {
        $srv = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertIsResource($srv);
        $c = stream_socket_client('tcp://' . stream_socket_get_name($srv, false), $errno, $errstr, 5);
        self::assertIsResource($c);
        $a = stream_socket_accept($srv, 5);
        self::assertIsResource($a);
        stream_set_blocking($c, false);
        return [$srv, $c, $a];
    }

    public function testWithoutOpensslTheMeshRefuses(): void
    {
        MpcNetMesh::$extensionHook = static fn(string $name): bool => $name !== 'openssl';
        $c = ['keyPem' => 'k', 'certPem' => 'c'];
        try {
            new MpcNetMesh(RefMpcNetSupport::cfg(0, [['id' => 0, 'host' => '127.0.0.1', 'port' => 0, 'certPem' => 'c']], $c, 1000, 1000));
            $this->fail('no ext-openssl must be refused');
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertSame('mesh: ext-openssl is required', $e->getMessage());
        }
    }

    /** A dial that cannot even start is retried DIAL_RETRY_MS later: not before, exactly then. */
    public function testFailedDialIsRetriedAfterThePacing(): void
    {
        $this->needMesh();
        $nodes = (self::$ids ??= RefMpcNetSupport::identities(2))['nodes'];
        $nodes[0]['host'] = '['; // an address that does not parse: the dial fails at once
        $m = $this->mesh(1, $nodes);
        $d = ['sock' => null, 'state' => 'idle', 'retryAt' => 0, 'started' => 0];
        $this->t = 1000;
        self::dial($m, 0, $d);
        $this->assertSame(['sock' => null, 'state' => 'idle', 'retryAt' => 1150, 'started' => 0], $d);
        $this->t = 1149;
        self::dial($m, 0, $d);
        $this->assertSame(1150, $d['retryAt'], 'not dialled before the retry time');
        $this->t = 1150;
        self::dial($m, 0, $d);
        $this->assertSame(1300, $d['retryAt'], 'dialled again at the retry time');
    }

    /** A TCP connect still pending after DIAL_CONNECT_TIMEOUT_MS is closed and retried; at the limit it is kept. */
    public function testPendingConnectIsDroppedPastItsLimit(): void
    {
        $this->needMesh();
        $m = $this->mesh(1);
        $srv = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr); // a listening socket never becomes writable: a connect that never completes
        $this->assertIsResource($srv);
        $d = ['sock' => $srv, 'state' => 'connecting', 'retryAt' => 0, 'started' => 1000];
        $this->t = 1000 + MpcNetMesh::DIAL_CONNECT_TIMEOUT_MS;
        self::dial($m, 0, $d);
        $this->assertSame('connecting', $d['state']);
        $this->assertTrue(is_resource($srv));
        $this->t++;
        self::dial($m, 0, $d);
        $this->assertSame(['sock' => null, 'state' => 'idle', 'retryAt' => $this->t + MpcNetMesh::DIAL_RETRY_MS, 'started' => 0], $d);
        $this->assertFalse(is_resource($srv), 'the abandoned socket is closed');
    }

    /** A TLS handshake the peer never answers is dropped past HANDSHAKE_TIMEOUT_MS; at the limit it is kept. */
    public function testStalledHandshakeIsDroppedPastItsLimit(): void
    {
        $this->needMesh();
        $m = $this->mesh(1);
        [$srv, $c, $a] = self::tcpPair();
        $d = ['sock' => $c, 'state' => 'tls', 'retryAt' => 0, 'started' => 1000];
        $this->t = 1000 + MpcNetMesh::HANDSHAKE_TIMEOUT_MS;
        self::dial($m, 0, $d);
        $this->assertSame('tls', $d['state']);
        $this->t++;
        self::dial($m, 0, $d);
        $this->assertSame(['sock' => null, 'state' => 'idle', 'retryAt' => $this->t + MpcNetMesh::DIAL_RETRY_MS, 'started' => 0], $d);
        $this->assertFalse(is_resource($c));
        fclose($a);
        fclose($srv);
    }

    /** A peer that answers the ClientHello with something that is not TLS fails the handshake: the dial is retried at once (paced). */
    public function testRefusedHandshakeIsRetried(): void
    {
        $this->needMesh();
        $m = $this->mesh(1);
        [$srv, $c, $a] = self::tcpPair();
        fwrite($a, "HTTP/1.0 400 Bad Request\r\n\r\n");
        $r = [$c];
        $w = $e = [];
        $this->assertSame(1, stream_select($r, $w, $e, 5), 'the reply is readable before the handshake starts');
        $this->t = 1000;
        $d = ['sock' => $c, 'state' => 'tls', 'retryAt' => 0, 'started' => 1000];
        self::dial($m, 0, $d);
        $this->assertSame(['sock' => null, 'state' => 'idle', 'retryAt' => 1150, 'started' => 0], $d);
        $this->assertFalse(is_resource($c));
        fclose($a);
        fclose($srv);
    }

    /** An accepted client that never sends a ClientHello is dropped, noted as timed out, exactly at HANDSHAKE_TIMEOUT_MS. */
    public function testAcceptedHandshakeTimesOutAtItsLimit(): void
    {
        $this->needMesh();
        $m = $this->mesh(0);
        $port = $m->listen();
        $c = stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 5);
        $this->assertIsResource($c);
        $this->t = 1000;
        for ($i = 0; $i < 1000 && self::priv($m, 'pendingSeq') < 1; $i++) {
            $m->pump(); // the connection is already in the backlog: the first pumps accept it
        }
        $this->assertSame(1, self::priv($m, 'pendingSeq'));
        $this->t = 1000 + MpcNetMesh::HANDSHAKE_TIMEOUT_MS - 1;
        $m->pump();
        $this->assertCount(1, self::priv($m, 'pending'));
        $this->assertSame([], $m->events);
        $this->t++;
        $m->pump();
        $this->assertSame([], self::priv($m, 'pending'));
        $this->assertSame(['tlsClientError: handshake timed out'], $m->events);
        fclose($c);
    }

    /** flush: only a failed write on a socket at end-of-file closes the link (noted before the hello); a short or failed write alone waits. */
    public function testWriteFailureAtEofClosesTheLink(): void
    {
        $this->needMesh();
        foreach ([[false, true, true], [false, false, false], [0, true, false]] as [$n, $eof, $closes]) {
            $m = $this->mesh(0);
            /** @var MpcNetLink $l */
            $l = self::priv($m, 'links')[1];
            $mem = fopen('php://memory', 'r+');
            $l->sock = $mem;
            $l->out = 'frame';
            MpcNetMesh::$writeHook = static fn($s, string $data): int|false => $n;
            MpcNetMesh::$eofHook = static fn($s): bool => $s === $mem && $eof;
            (new \ReflectionMethod(MpcNetMesh::class, 'flush'))->invoke($m, $l);
            $label = var_export([$n, $eof], true);
            $this->assertSame($closes, $l->closed, $label);
            $this->assertSame($closes ? ['link 1 closed before hello: socket error: write failed'] : [], $m->events, $label);
            $this->assertSame('frame', $l->out, $label);
            $l->sock = null;
            fclose($mem);
        }
    }
}
