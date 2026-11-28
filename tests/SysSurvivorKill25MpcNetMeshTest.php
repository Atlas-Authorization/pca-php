<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCerts;
use Atlas\Pca\MpcNetLink;
use Atlas\Pca\MpcNetLoop;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetWire;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Group 25 kills for src/MpcNetMesh.php. The receive path is driven frame by frame through the mesh's own onData (no sockets, so every
 * verdict is exact); the dial and accept paths run over loopback, each waiting on mesh state rather than on time.
 */
final class SysSurvivorKill25MpcNetMeshTest extends TestCase
{
    private const SID = 'mesh-test-session';
    /** Scheduling rounds a network test waits on mesh state before it gives up (and fails) instead of hanging. */
    private const ROUNDS = 4000;

    /** @var array<int,array{ids:list<array{keyPem:string,certPem:string}>,nodes:list<array{id:int,host:string,port:int,certPem:string}>}> */
    private static array $ids = [];
    /** @var list<MpcNetMesh> */
    private array $meshes = [];

    protected function setUp(): void
    {
        $why = RefMpcNetSupport::meshUnavailable();
        if ($why !== null) {
            $this->markTestSkipped($why);
        }
    }

    protected function tearDown(): void
    {
        RefMpcNetSupport::closeAll($this->meshes);
        $this->meshes = [];
    }

    private static function ids(int $n): array
    {
        return self::$ids[$n] ??= RefMpcNetSupport::identities($n);
    }

    /** @param array<string,mixed> $extra */
    private function mesh(int $self, int $n = 2, array $extra = [], ?array $nodes = null): MpcNetMesh
    {
        $c = self::ids($n);
        return $this->meshes[] = new MpcNetMesh(RefMpcNetSupport::cfg($self, $nodes ?? $c['nodes'], $c['ids'][$self], 600000, 600000, $extra));
    }

    private static function link(MpcNetMesh $m, int $peer): MpcNetLink
    {
        return (new \ReflectionProperty(MpcNetMesh::class, 'links'))->getValue($m)[$peer];
    }

    private static function priv(MpcNetMesh $m, string $prop): mixed
    {
        return (new \ReflectionProperty(MpcNetMesh::class, $prop))->getValue($m);
    }

    private static function frame(int $seq, string $ty, string $rd, mixed $d, int $v = MpcNetWire::WIRE_VERSION): string
    {
        return MpcNetWire::encodeFrame(['v' => $v, 'ty' => $ty, 'sid' => self::SID, 'seq' => $seq, 'rd' => $rd, 'd' => $d]);
    }

    private static function feed(MpcNetMesh $m, int $peer, string ...$frames): void
    {
        $on = new \ReflectionMethod(MpcNetMesh::class, 'onData');
        foreach ($frames as $f) {
            $on->invoke($m, self::link($m, $peer), $f);
        }
    }

    private static function hello(int $id): string
    {
        return self::frame(0, 'hello', 'hello', ['id' => $id]);
    }

    /** @param \Closure():mixed $f */
    private function aborts(string $message, \Closure $f): MpcNetAbort
    {
        try {
            $f();
        } catch (MpcNetAbort $e) {
            $this->assertSame($message, $e->getMessage());
            return $e;
        }
        $this->fail("expected the abort $message");
    }

    public function testRealTimePacingConstants(): void
    {
        $this->assertSame(150, MpcNetMesh::DIAL_RETRY_MS);
        $this->assertSame(5000, MpcNetMesh::DIAL_CONNECT_TIMEOUT_MS);
        $this->assertSame(10000, MpcNetMesh::HANDSHAKE_TIMEOUT_MS);
    }

    public function testConfigurationRefusals(): void
    {
        $c = self::ids(2);
        try {
            new MpcNetMesh(RefMpcNetSupport::cfg(0, [$c['nodes'][1]], $c['ids'][0], 1000, 1000));
            $this->fail('self must be listed');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('mesh: self not in nodes', $e->getMessage());
        }
        try {
            new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 1000, 1000, ['linkTo' => [1, 5]]));
            $this->fail('a link target must be listed');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('mesh: unknown link target 5', $e->getMessage());
        }
        $m = $this->mesh(0);
        foreach ([9, 0] as $bad) {
            try {
                $m->setPeerPort($bad, 1);
                $this->fail('only a listed peer has a port to set');
            } catch (\InvalidArgumentException $e) {
                $this->assertSame("mesh: unknown peer $bad", $e->getMessage());
            }
        }
    }

    /** failed() is public; linkAuthenticated needs the link and its hello; verify of an unlisted peer is false. */
    public function testPublicState(): void
    {
        $m = $this->mesh(0);
        $this->assertNull($m->failed());
        $this->assertFalse($m->linkAuthenticated(9));
        $this->assertFalse($m->linkAuthenticated(1));
        self::link($m, 1)->helloSeen = true;
        $this->assertTrue($m->linkAuthenticated(1));
        $this->assertFalse($m->verify(9, 'statement', $m->sign('statement')));
    }

    /** At most MAX_MESH_EVENTS notes are kept; the rest are counted. */
    public function testEventCap(): void
    {
        $m = $this->mesh(0);
        $note = new \ReflectionMethod(MpcNetMesh::class, 'note');
        for ($i = 0; $i <= MpcNetMesh::MAX_MESH_EVENTS; $i++) {
            $note->invoke($m, "n$i");
        }
        $this->assertCount(MpcNetMesh::MAX_MESH_EVENTS, $m->events);
        $this->assertSame('n' . (MpcNetMesh::MAX_MESH_EVENTS - 1), $m->events[MpcNetMesh::MAX_MESH_EVENTS - 1]);
        $this->assertSame(1, $m->eventsDropped);
    }

    /** A link that closes before its hello is noted once; after the hello it is not. */
    public function testCloseBeforeHelloNote(): void
    {
        $m = $this->mesh(0, 3);
        $closed = new \ReflectionMethod(MpcNetMesh::class, 'onClosed');
        $closed->invoke($m, self::link($m, 1), 'socket closed');
        $closed->invoke($m, self::link($m, 1), 'socket closed');
        self::link($m, 2)->helloSeen = true;
        $closed->invoke($m, self::link($m, 2), 'socket closed');
        $this->assertSame(['link 1 closed before hello: socket closed'], $m->events);
    }

    public function testListenFailureNamesTheAddress(): void
    {
        $holder = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $this->assertIsResource($holder);
        $name = (string) stream_socket_get_name($holder, false);
        $port = (int) substr($name, (int) strrpos($name, ':') + 1);
        $nodes = self::ids(2)['nodes'];
        $nodes[0]['port'] = $port;
        $m = $this->mesh(0, 2, [], $nodes);
        try {
            $m->listen();
            $this->fail('the port is held');
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertStringStartsWith("mesh: cannot listen on 127.0.0.1:$port: ", $e->getMessage());
        } finally {
            fclose($holder);
        }
    }

    /** A bad identity key is a signing failure, not an empty signature. */
    public function testSigningFailure(): void
    {
        $c = self::ids(2);
        $m = $this->meshes[] = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], ['keyPem' => 'not a key', 'certPem' => $c['ids'][0]['certPem']], 1000, 1000));
        set_error_handler(static fn(): bool => true); // openssl warns about the key before it returns false
        try {
            $m->sign('statement');
            $this->fail('signing with no key must fail');
        } catch (\RuntimeException $e) {
            $this->assertSame('mesh: signing failed', $e->getMessage());
        } finally {
            restore_error_handler();
        }
    }

    /** The connect timeout names every missing peer and poisons the mesh with the same abort. */
    public function testConnectTimeoutDetail(): void
    {
        $clock = new RefManualClock();
        $c = self::ids(3);
        $m = $this->meshes[] = new MpcNetMesh(RefMpcNetSupport::cfg(1, $c['nodes'], $c['ids'][1], 3000, 3000, ['clock' => $clock]));
        $res = RefMpcNetSupport::run([0 => static fn() => $m->connect()], static function () use ($clock): void {
            $clock->advance(500);
        });
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame('[timeout] blamed=0 reporter=1: connect: no authenticated link from 0,2', $a->getMessage());
        $this->assertSame($a, $m->failed());
    }

    public function testVersionMismatch(): void
    {
        $m = $this->mesh(0);
        self::feed($m, 1, self::frame(0, 'hello', 'hello', ['id' => 1], 3));
        $this->assertSame('[version] blamed=1 reporter=0: peer 1 speaks wire version 3, this node speaks 2; upgrade both peers', $m->failed()?->getMessage());
    }

    public function testReplayedSequence(): void
    {
        $m = $this->mesh(0);
        self::feed($m, 1, self::hello(1), self::frame(1, 'msg', 'r1', ['x' => 1]), self::frame(1, 'msg', 'r1', ['x' => 1]));
        $this->assertSame('[duplicate] blamed=1 reporter=0: expected seq 2, got 1 (round r1)', $m->failed()?->getMessage());
    }

    public function testHelloClaims(): void
    {
        $m = $this->mesh(0);
        self::feed($m, 1, self::frame(0, 'hello', 'hello', ['id' => 5]));
        $this->assertSame('[identity] blamed=1 reporter=0: hello claims id 5 on the link pinned to 1', $m->failed()?->getMessage());
        $m = $this->mesh(0);
        self::feed($m, 1, self::frame(0, 'hello', 'hello', ['x' => 1]));
        $this->assertSame('[identity] blamed=1 reporter=0: hello claims id none on the link pinned to 1', $m->failed()?->getMessage());
        $m = $this->mesh(0);
        self::feed($m, 1, self::frame(0, 'msg', 'r1', ['x' => 1]));
        $this->assertSame('[malformed] blamed=1 reporter=0: data before hello', $m->failed()?->getMessage());
        $this->assertSame([], self::link($m, 1)->inbox);
    }

    /** Past half the inbox cap the link pauses; draining back to half resumes it. */
    public function testBackPressure(): void
    {
        $m = $this->mesh(0, 2, ['maxInboxFrames' => 4]);
        $l = self::link($m, 1);
        self::feed($m, 1, self::hello(1), self::frame(1, 'msg', 'r1', ['i' => 1]), self::frame(2, 'msg', 'r1', ['i' => 2]));
        $this->assertFalse($l->paused);
        self::feed($m, 1, self::frame(3, 'msg', 'r1', ['i' => 3]));
        $this->assertTrue($l->paused);
        $this->assertNull($m->failed());
        $got = $m->recv(1, 'r1', 0);
        $this->assertInstanceOf(Obj::class, $got);
        $this->assertSame(1.0, $got->get('i')->float());
        $this->assertFalse($l->paused);
    }

    public function testWrongRound(): void
    {
        $m = $this->mesh(0);
        self::feed($m, 1, self::hello(1), self::frame(1, 'msg', 'r1', ['x' => 1]));
        $e = $this->aborts("[wrong-round] blamed=1 reporter=0: expected round 'r2', got 'r1'", static fn() => $m->recv(1, 'r2', 0));
        $this->assertSame($e, $m->failed());
    }

    /** A deferred abort claim is raised when it is read, and poisons the mesh. */
    public function testDeferredAbortIsRaisedWhenRead(): void
    {
        $m = $this->mesh(0);
        $m->setDeferAborts(true);
        self::feed($m, 1, self::hello(1), self::frame(1, 'abort', 'abort', ['kind' => 'timeout', 'blamed' => 0, 'detail' => 'x']));
        $this->assertNull($m->failed());
        try {
            $m->recv(1, 'r1', 0);
            $this->fail('the claim must be raised');
        } catch (MpcNetAbort $e) {
            $this->assertSame('peer-abort', $e->kind);
            $this->assertSame($e, $m->failed());
        }
    }

    /** A closed link is a disconnect (not a timeout, even with no time left), and poisons the mesh; later sends raise it too. */
    public function testDisconnect(): void
    {
        $m = $this->mesh(0);
        self::feed($m, 1, self::hello(1));
        self::link($m, 1)->closed = true;
        $e = $this->aborts("[disconnect] blamed=1 reporter=0: link to 1 closed while awaiting 'r1'", static fn() => $m->recv(1, 'r1', 0));
        $this->assertSame($e, $m->failed());
        try {
            $m->send(1, 'r1', ['x' => 1]);
            $this->fail('a failed mesh sends nothing');
        } catch (MpcNetAbort $s) {
            $this->assertSame($e, $s);
        }
    }

    /** broadcast to an explicit list sends to those peers only. */
    public function testBroadcastToAList(): void
    {
        $m = $this->mesh(0, 3);
        $m->broadcast('r1', ['x' => 1], [2]);
        $this->assertSame([0, 1], array_column($m->stats(), 'framesOut'));
    }

    /** A dialed peer whose certificate passes TLS but is not the pinned one is an identity failure of that peer. */
    public function testDialedPeerMustPresentThePinnedCertificate(): void
    {
        $c = self::ids(2);
        $imposter = MpcNetCerts::generate('imposter');
        $view1 = $c['nodes'];
        $view1[0]['certPem'] = $imposter['certPem'];
        $clock = new RefManualClock();
        $m0 = $this->mesh(0, 2, ['clock' => $clock]);
        $m1 = $this->meshes[] = new MpcNetMesh(RefMpcNetSupport::cfg(1, $view1, $c['ids'][1], 600000, 600000, ['clock' => $clock]));
        RefMpcNetSupport::wire([$m0, $m1]);
        $rounds = 0;
        $res = RefMpcNetSupport::run([0 => static fn() => $m0->connect(), 1 => static fn() => $m1->connect()], static function () use ($m1, $clock, &$rounds): void {
            $d = self::priv($m1, 'dialers');
            // the dial has been judged (or a bounded number of rounds passed): let everyone else time out, so a failed handshake fails here, never hangs
            if (($d[0]['state'] ?? 'done') === 'done' || ++$rounds > self::ROUNDS) {
                $clock->advance(1_000_000);
            }
        });
        $this->assertSame('[identity] blamed=0 reporter=1: dial: peer certificate is not the pinned identity of node 0', RefMpcNetSupport::abortOf($res[1])->getMessage());
    }

    /**
     * Runs $client against $server's listener until the server has judged $accepts connections (none left in the handshake).
     * @param \Closure(int, \Closure():bool):void $client gets the port and a "judged" probe
     */
    private static function judge(MpcNetMesh $server, int $accepts, \Closure $client): void
    {
        $port = $server->listen();
        $judged = static fn(): bool => self::priv($server, 'pendingSeq') >= $accepts && self::priv($server, 'pending') === [];
        $tasks = [0 => static function () use ($judged): void {
            for ($i = 0; $i < self::ROUNDS && !$judged(); $i++) {
                MpcNetLoop::idle();
            }
        }, 1 => static fn() => $client($port, $judged)];
        $res = RefMpcNetSupport::run($tasks);
        self::assertTrue($res[0]['ok'] && $res[1]['ok']);
    }

    /** A TLS client holding $identity (null: no certificate) that stays connected until the server has judged it. */
    private static function tlsClient(?array $identity): \Closure
    {
        return static function (int $port, \Closure $judged) use ($identity): void {
            $ssl = ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true];
            $dir = MpcNetCerts::tempDir();
            if ($identity !== null) {
                file_put_contents($dir . '/c.pem', $identity['certPem']);
                file_put_contents($dir . '/k.pem', $identity['keyPem']);
                $ssl += ['local_cert' => $dir . '/c.pem', 'local_pk' => $dir . '/k.pem'];
            }
            try {
                $s = stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, stream_context_create(['ssl' => $ssl]));
                stream_set_blocking($s, false);
                for ($i = 0; $i < self::ROUNDS && @stream_socket_enable_crypto($s, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT) === 0; $i++) {
                    MpcNetLoop::idle();
                }
                for ($i = 0; $i < self::ROUNDS && !$judged(); $i++) {
                    MpcNetLoop::idle();
                }
                @fclose($s);
            } finally {
                MpcNetCerts::rmTree($dir);
            }
        };
    }

    public function testRejectedIncomingNotes(): void
    {
        $c = self::ids(2);
        $m1 = $this->mesh(1);
        self::judge($m1, 1, self::tlsClient(null));
        $this->assertSame(['rejected incoming connection (no pinned client certificate)'], $m1->events);
        $m1b = $this->mesh(1);
        self::judge($m1b, 1, self::tlsClient($c['ids'][0])); // node 0 dials no one: a lower id never connects in
        $this->assertSame(['rejected incoming connection (node 0)'], $m1b->events);
    }

    public function testRefusedHandshakeNote(): void
    {
        $m = $this->mesh(0);
        self::judge($m, 1, static function (int $port, \Closure $judged): void {
            $s = stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 5);
            fwrite($s, "GET / HTTP/1.0\r\n\r\n");
            for ($i = 0; $i < self::ROUNDS && !$judged(); $i++) {
                MpcNetLoop::idle();
            }
            fclose($s);
        });
        $this->assertSame(['tlsClientError: handshake refused'], $m->events);
    }

    /** A second connection from a node that already has a link is noted and dropped. */
    public function testDuplicateConnectionNote(): void
    {
        $c = self::ids(2);
        $m0 = $this->mesh(0);
        $m1 = $this->mesh(1);
        RefMpcNetSupport::wire([$m0, $m1]);
        $res = RefMpcNetSupport::run([0 => static fn() => $m0->connect(), 1 => static fn() => $m1->connect()], null, 30000);
        $this->assertTrue($res[0]['ok'] && $res[1]['ok']);
        self::judge($m0, 2, self::tlsClient($c['ids'][1]));
        $this->assertSame(['duplicate connection from node 1'], $m0->events);
    }
}
