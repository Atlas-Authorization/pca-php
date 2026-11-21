<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetFaults;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetLoop;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * The mutual-TLS mesh over loopback: an honest 3-node exchange, and the refusals (wrong pin, wrong hello id, oversize frame, early
 * close, replay, wrong round, flood, timeout under a virtual clock). Identities are generated per run; every node is a Fiber in one
 * process, so the sockets and the TLS handshakes are real.
 */
final class RefMpcNetMeshTest extends TestCase
{
    protected function setUp(): void
    {
        $why = RefMpcNetSupport::meshUnavailable();
        if ($why !== null) {
            $this->markTestSkipped($why);
        }
    }

    public function testHonestThreeNodeExchange(): void
    {
        $c = RefMpcNetSupport::identities(3);
        $meshes = [];
        $tasks = [];
        foreach ([0, 1, 2] as $i) {
            $meshes[$i] = new MpcNetMesh(RefMpcNetSupport::cfg($i, $c['nodes'], $c['ids'][$i], 20000, 10000));
            $tasks[$i] = static function () use ($meshes, $i): array {
                $m = $meshes[$i];
                $m->connect();
                $m->broadcast('r1', ['x' => $i]);
                $got = $m->collect('r1');
                return $got;
            };
        }
        $res = RefMpcNetSupport::run($tasks);
        foreach ([0, 1, 2] as $i) {
            $this->assertTrue($res[$i]['ok'], 'node ' . $i . ': ' . ($res[$i]['error'] ?? null)?->getMessage());
            $this->assertCount(2, $res[$i]['value']);
            foreach ($res[$i]['value'] as $from => $payload) {
                $this->assertNotSame($i, $from);
                $this->assertInstanceOf(Obj::class, $payload);
                $this->assertSame((float) $from, $payload->get('x')->float());
            }
        }
        // signatures verify against the pinned certificate only
        $sig = $meshes[0]->sign('statement');
        $this->assertTrue($meshes[1]->verify(0, 'statement', $sig));
        $this->assertFalse($meshes[1]->verify(2, 'statement', $sig));
        $this->assertFalse($meshes[1]->verify(0, 'other', $sig));
        $this->assertFalse($meshes[0]->verify(0, 'statement', $sig));
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testPinnedCertMismatchRefusesTheLink(): void
    {
        $c = RefMpcNetSupport::identities(2);
        $imposter = \Atlas\Pca\MpcNetCerts::generate('imposter');
        // node 1 pins an imposter certificate for node 0, so the real node 0 must be refused
        $view1 = $c['nodes'];
        $view1[0]['certPem'] = $imposter['certPem'];
        $m0 = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 2500, 2000));
        $m1 = new MpcNetMesh(RefMpcNetSupport::cfg(1, $view1, $c['ids'][1], 2500, 2000));
        $res = RefMpcNetSupport::run([0 => static fn() => $m0->connect(), 1 => static fn() => $m1->connect()]);
        $this->assertContains(RefMpcNetSupport::abortOf($res[1])->kind, ['timeout', 'identity']);
        $this->assertFalse($res[0]['ok']);
        RefMpcNetSupport::closeAll([$m0, $m1]);
    }

    /** A bare TLS 1.3 client (non-blocking, cooperative with the mesh loop): $identity = null presents NO certificate. */
    private static function bareClient(int $port, ?array $identity): void
    {
        $ssl = ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true];
        $dir = null;
        if ($identity !== null) {
            $dir = \Atlas\Pca\MpcNetCerts::tempDir();
            file_put_contents($dir . '/c.pem', $identity['certPem']);
            file_put_contents($dir . '/k.pem', $identity['keyPem']);
            $ssl += ['local_cert' => $dir . '/c.pem', 'local_pk' => $dir . '/k.pem'];
        }
        $s = false;
        for ($i = 0; $i < 200 && $s === false; $i++) {
            $s = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 1, STREAM_CLIENT_CONNECT, stream_context_create(['ssl' => $ssl]));
            if ($s === false) {
                MpcNetLoop::idle();
            }
        }
        if ($s === false) {
            return;
        }
        stream_set_blocking($s, false);
        for ($i = 0; $i < 400; $i++) {
            if (@stream_socket_enable_crypto($s, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT) !== 0) {
                break;
            }
            MpcNetLoop::idle();
        }
        for ($i = 0; $i < 100; $i++) {
            MpcNetLoop::idle(); // give the server time to judge the client
        }
        @fclose($s);
        if ($dir !== null) {
            @unlink($dir . '/c.pem');
            @unlink($dir . '/k.pem');
            @rmdir($dir);
        }
    }

    /** @return array<string,array{0:bool}> whether the bare client carries a certificate at all */
    public static function strangers(): array
    {
        return ['no client certificate' => [false], 'an unpinned self-signed certificate' => [true]];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('strangers')]
    public function testAClientWithoutAPinnedCertificateNeverGetsALink(bool $presentsACert): void
    {
        $c = RefMpcNetSupport::identities(2);
        $m0 = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 6000, 3000));
        $stranger = $presentsACert ? \Atlas\Pca\MpcNetCerts::generate('stranger') : null;
        $res = RefMpcNetSupport::run([0 => static fn() => $m0->connect(), 1 => fn() => self::bareClient($c['nodes'][0]['port'], $stranger)]);
        $this->assertSame('timeout', RefMpcNetSupport::abortOf($res[0])->kind, 'node 1 never authenticated');
        $this->assertSame([], array_values(array_filter($m0->peers(), fn(int $p): bool => $m0->linkAuthenticated($p))));
        RefMpcNetSupport::closeAll([$m0]);
    }

    public function testTamperHookNeedsExplicitOptInAndOwnCertMustMatch(): void
    {
        $c = RefMpcNetSupport::identities(2);
        $cfg = RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 1000, 1000, ['tamper' => static fn(array $ev): array => [$ev['raw']]]);
        try {
            new MpcNetMesh($cfg);
            $this->fail('the tamper hook must be refused without unsafeTestHooks');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        $this->expectException(\InvalidArgumentException::class);
        new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][1], 1000, 1000));
    }

    public function testHelloWithAnotherIdIsRefused(): void
    {
        $c = RefMpcNetSupport::identities(2);
        $m0 = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 5000, 3000));
        $liar = new class (RefMpcNetSupport::cfg(1, $c['nodes'], $c['ids'][1], 5000, 3000)) extends MpcNetMesh {
            protected function helloId(): int
            {
                return 5; // claims an identity the pinned certificate does not carry
            }
        };
        $res = RefMpcNetSupport::run([0 => static fn() => $m0->connect(), 1 => static fn() => $liar->connect()]);
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame('identity', $a->kind);
        $this->assertSame(1, $a->blamed);
        RefMpcNetSupport::closeAll([$m0, $liar]);
    }

    /** @return array<string,array{0:string,1:string}> fault kind => the abort kind the receiver must raise */
    public static function frameFaults(): array
    {
        return ['oversize frame' => ['oversize', 'oversize'], 'replayed frame' => ['duplicate', 'duplicate'], 'skipped sequence' => ['skip-seq', 'out-of-order'],
            'wrong round' => ['wrong-round', 'wrong-round'], 'wrong session' => ['wrong-session', 'wrong-session'], 'garbage frame' => ['garbage', 'malformed'],
            'extra field' => ['extra-field', 'malformed']];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('frameFaults')]
    public function testMaliciousSenderFramesAreRefused(string $fault, string $expected): void
    {
        $c = RefMpcNetSupport::identities(2);
        $m0 = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 10000, 4000));
        $m1 = new MpcNetMesh(RefMpcNetSupport::cfg(1, $c['nodes'], $c['ids'][1], 10000, 4000,
            ['tamper' => MpcNetFaults::tamperFor(['kind' => $fault, 'round' => 'r1']), 'unsafeTestHooks' => true]));
        $res = RefMpcNetSupport::run([
            0 => static function () use ($m0): mixed {
                $m0->connect();
                return $m0->recv(1, 'r1');
            },
            1 => static function () use ($m1): void {
                $m1->connect();
                $m1->send(0, 'r1', ['x' => 1]);
                for ($i = 0; $i < 40; $i++) {
                    MpcNetLoop::idle();
                }
            },
        ]);
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame($expected, $a->kind);
        $this->assertSame(1, $a->blamed);
        RefMpcNetSupport::closeAll([$m0, $m1]);
    }

    public function testEarlyCloseIsADisconnect(): void
    {
        $c = RefMpcNetSupport::identities(2);
        $m0 = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 10000, 6000));
        $m1 = new MpcNetMesh(RefMpcNetSupport::cfg(1, $c['nodes'], $c['ids'][1], 10000, 6000));
        $res = RefMpcNetSupport::run([
            0 => static function () use ($m0): mixed {
                $m0->connect();
                return $m0->recv(1, 'r1');
            },
            1 => static function () use ($m1): void {
                $m1->connect();
                $m1->close();
            },
        ]);
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame('disconnect', $a->kind);
        $this->assertSame(1, $a->blamed);
        RefMpcNetSupport::closeAll([$m0, $m1]);
    }

    public function testInboxFloodIsBlamedOnTheSender(): void
    {
        $c = RefMpcNetSupport::identities(2);
        $m0 = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 10000, 5000, ['maxInboxFrames' => 2]));
        $m1 = new MpcNetMesh(RefMpcNetSupport::cfg(1, $c['nodes'], $c['ids'][1], 10000, 5000));
        $res = RefMpcNetSupport::run([
            0 => static function () use ($m0): mixed {
                $m0->connect();
                for ($i = 0; $i < 30; $i++) {
                    MpcNetLoop::idle(); // reads nothing: the inbox fills up
                }
                return $m0->recv(1, 'r');
            },
            1 => static function () use ($m1): void {
                $m1->connect();
                for ($i = 0; $i < 6; $i++) {
                    $m1->send(0, 'r', ['i' => $i]);
                }
                for ($i = 0; $i < 40; $i++) {
                    MpcNetLoop::idle();
                }
            },
        ]);
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame('flood', $a->kind);
        $this->assertSame(1, $a->blamed);
        RefMpcNetSupport::closeAll([$m0, $m1]);
    }

    public function testASilentPeerTimesOutOnTheInjectedClock(): void
    {
        $c = RefMpcNetSupport::identities(2);
        $clock = new RefManualClock();
        $m0 = new MpcNetMesh(RefMpcNetSupport::cfg(0, $c['nodes'], $c['ids'][0], 600000, 600000, ['clock' => $clock]));
        $m1 = new MpcNetMesh(RefMpcNetSupport::cfg(1, $c['nodes'], $c['ids'][1], 600000, 600000, ['clock' => $clock]));
        $done = false;
        $res = RefMpcNetSupport::run([
            0 => static function () use ($m0, &$done): mixed {
                try {
                    $m0->connect();
                    return $m0->recv(1, 'never', 5000);
                } finally {
                    $done = true;
                }
            },
            1 => static function () use ($m1, &$done): void {
                $m1->connect();
                while (!$done) {
                    MpcNetLoop::idle();
                }
            },
        ], static function () use ($clock): void {
            $clock->advance(250); // virtual time moves one step per scheduling round, whatever the machine load
        });
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame('timeout', $a->kind);
        $this->assertSame(1, $a->blamed);
        $this->assertSame(5000, $a->deadlineMs);
        RefMpcNetSupport::closeAll([$m0, $m1]);
    }

    public function testConnectTimeoutNamesTheMissingPeer(): void
    {
        $c = RefMpcNetSupport::identities(2);
        $clock = new RefManualClock();
        $m1 = new MpcNetMesh(RefMpcNetSupport::cfg(1, $c['nodes'], $c['ids'][1], 3000, 3000, ['clock' => $clock]));
        $res = RefMpcNetSupport::run([0 => static fn() => $m1->connect()], static function () use ($clock): void {
            $clock->advance(500);
        });
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame('timeout', $a->kind);
        $this->assertSame(0, $a->blamed);
        RefMpcNetSupport::closeAll([$m1]);
    }
}
