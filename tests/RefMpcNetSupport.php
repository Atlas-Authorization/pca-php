<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ed25519Core;
use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetCerts;
use Atlas\Pca\MpcNetClock;
use Atlas\Pca\MpcNetLaunch;
use Atlas\Pca\MpcNetLoop;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcShake256;

/** A virtual clock: time moves only when the test says so. */
final class RefManualClock implements MpcNetClock
{
    private int $t = 0;

    public function now(): int
    {
        return $this->t;
    }

    public function advance(int $ms): void
    {
        $this->t += $ms;
    }
}

/** Cluster construction and result helpers shared by the networked MPC tests (identities are generated per run, never stored). */
final class RefMpcNetSupport
{
    /** Skip reason when the platform cannot run the mesh, else null. */
    public static function meshUnavailable(): ?string
    {
        if (!extension_loaded('openssl') || !extension_loaded('gmp') || !defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER')) {
            return 'needs ext-openssl, ext-gmp and TLS 1.3 streams';
        }
        try {
            MpcNetCerts::generate('probe');
        } catch (\Throwable $e) {
            return 'needs the openssl command line: ' . $e->getMessage();
        }
        return null;
    }

    /** Skip reason when the no-dealer OT stack is missing, else null. */
    public static function otUnavailable(): ?string
    {
        if (!Ed25519Core::available() || !MpcShake256::available()) {
            return 'needs ext-sodium with the Ed25519 core functions (libsodium >= 1.0.18) and ext-ffi + libcrypto (SHAKE256)';
        }
        return null;
    }

    /** A test that runs long on purpose: lift the per-test alarm (the bootstrap re-arms it per test). */
    public static function longTest(int $seconds): void
    {
        if (function_exists('pcntl_alarm')) {
            pcntl_alarm($seconds);
        }
    }

    /** @return array{ids:list<array{keyPem:string,certPem:string}>,nodes:list<array{id:int,host:string,port:int,certPem:string}>} */
    public static function identities(int $count): array
    {
        $ports = MpcNetLaunch::reservePorts($count);
        $ids = [];
        $nodes = [];
        for ($i = 0; $i < $count; $i++) {
            $ids[$i] = MpcNetCerts::generate('node' . $i);
            $nodes[$i] = ['id' => $i, 'host' => '127.0.0.1', 'port' => $ports[$i], 'certPem' => $ids[$i]['certPem']];
        }
        return ['ids' => $ids, 'nodes' => $nodes];
    }

    /** @param array<string,mixed> $extra @return array<string,mixed> */
    public static function cfg(int $self, array $nodes, array $id, int $connectMs, int $recvMs, array $extra = []): array
    {
        return $extra + ['selfId' => $self, 'nodes' => $nodes, 'keyPem' => $id['keyPem'], 'certPem' => $id['certPem'], 'sessionId' => 'mesh-test-session',
            'listenHost' => '127.0.0.1', 'connectTimeoutMs' => $connectMs, 'recvTimeoutMs' => $recvMs];
    }

    /** @param list<MpcNetMesh> $meshes */
    public static function closeAll(array $meshes): void
    {
        foreach ($meshes as $m) {
            $m->close();
        }
    }

    /** The MpcNetAbort a task failed with (or the failure of its mesh); fails the test when there is none. @param array{ok:bool,error?:\Throwable} $res */
    public static function abortOf(array $res): MpcNetAbort
    {
        if ($res['ok'] || !($res['error'] ?? null) instanceof MpcNetAbort) {
            throw new \PHPUnit\Framework\AssertionFailedError('expected a MpcNetAbort, got ' . ($res['ok'] ? 'success' : get_debug_type($res['error'] ?? null) . ': ' . ($res['error'] ?? null)?->getMessage()));
        }
        return $res['error'];
    }

    public static function run(array $tasks, ?callable $onIdle = null, int $capMs = 120000): array
    {
        return MpcNetLoop::run($tasks, $onIdle, $capMs);
    }
}
