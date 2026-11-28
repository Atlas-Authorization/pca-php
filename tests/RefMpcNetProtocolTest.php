<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcCompose;
use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetLaunch;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetProtocol;
use PHPUnit\Framework\TestCase;

/**
 * The networked SPDZ-style protocol over loopback mutual TLS (one Fiber per node, real sockets): both offline modes against the
 * deterministic engine's clear composition, the refusals of a lying dealer and lying parties, and the multi-process launcher.
 */
final class RefMpcNetProtocolTest extends TestCase
{
    private const Q = 3;

    /** @var list<array{allow:int,t:int,rQuant:int}> */
    private const INPUTS = [['allow' => 1, 't' => 1, 'rQuant' => 1], ['allow' => 1, 't' => 2, 'rQuant' => 3], ['allow' => 1, 't' => 1, 'rQuant' => 2]];

    protected function setUp(): void
    {
        $why = RefMpcNetSupport::meshUnavailable();
        if ($why !== null) {
            $this->markTestSkipped($why);
        }
    }

    /** @return list<MpcNetMesh> n party nodes (ids 0..n-1) and, with $dealer, one dealer node (id n) that links only to the parties */
    private static function cluster(int $n, bool $dealer, int $recvMs): array
    {
        $total = $dealer ? $n + 1 : $n;
        $c = RefMpcNetSupport::identities($total);
        $meshes = [];
        for ($i = 0; $i < $total; $i++) {
            $extra = $dealer && $i === $n ? ['linkTo' => range(0, $n - 1)] : [];
            $meshes[$i] = new MpcNetMesh(RefMpcNetSupport::cfg($i, $c['nodes'], $c['ids'][$i], 60000, $recvMs, $extra));
        }
        RefMpcNetSupport::wire($meshes);
        return $meshes;
    }

    /**
     * Run every party (and the dealer when $dealerCfg is given) to the end.
     *
     * @param list<MpcNetMesh> $meshes @param list<array> $inputs @param ?array $dealerCfg @param array<int,array> $behaviors
     * @return array<int,array{ok:bool,value?:mixed,error?:\Throwable}>
     */
    private static function runAll(array $meshes, array $inputs, string $offline, ?array $dealerCfg = null, array $behaviors = [], ?int $slow = null): array
    {
        $n = count($inputs);
        $tasks = [];
        foreach ($inputs as $i => $v) {
            $tasks[$i] = static function () use ($meshes, $i, $n, $v, $offline, $behaviors): array {
                $m = $meshes[$i];
                $m->connect();
                $cfg = ['id' => $i, 'n' => $n, 'Q' => self::Q, 'input' => $v, 'mesh' => $m, 'sessionId' => $m->sessionId(), 'offline' => $offline, 'insecureTrustedDealer' => $offline === 'trusted-dealer'];
                if (isset($behaviors[$i])) {
                    $cfg['behavior'] = $behaviors[$i];
                    $cfg['unsafeTestHooks'] = true;
                }
                return MpcNetProtocol::runParty($cfg);
            };
        }
        if ($dealerCfg !== null) {
            $tasks[$n] = static function () use ($meshes, $n, $dealerCfg): bool {
                $meshes[$n]->connect();
                MpcNetProtocol::runDealer($dealerCfg + ['n' => $n, 'Q' => self::Q, 'mesh' => $meshes[$n], 'insecureTrustedDealer' => true]);
                return true;
            };
        }
        if ($slow !== null) {
            // party $slow is resumed one scheduling round in eight: its peers run ahead and their frames (an abort included) reach its socket first
            $inner = $tasks[$slow];
            $tasks[$slow] = static function () use ($inner) {
                $f = new \Fiber($inner);
                $f->start();
                while (!$f->isTerminated()) {
                    for ($i = 0; $i < 8; $i++) {
                        \Fiber::suspend();
                    }
                    $f->resume();
                }
                return $f->getReturn();
            };
        }
        return RefMpcNetSupport::run($tasks, null, 600000);
    }

    private function assertAgrees(array $res, int $n, string $mode): void
    {
        $clear = MpcCompose::composeClear(array_slice(self::INPUTS, 0, $n), self::Q);
        $digest = null;
        for ($i = 0; $i < $n; $i++) {
            $this->assertTrue($res[$i]['ok'], 'party ' . $i . ': ' . ($res[$i]['error'] ?? null)?->getMessage());
            $r = $res[$i]['value'];
            $this->assertSame($clear, $r['composed']);
            $this->assertSame($mode, $r['offlineMode']);
            $this->assertTrue($r['identifiableAbort']);
            $digest ??= $r['transcriptDigest'];
            $this->assertSame($digest, $r['transcriptDigest']);
        }
    }

    public function testDealerModeAgreesWithTheClearComposition(): void
    {
        $meshes = self::cluster(3, true, 120000);
        $res = self::runAll($meshes, self::INPUTS, 'trusted-dealer', ['seed' => gmp_init(7)]);
        $this->assertAgrees($res, 3, 'trusted-dealer');
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testDealerRefusesWithoutTheExplicitOptIn(): void
    {
        $meshes = self::cluster(2, true, 5000);
        try {
            MpcNetProtocol::runDealer(['n' => 2, 'mesh' => $meshes[2]]);
            $this->fail('a dealer needs insecureTrustedDealer');
        } catch (\InvalidArgumentException) {
            $this->addToAssertionCount(1);
        }
        try {
            MpcNetProtocol::runParty(['id' => 0, 'n' => 2, 'Q' => self::Q, 'input' => self::INPUTS[0], 'mesh' => $meshes[0], 'sessionId' => 'x', 'offline' => 'trusted-dealer']);
            $this->fail('trusted-dealer mode needs insecureTrustedDealer');
        } catch (MpcNetAbort $e) {
            $this->assertSame('local', $e->kind);
        }
        try {
            MpcNetProtocol::runParty(['id' => 0, 'n' => 2, 'Q' => self::Q, 'input' => self::INPUTS[0], 'mesh' => $meshes[0], 'sessionId' => 'x', 'behavior' => ['kind' => 'open-lie', 'round' => 'out']]);
            $this->fail('a behavior needs unsafeTestHooks');
        } catch (MpcNetAbort $e) {
            $this->assertSame('local', $e->kind);
        }
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testALyingDealerIsNamedBySacrifice(): void
    {
        $meshes = self::cluster(2, true, 60000);
        $res = self::runAll($meshes, array_slice(self::INPUTS, 0, 2), 'trusted-dealer', ['seed' => gmp_init(7), 'fault' => ['keepCDelta' => gmp_init(1), 'partnerCDelta' => null]]);
        foreach ([0, 1] as $i) {
            $a = RefMpcNetSupport::abortOf($res[$i]);
            $this->assertSame('dealer', $a->kind);
            $this->assertSame(2, $a->blamed);
        }
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testALyingOpeningIsNamedByThePairwiseTag(): void
    {
        $meshes = self::cluster(3, true, 60000);
        $res = self::runAll($meshes, self::INPUTS, 'trusted-dealer', ['seed' => gmp_init(7)], [1 => ['kind' => 'open-lie', 'round' => 'mul0']]);
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertSame('mac-check', $a->kind);
        $this->assertSame(1, $a->blamed);
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testMalformedBroadcastsAreAttributed(): void
    {
        foreach (['short-array', 'noncanonical'] as $kind) {
            $meshes = self::cluster(2, true, 60000);
            $res = self::runAll($meshes, array_slice(self::INPUTS, 0, 2), 'trusted-dealer', ['seed' => gmp_init(7)], [1 => ['kind' => $kind, 'round' => 'mul0']]);
            $a = RefMpcNetSupport::abortOf($res[0]);
            $this->assertSame('malformed', $a->kind, $kind);
            $this->assertSame(1, $a->blamed, $kind);
            RefMpcNetSupport::closeAll($meshes);
        }
    }

    /**
     * Dealer mode, three parties, $culprit misbehaves. No honest party may finish, and at least one names $culprit with a kind in $kinds
     * (an abort frame from a faster party can reach a slower one first, so that one reports a relayed abort instead).
     *
     * @param list<string> $kinds
     */
    private function assertCulpritNamed(string $kind, ?string $round, int $culprit, array $kinds, int $recvMs = 60000): void
    {
        $meshes = self::cluster(3, true, $recvMs);
        $beh = ['kind' => $kind] + ($round === null ? [] : ['round' => $round]);
        $res = self::runAll($meshes, self::INPUTS, 'trusted-dealer', ['seed' => gmp_init(7)], [$culprit => $beh]);
        $named = false;
        foreach ([0, 1, 2] as $i) {
            if ($i === $culprit) {
                continue;
            }
            $a = RefMpcNetSupport::abortOf($res[$i]);
            if (in_array($a->kind, $kinds, true) && $a->blamed === $culprit) {
                $named = true;
            }
        }
        $this->assertTrue($named, "$kind: an honest party names party $culprit");
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testABadPairwiseTagIsNamed(): void
    {
        $this->assertCulpritNamed('bad-tag', 'mul0', 1, ['mac-check']);
    }

    public function testAForgedMacShareIsCaughtByTheMacCheck(): void
    {
        $this->assertCulpritNamed('mac-lie', 'mul0', 1, ['mac-check']);
    }

    public function testALyingMacResidualIsNamedByTheBlameRound(): void
    {
        $this->assertCulpritNamed('sigma-lie', null, 2, ['mac-check']);
    }

    public function testACoinSeedThatDoesNotMatchItsCommitmentIsNamed(): void
    {
        $this->assertCulpritNamed('bad-coin-open', null, 1, ['commitment']);
    }

    public function testAMacResidualThatDoesNotMatchItsCommitmentIsNamed(): void
    {
        $this->assertCulpritNamed('bad-sigma-open', null, 1, ['commitment']);
    }

    public function testACrashedPartyIsNamedAsDisconnectedOrTimedOut(): void
    {
        $this->assertCulpritNamed('crash', 'mul1', 1, ['disconnect', 'timeout'], 5000);
    }

    public function testASilentPartyIsNamedByTheTimeout(): void
    {
        $this->assertCulpritNamed('silent', 'mul1', 1, ['timeout', 'disconnect'], 5000);
    }

    public function testEquivocationNeverYieldsAnOutput(): void
    {
        $meshes = self::cluster(3, true, 60000);
        $res = self::runAll($meshes, self::INPUTS, 'trusted-dealer', ['seed' => gmp_init(7)], [1 => ['kind' => 'equivocate', 'round' => 'mul0']]);
        foreach ([0, 1, 2] as $i) {
            $this->assertFalse($res[$i]['ok'], "party $i must not produce output");
        }
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testNoDealerModeAgreesWithTheClearComposition(): void
    {
        if (($why = RefMpcNetSupport::otUnavailable()) !== null) {
            $this->markTestSkipped($why);
        }
        RefMpcNetSupport::longTest(1800);
        $meshes = self::cluster(3, false, 900000);
        $res = self::runAll($meshes, self::INPUTS, 'no-dealer');
        $this->assertAgrees($res, 3, 'no-dealer');
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testNoDealerWrongOtOperandIsCaughtAndNamedForTwoParties(): void
    {
        if (($why = RefMpcNetSupport::otUnavailable()) !== null) {
            $this->markTestSkipped($why);
        }
        RefMpcNetSupport::longTest(1800);
        $meshes = self::cluster(2, false, 900000);
        $res = self::runAll($meshes, array_slice(self::INPUTS, 0, 2), 'no-dealer', null, [1 => ['kind' => 'offline-lie']]);
        $a = RefMpcNetSupport::abortOf($res[0]);
        $what = static fn (array $r): string => $r['ok'] ? 'ok' : (($e = $r['error'] ?? null) instanceof \Atlas\Pca\MpcNetAbort ? "{$e->kind} blamed " . var_export($e->blamed, true) . ': ' . $e->getMessage() : get_debug_type($e) . ': ' . ($e?->getMessage() ?? ''));
        $why = 'party 0: ' . $what($res[0]) . ' | party 1: ' . $what($res[1]);
        $this->assertContains($a->kind, ['mac-check', 'dealer'], $why);
        $this->assertSame(1, $a->blamed, $why);
        RefMpcNetSupport::closeAll($meshes);
    }

    /** The honest party is the slow one: the liar finishes the audit and aborts while it still collects the disclosure, and it must still name the liar. */
    public function testASlowHonestPartyIsNotPreemptedByTheLiarsAbort(): void
    {
        if (($why = RefMpcNetSupport::otUnavailable()) !== null) {
            $this->markTestSkipped($why);
        }
        RefMpcNetSupport::longTest(1800);
        $meshes = self::cluster(2, false, 900000);
        $res = self::runAll($meshes, array_slice(self::INPUTS, 0, 2), 'no-dealer', null, [1 => ['kind' => 'offline-lie']], 0);
        $a = RefMpcNetSupport::abortOf($res[0]);
        $this->assertContains($a->kind, ['mac-check', 'dealer'], $a->kind . ': ' . $a->getMessage());
        $this->assertSame(1, $a->blamed);
        RefMpcNetSupport::closeAll($meshes);
    }

    public function testLauncherRunsEveryNodeAsItsOwnProcess(): void
    {
        RefMpcNetSupport::longTest(600);
        $r = MpcNetLaunch::launchLocal(['n' => 3, 'Q' => self::Q, 'vectors' => self::INPUTS, 'offline' => 'trusted-dealer', 'insecureTrustedDealer' => true, 'dealerSeed' => '7',
            'recvTimeoutMs' => 60000, 'killAfterMs' => 300000]);
        $clear = MpcCompose::composeClear(self::INPUTS, self::Q);
        $this->assertCount(4, $r['outputs']);
        foreach ($r['outputs'] as $o) {
            $this->assertNotNull($o['json'], 'node ' . $o['id'] . ' printed no verdict: ' . $o['stderr']);
            $this->assertTrue($o['json']['ok'], 'node ' . $o['id'] . ': ' . json_encode($o['json']['error'] ?? null));
            if ($o['role'] === 'party') {
                $c = $o['json']['result']['composed'];
                $this->assertSame($clear, ['allow' => $c['allow'], 't' => $c['t'], 'rQuant' => $c['rQuant']]);
            }
        }
    }

    public function testATcpBitFlipOnTheWireNeverYieldsAWrongValue(): void
    {
        RefMpcNetSupport::longTest(600);
        $r = MpcNetLaunch::launchLocal(['n' => 2, 'Q' => self::Q, 'vectors' => array_slice(self::INPUTS, 0, 2), 'offline' => 'trusted-dealer', 'insecureTrustedDealer' => true, 'dealerSeed' => '7',
            'recvTimeoutMs' => 20000, 'killAfterMs' => 120000, 'wireFault' => ['dialer' => 1, 'target' => 0, 'fault' => ['kind' => 'bitflip', 'dir' => 'c2s', 'afterBytes' => 2500]]]);
        $clear = MpcCompose::composeClear(array_slice(self::INPUTS, 0, 2), self::Q);
        $aborted = 0;
        foreach ($r['outputs'] as $o) {
            if ($o['json'] === null || !($o['json']['ok'] ?? false)) {
                $aborted++;
            } elseif ($o['role'] === 'party') {
                $c = $o['json']['result']['composed'];
                $this->assertSame($clear, ['allow' => $c['allow'], 't' => $c['t'], 'rQuant' => $c['rQuant']], 'a corrupted link must never change the output');
            }
        }
        $this->assertGreaterThan(0, $aborted, 'the corrupted link must abort at least one node');
        $fired = array_filter($r['proxyLog'], static fn(string $l): bool => str_starts_with($l, 'fault '));
        $this->assertNotSame([], array_values($fired), 'the proxy never reached the fault point; proxy log: ' . json_encode($r['proxyLog']) . '; nodes: '
            . json_encode(array_map(static fn(array $o): array => ['id' => $o['id'], 'role' => $o['role'], 'exit' => $o['exitCode'], 'error' => $o['json']['error'] ?? null, 'stderr' => substr((string)$o['stderr'], 0, 300)], $r['outputs'])));
    }

    public function testPartyMainRefusesTestHooksWithoutTheEnvironmentOptIn(): void
    {
        $dir = \Atlas\Pca\MpcNetCerts::tempDir();
        try {
            $id = \Atlas\Pca\MpcNetCerts::generateFiles($dir . '/n0', 'n0');
            file_put_contents($dir . '/cfg.json', json_encode(['role' => 'party', 'id' => 0, 'n' => 1, 'sessionId' => 'x', 'nodes' => [['id' => 0, 'host' => '127.0.0.1', 'port' => 1, 'certPath' => $id['certPath']]],
                'keyPath' => $id['keyPath'], 'certPath' => $id['certPath'], 'behavior' => ['kind' => 'crash', 'round' => 'prep'], 'unsafeTestHooks' => true]));
            $env = getenv();
            unset($env['PCA_MPC_UNSAFE_TEST_HOOKS']);
            $p = proc_open([PHP_BINARY, dirname(__DIR__) . '/bin/pca-mpc-party', $dir . '/cfg.json'], [0 => ['file', \Atlas\Pca\PrivateFile::nullDevice(), 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
            $this->assertIsResource($p);
            $out = (string) stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            $this->assertSame(3, proc_close($p));
            $j = json_decode(trim($out), true);
            $this->assertFalse($j['ok']);
            $this->assertStringContainsString('refusing to start', $j['error']['message']);
        } finally {
            \Atlas\Pca\MpcNetCerts::rmTree($dir);
        }
    }
}
