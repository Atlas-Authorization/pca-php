<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetLaunch;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcNetLaunch::launchLocal: the trusted-dealer opt-in, the test-hook flag a node gets, and that the launcher stops
 * nodes with SIGKILL both when a node dies before binding and at the kill deadline. The nodes are a tiny stand-in party program (written
 * to a temp file) that reports a port at once; it turns SIGUSR1 / SIGFPE into a distinct exit code (when pcntl is loaded) and, left
 * alone, exits 7 after 5 s, so a node the launcher failed to kill is told apart by its exit code, never by waiting on the test side.
 */
final class MpcSurvivorKill34MpcNetLaunchTest extends TestCase
{
    private const NODE = <<<'PHP'
        <?php
        $cfg = json_decode((string) file_get_contents($argv[1]), true);
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            pcntl_signal(SIGUSR1, static function (): void { exit(110); });
            pcntl_signal(SIGFPE, static function (): void { exit(108); });
        }
        $mode = $cfg['fake'] ?? 'linger';
        if ($mode === 'die') {
            // exit only once the other node has reported its port, so the launcher sees one bound node and one dead one
            $peer = dirname($argv[1]) . '/out1.txt';
            for ($i = 0; $i < 1000 && !str_contains((string) @file_get_contents($peer), 'listening'); $i++) {
                usleep(5000);
            }
            exit(3);
        }
        $hooks = $cfg['unsafeTestHooks'] ?? null;
        $env = getenv('PCA_MPC_UNSAFE_TEST_HOOKS');
        echo json_encode(['listening' => 40000 + $cfg['id'], 'id' => $cfg['id'], 'hooks' => $hooks, 'env' => $env]), "\n";
        if ($mode === 'linger') {
            $line = fgets(STDIN);
            echo json_encode(['ports' => json_decode((string) $line, true), 'hooks' => $hooks, 'env' => $env]), "\n";
        }
        usleep(5000000);
        exit(7);
        PHP;

    private string $main = '';

    protected function setUp(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('POSIX signals (proc_terminate with SIGKILL) only');
        }
        $this->main = sys_get_temp_dir() . '/pca-k34-node-' . bin2hex(random_bytes(6)) . '.php';
        file_put_contents($this->main, self::NODE);
    }

    protected function tearDown(): void
    {
        if ($this->main !== '') {
            @unlink($this->main);
        }
    }

    /** A trusted dealer is refused unless insecureTrustedDealer is exactly true. */
    public function testTrustedDealerNeedsTheExplicitOptIn(): void
    {
        foreach ([[], ['insecureTrustedDealer' => false], ['insecureTrustedDealer' => 'yes']] as $extra) {
            try {
                MpcNetLaunch::launchLocal(['n' => 2, 'vectors' => [[], []], 'offline' => 'trusted-dealer'] + $extra);
                $this->fail('a trusted dealer must need the opt-in');
            } catch (\InvalidArgumentException $e) {
                $this->assertSame("launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer: true", $e->getMessage());
            }
        }
    }

    /**
     * A node that dies before every node is bound makes the launcher SIGKILL the rest at once (exit code -1, not the stand-in's 7 or
     * signal codes); a node given a behaviour override runs with unsafeTestHooks and the env opt-in.
     */
    public function testNodesAreKilledWhenOneDiesBeforeBinding(): void
    {
        $r = MpcNetLaunch::launchLocal(['n' => 2, 'vectors' => [[], []], 'partyMain' => $this->main, 'killAfterMs' => 60000,
            'overrides' => [0 => ['fake' => 'die'], 1 => ['fake' => 'hold', 'behavior' => 'mpc34']]]);
        $this->assertSame([], $r['ports']);
        $held = $r['outputs'][1];
        $this->assertSame(1, $held['id']);
        $this->assertSame(-1, $held['exitCode'], 'the bound node is killed with SIGKILL: ' . $held['stderr']);
        $this->assertSame(['listening' => 40001, 'id' => 1, 'hooks' => true, 'env' => '1'], $held['json']);
    }

    /** At the kill deadline every node still running is SIGKILLed; a node without hook overrides gets neither the flag nor the env. */
    public function testNodesPastTheKillDeadlineAreKilled(): void
    {
        $r = MpcNetLaunch::launchLocal(['n' => 2, 'vectors' => [[], []], 'partyMain' => $this->main, 'killAfterMs' => 1]);
        $this->assertSame([40000, 40001], $r['ports']);
        foreach ($r['outputs'] as $o) {
            $this->assertSame(-1, $o['exitCode'], 'node ' . $o['id'] . ' is killed with SIGKILL: ' . $o['stderr']);
        }
        // the node may be killed before or after it echoes the port map: both of its lines carry the hook flag and the env opt-in
        $this->assertNull($r['outputs'][0]['json']['hooks']);
        $this->assertFalse($r['outputs'][0]['json']['env']);
    }
}
