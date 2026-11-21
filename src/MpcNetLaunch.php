<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Multi-process launcher: spawns the dealer and each party as its own OS process (bin/pca-mpc-party) on localhost, generates a fresh
 * per-run identity for each, optionally routes one link through a MpcNetFaultProxy, and collects each node's one-line JSON verdict.
 * Used by the tests and demos; a real multi-host run uses the same party program with a config per host.
 *
 * A node output is ['id' => int, 'role' => 'party'|'dealer', 'exitCode' => ?int, 'json' => ?array, 'stderr' => string].
 */
final class MpcNetLaunch
{
    private static function scale(): float
    {
        $v = (float) (getenv('PCA_MPC_TEST_TIMEOUT_SCALE') ?: 1);
        return is_finite($v) && $v > 0 ? $v : 1.0;
    }

    /** Scale a duration (ms) by the one timeout knob PCA_MPC_TEST_TIMEOUT_SCALE (default 1; raise it on a slow machine). */
    public static function t(int $ms): int
    {
        return (int) ceil($ms * self::scale());
    }

    /** `count` DISTINCT free ephemeral ports, all held open at the same time (so they cannot collide) and released together. @return list<int> */
    public static function reservePorts(int $count): array
    {
        $servers = [];
        $ports = [];
        for ($i = 0; $i < $count; $i++) {
            $s = @stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
            if ($s === false) {
                throw new \RuntimeException("cannot reserve a port: $errstr");
            }
            $servers[] = $s;
            $ports[] = (int) substr((string) strrchr((string) stream_socket_get_name($s, false), ':'), 1);
        }
        foreach ($servers as $s) {
            fclose($s);
        }
        return $ports;
    }

    /**
     * Options: n, vectors (list of ['allow','t','rQuant']); optional Q, partyMain (path of the party program), recvTimeoutMs,
     * killAfterMs, overrides (id => config keys merged over the node config), wireFault (['dialer','target','fault' => wire fault]),
     * dealerSeed, offline ('no-dealer' default | 'trusted-dealer'), insecureTrustedDealer.
     *
     * @param array<string,mixed> $o
     * @return array{outputs:list<array<string,mixed>>,wallMs:int,proxyLog:list<string>}
     */
    public static function launchLocal(array $o): array
    {
        $n = $o['n'];
        $mode = $o['offline'] ?? 'no-dealer';
        if ($mode === 'trusted-dealer' && ($o['insecureTrustedDealer'] ?? false) !== true) {
            throw new \InvalidArgumentException("launchLocal: offline 'trusted-dealer' requires insecureTrustedDealer: true");
        }
        $noDealer = $mode === 'no-dealer';
        $nodeCount = $noDealer ? $n : $n + 1;
        $dir = MpcNetCerts::tempDir();
        $proxy = null;
        $procs = [];
        try {
            $sessionId = bin2hex(random_bytes(8));
            $ports = self::reservePorts($nodeCount + 1); // the last one is for the optional fault proxy
            $ids = [];
            for ($i = 0; $i < $nodeCount; $i++) {
                $ids[] = MpcNetCerts::generateFiles($dir . "/node$i", "mpc-node-$i");
            }
            $proxyPort = 0;
            if (isset($o['wireFault'])) {
                $wf = $o['wireFault'];
                $proxyPort = $ports[$nodeCount];
                $fault = $wf['fault'];
                if (isset($fault['ms'])) {
                    $fault['ms'] = self::t($fault['ms']);
                }
                $proxy = new MpcNetFaultProxy($proxyPort, ['host' => '127.0.0.1', 'port' => $ports[$wf['target']]], $fault);
                $proxy->listen();
            }
            $main = $o['partyMain'] ?? dirname(__DIR__) . '/bin/pca-mpc-party';
            $t0 = (int) floor(microtime(true) * 1000);
            for ($id = 0; $id < $nodeCount; $id++) {
                $nodes = [];
                foreach ($ids as $j => $x) {
                    $nodes[] = ['id' => $j, 'host' => '127.0.0.1', 'port' => isset($o['wireFault']) && $id === $o['wireFault']['dialer'] && $j === $o['wireFault']['target'] ? $proxyPort : $ports[$j], 'certPath' => $x['certPath']];
                }
                $isDealer = !$noDealer && $id === $n;
                $cfg = ['role' => $isDealer ? 'dealer' : 'party', 'id' => $id, 'n' => $n, 'offline' => $mode, 'sessionId' => $sessionId, 'listenHost' => '127.0.0.1',
                    'nodes' => $nodes, 'keyPath' => $ids[$id]['keyPath'], 'certPath' => $ids[$id]['certPath'],
                    'recvTimeoutMs' => self::t($o['recvTimeoutMs'] ?? 30000), 'connectTimeoutMs' => self::t(120000)];
                if (isset($o['Q'])) {
                    $cfg['Q'] = $o['Q'];
                }
                if (isset($o['insecureTrustedDealer'])) {
                    $cfg['insecureTrustedDealer'] = $o['insecureTrustedDealer'];
                }
                if ($id < $n) {
                    $cfg['input'] = $o['vectors'][$id];
                }
                if ($isDealer && isset($o['dealerSeed'])) {
                    $cfg['dealerSeed'] = $o['dealerSeed'];
                }
                $cfg = ($o['overrides'][$id] ?? []) + $cfg;
                $hooks = isset($cfg['behavior']) || isset($cfg['frameFault']) || isset($cfg['dealerFault']);
                if ($hooks) {
                    $cfg['unsafeTestHooks'] = true;
                }
                $cfgPath = $dir . "/cfg$id.json";
                PrivateFile::write($cfgPath, json_encode($cfg));
                $env = getenv();
                unset($env['PCA_MPC_UNSAFE_TEST_HOOKS']);
                if ($hooks) {
                    $env['PCA_MPC_UNSAFE_TEST_HOOKS'] = '1';
                }
                $p = proc_open([PHP_BINARY, '-d', 'memory_limit=2048M', $main, $cfgPath], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $env);
                if (!is_resource($p)) {
                    throw new \RuntimeException('launchLocal: cannot start a node');
                }
                stream_set_blocking($pipes[1], false);
                stream_set_blocking($pipes[2], false);
                $procs[$id] = ['p' => $p, 'out' => '', 'err' => '', 'pipes' => $pipes, 'code' => null, 'role' => $isDealer ? 'dealer' : 'party'];
            }
            $killAt = MpcNetLoop::mono() + self::t($o['killAfterMs'] ?? 120000);
            while (true) {
                $live = 0;
                foreach ($procs as &$pr) {
                    $pr['out'] .= (string) stream_get_contents($pr['pipes'][1]);
                    $pr['err'] .= (string) stream_get_contents($pr['pipes'][2]);
                    $st = proc_get_status($pr['p']);
                    if ($st['running']) {
                        $live++;
                        if (MpcNetLoop::mono() > $killAt) {
                            proc_terminate($pr['p'], 9);
                        }
                    } elseif ($pr['code'] === null) {
                        $pr['code'] = $st['exitcode'];
                        $pr['out'] .= (string) stream_get_contents($pr['pipes'][1]);
                        $pr['err'] .= (string) stream_get_contents($pr['pipes'][2]);
                    }
                }
                unset($pr);
                if ($live === 0) {
                    break;
                }
                MpcNetLoop::step(10);
            }
            $outputs = [];
            foreach ($procs as $id => $pr) {
                $lines = array_values(array_filter(explode("\n", trim($pr['out'])), static fn(string $l): bool => $l !== ''));
                $json = $lines === [] ? null : json_decode((string) end($lines), true);
                $outputs[] = ['id' => $id, 'role' => $pr['role'], 'exitCode' => $pr['code'], 'json' => is_array($json) ? $json : null, 'stderr' => substr($pr['err'], 0, 2000)];
            }
            return ['outputs' => $outputs, 'wallMs' => (int) floor(microtime(true) * 1000) - $t0, 'proxyLog' => $proxy?->log ?? []];
        } finally {
            foreach ($procs as $pr) {
                foreach ($pr['pipes'] as $pp) {
                    if (is_resource($pp)) {
                        fclose($pp);
                    }
                }
                proc_close($pr['p']);
            }
            $proxy?->close();
            MpcNetCerts::rmTree($dir);
        }
    }
}
