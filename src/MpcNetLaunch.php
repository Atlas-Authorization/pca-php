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

    /**
     * The port a node reported on stdout: the first COMPLETE line that is JSON with an integer `listening` in 1..65535 and, when it has an `id`,
     * that id equal to $id. Key order is the node's own (Go sorts keys); a partial last line, a non-JSON line or a bad value is never a port.
     */
    public static function parseListening(string $out, int $id): ?int
    {
        $lines = explode("\n", $out);
        array_pop($lines); // the text after the last newline is not a line yet
        foreach ($lines as $line) {
            $j = json_decode($line, true);
            if (!is_array($j) || !isset($j['listening']) || !is_int($j['listening']) || $j['listening'] < 1 || $j['listening'] > 65535) {
                continue;
            }
            if (array_key_exists('id', $j) && $j['id'] !== $id) {
                continue;
            }
            return $j['listening'];
        }
        return null;
    }

    /**
     * Options: n, vectors (list of ['allow','t','rQuant']); optional Q, partyMain (path of the party program), recvTimeoutMs,
     * killAfterMs, overrides (id => config keys merged over the node config), wireFault (['dialer','target','fault' => wire fault]),
     * dealerSeed, offline ('no-dealer' default | 'trusted-dealer'), insecureTrustedDealer.
     *
     * Bind first: every node binds port 0 itself and prints {"listening":port}; the launcher then sends each node the full port map on one stdin
     * line (the fault proxy, which also binds port 0, stands in for the target in the dialer's view). No port is probed and released.
     *
     * @param array<string,mixed> $o
     * @return array{outputs:list<array<string,mixed>>,wallMs:int,proxyLog:list<string>,ports:list<int>}
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
            $ids = [];
            for ($i = 0; $i < $nodeCount; $i++) {
                $ids[] = MpcNetCerts::generateFiles($dir . "/node$i", "mpc-node-$i");
            }
            $main = $o['partyMain'] ?? dirname(__DIR__) . '/bin/pca-mpc-party';
            $t0 = (int) floor(microtime(true) * 1000);
            for ($id = 0; $id < $nodeCount; $id++) {
                $nodes = [];
                foreach ($ids as $j => $x) {
                    $nodes[] = ['id' => $j, 'host' => '127.0.0.1', 'port' => 0, 'certPath' => $x['certPath']];
                }
                $isDealer = !$noDealer && $id === $n;
                $cfg = ['role' => $isDealer ? 'dealer' : 'party', 'id' => $id, 'n' => $n, 'offline' => $mode, 'sessionId' => $sessionId, 'listenHost' => '127.0.0.1',
                    'bindFirst' => true, 'nodes' => $nodes, 'keyPath' => $ids[$id]['keyPath'], 'certPath' => $ids[$id]['certPath'],
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
                $p = proc_open([PHP_BINARY, '-d', 'memory_limit=2048M', $main, $cfgPath], [0 => ['pipe', 'r'], 1 => ['file', $dir . "/out$id.txt", 'w'], 2 => ['file', $dir . "/err$id.txt", 'w']], $pipes, null, $env);
                if (!is_resource($p)) {
                    throw new \RuntimeException('launchLocal: cannot start a node');
                }
                // stdout and stderr go to files that are polled: on Windows a pipe cannot be read without blocking, and a parent blocked on a
                // running node's pipe never services the fault proxy, so no link would form
                $procs[$id] = ['p' => $p, 'out' => '', 'err' => '', 'outFile' => $dir . "/out$id.txt", 'errFile' => $dir . "/err$id.txt", 'pipes' => $pipes, 'code' => null, 'role' => $isDealer ? 'dealer' : 'party', 'port' => null];
            }
            // wait for every node to report the port it really holds; one that exits first ends the wait and the rest are stopped
            $ports = [];
            $bindBy = MpcNetLoop::mono() + self::t(120000);
            $allBound = false;
            while (true) {
                $allBound = true;
                foreach ($procs as $id => &$pr) {
                    $pr['out'] = (string) @file_get_contents($pr['outFile']);
                    $pr['err'] = (string) @file_get_contents($pr['errFile']);
                    $pr['port'] ??= self::parseListening($pr['out'], $id); // the node holds this port once it prints a valid line
                    if ($pr['port'] === null) {
                        $allBound = false;
                        if (!proc_get_status($pr['p'])['running']) {
                            $bindBy = 0;
                        }
                    }
                }
                unset($pr);
                if ($allBound || MpcNetLoop::mono() > $bindBy) {
                    break;
                }
                MpcNetLoop::step(10);
            }
            if ($allBound) {
                foreach ($procs as $id => $pr) {
                    $ports[$id] = $pr['port'];
                }
                $proxyPort = 0;
                if (isset($o['wireFault'])) {
                    $wf = $o['wireFault'];
                    $fault = $wf['fault'];
                    if (isset($fault['ms'])) {
                        $fault['ms'] = self::t($fault['ms']);
                    }
                    $proxy = new MpcNetFaultProxy(0, ['host' => '127.0.0.1', 'port' => $ports[$wf['target']]], $fault);
                    $proxy->listen();
                    $proxyPort = $proxy->port();
                }
                foreach ($procs as $id => $pr) {
                    $view = $ports;
                    if (isset($o['wireFault']) && $id === $o['wireFault']['dialer']) {
                        $view[$o['wireFault']['target']] = $proxyPort;
                    }
                    fwrite($pr['pipes'][0], json_encode(['ports' => $view]) . "\n");
                    fclose($pr['pipes'][0]);
                }
            } else {
                foreach ($procs as $pr) {
                    proc_terminate($pr['p'], 9);
                }
            }
            $killAt = MpcNetLoop::mono() + self::t($o['killAfterMs'] ?? 120000);
            while (true) {
                $live = 0;
                foreach ($procs as &$pr) {
                    $pr['out'] = (string) @file_get_contents($pr['outFile']);
                    $pr['err'] = (string) @file_get_contents($pr['errFile']);
                    $st = proc_get_status($pr['p']);
                    if ($st['running']) {
                        $live++;
                        if (MpcNetLoop::mono() > $killAt) {
                            proc_terminate($pr['p'], 9);
                        }
                    } elseif ($pr['code'] === null) {
                        $pr['code'] = $st['exitcode'];
                        $pr['out'] = (string) @file_get_contents($pr['outFile']);
                        $pr['err'] = (string) @file_get_contents($pr['errFile']);
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
            return ['outputs' => $outputs, 'wallMs' => (int) floor(microtime(true) * 1000) - $t0, 'proxyLog' => $proxy?->log ?? [], 'ports' => array_values($ports)];
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
