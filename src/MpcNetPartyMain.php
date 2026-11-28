<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * One MPC node (a party, the trusted dealer, or one side of a base-OT demo) as its OWN OS process, talking to the others only over
 * the TLS mesh. Usage: `pca-mpc-party <config.json>` or `pca-mpc-party keygen <dir> <cn>`. Prints exactly one JSON line (the result
 * or the attributable abort) on stdout and exits 0, or 3 on an abort.
 *
 * Config (JSON object): role (party|dealer|ot-sender|ot-receiver), id, n, sessionId, nodes (list of {id, host, port, certPath}),
 * keyPath, certPath; optional Q, input {allow,t,rQuant}, listenHost, recvTimeoutMs, connectTimeoutMs, offline, insecureTrustedDealer,
 * dealerSeed, ot {kind,count}. TEST-ONLY keys (behavior, frameFault, dealerFault) need unsafeTestHooks AND the environment variable
 * PCA_MPC_UNSAFE_TEST_HOOKS=1, else the node refuses to start.
 */
final class MpcNetPartyMain
{
    /** @param list<string> $argv */
    public static function main(array $argv): int
    {
        $args = array_slice($argv, 1);
        if (($args[0] ?? '') === 'keygen') {
            if (!isset($args[1])) {
                self::write(2, "usage: pca-mpc-party keygen <dir> [cn]\n");
                return 2;
            }
            self::out(MpcNetCerts::generateFiles($args[1], $args[2] ?? 'mpc-node'));
            return 0;
        }
        if (!isset($args[0])) {
            self::write(2, "usage: pca-mpc-party <config.json> | keygen <dir> [cn]\n");
            return 2;
        }
        $raw = @file_get_contents($args[0]);
        $cfg = $raw === false ? null : json_decode($raw, true);
        if (!is_array($cfg)) {
            self::write(2, "pca-mpc-party: unreadable config\n");
            return 2;
        }
        $role = (string) ($cfg['role'] ?? 'party');
        $id = (int) $cfg['id'];
        $hooks = isset($cfg['behavior']) || isset($cfg['frameFault']) || isset($cfg['dealerFault']);
        if ($hooks && !(($cfg['unsafeTestHooks'] ?? false) === true && getenv('PCA_MPC_UNSAFE_TEST_HOOKS') === '1')) {
            self::out(['ok' => false, 'role' => $role, 'id' => $id, 'error' => ['kind' => 'local', 'blamed' => null, 'reporter' => $id,
                'message' => 'refusing to start: test hooks (behavior/frameFault) are not enabled in this environment']]);
            return 3;
        }
        $nodes = array_map(static fn(array $x): array => ['id' => (int) $x['id'], 'host' => (string) $x['host'], 'port' => (int) $x['port'], 'certPem' => MpcNetCerts::readPem($x['certPath'])], $cfg['nodes']);
        $n = (int) $cfg['n'];
        $mc = ['selfId' => $id, 'nodes' => $nodes, 'keyPem' => MpcNetCerts::readPem($cfg['keyPath']), 'certPem' => MpcNetCerts::readPem($cfg['certPath']),
            'sessionId' => (string) $cfg['sessionId']];
        if ($role === 'dealer') {
            $mc['linkTo'] = array_values(array_map(static fn(array $x): int => $x['id'], array_filter($nodes, static fn(array $x): bool => $x['id'] < $n)));
        }
        foreach (['listenHost' => 'listenHost', 'recvTimeoutMs' => 'recvTimeoutMs', 'connectTimeoutMs' => 'connectTimeoutMs'] as $k => $from) {
            if (isset($cfg[$from])) {
                $mc[$k] = $cfg[$from];
            }
        }
        if (isset($cfg['frameFault'])) {
            $mc['tamper'] = MpcNetFaults::tamperFor($cfg['frameFault']);
        }
        if ($hooks) {
            $mc['unsafeTestHooks'] = true;
        }
        $mesh = self::mesh($mc);
        $t0 = self::now();
        $code = 0;
        try {
            if (($cfg['bindFirst'] ?? false) === true) {
                // bind first: report the port this node really holds, then take every peer's real port from one stdin line before any dial
                self::out(['listening' => $mesh->listen(), 'id' => $id]);
                $line = self::readLine();
                if ($line === false) {
                    throw new MpcNetAbort('local', null, $id, 'stdin closed before the port map arrived');
                }
                foreach ((array) (json_decode($line, true)['ports'] ?? []) as $k => $port) {
                    if ((int) $k !== $id) {
                        $mesh->setPeerPort((int) $k, (int) $port);
                    }
                }
            }
            $mesh->connect();
            $connectMs = (int) ((self::now() - $t0) * 1000);
            if ($role === 'dealer') {
                $df = $cfg['dealerFault'] ?? null;
                self::run('dealer', MpcNetProtocol::runDealer(...), ['n' => $n, 'Q' => $cfg['Q'] ?? MpcNetProtocol::DEFAULT_Q, 'mesh' => $mesh, 'seed' => isset($cfg['dealerSeed']) ? gmp_init((string) $cfg['dealerSeed']) : null,
                    'insecureTrustedDealer' => $cfg['insecureTrustedDealer'] ?? false, 'macFaultAtInput' => $df['macFaultAtInput'] ?? null,
                    'fault' => $df === null ? null : ['keepCDelta' => isset($df['keepCDelta']) ? gmp_init((string) $df['keepCDelta']) : null,
                        'partnerCDelta' => isset($df['partnerCDelta']) ? array_map(static fn(mixed $x): ?\GMP => $x === null ? null : gmp_init((string) $x), $df['partnerCDelta']) : null]]);
                self::out(['ok' => true, 'role' => 'dealer', 'id' => $id, 'connectMs' => $connectMs, 'links' => $mesh->stats(), 'events' => $mesh->events]);
            } elseif ($role === 'ot-sender' || $role === 'ot-receiver') {
                $ot = $cfg['ot'] ?? ['kind' => 'ec', 'count' => 128];
                $r = $role === 'ot-sender' ? self::run('ot-sender', MpcNetOt::runOtSender(...), $mesh, 1, (string) $ot['kind'], (int) $ot['count'])
                    : self::run('ot-receiver', MpcNetOt::runOtReceiver(...), $mesh, 0, (string) $ot['kind'], (int) $ot['count']);
                self::out(['ok' => true, 'role' => $role, 'connectMs' => $connectMs, 'result' => $r, 'links' => $mesh->stats(), 'events' => $mesh->events]);
            } else {
                $pc = ['id' => $id, 'n' => $n, 'input' => $cfg['input'], 'mesh' => $mesh, 'sessionId' => (string) $cfg['sessionId'],
                    'offline' => $cfg['offline'] ?? 'no-dealer', 'insecureTrustedDealer' => $cfg['insecureTrustedDealer'] ?? false];
                if (isset($cfg['Q'])) {
                    $pc['Q'] = $cfg['Q'];
                }
                if (isset($cfg['behavior'])) {
                    $pc['behavior'] = $cfg['behavior'];
                    $pc['unsafeTestHooks'] = true;
                }
                $r = self::run('party', MpcNetProtocol::runParty(...), $pc);
                self::out(['ok' => true, 'role' => 'party', 'connectMs' => $connectMs, 'result' => $r, 'links' => $mesh->stats(), 'events' => $mesh->events]);
            }
        } catch (MpcNetCrashParty) {
            self::quit(7); // abrupt: no close, no flush
        } catch (MpcNetSilentParty) {
            // stay connected but say nothing; the peers must time out
            $end = self::mono() + 4 * (int) ($cfg['recvTimeoutMs'] ?? 20000);
            while (self::mono() < $end) {
                self::wait('step', 50);
            }
            return 0;
        } catch (\Throwable $e) {
            $ne = $e instanceof MpcNetAbort ? $e : ($mesh->failed() ?? new MpcNetAbort('local', null, $id, $e->getMessage()));
            self::out(['ok' => false, 'role' => $role, 'id' => $id, 'error' => ['kind' => $ne->kind, 'blamed' => $ne->blamed, 'reporter' => $ne->reporter,
                'claimedKind' => $ne->claimedKind, 'claimedBlame' => $ne->claimedBlame, 'reason' => $ne->reason, 'evidence' => $ne->evidence,
                'deadlineMs' => $ne->deadlineMs, 'message' => $ne->getMessage()], 'links' => $mesh->stats(), 'events' => $mesh->events]);
            $code = 3;
        }
        // give sockets a moment to flush abort frames, then close
        self::wait('drain', 300);
        $mesh->close();
        return $code;
    }

    /** JSON-model view of a value: GMP as decimal strings, parsed objects as maps. */
    private static function plain(mixed $v): mixed
    {
        if ($v instanceof \GMP) {
            return gmp_strval($v);
        }
        if ($v instanceof Num) {
            return $v->float();
        }
        if ($v instanceof Obj) {
            $o = new \stdClass();
            foreach ($v->keys() as $k) {
                $o->{$k} = self::plain($v->get($k));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(self::plain(...), $v);
        }
        return $v;
    }

    private static function out(mixed $o): void
    {
        self::write(1, json_encode(self::plain($o), JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR) . "\n");
    }

    /** @internal Test seam: when set, stdout (fd 1) and stderr (fd 2) writes go to it as (fd, text). */
    public static ?\Closure $writeHook = null;
    /** @internal Test seam: when set, the stdin port-map line is read from it (string, or false for a closed stdin). */
    public static ?\Closure $stdinHook = null;
    /** @internal Test seam: when set, it is called with the exit code before the process exits (a test hook throws). */
    public static ?\Closure $exitHook = null;
    /** @internal Test seam: when set, it builds the mesh from the mesh config instead of new MpcNetMesh. */
    public static ?\Closure $meshHook = null;
    /** @internal Test seam: when set, it runs the dealer / party / OT side as (what, ...args) instead of the real run. */
    public static ?\Closure $runHook = null;
    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it. */
    public static ?\Closure $nowHook = null;
    /** @internal Test seam: when set, the event loop's monotonic clock (ms) is read from it. */
    public static ?\Closure $monoHook = null;
    /** @internal Test seam: when set, event-loop waits go to it as ('step' or 'drain', ms) instead of servicing sockets. */
    public static ?\Closure $waitHook = null;

    private static function write(int $fd, string $text): void
    {
        if (self::$writeHook !== null) {
            (self::$writeHook)($fd, $text);
        } else {
            fwrite($fd === 1 ? STDOUT : STDERR, $text);
        }
    }

    private static function readLine(): string|false
    {
        return self::$stdinHook !== null ? (self::$stdinHook)() : fgets(STDIN);
    }

    private static function quit(int $code): never
    {
        if (self::$exitHook !== null) {
            (self::$exitHook)($code);
        }
        exit($code);
    }

    private static function mesh(array $mc): MpcNetMesh
    {
        return self::$meshHook !== null ? (self::$meshHook)($mc) : new MpcNetMesh($mc);
    }

    private static function run(string $what, \Closure $real, mixed ...$args): mixed
    {
        return self::$runHook !== null ? (self::$runHook)($what, ...$args) : $real(...$args);
    }

    private static function now(): float
    {
        return self::$nowHook !== null ? (self::$nowHook)() : microtime(true);
    }

    private static function mono(): int
    {
        return self::$monoHook !== null ? (self::$monoHook)() : MpcNetLoop::mono();
    }

    private static function wait(string $kind, int $ms): void
    {
        if (self::$waitHook !== null) {
            (self::$waitHook)($kind, $ms);
        } elseif ($kind === 'step') {
            MpcNetLoop::step($ms);
        } else {
            MpcNetLoop::drain($ms);
        }
    }
}
