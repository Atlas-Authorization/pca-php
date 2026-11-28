<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sandbox;
use Atlas\Pca\SandboxEgressPolicy;
use Atlas\Pca\SandboxHandleTable;
use Atlas\Pca\SandboxReceiptLog;
use Atlas\Pca\SandboxWasmHost;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * The subprocess hosts: pin refusals, the JSON-lines protocol against a fake host, and, when PCA_WASMTIME_HOST_BIN and
 * PCA_WASMTIME_HOST_SHA256 name a built reference host, real core-module and component runs (fuel, memory, imports, egress).
 */
final class SandboxWasmHostTest extends TestCase
{
    private static function opResult(Obj $op): Obj
    {
        return Obj::of(['allow' => true, 'operation' => Obj::of(['verb' => $op->get('verb'), 'resource' => $op->get('resource'),
            'params_digest' => Pca::hashCanonical($op->get('params')), 'id' => 'op'])]);
    }

    private static function op(string $verb, string $resource): Obj
    {
        return Obj::of(['verb' => $verb, 'resource' => $resource, 'params' => new Obj()]);
    }

    /** @return array{0:SandboxHandleTable,1:SandboxReceiptLog} handles: 1 fs.read, 2 net.ok, 3 net.evil */
    private static function table(): array
    {
        $policy = new SandboxEgressPolicy();
        $ok = self::op('net.ok', 'api.example.com');
        $policy->admit(self::opResult($ok), $ok, static fn($op) => Obj::of(['method' => 'GET', 'scheme' => 'https', 'host' => 'api.example.com', 'path' => '/v1']));
        $fetch = static function (string $url) use ($policy): \Closure {
            return static function ($op) use ($policy, $url) {
                $d = $policy->claim(Obj::of(['method' => 'GET', 'url' => $url]));
                if ($d->get('allow') !== true) {
                    throw new \RuntimeException('egress denied');
                }
                return new Bytes("\x01");
            };
        };
        $log = new SandboxReceiptLog();
        $t = new SandboxHandleTable('wasi_no_ambient', $log, [
            'fs.read' => static fn($op) => new Bytes("\x07\x08\x09"),
            'net.ok' => $fetch('https://api.example.com/v1'),
            'net.evil' => $fetch('https://evil.example/x'),
        ]);
        foreach ([['fs.read', '/x'], ['net.ok', 'api.example.com'], ['net.evil', 'evil.example']] as [$v, $r]) {
            $o = self::op($v, $r);
            $t->mint(self::opResult($o), $o);
        }
        return [$t, $log];
    }

    /** A fake host: a shell script, or on Windows (no /bin/sh) a command file that runs the same protocol as a PHP script. */
    private static function fake(string $tag, string $body, string $phpBody): SandboxWasmHost
    {
        return new SandboxWasmHost(...self::fakeFiles($tag, $body, $phpBody));
    }

    /** @return array{0:string,1:string} the fake host's path and pinned sha256 */
    private static function fakeFiles(string $tag, string $body, string $phpBody): array
    {
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-host-test-' . getmypid() . '-' . $tag;
        @mkdir($dir, 0700, true);
        if (PHP_OS_FAMILY === 'Windows') {
            file_put_contents("$dir\\host.php", "<?php\n$phpBody\n");
            $script = "@\"" . PHP_BINARY . "\" \"$dir\\host.php\"\r\n";
            file_put_contents("$dir\\host.cmd", $script);
            return ["$dir\\host.cmd", hash('sha256', $script)];
        }
        $script = "#!/bin/sh\n$body\n";
        file_put_contents("$dir/host.sh", $script);
        chmod("$dir/host.sh", 0755);
        return ["$dir/host.sh", hash('sha256', $script)];
    }

    /** Any existing file stands in for a host where only the pin is under test. */
    private static function anyFile(): string
    {
        return PHP_BINARY;
    }

    private static function real(): ?SandboxWasmHost
    {
        $p = getenv('PCA_WASMTIME_HOST_BIN');
        $h = getenv('PCA_WASMTIME_HOST_SHA256');
        return $p !== false && $h !== false ? new SandboxWasmHost($p, $h) : null;
    }

    /** In CI a missing real host is a failure, so a green run never skips it. */
    private function skipOrFailInCi(): void
    {
        if (getenv('CI') !== false && getenv('CI') !== '') {
            $this->fail('CI must export PCA_WASMTIME_HOST_BIN and PCA_WASMTIME_HOST_SHA256');
        }
        $this->markTestSkipped('PCA_WASMTIME_HOST_BIN / PCA_WASMTIME_HOST_SHA256 not set');
    }

    public function testPinRefusals(): void
    {
        [$t] = self::table();
        $this->assertSame('host_missing', (new SandboxWasmHost(sys_get_temp_dir() . '/nonexistent/pca-wasmtime-host', str_repeat('a', 64)))->runComponent($t, 'x', 100)->get('reason'));
        $this->assertSame('host_unpinned', (new SandboxWasmHost(self::anyFile(), ''))->runComponent($t, 'x', 100)->get('reason'));
        $this->assertSame('host_hash_mismatch', (new SandboxWasmHost(self::anyFile(), str_repeat('0', 64)))->runCore($t, 'x', 100)->get('reason'));
        $this->assertSame('bad_fuel', (new SandboxWasmHost(self::anyFile(), str_repeat('0', 64)))->runComponent($t, 'x', 0)->get('reason'));
        $this->assertSame('bad_fuel', (new SandboxWasmHost(self::anyFile(), str_repeat('0', 64)))->runCore($t, 'x', -1)->get('reason'));
        $this->assertSame('module_size', (new SandboxWasmHost(self::anyFile(), str_repeat('0', 64)))->runCore($t, '', 10)->get('reason'));
    }

    public function testProtocolAgainstFakeHost(): void
    {
        [$t, $log] = self::table();
        $h = self::fake('proto', 'printf \'{"op":"count"}\n\'; read a; printf \'{"op":"invoke","h":1}\n\'; read b; case "$b" in *"[7,8,9]"*) printf \'{"done":5,"fuel_used":1}\n\';; *) printf \'{"fail":"bad_reply"}\n\';; esac',
            'echo "{\\"op\\":\\"count\\"}\\n"; fgets(STDIN); echo "{\\"op\\":\\"invoke\\",\\"h\\":1}\\n"; $b = (string)fgets(STDIN); echo str_contains($b, "[7,8,9]") ? "{\\"done\\":5,\\"fuel_used\\":1}\\n" : "{\\"fail\\":\\"bad_reply\\"}\\n";');
        $r = $h->runComponent($t, 'x', 1000);
        $this->assertTrue($r->get('ok'));
        $this->assertSame(5, $r->get('value'));
        // the single use is spent: the second run is answered err -2 and the fake reports it
        $this->assertSame('bad_reply', $h->runComponent($t, 'x', 1000)->get('reason'));
    }

    public function testHungGarbageAndExitingHosts(): void
    {
        [$t] = self::table();
        $this->assertSame('timeout', $this->runHungHostWithinDeadline(), 'a hung host is refused as a timeout');
        $this->assertSame('host_protocol', self::fake('junk', 'echo not-json', 'echo "not-json\\n";')->runComponent($t, 'x', 1000)->get('reason'));
        $this->assertSame('host_exit', self::fake('quiet', 'exit 0', 'exit(0);')->runComponent($t, 'x', 1000)->get('reason'));
        $this->assertSame('fuel_exhausted', self::fake('fail', 'echo \'{"fail":"fuel_exhausted"}\'', 'echo "{\\"fail\\":\\"fuel_exhausted\\"}\\n";')->runComponent($t, 'x', 1000)->get('reason'));
    }

    /**
     * The hung-host case runs in its own process under a hard limit of this test: if the client ever blocks on a host that says nothing,
     * the test fails here with that message instead of hanging the whole run.
     */
    private function runHungHostWithinDeadline(string $mode = 'hang'): string
    {
        [$path, $sha] = $mode === 'hang' ? self::fakeFiles('hang', 'read a', 'fgets(STDIN);')
            : self::fakeFiles('deaf', 'printf \'{"op":"invoke","h":1}\n\'; sleep 30', 'echo "{\\"op\\":\\"invoke\\",\\"h\\":1}\\n"; sleep(30);');
        $out = tempnam(sys_get_temp_dir(), 'hangout');
        $proc = proc_open([PHP_BINARY, __DIR__ . '/sandbox-hung-host-probe.php', $path, $sha, $mode], [0 => ['pipe', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $out . '.err', 'w']], $pipes);
        $this->assertIsResource($proc);
        $until = microtime(true) + 30;
        while (microtime(true) < $until && proc_get_status($proc)['running']) {
            usleep(50000);
        }
        $running = proc_get_status($proc)['running'];
        if ($running) {
            $pid = (int)proc_get_status($proc)['pid'];
            PHP_OS_FAMILY === 'Windows' ? @exec("taskkill /T /F /PID $pid >NUL 2>&1") : null;
            @proc_terminate($proc, 9);
        }
        @fclose($pipes[0]);
        @proc_close($proc);
        $reason = trim((string)@file_get_contents($out));
        @unlink($out);
        @unlink($out . '.err');
        $this->assertFalse($running, 'the client did not return from a hung host within 30 s (its deadline was 1.3 s): it blocks on the host instead of enforcing the deadline');
        return $reason;
    }

    /** A host that asks for a 1 MiB result and never reads its stdin: the client's write must not outlast its deadline either. */
    public function testAHostThatNeverReadsItsInputIsRefusedWithinTheDeadline(): void
    {
        $this->assertSame('timeout', $this->runHungHostWithinDeadline('deaf'), 'a host that does not read the client\'s reply is refused as a timeout');
    }

    #[Group('native-lib')] // runs in the sandbox-wasm workflow, which builds the real host
    public function testRealCoreModuleLimits(): void
    {
        $host = self::real();
        if ($host === null) {
            $this->skipOrFailInCi();
        }
        $call = static fn(int $h) => Obj::of(['calls' => [Obj::of(['handle' => $h, 'ptr' => 0, 'cap' => 16])], 'returns' => 'byte0']);
        [$t] = self::table();
        $this->assertSame(7, $host->runCore($t, Sandbox::buildTool($call(1)), 1000000)->get('value'));
        [$t] = self::table();
        $this->assertSame('fuel_exhausted', $host->runCore($t, Sandbox::buildTool(Obj::of(['calls' => [], 'spin' => true])), 10000)->get('reason'));
        $this->assertSame('timeout', $host->runCore($t, Sandbox::buildTool(Obj::of(['calls' => [], 'spin' => true])), 4000000000000, 'run', 256, 300)->get('reason'));
        $this->assertSame('memory_limits', $host->runCore($t, Sandbox::buildTool(Obj::of(['calls' => [], 'memory' => Obj::of(['min' => 1, 'max' => 257])])), 1000)->get('reason'));
        $this->assertSame('memory_limits', $host->runCore($t, Sandbox::buildTool(Obj::of(['calls' => [], 'memory' => Obj::of(['min' => 1, 'max' => null])])), 1000)->get('reason'));
        foreach ([['wasi_snapshot_preview1', 'fd_write'], ['env', 'x'], ['pca:act', 'other']] as [$m, $n]) {
            $spec = Obj::of(['calls' => [], 'extraImports' => [Obj::of(['module' => $m, 'name' => $n])]]);
            $this->assertSame("ambient_import:$m.$n", $host->runCore($t, Sandbox::buildTool($spec), 1000)->get('reason'));
        }
        // egress: in-policy handle 2 returns 1; out-of-policy handle 3 is refused by the policy (executor error -5)
        [$t] = self::table();
        $this->assertSame(1, $host->runCore($t, Sandbox::buildTool(Obj::of(['calls' => [Obj::of(['handle' => 2, 'ptr' => 0, 'cap' => 16])]])), 1000000)->get('value'));
        $this->assertSame(-5, $host->runCore($t, Sandbox::buildTool(Obj::of(['calls' => [Obj::of(['handle' => 3, 'ptr' => 0, 'cap' => 16])]])), 1000000)->get('value'));
    }

    #[Group('native-lib')]
    public function testRealComponentLimits(): void
    {
        $host = self::real();
        if ($host === null) {
            $this->skipOrFailInCi();
        }
        [$t] = self::table();
        $this->assertSame(7, $host->runComponent($t, Sandbox::referenceComponentWat(), 1000000)->get('value'));
        $this->assertSame('fuel_exhausted', $host->runComponent($t, Sandbox::referenceComponentWat(Obj::of(['spin' => true])), 10000)->get('reason'));
        $this->assertSame('ambient_import:wasi:cli/environment@0.2.0', $host->runComponent($t, Sandbox::referenceComponentWat(Obj::of(['extraImport' => 'wasi:cli/environment@0.2.0'])), 1000000)->get('reason'));
    }
}
