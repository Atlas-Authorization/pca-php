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

    private static function fake(string $tag, string $body): SandboxWasmHost
    {
        $dir = sys_get_temp_dir() . '/pca-host-test-' . getmypid() . '-' . $tag;
        @mkdir($dir, 0700, true);
        $script = "#!/bin/sh\n$body\n";
        file_put_contents("$dir/host.sh", $script);
        chmod("$dir/host.sh", 0755);
        return new SandboxWasmHost("$dir/host.sh", hash('sha256', $script));
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
        $this->assertSame('host_missing', (new SandboxWasmHost('/nonexistent/pca-wasmtime-host', str_repeat('a', 64)))->runComponent($t, 'x', 100)->get('reason'));
        $this->assertSame('host_unpinned', (new SandboxWasmHost('/bin/sh', ''))->runComponent($t, 'x', 100)->get('reason'));
        $this->assertSame('host_hash_mismatch', (new SandboxWasmHost('/bin/sh', str_repeat('0', 64)))->runCore($t, 'x', 100)->get('reason'));
        $this->assertSame('bad_fuel', (new SandboxWasmHost('/bin/sh', str_repeat('0', 64)))->runComponent($t, 'x', 0)->get('reason'));
        $this->assertSame('bad_fuel', (new SandboxWasmHost('/bin/sh', str_repeat('0', 64)))->runCore($t, 'x', -1)->get('reason'));
        $this->assertSame('module_size', (new SandboxWasmHost('/bin/sh', str_repeat('0', 64)))->runCore($t, '', 10)->get('reason'));
    }

    public function testProtocolAgainstFakeHost(): void
    {
        [$t, $log] = self::table();
        $h = self::fake('proto', 'printf \'{"op":"count"}\n\'; read a; printf \'{"op":"invoke","h":1}\n\'; read b; case "$b" in *"[7,8,9]"*) printf \'{"done":5,"fuel_used":1}\n\';; *) printf \'{"fail":"bad_reply"}\n\';; esac');
        $r = $h->runComponent($t, 'x', 1000);
        $this->assertTrue($r->get('ok'));
        $this->assertSame(5, $r->get('value'));
        // the single use is spent: the second run is answered err -2 and the fake reports it
        $this->assertSame('bad_reply', $h->runComponent($t, 'x', 1000)->get('reason'));
    }

    public function testHungGarbageAndExitingHosts(): void
    {
        [$t] = self::table();
        $this->assertSame('timeout', self::fake('hang', 'read a')->runComponent($t, 'x', 1000, 300)->get('reason'));
        $this->assertSame('host_protocol', self::fake('junk', 'echo not-json')->runComponent($t, 'x', 1000)->get('reason'));
        $this->assertSame('host_exit', self::fake('quiet', 'exit 0')->runComponent($t, 'x', 1000)->get('reason'));
        $this->assertSame('fuel_exhausted', self::fake('fail', 'echo \'{"fail":"fuel_exhausted"}\'')->runComponent($t, 'x', 1000)->get('reason'));
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
