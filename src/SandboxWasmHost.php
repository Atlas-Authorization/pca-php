<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/NativeDir.php';

/**
 * WebAssembly hosts for sandboxed tools, run as a subprocess of the reference `pca-wasmtime-host` binary (PHP has no maintained
 * WebAssembly engine). The binary does the work: instruction fuel, a wall-clock epoch deadline, a hard memory cap, the import
 * allow-list (`pca:act.{invoke,handle_count,handle_verb}`, no WASI) for core modules, and the canonical ABI for components. This
 * class pins the binary, spawns it with an empty environment and no shell, and serves its handle requests from a
 * `SandboxHandleTable` over JSON lines.
 *
 * Trust in the binary: path from configuration only, SHA-256 pinned. A missing binary, a missing pin or a different hash is
 * refused before anything is spawned. The hash is checked on the file's bytes and then the path is executed, so a writer who can
 * replace the file in between wins that race: install the binary where only the operator can write.
 *
 * Every method returns an Obj `{ok:true,value}` or `{ok:false,reason}`; reasons are the host's (fuel_exhausted, timeout,
 * memory_limits, ambient_import:<name>, trap:RuntimeError, ...) plus bad_fuel, host_unpinned, host_missing, host_hash_mismatch,
 * host_unavailable, host_protocol, host_exit.
 */
final class SandboxWasmHost
{
    private const MAX_FUEL = 9007199254740991;

    public function __construct(private readonly string $path, private readonly string $expectedSha256)
    {
    }

    /**
     * The host binary the release package ships for this platform (native/<os>-<arch>/), pinned to the digest recorded beside it when the
     * package was built; null for a source checkout or an unsupported platform. The digest guards against a damaged file, not against
     * someone who can write the package directory: pass your own pin to `new SandboxWasmHost($path, $sha256)` for that.
     */
    public static function packaged(): ?self
    {
        $exe = NativeDir::dir() . '/pca-wasmtime-host' . (PHP_OS_FAMILY === 'Windows' ? '.exe' : '');
        $sum = @file_get_contents($exe . '.sha256');
        return is_file($exe) && is_string($sum) ? new self($exe, trim($sum)) : null;
    }

    private static function fail(string $reason): Obj
    {
        return Obj::of(['ok' => false, 'reason' => $reason]);
    }

    /** Null when the binary matches its pin, else the refusal reason. */
    public function verify(): ?string
    {
        return $this->readVerified($bytes);
    }

    /** Returns a refusal reason, or null with the verified binary bytes in `$bytes`. */
    private function readVerified(?string &$bytes = null): ?string
    {
        $pin = strtolower($this->expectedSha256);
        if (preg_match('/\A[0-9a-f]{64}\z/', $pin) !== 1) {
            return 'host_unpinned';
        }
        $bytes = is_file($this->path) ? @file_get_contents($this->path) : false;
        if ($bytes === false) {
            return 'host_missing';
        }
        if (!hash_equals($pin, hash('sha256', $bytes))) {
            $bytes = null;
            return 'host_hash_mismatch';
        }
        return null;
    }

    /** Run a component (binary or WAT text) with `$fuel` instructions of budget. `$fuel` has no default: a budget is a decision. */
    public function runComponent(SandboxHandleTable $table, string $component, int $fuel, int $timeoutMs = 10000, int $maxResultBytes = 1 << 20): Obj
    {
        if ($fuel < 1 || $fuel > self::MAX_FUEL) {
            return self::fail('bad_fuel');
        }
        return $this->run($table, $component, fn(string $file) => [$file, (string)$fuel], $timeoutMs, $maxResultBytes);
    }

    /** Run a core module's export `$entry` under fuel, a wall-clock deadline and a memory cap of `$maxPages` 64 KiB pages. */
    public function runCore(SandboxHandleTable $table, string $module, int $fuel, string $entry = 'run', int $maxPages = 256, int $timeoutMs = 5000, int $maxModuleBytes = 1 << 20, int $maxResultBytes = 1 << 20): Obj
    {
        if ($fuel < 1 || $fuel > self::MAX_FUEL) {
            return self::fail('bad_fuel');
        }
        if ($maxPages < 1 || $maxPages > 65536 || $timeoutMs < 1) {
            return self::fail('bad_limits');
        }
        if ($module === '' || strlen($module) > $maxModuleBytes || strlen($module) > (1 << 20)) {
            return self::fail('module_size');
        }
        // the host enforces its own deadline; this parent's kill timer is a little longer so the host's reason wins
        return $this->run($table, $module, fn(string $file) => ['core', $file, (string)$fuel, (string)$maxPages, (string)$timeoutMs, $entry], $timeoutMs + 1000, $maxResultBytes);
    }

    /** @param \Closure(string):list<string> $args */
    private function run(SandboxHandleTable $table, string $payload, \Closure $args, int $timeoutMs, int $maxResult): Obj
    {
        $bad = $this->readVerified($binary);
        if ($bad !== null) {
            return self::fail($bad);
        }
        $dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-comp-' . bin2hex(random_bytes(8));
        try {
            if (!PrivateFile::mkdir($dir)) {
                return self::fail('host_unavailable');
            }
        } catch (PrivateFileError) { // no owner-only directory is possible here: nothing is staged
            return self::fail('host_unavailable');
        }
        $file = $dir . DIRECTORY_SEPARATOR . 'tool.wasm';
        $exe = $dir . DIRECTORY_SEPARATOR . 'host';
        $proc = null;
        $pipes = [];
        try {
            // hash, then exec a private 0700 copy of the verified bytes: the path cannot change between check and exec
            if (PrivateFile::write($exe, $binary) === false || !@chmod($exe, 0700) || PrivateFile::write($file, $payload) === false) {
                return self::fail('host_unavailable');
            }
            // an array command runs without a shell; the empty environment carries no secrets
            $proc = @proc_open([$exe, ...$args($file)], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes, null, []);
            if (!is_resource($proc)) {
                return self::fail('host_unavailable');
            }
            stream_set_blocking($pipes[1], false);
            return $this->serve($table, $pipes[0], $pipes[1], $timeoutMs, $maxResult);
        } finally {
            foreach ($pipes as $p) {
                if (is_resource($p)) {
                    @fclose($p);
                }
            }
            if (is_resource($proc)) {
                @proc_terminate($proc, 9);
                @proc_close($proc);
            }
            @unlink($file);
            @unlink($exe);
            @rmdir($dir);
        }
    }

    /** @param resource $in @param resource $out */
    private function serve(SandboxHandleTable $table, $in, $out, int $timeoutMs, int $maxResult): Obj
    {
        $deadline = microtime(true) + $timeoutMs / 1000;
        $buf = '';
        while (true) {
            while (($nl = strpos($buf, "\n")) === false) {
                $left = $deadline - microtime(true);
                if ($left <= 0) {
                    return self::fail('timeout');
                }
                $r = [$out];
                $w = $e = null;
                $n = @stream_select($r, $w, $e, (int)$left, (int)(fmod($left, 1) * 1e6));
                if ($n === false) {
                    return self::fail('host_unavailable');
                }
                if ($n === 0) {
                    continue;
                }
                $chunk = fread($out, 65536);
                if ($chunk === false || ($chunk === '' && feof($out))) {
                    return self::fail('host_exit');
                }
                $buf .= $chunk;
            }
            $line = substr($buf, 0, $nl);
            $buf = substr($buf, $nl + 1);
            $m = json_decode($line, true);
            if (!is_array($m)) {
                return self::fail('host_protocol');
            }
            if (isset($m['fail']) && is_string($m['fail'])) {
                return self::fail($m['fail']);
            }
            if (isset($m['done']) && (is_int($m['done']) || is_float($m['done']))) {
                return Obj::of(['ok' => true, 'value' => (int)$m['done']]);
            }
            $h = isset($m['h']) && is_int($m['h']) ? $m['h'] : 0;
            $reply = match ($m['op'] ?? null) {
                'count' => ['n' => $table->size()],
                'verb' => ($v = $table->verbOf($h)) === null ? ['err' => -1] : ['ok' => $v],
                'invoke' => $this->invoke($table, $h, $maxResult),
                default => null,
            };
            if ($reply === null) {
                return self::fail('host_protocol');
            }
            // requests are answered strictly one at a time, in order
            if (@fwrite($in, json_encode($reply, JSON_UNESCAPED_SLASHES) . "\n") === false) {
                return self::fail('host_exit');
            }
            @fflush($in);
        }
    }

    /** @return array<string,mixed> */
    private function invoke(SandboxHandleTable $table, int $h, int $maxResult): array
    {
        $r = $table->use($h);
        if ($r->get('ok') !== true) {
            return ['err' => Sandbox::USE_ERR[$r->get('reason')] ?? -5];
        }
        $raw = Bytes::of($r->get('result')) ?? '';
        return strlen($raw) > $maxResult ? ['err' => -3] : ['ok' => array_values(unpack('C*', $raw) ?: [])];
    }
}
