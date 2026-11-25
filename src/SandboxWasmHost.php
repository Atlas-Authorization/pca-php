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
        // Windows only runs a file with an executable extension: the private copy keeps the host's
        $ext = PrivateFile::isWindows() ? strtolower((string)pathinfo($this->path, PATHINFO_EXTENSION)) : '';
        $exe = $dir . DIRECTORY_SEPARATOR . 'host' . ($ext === '' ? '' : '.' . $ext);
        $proc = null;
        $pipes = [];
        $outFile = null;
        try {
            // hash, then exec a private 0700 copy of the verified bytes: the path cannot change between check and exec
            if (PrivateFile::write($exe, $binary) === false || !@chmod($exe, 0700) || PrivateFile::write($file, $payload) === false) {
                return self::fail('host_unavailable');
            }
            // an array command runs without a shell; the empty environment carries no secrets
            $deadline = microtime(true) + $timeoutMs / 1000;
            $cmd = [$exe, ...$args($file)];
            $nul = ['file', PrivateFile::nullDevice(), 'w'];
            if (!PrivateFile::isWindows()) {
                $proc = @proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => $nul], $pipes, null, []);
                if (!is_resource($proc)) {
                    return self::fail('host_unavailable');
                }
                stream_set_blocking($pipes[0], false);
                stream_set_blocking($pipes[1], false);
                $in = $pipes[0];
                $out = $pipes[1];
                $pull = static function (float $left) use ($out): ?string {
                    $r = [$out];
                    $w = $e = null;
                    $n = @stream_select($r, $w, $e, (int)$left, (int)(fmod($left, 1) * 1e6));
                    if ($n === false) {
                        return null;
                    }
                    if ($n === 0) {
                        return '';
                    }
                    $chunk = fread($out, 65536);
                    return $chunk === false || ($chunk === '' && feof($out)) ? null : $chunk;
                };
            } else {
                // Windows: a pipe can be neither read nor written without blocking (stream_select does not wait on it), so a silent or deaf host would hold the
                // client past its deadline. The host's stdout goes to a private file that is polled; its stdin is fed through a relay process over a loopback socket
                // (non-blocking, with select) that accepts one connection, presenting this run's random token. The deadline then holds in both directions.
                $outFile = $dir . DIRECTORY_SEPARATOR . 'out.txt';
                if (!PrivateFile::create($outFile)) {
                    return self::fail('host_unavailable');
                }
                $server = ExclusiveListener::bind('127.0.0.1', 0, [], $errno, $errstr);
                if ($server === false) {
                    return self::fail('host_unavailable');
                }
                $pipes[] = $server;
                $port = (int)substr((string)stream_socket_get_name($server, false), (int)strrpos((string)stream_socket_get_name($server, false), ':') + 1);
                $token = bin2hex(random_bytes(16));
                $env = ['PCA_RELAY_TOKEN' => $token, 'SystemRoot' => (string)getenv('SystemRoot')];
                $proc = @proc_open([PHP_BINARY, __DIR__ . DIRECTORY_SEPARATOR . 'SandboxWasmRelay.php', (string)$port, $outFile, ...$cmd], [0 => $nul, 1 => $nul, 2 => $nul], $relayPipes, null, $env);
                if (!is_resource($proc)) {
                    return self::fail('host_unavailable');
                }
                $in = @stream_socket_accept($server, max(0.0, $deadline - microtime(true)));
                if ($in === false) {
                    return self::fail('timeout'); // the relay never connected within the deadline
                }
                $pipes[] = $in;
                stream_set_timeout($in, 2);
                $given = (string)fgets($in, 128);
                if (!hash_equals($token . "\n", $given)) {
                    return self::fail('host_unavailable'); // one connection is accepted, and only the relay's
                }
                stream_set_blocking($in, false);
                $fh = @fopen($outFile, 'rb');
                if ($fh === false) {
                    return self::fail('host_unavailable');
                }
                $pipes[] = $fh;
                $pos = 0;
                $pull = static function (float $left) use ($fh, $proc, &$pos): ?string {
                    for ($again = 0; $again < 2; $again++) {
                        fseek($fh, $pos);
                        $chunk = (string)fread($fh, 65536);
                        if ($chunk !== '') {
                            $pos += strlen($chunk);
                            return $chunk;
                        }
                        if (!proc_get_status($proc)['running']) {
                            continue; // the relay (which ends with the host) has exited: one last read picks up what the host wrote just before
                        }
                        usleep((int)min(5000, $left * 1e6));
                        return '';
                    }
                    return null;
                };
            }
            return $this->serve($table, $in, $pull, $deadline, $maxResult);
        } finally {
            foreach ($pipes as $p) {
                if (is_resource($p)) {
                    @fclose($p);
                }
            }
            if (is_resource($proc)) {
                if (PrivateFile::isWindows()) {
                    // proc_terminate ends only the process it started (a .cmd shell); the host it launched would keep running
                    $pid = (int)(proc_get_status($proc)['pid'] ?? 0);
                    if ($pid > 0) {
                        @exec('taskkill /T /F /PID ' . $pid . ' >NUL 2>&1');
                    }
                }
                @proc_terminate($proc, 9);
                @proc_close($proc);
            }
            @unlink($file);
            @unlink($exe);
            if ($outFile !== null) {
                @unlink($outFile);
            }
            @rmdir($dir);
        }
    }

    /**
     * @param resource $in the non-blocking channel to the host: its stdin pipe, or the relay's socket on Windows
     * @param \Closure(float):?string $pull what the host has written since the last call, '' when nothing yet (waits at most `$left` seconds), null when it has exited
     */
    private function serve(SandboxHandleTable $table, $in, \Closure $pull, float $deadline, int $maxResult): Obj
    {
        $buf = '';
        while (true) {
            while (($nl = strpos($buf, "\n")) === false) {
                $left = $deadline - microtime(true);
                if ($left <= 0) {
                    return self::fail('timeout');
                }
                $chunk = $pull($left);
                if ($chunk === null) {
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
            $failed = self::sendAll($in, json_encode($reply, JSON_UNESCAPED_SLASHES) . "\n", $deadline);
            if ($failed !== null) {
                return self::fail($failed);
            }
        }
    }

    /** Write all of `$data` to a non-blocking stream by the deadline: null when sent, else the refusal reason ('timeout' when the host does not read). @param resource $stream */
    private static function sendAll($stream, string $data, float $deadline): ?string
    {
        for ($off = 0, $len = strlen($data); $off < $len;) {
            $left = $deadline - microtime(true);
            if ($left <= 0) {
                return 'timeout';
            }
            $r = $e = null;
            $w = [$stream];
            $n = @stream_select($r, $w, $e, 0, (int)(min($left, 0.1) * 1e6));
            if ($n === false) {
                return 'host_exit';
            }
            if ($n === 0) {
                continue;
            }
            $k = @fwrite($stream, substr($data, $off, 65536));
            if ($k === false) {
                return 'host_exit';
            }
            $off += $k;
        }
        return null;
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
