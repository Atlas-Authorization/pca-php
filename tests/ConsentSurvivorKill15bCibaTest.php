<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\CibaClient;
use Atlas\Pca\CibaProviderError;
use Atlas\Pca\DirectoryKv;
use Atlas\Pca\FileApprovalStore;
use PHPUnit\Framework\TestCase;

/** group 15b mutation kills for src/Ciba.php: the file stores' read / write / rename failures and the transport timeout unit. */
final class ConsentSurvivorKill15bCibaTest extends TestCase
{
    /** A one-shot HTTP server: answers the first request after `$delayUs` microseconds (it is killed at the end of the test). */
    private const SERVER = <<<'SRV'
$s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($s === false) {
    fwrite(STDERR, $errstr);
    exit(1);
}
$name = (string) stream_socket_get_name($s, false);
fwrite(STDOUT, substr($name, (int) strrpos($name, ':') + 1) . "\n");
$c = @stream_socket_accept($s, 5);
if ($c !== false) {
    $req = '';
    while (!str_contains($req, "\r\n\r\n")) {
        $b = fread($c, 8192);
        if ($b === false || $b === '') {
            break;
        }
        $req .= $b;
    }
    usleep($delayUs);
    @fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    @fclose($c);
}
SRV;

    private ?string $cwd = null;
    private ?string $dir = null;
    /** @var list<resource> */
    private array $socks = [];

    protected function setUp(): void
    {
        $this->cwd = (string) getcwd();
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k15b-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
        chdir($this->dir); // relative paths keep a unix socket path under the 104-byte sun_path limit
    }

    protected function tearDown(): void
    {
        foreach ($this->socks as $s) {
            fclose($s);
        }
        chdir((string) $this->cwd);
        self::rmTree((string) $this->dir);
    }

    private static function rmTree(string $p): void
    {
        if (is_dir($p) && !is_link($p)) {
            foreach (scandir($p) ?: [] as $e) {
                if ($e !== '.' && $e !== '..') {
                    self::rmTree("$p/$e");
                }
            }
            @rmdir($p);
        } elseif (file_exists($p) || is_link($p)) {
            @unlink($p);
        }
    }

    /** A path that exists but cannot be opened for reading: a unix socket (open fails with ENXIO / EOPNOTSUPP), on Windows a directory. */
    private function unreadable(string $path): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            mkdir($path);
            return;
        }
        $s = stream_socket_server('unix://' . $path, $errno, $errstr);
        self::assertIsResource($s, $errstr);
        $this->socks[] = $s;
        self::assertFileExists($path);
    }

    /** `$f()` with PHP warnings and notices swallowed (the failing file call itself warns). */
    private static function quiet(callable $f): \Throwable
    {
        set_error_handler(static fn(): bool => true);
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        } finally {
            restore_error_handler();
        }
        self::fail('expected a throw');
    }

    private static function assertQuietThrow(string $message, callable $f): void
    {
        $e = self::quiet($f);
        self::assertSame(\RuntimeException::class, get_class($e), $e->getMessage());
        self::assertSame($message, $e->getMessage());
    }

    private static function file(string $key): string
    {
        return 'd' . DIRECTORY_SEPARATOR . hash('sha256', $key);
    }

    /** An approval-store file that exists but cannot be read is refused as corrupt (fail closed), never read as empty. */
    public function testFileApprovalStoreUnreadable(): void
    {
        $this->unreadable('s');
        self::assertQuietThrow('ciba: approval store file is corrupt', static fn() => (new FileApprovalStore('s'))->get('a'));
    }

    /** A record file that exists but cannot be read is an error, on get and on a swap (which then releases its lock). */
    public function testDirectoryKvUnreadableRecord(): void
    {
        $kv = new DirectoryKv('d');
        $this->unreadable(self::file('k'));
        self::assertQuietThrow('ciba: could not read the store', static fn() => $kv->get('k'));
        self::assertQuietThrow('ciba: could not read the store', static fn() => $kv->putIfEquals('k', null, 'a'));
        $this->assertFileDoesNotExist(self::file('k') . '.lock');
    }

    /** A rename that cannot publish the new record (a directory holds its name) is an error, not a silent success. */
    public function testDirectoryKvRenameFails(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('a directory is unreadable on Windows, so the read check refuses first');
        }
        $kv = new DirectoryKv('d');
        mkdir(self::file('k'));
        touch(self::file('k') . DIRECTORY_SEPARATOR . 'x'); // non-empty: no platform renames a file over it
        // reading a directory gives '' (EISDIR on read), so the swap from '' goes on to the rename
        self::assertQuietThrow('ciba: could not write the store', static fn() => $kv->putIfEquals('k', '', 'a'));
        $this->assertFileDoesNotExist(self::file('k') . '.lock');
    }

    /** A temp file whose write fails (it is /dev/full) is an error before any rename. */
    public function testDirectoryKvWriteFails(): void
    {
        if (!is_writable('/dev/full') || (function_exists('posix_geteuid') && posix_geteuid() === 0)) {
            $this->markTestSkipped('needs /dev/full, and a non-root user (the store chmods the file it opens)');
        }
        $kv = new DirectoryKv('d');
        symlink('/dev/full', self::file('k') . '.' . getmypid() . '.tmp');
        self::assertQuietThrow('ciba: could not write the store', static fn() => $kv->putIfEquals('k', null, 'a'));
        $this->assertFileDoesNotExist(self::file('k'));
        $this->assertFileDoesNotExist(self::file('k') . '.lock');
    }

    /** The transport timeout is in milliseconds: with 100 ms, a server that answers only after 1.5 s is a network error (in ~0.1 s). */
    public function testTransportTimeoutIsMilliseconds(): void
    {
        $code = '$delayUs = 1500000;' . "\n" . self::SERVER;
        $p = proc_open([PHP_BINARY, '-d', 'display_errors=stderr', '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        try {
            $port = (int) trim((string) fgets($pipes[1]));
            self::assertGreaterThan(0, $port);
            $client = new CibaClient(['backchannelAuthenticationEndpoint' => "http://127.0.0.1:$port/bc", 'tokenEndpoint' => "http://127.0.0.1:$port/t",
                'clientId' => 'c', 'clientSecret' => 's', 'allowInsecureHttp' => true, 'timeoutMs' => 100]);
            try {
                $client->post("http://127.0.0.1:$port/bc", [['a', 'b']]);
                self::fail('expected a network error');
            } catch (CibaProviderError $e) {
                self::assertSame('network_error', $e->error);
                self::assertSame('request failed', $e->errorDescription);
            }
        } finally {
            proc_terminate($p);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($p);
        }
    }
}
