<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PrivateFile;
use Atlas\Pca\Siem;
use PHPUnit\Framework\TestCase;

/**
 * The HTTP sink's default transport against a raw loopback responder that writes exact status lines: the request it sends
 * (method, headers, body) is echoed back in a reason phrase, and the status line is parsed exactly.
 */
final class ToolSurvivorKill18bSiemHttpTest extends TestCase
{
    /** @var array{0: mixed, 1: int}|null [process, port] */
    private static ?array $server = null;
    private static string $dir = '';

    private const RESPONDER = <<<'PHP'
<?php
// Prints its port, then answers each request with exact bytes chosen by the request path.
$s = stream_socket_server('tcp://127.0.0.1:0', $no, $err);
if ($s === false) {
    fwrite(STDOUT, "0\n");
    exit(1);
}
$name = (string)stream_socket_get_name($s, false);
fwrite(STDOUT, substr($name, strrpos($name, ':') + 1) . "\n");
fflush(STDOUT);
while (true) {
    $c = @stream_socket_accept($s, 60);
    if ($c === false) {
        continue;
    }
    stream_set_timeout($c, 5);
    $first = (string)fgets($c);
    $hdrs = [];
    while (($l = fgets($c)) !== false && $l !== "\r\n") {
        $i = strpos($l, ':');
        if ($i !== false) {
            $hdrs[strtolower(trim(substr($l, 0, $i)))] = trim(substr($l, $i + 1));
        }
    }
    $len = (int)($hdrs['content-length'] ?? 0);
    $body = '';
    while (strlen($body) < $len && !feof($c)) {
        $body .= (string)fread($c, $len - strlen($body));
    }
    [$method, $path] = array_pad(explode(' ', $first), 2, '');
    $send = static function (string $statusLine) use ($c): void {
        fwrite($c, "$statusLine\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
    };
    if ($path === '/echo') {
        $send(sprintf('HTTP/1.1 418 m=%s ct=%s xa=%s b=%s', $method, $hdrs['content-type'] ?? '-', $hdrs['x-a'] ?? '-', str_replace(["\r", "\n"], '~', $body)));
    } elseif ($path === '/ok') {
        $send('HTTP/1.1 200 OK');
    } elseif ($path === '/s300') {
        $send('HTTP/1.1 300 Multiple Choices');
    } elseif ($path === '/s503') {
        $send('HTTP/1.1 503 Service Unavailable');
    } elseif ($path === '/s042') {
        $send('HTTP/1.1 042 Odd');
    } elseif ($path === '/xline') {
        $send('XHTTP/1.1 200 OK');
    } elseif ($path === '/s2000') {
        $send('HTTP/1.1 2000 Big');
    }
    // '/silent' (and anything else): close without a status line
    @fclose($c);
}
PHP;

    private static function port(): int
    {
        if (self::$server !== null) {
            return self::$server[1];
        }
        self::$dir = sys_get_temp_dir() . '/pca-kill18b-' . bin2hex(random_bytes(6));
        mkdir(self::$dir);
        file_put_contents(self::$dir . '/responder.php', self::RESPONDER);
        $null = PrivateFile::nullDevice();
        $proc = proc_open([PHP_BINARY, self::$dir . '/responder.php'], [0 => ['file', $null, 'r'], 1 => ['pipe', 'w'], 2 => ['file', $null, 'w']], $pipes);
        self::assertIsResource($proc);
        $port = (int)trim((string)fgets($pipes[1]));
        self::assertGreaterThan(0, $port, 'the responder did not start');
        self::$server = [$proc, $port];
        return $port;
    }

    public static function tearDownAfterClass(): void
    {
        if (self::$server !== null) {
            proc_terminate(self::$server[0]);
            proc_close(self::$server[0]);
            self::$server = null;
        }
        if (self::$dir !== '') {
            @unlink(self::$dir . '/responder.php');
            @rmdir(self::$dir);
            self::$dir = '';
        }
    }

    private static function deliver(string $path, array $opts = []): array
    {
        $sink = Siem::httpSink('http://127.0.0.1:' . self::port() . $path, 'cef', $opts + ['timeoutMs' => 5000]);
        return ($sink->deliver)([['line' => 'a'], ['line' => 'b']]);
    }

    /** The request: POST, the content type, every configured header as `name: value`, the joined lines as the body. */
    public function testTheRequestIsSentAsConfigured(): void
    {
        error_clear_last();
        $this->assertSame(['ok' => false, 'error' => 'HTTP 418 m=POST ct=text/plain; charset=utf-8 xa=b b=a~b'], self::deliver('/echo', ['headers' => ['x-a' => 'b']]));
        // an error status is read as a response (ignore_errors), not as a failed open
        $this->assertNull(error_get_last());
    }

    public function testStatusClasses(): void
    {
        $this->assertSame(['ok' => true], self::deliver('/ok'));
        $this->assertSame(['ok' => false, 'error' => 'HTTP 300 Multiple Choices'], self::deliver('/s300'));
        $this->assertSame(['ok' => false, 'error' => 'HTTP 503 Service Unavailable'], self::deliver('/s503'));
        $this->assertSame(['ok' => false, 'error' => 'HTTP 42 Odd'], self::deliver('/s042'));
    }

    public function testStatusLineIsParsedWhole(): void
    {
        // a line that does not start with HTTP/, or a four-digit code, is no status: 0
        $this->assertSame(['ok' => false, 'error' => 'HTTP 0'], self::deliver('/xline'));
        $this->assertSame(['ok' => false, 'error' => 'HTTP 0'], self::deliver('/s2000'));
    }

    /** A relative URL is opened as given, never searched for on the include path. */
    public function testTheIncludePathIsNotSearched(): void
    {
        $dir = sys_get_temp_dir() . '/pca-kill18b-inc-' . bin2hex(random_bytes(6));
        mkdir($dir);
        $name = 'pca-kill18b-probe-' . bin2hex(random_bytes(6)) . '.txt';
        file_put_contents("$dir/$name", 'x');
        $old = set_include_path($dir);
        try {
            $sink = Siem::httpSink($name, 'cef');
            $this->assertSame(['ok' => false, 'error' => 'delivery timed out'], ($sink->deliver)([['line' => 'a']]));
        } finally {
            set_include_path((string)$old);
            unlink("$dir/$name");
            rmdir($dir);
        }
    }

    public function testNoStatusLineIsATimeout(): void
    {
        $this->assertSame(['ok' => false, 'error' => 'delivery timed out'], self::deliver('/silent'));
    }
}
