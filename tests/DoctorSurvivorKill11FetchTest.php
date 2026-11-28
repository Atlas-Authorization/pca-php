<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Doctor.php';

use Atlas\Pca\Doctor;
use PHPUnit\Framework\TestCase;

/** The doctor's default HTTP client against a local one-shot server: the request it sends and the response it reads back. */
final class DoctorSurvivorKill11FetchTest extends TestCase
{
    /** Child server: prints its port, answers each connection with the next canned response ({REQ} = base64 of the request head). */
    private const SERVER = <<<'SRV'
$s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($s === false) {
    fwrite(STDERR, $errstr);
    exit(1);
}
$name = (string) stream_socket_get_name($s, false);
fwrite(STDOUT, substr($name, (int) strrpos($name, ':') + 1) . "\n");
foreach ($responses as $resp) {
    $c = @stream_socket_accept($s, 5);
    if ($c === false) {
        break;
    }
    $req = '';
    while (!str_contains($req, "\r\n\r\n")) {
        $b = fread($c, 8192);
        if ($b === false || $b === '') {
            break;
        }
        $req .= $b;
    }
    fwrite($c, str_replace('{REQ}', base64_encode(explode("\r\n\r\n", $req)[0]), $resp));
    fclose($c);
}
SRV;

    /** @return array{0:resource,1:array,2:int} */
    private static function serve(array $responses): array
    {
        $code = '$responses = ' . var_export($responses, true) . ";\n" . self::SERVER;
        $p = proc_open([PHP_BINARY, '-d', 'display_errors=stderr', '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        $port = (int) trim((string) fgets($pipes[1]));
        self::assertGreaterThan(0, $port);
        return [$p, $pipes, $port];
    }

    private static function stop(array $srv): void
    {
        proc_terminate($srv[0]);
        fclose($srv[1][1]);
        fclose($srv[1][2]);
        proc_close($srv[0]);
    }

    private static function closedPort(): int
    {
        $s = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($s);
        $name = (string) stream_socket_get_name($s, false);
        fclose($s);
        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }

    /** The method, path and every header go out as `Name: value`; the status and the lower-cased, trimmed headers come back exactly. */
    public function testRequestAndResponseShape(): void
    {
        $srv = self::serve(["HTTP/1.1 200 OK:fine\r\nX-Req: {REQ}\r\nX-Mixed-Case: A b\r\nX-Tight:abc\r\nX-Pad:   v  \r\nNoColonLine\r\n"
            . "Content-Length: 0\r\nConnection: close\r\n\r\n"]);
        try {
            $r = Doctor::defaultFetch("http://127.0.0.1:{$srv[2]}/p?q=1", 'HEAD', ['X-Probe' => 'abc', 'X-Two' => '2'], 5000.0);
        } finally {
            self::stop($srv);
        }
        self::assertSame(['status', 'headers'], array_keys($r));
        self::assertSame(200, $r['status']);
        $req = (string) base64_decode((string) ($r['headers']['x-req'] ?? ''), true);
        self::assertStringStartsWith('HEAD /p?q=1 HTTP/1.', $req);
        self::assertStringContainsString("\r\nX-Probe: abc\r\n", $req . "\r\n");
        self::assertStringContainsString("\r\nX-Two: 2\r\n", $req . "\r\n");
        unset($r['headers']['x-req']);
        self::assertSame(['x-mixed-case' => 'A b', 'x-tight' => 'abc', 'x-pad' => 'v', 'content-length' => '0', 'connection' => 'close'], $r['headers']);
    }

    /** A redirect is returned as it is, never followed. */
    public function testRedirectIsNotFollowed(): void
    {
        $srv = self::serve([
            "HTTP/1.1 302 Found\r\nLocation: /next\r\nX-Hop: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nX-Hop: 2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ]);
        try {
            $r = Doctor::defaultFetch("http://127.0.0.1:{$srv[2]}/", 'GET', [], 5000.0);
        } finally {
            self::stop($srv);
        }
        self::assertSame(['status' => 302, 'headers' => ['location' => '/next', 'x-hop' => '1', 'content-length' => '0', 'connection' => 'close']], $r);
    }

    /** An error status is a response; a status line whose code is not three digits right after the protocol reads as 0. */
    public function testErrorAndUnreadableStatus(): void
    {
        $srv = self::serve(["HTTP/1.1 404 Not Found\r\nX-K: v\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"]);
        try {
            $r = Doctor::defaultFetch("http://127.0.0.1:{$srv[2]}/", 'GET', [], 5000.0);
        } finally {
            self::stop($srv);
        }
        self::assertSame(['status' => 404, 'headers' => ['x-k' => 'v', 'content-length' => '0', 'connection' => 'close']], $r);

        $srv = self::serve(["HTTP/1.1 2x0 HTTP/1.1 200\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"]);
        try {
            $r = Doctor::defaultFetch("http://127.0.0.1:{$srv[2]}/", 'GET', [], 5000.0);
        } finally {
            self::stop($srv);
        }
        self::assertSame(['status' => 0, 'headers' => ['content-length' => '0', 'connection' => 'close']], $r);
    }

    /** A refused connection throws with the stream's own error; a relative name is never looked up on the include path. */
    public function testTransportFailuresThrowTheStreamError(): void
    {
        $dir = sys_get_temp_dir() . '/pca-k11-inc-' . bin2hex(random_bytes(6));
        mkdir($dir);
        $name = 'pca-k11-include-probe-' . bin2hex(random_bytes(6)) . '.txt';
        file_put_contents("$dir/$name", 'local file');
        $oldPath = get_include_path();
        set_error_handler(static fn(): bool => false);
        $msgs = [];
        try {
            foreach (["http://127.0.0.1:" . self::closedPort() . '/', $name] as $i => $url) {
                if ($i === 1) {
                    set_include_path($dir);
                }
                error_clear_last();
                try {
                    Doctor::defaultFetch($url, 'GET', [], 5000.0);
                    $msgs[] = 'no exception';
                } catch (\RuntimeException $e) {
                    $msgs[] = $e->getMessage();
                }
            }
        } finally {
            restore_error_handler();
            set_include_path($oldPath);
            unlink("$dir/$name");
            rmdir($dir);
        }
        self::assertStringStartsWith('file_get_contents(http://127.0.0.1:', $msgs[0]);
        self::assertStringStartsWith("file_get_contents($name)", $msgs[1]);
    }

    /** A server that accepts but never answers is given up on after the timeout. */
    public function testSilentServerTimesOut(): void
    {
        $s = stream_socket_server('tcp://127.0.0.1:0');
        self::assertIsResource($s);
        $name = (string) stream_socket_get_name($s, false);
        $port = substr($name, (int) strrpos($name, ':') + 1);
        try {
            Doctor::defaultFetch("http://127.0.0.1:$port/", 'GET', [], 200.0);
            self::fail('a silent server must time out');
        } catch (\RuntimeException $e) {
            self::assertNotSame('', get_class($e));
        } finally {
            fclose($s);
        }
    }
}
