<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/UndoServer.php';

use Atlas\Pca\PrivateFile;
use Atlas\Pca\UndoServer;
use Atlas\Pca\UndoVetoRelay;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills (group 24b) for the veto relay's default HTTP transport, against a loopback responder that writes exact bytes:
 * the request it sends, no redirect following, the body of a non-2xx answer, the status-line parse and the 2xx boundary.
 */
final class PolicySurvivorKill24bUndoServerTest extends TestCase
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
    $hdr = [];
    while (($l = fgets($c)) !== false && $l !== "\r\n") {
        $p = strpos($l, ':');
        if ($p !== false) {
            $hdr[strtolower(trim(substr($l, 0, $p)))] = trim(substr($l, $p + 1));
        }
    }
    [$method, $path] = array_pad(explode(' ', $first), 2, '/');
    $send = static function (string $status, array $lines, string $body) use ($c): void {
        fwrite($c, "HTTP/1.1 $status\r\n" . implode('', array_map(static fn(string $l): string => "$l\r\n", $lines))
            . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
    };
    $auth = $hdr['authorization'] ?? '';
    $accept = $hdr['accept'] ?? '';
    if ($path === '/echo') {
        $send('200 OK', [], "$method|$auth|$accept");
    } elseif ($path === '/s300') {
        $send('300 Multiple Choices', [], 'm');
    } elseif ($path === '/nf') {
        $send('404 Not Found', [], 'nf');
    } elseif ($path === '/redir') {
        $send('302 Found', ['Location: /echo'], 'moved');
    } elseif ($path === '/via') {
        $send('200 OK', ['X-Via: HTTP/1.0 404 upstream'], 'v');
    } elseif ($path === '/v1/pca/undo/vetoes?limit=200') {
        $ok = $auth === 'Bearer sk_test' && $accept === 'application/json';
        $send($ok ? '200 OK' : '401 Unauthorized', [], $ok ? '{"data":[{"record_id":"r1","veto":{"token":"t1","at":42}}]}' : 'no');
    } else {
        $send('500 Internal Server Error', [], 'unknown');
    }
    @fclose($c);
}
PHP;

    private static function port(): int
    {
        if (self::$server !== null) {
            return self::$server[1];
        }
        self::$dir = sys_get_temp_dir() . '/pca-kill24b-' . bin2hex(random_bytes(6));
        mkdir(self::$dir);
        file_put_contents(self::$dir . '/responder.php', self::RESPONDER);
        $null = PrivateFile::nullDevice();
        $proc = proc_open([PHP_BINARY, self::$dir . '/responder.php'],
            [0 => ['file', $null, 'r'], 1 => ['pipe', 'w'], 2 => ['file', $null, 'w']], $pipes);
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
            foreach (glob(self::$dir . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir(self::$dir);
            self::$dir = '';
        }
    }

    /** @return array{ok:bool,status:int,body:string} */
    private static function get(string $path, string $method = 'GET'): array
    {
        return UndoVetoRelay::defaultFetch('http://127.0.0.1:' . self::port() . $path,
            ['method' => $method, 'headers' => ['authorization' => 'Bearer sk_test', 'accept' => 'application/json']]);
    }

    /** The transport sends the requested method and every header, and reads a 2xx answer as ok with its integer status and body. */
    public function testSendsMethodAndHeadersAndReadsA2xx(): void
    {
        $this->assertSame(['ok' => true, 'status' => 200, 'body' => 'DELETE|Bearer sk_test|application/json'], self::get('/echo', 'DELETE'));
    }

    /** A redirect is not followed: the 302 itself is the (not ok) answer. */
    public function testRedirectIsNotFollowed(): void
    {
        $this->assertSame(['ok' => false, 'status' => 302, 'body' => 'moved'], self::get('/redir'));
    }

    /** A 4xx answer keeps its status and its body; 300 is already outside the 2xx range. */
    public function testNon2xxKeepsStatusAndBody(): void
    {
        $this->assertSame(['ok' => false, 'status' => 404, 'body' => 'nf'], self::get('/nf'));
        $this->assertSame(['ok' => false, 'status' => 300, 'body' => 'm'], self::get('/s300'));
    }

    /** Only a line that starts with HTTP/ is a status line: a header value that holds one does not change the status. */
    public function testStatusComesFromTheStatusLineOnly(): void
    {
        $this->assertSame(['ok' => true, 'status' => 200, 'body' => 'v'], self::get('/via'));
    }

    /** A body read without any status line (a data: URL), even right after an HTTP answer, has status 0 and is not ok. */
    public function testStatuslessBodyIsNotOk(): void
    {
        $this->assertTrue(self::get('/echo')['ok']);
        $this->assertSame(['ok' => false, 'status' => 0, 'body' => 'abc'],
            UndoVetoRelay::defaultFetch('data:text/plain,abc', ['method' => 'GET', 'headers' => []]));
    }

    /** A target that cannot be opened is an empty, not ok answer with status 0, and a relative target is never searched for on the include path. */
    public function testUnopenableTargetAndNoIncludePath(): void
    {
        self::port();
        $inc = self::$dir;
        $rel = 'pca-kill24b-rel-' . bin2hex(random_bytes(6));
        mkdir("$inc/$rel");
        file_put_contents("$inc/$rel/v", 'local');
        $old = get_include_path();
        set_include_path($inc);
        try {
            $r = UndoVetoRelay::defaultFetch("$rel/v", ['method' => 'GET', 'headers' => []]);
        } finally {
            set_include_path($old);
            @unlink("$inc/$rel/v");
            @rmdir("$inc/$rel");
        }
        $this->assertSame(['ok' => false, 'status' => 0, 'body' => ''], $r);
    }

    /** The default transport's timeout is five seconds. */
    public function testTimeoutIsFiveSeconds(): void
    {
        $this->assertSame(5, UndoVetoRelay::FETCH_TIMEOUT_S);
    }

    /** End to end: a relay without an injected fetch reads the vetoes over the default transport with its secret key. */
    public function testRelayUsesTheDefaultTransport(): void
    {
        $r = UndoServer::hostedUndoVetoRelay('http://127.0.0.1:' . self::port() . '/', 'sk_test');
        $this->assertSame([['id' => 'r1', 'token' => 't1', 'at' => 42]], $r->pending());
    }
}
