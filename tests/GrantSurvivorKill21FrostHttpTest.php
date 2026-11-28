<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Frost;
use Atlas\Pca\FrostHttp;
use Atlas\Pca\GuardianSignerService;
use Atlas\Pca\HttpSignerTransport;
use Atlas\Pca\Obj;
use Atlas\Pca\SignerHttpServer;
use PHPUnit\Framework\TestCase;

/** The FROST HTTP transport: listener binding, the request framing and size bounds, the serve loop, and the client's response checks. */
final class GrantSurvivorKill21FrostHttpTest extends TestCase
{
    private const BODY = '{"typ":"pca.frost.round1.v1","session_id":"s"}';

    protected function tearDown(): void
    {
        HttpSignerTransport::$clockHook = null;
    }

    private static function svc(?\Closure $now = null): GuardianSignerService
    {
        $kg = Frost::trustedDealerKeygen(1, 1);
        return new GuardianSignerService(['identifier' => 1, 'share' => $kg['participantShares'][0]['share'], 'groupPublicKey' => $kg['groupPublicKey'],
            'threshold' => 1, 'policyAuthorityPublicKey' => str_repeat("\x07", 32)] + ($now !== null ? ['now' => $now] : []));
    }

    private static function post(string $body = self::BODY): string
    {
        return "POST /round1 HTTP/1.1\r\ncontent-length: " . strlen($body) . "\r\n\r\n$body";
    }

    /** One request through the private connection handler over an in-process socket pair; returns everything written back. */
    private static function exchange(SignerHttpServer $srv, string $request): string
    {
        [$a, $b] = stream_socket_pair(PHP_OS_FAMILY === 'Windows' ? STREAM_PF_INET : STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        fwrite($a, $request);
        stream_socket_shutdown($a, STREAM_SHUT_WR);
        (new \ReflectionMethod(SignerHttpServer::class, 'handle'))->invoke($srv, $b);
        stream_set_blocking($b, false);
        stream_get_contents($b); // drain what the handler left unread
        fclose($b);
        $out = (string)stream_get_contents($a);
        fclose($a);
        return $out;
    }

    /** [status line, json body] of a framed response, checking the header block and content-length exactly. */
    private function parse(string $resp): array
    {
        $ok = preg_match('#\A(HTTP/1\.1 \d+ [A-Za-z ]+)\r\ncontent-type: application/json\r\ncontent-length: (\d+)\r\nconnection: close\r\n\r\n(.*)\z#s', $resp, $m);
        $this->assertSame(1, $ok, "unexpected response framing: $resp");
        $this->assertSame((int)$m[2], strlen($m[3]));
        return [$m[1], $m[3]];
    }

    private function assertRound1Ok(string $resp): void
    {
        [$status, $json] = $this->parse($resp);
        $this->assertSame('HTTP/1.1 200 OK', $status);
        $this->assertTrue(json_decode($json, true)['ok']);
    }

    /** A header block padded to exactly `$total` bytes (terminator included), then the body. */
    private static function padded(int $total, string $body = self::BODY): string
    {
        $pre = "POST /round1 HTTP/1.1\r\ncontent-length: " . strlen($body) . "\r\nx-pad: ";
        return $pre . str_repeat('a', $total - strlen($pre) - 4) . "\r\n\r\n" . $body;
    }

    // ---- binding -------------------------------------------------------------------------------------------------------

    /** The default bind takes an ephemeral port, reports the real one, holds it exclusively, and close() releases it. */
    public function testBindPortAndClose(): void
    {
        $svc = self::svc();
        $srv = SignerHttpServer::bind($svc);
        $name = (string)stream_socket_get_name((new \ReflectionProperty(SignerHttpServer::class, 'socket'))->getValue($srv), false);
        $this->assertSame((int)substr($name, (int)strrpos($name, ':') + 1), $srv->port);
        $this->assertGreaterThan(1023, $srv->port);
        $this->assertSame("http://127.0.0.1:{$srv->port}", $srv->url);
        $e = null;
        try {
            SignerHttpServer::bind($svc, '127.0.0.1', $srv->port);
        } catch (\Throwable $e) {
        }
        $this->assertInstanceOf(\RuntimeException::class, $e);
        $this->assertStringStartsWith("startSignerHttpServer: could not listen on 127.0.0.1:{$srv->port} (", $e->getMessage());
        $srv->close();
        $again = SignerHttpServer::bind($svc, '127.0.0.1', $srv->port);
        $this->assertSame($srv->port, $again->port);
        $again->close();
        $f = FrostHttp::startSignerHttpServer($svc);
        $this->assertGreaterThan(1023, $f->port);
        $f->close();
    }

    // ---- request framing -----------------------------------------------------------------------------------------------

    /** A POST is answered 200 with the exact framing; the length may carry NUL padding, later headers and trailing bytes are ignored. */
    public function testHandleFramesARound1Request(): void
    {
        $srv = SignerHttpServer::bind(self::svc());
        $len = strlen(self::BODY);
        $req = "POST /round1 HTTP/1.1\r\ncontent-length:\x00$len\r\nx-after: zzzzzzzzzzzzzzzzzzzz\r\n\r\n" . self::BODY . 'XX';
        $this->assertRound1Ok(self::exchange($srv, $req));
        $srv->close();
    }

    /** Status lines carry their reason phrases and the refusal bodies are exact. */
    public function testHandleRefusalResponses(): void
    {
        $srv = SignerHttpServer::bind(self::svc());
        $this->assertSame(['HTTP/1.1 405 Method Not Allowed', '{"ok":false,"reason":"method not allowed"}'],
            $this->parse(self::exchange($srv, "GET /round1 HTTP/1.1\r\n\r\n")));
        $this->assertSame(['HTTP/1.1 404 Not Found', '{"ok":false,"reason":"not found"}'], $this->parse(self::exchange($srv, "POST /other HTTP/1.1\r\n\r\n")));
        $this->assertSame(['HTTP/1.1 400 Bad Request', '{"identifier":1,"ok":false,"reason":"request body too large","refused":true}'],
            $this->parse(self::exchange($srv, "POST /round1 HTTP/1.1\r\ncontent-length: " . (SignerHttpServer::BODY_LIMIT + 1) . "\r\n\r\n")));
        // no content-length: the body is empty, bytes after the header block are ignored
        $this->assertSame(['HTTP/1.1 200 OK', '{"identifier":1,"ok":false,"reason":"malformed round-1 request"}'],
            $this->parse(self::exchange($srv, "POST /round1 HTTP/1.1\r\n\r\nXY")));
        // a header-like line inside the body is not a header
        [$status] = $this->parse(self::exchange($srv, "POST /round1 HTTP/1.1\r\ncontent-length: 21\r\n\r\n{}\r\ncontent-length: 2"));
        $this->assertSame('HTTP/1.1 400 Bad Request', $status);
        $srv->close();
    }

    /** A header block may grow to the read that crosses 16384 bytes: one ending exactly at 20480 is served. */
    public function testHandleHeaderLimitBoundary(): void
    {
        $srv = SignerHttpServer::bind(self::svc());
        $this->assertRound1Ok(self::exchange($srv, self::padded(20480)));
        $srv->close();
    }

    /** A body split across reads is reassembled; a length of exactly BODY_LIMIT is read (the peer hanging up gets no answer). */
    public function testHandleBodyReadsAndLimitBoundary(): void
    {
        $srv = SignerHttpServer::bind(self::svc());
        $this->assertRound1Ok(self::exchange($srv, self::padded(20470)));
        $this->assertSame('', self::exchange($srv, "POST /round1 HTTP/1.1\r\ncontent-length: " . SignerHttpServer::BODY_LIMIT . "\r\n\r\n"));
        $srv->close();
    }

    // ---- the serve loop ------------------------------------------------------------------------------------------------

    private static function client(int $port, string $request)
    {
        $c = stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 5);
        fwrite($c, $request);
        stream_socket_shutdown($c, STREAM_SHUT_WR);
        stream_set_timeout($c, 5);
        return $c;
    }

    /** keepGoing is consulted before every connection, close() during a request ends the loop, and an idle wait goes round again. */
    public function testServeLoop(): void
    {
        // close() from inside the handled request: the loop ends without asking keepGoing again
        $srv = null;
        $srv = SignerHttpServer::bind(self::svc(static function () use (&$srv): int {
            $srv->close();
            return 0;
        }));
        $c = self::client($srv->port, self::post());
        $calls = 0;
        $srv->serve(static function () use (&$calls): bool {
            if (++$calls >= 3) {
                throw new \RuntimeException('runaway serve loop');
            }
            return $calls === 1;
        });
        $this->assertSame(1, $calls);
        $this->assertRound1Ok((string)stream_get_contents($c));
        fclose($c);

        // keepGoing false ends the loop; the served connection is already closed when it is asked
        $srv = null;
        $n = 0;
        $srv = SignerHttpServer::bind(self::svc(static function () use (&$srv, &$n): int {
            if (++$n >= 2) {
                $srv->close(); // only a runaway loop reaches the second connection
            }
            return 0;
        }));
        $a = self::client($srv->port, self::post());
        $b = self::client($srv->port, self::post('{"typ":"pca.frost.round1.v1","session_id":"t"}'));
        $calls = 0;
        $seen = null;
        $srv->serve(static function () use (&$calls, &$seen, $a): bool {
            if (++$calls >= 3) {
                throw new \RuntimeException('runaway serve loop');
            }
            if ($calls === 2) {
                $seen = [(string)stream_get_contents($a), feof($a)];
            }
            return $calls === 1;
        });
        $this->assertSame(2, $calls);
        $this->assertTrue($seen[1], 'the connection is closed once served');
        $this->assertRound1Ok($seen[0]);
        $this->assertSame(1, $n);
        $srv->close();
        fclose($a);
        fclose($b);

        // an idle wait (no connection) goes round and asks keepGoing again
        $srv = null;
        $srv = SignerHttpServer::bind(self::svc(static function () use (&$srv): int {
            $srv->close();
            return 0;
        }));
        $c = null;
        $calls = 0;
        $port = $srv->port;
        $srv->serve(static function () use (&$calls, &$c, $port): bool {
            if (++$calls >= 4) {
                throw new \RuntimeException('runaway serve loop');
            }
            if ($calls === 2) {
                $c = self::client($port, self::post());
            }
            return true;
        });
        $this->assertSame(2, $calls);
        $this->assertRound1Ok((string)stream_get_contents($c));
        fclose($c);
    }

    // ---- the client transport ------------------------------------------------------------------------------------------

    /** Only an http://host:port base URL is accepted; the factory keeps the identifier. */
    public function testTransportBaseUrl(): void
    {
        $e = null;
        try {
            new HttpSignerTransport('https://h:1', 1);
        } catch (\Throwable $e) {
        }
        $this->assertSame([\InvalidArgumentException::class, 'httpSignerTransport: baseUrl must be http://host:port'], [get_class($e), $e->getMessage()]);
        $this->assertSame(7, FrostHttp::httpSignerTransport('http://127.0.0.1:1', 7)->identifier());
    }

    /** A refused connection is a RuntimeException naming the connect failure. */
    public function testTransportCannotConnect(): void
    {
        $e = null;
        try {
            FrostHttp::httpSignerTransport('http://127.0.0.1:1', 1, 2000)->round1(Obj::of(['a' => 1]));
        } catch (\Throwable $e) {
        }
        $this->assertInstanceOf(\RuntimeException::class, $e);
        $this->assertStringStartsWith('httpSignerTransport: cannot connect (', $e->getMessage());
    }

    private static function drain($s): void
    {
        stream_set_timeout($s, 5);
        $buf = '';
        while (($e = strpos($buf, "\r\n\r\n")) === false) {
            $c = fread($s, 8192);
            if ($c === false || $c === '') {
                return;
            }
            $buf .= $c;
        }
        $need = $e + 4 + (preg_match('/content-length: (\d+)/i', $buf, $m) === 1 ? (int)$m[1] : 0);
        while (strlen($buf) < $need) {
            $c = fread($s, 8192);
            if ($c === false || $c === '') {
                return;
            }
            $buf .= $c;
        }
    }

    /**
     * One round1 call against a local listener that answers `$reply`: the clock seam answers from inside the transport's read
     * loop (its second reading), and that reading is `$late` seconds (the deadline is 10 s after a reading of 0).
     */
    private static function viaReply(string $reply, float $late = 0.0): mixed
    {
        $server = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $name = (string)stream_socket_get_name($server, false);
        $port = (int)substr($name, (int)strrpos($name, ':') + 1);
        $n = 0;
        HttpSignerTransport::$clockHook = static function () use (&$n, $server, $reply, $late): float {
            if (++$n === 2) {
                $acc = stream_socket_accept($server, 5);
                self::drain($acc);
                fwrite($acc, $reply);
                fclose($acc);
                return $late;
            }
            return 0.0;
        };
        try {
            return (new HttpSignerTransport("http://127.0.0.1:$port", 1, 10000))->round1(Obj::of(['a' => 1]));
        } catch (\Throwable $e) {
            return $e;
        } finally {
            fclose($server);
        }
    }

    /** The response must have a header block and an object body; the deadline is checked before every read. */
    public function testTransportResponseChecks(): void
    {
        $ok = self::viaReply("HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}");
        $this->assertInstanceOf(Obj::class, $ok);
        $this->assertTrue($ok->get('ok'));
        foreach (['garbage' => 'httpSignerTransport: malformed response', "HTTP/1.1 200 OK\r\n\r\n[1]" => 'httpSignerTransport: response is not an object'] as $reply => $msg) {
            $e = self::viaReply((string)$reply);
            $this->assertSame([\RuntimeException::class, $msg], [get_class($e), $e->getMessage()]);
        }
        $e = self::viaReply("HTTP/1.1 200 OK\r\n\r\n{\"ok\":true}", 1.0e9);
        $this->assertSame([\RuntimeException::class, 'httpSignerTransport: timed out'], [get_class($e), $e->getMessage()]);
    }
}
