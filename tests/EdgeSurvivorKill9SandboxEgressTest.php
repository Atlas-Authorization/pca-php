<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sandbox;
use Atlas\Pca\SandboxEgress;
use Atlas\Pca\SandboxEgressPolicy;
use Atlas\Pca\SandboxReceiptLog;
use PHPUnit\Framework\TestCase;

/** A receipt signer failure whose class name is longer than the 64-character receipt reason keeps. */
final class Kill9EgressSignerFailureWithALongNameThatPassesTheReceiptCut extends \LogicException
{
}

/**
 * Egress admission (claim) and the forward proxy over loopback sockets. A real upstream runs in a forked copy that accepts one
 * connection on a listener bound before the fork, so the blocking proxy can be driven from this process.
 */
final class EdgeSurvivorKill9SandboxEgressTest extends TestCase
{
    private static function op(): Obj
    {
        return Obj::of(['verb' => 'read', 'resource' => 'r', 'params' => new Obj()]);
    }

    private static function egressResult(): Obj
    {
        return Obj::of(['allow' => true, 'operation' => Obj::of(['id' => 'op1', 'verb' => 'read', 'resource' => 'r',
            'params_digest' => Pca::hashCanonical(new Obj())])]);
    }

    /** @param array<string,mixed> $t */
    private static function admit(SandboxEgressPolicy $p, array $t, mixed $opts = null): void
    {
        $p->admit(self::egressResult(), self::op(), static fn() => Obj::of($t), $opts);
    }

    /** @return array<string,mixed> */
    private static function base(array $over = []): array
    {
        return [...['method' => 'GET', 'scheme' => 'http', 'host' => 'h.example', 'path' => '/p'], ...$over];
    }

    private static function claim(SandboxEgressPolicy $p, string $method, string $url, ?string $body = null): Obj
    {
        $req = ['method' => $method, 'url' => $url];
        if ($body !== null) {
            $req['body'] = new Bytes($body);
        }
        return $p->claim(Obj::of($req));
    }

    /** @return array{0:string,1:string} class and message of what $f throws */
    private static function thrown(\Closure $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [$e::class, $e->getMessage()];
        }
        return ['', ''];
    }

    // ---- admission and claim --------------------------------------------------------------------------------------------

    public function testMalformedTemplatesAreRefusedWithTheirOwnError(): void
    {
        $p = new SandboxEgressPolicy();
        $this->assertSame([\InvalidArgumentException::class, 'no_egress_for_operation'],
            self::thrown(static fn() => $p->admit(self::egressResult(), self::op(), static fn() => null)));
        $this->assertSame([\TypeError::class, 'template is not an object'],
            self::thrown(static fn() => $p->admit(self::egressResult(), self::op(), static fn() => 'x')));
        $this->assertSame([\TypeError::class, 'host.toLowerCase is not a function'], self::thrown(static fn() => self::admit($p, self::base(['host' => 5]))));
        $this->assertSame([\TypeError::class, 't.path.startsWith is not a function'], self::thrown(static fn() => self::admit($p, self::base(['path' => 5]))));
        $this->assertSame([\TypeError::class, 'method.toUpperCase is not a function'],
            self::thrown(static fn() => $p->claim(Obj::of(['method' => 5, 'url' => 'http://h.example/p']))));
    }

    /** Credentials are refused wherever the fragment or query cut leaves them; an "@" in the query is not userinfo. */
    public function testUserinfoDetection(): void
    {
        $p = new SandboxEgressPolicy();
        foreach (['http://u@h.example/#', 'http:u@h.example/#', 'http://u@h.example/?x', 'http:u@h.example/?x', 'http://:x@h.example/'] as $url) {
            $this->assertSame('bad_url', self::claim($p, 'GET', $url)->get('reason'), $url);
        }
        $this->assertSame('no_admission', self::claim($p, 'GET', 'http://h.example?a@b')->get('reason'));
    }

    public function testBracketedIpv6HostAndPort(): void
    {
        $p = new SandboxEgressPolicy();
        self::admit($p, self::base(['host' => '::1', 'port' => 8080]));
        $this->assertTrue(self::claim($p, 'GET', 'http://[::1]:8080/p')->get('allow'));
    }

    /** An admission that does not fit is skipped, never the end of the search: a later one still matches. */
    public function testAMismatchMovesOnToTheNextAdmission(): void
    {
        $cases = [
            [self::base(['tunnel' => true]), null, 'GET', null],
            [self::base(['method' => 'POST']), null, 'GET', null],
            [self::base(['scheme' => 'https']), null, 'GET', null],
            [self::base(['query' => 'x=1']), null, 'GET', null],
            [self::base(['body_sha256' => Sandbox::sha256B64u('zzz')]), null, 'GET', null],
            [self::base(['method' => 'POST']), null, 'POST', 'abc'],
            [self::base(), Obj::of(['expiresAt' => 0]), 'GET', null],
        ];
        foreach ($cases as $k => [$bad, $opts, $method, $body]) {
            $p = new SandboxEgressPolicy();
            self::admit($p, $bad, $opts);
            $good = self::base(['method' => $method]);
            if ($body !== null) {
                $good['body_sha256'] = Sandbox::sha256B64u($body);
            }
            self::admit($p, $good);
            $d = self::claim($p, $method, 'http://h.example/p', $body);
            $this->assertSame([true, 'op1'], [$d->get('allow'), $d->get('op_id')], "case $k");
        }
    }

    // ---- the proxy without an upstream ----------------------------------------------------------------------------------

    private static function roundTrip(SandboxEgress $proxy, string $request, bool $endWrite = false): string
    {
        $proxy->start();
        try {
            $client = stream_socket_client('tcp://127.0.0.1:' . $proxy->port, $errno, $errstr, 2.0);
            self::assertNotFalse($client, (string)$errstr);
            fwrite($client, $request);
            if ($endWrite) {
                stream_socket_shutdown($client, STREAM_SHUT_WR);
            }
            self::assertTrue($proxy->serveOne(2.0));
            $resp = (string)stream_get_contents($client);
            fclose($client);
            return $resp;
        } finally {
            $proxy->close();
        }
    }

    private static function denied(int $status, string $text, string $reason): string
    {
        $body = '{"error":"egress_denied","reason":"' . $reason . '"}';
        return "HTTP/1.1 $status $text\r\nconnection: close\r\ncontent-length: " . strlen($body) . "\r\ncontent-type: application/json\r\n\r\n" . $body;
    }

    private const BAD_GATEWAY = "HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";

    private static function closedPort(): int
    {
        $s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($s, (string)$errstr);
        $name = (string)stream_socket_get_name($s, false);
        fclose($s);
        return (int)substr($name, (int)strrpos($name, ':') + 1);
    }

    /** @return array<string,mixed> */
    private static function subject(SandboxReceiptLog $log, int $i = 0): array
    {
        $s = $log->entries[$i]->get('subject');
        return ['op_id' => $s->get('op_id'), 'verb' => $s->get('verb'), 'resource' => $s->get('resource'), 'params_digest' => $s->get('params_digest')];
    }

    public function testRefusalResponseAndReceipt(): void
    {
        $log = new SandboxReceiptLog();
        $resp = self::roundTrip(new SandboxEgress(new SandboxEgressPolicy(), $log), "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
        $this->assertSame(self::denied(403, 'Forbidden', 'no_admission'), $resp);
        $this->assertCount(1, $log->entries);
        $e = $log->entries[0];
        $this->assertSame(['egress_default_deny', 'egress', 'refused', 'no_admission'], [$e->get('runtime_class'), $e->get('kind'), $e->get('outcome'), $e->get('reason')]);
        $this->assertSame(['op_id' => '', 'verb' => '', 'resource' => 'GET http://example.com/', 'params_digest' => ''], self::subject($log));
    }

    public function testRefusedResourceIsCutAt256Characters(): void
    {
        $log = new SandboxReceiptLog();
        $url = 'http://example.com/' . str_repeat('é', 300);
        self::roundTrip(new SandboxEgress(new SandboxEgressPolicy(), $log), "GET $url HTTP/1.1\r\n\r\n");
        $this->assertSame('GET http://example.com/' . str_repeat('é', 233), self::subject($log)['resource']);
    }

    public function testLowercaseConnectIsATunnelRequest(): void
    {
        $log = new SandboxReceiptLog();
        $resp = self::roundTrip(new SandboxEgress(new SandboxEgressPolicy(), $log), "connect example.com:443 HTTP/1.1\r\n\r\n");
        $this->assertSame(self::denied(403, 'Forbidden', 'no_admission'), $resp);
        $this->assertSame('CONNECT example.com:443', self::subject($log)['resource']);
    }

    public function testHeadParsing(): void
    {
        $line = "GET http://example.com/ HTTP/1.1\r\n";
        $cases = [
            [$line . "nocolon\r\n\r\n", self::denied(400, 'Bad Request', 'bad_header')],
            [$line . ":x\r\n\r\n", self::denied(400, 'Bad Request', 'bad_header')],
            [$line . "a b: c\r\n\r\n", self::denied(400, 'Bad Request', 'bad_header')],
            [$line . "a\x0B: v\r\n\r\n", self::denied(400, 'Bad Request', 'bad_header')],
            [$line . "content-length: 1x\r\n\r\n", self::denied(400, 'Bad Request', 'bad_content_length')],
            [$line . "content-length: 1\r\ncontent-length: 2\r\n\r\n", self::denied(400, 'Bad Request', 'duplicate_content_length')],
            [$line . "content-length:\r\n\r\n", self::denied(403, 'Forbidden', 'no_admission')],
            [$line . "content-length: 0\r\n\r\n", self::denied(403, 'Forbidden', 'no_admission')],
            [$line . 'x: ' . str_repeat('a', 65495) . "\r\n\r\n", self::denied(403, 'Forbidden', 'no_admission')],
            [$line . 'x: ' . str_repeat('a', 65496) . "\r\n\r\n", self::denied(431, 'Header Fields Too Large', 'head_too_large')],
        ];
        foreach ($cases as $k => [$req, $want]) {
            $this->assertSame($want, self::roundTrip(new SandboxEgress(new SandboxEgressPolicy(), new SandboxReceiptLog()), $req), "case $k");
        }
        // the head ends before "\r\n\r\n": the reader's default refusal
        $resp = self::roundTrip(new SandboxEgress(new SandboxEgressPolicy(), new SandboxReceiptLog()), $line, true);
        $this->assertSame(self::denied(400, 'Bad Request', 'bad_request'), $resp);
    }

    public function testBodyLimits(): void
    {
        $small = static fn() => new SandboxEgress(new SandboxEgressPolicy(), new SandboxReceiptLog(), maxBodyBytes: 5);
        $line = "POST http://example.com/ HTTP/1.1\r\n";
        $this->assertSame(self::denied(413, 'Payload Too Large', 'body_too_large'), self::roundTrip($small(), $line . "content-length: 6\r\n\r\n"));
        $this->assertSame(self::denied(413, 'Payload Too Large', 'body_too_large'), self::roundTrip($small(), $line . "content-length:12\r\n\r\n"));
        $this->assertSame(self::denied(403, 'Forbidden', 'no_admission'), self::roundTrip($small(), $line . "content-length: 5\r\n\r\nabcde"));
        // the default limit is 1 MiB
        $dflt = static fn() => new SandboxEgress(new SandboxEgressPolicy(), new SandboxReceiptLog());
        $this->assertSame(self::denied(413, 'Payload Too Large', 'body_too_large'), self::roundTrip($dflt(), $line . "content-length: 1048577\r\n\r\n"));
        $this->assertSame('', self::roundTrip($dflt(), $line . "content-length: 1048576\r\n\r\n", true));
    }

    /** A body read in several chunks is hashed whole; the admitted private upstream is then refused (default deny of private addresses). */
    public function testWholeBodyIsClaimedAndPrivateUpstreamRefused(): void
    {
        $body = str_repeat('x', 10000);
        $p = new SandboxEgressPolicy();
        self::admit($p, ['method' => 'POST', 'scheme' => 'http', 'host' => '127.0.0.1', 'path' => '/u', 'body_sha256' => Sandbox::sha256B64u($body)]);
        $log = new SandboxReceiptLog();
        $resp = self::roundTrip(new SandboxEgress($p, $log), "POST http://127.0.0.1/u HTTP/1.1\r\ncontent-length: 10000\r\n\r\n" . $body);
        $this->assertSame(self::BAD_GATEWAY, $resp);
        $this->assertCount(1, $log->entries);
        $this->assertSame(['error', 'upstream:EACCES'], [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
        $this->assertSame(['op_id' => 'op1', 'verb' => 'read', 'resource' => 'r', 'params_digest' => Pca::hashCanonical(new Obj())], self::subject($log));
    }

    public function testRefusedUpstreamConnection(): void
    {
        $port = self::closedPort();
        $p = new SandboxEgressPolicy();
        self::admit($p, ['method' => 'GET', 'scheme' => 'http', 'host' => '127.0.0.1', 'port' => $port, 'path' => '/']);
        $log = new SandboxReceiptLog();
        $resp = self::roundTrip(new SandboxEgress($p, $log, allowPrivate: true), "GET http://127.0.0.1:$port/ HTTP/1.1\r\n\r\n");
        $this->assertSame(self::BAD_GATEWAY, $resp);
        $this->assertCount(1, $log->entries);
        $this->assertSame(['error', 'upstream:error'], [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
    }

    /** @return array<string,mixed> */
    private static function tunnel(int $port): array
    {
        return ['method' => 'CONNECT', 'scheme' => 'https', 'host' => '127.0.0.1', 'port' => $port, 'path' => '/', 'tunnel' => true];
    }

    public function testTunnelUpstreamErrors(): void
    {
        $port = self::closedPort();
        foreach ([[false, 'upstream:EACCES'], [true, 'upstream:error']] as [$private, $reason]) {
            $p = new SandboxEgressPolicy();
            self::admit($p, self::tunnel($port));
            $log = new SandboxReceiptLog();
            $resp = self::roundTrip(new SandboxEgress($p, $log, allowPrivate: $private), "CONNECT 127.0.0.1:$port HTTP/1.1\r\n\r\n");
            $this->assertSame(self::BAD_GATEWAY, $resp);
            $this->assertCount(1, $log->entries);
            $this->assertSame(['error', $reason], [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
            $this->assertSame('r', self::subject($log)['resource']);
        }
    }

    public function testAnInternalErrorIsAnsweredWithBadGateway(): void
    {
        $log = new SandboxReceiptLog(null, static function (): never {
            throw new \LogicException('signer down');
        });
        $resp = self::roundTrip(new SandboxEgress(new SandboxEgressPolicy(), $log), "GET http://example.com/ HTTP/1.1\r\n\r\n");
        $this->assertSame(self::BAD_GATEWAY, $resp);
    }

    public function testListenerLifecycle(): void
    {
        $a = (new SandboxEgress(new SandboxEgressPolicy(), new SandboxReceiptLog()))->start();
        try {
            $this->assertGreaterThan(0, $a->port);
            $this->assertFalse($a->serveOne(0.01));
            [$cls, $msg] = self::thrown(static fn() => (new SandboxEgress(new SandboxEgressPolicy(), new SandboxReceiptLog(), listenPort: $a->port))->start());
            $this->assertSame(\RuntimeException::class, $cls);
            $this->assertStringStartsWith('cannot listen: ', $msg);
        } finally {
            $port = $a->port;
            $a->close();
        }
        $this->assertFalse(@stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $errstr, 1.0));
    }

    /** The default listen port is 0 (any free port): it still starts while port 65535 is taken. */
    public function testDefaultListenPortIsAnyFreePort(): void
    {
        $hold = @stream_socket_server('tcp://127.0.0.1:65535', $errno, $errstr); // taken by us or by someone else: either way not free
        $a = new SandboxEgress(new SandboxEgressPolicy(), new SandboxReceiptLog());
        try {
            $a->start();
            $this->assertGreaterThan(0, $a->port);
        } finally {
            $a->close();
            if ($hold !== false) {
                fclose($hold);
            }
        }
    }

    // ---- the proxy with a real upstream (forked) ------------------------------------------------------------------------

    /** @return array{0:int,1:ForkedCopy,2:string} the upstream port, its copy, and the file it records into */
    private static function upstream(\Closure $serve): array
    {
        if (!function_exists('pcntl_fork')) {
            self::markTestSkipped('pcntl not available');
        }
        $srv = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        self::assertNotFalse($srv, (string)$errstr);
        $name = (string)stream_socket_get_name($srv, false);
        $port = (int)substr($name, (int)strrpos($name, ':') + 1);
        $rec = (string)tempnam(sys_get_temp_dir(), 'k9up');
        $copy = ForkedCopy::start(static function () use ($srv, $serve, $rec): int {
            $c = @stream_socket_accept($srv, 5.0);
            if ($c === false) {
                return 1;
            }
            stream_set_timeout($c, 3);
            file_put_contents($rec, (string)$serve($c));
            fclose($c);
            return 0;
        });
        fclose($srv);
        return [$port, $copy, $rec];
    }

    /** @param resource $c */
    private static function readHead($c): string
    {
        $h = '';
        while (!str_ends_with($h, "\r\n\r\n")) {
            $l = fgets($c);
            if ($l === false) {
                break;
            }
            $h .= $l;
        }
        return $h;
    }

    /** @param resource $c */
    private static function readN($c, int $n): string
    {
        $b = '';
        while (strlen($b) < $n) {
            $x = fread($c, $n - strlen($b));
            if ($x === false || $x === '') {
                break;
            }
            $b .= $x;
        }
        return $b;
    }

    /** @return array{0:string,1:string} what the client got and what the upstream received */
    private static function viaUpstream(SandboxEgress $proxy, ForkedCopy $copy, string $rec, string $request): array
    {
        $resp = self::roundTrip($proxy, $request);
        self::assertSame(0, $copy->wait());
        $got = (string)file_get_contents($rec);
        @unlink($rec);
        return [$resp, $got];
    }

    public function testForwardedRequestAndResponse(): void
    {
        [$port, $copy, $rec] = self::upstream(static function ($c): string {
            $h = self::readHead($c);
            fwrite($c, "HTTP/1.1 200 OK\r\nX-R: v\r\nTransfer-Encoding: identity\r\nConnection: keep-alive\r\nKeep-Alive: t=1\r\n\r\nhello");
            return $h;
        });
        $p = new SandboxEgressPolicy();
        self::admit($p, ['method' => 'GET', 'scheme' => 'http', 'host' => '127.0.0.1', 'port' => $port, 'path' => '/p', 'query' => 'q=1']);
        $log = new SandboxReceiptLog();
        [$resp, $got] = self::viaUpstream(new SandboxEgress($p, $log, allowPrivate: true, upstreamTimeoutMs: 3000), $copy, $rec,
            "GET http://127.0.0.1:$port/p?q=1 HTTP/1.1\r\nHost: 127.0.0.1:$port\r\nX-A: 1\r\nProxy-Authorization: secret\r\nConnection: keep-alive\r\n\r\n");
        $this->assertSame("GET /p?q=1 HTTP/1.1\r\nhost: 127.0.0.1:$port\r\nconnection: close\r\nx-a: 1\r\n\r\n", $got);
        $this->assertSame("HTTP/1.1 200 OK\r\nx-r: v\r\ntransfer-encoding: identity\r\nconnection: close\r\n\r\nhello", $resp);
        $this->assertCount(1, $log->entries);
        $this->assertSame(['ok', 'status:200'], [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
        $this->assertSame(['op_id' => 'op1', 'verb' => 'read', 'resource' => 'r', 'params_digest' => Pca::hashCanonical(new Obj())], self::subject($log));
    }

    public function testForwardedBodyAndBareStatusLine(): void
    {
        [$port, $copy, $rec] = self::upstream(static function ($c): string {
            $h = self::readHead($c);
            $b = self::readN($c, 5);
            fwrite($c, "HTTP/1.1 201 Created\r\n\r\n");
            return $h . $b;
        });
        $p = new SandboxEgressPolicy();
        self::admit($p, ['method' => 'POST', 'scheme' => 'http', 'host' => '127.0.0.1', 'port' => $port, 'path' => '/u', 'body_sha256' => Sandbox::sha256B64u('abcde')]);
        $log = new SandboxReceiptLog();
        [$resp, $got] = self::viaUpstream(new SandboxEgress($p, $log, allowPrivate: true, upstreamTimeoutMs: 3000), $copy, $rec,
            "POST http://127.0.0.1:$port/u HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde");
        $this->assertSame("POST /u HTTP/1.1\r\nhost: 127.0.0.1:$port\r\nconnection: close\r\ncontent-length: 5\r\n\r\nabcde", $got);
        $this->assertSame("HTTP/1.1 201 Created\r\nconnection: close\r\n\r\n", $resp);
        $this->assertSame('status:201', $log->entries[0]->get('reason'));
    }

    /** An https target is reached over TLS: a plain-text upstream fails the handshake. */
    public function testHttpsUpstreamNeedsTls(): void
    {
        [$port, $copy, $rec] = self::upstream(static function ($c): string {
            fwrite($c, "HTTP/1.1 200 OK\r\n\r\n");
            return '';
        });
        $p = new SandboxEgressPolicy();
        self::admit($p, ['method' => 'GET', 'scheme' => 'https', 'host' => '127.0.0.1', 'port' => $port, 'path' => '/']);
        $log = new SandboxReceiptLog();
        [$resp] = self::viaUpstream(new SandboxEgress($p, $log, allowPrivate: true, upstreamTimeoutMs: 3000), $copy, $rec,
            "GET https://127.0.0.1:$port/ HTTP/1.1\r\n\r\n");
        $this->assertSame(self::BAD_GATEWAY, $resp);
        $this->assertSame(['error', 'upstream:error'], [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
    }

    public function testUpstreamWithoutAResponseHead(): void
    {
        [$port, $copy, $rec] = self::upstream(static fn($c): string => self::readHead($c));
        $p = new SandboxEgressPolicy();
        self::admit($p, ['method' => 'GET', 'scheme' => 'http', 'host' => '127.0.0.1', 'port' => $port, 'path' => '/']);
        $log = new SandboxReceiptLog();
        [$resp] = self::viaUpstream(new SandboxEgress($p, $log, allowPrivate: true, upstreamTimeoutMs: 3000), $copy, $rec,
            "GET http://127.0.0.1:$port/ HTTP/1.1\r\n\r\n");
        $this->assertSame(self::BAD_GATEWAY, $resp);
        $this->assertCount(1, $log->entries);
        $this->assertSame(['error', 'upstream:RuntimeException'], [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
    }

    /** Once the upstream head went out, a later failure is receipted but not answered with a second (502) response. */
    public function testFailureAfterTheHeadIsNotAnsweredAgain(): void
    {
        [$port, $copy, $rec] = self::upstream(static function ($c): string {
            self::readHead($c);
            fwrite($c, "HTTP/1.1 200 OK\r\n\r\nok");
            return '';
        });
        $p = new SandboxEgressPolicy();
        self::admit($p, ['method' => 'GET', 'scheme' => 'http', 'host' => '127.0.0.1', 'port' => $port, 'path' => '/']);
        $calls = 0;
        $log = new SandboxReceiptLog(null, static function () use (&$calls): string {
            if ($calls++ === 0) {
                throw new Kill9EgressSignerFailureWithALongNameThatPassesTheReceiptCut('first receipt fails');
            }
            return 'sig';
        });
        [$resp] = self::viaUpstream(new SandboxEgress($p, $log, allowPrivate: true, upstreamTimeoutMs: 3000), $copy, $rec,
            "GET http://127.0.0.1:$port/ HTTP/1.1\r\n\r\n");
        $this->assertSame("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nok", $resp);
        $this->assertCount(1, $log->entries);
        $this->assertSame(['error', 'upstream:Kill9EgressSignerFailureWithALongNameThatPassesTheRecei'],
            [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
    }

    public function testConnectTunnelRelaysBothWays(): void
    {
        [$port, $copy, $rec] = self::upstream(static function ($c): string {
            $in = self::readN($c, 4);
            fwrite($c, 'PONG');
            return $in;
        });
        $p = new SandboxEgressPolicy();
        self::admit($p, self::tunnel($port));
        $log = new SandboxReceiptLog();
        [$resp, $got] = self::viaUpstream(new SandboxEgress($p, $log, allowPrivate: true, upstreamTimeoutMs: 3000), $copy, $rec,
            "CONNECT 127.0.0.1:$port HTTP/1.1\r\n\r\nPING");
        $this->assertSame('PING', $got);
        $this->assertSame("HTTP/1.1 200 Connection Established\r\n\r\nPONG", $resp);
        $this->assertCount(1, $log->entries);
        $this->assertSame(['ok', 'tunnel'], [$log->entries[0]->get('outcome'), $log->entries[0]->get('reason')]);
    }
}
