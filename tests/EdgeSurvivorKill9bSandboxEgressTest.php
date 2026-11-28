<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SandboxEgress;
use Atlas\Pca\SandboxEgressPolicy;
use Atlas\Pca\SandboxReceiptLog;
use PHPUnit\Framework\TestCase;

/**
 * The upstream connection the proxy builds (stream URI, TLS context, connect timeout), read through the connect seam, which then
 * aborts it: nothing is dialled, so ports 80 and 443 are never touched.
 */
final class EdgeSurvivorKill9bSandboxEgressTest extends TestCase
{
    private const BAD_GATEWAY = "HTTP/1.1 502 Bad Gateway\r\nconnection: close\r\ncontent-length: 0\r\n\r\n";

    protected function tearDown(): void
    {
        SandboxEgress::$connectHook = null;
    }

    private static function admit(SandboxEgressPolicy $p, array $t): void
    {
        $result = Obj::of(['allow' => true, 'operation' => Obj::of(['id' => 'op1', 'verb' => 'read', 'resource' => 'r',
            'params_digest' => Pca::hashCanonical(new Obj())])]);
        $p->admit($result, Obj::of(['verb' => 'read', 'resource' => 'r', 'params' => new Obj()]), static fn() => Obj::of($t));
    }

    /**
     * Send `$request` through a proxy admitting `$target`; every connect it attempts is recorded and refused.
     *
     * @return array{0: list<array{0:string,1:array<mixed>,2:float}>, 1: string, 2: ?string}
     */
    private static function attempt(array $target, string $request, int ...$timeoutMs): array
    {
        $p = new SandboxEgressPolicy();
        self::admit($p, $target);
        $log = new SandboxReceiptLog();
        $proxy = $timeoutMs === [] ? new SandboxEgress($p, $log, allowPrivate: true)
            : new SandboxEgress($p, $log, allowPrivate: true, upstreamTimeoutMs: $timeoutMs[0]);
        $calls = [];
        SandboxEgress::$connectHook = static function (string $uri, array $options, float $timeout) use (&$calls): void {
            $calls[] = [$uri, $options, $timeout];
            throw new \RuntimeException('not dialled');
        };
        $proxy->start();
        try {
            $client = stream_socket_client('tcp://127.0.0.1:' . $proxy->port, $errno, $errstr, 2.0);
            self::assertNotFalse($client, (string)$errstr);
            fwrite($client, $request);
            self::assertTrue($proxy->serveOne(2.0));
            $resp = (string)stream_get_contents($client);
            fclose($client);
        } finally {
            $proxy->close();
            SandboxEgress::$connectHook = null;
        }
        $reason = $log->entries === [] ? null : $log->entries[0]->get('reason');
        return [$calls, $resp, $reason];
    }

    private static function tls(string $name): array
    {
        return ['ssl' => ['peer_name' => $name, 'verify_peer' => true, 'verify_peer_name' => true, 'SNI_enabled' => true]];
    }

    private static function get(string $scheme, string $host, ?int $port = null): array
    {
        $t = ['method' => 'GET', 'scheme' => $scheme, 'host' => $host, 'path' => '/p'];
        if ($port !== null) {
            $t['port'] = $port;
        }
        return $t;
    }

    /** Without a port the scheme's default is dialled (80 / 443); a given port wins. */
    public function testUpstreamPortDefaultsToTheSchemes(): void
    {
        $cases = [
            ['http', null, 'http://127.0.0.1/p', 'tcp://127.0.0.1:80'],
            ['https', null, 'https://127.0.0.1/p', 'ssl://127.0.0.1:443'],
            ['http', 8080, 'http://127.0.0.1:8080/p', 'tcp://127.0.0.1:8080'],
            ['https', 8443, 'https://127.0.0.1:8443/p', 'ssl://127.0.0.1:8443'],
        ];
        foreach ($cases as [$scheme, $port, $url, $uri]) {
            [$calls, $resp, $reason] = self::attempt(self::get($scheme, '127.0.0.1', $port), "GET $url HTTP/1.1\r\n\r\n");
            $this->assertCount(1, $calls, $url);
            $this->assertSame($uri, $calls[0][0]);
            $this->assertSame([self::BAD_GATEWAY, 'upstream:error'], [$resp, $reason]);
        }
    }

    /** Plain HTTP gets no TLS options; HTTPS verifies the peer and its name (the URL host) with SNI. */
    public function testTlsContextOptions(): void
    {
        [$calls] = self::attempt(self::get('http', '127.0.0.1'), "GET http://127.0.0.1/p HTTP/1.1\r\n\r\n");
        $this->assertSame([], $calls[0][1]);
        [$calls] = self::attempt(self::get('https', '127.0.0.1'), "GET https://127.0.0.1/p HTTP/1.1\r\n\r\n");
        $this->assertSame(self::tls('127.0.0.1'), $calls[0][1]);
        [$calls] = self::attempt(self::get('https', '::1'), "GET https://[::1]/p HTTP/1.1\r\n\r\n");
        $this->assertSame(['ssl://[::1]:443', self::tls('::1')], [$calls[0][0], $calls[0][1]]);
    }

    /** The connect timeout is the configured milliseconds in seconds (10 s by default). */
    public function testConnectTimeout(): void
    {
        [$calls] = self::attempt(self::get('http', '127.0.0.1'), "GET http://127.0.0.1/p HTTP/1.1\r\n\r\n");
        $this->assertSame(10.0, $calls[0][2]);
        [$calls] = self::attempt(self::get('http', '127.0.0.1'), "GET http://127.0.0.1/p HTTP/1.1\r\n\r\n", 2500);
        $this->assertSame(2.5, $calls[0][2]);
    }

    /** An IPv6 literal is dialled as is, in brackets; a name is resolved first (localhost to its IPv4 loopback). */
    public function testAddressLiteralsAndNames(): void
    {
        [$calls] = self::attempt(self::get('http', '::1', 8080), "GET http://[::1]:8080/p HTTP/1.1\r\n\r\n");
        $this->assertSame('tcp://[::1]:8080', $calls[0][0]);
        [$calls] = self::attempt(self::get('http', 'localhost'), "GET http://localhost/p HTTP/1.1\r\n\r\n");
        $this->assertSame('tcp://127.0.0.1:80', $calls[0][0]);
    }

    /** A tunnel dials its host and port exactly, an IPv6 host unbracketed and re-bracketed, never over TLS. */
    public function testTunnelTarget(): void
    {
        foreach ([['127.0.0.1', '127.0.0.1:8443', 'tcp://127.0.0.1:8443'], ['::1', '[::1]:8443', 'tcp://[::1]:8443']] as [$host, $target, $uri]) {
            [$calls, $resp, $reason] = self::attempt(['method' => 'CONNECT', 'scheme' => 'https', 'host' => $host, 'port' => 8443, 'path' => '/', 'tunnel' => true],
                "CONNECT $target HTTP/1.1\r\n\r\n");
            $this->assertCount(1, $calls, $target);
            $this->assertSame([$uri, [], 10.0], $calls[0]);
            $this->assertSame([self::BAD_GATEWAY, 'upstream:error'], [$resp, $reason]);
        }
    }
}
