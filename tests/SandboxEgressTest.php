<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\SandboxEgress;
use Atlas\Pca\SandboxEgressPolicy;
use Atlas\Pca\SandboxReceiptLog;
use PHPUnit\Framework\TestCase;

/** The egress proxy over a real loopback socket: with no admission every request is refused and receipted. */
final class SandboxEgressTest extends TestCase
{
    /** @return array{0:string,1:SandboxReceiptLog} the raw response and the receipts */
    private static function roundTrip(string $request): array
    {
        $log = new SandboxReceiptLog();
        $proxy = (new SandboxEgress(new SandboxEgressPolicy(), $log))->start();
        try {
            $client = stream_socket_client('tcp://127.0.0.1:' . $proxy->port, $errno, $errstr, 2.0);
            self::assertNotFalse($client, (string)$errstr);
            fwrite($client, $request); // the kernel buffers it until the proxy accepts
            self::assertTrue($proxy->serveOne(2.0));
            $resp = (string)stream_get_contents($client);
            fclose($client);
            return [$resp, $log];
        } finally {
            $proxy->close();
        }
    }

    public function testUnadmittedRequestIsRefusedAndReceipted(): void
    {
        [$resp, $log] = self::roundTrip("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
        $this->assertStringStartsWith('HTTP/1.1 403 Forbidden', $resp);
        $this->assertStringContainsString('"reason":"no_admission"', $resp);
        $this->assertCount(1, $log->entries);
        $this->assertSame('refused', $log->entries[0]->get('outcome'));
    }

    public function testTransferEncodingIsRefused(): void
    {
        [$resp] = self::roundTrip("POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
        $this->assertStringStartsWith('HTTP/1.1 400 Bad Request', $resp);
        $this->assertStringContainsString('transfer_encoding', $resp);
    }

    public function testMalformedRequestLineIsRefused(): void
    {
        [$resp] = self::roundTrip("NONSENSE\r\n\r\n");
        $this->assertStringStartsWith('HTTP/1.1 400 Bad Request', $resp);
    }

    public function testConnectWithoutTunnelAdmissionIsRefused(): void
    {
        [$resp] = self::roundTrip("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        $this->assertStringStartsWith('HTTP/1.1 403 Forbidden', $resp);
    }
}
