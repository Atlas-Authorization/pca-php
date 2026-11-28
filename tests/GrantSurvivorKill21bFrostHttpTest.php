<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Frost;
use Atlas\Pca\GuardianSignerService;
use Atlas\Pca\SignerHttpServer;
use PHPUnit\Framework\TestCase;

/** The signer server's documented timeouts, and a failed read (fread false) that ends the connection without an answer. */
final class GrantSurvivorKill21bFrostHttpTest extends TestCase
{
    private const BODY = '{"typ":"pca.frost.round1.v1","session_id":"s"}';

    protected function tearDown(): void
    {
        SignerHttpServer::$readHook = null;
        SignerHttpServer::$timeoutHook = null;
    }

    private static function server(): SignerHttpServer
    {
        $kg = Frost::trustedDealerKeygen(1, 1);
        return SignerHttpServer::bind(new GuardianSignerService(['identifier' => 1, 'share' => $kg['participantShares'][0]['share'],
            'groupPublicKey' => $kg['groupPublicKey'], 'threshold' => 1, 'policyAuthorityPublicKey' => str_repeat("\x07", 32)]));
    }

    /** Runs the private connection handler with reads fed by `$reads` (one entry per read call); returns what it wrote, the read sizes and the timeouts set. */
    private static function handle(array $reads): array
    {
        $sizes = [];
        $timeouts = [];
        SignerHttpServer::$timeoutHook = static function ($conn, int $s) use (&$timeouts): void {
            $timeouts[] = $s;
        };
        SignerHttpServer::$readHook = static function ($conn, int $n) use (&$reads, &$sizes): string|false {
            $sizes[] = $n;
            return $reads === [] ? '' : array_shift($reads);
        };
        [$a, $b] = stream_socket_pair(PHP_OS_FAMILY === 'Windows' ? STREAM_PF_INET : STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        $srv = self::server();
        try {
            (new \ReflectionMethod(SignerHttpServer::class, 'handle'))->invoke($srv, $b);
        } finally {
            $srv->close();
            fclose($b);
        }
        $out = (string)stream_get_contents($a);
        fclose($a);
        return [$out, $sizes, $timeouts];
    }

    public function testDocumentedTimeouts(): void
    {
        $this->assertSame([0, 250000, 1, 5], [SignerHttpServer::IDLE_POLL_S, SignerHttpServer::IDLE_POLL_US, SignerHttpServer::ACCEPT_TIMEOUT_S,
            SignerHttpServer::READ_TIMEOUT_S]);
    }

    /** A failed read of the header or of the body ends the connection unanswered, even when more bytes would follow. */
    public function testFailedReadEndsTheConnection(): void
    {
        $head = "POST /round1 HTTP/1.1\r\ncontent-length: " . strlen(self::BODY) . "\r\n\r\n";
        [$out, , $timeouts] = self::handle([$head . self::BODY]);
        $this->assertStringStartsWith('HTTP/1.1 200 OK', $out, 'the hook feeds the real handler');
        $this->assertSame([SignerHttpServer::READ_TIMEOUT_S], $timeouts, 'the connection gets the read timeout once');
        $this->assertSame(['', [4096], [5]], self::handle([false, $head . self::BODY]));
        $this->assertSame(['', [4096, strlen(self::BODY)], [5]], self::handle([$head, false, self::BODY]));
    }
}
