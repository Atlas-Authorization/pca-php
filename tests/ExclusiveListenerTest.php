<?php
declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ExclusiveListener;
use PHPUnit\Framework\TestCase;

/** The listener every local protocol binds through: a held port is never bindable again (on Windows a plain bind would allow it). */
final class ExclusiveListenerTest extends TestCase
{
    private static function port(string $host = '127.0.0.1'): int
    {
        $s = stream_socket_server("tcp://$host:0", $e, $m);
        $port = (int)substr((string)strrchr((string)stream_socket_get_name($s, false), ':'), 1);
        fclose($s);
        return $port;
    }

    public function testBindsAndAcceptsAConnection(): void
    {
        $port = self::port();
        $srv = ExclusiveListener::bind('127.0.0.1', $port);
        $this->assertIsResource($srv);
        $c = stream_socket_client("tcp://127.0.0.1:$port", $e, $m, 5);
        $this->assertIsResource($c);
        $this->assertIsResource(stream_socket_accept($srv, 5));
    }

    public function testASecondBindOfAHeldPortFailsAndReportsWhy(): void
    {
        $port = self::port();
        $srv = ExclusiveListener::bind('127.0.0.1', $port);
        $this->assertIsResource($srv);
        $errno = null;
        $errstr = null;
        $this->assertFalse(ExclusiveListener::bind('127.0.0.1', $port, [], $errno, $errstr));
        $this->assertNotEmpty($errstr);
        $this->assertNotSame(0, $errno);
    }

    public function testASpecificAddressCannotShadowAHeldWildcardListener(): void
    {
        $port = self::port();
        $srv = ExclusiveListener::bind('0.0.0.0', $port);
        $this->assertIsResource($srv);
        if (PHP_OS_FAMILY === 'Darwin') {
            // BSD lets a specific-address bind with SO_REUSEADDR sit beside a held wildcard and offers no exclusive option, so the
            // listener cannot refuse shadowing there (documented on ExclusiveListener); what it does guarantee is the same-address refusal
            $this->assertFalse(ExclusiveListener::bind('0.0.0.0', $port));
            return;
        }
        $this->assertFalse(ExclusiveListener::bind('127.0.0.1', $port));
    }

    public function testTheContextOptionsAreApplied(): void
    {
        $srv = ExclusiveListener::bind('127.0.0.1', self::port(), ['ssl' => ['verify_peer' => false]]);
        $this->assertIsResource($srv);
        $this->assertFalse(stream_context_get_options($srv)['ssl']['verify_peer'] ?? true);
    }
}
