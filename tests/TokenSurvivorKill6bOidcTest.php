<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Oidc;
use Atlas\Pca\PrivateFile;
use PHPUnit\Framework\TestCase;

/**
 * The default HTTP fetch against PHP's built-in server on loopback (status, body, request and response headers, redirects not
 * followed, error statuses read, the timeout).
 */
final class TokenSurvivorKill6bOidcTest extends TestCase
{
    private static mixed $proc = null;
    private static string $dir = '';
    private static string $base = '';

    private const ROUTER = <<<'PHP'
<?php
$p = (string)parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$host = 'http://' . $_SERVER['HTTP_HOST'];
if ($p === '/echo') {
    header('X-Tight:value');
    header('X-Sp : v');
    header('X-Upper: Up');
    echo $_SERVER['HTTP_ACCEPT'] ?? 'none';
} elseif ($p === '/missing') {
    http_response_code(404);
    echo 'nf';
} elseif ($p === '/redirect') {
    header('Location: /echo', true, 302);
    echo 'moved';
} elseif ($p === '/slow') {
    usleep(400000);
    echo 'late';
} elseif ($p === '/.well-known/openid-configuration') {
    header('Content-Type: application/json');
    echo json_encode(['issuer' => $host, 'jwks_uri' => $host . '/jwks'], JSON_UNESCAPED_SLASHES);
} elseif ($p === '/jwks') {
    header('Content-Type: application/json');
    echo json_encode(['keys' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo']]]);
} else {
    http_response_code(500);
}
PHP;

    private const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    /** Start `php -S` on a free loopback port (once per class). */
    private static function server(): string
    {
        if (self::$proc !== null) {
            return self::$base;
        }
        $s = stream_socket_server('tcp://127.0.0.1:0', $no, $err);
        self::assertNotFalse($s, (string)$err);
        $port = (int)substr((string)strrchr((string)stream_socket_get_name($s, false), ':'), 1);
        fclose($s);
        self::$dir = sys_get_temp_dir() . '/pca-kill6b-' . bin2hex(random_bytes(6));
        mkdir(self::$dir);
        file_put_contents(self::$dir . '/router.php', self::ROUTER);
        $null = PrivateFile::nullDevice();
        self::$proc = proc_open([PHP_BINARY, '-S', "127.0.0.1:$port", '-t', self::$dir, self::$dir . '/router.php'],
            [0 => ['file', $null, 'r'], 1 => ['file', $null, 'w'], 2 => ['file', $null, 'w']], $pipes);
        self::assertIsResource(self::$proc);
        $end = hrtime(true) + 10_000_000_000;
        do {
            $c = @fsockopen('127.0.0.1', $port, $no, $err, 0.2);
            if ($c !== false) {
                fclose($c);
                return self::$base = "http://127.0.0.1:$port";
            }
            usleep(20000); // waiting for the server process to bind
        } while (hrtime(true) < $end);
        self::fail('the built-in server did not start');
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$proc)) {
            proc_terminate(self::$proc);
            proc_close(self::$proc);
        }
        self::$proc = null;
        if (self::$dir !== '' && is_dir(self::$dir)) {
            @unlink(self::$dir . '/router.php');
            @rmdir(self::$dir);
        }
    }

    /** The response headers, parsed the way the spec reads them: lower-cased, trimmed name -> trimmed value, status line skipped. */
    private static function expectedHeaders(array $raw): array
    {
        $out = [];
        foreach (array_slice($raw, 1) as $line) {
            $i = strpos($line, ':');
            if ($i !== false) {
                $out[strtolower(trim(substr($line, 0, $i)))] = trim(substr($line, $i + 1));
            }
        }
        return $out;
    }

    /** A 200: an int status, the body, the request headers sent, and every response header lower-cased and trimmed. */
    public function testDefaultFetchReadsAResponse(): void
    {
        $base = self::server();
        $r = Oidc::defaultFetch("$base/echo", ['accept' => 'application/json'], 2000);
        $raw = function_exists('http_get_last_response_headers') ? (http_get_last_response_headers() ?? []) : null;
        self::assertSame(200, $r['status']);
        self::assertSame('application/json', $r['body']);
        self::assertSame(['status', 'body', 'headers'], array_keys($r));
        self::assertSame('value', $r['headers']['x-tight'] ?? null);
        self::assertSame('Up', $r['headers']['x-upper'] ?? null);
        if (isset($r['headers']['x-sp'])) {
            self::assertSame('v', $r['headers']['x-sp']);
        }
        if ($raw !== null) {
            self::assertNotSame([], $raw);
            self::assertSame(self::expectedHeaders($raw), $r['headers']);
        }
    }

    /** Error statuses are read (not refused) and a redirect is not followed. */
    public function testDefaultFetchReadsErrorsAndKeepsRedirects(): void
    {
        $base = self::server();
        $r = Oidc::defaultFetch("$base/missing", [], 2000);
        self::assertSame([404, 'nf'], [$r['status'], $r['body']]);
        $r = Oidc::defaultFetch("$base/redirect", [], 2000);
        self::assertSame([302, 'moved'], [$r['status'], $r['body']]);
        self::assertSame('/echo', $r['headers']['location'] ?? null);
    }

    /** timeoutMs is milliseconds: a reply slower than it is a failed fetch. */
    public function testDefaultFetchTimesOut(): void
    {
        $base = self::server();
        try {
            Oidc::defaultFetch("$base/slow", [], 150);
            self::fail('a reply slower than the timeout was accepted');
        } catch (\RuntimeException $e) {
            self::assertSame("fetch of $base/slow failed", $e->getMessage());
        }
    }

    /** Discovery and the JWKS resolver run end to end on the default fetch (requireHttps: false for loopback). */
    public function testDiscoveryAndJwksOnTheDefaultFetch(): void
    {
        $base = self::server();
        $m = Oidc::discoverOidc($base, ['requireHttps' => false]);
        self::assertSame("$base/jwks", $m->get('jwks_uri'));
        $r = Oidc::createOidcJwks(['jwksUri' => $m->get('jwks_uri'), 'requireHttps' => false]);
        self::assertSame(self::X, Js::opt($r(Obj::of(['alg' => 'EdDSA'])), 'x'));
    }
}
