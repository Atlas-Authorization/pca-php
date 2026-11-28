<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Oidc;
use Atlas\Pca\PrivateFile;
use PHPUnit\Framework\TestCase;

/**
 * The default fetch against a raw loopback responder that writes exact bytes (a reason phrase with ':', a header line without ':',
 * unspaced and spaced-out header names, stalls), and the issuer-only JWKS factory over a local TLS responder trusted through
 * SSL_CERT_FILE.
 */
final class TokenSurvivorKill6cOidcRawTest extends TestCase
{
    /** @var array<string, array{0: mixed, 1: int}> name => [process, port] */
    private static array $servers = [];
    private static string $dir = '';

    private const RESPONDER = <<<'PHP'
<?php
// argv: tcp | tls <cert.pem> <key.pem>. Prints its port, then answers each request with exact bytes.
$tls = ($argv[1] ?? 'tcp') === 'tls';
$ctx = stream_context_create($tls ? ['ssl' => ['local_cert' => $argv[2], 'local_pk' => $argv[3]]] : []);
$s = stream_socket_server(($tls ? 'ssl' : 'tcp') . '://127.0.0.1:0', $no, $err, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
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
    $req = '';
    while (($l = fgets($c)) !== false) {
        $req .= $l;
        if ($l === "\r\n") {
            break;
        }
    }
    $path = explode(' ', $req)[1] ?? '/';
    $host = 'https://127.0.0.1:' . substr($name, strrpos($name, ':') + 1);
    $send = static function (string $status, array $lines, string $body) use ($c): void {
        fwrite($c, "HTTP/1.1 $status\r\n" . implode('', array_map(static fn(string $l): string => "$l\r\n", $lines))
            . 'Content-Length: ' . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
    };
    if ($path === '/raw') {
        $send('200 Odd: Reason', ['X-Tight:value', 'X-Sp : v'], 'ok');
    } elseif ($path === '/nocolon') {
        $send('200 OK', ['NoColonHere', 'X-B: 2'], 'ok');
    } elseif ($path === '/stall-headers') {
        fwrite($c, "HTTP/1.1 200 OK\r\nX-A: 1\r\n");
        fflush($c);
        usleep(600000);
    } elseif ($path === '/stall-body') {
        fwrite($c, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nab");
        fflush($c);
        usleep(600000);
    } elseif ($path === '/.well-known/openid-configuration') {
        $send('200 OK', ['Content-Type: application/json'], json_encode(['issuer' => $host, 'jwks_uri' => "$host/jwks"], JSON_UNESCAPED_SLASHES));
    } else {
        $send('404 Not Found', [], 'nf');
    }
    @fclose($c);
}
PHP;

    private static function dir(): string
    {
        if (self::$dir === '') {
            self::$dir = sys_get_temp_dir() . '/pca-kill6c-' . bin2hex(random_bytes(6));
            mkdir(self::$dir);
            file_put_contents(self::$dir . '/responder.php', self::RESPONDER);
        }
        return self::$dir;
    }

    /** Start a responder `$name` with argv `$args` (mode first; once per class); its port. */
    private static function port(string $name, array $args = ['tcp']): int
    {
        if (isset(self::$servers[$name])) {
            return self::$servers[$name][1];
        }
        $null = PrivateFile::nullDevice();
        $proc = proc_open([PHP_BINARY, self::dir() . '/responder.php', ...$args],
            [0 => ['file', $null, 'r'], 1 => ['pipe', 'w'], 2 => ['file', $null, 'w']], $pipes);
        self::assertIsResource($proc);
        $line = fgets($pipes[1]);
        $port = (int)trim((string)$line);
        self::assertGreaterThan(0, $port, 'the responder did not start');
        self::$servers[$name] = [$proc, $port];
        return $port;
    }

    public static function tearDownAfterClass(): void
    {
        foreach (self::$servers as [$proc]) {
            proc_terminate($proc);
            proc_close($proc);
        }
        self::$servers = [];
        if (self::$dir !== '') {
            foreach (glob(self::$dir . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir(self::$dir);
            self::$dir = '';
        }
    }

    /** The status comes from the status line only (its reason phrase is no header); names are trimmed and lower-cased, values trimmed. */
    public function testHeaderParsingIsExact(): void
    {
        $port = self::port('tcp');
        $r = Oidc::defaultFetch("http://127.0.0.1:$port/raw", ['accept' => 'application/json'], 2000);
        self::assertSame(200, $r['status']);
        self::assertSame('ok', $r['body']);
        self::assertSame(['x-tight' => 'value', 'x-sp' => 'v', 'content-length' => '2', 'connection' => 'close'], $r['headers']);
    }

    /** A header line without ':' is skipped (a runtime that refuses such a reply fails the fetch instead). */
    public function testHeaderLineWithoutColonIsSkipped(): void
    {
        $port = self::port('tcp');
        $url = "http://127.0.0.1:$port/nocolon";
        try {
            $r = Oidc::defaultFetch($url, [], 2000);
        } catch (\RuntimeException $e) {
            self::assertSame("fetch of $url failed", $e->getMessage());
            return;
        }
        self::assertSame([200, 'ok'], [$r['status'], $r['body']]);
        self::assertSame(['x-b' => '2', 'content-length' => '2', 'connection' => 'close'], $r['headers']);
    }

    /** A reply that stalls (inside the headers or the body) past the timeout is a failed fetch or a string body, never a false body. */
    public function testStalledRepliesNeverYieldAFalseBody(): void
    {
        foreach (['stall-headers', 'stall-body'] as $p) {
            $port = self::port($p); // one responder each: a stalled one answers nothing else for 0.6 s
            $url = "http://127.0.0.1:$port/$p";
            try {
                $r = Oidc::defaultFetch($url, [], 200);
                self::assertSame(200, $r['status'], $p);
                self::assertIsString($r['body'], $p);
            } catch (\RuntimeException $e) {
                self::assertSame("fetch of $url failed", $e->getMessage(), $p);
            }
        }
    }

    /** A self-signed P-256 certificate for 127.0.0.1 (CN and IP SAN): [cert.pem path, key.pem path]. */
    private static function selfSigned(): array
    {
        $d = self::dir();
        $cnf = "$d/openssl.cnf";
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n[v3]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n");
        $key = openssl_pkey_new(['config' => $cnf, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);
        $csr = openssl_csr_new(['commonName' => '127.0.0.1'], $key, ['config' => $cnf, 'digest_alg' => 'sha256']);
        self::assertNotFalse($csr);
        $crt = openssl_csr_sign($csr, null, $key, 2, ['config' => $cnf, 'digest_alg' => 'sha256', 'x509_extensions' => 'v3'], 1);
        self::assertNotFalse($crt);
        self::assertTrue(openssl_x509_export($crt, $certPem));
        self::assertTrue(openssl_pkey_export($key, $keyPem, null, ['config' => $cnf]));
        file_put_contents("$d/cert.pem", $certPem);
        file_put_contents("$d/key.pem", $keyPem);
        return ["$d/cert.pem", "$d/key.pem"];
    }

    /** createOidcJwksFromIssuer with null options discovers over https (the default fetch) and builds the resolver. */
    public function testJwksFromIssuerWithNullOptionsOverTls(): void
    {
        [$cert, $key] = self::selfSigned();
        $port = self::port('tls', ['tls', $cert, $key]);
        $prev = getenv('SSL_CERT_FILE');
        putenv("SSL_CERT_FILE=$cert");
        try {
            self::assertSame(404, Oidc::defaultFetch("https://127.0.0.1:$port/probe", [], 5000)['status'], 'the TLS responder is trusted');
            self::assertInstanceOf(\Closure::class, Oidc::createOidcJwksFromIssuer("https://127.0.0.1:$port", null));
        } finally {
            putenv($prev === false ? 'SSL_CERT_FILE' : "SSL_CERT_FILE=$prev");
        }
    }
}
