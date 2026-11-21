<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostDkgTls.php';

use Atlas\Pca\FrostDkgTls;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * The mutual-TLS DKG channel, each participant in its own process: a 2-of-3 ceremony over pinned self-signed certificates agrees on one group key, a peer
 * with a certificate nobody pinned and a plaintext client are refused before any DKG byte is read (the node's connect times out), and a bad pin set is refused at start.
 */
final class FrostDkgTlsTest extends TestCase
{
    /** @var list<resource> */
    private array $procs = [];
    /** @var list<string> */
    private array $files = [];

    protected function setUp(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('needs the openssl extension');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->procs as $p) {
            @proc_terminate($p, 9);   // SIGKILL: a signer that ignores SIGTERM would make proc_close wait forever
            @proc_close($p);
        }
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    /** @return array{key:string,cert:string} */
    private static function identity(string $cn): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => $cn], $key, ['digest_alg' => 'sha256']);
        $x = openssl_csr_sign($csr, null, $key, 2, ['digest_alg' => 'sha256']);
        openssl_x509_export($x, $cert);
        openssl_pkey_export($key, $pem);
        return ['key' => $pem, 'cert' => $cert];
    }

    /** @return array{0:resource,1:array<int,resource>} */
    private function spawn(array $cfg): array
    {
        $path = tempnam(sys_get_temp_dir(), 'dkgparty');
        $this->files[] = $path;
        file_put_contents($path, json_encode($cfg));
        // stdout and stderr go to files, not pipes: a Windows pipe cannot be read without blocking, which hung the suite
        $out = tempnam(sys_get_temp_dir(), 'dkgout');
        $err = tempnam(sys_get_temp_dir(), 'dkgerr');
        $this->files[] = $out;
        $this->files[] = $err;
        $proc = proc_open([PHP_BINARY, __DIR__ . '/frost-dkg-tls-party.php', $path], [0 => ['pipe', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes);
        $this->assertIsResource($proc);
        $this->procs[] = $proc;
        $pipes[1] = $out;
        $pipes[2] = $err;
        return [$proc, $pipes];
    }

    /** What a still-running child has written so far to its stderr file. */
    private static function drain(string $file): string
    {
        return (string)@file_get_contents($file);
    }

    /** @var array<string,int> bytes of each output file already handed out */
    private static array $consumed = [];

    /** The next line of a child's stdout file (waits up to $seconds for it to be complete). */
    private static function line(string $file, float $seconds): string
    {
        $until = microtime(true) + $seconds;
        $from = self::$consumed[$file] ?? 0;
        do {
            $all = (string)@file_get_contents($file);
            $nl = strpos($all, "\n", $from);
            if ($nl !== false) {
                self::$consumed[$file] = $nl + 1;
                return trim(substr($all, $from, $nl - $from));
            }
            usleep(20000);
        } while (microtime(true) < $until);
        return trim(substr($all, $from));
    }

    public function testATwoOfThreeCeremonyOverPinnedMutualTls(): void
    {
        $ids = [1, 2, 3];
        $idt = [];
        foreach ($ids as $i) {
            $idt[$i] = self::identity("dkg-party-$i");
        }
        $sid = Pca::b64u(random_bytes(16));
        $pipes = [];
        $ports = [];
        foreach ($ids as $i) {
            $peers = [];
            foreach ($ids as $j) {
                if ($j !== $i) {
                    $peers[] = ['id' => $j, 'certPem' => $idt[$j]['cert']];
                }
            }
            [, $pipes[$i]] = $this->spawn(['self' => $i, 'sessionId' => $sid, 'keyPem' => $idt[$i]['key'], 'certPem' => $idt[$i]['cert'], 'peerCerts' => $peers, 't' => 2, 'participants' => $ids]);
            $line = self::line($pipes[$i][1], 20);
            $this->assertStringStartsWith('PORT ', $line, 'party ' . $i . ' did not start: ' . self::drain($pipes[$i][2]));
            $ports[$i] = (int)substr($line, 5);
        }
        $addr = array_map(static fn(int $i): array => ['id' => $i, 'host' => '127.0.0.1', 'port' => $ports[$i]], $ids);
        foreach ($ids as $i) {
            fwrite($pipes[$i][0], json_encode(array_values(array_filter($addr, static fn(array $a): bool => $a['id'] !== $i))) . "\n");
        }
        $gpks = [];
        foreach ($ids as $i) {
            $line = self::line($pipes[$i][1], 90);
            $this->assertStringStartsWith('RESULT ', $line, "party $i: $line");
            $r = json_decode(substr($line, 7), true);
            $this->assertSame(3, $r['qualified']);
            $gpks[] = $r['gpk'];
        }
        $this->assertNotSame('', $gpks[0]);
        $this->assertSame([$gpks[0], $gpks[0], $gpks[0]], $gpks);
    }

    public function testAnUnpinnedPeerAndAPlaintextClientNeverLink(): void
    {
        $a = self::identity('node-1');
        $b = self::identity('pinned-2');
        $stranger = self::identity('stranger');
        $sid = Pca::b64u(random_bytes(16));
        [, $pipes] = $this->spawn(['self' => 1, 'sessionId' => $sid, 'keyPem' => $a['key'], 'certPem' => $a['cert'], 'peerCerts' => [['id' => 2, 'certPem' => $b['cert']]],
            'mode' => 'link-only', 'connectTimeoutMs' => 4000]);
        $port = (int)substr(self::line($pipes[1], 20), 5);
        $this->assertGreaterThan(0, $port);
        fwrite($pipes[0], json_encode([['id' => 2, 'host' => '127.0.0.1', 'port' => 1]]) . "\n");
        // a TLS client whose certificate nobody pinned (it may claim to be anyone: only the certificate counts)
        $c = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 3);
        if ($c !== false) {
            $tmp = tempnam(sys_get_temp_dir(), 'stranger');
            $this->files[] = $tmp;
            file_put_contents($tmp, $stranger['cert'] . "\n" . $stranger['key']);
            stream_context_set_option($c, 'ssl', 'local_cert', $tmp);
            stream_context_set_option($c, 'ssl', 'verify_peer', false);
            stream_context_set_option($c, 'ssl', 'verify_peer_name', false);
            @stream_socket_enable_crypto($c, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            @fclose($c);
        }
        // and a plaintext client
        $p = @stream_socket_client("tcp://127.0.0.1:$port", $errno, $errstr, 3);
        if ($p !== false) {
            @fwrite($p, "GET / HTTP/1.1\r\n\r\n");
            @fclose($p);
        }
        $line = self::line($pipes[1], 30);
        $this->assertStringStartsWith('ERROR ', $line);
        $this->assertStringContainsString('(timeout', $line);
    }

    public function testBadPinSetsAreRefusedAtStart(): void
    {
        $a = self::identity('a');
        $this->expectException(\RuntimeException::class);
        FrostDkgTls::startTlsDkgNode(['self' => 1, 'sessionId' => 'sid', 'keyPem' => $a['key'], 'certPem' => $a['cert'],
            'peerCerts' => [['id' => 2, 'certPem' => $a['cert']], ['id' => 3, 'certPem' => $a['cert']]]]);
    }
}
