<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostDkgTls.php';

use Atlas\Pca\FrostDkgTls;
use Atlas\Pca\Pca;
use Atlas\Pca\PrivateFile;
use PHPUnit\Framework\Attributes\Depends;
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
        $cmd = [PHP_BINARY, __DIR__ . '/frost-dkg-tls-party.php', $path];
        $proc = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes);
        $this->assertIsResource($proc);
        $this->procs[] = $proc;
        $this->cmds[(int)$proc] = $cmd;
        $pipes[1] = $out;
        $pipes[2] = $err;
        return [$proc, $pipes];
    }

    /** @var array<int,list<string>> the command each child was started with */
    private array $cmds = [];

    /** Everything needed to tell why a child printed nothing: its command, whether it is alive, its exit code, and both captured streams. */
    private function describe($proc, string $outFile, string $errFile): string
    {
        $st = proc_get_status($proc);
        return 'command=' . json_encode($this->cmds[(int)$proc] ?? null) . ' running=' . var_export($st['running'], true) . ' exitcode=' . $st['exitcode']
            . ' stdout=' . json_encode((string)@file_get_contents($outFile)) . ' stderr=' . json_encode((string)@file_get_contents($errFile));
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
                $line = trim(substr($all, $from, $nl - $from));
                if ($line === '') { // the blank line that precedes a displayed PHP diagnostic: not a protocol line
                    $from = $nl + 1;
                    continue;
                }
                return $line;
            }
            usleep(20000);
        } while (microtime(true) < $until);
        return trim(substr($all, $from));
    }

    /**
     * A marker before a native call: a crash in this process leaves the last one as the call that made it. It goes to the stdout
     * descriptor (beside PHPUnit's --debug events, outside the output buffer PHPUnit checks), never to stderr: Infection stops its
     * initial test run (SIGTERM, exit 143) at the first byte the suite writes to stderr.
     */
    private static function step(string $what): void
    {
        fwrite(STDOUT, "\n[node-start] $what\n");
    }

    /** The party's start-up, in this process, one native step per test in order (--debug names the test prepared last before a crash). */
    public function testStartStepSid(): void
    {
        if (!PrivateFile::isWindows()) {
            // the SID comes from advapi32 (Windows only); the later steps still run, so this step passes without the native call
            $this->assertNotSame('Windows', PHP_OS_FAMILY);
            return;
        }
        self::step('PrivateFile::currentSid');
        $this->assertNotSame('', PrivateFile::currentSid());
    }

    #[Depends('testStartStepSid')]
    public function testStartStepTempnam(): string
    {
        self::step('PrivateFile::tempnam');
        $f = PrivateFile::tempnam(sys_get_temp_dir(), 'dkgstep');
        $this->assertIsString($f);
        $this->files[] = $f;
        return $f;
    }

    #[Depends('testStartStepTempnam')]
    public function testStartStepCreate(string $f): string
    {
        self::step('PrivateFile::create (existing file, not exclusive)');
        $this->assertTrue(PrivateFile::create($f));
        self::step('PrivateFile::create (exclusive, new path)');
        $g = $f . 'x';
        $this->files[] = $g;
        $this->assertTrue(PrivateFile::create($g, true));
        return $f;
    }

    #[Depends('testStartStepCreate')]
    public function testStartStepWriteAndReadBack(string $f): string
    {
        self::step('PrivateFile::write');
        $pem = str_repeat("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", 8);
        $this->assertSame(strlen($pem), PrivateFile::write($f, $pem));
        self::step('read back');
        $this->assertSame($pem, file_get_contents($f));
        return $f;
    }

    #[Depends('testStartStepWriteAndReadBack')]
    public function testStartStepTlsContext(string $f): void
    {
        self::step('stream_context_create with the ssl options');
        $ctx = stream_context_create(['ssl' => ['local_cert' => $f, 'verify_peer' => true, 'allow_self_signed' => true]]);
        $this->assertIsResource($ctx);
    }

    public function testStartStepListen(): void
    {
        self::step('stream_socket_server');
        $s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $this->assertIsResource($s, (string)$errstr);
        self::step('stream_socket_get_name');
        $this->assertNotFalse(stream_socket_get_name($s, false));
        fclose($s);
    }

    #[Depends('testStartStepSid')]
    #[Depends('testStartStepTempnam')]
    #[Depends('testStartStepCreate')]
    #[Depends('testStartStepWriteAndReadBack')]
    #[Depends('testStartStepTlsContext')]
    #[Depends('testStartStepListen')]
    public function testStartStepStartAndClose(): void
    {
        $a = self::identity('dkg-inproc-a');
        $b = self::identity('dkg-inproc-b');
        self::step('startTlsDkgNode');
        $node = FrostDkgTls::startTlsDkgNode(['self' => 1, 'sessionId' => random_bytes(16), 'keyPem' => $a['key'], 'certPem' => $a['cert'],
            'peerCerts' => [['id' => 2, 'certPem' => $b['cert']]]]);
        $this->assertGreaterThan(0, $node->port);
        self::step('close');
        $node->close();
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
        $procs = [];
        $ports = [];
        foreach ($ids as $i) {
            $peers = [];
            foreach ($ids as $j) {
                if ($j !== $i) {
                    $peers[] = ['id' => $j, 'certPem' => $idt[$j]['cert']];
                }
            }
            [$procs[$i], $pipes[$i]] = $this->spawn(['self' => $i, 'sessionId' => $sid, 'keyPem' => $idt[$i]['key'], 'certPem' => $idt[$i]['cert'], 'peerCerts' => $peers, 't' => 2, 'participants' => $ids]);
            $line = self::line($pipes[$i][1], 20);
            $this->assertStringStartsWith('PORT ', $line, 'party ' . $i . ' did not start: ' . $this->describe($procs[$i], $pipes[$i][1], $pipes[$i][2]));
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
        [$proc, $pipes] = $this->spawn(['self' => 1, 'sessionId' => $sid, 'keyPem' => $a['key'], 'certPem' => $a['cert'], 'peerCerts' => [['id' => 2, 'certPem' => $b['cert']]],
            'mode' => 'link-only', 'connectTimeoutMs' => 4000]);
        $first = self::line($pipes[1], 20);
        $this->assertStringStartsWith('PORT ', $first, 'the node did not start: ' . $this->describe($proc, $pipes[1], $pipes[2]));
        $port = (int)substr($first, 5);
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
        $this->assertStringStartsWith('ERROR ', $line, $this->describe($proc, $pipes[1], $pipes[2]));
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
