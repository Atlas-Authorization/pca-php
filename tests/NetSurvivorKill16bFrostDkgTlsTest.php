<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostDkgTls.php';

use Atlas\Pca\DkgChannelError;
use Atlas\Pca\DkgFrames;
use Atlas\Pca\FrostDkgChannel;
use Atlas\Pca\FrostDkgTls;
use Atlas\Pca\TlsDkgNode;
use PHPUnit\Framework\TestCase;

/**
 * The DKG-over-TLS node's fault paths, in this process against raw-TLS peer processes on 127.0.0.1: temp files that cannot be created,
 * a peer reset (killed with unread data, so its kernel answers with a TCP RST), a peer that never reads (the write stalls on a full
 * socket buffer and runs into its deadline, counted through TlsDkgNode::$clockHook), and data that is already waiting when collect starts.
 */
final class NetSurvivorKill16bFrostDkgTlsTest extends TestCase
{
    private const PEER = <<<'PHP'
<?php
declare(strict_types=1);
ini_set('display_errors', 'stderr');
$cfg = json_decode((string)file_get_contents($argv[1]), true);
$say = static function (string $l): void {
    fwrite(STDOUT, $l . "\n");
    fflush(STDOUT);
};
$ssl = ['verify_peer_name' => false, 'allow_self_signed' => true, 'capture_peer_cert' => true];
if ($cfg['pem'] !== null) {
    $ssl['local_cert'] = $cfg['pem'];
}
if ($cfg['mode'] === 'server') {
    $ssl['verify_peer'] = true;
    $ssl['cafile'] = $cfg['cafile'];
    $srv = stream_socket_server('tcp://127.0.0.1:0', $no, $str, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, stream_context_create(['ssl' => $ssl]));
    $name = (string)stream_socket_get_name($srv, false);
    $say('PORT ' . substr($name, (int)strrpos($name, ':') + 1));
    $c = @stream_socket_accept($srv, 30);
    if ($c === false) {
        $say('NOACCEPT');
        exit(0);
    }
    if (@stream_socket_enable_crypto($c, true, STREAM_CRYPTO_METHOD_TLSv1_3_SERVER) !== true) {
        $say('NOTLS');
        exit(0);
    }
    $pc = stream_context_get_options($c)['ssl']['peer_certificate'] ?? null;
    if (($pc === null ? null : openssl_x509_fingerprint($pc, 'sha256')) !== $cfg['expect']) {
        $say('REJECT');
        fclose($c);
        exit(0);
    }
} else {
    $c = @stream_socket_client('tcp://127.0.0.1:' . $cfg['port'], $no, $str, 10);
    if ($c === false) {
        $say('NOCONNECT');
        exit(0);
    }
    $say('TCP');
    if ($cfg['mode'] === 'client') {
        $ssl['verify_peer'] = false;
        foreach ($ssl as $k => $v) {
            stream_context_set_option($c, 'ssl', $k, $v);
        }
        if (@stream_socket_enable_crypto($c, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT) !== true) {
            $say('NOTLS');
            exit(0);
        }
    }
}
if ($cfg['gate']) {
    fgets(STDIN);
}
if ($cfg['send'] !== '') {
    fwrite($c, (string)hex2bin($cfg['send']));
}
$say('SENT');
if ($cfg['then'] === 'close') {
    fgets(STDIN);
    fclose($c);
    $say('CLOSED');
    exit(0);
}
stream_set_timeout($c, (int)$cfg['hold']);
$got = '';
while (!feof($c)) {
    $x = fread($c, 65536);
    if ($x === false) {
        break;
    }
    if ($x === '') {
        if (stream_get_meta_data($c)['timed_out']) {
            $say('TIMEOUT');
            exit(0);
        }
        continue;
    }
    $got .= $x;
}
$say('GOT ' . bin2hex($got));
PHP;


    /** @var list<resource> */
    private array $procs = [];
    /** @var list<string> */
    private array $files = [];
    /** @var list<TlsDkgNode> */
    private array $nodes = [];
    /** @var array<string,int> lines of each output file already handed out */
    private array $consumed = [];
    private int $calls = 0;
    private string $sid = '';
    private ?string $script = null;

    protected function setUp(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('needs the openssl extension');
        }
        $this->sid = hash('sha256', 'net16-dkg-session', true);
    }

    protected function tearDown(): void
    {
        TlsDkgNode::$clockHook = null;
        TlsDkgNode::$tempDirHook = null;
        foreach ($this->nodes as $n) {
            $n->close();
        }
        foreach ($this->procs as $p) {
            @proc_terminate($p, 9);
            @proc_close($p);
        }
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    private function file(string $content): string
    {
        $f = (string)tempnam(sys_get_temp_dir(), 'net16');
        $this->files[] = $f;
        file_put_contents($f, $content);
        return $f;
    }

    /** @return array{key:string,cert:string,pem:string,fp:string} */
    private function identity(string $cn): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => $cn], $key, ['digest_alg' => 'sha256']);
        $x = openssl_csr_sign($csr, null, $key, 2, ['digest_alg' => 'sha256']);
        openssl_x509_export($x, $cert);
        openssl_pkey_export($key, $pem);
        return ['key' => $pem, 'cert' => $cert, 'pem' => $this->file($cert . "\n" . $pem), 'fp' => (string)openssl_x509_fingerprint($cert, 'sha256')];
    }

    /** @param array<int,array{cert:string}> $peers id => identity */
    private function node(int $self, array $me, array $peers): TlsDkgNode
    {
        $pc = [];
        foreach ($peers as $id => $p) {
            $pc[] = ['id' => $id, 'certPem' => $p['cert']];
        }
        $n = FrostDkgTls::startTlsDkgNode(['self' => $self, 'sessionId' => $this->sid, 'keyPem' => $me['key'], 'certPem' => $me['cert'], 'peerCerts' => $pc]);
        $this->nodes[] = $n;
        return $n;
    }

    /**
     * A peer process. mode client (TLS to `port`), plain (raw TCP to `port`) or server (prints PORT, accepts one TLS client whose
     * certificate must have fingerprint `expect`); then writes `send` (hex), and either holds (prints GOT <hex> at EOF, TIMEOUT after
     * `hold` s) or, for then = close, closes on a line on its stdin.
     * @return array{out:string,in:resource}
     */
    private function peer(array $cfg): array
    {
        $this->script ??= $this->file(self::PEER);
        $cfg += ['gate' => false, 'pem' => null, 'send' => '', 'then' => 'hold', 'hold' => 30, 'cafile' => null, 'expect' => null, 'port' => 0];
        $out = $this->file('');
        $err = $this->file('');
        $proc = proc_open([PHP_BINARY, $this->script, $this->file((string)json_encode($cfg))], [0 => ['pipe', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes);
        $this->assertIsResource($proc);
        $this->procs[] = $proc;
        return ['out' => $out, 'in' => $pipes[0], 'proc' => $proc];
    }

    /** The next non-empty line a peer printed (waits up to $seconds). */
    private function line(array $peer, float $seconds = 20): string
    {
        $until = microtime(true) + $seconds;
        $k = $peer['out'];
        do {
            $lines = array_values(array_filter(array_map('trim', explode("\n", (string)file_get_contents($k))), static fn(string $l): bool => $l !== ''));
            $i = $this->consumed[$k] ?? 0;
            if (isset($lines[$i])) {
                $this->consumed[$k] = $i + 1;
                return $lines[$i];
            }
            usleep(20000);
        } while (microtime(true) < $until);
        return '';
    }

    private function frame(string $kind, string $body): string
    {
        return DkgFrames::encode(FrostDkgChannel::encodeMessage($this->sid, $kind, $body));
    }

    /** The node clock reads `$times` in turn (the last one repeats), counting every read in $this->calls. */
    private function clock(float ...$times): void
    {
        $this->calls = 0;
        TlsDkgNode::$clockHook = function () use ($times): float {
            return $times[min($this->calls++, count($times) - 1)];
        };
    }

    private function expectChannelError(\Closure $f, string $message): DkgChannelError
    {
        try {
            $f();
        } catch (DkgChannelError $e) {
            $this->assertSame($message, $e->getMessage());
            return $e;
        }
        $this->fail('no DkgChannelError: ' . $message);
    }

    /** A peer killed with unread data in its receive buffer: its kernel resets the connection. Waits until it has exited. */
    private function reset(array $peer): void
    {
        proc_terminate($peer['proc'], 9);
        for ($i = 0; $i < 250 && proc_get_status($peer['proc'])['running']; $i++) {
            usleep(20000);
        }
        $this->assertFalse(proc_get_status($peer['proc'])['running']);
    }

    /** Waits (bounded) until the node's socket for $id is readable: data or a reset has arrived. */
    private function waitReadable(TlsDkgNode $n, int $id): void
    {
        $sock = (new \ReflectionProperty(TlsDkgNode::class, 'links'))->getValue($n)[$id]['sock'];
        for ($i = 0; $i < 200; $i++) {
            $r = [$sock];
            $w = $e = [];
            if (stream_select($r, $w, $e, 0, 50000) > 0) {
                return;
            }
        }
        $this->fail('the link never became readable');
    }

    /** A linked node 1 with peer 2 as a client process that never reads unless told to (see peer()). @return array{0: TlsDkgNode, 1: array} */
    private function linked(array $cfg = []): array
    {
        $me = $this->identity('n1');
        $two = $this->identity('p2');
        $node = $this->node(1, $me, [2 => $two]);
        $p = $this->peer($cfg + ['mode' => 'client', 'port' => $node->port, 'pem' => $two['pem'], 'then' => 'close']);
        $this->assertSame('TCP', $this->line($p));
        $node->connect([], 8000);
        $this->assertTrue($node->hasLink(2));
        return [$node, $p];
    }

    public function testTempFilesThatCannotBeCreated(): void
    {
        $a = $this->identity('a');
        $b = $this->identity('b');
        $blocked = $this->file('a regular file') . DIRECTORY_SEPARATOR . 'sub';
        TlsDkgNode::$tempDirHook = $blocked;
        try {
            FrostDkgTls::startTlsDkgNode(['self' => 1, 'sessionId' => 's', 'keyPem' => $a['key'], 'certPem' => $a['cert'], 'peerCerts' => [['id' => 2, 'certPem' => $b['cert']]]]);
            $this->fail('started without its key file');
        } catch (\RuntimeException $e) {
            $this->assertSame('startTlsDkgNode: cannot write a private key or certificate file', $e->getMessage());
        }
        TlsDkgNode::$tempDirHook = null;
        $node = $this->node(2, $b, [1 => $a]);
        TlsDkgNode::$tempDirHook = $blocked;
        $this->clock(0.0, 1e12);
        // the dial cannot write its one-certificate CA file: it gives up on that peer without connecting
        $this->expectChannelError(fn() => $node->connect([['id' => 1, 'host' => '127.0.0.1', 'port' => 1]], 8000), 'dkg channel (timeout, peer 1): no authenticated link to 1');
    }

    /** Bytes already waiting on a link are read before the first inbox check: the message is collected without reading the clock again. */
    public function testCollectReadsWhatHasArrivedBeforeItsFirstCheck(): void
    {
        [$node, $p] = $this->linked(['gate' => true, 'send' => bin2hex($this->frame('round1', 'hello')), 'then' => 'hold']);
        fwrite($p['in'], "go\n");
        fflush($p['in']);
        $this->assertSame('SENT', $this->line($p));
        $this->waitReadable($node, 2);
        $this->clock(0.0, 1e12);
        $this->assertSame([2 => 'hello'], $node->collect('round1', [2], 5000));
        $this->assertSame(1, $this->calls);
    }

    /** A write to a peer that reset the connection fails as a closed link. */
    public function testAWriteToAResetPeerFails(): void
    {
        [$node, $p] = $this->linked();
        $node->write(2, 'share', 'unread');
        $this->assertSame('SENT', $this->line($p));
        $this->reset($p);
        $this->waitReadable($node, 2);
        $this->expectChannelError(fn() => $node->write(2, 'share', 'z'), 'dkg channel (closed, peer 2): write failed');
    }

    /** A read from a peer that reset the connection ends the link. */
    public function testAReadFromAResetPeerEndsTheLink(): void
    {
        [$node, $p] = $this->linked();
        $node->write(2, 'share', 'unread');
        $this->assertSame('SENT', $this->line($p));
        $this->reset($p);
        $this->waitReadable($node, 2);
        $node->pump(0);
        $this->assertFalse($node->hasLink(2));
    }

    /**
     * A peer that never reads: the socket buffers fill, a write stalls, and it fails once the clock is strictly past its start + 10 s.
     * The clock advances by 1 per read, so the stalled write reads it once for its deadline and then once per wait: 11 waits.
     */
    public function testAStalledWriteRunsIntoItsDeadline(): void
    {
        [$node] = $this->linked();
        $this->calls = 0;
        TlsDkgNode::$clockHook = function (): float {
            return (float)$this->calls++;
        };
        $big = str_repeat('a', 260000);
        $failed = null;
        for ($i = 0; $i < 400 && $failed === null; $i++) {
            $before = $this->calls;
            try {
                $node->write(2, 'share', $big);
            } catch (DkgChannelError $e) {
                $failed = $e;
            }
        }
        $this->assertNotNull($failed, 'the socket buffers never filled');
        $this->assertSame('dkg channel (closed, peer 2): write failed', $failed->getMessage());
        $this->assertSame(11, $this->calls - $before - 1);
    }
}
