<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostDkgTls.php';

use Atlas\Pca\DkgChannelError;
use Atlas\Pca\DkgFrameDecoder;
use Atlas\Pca\DkgFrames;
use Atlas\Pca\FrostDkgChannel;
use Atlas\Pca\FrostDkgTls;
use Atlas\Pca\TlsDkgNode;
use PHPUnit\Framework\TestCase;

/**
 * The mutual-TLS DKG node under test runs in this process; every other party is a small raw-TLS peer process on 127.0.0.1 (written to a
 * temp file at run time). Covers which inbound and outbound connections link (pinning, dial direction, wrong certificate, no certificate,
 * plaintext), the frames each way, the link teardown on hang-up and on an oversize frame, the connect / collect deadlines (through
 * TlsDkgNode::$clockHook, so no wall-clock race), address validation and the channel's send guards. Linux and Windows alike: the peers
 * write their output to files (a Windows pipe cannot be read without blocking).
 */
final class NetSurvivorKill16FrostDkgTlsTest extends TestCase
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
        $cfg += ['pem' => null, 'send' => '', 'then' => 'hold', 'hold' => 30, 'cafile' => null, 'expect' => null, 'port' => 0];
        $out = $this->file('');
        $err = $this->file('');
        $proc = proc_open([PHP_BINARY, $this->script, $this->file((string)json_encode($cfg))], [0 => ['pipe', 'r'], 1 => ['file', $out, 'w'], 2 => ['file', $err, 'w']], $pipes);
        $this->assertIsResource($proc);
        $this->procs[] = $proc;
        return ['out' => $out, 'in' => $pipes[0]];
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

    /** Pumps until the link to $id is gone (bounded). */
    private static function drainUntilGone(TlsDkgNode $n, int $id): void
    {
        for ($i = 0; $i < 200 && $n->hasLink($id); $i++) {
            $n->pump(50);
        }
    }

    private static function quiet(\Closure $f): mixed
    {
        set_error_handler(static fn(): bool => true);
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    // ---- start -------------------------------------------------------------------------------------------------------------------

    public function testStartRefusals(): void
    {
        $a = $this->identity('a');
        $b = $this->identity('b');
        try {
            self::quiet(fn() => FrostDkgTls::startTlsDkgNode(['self' => 1, 'sessionId' => 's', 'keyPem' => $a['key'], 'certPem' => $a['cert'],
                'peerCerts' => [['id' => 2, 'certPem' => 'not a certificate']]]));
            $this->fail('a junk peer certificate was pinned');
        } catch (\RuntimeException $e) {
            $this->assertSame('startTlsDkgNode: a peer certificate is not a certificate', $e->getMessage());
        }
        $first = $this->node(1, $a, [2 => $b]);
        try {
            self::quiet(fn() => FrostDkgTls::startTlsDkgNode(['self' => 2, 'sessionId' => 's', 'keyPem' => $b['key'], 'certPem' => $b['cert'],
                'peerCerts' => [['id' => 1, 'certPem' => $a['cert']]], 'listenPort' => $first->port]));
            $this->fail('a second node listened on a busy port');
        } catch (\RuntimeException $e) {
            $this->assertStringStartsWith('startTlsDkgNode: cannot listen (', $e->getMessage());
        }
    }

    // ---- linking -----------------------------------------------------------------------------------------------------------------

    /** A pinned higher-numbered peer dials in, links at once, and frames flow both ways. */
    public function testAnAcceptedPeerLinksAndExchangesFrames(): void
    {
        $me = $this->identity('n1');
        $two = $this->identity('p2');
        $node = $this->node(1, $me, [2 => $two]);
        $p = $this->peer(['mode' => 'client', 'port' => $node->port, 'pem' => $two['pem'], 'send' => bin2hex($this->frame('round1', 'hello'))]);
        $this->assertSame('TCP', $this->line($p));
        $this->clock(0.0, 1e12);
        $ch = $node->connect([['id' => 2, 'host' => '127.0.0.1', 'port' => 1]], 8000);
        $this->assertSame(1, $this->calls, 'linked in the first round: the deadline is never consulted');
        TlsDkgNode::$clockHook = null;
        $links = (new \ReflectionProperty(TlsDkgNode::class, 'links'))->getValue($node);
        $this->assertSame([2], array_keys($links));
        $this->assertFalse(stream_get_meta_data($links[2]['sock'])['blocked'], 'links are non-blocking');
        $this->assertInstanceOf(DkgFrameDecoder::class, $links[2]['dec']);
        $this->assertSame([2 => 'hello'], $ch->collect('round1', [2], 5000));
        $this->assertTrue($node->hasLink(2));
        $this->expectChannelError(fn() => $ch->send('x', 'share', 'z'), 'dkg channel (identity, peer x): not a connected peer');
        $this->expectChannelError(fn() => $ch->send(9, 'share', 'z'), 'dkg channel (identity, peer 9): not a connected peer');
        $this->expectChannelError(fn() => $node->write(9, 'share', 'z'), 'dkg channel (closed, peer 9): no authenticated link');
        $this->clock(0.0, 1e12);
        $ch->send(2, 'share', 's1');
        $ch->broadcast('echo', 'b1');
        $this->assertSame(2, $this->calls, 'a write that goes out whole never consults its deadline');
        TlsDkgNode::$clockHook = null;
        $this->assertSame('SENT', $this->line($p));
        $ch->close();
        $this->assertFalse($node->hasLink(2));
        $this->assertSame('GOT ' . bin2hex($this->frame('share', 's1') . $this->frame('echo', 'b1')), $this->line($p));
    }

    /** The higher-numbered node dials the lower peer it has an address for; the peer checks the node's certificate. */
    public function testADialledPeerLinksAndItsFramesArrive(): void
    {
        $me = $this->identity('n2');
        $one = $this->identity('p1');
        $node = $this->node(2, $me, [1 => $one]);
        $p = $this->peer(['mode' => 'server', 'pem' => $one['pem'], 'cafile' => $this->file($me['cert']), 'expect' => $me['fp'],
            'send' => bin2hex($this->frame('round1', 'from1'))]);
        $port = $this->line($p);
        $this->assertStringStartsWith('PORT ', $port);
        $ch = $node->connect([['id' => 1, 'host' => '127.0.0.1', 'port' => (int)substr($port, 5)]], 8000);
        $this->assertTrue($node->hasLink(1));
        $this->assertSame([1 => 'from1'], $ch->collect('round1', [1], 5000));
    }

    /** A certificate nobody pinned, and a TLS client with no certificate, never link. */
    public function testUnpinnedAndCertificateLessClientsAreRefused(): void
    {
        $me = $this->identity('n1');
        $node = $this->node(1, $me, [2 => $this->identity('p2')]);
        $a = $this->peer(['mode' => 'client', 'port' => $node->port, 'pem' => $this->identity('stranger')['pem']]);
        $b = $this->peer(['mode' => 'client', 'port' => $node->port]);
        $this->assertSame(['TCP', 'TCP'], [$this->line($a), $this->line($b)]);
        $this->clock(0.0, 0.0, 1e12);
        $e = $this->expectChannelError(fn() => $node->connect([], 8000), 'dkg channel (timeout, peer 2): no authenticated link to 2');
        $this->assertSame('timeout', $e->errorCode);
    }

    /** A pinned peer that should have been dialled (a lower id) is refused when it dials in. */
    public function testALowerPeerThatDialsInIsRefused(): void
    {
        $me = $this->identity('n2');
        $one = $this->identity('p1');
        $node = $this->node(2, $me, [1 => $one]);
        $p = $this->peer(['mode' => 'client', 'port' => $node->port, 'pem' => $one['pem']]);
        $this->assertSame('TCP', $this->line($p));
        $this->clock(0.0, 1e12);
        $this->expectChannelError(fn() => $node->connect([], 8000), 'dkg channel (timeout, peer 1): no authenticated link to 1');
    }

    /** The timeout names only the peers still missing, and closes the node. */
    public function testATimeoutNamesTheMissingPeersAndClosesTheNode(): void
    {
        $me = $this->identity('n1');
        $two = $this->identity('p2');
        $node = $this->node(1, $me, [2 => $two, 3 => $this->identity('p3')]);
        $p = $this->peer(['mode' => 'client', 'port' => $node->port, 'pem' => $two['pem']]);
        $this->assertSame('TCP', $this->line($p));
        $this->clock(0.0, 1e12);
        $e = $this->expectChannelError(fn() => $node->connect([], 8000), 'dkg channel (timeout, peer 3): no authenticated link to 3');
        $this->assertSame(3, $e->peer);
        $this->assertFalse($node->hasLink(2));
        $this->assertTrue((new \ReflectionProperty(TlsDkgNode::class, 'closed'))->getValue($node));
    }

    public function testAddressValidation(): void
    {
        $node = $this->node(1, $this->identity('n1'), [2 => $this->identity('p2')]);
        $this->clock(0.0, 1e12);
        $e = $this->expectChannelError(fn() => $node->connect([['id' => 9, 'host' => '127.0.0.1', 'port' => 1]], 8000),
            'dkg channel (identity, peer 9): address for a participant that is not a pinned peer');
        $this->assertSame('identity', $e->errorCode);
        $this->clock(0.0, 1e12);
        $this->expectChannelError(fn() => $node->connect([['id' => '2', 'host' => '127.0.0.1', 'port' => 1]], 8000),
            'dkg channel (timeout, peer 2): no authenticated link to 2');
    }

    /** Addresses are read as int id / string host / int port; a dial that cannot connect just leaves the peer missing. */
    public function testFailedDialsAndAddressCasts(): void
    {
        $node = $this->node(3, $this->identity('n3'), [1 => $this->identity('p1'), 2 => $this->identity('p2')]);
        $this->clock(0.0, 1e12);
        $this->expectChannelError(fn() => $node->connect([['id' => '1', 'host' => '127.0.0.1', 'port' => '1'], ['id' => 2, 'host' => 127, 'port' => 1]], 8000),
            'dkg channel (timeout, peer 1): no authenticated link to 1,2');
    }

    /** A server at a peer's address that presents another pinned peer's certificate is not that peer. */
    public function testAWrongCertificateAtAPeerAddressIsRefused(): void
    {
        $me = $this->identity('n3');
        $two = $this->identity('p2');
        $node = $this->node(3, $me, [1 => $this->identity('p1'), 2 => $two]);
        $p = $this->peer(['mode' => 'server', 'pem' => $two['pem'], 'cafile' => $this->file($me['cert']), 'expect' => $me['fp']]);
        $port = $this->line($p);
        $this->assertStringStartsWith('PORT ', $port);
        $this->clock(0.0, 1e12);
        $this->expectChannelError(fn() => $node->connect([['id' => 1, 'host' => '127.0.0.1', 'port' => (int)substr($port, 5)], ['id' => 2, 'host' => '127.0.0.1', 'port' => 1]], 8000),
            'dkg channel (timeout, peer 1): no authenticated link to 1,2');
    }

    /** Only lower-numbered peers are dialled: a higher one with a known address must dial in itself. */
    public function testOnlyLowerPeersAreDialled(): void
    {
        $me = $this->identity('n2');
        $one = $this->identity('p1');
        $three = $this->identity('p3');
        $node = $this->node(2, $me, [1 => $one, 3 => $three]);
        $ca = $this->file($me['cert']);
        $p1 = $this->peer(['mode' => 'server', 'pem' => $one['pem'], 'cafile' => $ca, 'expect' => $me['fp']]);
        $p3 = $this->peer(['mode' => 'server', 'pem' => $three['pem'], 'cafile' => $ca, 'expect' => $me['fp']]);
        $port1 = (int)substr($this->line($p1), 5);
        $port3 = (int)substr($this->line($p3), 5);
        $this->assertGreaterThan(0, $port1 * $port3);
        $this->clock(0.0, 1e12);
        $this->expectChannelError(fn() => $node->connect([['id' => 1, 'host' => '127.0.0.1', 'port' => $port1], ['id' => 3, 'host' => '127.0.0.1', 'port' => $port3]], 8000),
            'dkg channel (timeout, peer 3): no authenticated link to 3');
    }

    /** A node with no peers returns at once and never accepts the connection waiting on its listener. */
    public function testANodeWithoutPeersAcceptsNothing(): void
    {
        $node = $this->node(1, $this->identity('n1'), []);
        $p = $this->peer(['mode' => 'plain', 'port' => $node->port, 'send' => bin2hex("GET / HTTP/1.1\r\n\r\n"), 'hold' => 2]);
        $this->assertSame('TCP', $this->line($p));
        $this->assertSame([], $node->connect([], 8000)->peers());
        $this->assertSame('SENT', $this->line($p));
        $this->assertSame('TIMEOUT', $this->line($p), 'the pending connection was never accepted (and so never closed)');
    }

    // ---- deadlines -------------------------------------------------------------------------------------------------------------

    /** connect's deadline is now + 15 s by default, and only a time strictly past it times out. */
    public function testTheConnectDeadline(): void
    {
        $node = $this->node(1, $this->identity('n1'), [2 => $this->identity('p2')]);
        $this->clock(1000.0, 1014.9995, 1015.0, 1015.0005, 1e12);
        $this->expectChannelError(fn() => $node->connect([]), 'dkg channel (timeout, peer 2): no authenticated link to 2');
        $this->assertSame(4, $this->calls);
    }

    /** collect's deadline is now + timeoutMs, and only a time strictly past it gives up. */
    public function testTheCollectDeadline(): void
    {
        $node = $this->node(1, $this->identity('n1'), [2 => $this->identity('p2')]);
        $node->pump(0);
        $this->clock(1000.0, 1004.9995, 1005.0, 1005.0005, 1e12);
        $this->expectChannelError(fn() => $node->collect('round1', [2], 5000), 'dkg channel (timeout, peer 2): no round1 message from 2');
        $this->assertSame(4, $this->calls);
    }

    // ---- teardown of a link -----------------------------------------------------------------------------------------------------

    /** A peer that hangs up loses its link, and collecting from it reports the ended link at once. */
    public function testAPeerThatHangsUpEndsItsLink(): void
    {
        $me = $this->identity('n1');
        $two = $this->identity('p2');
        $node = $this->node(1, $me, [2 => $two]);
        $p = $this->peer(['mode' => 'client', 'port' => $node->port, 'pem' => $two['pem'], 'then' => 'close']);
        $this->assertSame('TCP', $this->line($p));
        $node->connect([], 8000);
        $this->assertTrue($node->hasLink(2));
        $this->assertSame('SENT', $this->line($p));
        fwrite($p['in'], "close\n");
        fflush($p['in']);
        $this->assertSame('CLOSED', $this->line($p));
        self::drainUntilGone($node, 2);
        $this->assertFalse($node->hasLink(2));
        $this->expectChannelError(fn() => $node->collect('round1', [2], 1000), 'dkg channel (closed, peer 2): link ended before its round1 message arrived');
    }

    /** A frame header over the cap fails that peer (sticky) and drops its link; the failure is rethrown without waiting. */
    public function testAnOversizeFrameFailsThePeer(): void
    {
        $me = $this->identity('n1');
        $two = $this->identity('p2');
        $node = $this->node(1, $me, [2 => $two]);
        $p = $this->peer(['mode' => 'client', 'port' => $node->port, 'pem' => $two['pem'], 'send' => bin2hex(pack('N', FrostDkgChannel::DKG_MAX_MESSAGE_BYTES + 1))]);
        $this->assertSame('TCP', $this->line($p));
        $node->connect([], 8000);
        $this->assertSame('SENT', $this->line($p));
        self::drainUntilGone($node, 2);
        $this->assertFalse($node->hasLink(2));
        $this->clock(0.0, 1e12);
        $e = $this->expectChannelError(fn() => $node->collect('round1', [2], 5000), 'dkg channel (oversize, peer 2): frame exceeds the cap');
        $this->assertSame('oversize', $e->errorCode);
        $this->assertSame(1, $this->calls, 'a peer failure is rethrown without reading the clock');
    }
}
