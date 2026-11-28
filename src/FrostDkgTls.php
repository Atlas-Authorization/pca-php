<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/FrostDkgChannel.php';

/**
 * REFERENCE MUTUAL-TLS CHANNEL FOR THE FROST DKG.
 *
 * One TLS 1.3 connection per pair of participants, mutually authenticated by pinned certificate: each side trusts exactly the other participants'
 * certificates, and the peer's SHA-256 certificate fingerprint maps to its participant id, so the sender identity the DKG driver sees comes from the
 * handshake and never from message content. The higher-numbered party dials the lower-numbered one. A peer without a pinned certificate, a plaintext
 * client, a TLS 1.2 client, a second connection for an already linked identity and a connection from a party that should have been dialled are all
 * refused before any DKG byte is read. Frames are a 4-byte big-endian length then the message; the length is checked against
 * {@see FrostDkgChannel::DKG_MAX_MESSAGE_BYTES} before any buffering ({@see DkgFrameDecoder}).
 *
 * PHP is synchronous: {@see TlsDkgNode::connect} and the channel's `collect` pump the sockets themselves, so each participant runs in its own process
 * (as a real ceremony does). This is a reference: certificate issuance, rotation and revocation are the deployer's.
 */
final class FrostDkgTls
{
    /**
     * Start a node: listen (port 0 = ephemeral; read {@see TlsDkgNode::$port}), default host 127.0.0.1.
     * `$opts`: self (id), sessionId (raw bytes), keyPem, certPem (this node's), peerCerts (list of `['id' => int, 'certPem' => string]`, every OTHER
     * participant, certificate only), listenPort?, listenHost?.
     * @param array<string,mixed> $opts
     */
    public static function startTlsDkgNode(array $opts): TlsDkgNode
    {
        return TlsDkgNode::start($opts);
    }
}

/** A running node: its listening socket, the pinned peers and (after {@see connect}) the authenticated links. */
final class TlsDkgNode
{
    public readonly int $port;
    /** @var resource|null */
    private $server;
    /** @var array<string,int> fingerprint => participant id */
    private array $pinned = [];
    /** @var list<int> ascending */
    private array $peers;
    /** @var array<int,array{sock:resource,dec:DkgFrameDecoder}> */
    private array $links = [];
    /** @var list<string> */
    private array $files = [];
    private DkgInbox $inbox;
    private bool $closed = false;

    private function __construct(private readonly int $self, private readonly string $sessionId, private readonly string $certFile, private readonly string $bundleFile,
                                 private readonly array $peerCerts, $server, int $port)
    {
        $this->server = $server;
        $this->port = $port;
        $this->peers = array_map(static fn(array $p): int => $p['id'], $peerCerts);
        sort($this->peers);
        $this->inbox = new DkgInbox($sessionId, $this->peers);
    }

    /** @param array<string,mixed> $opts */
    public static function start(array $opts): self
    {
        $peerCerts = [];
        $pinned = [];
        foreach ($opts['peerCerts'] ?? [] as $p) {
            $fp = openssl_x509_fingerprint((string)$p['certPem'], 'sha256');
            if ($fp === false) {
                throw new \RuntimeException('startTlsDkgNode: a peer certificate is not a certificate');
            }
            $pinned[$fp] = (int)$p['id'];
            $peerCerts[] = ['id' => (int)$p['id'], 'certPem' => (string)$p['certPem']];
        }
        $self = (int)$opts['self'];
        if (count($pinned) !== count($peerCerts) || in_array($self, array_column($peerCerts, 'id'), true)) {
            throw new \RuntimeException('startTlsDkgNode: peer certificates must be distinct and none may be this node');
        }
        $tmp = static function (string $pem): string {
            $f = PrivateFile::tempnam(self::tempDir(), 'dkgtls');
            if ($f === false || PrivateFile::write($f, $pem) === false) {
                throw new \RuntimeException('startTlsDkgNode: cannot write a private key or certificate file');
            }
            return $f;
        };
        $own = $tmp((string)$opts['certPem'] . "\n" . (string)$opts['keyPem']);
        $bundle = $tmp(implode("\n", array_column($peerCerts, 'certPem')));
        $host = (string)($opts['listenHost'] ?? '127.0.0.1');
        $server = ExclusiveListener::bind($host, (int)($opts['listenPort'] ?? 0), [], $errno, $errstr);
        if ($server === false) {
            @unlink($own);
            @unlink($bundle);
            throw new \RuntimeException("startTlsDkgNode: cannot listen ($errstr)");
        }
        $name = (string)stream_socket_get_name($server, false);
        $node = new self($self, (string)$opts['sessionId'], $own, $bundle, $peerCerts, $server, (int)substr($name, (int)strrpos($name, ':') + 1));
        $node->pinned = $pinned;
        $node->files = [$own, $bundle];
        return $node;
    }

    private function sslOptions(string $cafile): array
    {
        return ['local_cert' => $this->certFile, 'cafile' => $cafile, 'verify_peer' => true, 'verify_peer_name' => false, 'allow_self_signed' => true,
            'capture_peer_cert' => true, 'disable_compression' => true];
    }

    /** The pinned id of the peer certificate a TLS stream presented, or null. @param resource $sock */
    private function peerId($sock): ?int
    {
        $cert = stream_context_get_options($sock)['ssl']['peer_certificate'] ?? null;
        $fp = $cert === null ? false : openssl_x509_fingerprint($cert, 'sha256');
        return $fp === false ? null : ($this->pinned[$fp] ?? null);
    }

    /** @param resource $sock */
    private function attach(int $id, $sock): void
    {
        stream_set_blocking($sock, false);
        $this->links[$id] = ['sock' => $sock, 'dec' => new DkgFrameDecoder()];
    }

    /** Dial a lower-numbered peer once; true when an authenticated link to exactly that peer now exists. */
    private function dial(int $id, string $host, int $port): bool
    {
        $cert = null;
        foreach ($this->peerCerts as $p) {
            if ($p['id'] === $id) {
                $cert = $p['certPem'];
            }
        }
        $one = PrivateFile::tempnam(self::tempDir(), 'dkgtls');
        if ($one === false) {
            return false;
        }
        $this->files[] = $one;
        PrivateFile::write($one, (string)$cert);
        $sock = @stream_socket_client("tcp://$host:$port", $errno, $errstr, 2);
        if ($sock === false) {
            return false;
        }
        stream_set_timeout($sock, 5);
        foreach ($this->sslOptions($one) as $k => $v) {
            stream_context_set_option($sock, 'ssl', $k, $v);
        }
        $ok = @stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
        if ($ok !== true || $this->peerId($sock) !== $id) {
            @fclose($sock);
            return false;
        }
        $this->attach($id, $sock);
        return true;
    }

    /** Accept at most one inbound connection within `$waitMs`; only a pinned peer that should dial us (a higher id), once, is kept. */
    private function acceptOne(int $waitMs): void
    {
        $r = [$this->server];
        $w = $e = [];
        if (@stream_select($r, $w, $e, 0, $waitMs * 1000) < 1) {
            return;
        }
        $sock = @stream_socket_accept($this->server, 1);
        if ($sock === false) {
            return;
        }
        stream_set_timeout($sock, 5);
        foreach ($this->sslOptions($this->bundleFile) + ['local_cert' => $this->certFile] as $k => $v) {
            stream_context_set_option($sock, 'ssl', $k, $v);
        }
        $ok = @stream_socket_enable_crypto($sock, true, STREAM_CRYPTO_METHOD_TLSv1_3_SERVER);
        $id = $ok === true ? $this->peerId($sock) : null;
        if ($id === null || $id < $this->self || isset($this->links[$id])) {
            @fclose($sock);
            return;
        }
        $this->attach($id, $sock);
    }

    /**
     * Dial the lower-numbered peers, wait for the higher-numbered ones, and return the channel once every link is authenticated.
     * `$addresses`: list of `['id' => int, 'host' => string, 'port' => int]`. A timeout closes the node and throws a `timeout` {@see DkgChannelError}.
     * @param list<array{id:int,host:string,port:int}> $addresses
     */
    public function connect(array $addresses, int $connectTimeoutMs = 15000): DkgChannel
    {
        foreach ($addresses as $a) {
            if (!in_array((int)$a['id'], $this->peers, true)) {
                throw new DkgChannelError('identity', $a['id'], 'address for a participant that is not a pinned peer');
            }
        }
        $deadline = self::clock() + $connectTimeoutMs / 1000;
        while (count($this->links) < count($this->peers)) {
            foreach ($addresses as $a) {
                if ((int)$a['id'] < $this->self && !isset($this->links[(int)$a['id']])) {
                    $this->dial((int)$a['id'], (string)$a['host'], (int)$a['port']);
                }
            }
            $this->acceptOne(50);
            if (count($this->links) >= count($this->peers)) {
                break;
            }
            if (self::clock() > $deadline) {
                $missing = array_values(array_filter($this->peers, fn(int $p): bool => !isset($this->links[$p])));
                $this->close();
                throw new DkgChannelError('timeout', $missing[0], 'no authenticated link to ' . implode(',', $missing));
            }
            usleep(50000);
        }
        return new TlsDkgChannel($this, $this->self, $this->peers, $this->sessionId);
    }

    /** One framed message to a linked peer. */
    public function write(int $to, string $kind, mixed $body): void
    {
        $link = $this->links[$to] ?? null;
        if ($link === null) {
            throw new DkgChannelError('closed', $to, 'no authenticated link');
        }
        $frame = DkgFrames::encode(FrostDkgChannel::encodeMessage($this->sessionId, $kind, $body));
        $deadline = self::clock() + 10;
        while ($frame !== '') {
            $n = @fwrite($link['sock'], $frame);
            if ($n === false) {
                throw new DkgChannelError('closed', $to, 'write failed');
            }
            $frame = (string)substr($frame, $n);
            if ($frame !== '') {
                if (self::clock() > $deadline) {
                    throw new DkgChannelError('closed', $to, 'write failed');
                }
                $r = $e = [];
                $w = [$link['sock']];
                @stream_select($r, $w, $e, 0, 100000);
            }
        }
    }

    /** Read whatever has arrived on every link (waiting up to `$waitMs` for the first byte) and feed the inbox. */
    public function pump(int $waitMs): void
    {
        $socks = [];
        foreach ($this->links as $id => $l) {
            $socks[$id] = $l['sock'];
        }
        if ($socks === []) {
            usleep($waitMs * 1000);
            return;
        }
        $r = array_values($socks);
        $w = $e = [];
        @stream_select($r, $w, $e, 0, $waitMs * 1000);
        // a TLS stream can hold decrypted bytes the socket no longer shows: always drain every link
        foreach (array_keys($this->links) as $id) {
            $link = &$this->links[$id];
            for (;;) {
                $chunk = @fread($link['sock'], 65536);
                if ($chunk === false || $chunk === '') {
                    break;
                }
                $link['dec']->push($chunk);
            }
            foreach ($link['dec']->accepted as $bytes) {
                $this->inbox->accept($id, $bytes);
            }
            $link['dec']->accepted = [];
            $dead = false;
            if ($link['dec']->error !== null) {
                $this->inbox->fail($id, new DkgChannelError($link['dec']->error, $id, 'frame exceeds the cap'));
                $dead = true;
            } elseif (feof($link['sock'])) {
                $dead = true;
            }
            if ($dead) {
                @fclose($link['sock']);
                unset($link);
                unset($this->links[$id]);
                $this->inbox->peerGone($id);
            } else {
                unset($link);
            }
        }
    }

    /** Collect `$kind` from `$from`, pumping the links until every message arrived, a peer failed or the deadline passed. @return array<int|string,mixed> */
    public function collect(string $kind, array $from, mixed $timeoutMs): array
    {
        $deadline = self::clock() + ((Js::num($timeoutMs) ?? 30000.0) / 1000);
        for (;;) {
            $this->pump(0);
            try {
                return $this->inbox->collect($kind, $from, $timeoutMs);
            } catch (DkgChannelError $e) {
                if ($e->errorCode !== 'timeout' || self::clock() > $deadline) {
                    throw $e;
                }
            }
            $this->pump(100);
        }
    }

    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        $this->inbox->close();
        foreach ($this->links as $l) {
            @fclose($l['sock']);
        }
        $this->links = [];
        if ($this->server !== null) {
            @fclose($this->server);
            $this->server = null;
        }
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    /** @internal for the channel */
    public function hasLink(int $id): bool
    {
        return isset($this->links[$id]);
    }

    /** @internal Test seam: when set, the wall clock (epoch seconds, as microtime(true)) is read from it instead. */
    public static ?\Closure $clockHook = null;

    private static function clock(): float
    {
        return self::$clockHook !== null ? (self::$clockHook)() : microtime(true);
    }

    /** @internal Test seam: when set, the private key / certificate temp files are created in this directory instead. */
    public static ?string $tempDirHook = null;

    private static function tempDir(): string
    {
        return self::$tempDirHook ?? sys_get_temp_dir();
    }
}

/** The authenticated channel of a {@see TlsDkgNode}. */
final class TlsDkgChannel implements DkgChannel
{
    /** @param list<int> $peers */
    public function __construct(private readonly TlsDkgNode $node, private readonly int $self, private readonly array $peers, private readonly string $sessionId)
    {
    }

    public function self(): mixed
    {
        return $this->self;
    }

    public function peers(): array
    {
        return $this->peers;
    }

    public function broadcast(string $kind, mixed $body): void
    {
        foreach ($this->peers as $p) {
            $this->node->write($p, $kind, $body);
        }
    }

    public function send(mixed $to, string $kind, mixed $body): void
    {
        $t = Js::num($to);
        if ($t === null || !in_array((int)$t, $this->peers, true)) {
            throw new DkgChannelError('identity', $to, 'not a connected peer');
        }
        $this->node->write((int)$t, $kind, $body);
    }

    public function collect(string $kind, array $from, mixed $timeoutMs): array
    {
        return $this->node->collect($kind, $from, $timeoutMs);
    }

    public function close(): void
    {
        $this->node->close();
    }
}
