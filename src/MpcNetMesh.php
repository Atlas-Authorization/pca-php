<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** Per-peer link state of a MpcNetMesh. */
final class MpcNetLink
{
    /** @var resource|null */
    public $sock = null;
    public MpcNetFrameSplitter $splitter;
    /** @var list<array{f:Obj,size:int,abort:?MpcNetAbort}> queued frames; `abort` marks a peer's abort claim deferred behind its earlier frames */
    public array $inbox = [];
    public int $inboxBytes = 0;
    public bool $paused = false;
    public int $sendSeq = 0;
    public int $recvSeq = 0;
    public bool $closed = false;
    public bool $helloSeen = false;
    public int $bytesIn = 0;
    public int $bytesOut = 0;
    public int $framesIn = 0;
    public int $framesOut = 0;
    /** Bytes accepted for sending but not yet written to the socket. */
    public string $out = '';

    public function __construct(public readonly int $id)
    {
        $this->splitter = new MpcNetFrameSplitter();
    }
}

/**
 * Authenticated, confidential, fail-closed point-to-point mesh over TLS 1.3.
 *
 *  - MUTUAL TLS with PINNED self-signed certificates (see MpcNetCerts). A peer is identified by the SHA-256 fingerprint of its
 *    certificate, never by anything it claims; the claimed id in the hello frame must agree with the pinned fingerprint.
 *  - Strict framing and per-link sequence numbers. A malformed frame, a duplicate / replayed frame, a skipped frame, a frame for the
 *    wrong round or session, or an oversize length prefix aborts the whole run with an ATTRIBUTABLE MpcNetAbort naming the sender.
 *  - Timeouts on every receive (no hangs); a silent peer is blamed after recvTimeoutMs.
 *  - ABORT PROPAGATION: the first failure poisons the mesh, wakes every pending receive, best-effort sends an `abort` frame to every
 *    peer and then closes the sockets. Once failed, nothing further is sent as protocol data.
 *
 * The mesh is single-threaded and non-blocking: send() queues, recv()/collect() wait through MpcNetLoop::idle() (a Fiber yield inside
 * MpcNetLoop::run, a bounded select otherwise).
 *
 * Config keys: selfId, nodes (list of ['id','host','port','certPem']), keyPem, certPem, sessionId; optional linkTo (list<int>),
 * listenHost, connectTimeoutMs, recvTimeoutMs, clock (MpcNetClock), tamper (callable(array{to,frame,raw}): list<string>, test-only,
 * needs unsafeTestHooks === true), maxInboxFrames, maxInboxBytes.
 */
class MpcNetMesh implements MpcNetPumpable
{
    /** Most non-fatal observations kept in $events; further ones are only counted. */
    public const MAX_MESH_EVENTS = 64;

    public readonly int $selfId;
    /** Non-fatal observations (e.g. a TLS client rejected at the door) for evidence logs. @var list<string> */
    public array $events = [];
    public int $eventsDropped = 0;

    /** @var array<int,MpcNetLink> */
    private array $links = [];
    /** @var array<string,int> fingerprint -> node id */
    private array $pinned = [];
    /** @var list<array{id:int,host:string,port:int,certPem:string}> */
    private array $nodes;
    private string $sessionId;
    private string $listenHost;
    private MpcNetClock $clock;
    private int $recvTimeoutMs;
    private int $connectTimeoutMs;
    private int $maxInboxFrames;
    private int $maxInboxBytes;
    /** @var callable|null */
    private $tamper;
    private ?MpcNetAbort $failure = null;
    private bool $finished = false;
    private bool $deferAborts = false;
    private bool $closedAll = false;
    private ?int $closeAt = null;
    /** @var resource|null */
    private $server = null;
    /** @var array<int,array{sock:resource,peer:?int,server:bool,started:int}> accepted / dialed connections still in the TLS handshake */
    private array $pending = [];
    private int $pendingSeq = 0;
    /** @var array<int,array{sock:mixed,state:string,retryAt:int,started:int}> */
    private array $dialers = [];
    private string $dir;
    private string $keyFile;
    private string $certFile;
    private string $caFile;
    private string $keyPem;

    /** @param array<string,mixed> $cfg */
    public function __construct(array $cfg)
    {
        $this->selfId = (int) $cfg['selfId'];
        $this->nodes = array_values($cfg['nodes']);
        $this->sessionId = (string) $cfg['sessionId'];
        $this->keyPem = (string) $cfg['keyPem'];
        $this->clock = $cfg['clock'] ?? new MpcNetWallClock();
        $this->listenHost = (string) ($cfg['listenHost'] ?? '0.0.0.0');
        $this->recvTimeoutMs = (int) ($cfg['recvTimeoutMs'] ?? 20000);
        $this->connectTimeoutMs = (int) ($cfg['connectTimeoutMs'] ?? 30000);
        $this->maxInboxFrames = (int) ($cfg['maxInboxFrames'] ?? 1024);
        $this->maxInboxBytes = (int) ($cfg['maxInboxBytes'] ?? 32 * 1024 * 1024);
        $this->tamper = $cfg['tamper'] ?? null;
        if ($this->tamper !== null && ($cfg['unsafeTestHooks'] ?? false) !== true) {
            throw new \InvalidArgumentException('mesh: the tamper test hook requires unsafeTestHooks: true (test-only)');
        }
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException('mesh: ext-openssl is required');
        }
        $self = null;
        foreach ($this->nodes as $n) {
            if ($n['id'] === $this->selfId) {
                $self = $n;
            }
        }
        if ($self === null) {
            throw new \InvalidArgumentException('mesh: self not in nodes');
        }
        $certPem = (string) $cfg['certPem'];
        if (MpcNetCerts::fingerprintOf($certPem) !== MpcNetCerts::fingerprintOf($self['certPem'])) {
            throw new \InvalidArgumentException('mesh: the node certificate differs from the one listed for this node');
        }
        $want = $cfg['linkTo'] ?? array_values(array_filter(array_map(static fn(array $n): int => $n['id'], $this->nodes), fn(int $i): bool => $i !== $this->selfId));
        $bundle = '';
        foreach ($this->nodes as $n) {
            if ($n['id'] !== $this->selfId) {
                $this->pinned[MpcNetCerts::fingerprintOf($n['certPem'])] = $n['id'];
                $bundle .= rtrim($n['certPem']) . "\n";
            }
        }
        foreach ($want as $id) {
            if (!in_array($id, array_map(static fn(array $n): int => $n['id'], $this->nodes), true)) {
                throw new \InvalidArgumentException("mesh: unknown link target $id");
            }
            $this->links[$id] = new MpcNetLink($id);
        }
        ksort($this->links);
        // the TLS layer reads its key and certificates from files: private temp files, removed at close
        $this->dir = MpcNetCerts::tempDir();
        $this->keyFile = $this->dir . '/key.pem';
        $this->certFile = $this->dir . '/cert.pem';
        $this->caFile = $this->dir . '/ca.pem';
        MpcNetCerts::writeSecret($this->keyFile, $this->keyPem);
        file_put_contents($this->certFile, $certPem);
        file_put_contents($this->caFile, $bundle);
        MpcNetLoop::register($this);
    }

    public function __destruct()
    {
        $this->close();
    }

    private function note(string $msg): void
    {
        if (count($this->events) < self::MAX_MESH_EVENTS) {
            $this->events[] = $msg;
        } else {
            $this->eventsDropped++;
        }
    }

    public function sessionId(): string
    {
        return $this->sessionId;
    }

    /** @return list<int> */
    public function peers(): array
    {
        return array_keys($this->links);
    }

    /** Whether the link to $peer has completed its authenticated hello. */
    public function linkAuthenticated(int $peer): bool
    {
        return isset($this->links[$peer]) && $this->links[$peer]->helloSeen;
    }

    public function failed(): ?MpcNetAbort
    {
        return $this->failure;
    }

    /** The id announced in the hello frame (a test subclass overrides it to impersonate). */
    protected function helloId(): int
    {
        return $this->selfId;
    }

    // ------------------------------------------------------------------ connect

    private function sslOptions(): array
    {
        // verify_peer makes a server REQUEST the client certificate (the reference sets requestCert). PHP does not turn an ABSENT client
        // certificate into a handshake error, and allow_self_signed lets any self-signed certificate through the chain check, so the
        // gate is pinnedIdOf(): capture_peer_cert + the SHA-256 pin + the validity window, run on every established stream before a link exists.
        return ['ssl' => ['local_cert' => $this->certFile, 'local_pk' => $this->keyFile, 'cafile' => $this->caFile, 'verify_peer' => true,
            'verify_peer_name' => false, 'allow_self_signed' => true, 'capture_peer_cert' => true, 'disable_compression' => true, 'SNI_enabled' => false]];
    }

    private function address(int $id): array
    {
        foreach ($this->nodes as $n) {
            if ($n['id'] === $id) {
                return $n;
            }
        }
        throw new \LogicException('unknown node');
    }

    /** Listen, dial every lower-numbered link target, and wait until all links are authenticated. */
    public function connect(): void
    {
        $self = $this->address($this->selfId);
        $errno = 0;
        $errstr = '';
        $srv = @stream_socket_server('tcp://' . $this->listenHost . ':' . $self['port'], $errno, $errstr, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, stream_context_create($this->sslOptions()));
        if ($srv === false) {
            throw new \RuntimeException("mesh: cannot listen on {$this->listenHost}:{$self['port']}: $errstr");
        }
        stream_set_blocking($srv, false);
        $this->server = $srv;
        $deadline = $this->clock->now() + $this->connectTimeoutMs;
        foreach ($this->peers() as $id) {
            if ($id < $this->selfId) {
                $this->dialers[$id] = ['sock' => null, 'state' => 'idle', 'retryAt' => 0, 'started' => 0];
            }
        }
        while (true) {
            if ($this->failure !== null) {
                throw $this->failure;
            }
            $missing = array_values(array_filter($this->peers(), fn(int $i): bool => !$this->links[$i]->helloSeen));
            if ($missing === []) {
                return;
            }
            if ($this->clock->now() > $deadline) {
                $e = new MpcNetAbort('timeout', $missing[0], $this->selfId, 'connect: no authenticated link from ' . implode(',', $missing));
                $this->fail($e);
                throw $e;
            }
            MpcNetLoop::idle();
        }
    }

    private function dialStep(int $id, array &$d): void
    {
        $now = MpcNetLoop::mono();
        if ($d['state'] === 'done' || $this->failure !== null) {
            return;
        }
        if ($d['state'] === 'idle') {
            if ($now < $d['retryAt']) {
                return;
            }
            $node = $this->address($id);
            $errno = 0;
            $errstr = '';
            $s = @stream_socket_client('tcp://' . $node['host'] . ':' . $node['port'], $errno, $errstr, 0, STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT, stream_context_create($this->sslOptions()));
            if ($s === false) {
                $d['retryAt'] = $now + 150;
                return;
            }
            stream_set_blocking($s, false);
            $d = ['sock' => $s, 'state' => 'connecting', 'retryAt' => 0, 'started' => $now];
            return;
        }
        $s = $d['sock'];
        if ($d['state'] === 'connecting') {
            $r = [];
            $w = [$s];
            $e = [];
            if (@stream_select($r, $w, $e, 0) < 1) {
                if ($now - $d['started'] > 5000) {
                    $this->dialRetry($d);
                }
                return;
            }
            $d['state'] = 'tls';
        }
        $st = $this->cryptoStep($s, false);
        if ($st === 0) {
            if ($now - $d['started'] > 10000) {
                $this->dialRetry($d);
            }
            return;
        }
        if ($st < 0) {
            $this->dialRetry($d);
            return;
        }
        $got = $this->pinnedIdOf($s);
        $d = ['sock' => null, 'state' => 'done', 'retryAt' => 0, 'started' => 0];
        if ($got !== $id) {
            @fclose($s);
            $this->fail(new MpcNetAbort('identity', $id, $this->selfId, "dial: peer certificate is not the pinned identity of node $id"));
            return;
        }
        $this->attach($id, $s);
    }

    private function dialRetry(array &$d): void
    {
        if (is_resource($d['sock'])) {
            @fclose($d['sock']);
        }
        $d = ['sock' => null, 'state' => 'idle', 'retryAt' => MpcNetLoop::mono() + 150, 'started' => 0]; // retry pacing: real time
    }

    /** One non-blocking TLS 1.3 handshake step: 1 done, 0 needs more I/O, -1 failed. @param resource $s */
    private function cryptoStep($s, bool $server): int
    {
        $m = $server ? STREAM_CRYPTO_METHOD_TLSv1_3_SERVER : STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
        $r = @stream_socket_enable_crypto($s, true, $m);
        return $r === true ? 1 : ($r === 0 ? 0 : -1);
    }

    /**
     * The id of the node whose PINNED certificate the peer of an established TLS stream presented, or null (fail closed): no certificate
     * at all (a server that requested one and was given none), a certificate that is not in its validity window (as OpenSSL would refuse
     * it), or a SHA-256 fingerprint that is not pinned. Used by both sides, so a client certificate is required exactly as the reference's
     * requestCert + pinned ca does.
     * @param resource $s
     */
    private function pinnedIdOf($s): ?int
    {
        $c = stream_context_get_params($s)['options']['ssl']['peer_certificate'] ?? null;
        if ($c === null) {
            return null;
        }
        $info = @openssl_x509_parse($c);
        $now = time();
        if (!is_array($info) || !isset($info['validFrom_time_t'], $info['validTo_time_t']) || $now < $info['validFrom_time_t'] || $now > $info['validTo_time_t']) {
            return null;
        }
        $fp = @openssl_x509_fingerprint($c, 'sha256');
        return is_string($fp) ? ($this->pinned[strtolower($fp)] ?? null) : null;
    }

    /** @param resource $s */
    private function onIncoming($s): void
    {
        $id = $this->pinnedIdOf($s);
        if ($id === null || !isset($this->links[$id]) || $id < $this->selfId) {
            $this->note('rejected incoming connection (' . ($id === null ? 'no pinned client certificate' : "node $id") . ')');
            @fclose($s);
            return;
        }
        if ($this->links[$id]->sock !== null) {
            $this->note("duplicate connection from node $id");
            @fclose($s);
            return;
        }
        $this->attach($id, $s);
    }

    /** @param resource $sock */
    private function attach(int $id, $sock): void
    {
        $l = $this->links[$id];
        if ($l->sock !== null) {
            @fclose($sock);
            return;
        }
        stream_set_blocking($sock, false);
        $l->sock = $sock;
        // hello: first frame on every link (seq 0); carries our id so the peer can cross-check the pin
        $this->sendFrame($l, 'hello', 'hello', ['id' => $this->helloId()]);
    }

    // ------------------------------------------------------------------ the loop's service routine

    public function readStreams(): array
    {
        $out = [];
        if ($this->server !== null) {
            $out[] = $this->server;
        }
        foreach ($this->pending as $p) {
            $out[] = $p['sock'];
        }
        foreach ($this->dialers as $d) {
            if (is_resource($d['sock'])) {
                $out[] = $d['sock'];
            }
        }
        foreach ($this->links as $l) {
            if ($l->sock !== null && !$l->closed && !$l->paused) {
                $out[] = $l->sock;
            }
        }
        return $out;
    }

    public function writeStreams(): array
    {
        $out = [];
        foreach ($this->dialers as $d) {
            if (is_resource($d['sock']) && $d['state'] === 'connecting') {
                $out[] = $d['sock'];
            }
        }
        foreach ($this->links as $l) {
            if ($l->sock !== null && !$l->closed && $l->out !== '') {
                $out[] = $l->sock;
            }
        }
        return $out;
    }

    public function pump(): void
    {
        if ($this->closedAll) {
            return;
        }
        if ($this->server !== null) {
            while ($this->failure === null && ($c = @stream_socket_accept($this->server, 0)) !== false) {
                stream_set_blocking($c, false);
                $this->pending[++$this->pendingSeq] = ['sock' => $c, 'peer' => null, 'server' => true, 'started' => MpcNetLoop::mono()];
            }
            foreach ($this->pending as $k => $p) {
                $st = $this->cryptoStep($p['sock'], true);
                if ($st === 0 && MpcNetLoop::mono() - $p['started'] < 10000) {
                    continue;
                }
                unset($this->pending[$k]);
                if ($st === 1) {
                    $this->onIncoming($p['sock']);
                } else {
                    $this->note($st < 0 ? 'tlsClientError: handshake refused' : 'tlsClientError: handshake timed out');
                    @fclose($p['sock']);
                }
            }
            foreach ($this->dialers as $id => $_) {
                $this->dialStep($id, $this->dialers[$id]);
            }
        }
        foreach ($this->links as $l) {
            if ($l->sock === null || $l->closed) {
                continue;
            }
            $this->flush($l);
            $this->readLink($l);
        }
        if ($this->closeAt !== null && MpcNetLoop::mono() >= $this->closeAt) {
            $this->close();
        }
    }

    private function flush(MpcNetLink $l): void
    {
        while ($l->out !== '' && $l->sock !== null && !$l->closed) {
            $n = @fwrite($l->sock, $l->out);
            if ($n === false || $n === 0) {
                if ($n === false && feof($l->sock)) {
                    $this->onClosed($l, 'socket error: write failed');
                }
                return;
            }
            $l->out = (string) substr($l->out, $n);
        }
    }

    private function readLink(MpcNetLink $l): void
    {
        while ($l->sock !== null && !$l->closed && !$l->paused && $this->failure === null) {
            $d = @fread($l->sock, 65536);
            if ($d === false || $d === '') {
                if (feof($l->sock)) {
                    $this->onClosed($l, 'socket closed');
                }
                return;
            }
            $this->onData($l, $d);
        }
    }

    // ------------------------------------------------------------------ receive path

    private static function isSafeId(mixed $x, int $max): ?int
    {
        if (!$x instanceof Num) {
            return null;
        }
        $f = $x->float();
        if (!is_finite($f) || $f !== floor($f) || ($f === 0.0 && fdiv(1, $f) < 0) || $f < 0 || $f > $max) {
            return null;
        }
        return (int) $f;
    }

    private static function sanitize(string $x, int $max): string
    {
        return substr((string) preg_replace('/[^\x20-\x7e]/', '?', $x), 0, $max);
    }

    private function onData(MpcNetLink $l, string $chunk): void
    {
        if ($this->failure !== null) {
            return;
        }
        $l->bytesIn += strlen($chunk);
        try {
            $bodies = $l->splitter->push($chunk);
        } catch (\LengthException) {
            $this->fail(new MpcNetAbort('oversize', $l->id, $this->selfId, 'length prefix above MAX_FRAME_BYTES'));
            return;
        }
        foreach ($bodies as $b) {
            $f = MpcNetWire::parseFrame($b);
            if ($f === null) {
                $pv = MpcNetWire::versionMismatch($b);
                if ($pv !== null) {
                    $this->fail(new MpcNetAbort('version', $l->id, $this->selfId, "peer {$l->id} speaks wire version $pv, this node speaks " . MpcNetWire::WIRE_VERSION . '; upgrade both peers'));
                    return;
                }
                $this->fail(new MpcNetAbort('malformed', $l->id, $this->selfId, 'undecodable or ill-shaped frame'));
                return;
            }
            if ($f->get('sid') !== $this->sessionId) {
                $this->fail(new MpcNetAbort('wrong-session', $l->id, $this->selfId, 'frame from another session'));
                return;
            }
            $ty = $f->get('ty');
            $d = $f->get('d');
            if ($ty === 'abort') {
                // An abort frame is only a CLAIM by the peer that sent it. We blame that peer (the authenticated sender), never
                // the party it names: otherwise any peer could frame an honest one.
                $o = $d instanceof Obj ? $d : null;
                $relayed = $o !== null && $o->get('relayed') === true;
                $k = $o?->get('kind');
                $claimedKind = is_string($k) && in_array($k, MpcNetWire::ABORT_KINDS, true) ? $k : null;
                $maxId = max(array_map(static fn(array $x): int => $x['id'], $this->nodes));
                $claimedBlame = self::isSafeId($o?->get('blamed'), $maxId);
                $det = $o?->get('detail');
                $detail = is_string($det) ? self::sanitize($det, 120) : '';
                $claim = new MpcNetAbort('peer-abort', $relayed ? null : $l->id, $this->selfId,
                    "peer {$l->id} " . ($relayed ? 'relayed' : 'reported') . ' an abort (' . ($claimedKind ?? 'unspecified') . ', accuses '
                    . ($claimedBlame === null ? 'no one' : (string) $claimedBlame) . ', unverified) ' . $detail,
                    $claimedKind, $claimedBlame,
                    $relayed ? 'relayed abort: a second-hand claim passed on by an honest peer; it names no one and is never evidence' : null);
                if ($this->deferAborts) {
                    // Order-preserving: the claim takes effect when it is READ, i.e. only after every frame this peer sent before it.
                    $l->inbox[] = ['f' => $f, 'size' => strlen($b), 'abort' => $claim];
                    continue;
                }
                $this->fail($claim, $l->id);
                return;
            }
            $seq = (int) $f->get('seq')->float();
            if ($seq !== $l->recvSeq) {
                $this->fail(new MpcNetAbort($seq < $l->recvSeq ? 'duplicate' : 'out-of-order', $l->id, $this->selfId, "expected seq {$l->recvSeq}, got $seq (round " . $f->get('rd') . ')'));
                return;
            }
            $l->recvSeq++;
            $l->framesIn++;
            if ($ty === 'hello') {
                $id = $d instanceof Obj ? $d->get('id') : null;
                if ($l->helloSeen || !$id instanceof Num || $id->float() !== (float) $l->id) {
                    $this->fail(new MpcNetAbort('identity', $l->id, $this->selfId, 'hello claims id ' . ($id instanceof Num ? $id->lexeme : 'none') . " on the link pinned to {$l->id}"));
                    return;
                }
                $l->helloSeen = true;
            } else {
                if (!$l->helloSeen) {
                    $this->fail(new MpcNetAbort('malformed', $l->id, $this->selfId, 'data before hello'));
                    return;
                }
                $l->inbox[] = ['f' => $f, 'size' => strlen($b), 'abort' => null];
                $l->inboxBytes += strlen($b);
                if (count($l->inbox) > $this->maxInboxFrames || $l->inboxBytes > $this->maxInboxBytes) {
                    $this->fail(new MpcNetAbort('flood', $l->id, $this->selfId, "peer {$l->id} queued more than the inbox cap allows"));
                    return;
                }
                if (!$l->paused && (count($l->inbox) > $this->maxInboxFrames / 2 || $l->inboxBytes > $this->maxInboxBytes / 2)) {
                    $l->paused = true; // back-pressure: stop reading this socket until the inbox drains
                }
            }
        }
    }

    private function onClosed(MpcNetLink $l, string $why): void
    {
        if ($l->closed) {
            return;
        }
        $l->closed = true;
        if (!$this->finished && $this->failure === null && !$l->helloSeen) {
            $this->note("link {$l->id} closed before hello: $why");
        }
    }

    // ------------------------------------------------------------------ send path

    private function sendFrame(MpcNetLink $l, string $ty, string $rd, mixed $d): void
    {
        $frame = ['v' => MpcNetWire::WIRE_VERSION, 'ty' => $ty, 'sid' => $this->sessionId, 'seq' => $l->sendSeq++, 'rd' => $rd, 'd' => $d];
        $raw = MpcNetWire::encodeFrame($frame);
        $outs = $this->tamper !== null && $ty !== 'hello' ? ($this->tamper)(['to' => $l->id, 'frame' => $frame, 'raw' => $raw]) : [$raw];
        foreach ($outs as $b) {
            if ($l->sock !== null && !$l->closed) {
                $l->out .= $b;
                $l->bytesOut += strlen($b);
            }
        }
        $l->framesOut++;
        if ($l->sock !== null && !$l->closed) {
            $this->flush($l);
        }
    }

    /** Send a protocol message to one peer. Throws the mesh failure if already aborted (fail closed). */
    public function send(int $to, string $round, mixed $payload): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
        $l = $this->links[$to] ?? throw new \InvalidArgumentException("mesh: no link to $to");
        $this->sendFrame($l, 'msg', $round, $payload);
    }

    /** @param ?list<int> $to default: every peer */
    public function broadcast(string $round, mixed $payload, ?array $to = null): void
    {
        foreach ($to ?? $this->peers() as $p) {
            $this->send($p, $round, $payload);
        }
    }

    /** ECDSA-P256/SHA-256 (DER) signature over $data with this node's TLS identity key (verifiable against the pinned certificate). */
    public function sign(string $data): string
    {
        $sig = '';
        if (!openssl_sign($data, $sig, $this->keyPem, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException('mesh: signing failed');
        }
        return $sig;
    }

    /** Verify $sig over $data against the PINNED certificate of node $peer. False on any failure (never throws). */
    public function verify(int $peer, string $data, string $sig): bool
    {
        if ($peer === $this->selfId) {
            return false;
        }
        foreach ($this->nodes as $n) {
            if ($n['id'] === $peer) {
                return @openssl_verify($data, $sig, $n['certPem'], OPENSSL_ALGO_SHA256) === 1;
            }
        }
        return false;
    }

    /** @return array{v:mixed}|null the next message from $from when ready (it must belong to $round), null to keep waiting */
    private function poll(int $from, string $round, int $deadline, int $timeoutMs): ?array
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
        $l = $this->links[$from] ?? throw new \InvalidArgumentException("mesh: no link to $from");
        $it = array_shift($l->inbox);
        if ($it !== null && $it['abort'] !== null) {
            $this->fail($it['abort'], $from);
            throw $it['abort'];
        }
        if ($it !== null) {
            $f = $it['f'];
            $l->inboxBytes -= $it['size'];
            if ($l->paused && count($l->inbox) <= $this->maxInboxFrames / 2 && $l->inboxBytes <= $this->maxInboxBytes / 2) {
                $l->paused = false;
            }
            if ($f->get('rd') !== $round) {
                $e = new MpcNetAbort('wrong-round', $from, $this->selfId, "expected round '$round', got '" . $f->get('rd') . "'");
                $this->fail($e);
                throw $e;
            }
            return ['v' => $f->get('d')];
        }
        if ($l->closed) {
            $e = new MpcNetAbort('disconnect', $from, $this->selfId, "link to $from closed while awaiting '$round'");
            $this->fail($e);
            throw $e;
        }
        if ($deadline - $this->clock->now() <= 0) {
            $e = new MpcNetAbort('timeout', $from, $this->selfId, "no '$round' message from $from within {$timeoutMs}ms (deadline {$timeoutMs}ms; a silent peer is blamed on this local observation only)", null, null, null, null, $timeoutMs);
            $this->fail($e);
            throw $e;
        }
        return null;
    }

    /** Receive the next message from $from, which must belong to $round. Times out; never hangs. */
    public function recv(int $from, string $round, ?int $timeoutMs = null): mixed
    {
        $timeoutMs ??= $this->recvTimeoutMs;
        $deadline = $this->clock->now() + $timeoutMs;
        while (true) {
            $r = $this->poll($from, $round, $deadline, $timeoutMs);
            if ($r !== null) {
                return $r['v'];
            }
            MpcNetLoop::idle();
        }
    }

    /**
     * While on, a peer's abort frame does not poison the mesh on arrival: it is queued behind that peer's earlier frames and only
     * takes effect when a receive from that peer reaches it (used for the blame round, so a cheater's early abort cannot pre-empt an
     * honest party that is still collecting the blame data it needs to name the culprit).
     */
    public function setDeferAborts(bool $on): void
    {
        $this->deferAborts = $on;
    }

    /**
     * Receive $round from every peer in $from; a failure on any link raises at once. All waits share one deadline.
     * @param ?list<int> $from @return array<int,mixed>
     */
    public function collect(string $round, ?array $from = null, ?int $timeoutMs = null): array
    {
        $from ??= $this->peers();
        $timeoutMs ??= $this->recvTimeoutMs;
        $deadline = $this->clock->now() + $timeoutMs;
        $got = [];
        $left = $from;
        while ($left !== []) {
            foreach ($left as $k => $p) {
                $r = $this->poll($p, $round, $deadline, $timeoutMs);
                if ($r !== null) {
                    $got[$p] = $r['v'];
                    unset($left[$k]);
                }
            }
            if ($left !== []) {
                MpcNetLoop::idle();
            }
        }
        return $got;
    }

    // ------------------------------------------------------------------ failure / shutdown

    /**
     * Poison the mesh: record the first failure, tell EVERY peer except $skipPeer (the one that just told us; the original accusation
     * is forwarded as a claim so an innocent bystander is never blamed for merely closing), close all shortly after.
     */
    public function fail(MpcNetAbort $err, ?int $skipPeer = null): void
    {
        if ($this->failure !== null) {
            return;
        }
        $this->failure = $err;
        foreach ($this->links as $l) {
            if ($l->id === $skipPeer || $l->sock === null || $l->closed) {
                continue;
            }
            try {
                $relay = $err->kind === 'peer-abort';
                $d = ['kind' => $relay ? ($err->claimedKind ?? 'peer-abort') : $err->kind, 'blamed' => $relay ? $err->claimedBlame : $err->blamed,
                    'detail' => self::sanitize($err->getMessage(), 200)];
                if ($relay) {
                    $d['relayed'] = true;
                }
                $frame = ['v' => MpcNetWire::WIRE_VERSION, 'ty' => 'abort', 'sid' => $this->sessionId, 'seq' => $l->sendSeq++, 'rd' => 'abort', 'd' => $d];
                $l->out .= MpcNetWire::encodeFrame($frame);
                $this->flush($l);
            } catch (\Throwable) {
                // best effort
            }
        }
        $this->closeAt = MpcNetLoop::mono() + 50;
    }

    /** Normal completion: flush and close. Peers that are still reading see EOF only after our data. */
    public function finish(): void
    {
        $this->finished = true;
        $end = MpcNetLoop::mono() + 100;
        while (MpcNetLoop::mono() < $end) {
            MpcNetLoop::idle();
        }
        $this->close();
    }

    /** Close every socket now and remove the temporary key material. Idempotent. */
    public function close(): void
    {
        if ($this->closedAll) {
            return;
        }
        $this->closedAll = true;
        foreach ($this->links as $l) {
            if ($l->sock !== null) {
                @fclose($l->sock);
                $l->sock = null;
            }
            $l->closed = true;
        }
        foreach ($this->pending as $p) {
            @fclose($p['sock']);
        }
        $this->pending = [];
        foreach ($this->dialers as $d) {
            if (is_resource($d['sock'])) {
                @fclose($d['sock']);
            }
        }
        $this->dialers = [];
        if ($this->server !== null) {
            @fclose($this->server);
            $this->server = null;
        }
        MpcNetLoop::unregister($this);
        if (isset($this->dir)) {
            MpcNetCerts::rmTree($this->dir);
        }
    }

    /** @return list<array{peer:int,appBytesOut:int,appBytesIn:int,framesOut:int,framesIn:int}> */
    public function stats(): array
    {
        $out = [];
        foreach ($this->links as $p => $l) {
            $out[] = ['peer' => $p, 'appBytesOut' => $l->bytesOut, 'appBytesIn' => $l->bytesIn, 'framesOut' => $l->framesOut, 'framesIn' => $l->framesIn];
        }
        return $out;
    }
}
