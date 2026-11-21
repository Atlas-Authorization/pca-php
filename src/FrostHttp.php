<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/FrostService.php';
require_once __DIR__ . '/Json.php';

/**
 * The HTTP transport of networked FROST: one signer served over loopback HTTP and the coordinator-side transport that talks to it.
 *
 * {@see SignerHttpServer} serves ONE {@see GuardianSignerService}: `POST /round1` and `POST /round2`, JSON in and out (every byte
 * string is base64url). It binds the given host (use 127.0.0.1) on a port (0: an ephemeral one) and answers one connection at a time;
 * run it in its own OS process for real trust-domain separation (`bin/pca-frost-signer`). A handler error is a refusal response, never
 * a leaked stack or share. The channel itself (confidentiality, availability) is the deployment's responsibility.
 * {@see HttpSignerTransport} is the {@see SignerTransport} of one remote signer; `timeoutMs` bounds each call (default 10 s), a failure
 * throws and the coordinator records the signer as unreachable.
 */
final class SignerHttpServer
{
    public const BODY_LIMIT = 1048576;
    private const HEADER_LIMIT = 16384;

    public readonly int $port;
    public readonly string $url;
    /** @var resource|null */
    private $socket;
    private bool $stopped = false;

    /** @param resource $socket */
    private function __construct(private readonly GuardianSignerService $service, $socket, string $host, int $port)
    {
        $this->socket = $socket;
        $this->port = $port;
        $this->url = "http://$host:$port";
    }

    /** Bind the listening socket (the server answers once {@see serve} runs). */
    public static function bind(GuardianSignerService $service, string $host = '127.0.0.1', int $port = 0): self
    {
        $socket = @stream_socket_server("tcp://$host:$port", $errno, $errstr);
        if ($socket === false) {
            throw new \RuntimeException("startSignerHttpServer: could not listen on $host:$port ($errstr)");
        }
        $name = (string)stream_socket_get_name($socket, false);
        $p = (int)substr($name, (int)strrpos($name, ':') + 1);
        if ($p <= 0) {
            throw new \RuntimeException('startSignerHttpServer: could not determine server address');
        }
        return new self($service, $socket, $host, $p);
    }

    /**
     * The status and payload for one request (pure; no socket). A non-POST is 405, an unknown path 404, anything that cannot be read is a
     * 400 refusal naming this signer.
     * @return array{0:int,1:Obj}
     */
    public static function respond(GuardianSignerService $service, string $method, string $target, string $body): array
    {
        if ($method !== 'POST') {
            return [405, Obj::of(['ok' => false, 'reason' => 'method not allowed'])];
        }
        if ($target !== '/round1' && $target !== '/round2') {
            return [404, Obj::of(['ok' => false, 'reason' => 'not found'])];
        }
        try {
            if (strlen($body) > self::BODY_LIMIT) {
                throw new \RuntimeException('request body too large');
            }
            $req = $body === '' ? new Obj() : Json::parseLax($body);
            return [200, $target === '/round1' ? $service->round1($req) : $service->round2($req)];
        } catch (\Throwable $e) {
            return [400, Obj::of(['ok' => false, 'identifier' => $service->identifier, 'refused' => true,
                'reason' => $e->getMessage() === '' ? 'bad request' : $e->getMessage()])];
        }
    }

    /**
     * Serve until {@see close} is called or `$keepGoing` returns false (checked between connections, every 250 ms while idle).
     * @param (callable():bool)|null $keepGoing
     */
    public function serve(?callable $keepGoing = null): void
    {
        while (!$this->stopped && $this->socket !== null && ($keepGoing === null || $keepGoing())) {
            $r = [$this->socket];
            $w = $e = [];
            if (@stream_select($r, $w, $e, 0, 250000) < 1) {
                continue;
            }
            $conn = @stream_socket_accept($this->socket, 1);
            if ($conn === false) {
                continue;
            }
            try {
                $this->handle($conn);
            } catch (\Throwable) {
                // a broken connection ends that connection only
            } finally {
                @fclose($conn);
            }
        }
    }

    /** @param resource $conn */
    private function handle($conn): void
    {
        stream_set_timeout($conn, 5);
        $buf = '';
        while (($end = strpos($buf, "\r\n\r\n")) === false) {
            if (strlen($buf) > self::HEADER_LIMIT) {
                return;
            }
            $chunk = fread($conn, 4096);
            if ($chunk === false || $chunk === '') {
                return;
            }
            $buf .= $chunk;
        }
        $lines = explode("\r\n", substr($buf, 0, $end));
        $parts = explode(' ', array_shift($lines));
        $method = $parts[0];
        $target = $parts[1] ?? '';
        $len = 0;
        foreach ($lines as $l) {
            if (stripos($l, 'content-length:') === 0) {
                $len = (int)trim(substr($l, 15));
            }
        }
        $body = substr($buf, $end + 4);
        if ($len > self::BODY_LIMIT) {
            $this->send($conn, 400, Obj::of(['ok' => false, 'identifier' => $this->service->identifier, 'refused' => true, 'reason' => 'request body too large']));
            return;
        }
        while (strlen($body) < $len) {
            $chunk = fread($conn, min(65536, $len - strlen($body)));
            if ($chunk === false || $chunk === '') {
                return;
            }
            $body .= $chunk;
        }
        [$status, $payload] = self::respond($this->service, $method, $target, substr($body, 0, $len));
        $this->send($conn, $status, $payload);
    }

    /** @param resource $conn */
    private function send($conn, int $status, Obj $payload): void
    {
        $json = Json::canonicalizeLenient($payload);
        $reason = [200 => 'OK', 400 => 'Bad Request', 404 => 'Not Found', 405 => 'Method Not Allowed'][$status] ?? 'OK';
        fwrite($conn, "HTTP/1.1 $status $reason\r\ncontent-type: application/json\r\ncontent-length: " . strlen($json) . "\r\nconnection: close\r\n\r\n$json");
    }

    public function close(): void
    {
        $this->stopped = true;
        if ($this->socket !== null) {
            @fclose($this->socket);
            $this->socket = null;
        }
    }
}

/** Talks to a {@see SignerHttpServer}: one instance per remote signer. */
final class HttpSignerTransport implements SignerTransport
{
    private readonly string $host;
    private readonly int $port;
    private readonly float $timeoutS;

    public function __construct(string $baseUrl, private readonly int $identifier, int|float|null $timeoutMs = null)
    {
        $u = parse_url($baseUrl);
        if (!is_array($u) || ($u['scheme'] ?? '') !== 'http' || !isset($u['host'], $u['port'])) {
            throw new \InvalidArgumentException('httpSignerTransport: baseUrl must be http://host:port');
        }
        $this->host = $u['host'];
        $this->port = $u['port'];
        $this->timeoutS = ($timeoutMs ?? 10000) / 1000;
    }

    public function identifier(): int
    {
        return $this->identifier;
    }

    public function round1(Obj $req): Obj
    {
        return $this->post('/round1', $req);
    }

    public function round2(Obj $req): Obj
    {
        return $this->post('/round2', $req);
    }

    private function post(string $path, Obj $body): Obj
    {
        $deadline = microtime(true) + $this->timeoutS;
        $conn = @stream_socket_client("tcp://{$this->host}:{$this->port}", $errno, $errstr, $this->timeoutS);
        if ($conn === false) {
            throw new \RuntimeException("httpSignerTransport: cannot connect ($errstr)");
        }
        try {
            $json = Json::canonicalizeLenient($body);
            fwrite($conn, "POST $path HTTP/1.1\r\nhost: {$this->host}:{$this->port}\r\ncontent-type: application/json\r\ncontent-length: " . strlen($json)
                . "\r\nconnection: close\r\n\r\n$json");
            $raw = '';
            while (!feof($conn)) {
                $left = $deadline - microtime(true);
                if ($left <= 0) {
                    throw new \RuntimeException('httpSignerTransport: timed out');
                }
                stream_set_timeout($conn, (int)floor($left), (int)(($left - floor($left)) * 1e6));
                $chunk = fread($conn, 65536);
                if ($chunk === false || (stream_get_meta_data($conn)['timed_out'] ?? false)) {
                    throw new \RuntimeException('httpSignerTransport: timed out');
                }
                $raw .= $chunk;
            }
        } finally {
            @fclose($conn);
        }
        $at = strpos($raw, "\r\n\r\n");
        if ($at === false) {
            throw new \RuntimeException('httpSignerTransport: malformed response');
        }
        $out = Json::parseLax(substr($raw, $at + 4));
        if (!($out instanceof Obj)) {
            throw new \RuntimeException('httpSignerTransport: response is not an object');
        }
        return $out;
    }
}

/** The reference's function names of the HTTP transport. */
final class FrostHttp
{
    /** Bind a signer HTTP server (`startSignerHttpServer`); it answers once {@see SignerHttpServer::serve} runs, so run it in its own process. */
    public static function startSignerHttpServer(GuardianSignerService $service, string $host = '127.0.0.1', int $port = 0): SignerHttpServer
    {
        return SignerHttpServer::bind($service, $host, $port);
    }

    /** The transport of one remote signer (`httpSignerTransport`); `$timeoutMs` bounds each call (default 10 s). */
    public static function httpSignerTransport(string $baseUrl, int $identifier, int|float|null $timeoutMs = null): HttpSignerTransport
    {
        return new HttpSignerTransport($baseUrl, $identifier, $timeoutMs);
    }
}
