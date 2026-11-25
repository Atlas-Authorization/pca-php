<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Sandbox.php';

/**
 * Egress admission policy. Default deny: the only way a request is allowed is by matching a template admitted from a verified
 * operation. The template is the one outbound request an operation maps to: `{method, scheme, host, port?, path, path_prefix?, query?,
 * body_sha256?, tunnel?}`, exact host, port and method; the path exact unless `path_prefix`; the query must equal `query` (absent =
 * none); a request with a body must match `body_sha256`; `tunnel` admits a CONNECT to host:port instead.
 */
final class SandboxEgressPolicy
{
    private const DEFAULT_PORT = ['http' => 80, 'https' => 443];
    private const HOST = '(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*';

    /** @var list<array<string,mixed>> */
    private array $admissions = [];
    private \Closure $now;

    public function __construct(?\Closure $now = null)
    {
        $this->now = $now ?? static fn() => new Num((string)(int)floor(microtime(true) * 1000));
    }

    private static function nullish(mixed $v): bool
    {
        return $v === null || $v instanceof Undef;
    }

    private static function isInt(mixed $v): bool
    {
        $f = K3Sig::num($v);
        return $f !== null && floor($f) === $f;
    }

    private static function isIp(string $h): bool
    {
        return Sandbox::isIpv4($h) || Sandbox::isIpv6($h);
    }

    /** Admit the request `$operation` maps to. Throws unless `$result` allows exactly `$operation` and the template is well formed. */
    public function admit(mixed $result, mixed $operation, \Closure $toRequest, mixed $opts = null): void
    {
        if (!Sandbox::isAuthorizedFor($result, $operation)) {
            throw new \InvalidArgumentException('not_authorized: result does not allow exactly this operation');
        }
        $t = $toRequest($operation);
        if (!Jsx::truthy($t)) {
            throw new \InvalidArgumentException('no_egress_for_operation');
        }
        if (!($t instanceof Obj)) {
            throw new \TypeError('template is not an object');
        }
        $host = $t->get('host');
        if (!is_string($host)) {
            throw new \TypeError('host.toLowerCase is not a function');
        }
        if (!(self::isIp($host) || preg_match('/\A' . self::HOST . '\z/', $host) === 1) || $host !== strtolower($host)) {
            throw new \InvalidArgumentException('bad_template_host');
        }
        $scheme = $t->get('scheme');
        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new \InvalidArgumentException('bad_template_scheme');
        }
        $portRaw = $t->get('port');
        $port = $portRaw === null ? (float)self::DEFAULT_PORT[$scheme] : (K3Sig::num($portRaw) ?? NAN);
        if ($portRaw !== null && !self::isInt($portRaw) || $port < 1 || $port > 65535) {
            throw new \InvalidArgumentException('bad_template_port');
        }
        $method = $t->get('method');
        if (!is_string($method) || preg_match('/\A[A-Z]+\z/', $method) !== 1) {
            throw new \InvalidArgumentException('bad_template_method');
        }
        $path = $t->get('path');
        if (!is_string($path)) {
            throw new \TypeError('t.path.startsWith is not a function');
        }
        if (!str_starts_with($path, '/') || preg_match('~[?#\\\\]|%2e|%2f|%5c|(?:\A|/)\.\.?(?:/|\z)~i', $path) === 1) {
            throw new \InvalidArgumentException('bad_template_path');
        }
        $usesRaw = Js::opt($opts, 'uses');
        $uses = $usesRaw === null ? 1.0 : (K3Sig::num($usesRaw) ?? NAN);
        if ($usesRaw !== null && !self::isInt($usesRaw) || $uses < 1) {
            throw new \InvalidArgumentException('bad_uses');
        }
        $bound = Jsx::get($result, 'operation');
        $bid = Jsx::get($bound, 'id');
        $exp = Js::opt($opts, 'expiresAt');
        $this->admissions[] = ['op_id' => self::nullish($bid) ? '' : $bid, 'op' => $operation, 't' => $t, 'port' => $port, 'uses' => $uses,
            'expiresAt' => $exp === null ? INF : (K3Sig::num($exp) ?? NAN)];
    }

    /** @return array<string,mixed> */
    private static function urlExtras(string $url): array
    {
        $s = (string)preg_replace('/\A[\x00-\x20]+|[\x00-\x20]+\z/', '', $url);
        $s = str_replace(["\t", "\n", "\r"], '', $s);
        $rest = preg_match('/\A[A-Za-z][A-Za-z0-9+.\-]*:/', $s, $m) === 1 ? substr($s, strlen($m[0])) : $s;
        $frag = strpos($rest, '#');
        $hash = $frag !== false && strlen($rest) > $frag + 1;
        if ($frag !== false) {
            $rest = substr($rest, 0, $frag);
        }
        $q = strpos($rest, '?');
        if ($q !== false) {
            $rest = substr($rest, 0, $q);
        }
        $rest = (string)preg_replace('#\A[/\\\\]+#', '', $rest);
        $authority = preg_match('#[/\\\\]#', $rest, $cm, PREG_OFFSET_CAPTURE) === 1 ? substr($rest, 0, $cm[0][1]) : $rest;
        $user = '';
        $pw = '';
        if (str_contains($authority, '@')) {
            $info = substr($authority, 0, (int)strrpos($authority, '@'));
            $c = strpos($info, ':');
            $user = $c === false ? $info : substr($info, 0, $c);
            $pw = $c === false ? '' : substr($info, $c + 1);
        }
        return ['userinfo' => $user !== '' || $pw !== '', 'hash' => $hash];
    }

    /** @return array<string,mixed> */
    private static function parseTarget(Obj $req): array
    {
        $method = $req->get('method');
        if (!is_string($method)) {
            throw new \TypeError('method.toUpperCase is not a function');
        }
        $method = mb_strtoupper($method, 'UTF-8');
        $url = Jsx::get($req, 'url');
        $text = $url instanceof Undef ? 'undefined' : Js::str($url);
        if ($method === 'CONNECT') {
            if (preg_match('/\A([a-z0-9.-]+|\[[0-9a-f:]+\]):([0-9]{1,5})\z/i', $text, $m) !== 1) {
                return ['reason' => 'bad_connect_target'];
            }
            return ['connect' => true, 'scheme' => 'https', 'host' => strtolower((string)preg_replace('/\A\[|\]\z/', '', $m[1])), 'port' => (int)$m[2], 'path' => '', 'query' => ''];
        }
        $u = WhatwgUrl::parse($text);
        if ($u === null) {
            return ['reason' => 'not_absolute_url'];
        }
        $scheme = $u['scheme'];
        if ($scheme !== 'http' && $scheme !== 'https') {
            return ['reason' => 'bad_url'];
        }
        $ex = self::urlExtras($text);
        if ($ex['userinfo'] || $ex['hash']) {
            return ['reason' => 'bad_url'];
        }
        // encoded dots and slashes are how a prefix match is walked out of: refuse rather than decode
        if (preg_match('/%2e|%2f|%5c|\\\\/i', $u['pathname']) === 1) {
            return ['reason' => 'encoded_path'];
        }
        $hostport = $u['host'];
        if (str_starts_with($hostport, '[')) {
            $end = strpos($hostport, ']');
            $host = substr($hostport, 1, $end - 1);
            $portText = (string)substr($hostport, $end + 2);
        } else {
            $c = strpos($hostport, ':');
            $host = $c === false ? $hostport : substr($hostport, 0, $c);
            $portText = $c === false ? '' : substr($hostport, $c + 1);
        }
        return ['connect' => false, 'scheme' => $scheme, 'host' => strtolower($host), 'port' => $portText !== '' ? (int)$portText : self::DEFAULT_PORT[$scheme],
            'path' => $u['pathname'], 'query' => str_starts_with($u['search'] ?? '', '?') ? substr($u['search'], 1) : ($u['search'] ?? '')];
    }

    /** Decide and, if allowed, spend one use of the matching admission. Anything not matched is denied with a reason. */
    public function claim(mixed $req): Obj
    {
        $parsed = self::parseTarget($req);
        if (isset($parsed['reason'])) {
            return Obj::of(['allow' => false, 'reason' => $parsed['reason']]);
        }
        $body = Bytes::of(Js::opt($req, 'body')) ?? '';
        $reqMethod = mb_strtoupper($req->get('method'), 'UTF-8');
        $why = 'no_admission';
        foreach ($this->admissions as $i => $a) {
            $t = $a['t'];
            if ($parsed['connect'] !== ($t->get('tunnel') === true)) {
                continue;
            }
            if ($t->get('method') !== $reqMethod && !$parsed['connect']) {
                continue;
            }
            if ($parsed['scheme'] !== $t->get('scheme') && !$parsed['connect']) {
                continue;
            }
            if ($parsed['host'] !== $t->get('host') || (float)$parsed['port'] !== $a['port']) {
                continue;
            }
            if (!$parsed['connect']) {
                $tp = $t->get('path');
                if (Jsx::truthy($t->get('path_prefix'))) {
                    $prefix = str_ends_with($tp, '/') ? $tp : $tp . '/';
                    $ok = $parsed['path'] === $tp || str_starts_with($parsed['path'], $prefix);
                } else {
                    $ok = $parsed['path'] === $tp;
                }
                if (!$ok) {
                    continue;
                }
                $q = $t->get('query');
                if ($parsed['query'] !== ($q === null ? '' : $q)) {
                    $why = 'query_mismatch';
                    continue;
                }
                $hasBh = $t->has('body_sha256');
                $bh = $t->get('body_sha256');
                if (strlen($body) > 0 && (!$hasBh || Sandbox::sha256B64u($body) !== $bh)) {
                    $why = 'body_mismatch';
                    continue;
                }
                if (strlen($body) === 0 && $hasBh && $bh !== Sandbox::sha256B64u($body)) {
                    $why = 'body_mismatch';
                    continue;
                }
            }
            // K3Sig::num maps a non-finite reading to null, which (float) turns into a valid epoch 0: read the clock directly
            $clock = ($this->now)();
            $nowMs = $clock instanceof Num ? $clock->float() : (is_int($clock) || is_float($clock) ? (float)$clock : NAN);
            if ($a['uses'] < 1 || !(is_finite($nowMs) && $nowMs < $a['expiresAt'])) { // reported only when the request would otherwise have matched
                $why = 'spent';
                continue;
            }
            $this->admissions[$i]['uses'] -= 1;
            return Obj::of(['allow' => true, 'op_id' => $a['op_id'], 'admission' => Obj::of([
                'verb' => $a['op']->get('verb'), 'resource' => $a['op']->get('resource'), 'params_digest' => Pca::hashCanonical($a['op']->get('params'))])]);
        }
        return Obj::of(['allow' => false, 'reason' => $why]);
    }
}

/**
 * The egress forward proxy of the PCA sandbox, the server side of {@see SandboxEgressPolicy} (blocking sockets, one connection at a
 * time: run it as its own process). Set it as a non-WASM tool's only route out. Every request is claimed against the admissions; a
 * refusal answers 403 and is receipted. The upstream address is resolved here and checked with Sandbox::isPrivateAddress BEFORE
 * connecting, and the connection goes to the checked address, so an admitted hostname cannot be re-pointed at an internal service.
 * Fail closed: anything the parser does not fully understand is refused. A request body must carry Content-Length (any
 * Transfer-Encoding is refused with 400) and the connection is closed after every response.
 */
final class SandboxEgress
{
    private const HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'host'];
    private const MAX_HEAD = 65536;

    /** @var resource|null */
    private $server = null;
    public int $port = 0;

    public function __construct(
        private readonly SandboxEgressPolicy $policy,
        private readonly SandboxReceiptLog $log,
        private readonly string $runtimeClass = 'egress_default_deny',
        private readonly bool $allowPrivate = false,
        private readonly int $maxBodyBytes = 1 << 20,
        private readonly int $upstreamTimeoutMs = 10000,
        private readonly string $host = '127.0.0.1',
        private readonly int $listenPort = 0,
    ) {
    }

    public function start(): self
    {
        $s = ExclusiveListener::bind($this->host, (int)$this->listenPort, [], $errno, $errstr);
        if ($s === false) {
            throw new \RuntimeException("cannot listen: $errstr");
        }
        $this->server = $s;
        $this->port = (int)substr((string)stream_socket_get_name($s, false), (int)strrpos((string)stream_socket_get_name($s, false), ':') + 1);
        return $this;
    }

    public function close(): void
    {
        if ($this->server !== null) {
            fclose($this->server);
            $this->server = null;
        }
    }

    /** Accept and serve one connection; false when none arrived within `$timeoutSec`. */
    public function serveOne(float $timeoutSec = 1.0): bool
    {
        $c = @stream_socket_accept($this->server, $timeoutSec);
        if ($c === false) {
            return false;
        }
        try {
            $this->serve($c);
        } catch (\Throwable) { // never leak an internal error shape to the tool
            $this->reply($c, 502);
        } finally {
            fclose($c);
        }
        return true;
    }

    private function receipt(string $method, string $url, mixed $d, string $outcome, string $reason): void
    {
        $allow = $d->get('allow') === true;
        $a = $d->get('admission');
        $this->log->append($this->runtimeClass, Obj::of(['kind' => 'egress', 'subject' => Obj::of([
            'op_id' => $allow ? $d->get('op_id') : '', 'verb' => $allow ? $a->get('verb') : '',
            'resource' => $allow ? $a->get('resource') : mb_substr($method . ' ' . $url, 0, 256, 'UTF-8'),
            'params_digest' => $allow ? $a->get('params_digest') : '']), 'outcome' => $outcome, 'reason' => $reason]));
    }

    /** @param resource $c */
    private function reply($c, int $status, string $body = ''): void
    {
        $text = [200 => 'OK', 400 => 'Bad Request', 403 => 'Forbidden', 413 => 'Payload Too Large', 431 => 'Header Fields Too Large', 502 => 'Bad Gateway'][$status] ?? 'Error';
        @fwrite($c, "HTTP/1.1 $status $text\r\nconnection: close\r\ncontent-length: " . strlen($body) . "\r\n" . ($body !== '' ? "content-type: application/json\r\n" : '') . "\r\n" . $body);
    }

    /** @param resource $c */
    private function deny($c, string $method, string $url, string $reason, int $status = 403): void
    {
        $this->receipt($method, $url, Obj::of(['allow' => false, 'reason' => $reason]), 'refused', $reason);
        $this->reply($c, $status, '{"error":"egress_denied","reason":"' . $reason . '"}');
    }

    /**
     * @param resource $s
     * @return array{0:string,1:list<array{0:string,1:string}>}|null the start line and lower-cased headers
     */
    private function readHead($s, ?int &$status = null, ?string &$why = null): ?array
    {
        $raw = '';
        while (!str_ends_with($raw, "\r\n\r\n")) {
            $ch = fgets($s, 8192);
            if ($ch === false) {
                return null;
            }
            $raw .= $ch;
            if (strlen($raw) > self::MAX_HEAD) {
                $status = 431;
                $why = 'head_too_large';
                return null;
            }
        }
        $lines = explode("\r\n", substr($raw, 0, -4));
        $headers = [];
        foreach (array_slice($lines, 1) as $ln) {
            $p = strpos($ln, ':');
            if ($p === false || $p === 0) {
                $status = 400;
                $why = 'bad_header';
                return null;
            }
            $k = substr($ln, 0, $p);
            if ($k !== trim($k) || str_contains($k, ' ') || str_contains($k, "\t")) {
                $status = 400;
                $why = 'bad_header';
                return null;
            }
            $headers[] = [strtolower($k), trim(substr($ln, $p + 1))];
        }
        return [$lines[0], $headers];
    }

    /** @param resource $c */
    private function serve($c): void
    {
        $status = 400;
        $why = 'bad_request';
        $head = $this->readHead($c, $status, $why);
        if ($head === null) {
            $this->deny($c, '', '', $why, $status);
            return;
        }
        [$line, $headers] = $head;
        $parts = explode(' ', $line);
        if (count($parts) !== 3 || !str_starts_with($parts[2], 'HTTP/1.')) {
            $this->deny($c, '', '', 'bad_request_line', 400);
            return;
        }
        [$method, $url] = $parts;
        foreach ($headers as [$k]) {
            if ($k === 'transfer-encoding') {
                $this->deny($c, '', '', 'transfer_encoding', 400);
                return;
            }
        }
        $cls = [];
        foreach ($headers as [$k, $v]) {
            if ($k === 'content-length') {
                $cls[$v] = true;
            }
        }
        if (count($cls) > 1) {
            $this->deny($c, '', '', 'duplicate_content_length', 400);
            return;
        }
        $cl = $cls === [] ? null : (string)array_key_first($cls);
        if ($cl !== null && ($cl === '' ? false : preg_match('/\A[0-9]+\z/', $cl) !== 1)) {
            $this->deny($c, '', '', 'bad_content_length', 400);
            return;
        }
        $n = $cl ? (int)$cl : 0;
        if (strtoupper($method) === 'CONNECT') {
            $this->connect($c, $url);
            return;
        }
        if ($n > $this->maxBodyBytes) {
            $this->deny($c, $method, $url, 'body_too_large', 413);
            return;
        }
        $body = '';
        while (strlen($body) < $n) {
            $chunk = fread($c, $n - strlen($body));
            if ($chunk === false || $chunk === '') {
                return;
            }
            $body .= $chunk;
        }
        $d = $this->policy->claim(Obj::of(['method' => $method, 'url' => $url, 'body' => new Bytes($body)]));
        if ($d->get('allow') !== true) {
            $this->deny($c, $method, $url, (string)$d->get('reason'));
            return;
        }
        $u = parse_url($url);
        $scheme = (string)($u['scheme'] ?? 'http');
        $host = trim((string)($u['host'] ?? ''), '[]');
        $port = (int)($u['port'] ?? ($scheme === 'https' ? 443 : 80));
        try {
            $addr = $this->resolve($host, $port);
            $up = $this->open($addr, $port, $scheme === 'https' ? $host : null);
        } catch (\Throwable $e) {
            $this->receipt($method, $url, $d, 'error', substr('upstream:' . ($e instanceof \RuntimeException && $e->getMessage() === 'EACCES' ? 'EACCES' : 'error'), 0, 64));
            $this->reply($c, 502);
            return;
        }
        $sent = false;
        try {
            $path = ($u['path'] ?? '') !== '' ? $u['path'] : '/';
            $out = [$method . ' ' . $path . (isset($u['query']) ? '?' . $u['query'] : '') . ' HTTP/1.1',
                'host: ' . $host . (isset($u['port']) ? ':' . $u['port'] : ''), 'connection: close'];
            foreach ($headers as [$k, $v]) {
                if (!in_array($k, self::HOP, true)) {
                    $out[] = $k . ': ' . $v;
                }
            }
            fwrite($up, implode("\r\n", $out) . "\r\n\r\n" . $body);
            stream_set_timeout($up, intdiv($this->upstreamTimeoutMs, 1000) ?: 1);
            $st = null;
            $w = null;
            $uh = $this->readHead($up, $st, $w);
            if ($uh === null) {
                throw new \RuntimeException('bad upstream response');
            }
            $sent = true;
            $sp = explode(' ', $uh[0]);
            $code = $sp[1] ?? '502';
            $keep = [];
            foreach ($uh[1] as [$k, $v]) {
                if (!in_array($k, self::HOP, true) || $k === 'transfer-encoding') {
                    $keep[] = $k . ': ' . $v;
                }
            }
            fwrite($c, $uh[0] . "\r\n" . implode("\r\n", [...$keep, 'connection: close']) . "\r\n\r\n");
            while (!feof($up)) {
                $chunk = fread($up, 65536);
                if ($chunk === false || $chunk === '') {
                    if (stream_get_meta_data($up)['timed_out']) {
                        throw new \RuntimeException('timeout');
                    }
                    break;
                }
                fwrite($c, $chunk);
            }
            $this->receipt($method, $url, $d, 'ok', 'status:' . $code);
        } catch (\Throwable $e) {
            $this->receipt($method, $url, $d, 'error', substr('upstream:' . (new \ReflectionClass($e))->getShortName(), 0, 64));
            if (!$sent) {
                $this->reply($c, 502);
            }
        } finally {
            fclose($up);
        }
    }

    /** The first resolved address, after every resolved address passed the private-address rule (a literal is checked as is). */
    private function resolve(string $host, int $port): string
    {
        $addrs = [];
        if (Sandbox::isIpv4($host) || Sandbox::isIpv6($host)) {
            $addrs[] = $host;
        } else {
            foreach ((@gethostbynamel($host)) ?: [] as $a) {
                $addrs[] = $a;
            }
            foreach ((@dns_get_record($host, DNS_AAAA)) ?: [] as $r) {
                if (isset($r['ipv6'])) {
                    $addrs[] = $r['ipv6'];
                }
            }
        }
        if ($addrs === []) {
            throw new \RuntimeException('EACCES');
        }
        if (!$this->allowPrivate) {
            foreach ($addrs as $a) {
                if (Sandbox::isPrivateAddress($a)) {
                    throw new \RuntimeException('EACCES');
                }
            }
        }
        return $addrs[0];
    }

    /** @return resource */
    private function open(string $addr, int $port, ?string $tlsName)
    {
        $target = (str_contains($addr, ':') ? '[' . $addr . ']' : $addr) . ':' . $port;
        $ctx = stream_context_create($tlsName === null ? [] : ['ssl' => ['peer_name' => $tlsName, 'verify_peer' => true, 'verify_peer_name' => true, 'SNI_enabled' => true]]);
        $s = @stream_socket_client(($tlsName === null ? 'tcp://' : 'ssl://') . $target, $errno, $errstr, $this->upstreamTimeoutMs / 1000, STREAM_CLIENT_CONNECT, $ctx);
        if ($s === false) {
            throw new \RuntimeException('connect failed');
        }
        return $s;
    }

    /** @param resource $c */
    private function connect($c, string $target): void
    {
        $d = $this->policy->claim(Obj::of(['method' => 'CONNECT', 'url' => $target]));
        if ($d->get('allow') !== true) {
            $this->deny($c, 'CONNECT', $target, (string)$d->get('reason'));
            return;
        }
        $p = strrpos($target, ':');
        $host = trim(substr($target, 0, (int)$p), '[]');
        $port = (int)substr($target, (int)$p + 1);
        try {
            $up = $this->open($this->resolve($host, $port), $port, null);
        } catch (\Throwable $e) {
            $this->receipt('CONNECT', $target, $d, 'error', $e->getMessage() === 'EACCES' ? 'upstream:EACCES' : 'upstream:error');
            $this->reply($c, 502);
            return;
        }
        $this->receipt('CONNECT', $target, $d, 'ok', 'tunnel');
        fwrite($c, "HTTP/1.1 200 Connection Established\r\n\r\n");
        try {
            while (!feof($c) && !feof($up)) {
                $r = [$c, $up];
                $w = null;
                $e = null;
                if (stream_select($r, $w, $e, 1) === false) {
                    break;
                }
                foreach ($r as $src) {
                    $chunk = fread($src, 65536);
                    if ($chunk === false || $chunk === '') {
                        break 2;
                    }
                    fwrite($src === $c ? $up : $c, $chunk);
                }
            }
        } finally {
            fclose($up);
        }
    }
}
