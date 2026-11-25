<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * TEST-ONLY fault injection for the networked MPC. Two layers, deliberately separate:
 *  - tamperFor(): a MALICIOUS SENDER rewriting its own outgoing frames at the application layer (duplicate, reorder, skipped sequence,
 *    garbage, truncation, wrong round / session, oversize length, drop, silence, a forged accusation). The bytes still travel inside
 *    valid TLS, so the receiver's framing checks decide.
 *  - MpcNetFaultProxy: a NETWORK adversary on the wire (TCP middlebox): drop / delay / truncate / bit-flip / duplicate / reorder at the
 *    byte level. TLS 1.3 record authentication rejects tampering, so the expected outcome is a `disconnect` on that link, never a
 *    silently corrupted value.
 *
 * A frame fault is ['kind' => ..., 'round' => string, 'to' => ?int, 'accuse' => ?int] with kind one of duplicate, reorder, skip-seq,
 * garbage, truncate, bitflip, wrong-round, wrong-session, oversize, drop, silent-from, extra-field, false-accuse.
 */
final class MpcNetFaults
{
    /** @param array{kind:string,round:string,to?:?int,accuse?:?int} $spec @return callable(array):list<string> the mesh `tamper` hook */
    public static function tamperFor(array $spec): callable
    {
        $stash = [];
        $silent = false;
        return static function (array $ev) use ($spec, &$stash, &$silent): array {
            if ($silent) {
                return [];
            }
            $frame = $ev['frame'];
            $raw = $ev['raw'];
            $hit = $frame['rd'] === $spec['round'] && (($spec['to'] ?? null) === null || $spec['to'] === $ev['to']);
            if ($spec['kind'] === 'reorder') {
                if (isset($stash[$ev['to']])) {
                    $held = $stash[$ev['to']];
                    unset($stash[$ev['to']]);
                    return [$raw, $held]; // later frame first, then the held-back one
                }
                if ($hit) {
                    $stash[$ev['to']] = $raw;
                    return [];
                }
                return [$raw];
            }
            if (!$hit) {
                return [$raw];
            }
            switch ($spec['kind']) {
                case 'duplicate':
                    return [$raw, $raw];
                case 'skip-seq':
                    return [MpcNetWire::encodeFrame(['seq' => $frame['seq'] + 1] + $frame)];
                case 'garbage':
                    return [pack('N', strlen($raw) - 4) . str_repeat("\x5a", strlen($raw) - 4)];
                case 'truncate':
                    return [substr($raw, 0, max(5, intdiv(strlen($raw), 2)))];
                case 'bitflip':
                    $i = (int) floor(strlen($raw) * 0.6);
                    $raw[$i] = chr(ord($raw[$i]) ^ 0x04);
                    return [$raw];
                case 'wrong-round':
                    return [MpcNetWire::encodeFrame(['rd' => 'zzz-' . $frame['rd']] + $frame)];
                case 'wrong-session':
                    return [MpcNetWire::encodeFrame(['sid' => 'not-this-session'] + $frame)];
                case 'oversize':
                    return [pack('N', 0x7fffffff)];
                case 'drop':
                    return [];
                case 'silent-from':
                    $silent = true;
                    return [];
                case 'false-accuse':
                    return [MpcNetWire::encodeFrame(['ty' => 'abort', 'rd' => 'abort', 'd' => ['kind' => 'timeout', 'blamed' => $spec['accuse'] ?? 0, 'detail' => 'forged accusation']] + $frame)];
                case 'extra-field':
                    $body = substr(MpcNetWire::stringify($frame), 0, -1) . ',"x":1}';
                    return [pack('N', strlen($body)) . $body];
            }
            throw new \InvalidArgumentException('unknown frame fault ' . $spec['kind']);
        };
    }
}

/**
 * A transparent TCP proxy that misbehaves once, after `afterBytes` bytes, in one direction. A wire fault is ['kind' => none|drop|delay|
 * truncate|bitflip|duplicate|reorder, 'dir' => 'c2s'|'s2c', 'afterBytes' => int, 'ms' => ?int (delay)]. Serviced by MpcNetLoop.
 */
final class MpcNetFaultProxy implements MpcNetPumpable
{
    /** @var list<string> */
    public array $log = [];
    /** @var resource|null */
    private $server = null;
    /** @var list<array{c:resource,u:resource,d:array{c2s:array,s2c:array}}> */
    private array $conns = [];

    /** @param array{host:string,port:int} $target @param array{kind:string,dir:string,afterBytes:int,ms?:?int} $fault */
    public function __construct(private readonly int $listenPort, private readonly array $target, private readonly array $fault)
    {
    }

    public function listen(): void
    {
        $errno = 0;
        $errstr = '';
        $s = ExclusiveListener::bind('127.0.0.1', $this->listenPort, [], $errno, $errstr);
        if ($s === false) {
            throw new \RuntimeException("fault proxy: cannot listen: $errstr");
        }
        stream_set_blocking($s, false);
        $this->server = $s;
        MpcNetLoop::register($this);
    }

    /** The port this proxy really holds (a listen port of 0 lets the OS choose), or -1 before {@see listen}. */
    public function port(): int
    {
        if ($this->server === null) {
            return -1;
        }
        $name = (string) stream_socket_get_name($this->server, false);
        return (int) substr($name, (int) strrpos($name, ':') + 1);
    }

    public function close(): void
    {
        foreach ($this->conns as $c) {
            @fclose($c['c']);
            @fclose($c['u']);
        }
        $this->conns = [];
        if ($this->server !== null) {
            @fclose($this->server);
            $this->server = null;
        }
        MpcNetLoop::unregister($this);
    }

    private static function newDir(): array
    {
        return ['seen' => 0, 'fired' => false, 'done' => false, 'held' => null, 'out' => '', 'delayed' => [], 'ended' => false, 'shut' => false];
    }

    public function readStreams(): array
    {
        $out = $this->server !== null ? [$this->server] : [];
        foreach ($this->conns as $c) {
            $out[] = $c['c'];
            $out[] = $c['u'];
        }
        return $out;
    }

    public function writeStreams(): array
    {
        $out = [];
        foreach ($this->conns as $c) {
            if ($c['d']['c2s']['out'] !== '') {
                $out[] = $c['u'];
            }
            if ($c['d']['s2c']['out'] !== '') {
                $out[] = $c['c'];
            }
        }
        return $out;
    }

    public function pump(): void
    {
        if ($this->server === null) {
            return;
        }
        while (($c = @stream_socket_accept($this->server, 0)) !== false) {
            $u = @stream_socket_client('tcp://' . $this->target['host'] . ':' . $this->target['port'], $errno, $errstr, 2);
            if ($u === false) {
                @fclose($c);
                continue;
            }
            stream_set_blocking($c, false);
            stream_set_blocking($u, false);
            $this->log[] = 'link opened to ' . $this->target['host'] . ':' . $this->target['port'];
            $this->conns[] = ['c' => $c, 'u' => $u, 'd' => ['c2s' => self::newDir(), 's2c' => self::newDir()]];
        }
        foreach ($this->conns as $k => &$c) {
            $this->pipe($c['c'], $c['u'], $c['d']['c2s'], 'c2s');
            $this->pipe($c['u'], $c['c'], $c['d']['s2c'], 's2c');
            if ($c['d']['c2s']['shut'] && $c['d']['s2c']['shut']) {
                $this->log[] = 'link closed after ' . $c['d']['c2s']['seen'] . ' bytes client to server, ' . $c['d']['s2c']['seen'] . ' bytes server to client';
                @fclose($c['c']);
                @fclose($c['u']);
                unset($this->conns[$k]);
            }
        }
        unset($c);
    }

    /** @param resource $from @param resource $to */
    private function pipe($from, $to, array &$st, string $dir): void
    {
        $f = $this->fault;
        $active = $f['kind'] !== 'none' && $f['dir'] === $dir;
        // deliver delayed bytes that are due, in order
        while ($st['delayed'] !== [] && $st['delayed'][0][0] <= MpcNetLoop::mono()) {
            $st['out'] .= array_shift($st['delayed'])[1];
        }
        while (!$st['ended'] && !$st['shut']) {
            $chunk = @fread($from, 65536);
            if ($chunk === false || $chunk === '') {
                if (feof($from)) {
                    if ($st['held'] !== null) {
                        $st['out'] .= $st['held'];
                        $st['held'] = null;
                    }
                    $st['ended'] = true;
                }
                break;
            }
            $before = $st['seen'];
            $st['seen'] += strlen($chunk);
            if (!$active || $st['done'] || $before + strlen($chunk) <= $f['afterBytes']) {
                if ($active && $f['kind'] === 'drop' && $st['fired']) {
                    continue; // black hole stays black
                }
                $st['out'] .= $chunk;
                continue;
            }
            if (!$st['fired']) {
                $st['fired'] = true;
                $this->log[] = "fault {$f['kind']} $dir after {$f['afterBytes']}B";
            }
            switch ($f['kind']) {
                case 'drop':
                    break;
                case 'delay':
                    $st['delayed'][] = [MpcNetLoop::mono() + ($f['ms'] ?? 1000), $chunk];
                    break;
                case 'truncate':
                    $st['done'] = true;
                    $st['out'] .= substr($chunk, 0, intdiv(strlen($chunk), 2));
                    $st['ended'] = true;
                    break;
                case 'bitflip':
                    $st['done'] = true;
                    $i = intdiv(strlen($chunk), 2);
                    $chunk[$i] = chr(ord($chunk[$i]) ^ 0x01);
                    $st['out'] .= $chunk;
                    break;
                case 'duplicate':
                    $st['done'] = true;
                    $st['out'] .= $chunk . $chunk;
                    break;
                case 'reorder':
                    if ($st['held'] === null) {
                        $st['held'] = $chunk;
                    } else {
                        $st['done'] = true;
                        $st['out'] .= $chunk . $st['held'];
                        $st['held'] = null;
                    }
                    break;
                default:
                    $st['out'] .= $chunk;
            }
        }
        while ($st['out'] !== '' && !$st['shut']) {
            $n = @fwrite($to, $st['out']);
            if ($n === false || $n === 0) {
                break;
            }
            $st['out'] = (string) substr($st['out'], $n);
        }
        // a closed side ends the other one, but only after this direction's delayed bytes are delivered (a real network delays data)
        if ($st['ended'] && $st['out'] === '' && $st['delayed'] === [] && !$st['shut']) {
            @stream_socket_shutdown($to, STREAM_SHUT_WR);
            $st['shut'] = true;
        }
    }
}
