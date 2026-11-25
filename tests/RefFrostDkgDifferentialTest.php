<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostDkgChannel.php';

use Atlas\Pca\DkgChannel;
use Atlas\Pca\DkgChannelError;
use Atlas\Pca\DkgFrameDecoder;
use Atlas\Pca\DkgFrames;
use Atlas\Pca\DkgInbox;
use Atlas\Pca\DkgState;
use Atlas\Pca\FrostDkg;
use Atlas\Pca\FrostDkgChannel;
use Atlas\Pca\Js;
use Atlas\Pca\MemoryDkgNetwork;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The scripted channel of one replayed party: every broadcast and send is recorded; inbound entries are delivered before the collect of their phase. */
final class ScriptedDkgChannel implements DkgChannel
{
    private const PHASES = ['round1', 'share', 'complaints', 'rebuttals', 'echo'];
    public array $outbound = [];
    private DkgInbox $inbox;

    public function __construct(private readonly mixed $selfId, private readonly array $peerIds, private readonly string $sid, private array $pending)
    {
        $this->inbox = new DkgInbox($sid, $peerIds);
    }

    public function inbox(): DkgInbox
    {
        return $this->inbox;
    }

    public function self(): mixed
    {
        return $this->selfId;
    }

    public function peers(): array
    {
        return $this->peerIds;
    }

    public function broadcast(string $kind, mixed $body): void
    {
        $this->outbound[] = Obj::of(['op' => 'broadcast', 'kind' => $kind, 'bytes' => Base::outBytes(FrostDkgChannel::encodeMessage($this->sid, $kind, $body))]);
    }

    public function send(mixed $to, string $kind, mixed $body): void
    {
        foreach ($this->peerIds as $p) {
            if (Js::num($p) === Js::num($to)) {
                $this->outbound[] = Obj::of(['op' => 'send', 'kind' => $kind, 'to' => $to, 'bytes' => Base::outBytes(FrostDkgChannel::encodeMessage($this->sid, $kind, $body))]);
                return;
            }
        }
        throw new DkgChannelError('identity', $to, 'not a connected peer');
    }

    public function collect(string $kind, array $from, mixed $timeoutMs): array
    {
        $lim = array_search($kind, self::PHASES, true);
        $keep = [];
        foreach ($this->pending as $m) {
            if (array_search($m->get('kind'), self::PHASES, true) <= $lim) {
                $this->inbox->accept($m->get('from'), $m->get('bytes'));
            } else {
                $keep[] = $m;
            }
        }
        $this->pending = $keep;
        return $this->inbox->collect($kind, $from, $timeoutMs);
    }

    public function close(): void
    {
        $this->inbox->close();
    }
}

/**
 * FROST distributed key generation against the TS reference: the cases of test-data/ref-frost-dkg.json.gz and of its CI-generated companion (the cases that carry
 * derived secrets: round-2 shares, signing shares, revealed shares and the wire bytes of share messages), through the rounds, complaints, blame, echo agreement
 * and finalize, the wire codec, the inbox, the in-memory network, the party driver and the TLS framing model. A thrown error nested in a result is compared by
 * class, code and peer; its text is informative. Nothing waits: a message that has not arrived is reported at once.
 */
final class RefFrostDkgDifferentialTest extends TestCase
{
    private const FILE = 'ref-frost-dkg.json.gz';
    private const FNS = ['constants' => 1, 'dkgRound1' => 56, 'dkgVerifyRound1' => 36, 'dkgSignShare' => 20, 'dkgCheckEchoes' => 18, 'dkgQualifiedSet' => 13, 'frostDkgSimulate' => 13,
        'dkgTranscriptDigest' => 10, 'dkgRound2' => 5, 'dkgEcho' => 4, 'dkgVerifyShare' => 3, 'dkgVerifyComplaint' => 3, 'dkgFileComplaint' => 2, 'dkgResolveBlame' => 1, 'dkgFinalize' => 1,
        'decodeDkgMessage' => 56, 'decodeDkgRound1Package' => 32, 'decodeDkgShareMessage' => 27, 'decodeDkgComplaints' => 25, 'dkgInbox' => 24, 'encodeDkgMessage' => 18,
        'tlsFrameDecode' => 17, 'runDkgOverChannel' => 16, 'decodeDkgEcho' => 13, 'memoryNetwork' => 11, 'decodeDkgRebuttals' => 9, 'tlsFrameEncode' => 5];
    private const BYTES_KEYS = ['share', 'signingShare', 'groupPublicKey', 'verifyingShare', 'publicKey', 'groupCommitment'];

    public static function provide(): array
    {
        return Base::datasetsWithGen(self::FILE);
    }

    /** Seeds resolved, then `{"$bytes"}` to raw bytes and `{"$num"}` to the double, throughout. */
    private static function conv(mixed $v): mixed
    {
        $v = Base::unseed($v);
        return self::walk($v);
    }

    private static function walk(mixed $v): mixed
    {
        if ($v instanceof Obj) {
            if ($v->keys() === ['$bytes']) {
                return Base::bytes($v);
            }
            if ($v->keys() === ['$num']) {
                return match ($v->get('$num')) {
                    'NaN' => NAN, 'Infinity' => INF, '-Infinity' => -INF,
                };
            }
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::walk($v->get($k)));
            }
            return $o;
        }
        return is_array($v) ? array_map(self::walk(...), $v) : $v;
    }

    /** Raw byte members become `{"$bytes"}`. */
    private static function out(mixed $v, string $key = ''): mixed
    {
        if ($v instanceof Obj) {
            $o = new Obj();
            foreach ($v->keys() as $k) {
                $o->set($k, self::out($v->get($k), $k));
            }
            return $o;
        }
        if (is_array($v)) {
            return array_map(static fn($x) => self::out($x, $key), $v);
        }
        return is_string($v) && in_array($key, self::BYTES_KEYS, true) ? Base::outBytes($v) : $v;
    }

    private static function err(\Throwable $e): Obj
    {
        $o = Obj::of(['$throws' => $e->getMessage()]);
        if ($e instanceof DkgChannelError) {
            $o->set('code', $e->errorCode);
            $o->set('class', 'DkgChannelError');
            $o->set('peer', $e->peer);
        }
        return $o;
    }

    private static function queue(array $a): ?\Closure
    {
        $last = $a[count($a) - 1] ?? null;
        if (!($last instanceof Obj) || !$last->has('$rng')) {
            return null;
        }
        $q = $last->get('$rng');
        return static function () use (&$q): string {
            return array_shift($q) ?? throw new \LogicException('randomness draw beyond the script');
        };
    }

    private static function arr(Obj $o): array
    {
        $r = [];
        foreach ($o->keys() as $k) {
            $r[$k] = $o->get($k);
        }
        return $r;
    }

    private static function state(Obj $s): DkgState
    {
        $o = [];
        if ($s->has('coefficients')) {
            $o['coefficients'] = $s->get('coefficients');
        }
        if ($s->has('popNonce')) {
            $o['popNonce'] = $s->get('popNonce');
        }
        return FrostDkg::round1($s->get('id'), $s->get('t'), $s->get('n'), $s->get('sessionId'), $o)['state'];
    }

    private static function inboxRun(Obj $a): array
    {
        $ib = new DkgInbox($a->get('sessionId'), $a->get('peers'));
        $out = [];
        foreach ($a->get('ops') as $op) {
            try {
                switch ($op->get('op')) {
                    case 'accept':
                        $ib->accept($op->get('sender'), $op->get('bytes'));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'fail':
                        $ib->fail($op->get('peer'), new DkgChannelError($op->get('code'), null, $op->get('message')));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'peerGone':
                        $ib->peerGone($op->get('peer'));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'close':
                        $ib->close();
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'collect':
                        $out[] = Obj::of(['ok' => true, 'bodies' => self::bodies($ib->collect($op->get('kind'), $op->get('from'), $op->get('timeoutMs')))]);
                        break;
                    default:
                        throw new \RuntimeException('bad op');
                }
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        return $out;
    }

    private static function bodies(array $m): Obj
    {
        $o = new Obj();
        foreach ($m as $k => $v) {
            $o->set((string)$k, $v);
        }
        return $o;
    }

    private static function netRun(Obj $a): array
    {
        $icpt = $a->get('intercept');
        $intercept = $icpt === null ? null : static function (array $d) use ($icpt): ?string {
            $hit = (!$icpt->has('kind') || $icpt->get('kind') === $d['kind']) && (!$icpt->has('from') || Js::num($icpt->get('from')) === Js::num($d['from']))
                && (!$icpt->has('to') || Js::num($icpt->get('to')) === Js::num($d['to']));
            if (!$hit) {
                return $d['bytes'];
            }
            return match ($icpt->get('action')) {
                'drop' => null,
                'replace' => $icpt->get('bytes'),
                default => $d['bytes'],
            };
        };
        $net = new MemoryDkgNetwork($a->get('ids'), $a->get('sessionId'), $intercept);
        $ch = new Obj();
        foreach ($net->channels as $id => $c) {
            $ch->set((string)$id, Obj::of(['self' => $c->self(), 'peers' => $c->peers()]));
        }
        $out = [Obj::of(['channels' => $ch])];
        foreach ($a->get('ops') as $op) {
            try {
                $c = $op->has('at') ? ($net->channels[FrostDkgChannel::txt($op->get('at'))] ?? null) : null;
                switch ($op->get('op')) {
                    case 'broadcast':
                        $net->channels[FrostDkgChannel::txt($op->get('from'))]->broadcast($op->get('kind'), $op->get('body'));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'send':
                        $net->channels[FrostDkgChannel::txt($op->get('from'))]->send($op->get('to'), $op->get('kind'), $op->get('body'));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'deliver':
                        $net->deliver($op->get('from'), $op->get('to'), $op->get('bytes'));
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    case 'collect':
                        $out[] = Obj::of(['ok' => true, 'bodies' => self::bodies($c->collect($op->get('kind'), $op->get('fromIds'), $op->get('timeoutMs')))]);
                        break;
                    case 'close':
                        $c->close();
                        $out[] = Obj::of(['ok' => true]);
                        break;
                    default:
                        throw new \RuntimeException('bad op');
                }
            } catch (\Throwable $e) {
                $out[] = self::err($e);
            }
        }
        return $out;
    }

    private static function party(Obj $spec, ?\Closure $rng): Obj
    {
        $sid = $spec->get('sessionId');
        $self = $spec->get('self');
        $peers = $spec->has('peers') ? $spec->get('peers') : array_values(array_filter($spec->get('participants'), static fn($p): bool => Js::num($p) !== Js::num($self)));
        if (!$spec->has('peers')) {
            usort($peers, static fn($a, $b): int => Js::num($a) <=> Js::num($b));
        }
        $ch = new ScriptedDkgChannel($self, $peers, $sid, $spec->get('inbound') ?? []);
        foreach ($spec->get('gone') ?? [] as $g) {
            $ch->inbox()->peerGone($g);
        }
        try {
            $r = FrostDkgChannel::run($ch, ['t' => $spec->get('t'), 'participants' => $spec->get('participants'), 'sessionId' => $sid, 'timeoutMs' => $spec->get('timeoutMs'), 'random' => $rng]);
            return Obj::of(['outbound' => $ch->outbound, 'result' => self::out(Obj::of(['qualified' => $r['qualified'], 'complaints' => $r['complaints'], 'keyPackage' => $r['keyPackage']]))]);
        } catch (\Throwable $e) {
            return Obj::of(['outbound' => $ch->outbound, 'error' => self::err($e)]);
        }
    }

    private static function tls(Obj $a): Obj
    {
        $d = new DkgFrameDecoder();
        foreach ($a->get('chunks') as $c) {
            $d->push($c);
        }
        return Obj::of(['accepted' => array_map(Base::outBytes(...), $d->accepted), 'error' => $d->error, 'buffered' => $d->buffered()]);
    }

    /** Nested thrown-error text is informative: dropped from both sides. */
    private static function norm(mixed $w, mixed $h): array
    {
        if ($w instanceof Obj && $h instanceof Obj) {
            $nw = new Obj();
            $nh = new Obj();
            foreach ($w->keys() as $k) {
                if ($k === '$throws') {
                    $nw->set($k, '');
                    $h->has($k) && $nh->set($k, '');
                    continue;
                }
                if ($h->has($k)) {
                    [$a, $b] = self::norm($w->get($k), $h->get($k));
                    $nw->set($k, $a);
                    $nh->set($k, $b);
                } else {
                    $nw->set($k, $w->get($k));
                }
            }
            foreach ($h->keys() as $k) {
                $nh->has($k) || $w->has($k) || $nh->set($k, $h->get($k));
            }
            return [$nw, $nh];
        }
        if (is_array($w) && is_array($h) && count($w) === count($h)) {
            $a = [];
            $b = [];
            foreach (array_keys($w) as $i) {
                [$a[], $b[]] = self::norm($w[$i], $h[$i]);
            }
            return [$a, $b];
        }
        return [$w, $h];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        if ($fn === '') {
            Base::missingGen($file);
        }
        $c_ = static fn(callable $f) => static function (array $a, Obj $c) use ($f) {
            $raw = $a;
            $a = array_map(self::conv(...), $a);
            $c->set('out', Base::unseed($c->get('out')));
            return $f($a, $c, self::queue($a), $raw);
        };
        $nested = static function (Obj $c, Obj|array $have) {
            [$w, $h] = self::norm($c->get('out'), $have);
            $c->set('out', $w);
            return $h;
        };
        Base::run($file, $fn, $k, [
            'constants' => $c_(static fn() => Obj::of(['DKG_WIRE_VERSION' => FrostDkgChannel::DKG_WIRE_VERSION, 'DKG_MAX_MESSAGE_BYTES' => FrostDkgChannel::DKG_MAX_MESSAGE_BYTES,
                'DKG_MAX_PARTICIPANTS' => FrostDkgChannel::DKG_MAX_PARTICIPANTS, 'DKG_MESSAGE_KINDS' => FrostDkgChannel::DKG_MESSAGE_KINDS])),
            'dkgRound1' => $c_(static function (array $a, Obj $c, ?\Closure $r, array $raw) {
                // a JS string is not a byte string (the reference types its arguments by Uint8Array)
                if (is_string($raw[3] ?? null)) {
                    throw new \InvalidArgumentException('dkgRound1: sessionId must be a non-empty byte string');
                }
                foreach ($raw[4] instanceof Obj ? ($raw[4]->get('coefficients') ?? []) : [] as $coef) {
                    if (is_string($coef)) {
                        throw new \InvalidArgumentException('ct-scalar: reduce takes 1..64 bytes');
                    }
                }
                $o = $a[4] instanceof Obj ? self::arr($a[4]) : [];
                $o['random'] = $r;
                return self::out(Obj::of(['package' => FrostDkg::round1($a[0], $a[1], $a[2], $a[3], $o)['package']]));
            }),
            'dkgVerifyRound1' => $c_(static fn(array $a) => FrostDkg::verifyRound1($a[0], $a[1], $a[2])),
            'dkgSignShare' => $c_(static fn(array $a) => FrostDkg::signShare(self::state($a[0]), $a[1], $a[2])),
            'dkgRound2' => $c_(static fn(array $a) => self::out(FrostDkg::round2(self::state($a[0]), $a[1]))),
            'dkgVerifyShare' => $c_(static fn(array $a) => FrostDkg::verifyShare($a[0], $a[1], $a[2], $a[3])),
            'dkgFileComplaint' => $c_(static fn(array $a) => FrostDkg::fileComplaint($a[0])),
            'dkgVerifyComplaint' => $c_(static fn(array $a) => FrostDkg::verifyComplaint($a[0], $a[1])),
            'dkgRebut' => $c_(static fn(array $a) => FrostDkg::rebut($a[0], $a[1], self::state($a[2]))),
            'dkgResolveBlame' => $c_(static fn(array $a) => FrostDkg::resolveBlame($a[0], $a[1], $a[2])),
            'dkgQualifiedSet' => $c_(static fn(array $a) => FrostDkg::qualifiedSet($a[0], $a[1], $a[2], $a[3] ?? [])),
            'dkgTranscriptDigest' => $c_(static fn(array $a) => FrostDkg::transcriptDigest($a[0]->get('round1Packages'), $a[0]->get('complaints'), $a[0]->get('qualified'), $a[0]->get('sessionId'))),
            'dkgEcho' => $c_(static fn(array $a) => FrostDkg::echo($a[0]->get('identifier'), $a[0]->get('round1Packages'), $a[0]->get('complaints'), $a[0]->get('qualified'), $a[0]->get('sessionId'))),
            'dkgCheckEchoes' => $c_(static fn(array $a) => FrostDkg::checkEchoes($a[0], $a[1], $a[2])),
            'dkgFinalize' => $c_(static fn(array $a) => self::out(FrostDkg::finalize($a[0], self::state($a[1]), $a[2], $a[3], $a[4] ?? null, $a[5] ?? null))),
            'frostDkgSimulate' => $c_(static function (array $a, Obj $c, ?\Closure $r) {
                $o = $a[2] instanceof Obj ? self::arr($a[2]) : [];
                $o['random'] = $r;
                $res = FrostDkg::simulate($a[0], $a[1], $o);
                $out = self::out($res);
                $out->set('sessionId', Base::outBytes($res->get('sessionId')));
                return $out;
            }),
            'encodeDkgMessage' => $c_(static fn(array $a) => Base::outBytes(FrostDkgChannel::encodeMessage($a[0], $a[1], $a[2]))),
            'decodeDkgMessage' => $c_(static function (array $a) {
                $r = FrostDkgChannel::decodeMessage($a[0], $a[1]);
                return Obj::of(['kind' => $r['kind'], 'body' => $r['body']]);
            }),
            'decodeDkgRound1Package' => $c_(static fn(array $a) => FrostDkgChannel::decodeRound1Package($a[0], $a[1])),
            'decodeDkgShareMessage' => $c_(static fn(array $a) => self::out(FrostDkgChannel::decodeShareMessage($a[0]))),
            'decodeDkgComplaints' => $c_(static fn(array $a) => FrostDkgChannel::decodeComplaints($a[0])),
            'decodeDkgRebuttals' => $c_(static fn(array $a) => FrostDkgChannel::decodeRebuttals($a[0])),
            'decodeDkgEcho' => $c_(static fn(array $a) => FrostDkgChannel::decodeEcho($a[0])),
            'dkgInbox' => $c_(static fn(array $a, Obj $c) => $nested($c, self::inboxRun($a[0]))),
            'memoryNetwork' => $c_(static fn(array $a, Obj $c) => $nested($c, self::netRun($a[0]))),
            'runDkgOverChannel' => $c_(static fn(array $a, Obj $c, ?\Closure $r) => $nested($c, self::party($a[0], $r))),
            'tlsFrameEncode' => $c_(static fn(array $a) => Base::outBytes(DkgFrames::encode($a[0]))),
            'tlsFrameDecode' => $c_(static fn(array $a) => self::tls($a[0])),
        ]);
    }

    public function testCorpusHasTheExpectedCaseCounts(): void
    {
        $have = array_fill_keys(array_keys(self::FNS), 0);
        foreach (gzfile(Base::path(self::FILE)) as $line) {
            foreach ($have as $fn => $_) {
                $have[$fn] += str_starts_with($line, '{"fn":"' . $fn . '"') ? 1 : 0;
            }
        }
        $this->assertSame(self::FNS, $have);
    }
}
