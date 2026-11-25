<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/FrostDkg.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/Json.php';
require_once __DIR__ . '/Jsx.php';
require_once __DIR__ . '/Pca.php';

/** A transport or protocol failure of a DKG session, attributed to a peer when known. `code`: timeout, identity, wrong-session, duplicate, equivocation, malformed, oversize, closed, protocol, disqualified. */
final class DkgChannelError extends \RuntimeException
{
    public function __construct(public readonly string $errorCode, public readonly mixed $peer, string $message)
    {
        parent::__construct("dkg channel ($errorCode" . ($peer === null ? '' : ', peer ' . Jsx::str($peer)) . "): $message");
    }
}

/** A session's link to the other participants (broadcast, point-to-point send, collect one message kind from a set of peers). */
interface DkgChannel
{
    public function self(): mixed;

    /** @return list<mixed> */
    public function peers(): array;

    public function broadcast(string $kind, mixed $body): void;

    public function send(mixed $to, string $kind, mixed $body): void;

    /** @return array<int|string,mixed> body per sender, in ascending sender order */
    public function collect(string $kind, array $from, mixed $timeoutMs): array;

    public function close(): void;
}

/** The self-delimiting length framing of a DKG TLS stream: a 4-byte big-endian length then that many payload bytes (a length over the message cap is refused before any buffering). */
final class DkgFrames
{
    public static function encode(string $payload): string
    {
        return pack('N', strlen($payload)) . $payload;
    }
}

final class DkgFrameDecoder
{
    private string $buf = '';
    public ?string $error = null;
    /** @var list<string> */
    public array $accepted = [];

    public function push(string $chunk): void
    {
        if ($this->error !== null) {
            return;
        }
        $this->buf .= $chunk;
        while (strlen($this->buf) >= 4) {
            $len = unpack('N', $this->buf)[1];
            if ($len > FrostDkgChannel::DKG_MAX_MESSAGE_BYTES) {
                $this->error = 'oversize';
                return;
            }
            if (strlen($this->buf) < 4 + $len) {
                return;
            }
            $this->accepted[] = substr($this->buf, 4, $len);
            $this->buf = substr($this->buf, 4 + $len);
        }
    }

    public function buffered(): int
    {
        return strlen($this->buf);
    }
}

/** Per-session inbox: authenticated-sender message store with sticky duplicate/equivocation/malformed errors; `collect` reports instead of waiting (synchronous). */
final class DkgInbox
{
    /** @var array<string,array{digest:string,body:mixed}> */
    private array $seen = [];
    /** @var array<string,DkgChannelError> */
    private array $errors = [];
    /** @var array<string,true> */
    private array $gone = [];
    private bool $closed = false;

    /** @param list<mixed> $peers */
    public function __construct(public readonly string $sessionId, public readonly array $peers)
    {
    }

    private static function key(mixed $x): string
    {
        return Js::isNum($x) ? 'n' . (string)Js::num($x) : (is_string($x) ? 's' . $x : 'o');
    }

    public function fail(mixed $peer, DkgChannelError $err): void
    {
        $k = self::key($peer);
        if (!isset($this->errors[$k])) {
            $this->errors[$k] = new DkgChannelError($err->errorCode, $peer, (string)preg_replace('/\Adkg channel \([^)]*\): /', '', $err->getMessage(), 1));
        }
    }

    public function accept(mixed $sender, string $bytes): void
    {
        $ok = false;
        foreach ($this->peers as $p) {
            $ok = $ok || self::key($p) === self::key($sender);
        }
        if (!$ok) {
            return;
        }
        try {
            ['kind' => $kind, 'body' => $body] = FrostDkgChannel::decodeMessage($bytes, $this->sessionId);
            $key = $kind . "\0" . self::key($sender);
            $digest = Pca::b64u($bytes);
            if (isset($this->seen[$key])) {
                throw new DkgChannelError($this->seen[$key]['digest'] === $digest ? 'duplicate' : 'equivocation', $sender, "second $kind message");
            }
            $this->seen[$key] = ['digest' => $digest, 'body' => $body];
        } catch (\Throwable $e) {
            $this->fail($sender, $e instanceof DkgChannelError ? $e : new DkgChannelError('malformed', $sender, 'undecodable message'));
        }
    }

    public function peerGone(mixed $peer): void
    {
        $this->gone[self::key($peer)] = true;
    }

    public function close(): void
    {
        $this->closed = true;
    }

    /**
     * The `$kind` bodies from `$from`, ascending by sender. Throws the first peer error (lowest id first), `closed` when the channel ended or a peer's link ended
     * before its message, else `timeout` naming the lowest missing peer. shortcut: nothing arrives while collecting (synchronous), so a missing message is
     * reported at once instead of after `$timeoutMs`; move to an event loop when a real network drives it.
     * @return array<int|string,mixed>
     */
    public function collect(string $kind, array $from, mixed $timeoutMs = null): array
    {
        $want = array_values($from);
        usort($want, static fn(mixed $a, mixed $b): int => Js::num($a) <=> Js::num($b));
        foreach ($want as $id) {
            if (isset($this->errors[self::key($id)])) {
                throw $this->errors[self::key($id)];
            }
        }
        $out = [];
        foreach ($want as $id) {
            $m = $this->seen[$kind . "\0" . self::key($id)] ?? null;
            if ($m !== null) {
                $out[FrostDkgChannel::txt($id)] = $m['body'];
            }
        }
        if (count($out) === count($want)) {
            return $out;
        }
        if ($this->closed) {
            throw new DkgChannelError('closed', null, 'channel closed before all messages arrived');
        }
        foreach ($want as $id) {
            if (!isset($out[FrostDkgChannel::txt($id)]) && isset($this->gone[self::key($id)])) {
                throw new DkgChannelError('closed', $id, "link ended before its $kind message arrived");
            }
        }
        $missing = array_values(array_filter($want, static fn(mixed $id): bool => !isset($out[FrostDkgChannel::txt($id)])));
        throw new DkgChannelError('timeout', $missing[0], "no $kind message from " . implode(',', array_map(static fn(mixed $x): string => Jsx::str($x), $missing)));
    }
}

/** One participant's end of the in-process network. */
final class MemoryDkgChannel implements DkgChannel
{
    /** @param list<mixed> $peers @param \Closure(mixed,string,mixed):void $route */
    public function __construct(private readonly mixed $self, private readonly array $peers, private readonly \Closure $route, private readonly DkgInbox $inbox)
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
            ($this->route)($p, $kind, $body);
        }
    }

    public function send(mixed $to, string $kind, mixed $body): void
    {
        foreach ($this->peers as $p) {
            if (Js::num($p) === Js::num($to)) {
                ($this->route)($to, $kind, $body);
                return;
            }
        }
        throw new DkgChannelError('identity', $to, 'not a connected peer');
    }

    public function collect(string $kind, array $from, mixed $timeoutMs): array
    {
        return $this->inbox->collect($kind, $from, $timeoutMs);
    }

    public function close(): void
    {
        $this->inbox->close();
    }
}

/** An in-process DKG network over `ids` (for tests and single-process ceremonies); `$intercept(['from','to','kind','bytes'])` may return other bytes or null (drop). */
final class MemoryDkgNetwork
{
    /** @var array<string,MemoryDkgChannel> */
    public array $channels = [];
    /** @var array<string,DkgInbox> */
    private array $inboxes = [];

    public function __construct(array $ids, string $sessionId, ?\Closure $intercept = null)
    {
        $sorted = array_values($ids);
        usort($sorted, static fn(mixed $a, mixed $b): int => Js::num($a) <=> Js::num($b));
        foreach ($sorted as $id) {
            $this->inboxes[FrostDkgChannel::txt($id)] = new DkgInbox($sessionId, array_values(array_filter($sorted, static fn(mixed $p): bool => Js::num($p) !== Js::num($id))));
        }
        foreach ($sorted as $self) {
            $peers = array_values(array_filter($sorted, static fn(mixed $p): bool => Js::num($p) !== Js::num($self)));
            $route = function (mixed $to, string $kind, mixed $body) use ($self, $sessionId, $intercept): void {
                $bytes = FrostDkgChannel::encodeMessage($sessionId, $kind, $body);
                $out = $intercept !== null ? $intercept(['from' => $self, 'to' => $to, 'kind' => $kind, 'bytes' => $bytes]) : $bytes;
                if ($out !== null) {
                    $this->deliver($self, $to, $out);
                }
            };
            $this->channels[FrostDkgChannel::txt($self)] = new MemoryDkgChannel($self, $peers, $route, $this->inboxes[FrostDkgChannel::txt($self)]);
        }
    }

    /** Hand raw bytes to `$to` as if `$from` had sent them (an adversary's entry point); lost silently for an unknown recipient. */
    public function deliver(mixed $from, mixed $to, string $bytes): void
    {
        ($this->inboxes[FrostDkgChannel::txt($to)] ?? null)?->accept($from, $bytes);
    }
}

/** The DKG wire codec (strict, versioned, session-bound envelope; every decoder is exact about members and canonical encodings) and the party driver. */
final class FrostDkgChannel
{
    public const DKG_WIRE_VERSION = 1;
    public const DKG_MAX_MESSAGE_BYTES = 262144;
    public const DKG_MAX_PARTICIPANTS = 256;
    public const DKG_MESSAGE_KINDS = ['round1', 'share', 'complaints', 'rebuttals', 'echo'];

    /** The JS text of an id (a number by value, else the string). */
    public static function txt(mixed $x): string
    {
        return Js::isNum($x) ? (string)Js::num($x) : (is_string($x) ? $x : '');
    }

    public static function encodeMessage(string $sessionId, mixed $kind, mixed $body): string
    {
        $bytes = Js::stringify(Obj::of(['v' => self::DKG_WIRE_VERSION, 'sid' => Pca::b64u($sessionId), 'kind' => $kind, 'body' => Sign::n($body)]));
        if (strlen($bytes) > self::DKG_MAX_MESSAGE_BYTES) {
            throw new DkgChannelError('oversize', null, 'message of ' . strlen($bytes) . ' bytes exceeds the cap');
        }
        return $bytes;
    }

    /** @return array{kind:string,body:mixed} */
    public static function decodeMessage(mixed $bytes, string $sessionId): array
    {
        if (!is_string($bytes)) {
            throw new DkgChannelError('malformed', null, 'message is not bytes');
        }
        if (strlen($bytes) > self::DKG_MAX_MESSAGE_BYTES) {
            throw new DkgChannelError('oversize', null, 'message of ' . strlen($bytes) . ' bytes exceeds the cap');
        }
        try {
            if (!mb_check_encoding($bytes, 'UTF-8')) {
                throw new \InvalidArgumentException('not UTF-8');
            }
            $msg = Json::parseStrict($bytes);
        } catch (\Throwable) {
            throw new DkgChannelError('malformed', null, 'message is not strict JSON');
        }
        $o = self::asRecord($msg, ['v', 'sid', 'kind', 'body'], 'envelope');
        $v = $o->get('v');
        if (!Js::isNum($v) || Js::num($v) !== (float)self::DKG_WIRE_VERSION) {
            throw new DkgChannelError('malformed', null, 'unsupported wire version');
        }
        $kind = $o->get('kind');
        if (!is_string($kind) || !in_array($kind, self::DKG_MESSAGE_KINDS, true)) {
            throw new DkgChannelError('malformed', null, 'unknown message kind');
        }
        if ($o->get('sid') !== Pca::b64u($sessionId)) {
            throw new DkgChannelError('wrong-session', null, 'message names another session');
        }
        return ['kind' => $kind, 'body' => $o->get('body')];
    }

    private static function asRecord(mixed $x, array $keys, string $what): Obj
    {
        if (!($x instanceof Obj)) {
            throw new DkgChannelError('malformed', null, "$what is not an object");
        }
        $got = $x->keys();
        if (count($got) !== count($keys) || array_diff($keys, $got) !== []) {
            throw new DkgChannelError('malformed', null, "$what has unexpected or missing members");
        }
        return $x;
    }

    private static function posInt(mixed $x, string $what): mixed
    {
        $f = Js::num($x);
        if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > 9007199254740991.0 || $f <= 0) {
            throw new DkgChannelError('malformed', null, "$what is not a positive integer");
        }
        return $x;
    }

    private static function b64Field(mixed $x, string $what, ?int $len = null): string
    {
        if (Pca::decodeB64uStrict($x, $len) === null) {
            throw new DkgChannelError('malformed', null, "$what is not canonical base64url");
        }
        return $x;
    }

    public static function decodeRound1Package(mixed $x, mixed $t): Obj
    {
        $o = self::asRecord($x, ['identifier', 'sessionId', 'coefficientCommitments', 'proofOfKnowledge'], 'round-1 package');
        $pok = self::asRecord($o->get('proofOfKnowledge'), ['R', 'mu'], 'proof of knowledge');
        $cc = $o->get('coefficientCommitments');
        if (!is_array($cc) || !array_is_list($cc) || Js::num($t) === null || (float)count($cc) !== Js::num($t)) {
            throw new DkgChannelError('malformed', null, 'round-1 package must commit to exactly t coefficients');
        }
        return Obj::of(['identifier' => self::posInt($o->get('identifier'), 'identifier'), 'sessionId' => self::b64Field($o->get('sessionId'), 'sessionId'),
            'coefficientCommitments' => array_map(static fn(mixed $c): string => self::b64Field($c, 'coefficient commitment', 32), $cc),
            'proofOfKnowledge' => Obj::of(['R' => self::b64Field($pok->get('R'), 'PoP R', 32), 'mu' => self::b64Field($pok->get('mu'), 'PoP mu', 32)])]);
    }

    /** @return Obj `{from, to, sessionId, share (raw), sig}` */
    public static function decodeShareMessage(mixed $x): Obj
    {
        $o = self::asRecord($x, ['from', 'to', 'sessionId', 'share', 'sig'], 'share message');
        return Obj::of(['from' => self::posInt($o->get('from'), 'from'), 'to' => self::posInt($o->get('to'), 'to'), 'sessionId' => self::b64Field($o->get('sessionId'), 'sessionId'),
            'share' => Pca::decodeB64uStrict(self::b64Field($o->get('share'), 'share', 32)), 'sig' => self::b64Field($o->get('sig'), 'share signature', 64)]);
    }

    private static function complaintOf(mixed $x): Obj
    {
        $o = self::asRecord($x, ['accused', 'accuser', 'sessionId', 'revealedShare', 'shareSig'], 'complaint');
        return Obj::of(['accused' => self::posInt($o->get('accused'), 'accused'), 'accuser' => self::posInt($o->get('accuser'), 'accuser'),
            'sessionId' => self::b64Field($o->get('sessionId'), 'sessionId'), 'revealedShare' => self::b64Field($o->get('revealedShare'), 'revealed share', 32),
            'shareSig' => self::b64Field($o->get('shareSig'), 'share signature', 64)]);
    }

    private static function rebuttalOf(mixed $x): Obj
    {
        $o = self::asRecord($x, ['accused', 'accuser', 'sessionId', 'presentedShare', 'shareSig'], 'rebuttal');
        return Obj::of(['accused' => self::posInt($o->get('accused'), 'accused'), 'accuser' => self::posInt($o->get('accuser'), 'accuser'),
            'sessionId' => self::b64Field($o->get('sessionId'), 'sessionId'), 'presentedShare' => self::b64Field($o->get('presentedShare'), 'presented share', 32),
            'shareSig' => self::b64Field($o->get('shareSig'), 'share signature', 64)]);
    }

    private static function listOf(mixed $x, string $key, \Closure $one): array
    {
        $o = self::asRecord($x, [$key], $key);
        $l = $o->get($key);
        if (!is_array($l) || !array_is_list($l) || count($l) > self::DKG_MAX_PARTICIPANTS) {
            throw new DkgChannelError('malformed', null, "$key is not a bounded list");
        }
        return array_map($one, $l);
    }

    public static function decodeComplaints(mixed $x): array
    {
        return self::listOf($x, 'complaints', self::complaintOf(...));
    }

    public static function decodeRebuttals(mixed $x): array
    {
        return self::listOf($x, 'rebuttals', self::rebuttalOf(...));
    }

    public static function decodeEcho(mixed $x): Obj
    {
        $o = self::asRecord($x, ['identifier', 'sessionId', 'transcriptDigest'], 'echo');
        return Obj::of(['identifier' => self::posInt($o->get('identifier'), 'identifier'), 'sessionId' => self::b64Field($o->get('sessionId'), 'sessionId'),
            'transcriptDigest' => self::b64Field($o->get('transcriptDigest'), 'transcript digest', 32)]);
    }

    private static function bind(mixed $peer, \Closure $f): mixed
    {
        try {
            return $f();
        } catch (DkgChannelError $e) {
            throw new DkgChannelError($e->errorCode, $peer, (string)preg_replace('/\Adkg channel \([^)]*\): /', '', $e->getMessage(), 1));
        }
    }

    private static function n(mixed $x): float
    {
        return Js::num($x) ?? NAN;
    }

    private static function eq(mixed $a, mixed $b): bool
    {
        return Js::isNum($a) && Js::isNum($b) && Js::num($a) === Js::num($b);
    }

    /**
     * Run one participant of the DKG over a channel: round 1 package broadcast and proof-of-knowledge check, signed shares point-to-point, blame (a bad share
     * becomes a verified complaint), rebuttals, the qualified set, echo broadcast agreement and finalize. Throws a {@see DkgChannelError}.
     * `$opts`: t, participants, sessionId (raw), timeoutMs?, coefficients?, random?. @return array{keyPackage:Obj,qualified:list<mixed>,complaints:list<Obj>}
     */
    public static function run(DkgChannel $ch, array $opts): array
    {
        $self = $ch->self();
        $ids = array_values($opts['participants']);
        usort($ids, static fn(mixed $a, mixed $b): int => self::n($a) <=> self::n($b));
        $bad = count($ids) > self::DKG_MAX_PARTICIPANTS;
        foreach ($ids as $k => $i) {
            $f = Js::num($i);
            if ($f === null || !is_finite($f) || $f != floor($f) || abs($f) > 9007199254740991.0 || $f <= 0 || ($k > 0 && self::eq($ids[$k - 1], $i))) {
                $bad = true;
            }
        }
        if ($bad) {
            throw new DkgChannelError('protocol', null, 'participants must be distinct positive integers within the cap');
        }
        $inIds = false;
        foreach ($ids as $i) {
            $inIds = $inIds || self::eq($i, $self);
        }
        if (!$inIds) {
            throw new DkgChannelError('protocol', null, 'this participant is not in the participant list');
        }
        $t = $opts['t'];
        $tf = Js::num($t);
        if ($tf === null || !is_finite($tf) || $tf != floor($tf) || $tf < 1 || $tf > count($ids)) {
            throw new DkgChannelError('protocol', null, 'need 1 <= t <= n');
        }
        $others = array_values(array_filter($ids, static fn(mixed $i): bool => !self::eq($i, $self)));
        $peers = $ch->peers();
        if (count($peers) !== count($others)) {
            throw new DkgChannelError('protocol', null, 'the channel peers are not exactly the other participants');
        }
        foreach ($others as $k => $o) {
            if (!self::eq($peers[$k], $o)) {
                throw new DkgChannelError('protocol', null, 'the channel peers are not exactly the other participants');
            }
        }
        $sid = $opts['sessionId'];
        $sidB64 = Pca::b64u($sid);
        $tmo = $opts['timeoutMs'] ?? 30000;
        $n = count($ids);
        $ro = array_filter(['coefficients' => $opts['coefficients'] ?? null, 'random' => $opts['random'] ?? null], static fn($v) => $v !== null);
        $r1 = FrostDkg::round1($self, $t, $n, $sid, $ro);
        $ch->broadcast('round1', $r1['package']);
        $pkgs = [$r1['package']];
        foreach ($ch->collect('round1', $others, $tmo) as $from => $body) {
            $from = self::idOf($from, $others);
            $p = self::bind($from, static fn() => self::decodeRound1Package($body, $t));
            if (!self::eq($p->get('identifier'), $from)) {
                throw new DkgChannelError('identity', $from, 'package claims identifier ' . Jsx::str($p->get('identifier')));
            }
            if ($p->get('sessionId') !== $sidB64) {
                throw new DkgChannelError('wrong-session', $from, 'package names another session');
            }
            $pkgs[] = $p;
        }
        $byId = [];
        foreach ($pkgs as $p) {
            $byId[self::txt($p->get('identifier'))] = $p;
        }
        $pok = array_values(array_filter($pkgs, static fn(Obj $p): bool => FrostDkg::verifyRound1($p->get('identifier'), $p, $sid)));
        $okPeers = array_values(array_filter($others, static function (mixed $o) use ($pok): bool {
            foreach ($pok as $p) {
                if (self::eq($p->get('identifier'), $o)) {
                    return true;
                }
            }
            return false;
        }));
        foreach (FrostDkg::round2($r1['state'], $pok) as $s) {
            $ch->send($s->get('to'), 'share', Obj::of(['from' => $s->get('from'), 'to' => $s->get('to'), 'sessionId' => $s->get('sessionId'),
                'share' => Pca::b64u($s->get('share')), 'sig' => $s->get('sig')]));
        }
        $inbox = [];
        $mine = [];
        foreach ($ch->collect('share', $okPeers, $tmo) as $from => $body) {
            $from = self::idOf($from, $okPeers);
            $m = self::bind($from, static fn() => self::decodeShareMessage($body));
            if (!self::eq($m->get('from'), $from)) {
                throw new DkgChannelError('identity', $from, 'share claims sender ' . Jsx::str($m->get('from')));
            }
            if (!self::eq($m->get('to'), $self)) {
                throw new DkgChannelError('identity', $from, 'share is addressed to ' . Jsx::str($m->get('to')));
            }
            if ($m->get('sessionId') !== $sidB64) {
                throw new DkgChannelError('wrong-session', $from, 'share names another session');
            }
            $received = Obj::of(['from' => $from, 'sessionId' => $m->get('sessionId'), 'share' => $m->get('share'), 'sig' => $m->get('sig')]);
            $sender = $byId[self::txt($from)];
            if (FrostDkg::verifyShare($received, $sender, $self, $sid)) {
                $inbox[] = $received;
                continue;
            }
            $c = FrostDkg::fileComplaint(Obj::of(['accused' => $from, 'accuser' => $self, 'receivedShare' => $m->get('share'), 'shareSig' => $m->get('sig'),
                'senderCommitments' => $sender->get('coefficientCommitments'), 'sessionId' => $sid]));
            if (FrostDkg::verifyComplaint($c, $pkgs)->get('justified') !== true) {
                throw new DkgChannelError('protocol', $from, 'share failed verification and is not admissible blame');
            }
            $mine[] = $c;
        }
        $ch->broadcast('complaints', Obj::of(['complaints' => $mine]));
        $complaints = $mine;
        foreach ($ch->collect('complaints', $others, $tmo) as $from => $body) {
            $from = self::idOf($from, $others);
            $pairs = [];
            foreach (self::bind($from, static fn() => self::decodeComplaints($body)) as $c) {
                if (!self::eq($c->get('accuser'), $from)) {
                    throw new DkgChannelError('identity', $from, 'complaint filed as ' . Jsx::str($c->get('accuser')));
                }
                if ($c->get('sessionId') !== $sidB64) {
                    throw new DkgChannelError('wrong-session', $from, 'complaint names another session');
                }
                $accusedKnown = false;
                foreach ($ids as $i) {
                    $accusedKnown = $accusedKnown || self::eq($i, $c->get('accused'));
                }
                if (self::eq($c->get('accused'), $from) || !$accusedKnown) {
                    throw new DkgChannelError('protocol', $from, 'complaint names an invalid accused');
                }
                $pk = self::txt($c->get('accused'));
                if (isset($pairs[$pk])) {
                    throw new DkgChannelError('duplicate', $from, 'two complaints against one accused');
                }
                $pairs[$pk] = true;
                $complaints[] = $c;
            }
        }
        $rebuttals = [];
        foreach ($complaints as $c) {
            if (self::eq($c->get('accused'), $self)) {
                $rebuttals[] = FrostDkg::rebut($self, $c, $r1['state']);
            }
        }
        $ch->broadcast('rebuttals', Obj::of(['rebuttals' => $rebuttals]));
        $allRebuttals = $rebuttals;
        foreach ($ch->collect('rebuttals', $others, $tmo) as $from => $body) {
            $from = self::idOf($from, $others);
            foreach (self::bind($from, static fn() => self::decodeRebuttals($body)) as $r) {
                if (!self::eq($r->get('accused'), $from)) {
                    throw new DkgChannelError('identity', $from, 'rebuttal made as ' . Jsx::str($r->get('accused')));
                }
                if ($r->get('sessionId') !== $sidB64) {
                    throw new DkgChannelError('wrong-session', $from, 'rebuttal names another session');
                }
                $allRebuttals[] = $r;
            }
        }
        $qualified = FrostDkg::qualifiedSet($ids, $complaints, $pkgs, $allRebuttals);
        $selfQ = false;
        foreach ($qualified as $q) {
            $selfQ = $selfQ || self::eq($q, $self);
        }
        if (!$selfQ) {
            throw new DkgChannelError('disqualified', $self, 'this participant was disqualified by the blame round');
        }
        if (count($qualified) < $tf) {
            throw new DkgChannelError('protocol', null, 'fewer than t participants remain qualified');
        }
        $echo = FrostDkg::echo($self, $pkgs, $complaints, $qualified, $sid);
        $ch->broadcast('echo', $echo);
        $echoes = [$echo];
        $others2 = array_values(array_filter($qualified, static fn(mixed $q): bool => !self::eq($q, $self)));
        foreach ($ch->collect('echo', $others2, $tmo) as $from => $body) {
            $from = self::idOf($from, $others2);
            $e = self::bind($from, static fn() => self::decodeEcho($body));
            if (!self::eq($e->get('identifier'), $from)) {
                throw new DkgChannelError('identity', $from, 'echo claims identifier ' . Jsx::str($e->get('identifier')));
            }
            $echoes[] = $e;
        }
        $agreement = FrostDkg::checkEchoes($qualified, $echoes, $sid);
        if ($agreement->get('agreed') !== true) {
            throw new DkgChannelError('equivocation', null, (string)$agreement->get('reason'));
        }
        $keyPackage = FrostDkg::finalize($self, $r1['state'], $inbox, $pkgs, $qualified, Obj::of(['echoes' => $echoes, 'complaints' => $complaints]));
        return ['keyPackage' => $keyPackage, 'qualified' => $qualified, 'complaints' => $complaints];
    }

    /** The original id value for a collected key (collect keys its map by the id's text). */
    private static function idOf(int|string $key, array $set): mixed
    {
        foreach ($set as $v) {
            if (self::txt($v) === (string)$key) {
                return $v;
            }
        }
        return $key;
    }
}
