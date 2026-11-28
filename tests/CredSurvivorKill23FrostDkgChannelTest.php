<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\DkgChannel;
use Atlas\Pca\DkgChannelError;
use Atlas\Pca\DkgInbox;
use Atlas\Pca\Frost;
use Atlas\Pca\FrostDkg;
use Atlas\Pca\FrostDkgChannel;
use Atlas\Pca\MemoryDkgNetwork;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** A channel whose inbound messages are all in the inbox before the run starts; it records what the party sends and the timeouts it asks for. */
final class Kill23DkgChannel implements DkgChannel
{
    /** @var list<array{0:string,1:mixed,2:mixed}> */
    public array $sent = [];
    /** @var list<mixed> */
    public array $timeouts = [];
    private DkgInbox $inbox;

    /** @param list<mixed> $peerIds @param list<array{0:mixed,1:string,2:mixed}> $inbound [from, kind, body] */
    public function __construct(private readonly mixed $me, private readonly array $peerIds, string $sid, array $inbound = [])
    {
        $this->inbox = new DkgInbox($sid, $peerIds);
        foreach ($inbound as [$from, $kind, $body]) {
            $this->inbox->accept($from, FrostDkgChannel::encodeMessage($sid, $kind, $body));
        }
    }

    public function self(): mixed
    {
        return $this->me;
    }

    public function peers(): array
    {
        return $this->peerIds;
    }

    public function broadcast(string $kind, mixed $body): void
    {
        $this->sent[] = [$kind, null, $body];
    }

    public function send(mixed $to, string $kind, mixed $body): void
    {
        $this->sent[] = [$kind, $to, $body];
    }

    public function collect(string $kind, array $from, mixed $timeoutMs): array
    {
        $this->timeouts[] = $timeoutMs;
        return $this->inbox->collect($kind, $from, $timeoutMs);
    }

    public function close(): void
    {
        $this->inbox->close();
    }
}

/** DKG channel: error text, inbox sender keys and timeouts, size caps, envelope shape, and the party driver's refusals per phase. */
final class CredSurvivorKill23FrostDkgChannelTest extends TestCase
{
    private const SID = 'session-kill23';

    private function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail("expected $class: $msg");
    }

    private static function b(int $len, string $c = "\1"): string
    {
        return Pca::b64u(str_repeat($c, $len));
    }

    private static function msg(): string
    {
        return FrostDkgChannel::encodeMessage(self::SID, 'round1', 'x');
    }

    /** The error text names the code, then the peer when there is one, then the message. */
    public function testErrorText(): void
    {
        $this->assertSame('dkg channel (identity, peer 5): m', (new DkgChannelError('identity', 5, 'm'))->getMessage());
        $this->assertSame('dkg channel (closed): m', (new DkgChannelError('closed', null, 'm'))->getMessage());
    }

    /** Senders are matched by number value or string content: a string "n1" is not peer 1, and string peers are told apart. */
    public function testInboxSenderKeys(): void
    {
        $te = DkgChannelError::class;
        $in = new DkgInbox(self::SID, [1]);
        $in->accept('n1', self::msg());
        $in->accept(9, self::msg());
        $this->throws(fn() => $in->collect('round1', [1]), $te, 'dkg channel (timeout, peer 1): no round1 message from 1');
        $this->throws(fn() => $in->collect('round1', [9]), $te, 'dkg channel (timeout, peer 9): no round1 message from 9');
        $s = new DkgInbox(self::SID, ['a']);
        $s->accept('b', self::msg());
        $this->throws(fn() => $s->collect('round1', ['a']), $te, 'dkg channel (timeout, peer a): no round1 message from a');
        $this->assertSame('a', FrostDkgChannel::txt('a'));
    }

    /** A timeout lists every missing peer in ascending order; a stored peer error is re-attributed with its message kept once. */
    public function testInboxErrors(): void
    {
        $te = DkgChannelError::class;
        $in = new DkgInbox(self::SID, [1, 2]);
        $this->throws(fn() => $in->collect('round1', [2, 1]), $te, 'dkg channel (timeout, peer 1): no round1 message from 1,2');
        $in->fail(1, new DkgChannelError('x', null, 'm'));
        $this->throws(fn() => $in->collect('round1', [1]), $te, 'dkg channel (x, peer 1): m');
    }

    /** The in-memory network never delivers a party's own message back to it. */
    public function testNetworkSkipsSelf(): void
    {
        $net = new MemoryDkgNetwork([1, 2], self::SID);
        $net->deliver(1, 1, self::msg());
        $this->throws(fn() => $net->channels['1']->collect('round1', [1], 0), DkgChannelError::class, 'dkg channel (timeout, peer 1): no round1 message from 1');
    }

    /** A message of exactly the cap is encoded; one byte more is refused on both sides with the size in the reason. */
    public function testSizeCaps(): void
    {
        $cap = FrostDkgChannel::DKG_MAX_MESSAGE_BYTES;
        $base = strlen(FrostDkgChannel::encodeMessage(self::SID, 'round1', ''));
        $this->assertSame($cap, strlen(FrostDkgChannel::encodeMessage(self::SID, 'round1', str_repeat('a', $cap - $base))));
        $over = $cap + 1;
        $this->throws(fn() => FrostDkgChannel::encodeMessage(self::SID, 'round1', str_repeat('a', $cap - $base + 1)), DkgChannelError::class,
            "dkg channel (oversize): message of $over bytes exceeds the cap");
        $this->throws(fn() => FrostDkgChannel::decodeMessage(str_repeat(' ', $over), self::SID), DkgChannelError::class,
            "dkg channel (oversize): message of $over bytes exceeds the cap");
    }

    /** An envelope that is JSON but not an object is malformed; the largest safe integer is a positive integer. */
    public function testShapes(): void
    {
        $this->throws(fn() => FrostDkgChannel::decodeMessage('[]', self::SID), DkgChannelError::class, 'dkg channel (malformed): envelope is not an object');
        $e = FrostDkgChannel::decodeEcho(Obj::of(['identifier' => 9007199254740991, 'sessionId' => Pca::b64u(self::SID), 'transcriptDigest' => self::b(32)]));
        $this->assertSame(9007199254740991, $e->get('identifier'));
    }

    private static function party(Kill23DkgChannel $ch, array $opts): DkgChannelError|\Throwable
    {
        try {
            FrostDkgChannel::run($ch, $opts + ['t' => 1, 'participants' => [1, 2], 'sessionId' => self::SID]);
        } catch (\Throwable $e) {
            return $e;
        }
        throw new \LogicException('the run completed');
    }

    private function runFails(array $inbound, string $msg, array $opts = []): void
    {
        $e = self::party(new Kill23DkgChannel(1, [2], self::SID, $inbound), $opts);
        $this->assertSame([DkgChannelError::class, $msg], [get_class($e), $e->getMessage()]);
    }

    /** @return array{0:Obj,1:Obj} peer 2's round-1 package (t = 1) and its valid share message to 1 */
    private static function peer2(): array
    {
        $r = FrostDkg::round1(2, 1, 2, self::SID, ['coefficients' => [Frost::scalarOfId(7)], 'popNonce' => Frost::scalarOfId(9)]);
        $s = FrostDkg::round2($r['state'], [Obj::of(['identifier' => 1, 'sessionId' => Pca::b64u(self::SID)]), $r['package']])[0];
        return [$r['package'], Obj::of(['from' => 2, 'to' => 1, 'sessionId' => $s->get('sessionId'), 'share' => Pca::b64u($s->get('share')), 'sig' => $s->get('sig')])];
    }

    private static function share(int $from, int $to): Obj
    {
        return Obj::of(['from' => $from, 'to' => $to, 'sessionId' => Pca::b64u(self::SID), 'share' => self::b(32), 'sig' => self::b(64)]);
    }

    /** Participant, threshold and timeout options: sorted before the duplicate check, the safe-integer bound, non-numbers refused, 30 s default. */
    public function testRunOptions(): void
    {
        $p = 'dkg channel (protocol): participants must be distinct positive integers within the cap';
        $this->assertSame($p, self::party(new Kill23DkgChannel(1, [2], self::SID), ['participants' => [1, 2, 1]])->getMessage());
        $this->assertSame($p, self::party(new Kill23DkgChannel(1, [2], self::SID), ['participants' => [1, 'x']])->getMessage());
        $this->assertSame('dkg channel (protocol): need 1 <= t <= n', self::party(new Kill23DkgChannel(1, [2], self::SID), ['t' => 'x'])->getMessage());
        $big = new Kill23DkgChannel(1, [9007199254740991], self::SID);
        $e = self::party($big, ['participants' => [1, 9007199254740991]]);
        $this->assertSame(['timeout', 9007199254740991], [$e->errorCode, $e->peer]);
        $ch = new Kill23DkgChannel(1, [2], self::SID);
        self::party($ch, ['coefficients' => [Frost::scalarOfId(5)]]);
        $this->assertSame([30000], $ch->timeouts);
        $this->assertSame([Pca::b64u(Frost::mulBase(Frost::scalarOfId(5)))], $ch->sent[0][2]->get('coefficientCommitments'));
        $five = new Kill23DkgChannel(1, [2], self::SID);
        self::party($five, ['timeoutMs' => 5]);
        $this->assertSame([5], $five->timeouts);
    }

    /** Round 1: a package for another identifier or session, or not an object, is refused and attributed to the sender (its original id value). */
    public function testRunRound1Refusals(): void
    {
        $claims3 = FrostDkg::round1(3, 1, 2, self::SID, ['coefficients' => [Frost::scalarOfId(7)], 'popNonce' => Frost::scalarOfId(9)])['package'];
        $this->runFails([[2, 'round1', $claims3]], 'dkg channel (identity, peer 2): package claims identifier 3');
        $other = FrostDkg::round1(2, 1, 2, 'other', ['coefficients' => [Frost::scalarOfId(7)], 'popNonce' => Frost::scalarOfId(9)])['package'];
        $this->runFails([[2, 'round1', $other]], 'dkg channel (wrong-session, peer 2): package names another session');
        $this->runFails([[2, 'round1', 5]], 'dkg channel (malformed, peer 2): round-1 package is not an object');
        $e = self::party(new Kill23DkgChannel(1, [2.0], self::SID, [[2.0, 'round1', $claims3]]), ['participants' => [1, 2.0]]);
        $this->assertSame(['identity', 2.0], [$e->errorCode, $e->peer]);
    }

    /** Shares, complaints, rebuttals and echoes must come from and name the right parties. */
    public function testRunPhaseRefusals(): void
    {
        [$pkg, $share] = self::peer2();
        $r1 = [2, 'round1', $pkg];
        $sh = [2, 'share', $share];
        $this->runFails([$r1, [2, 'share', self::share(3, 1)]], 'dkg channel (identity, peer 2): share claims sender 3');
        $this->runFails([$r1, [2, 'share', self::share(2, 3)]], 'dkg channel (identity, peer 2): share is addressed to 3');
        $c = static fn(int $accused, int $accuser): Obj => Obj::of(['complaints' => [Obj::of(['accused' => $accused, 'accuser' => $accuser,
            'sessionId' => Pca::b64u(self::SID), 'revealedShare' => self::b(32), 'shareSig' => self::b(64)])]]);
        $this->runFails([$r1, $sh, [2, 'complaints', $c(1, 3)]], 'dkg channel (identity, peer 2): complaint filed as 3');
        $this->runFails([$r1, $sh, [2, 'complaints', $c(7, 2)]], 'dkg channel (protocol, peer 2): complaint names an invalid accused');
        $none = [2, 'complaints', Obj::of(['complaints' => []])];
        $reb = Obj::of(['rebuttals' => [Obj::of(['accused' => 3, 'accuser' => 1, 'sessionId' => Pca::b64u(self::SID), 'presentedShare' => self::b(32), 'shareSig' => self::b(64)])]]);
        $this->runFails([$r1, $sh, $none, [2, 'rebuttals', $reb]], 'dkg channel (identity, peer 2): rebuttal made as 3');
        $noReb = [2, 'rebuttals', Obj::of(['rebuttals' => []])];
        $echo = Obj::of(['identifier' => 3, 'sessionId' => Pca::b64u(self::SID), 'transcriptDigest' => self::b(32)]);
        $this->runFails([$r1, $sh, $none, $noReb, [2, 'echo', $echo]], 'dkg channel (identity, peer 2): echo claims identifier 3');
    }

    /** A peer whose proof of knowledge fails drops out; with t = 2 that leaves too few qualified participants. */
    public function testRunTooFewQualified(): void
    {
        $p = FrostDkg::round1(2, 2, 2, self::SID, ['coefficients' => [Frost::scalarOfId(7), Frost::scalarOfId(8)], 'popNonce' => Frost::scalarOfId(9)])['package'];
        $bad = Obj::of(['identifier' => 2, 'sessionId' => $p->get('sessionId'), 'coefficientCommitments' => $p->get('coefficientCommitments'),
            'proofOfKnowledge' => Obj::of(['R' => $p->get('proofOfKnowledge')->get('R'), 'mu' => Pca::b64u(Frost::scalarOfId(1))])]);
        $this->runFails([[2, 'round1', $bad], [2, 'complaints', Obj::of(['complaints' => []])], [2, 'rebuttals', Obj::of(['rebuttals' => []])]],
            'dkg channel (protocol): fewer than t participants remain qualified', ['t' => 2]);
    }
}
