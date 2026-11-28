<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetPartyRun;
use Atlas\Pca\MpcNetProtocol;
use Atlas\Pca\MpcNetWire;
use PHPUnit\Framework\TestCase;

/** In-memory links between the meshes of one test: every message makes a real wire round trip (encode, strict parse). */
final class Mix28bHub
{
    /** @var array<int,array<int,list<array{0:string,1:mixed}>>> to => from => queue */
    public array $q = [];
    /** messages pushed plus messages taken (the scheduler's progress counter) */
    public int $events = 0;
    /** @var ?\Closure(int,int,string,mixed):mixed a man in the middle: (from, to, round, payload) => payload */
    public ?\Closure $tamper = null;

    public function push(int $from, int $to, string $round, mixed $payload): void
    {
        if ($this->tamper !== null) {
            $payload = ($this->tamper)($from, $to, $round, $payload);
        }
        $raw = MpcNetWire::encodeFrame(['v' => MpcNetWire::WIRE_VERSION, 'ty' => 'msg', 'sid' => 'mix28b', 'seq' => $this->events, 'rd' => $round, 'd' => $payload]);
        $f = MpcNetWire::parseFrame(substr($raw, 4)) ?? throw new \LogicException('frame did not round-trip');
        $this->q[$to][$from][] = [$round, $f->get('d')];
        $this->events++;
    }

    /** @return ?array{0:string,1:mixed} */
    public function take(int $to, int $from): ?array
    {
        if (($this->q[$to][$from] ?? []) === []) {
            return null;
        }
        $this->events++;
        return array_shift($this->q[$to][$from]);
    }
}

/** A mesh over the hub; a receive with nothing queued suspends the running Fiber until a peer has sent. */
final class Mix28bMesh extends MpcNetMesh
{
    /** @var list<MpcNetAbort> */
    public array $failures = [];

    public function __construct(private readonly Mix28bHub $hubRef, int $self, private readonly int $count)
    {
        \Closure::bind(function () use ($self): void {
            $this->selfId = $self;
        }, $this, MpcNetMesh::class)();
    }

    public function __destruct()
    {
    }

    public function sessionId(): string
    {
        return 'mix28b';
    }

    public function peers(): array
    {
        return array_values(array_diff(range(0, $this->count - 1), [$this->selfId]));
    }

    public function send(int $to, string $round, mixed $payload): void
    {
        $this->hubRef->push($this->selfId, $to, $round, $payload);
    }

    public function recv(int $from, string $round, ?int $timeoutMs = null): mixed
    {
        while (($m = $this->hubRef->take($this->selfId, $from)) === null) {
            \Fiber::suspend();
        }
        if ($m[0] !== $round) {
            throw new \LogicException("party {$this->selfId} expected '$round' from $from, got '{$m[0]}'");
        }
        return $m[1];
    }

    public function collect(string $round, ?array $from = null, ?int $timeoutMs = null): array
    {
        $got = [];
        foreach ($from ?? $this->peers() as $p) {
            $got[$p] = $this->recv($p, $round);
        }
        return $got;
    }

    public function fail(MpcNetAbort $err, ?int $skipPeer = null): void
    {
        $this->failures[] = $err;
    }

    public function setDeferAborts(bool $on): void
    {
    }

    public function finish(): void
    {
    }

    public function stats(): array
    {
        return [];
    }
}

/**
 * Group 28b survivors in MpcNetProtocol: the dealer's prep chunking, and the sigma opening, transcript echo and dealer-free forensics
 * note of a real two-party run driven in-process (Fibers over an in-memory hub, no sockets, no clocks).
 */
final class MixSurvivorKill28bMpcNetProtocolTest extends TestCase
{
    private const INPUT = ['allow' => 1, 't' => 2, 'rQuant' => 0];

    protected function tearDown(): void
    {
        MpcNetProtocol::$prepChunkHook = null;
    }

    public function testPrepChunkConstant(): void
    {
        self::assertSame(30000, MpcNetProtocol::PREP_CHUNK);
    }

    /** @return array<int,list<array{0:string,1:mixed}>> party => frames the dealer sent it */
    private static function dealerFrames(?int $chunk): array
    {
        MpcNetProtocol::$prepChunkHook = $chunk === null ? null : static fn(): int => $chunk;
        $hub = new Mix28bHub();
        MpcNetProtocol::runDealer(['n' => 2, 'mesh' => new Mix28bMesh($hub, 2, 3), 'insecureTrustedDealer' => true, 'Q' => 1, 'seed' => gmp_init(7)]);
        return [0 => $hub->q[0][2], 1 => $hub->q[1][2]];
    }

    /** Past one frame the dealer sends `prep.<c>` frames that each carry the next slice, and together they are the single-frame prep. */
    public function testDealerSplitsPrepIntoChunks(): void
    {
        $whole = self::dealerFrames(null);
        $split = self::dealerFrames(100);
        foreach ([0, 1] as $p) {
            self::assertCount(1, $whole[$p]);
            $all = $whole[$p][0][1]->get('nums');
            self::assertCount(417, $all);
            self::assertSame(['prep', 'prep.1', 'prep.2', 'prep.3', 'prep.4'], array_column($split[$p], 0));
            self::assertSame(['417', '5'], [$split[$p][0][1]->get('total')->lexeme, $split[$p][0][1]->get('chunks')->lexeme]);
            $nums = $split[$p][0][1]->get('nums');
            for ($c = 1; $c < 5; $c++) {
                self::assertSame(array_slice($all, $c * 100, 100), $split[$p][$c][1], "party $p chunk $c");
                $nums = [...$nums, ...$split[$p][$c][1]];
            }
            self::assertSame($all, $nums);
        }
    }

    /**
     * Run the dealer and two parties to completion or deadlock. @param array<string,mixed> $extra party config
     * @return array{0:array<int,array>,1:array<int,Mix28bMesh>} party => ['ok' => result] | ['err' => Throwable] | ['stuck' => true]
     */
    private static function twoParties(Mix28bHub $hub, array $extra = [], ?array $fault = null): array
    {
        $meshes = [0 => new Mix28bMesh($hub, 0, 2), 1 => new Mix28bMesh($hub, 1, 2)];
        $tasks = [2 => static fn() => MpcNetProtocol::runDealer(['n' => 2, 'mesh' => new Mix28bMesh($hub, 2, 3), 'insecureTrustedDealer' => true, 'Q' => 1,
            'seed' => gmp_init(7), 'fault' => $fault])];
        foreach ($meshes as $id => $m) {
            $tasks[$id] = static fn() => (new MpcNetPartyRun($extra + ['id' => $id, 'n' => 2, 'mesh' => $m, 'sessionId' => 'mix28b', 'Q' => 1,
                'input' => self::INPUT, 'offline' => 'trusted-dealer', 'insecureTrustedDealer' => true]))->run();
        }
        $fibers = [];
        foreach ($tasks as $k => $t) {
            $fibers[$k] = new \Fiber(static function () use ($t): array {
                try {
                    return ['ok' => $t()];
                } catch (\Throwable $e) {
                    return ['err' => $e];
                }
            });
            $fibers[$k]->start();
        }
        do {
            $before = $hub->events;
            $done = 0;
            foreach ($fibers as $f) {
                if ($f->isSuspended()) {
                    $f->resume();
                }
                $done += $f->isTerminated() ? 1 : 0;
            }
        } while ($done < count($fibers) && $hub->events !== $before);
        $out = [];
        foreach ([0, 1] as $id) {
            $out[$id] = $fibers[$id]->isTerminated() ? $fibers[$id]->getReturn() : ['stuck' => true];
        }
        return [$out, $meshes];
    }

    /** The harness itself: an honest run finishes for both parties with the same output and transcript. */
    public function testHonestRunCompletes(): void
    {
        [$r] = self::twoParties(new Mix28bHub());
        self::assertArrayHasKey('ok', $r[0], isset($r[0]['err']) ? $r[0]['err']->getMessage() : 'stuck');
        self::assertArrayHasKey('ok', $r[1], isset($r[1]['err']) ? $r[1]['err']->getMessage() : 'stuck');
        self::assertSame([$r[0]['ok']['composed'], $r[0]['ok']['transcriptDigest']], [$r[1]['ok']['composed'], $r[1]['ok']['transcriptDigest']]);
    }

    /** A sigma opening that is not an object is refused as malformed, naming the sender. */
    public function testMalformedSigmaOpening(): void
    {
        $hub = new Mix28bHub();
        $hub->tamper = static fn(int $from, int $to, string $rd, mixed $pl): mixed => $from === 1 && $to === 0 && $rd === 'sig-o' ? 'x' : $pl;
        [$r] = self::twoParties($hub);
        self::assertArrayHasKey('err', $r[0]);
        self::assertSame([MpcNetAbort::class, '[malformed] blamed=1 reporter=0: bad sigma opening'], [get_class($r[0]['err']), $r[0]['err']->getMessage()]);
    }

    /** A peer whose echoed transcript digest differs is an equivocation abort, and no output is produced. */
    public function testTranscriptEquivocation(): void
    {
        $hub = new Mix28bHub();
        $hub->tamper = static fn(int $from, int $to, string $rd, mixed $pl): mixed => $from === 1 && $to === 0 && $rd === 'digest' ? str_repeat('a', 64) : $pl;
        [$r] = self::twoParties($hub);
        self::assertArrayHasKey('err', $r[0]);
        self::assertSame('[equivocation] blamed=1 reporter=0: transcript digest of party 1 differs from mine (a broadcast was inconsistent)', $r[0]['err']->getMessage());
    }

    /**
     * Dealer-free mode with a failing sacrifice: when every disclosure is consistent the audit names no one, and the abort says so with
     * the number of inconsistent pairs (0). The prep is the dealer's, relabelled no-dealer, with a trivially consistent disclosure.
     */
    public function testDealerFreeForensicsNote(): void
    {
        $runner = function (array $ctx): array {
            $io = $ctx['io'];
            $prep = \Closure::bind(fn(): array => $this->receiveDealerPrep(), $io, MpcNetPartyRun::class)();
            $peer = 1 - $ctx['id'];
            $prep['mode'] = 'no-dealer';
            $prep['forensics'] = ['slots' => 1, 'rows' => 1, 'gadget' => [gmp_init(1)],
                'disclose' => static fn(int $bt): array => [['bits' => [0], 'y' => gmp_init(1), 'z' => gmp_init(0), 'recv' => [$peer => [gmp_init(0)]], 'rho' => [$peer => [gmp_init(0)]]]]];
            return $prep;
        };
        [$r] = self::twoParties(new Mix28bHub(), ['offline' => 'no-dealer', 'offlineRunner' => $runner], ['keepCDelta' => gmp_init(1)]);
        $note = ' (OT transcript audit: 0 inconsistent pair(s), no party can be named from this view: a pair failure between two other parties is not evidence against either of them to me)';
        foreach ([0, 1] as $id) {
            self::assertArrayHasKey('err', $r[$id]);
            self::assertSame('[mac-check] blamed=' . (1 - $id) . " reporter=$id: triple sacrifice FAILED at triple 0 (partner 0): c != a*b in the offline material; aborting with no output" . $note,
                $r[$id]['err']->getMessage());
        }
    }
}
