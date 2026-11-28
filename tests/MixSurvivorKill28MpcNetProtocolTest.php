<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcField;
use Atlas\Pca\MpcNetAbort;
use Atlas\Pca\MpcNetMesh;
use Atlas\Pca\MpcNetPa;
use Atlas\Pca\MpcNetPartyRun;
use Atlas\Pca\MpcNetProtocol;
use Atlas\Pca\MpcNetWire;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Raised by the scripted mesh when a party asks for a round the test did not script: the run stops there. */
final class Mix28Stop extends \RuntimeException
{
}

/** A socket-free mesh: records sends and failures, answers recv/collect from a script. */
final class Mix28Mesh extends MpcNetMesh
{
    /** @var list<array{0:int,1:string,2:mixed}> */
    public array $sent = [];
    /** @var list<MpcNetAbort> */
    public array $failures = [];
    /** @var array<string,mixed> recv round => payload (a Throwable is thrown) */
    public array $inbox = [];
    /** @var array<string,array<int,mixed>> collect round => peer => payload */
    public array $script = [];

    public function __construct()
    {
    }

    public function __destruct()
    {
    }

    public function send(int $to, string $round, mixed $payload): void
    {
        $this->sent[] = [$to, $round, $payload];
    }

    public function recv(int $from, string $round, ?int $timeoutMs = null): mixed
    {
        $v = $this->inbox[$round] ?? null;
        if ($v instanceof \Throwable) {
            throw $v;
        }
        return $v;
    }

    public function collect(string $round, ?array $from = null, ?int $timeoutMs = null): array
    {
        return $this->script[$round] ?? throw new Mix28Stop($round);
    }

    public function fail(MpcNetAbort $err, ?int $skipPeer = null): void
    {
        $this->failures[] = $err;
    }

    public function finish(): void
    {
    }

    public function stats(): array
    {
        return [];
    }

    public function setDeferAborts(bool $on): void
    {
    }
}

/** Group 28 survivors in MpcNetProtocol: config refusals, the dealer's MAC fault, the party's prep intake, round parse errors, the coin. */
final class MixSurvivorKill28MpcNetProtocolTest extends TestCase
{
    private const INPUT = ['allow' => 1, 't' => 1, 'rQuant' => 0];

    /** @param array<string,mixed> $extra */
    private static function party(Mix28Mesh $mesh, array $extra = []): MpcNetPartyRun
    {
        return new MpcNetPartyRun($extra + ['id' => 0, 'n' => 2, 'mesh' => $mesh, 'sessionId' => 'mix28', 'Q' => 1, 'input' => self::INPUT,
            'offline' => 'trusted-dealer', 'insecureTrustedDealer' => true]);
    }

    /** The prep total a party of 2 expects for Q (1 + K*paWidth + triples*7*aw + inputs*aw + C, with K = 2, paWidth 3, aw 9). */
    private static function total(int $Q): int
    {
        $C = MpcNetProtocol::chainCount($Q);
        return 1 + 2 * 3 + $C * 7 * 9 + 2 * $C * 9 + $C;
    }

    /** @return list<string> canonical hex of 1..$count (offset by $from) */
    private static function nums(int $count, int $from = 1): array
    {
        return array_map(static fn(int $i): string => dechex($i), range($from, $from + $count - 1));
    }

    private static function firstChunk(int $total, int $chunks, array $nums): Obj
    {
        return Obj::of(['total' => new Num((string) $total), 'chunks' => new Num((string) $chunks), 'nums' => $nums]);
    }

    private static function aborts(string $kind, string $msg, callable $f, ?Mix28Mesh $mesh = null): void
    {
        try {
            $f();
            self::fail('expected an MpcNetAbort');
        } catch (MpcNetAbort $e) {
            self::assertSame([$kind, $msg], [$e->kind, $e->getMessage()]);
            if ($mesh !== null) {
                self::assertSame([$e], $mesh->failures, 'the abort is also reported to the mesh');
            }
        }
    }

    /** run() refuses an unknown offline mode, a party count below one and an invalid decision vector, before any traffic. */
    public function testRunRefusesBadConfig(): void
    {
        $stop = static fn(array $ctx): array => throw new Mix28Stop('offline');
        $m = new Mix28Mesh();
        self::aborts('local', '[local] blamed=none reporter=0: unknown offline mode', static fn() => self::party($m, ['offline' => 'bogus', 'offlineRunner' => $stop])->run());
        self::aborts('local', '[local] blamed=none reporter=0: n must be >= 1', static fn() => self::party($m, ['n' => 0, 'offline' => 'no-dealer', 'offlineRunner' => $stop])->run());
        self::aborts('local', '[local] blamed=none reporter=0: invalid decision vector',
            static fn() => self::party($m, ['input' => ['allow' => 2, 't' => 1, 'rQuant' => 0], 'offline' => 'no-dealer', 'offlineRunner' => $stop])->run());
        self::assertSame([], $m->sent);
    }

    /** The dealer's test-only MAC fault adds exactly 1 to the first key's MAC of the chosen input, and nothing else. */
    public function testDealerMacFaultIsExactlyOne(): void
    {
        $m = new Mix28Mesh();
        MpcNetProtocol::runDealer(['n' => 2, 'mesh' => $m, 'insecureTrustedDealer' => true, 'Q' => 1, 'seed' => gmp_init(7), 'macFaultAtInput' => 0]);
        $total = self::total(1);
        $C = MpcNetProtocol::chainCount(1);
        $nums = [];
        foreach ($m->sent as [$to, $round, $payload]) {
            self::assertSame('prep', $round);
            self::assertSame([$total, 1], [$payload['total'], $payload['chunks']]);
            $nums[$to] = MpcNetWire::unhxArray($payload['nums'], $total);
        }
        self::assertSame([0, 1], array_keys($nums));
        $diffs = [];
        foreach ([0, 1] as $q) {
            $off = 1 + 2 * 3 + $C * 7 * 9 + $q * 9;
            $v = gmp_init(0);
            $mac = [gmp_init(0), gmp_init(0)];
            $alpha = [gmp_init(0), gmp_init(0)];
            foreach ([0, 1] as $p) {
                $aw = MpcNetPa::awParse($nums[$p], $off, $p, 2, 2, true);
                $v = MpcField::fadd($v, $aw['v']['x']);
                foreach ([0, 1] as $l) {
                    $mac[$l] = MpcField::fadd($mac[$l], $aw['m'][$l]['x']);
                    $alpha[$l] = MpcField::fadd($alpha[$l], MpcNetPa::paParse($nums[$p], 1 + 3 * $l, $p, 2, true)['x']);
                }
            }
            foreach ([0, 1] as $l) {
                $diffs[$q][$l] = gmp_strval(MpcField::fsub($mac[$l], MpcField::fmul($alpha[$l], $v)));
            }
        }
        self::assertSame([0 => ['1', '0'], 1 => ['0', '0']], $diffs);
    }

    /** A prep header with the wrong total or chunk count, or a zero verification key, aborts naming the dealer. */
    public function testPrepHeaderRefusals(): void
    {
        $total = self::total(1);
        $m = new Mix28Mesh();
        $m->inbox['prep'] = self::firstChunk($total - 1, 1, self::nums($total));
        self::aborts('malformed', '[malformed] blamed=2 reporter=0: bad prep size', static fn() => self::party($m)->run(), $m);
        $m = new Mix28Mesh();
        $m->inbox['prep'] = self::firstChunk($total, 2, self::nums($total));
        self::aborts('malformed', '[malformed] blamed=2 reporter=0: bad prep chunk count', static fn() => self::party($m)->run(), $m);
        $m = new Mix28Mesh();
        $m->inbox['prep'] = self::firstChunk($total, 1, ['0', ...self::nums($total - 1)]);
        self::aborts('dealer', '[dealer] blamed=2 reporter=0: the dealer gave me a zero verification key', static fn() => self::party($m)->run(), $m);
    }

    /** A two-chunk prep is read as `prep` then `prep.1`, concatenated in order (the mask block is the last C numbers). */
    public function testTwoChunkPrepIsConcatenated(): void
    {
        $Q = 363;
        $total = self::total($Q);
        $C = MpcNetProtocol::chainCount($Q);
        self::assertGreaterThan(30000, $total);
        self::assertLessThanOrEqual(60000, $total);
        $m = new Mix28Mesh();
        $m->inbox['prep'] = self::firstChunk($total, 2, self::nums(30000));
        $m->inbox['prep.1'] = self::nums($total - 30000, 30001);
        $run = self::party($m, ['Q' => $Q]);
        try {
            $run->run();
            self::fail('expected the scripted stop at the first coin round');
        } catch (Mix28Stop $e) {
            self::assertSame('coin1-c', $e->getMessage());
        }
        $prep = (new \ReflectionProperty(MpcNetPartyRun::class, 'prep'))->getValue($run);
        self::assertSame(self::nums($C, $total - $C + 1), array_map(MpcNetWire::hx(...), $prep['myPlain']));
        self::assertSame('1', MpcNetWire::hx($prep['delta']));
        self::assertSame([], $m->failures);
    }

    /** A chunk that fails to arrive is a malformed-prep abort naming the dealer, carrying the cause. */
    public function testMissingChunkAborts(): void
    {
        $total = self::total(363);
        $m = new Mix28Mesh();
        $m->inbox['prep'] = self::firstChunk($total, 2, self::nums(30000));
        $m->inbox['prep.1'] = new \RuntimeException('link down');
        self::aborts('malformed', '[malformed] blamed=2 reporter=0: link down', static fn() => self::party($m, ['Q' => 363])->run(), $m);
    }

    /** A parse callback that throws a non-abort becomes a malformed abort naming the sender and the round, reported to the mesh. */
    public function testParseErrorBecomesMalformedAbort(): void
    {
        $m = new Mix28Mesh();
        $m->script['r1'] = [1 => 'x'];
        self::aborts('malformed', "[malformed] blamed=1 reporter=0: round 'r1': boom",
            static fn() => self::party($m)->exchange('r1', static fn(int $p): string => 'mine', static fn(int $p, mixed $raw): mixed => throw new \RuntimeException('boom')), $m);
        self::assertSame([[1, 'r1', 'mine']], $m->sent);
    }

    /** A coin opening that is not 64 hex digits is a malformed `bad seed` abort, not a commitment mismatch. */
    public function testCoinRefusesANonHexSeed(): void
    {
        $m = new Mix28Mesh();
        $m->script['cc-c'] = [1 => str_repeat('a', 64)];
        $m->script['cc-o'] = [1 => 'zz'];
        $run = self::party($m);
        self::aborts('malformed', '[malformed] blamed=1 reporter=0: bad seed',
            static fn() => (new \ReflectionMethod(MpcNetPartyRun::class, 'coin'))->invoke($run, 'cc', false), $m);
    }

    /** A party in the blame round: prep and env set directly (opened is empty, so every challenge-weighted sum is 0). */
    private static function blameRun(Mix28Mesh $m, int $id, int $n, bool $tagged): MpcNetPartyRun
    {
        $run = self::party($m, ['id' => $id, 'n' => $n, 'offline' => 'no-dealer']);
        $zero = gmp_init(0);
        $pa = ['x' => $zero, 'tag' => array_fill(0, $n, $zero), 'key' => array_fill(0, $n, $zero)];
        $prep = ['mode' => 'no-dealer', 'tagged' => $tagged, 'delta' => gmp_init(5), 'alpha' => [$pa, $pa]];
        \Closure::bind(function () use ($prep, $id, $n): void {
            $this->prep = $prep;
            $this->env = ['id' => $id, 'n' => $n, 'delta' => $prep['delta'], 'tagged' => $prep['tagged']];
        }, $run, MpcNetPartyRun::class)();
        return $run;
    }

    private static function blameMsg(array $at = ['0', '0']): Obj
    {
        return Obj::of(['g' => ['0', '0'], 'gt' => ['0', '0'], 'a' => ['0', '0'], 'at' => $at]);
    }

    /** @param list<int> $peers */
    private static function blame(MpcNetPartyRun $run, array $peers): ?MpcNetAbort
    {
        $z = [gmp_init(0), gmp_init(0)];
        try {
            (new \ReflectionMethod(MpcNetPartyRun::class, 'blame'))->invoke($run, $z, $z, array_fill_keys($peers, $z), 'joint');
        } catch (MpcNetAbort $e) {
            return $e;
        }
        return null;
    }

    private const MSG = 'MAC-check FAILED: an opened value or MAC share was inconsistent; aborting with no output';

    /** Without pairwise tags a MAC-check failure names the other party only when there are two, else it gives the reason. */
    public function testUntaggedBlameNamesOnlyTheOtherOfTwo(): void
    {
        $m = new Mix28Mesh();
        $e = self::blame(self::blameRun($m, 1, 2, false), [0]);
        self::assertNotNull($e);
        self::assertSame(['mac-check', 0, '[mac-check] blamed=0 reporter=1: ' . self::MSG], [$e->kind, $e->blamed, $e->getMessage()]);
        self::assertSame([$e], $m->failures);
        $e3 = self::blame(self::blameRun(new Mix28Mesh(), 1, 3, false), [0, 2]);
        self::assertNotNull($e3);
        self::assertSame([null, 'this mode carries no pairwise tags, so a MAC-check failure cannot name a party (only possible with two parties)'], [$e3->blamed, $e3->reason]);
    }

    /** When every peer's blame data verifies, dealer-free mode blames the offline material: the other party of two, else no one. */
    public function testConsistentBlameRoundBlamesTheOfflineMaterial(): void
    {
        $tail = " - every party's shares verify under its pairwise tags, so the offline material is inconsistent (a wrong OT operand): not attributable";
        $m = new Mix28Mesh();
        $m->script['blame'] = [0 => self::blameMsg()];
        $e = self::blame(self::blameRun($m, 1, 2, true), [0]);
        self::assertNotNull($e);
        self::assertSame(['mac-check', 0, '[mac-check] blamed=0 reporter=1: ' . self::MSG . $tail], [$e->kind, $e->blamed, $e->getMessage()]);
        $m3 = new Mix28Mesh();
        $m3->script['blame'] = [0 => self::blameMsg(), 2 => self::blameMsg()];
        $e3 = self::blame(self::blameRun($m3, 1, 3, true), [0, 2]);
        self::assertNotNull($e3);
        self::assertSame([null, '[mac-check] blamed=none reporter=1: ' . self::MSG . $tail,
            "every party's shares verify under its pairwise tags, so the fault lies in the offline material, which names no party"], [$e3->blamed, $e3->getMessage(), $e3->reason]);
    }

    /** A peer whose opened key share does not match its pairwise tag is named. */
    public function testKeyShareTagMismatchIsNamed(): void
    {
        $m = new Mix28Mesh();
        $m->script['blame'] = [0 => self::blameMsg(['1', '0'])];
        $e = self::blame(self::blameRun($m, 1, 2, true), [0]);
        self::assertNotNull($e);
        self::assertSame(['mac-check', 0, '[mac-check] blamed=0 reporter=1: ' . self::MSG . " - party 0's key share (key 0) does not match its pairwise tag"],
            [$e->kind, $e->blamed, $e->getMessage()]);
    }
}
