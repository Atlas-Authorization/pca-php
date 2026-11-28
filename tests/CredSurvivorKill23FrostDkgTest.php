<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\DkgState;
use Atlas\Pca\Frost;
use Atlas\Pca\FrostDkg;
use Atlas\Pca\Jsx;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** FROST DKG: identifier keys, refusal messages of every round, complaint / rebuttal adjudication, the qualified set and simulate. */
final class CredSurvivorKill23FrostDkgTest extends TestCase
{
    private const SID = 'session-kill23';
    private const SID2 = 'session-other';

    protected function tearDown(): void
    {
        FrostDkg::$randomHook = null;
    }

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

    /** Round 1 with fixed small coefficients and nonce. @return array{package:Obj,state:DkgState} */
    private static function r1(int $id, int $t, int $n = 3, string $sid = self::SID): array
    {
        $c = array_map(static fn(int $j): string => Frost::scalarOfId(10 * $id + $j + 1), range(0, $t - 1));
        return FrostDkg::round1($id, $t, $n, $sid, ['coefficients' => $c, 'popNonce' => Frost::scalarOfId(100 + $id)]);
    }

    private static function counter(): \Closure
    {
        $i = 0;
        return static function () use (&$i): string {
            return hash('sha256', 'atlas-pca-conformance/dkg-kill23/' . $i++, true);
        };
    }

    /** A package naming `$id` in the run session (no commitments: only identifiers and sessions are read before the refusal). */
    private static function stub(mixed $id): Obj
    {
        return Obj::of(['identifier' => $id, 'sessionId' => Pca::b64u(self::SID)]);
    }

    /** Round 2 keys identifiers as JS does: by number value, by string content, every object alike; non-integers are refused. */
    public function testRound2IdentifierKeys(): void
    {
        $st = self::r1(1, 1)['state'];
        $own = $st->package;
        $notInt = [\RangeException::class, 'dkg: not an integer'];
        $dup = [\RuntimeException::class, 'dkgRound2: duplicate identifiers in round-1 packages'];
        $ser = substr(serialize(Obj::class), 1);
        foreach ([
            [['n1'], $notInt],
            [[[], Obj::of([])], $notInt],
            [[Obj::of([]), $ser], $notInt],
            [[Obj::of([]), $ser . 'o'], $notInt],
            [[Obj::of(['a' => 1]), Obj::of(['b' => 2])], $dup],
        ] as [$ids, $want]) {
            $this->throws(fn() => FrostDkg::round2($st, [$own, ...array_map(self::stub(...), $ids)]), $want[0], $want[1]);
        }
        $this->throws(fn() => FrostDkg::round2($st, 5), \TypeError::class, 'dkgRound2: packages must be a list');
        Jsx::init();
        $this->throws(fn() => FrostDkg::round2($st, [Jsx::$U]), \TypeError::class, "Cannot read properties of undefined (reading 'identifier')");
    }

    /** Round 1 refuses a non-finite identifier and a non-integer or zero threshold with its own message, and draws 32 bytes per scalar. */
    public function testRound1(): void
    {
        $re = \RuntimeException::class;
        $this->throws(fn() => FrostDkg::round1(INF, 1, 1, self::SID), $re, 'dkgRound1: identifier must be a positive integer');
        $this->throws(fn() => FrostDkg::round1(1, 1.5, 3, self::SID), $re, 'dkgRound1: need 1 <= t <= n');
        $this->throws(fn() => FrostDkg::round1(1, 0, 3, self::SID), $re, 'dkgRound1: need 1 <= t <= n');
        $asked = [];
        FrostDkg::$randomHook = static function (int $n) use (&$asked): string {
            $asked[] = $n;
            return hash('sha256', 'r' . count($asked), true);
        };
        $r = FrostDkg::round1(1, 2, 2, self::SID);
        $this->assertSame([32, 32, 32], $asked);
        $this->assertTrue(FrostDkg::verifyRound1(1, $r['package'], self::SID));
    }

    /** signShare needs a non-empty commitment list in the state's package. */
    public function testSignShareCommitments(): void
    {
        foreach ([5, []] as $cc) {
            $st = new DkgState(1, 1, 1, self::SID, [Frost::scalarOfId(1)], Obj::of(['coefficientCommitments' => $cc]));
            $this->throws(fn() => FrostDkg::signShare($st, 2, 'x'), \InvalidArgumentException::class, 'dkg: empty commitment vector');
        }
    }

    /** A complaint whose signature does not parse, or whose accused has unparseable commitments, is inadmissible (not justified). */
    public function testComplaintSignatureFailures(): void
    {
        $pk = [self::r1(1, 2)['package'], self::r1(2, 2)['package'], self::r1(3, 2)['package']];
        $c = static fn(string $sig): Obj => Obj::of(['accused' => 1, 'accuser' => 2, 'sessionId' => Pca::b64u(self::SID),
            'revealedShare' => Pca::b64u(str_repeat("\0", 32)), 'shareSig' => $sig]);
        $inadmissible = 'revealed share is not validly signed by the accused — inadmissible (cannot frame an honest party)';
        $v = FrostDkg::verifyComplaint($c(Pca::b64u(str_repeat("\0", 64))), $pk);
        $this->assertSame([false, $inadmissible], [$v->get('justified'), $v->get('reason')]);
        $bad = Obj::of(['identifier' => 1, 'sessionId' => Pca::b64u(self::SID), 'coefficientCommitments' => ['!!']]);
        $v = FrostDkg::verifyComplaint($c('AAAA'), [$bad, $pk[1], $pk[2]]);
        $this->assertSame([false, $inadmissible], [$v->get('justified'), $v->get('reason')]);
    }

    /** The run session is the majority session, not the first one seen. */
    public function testQualifiedSetMajoritySession(): void
    {
        $pk = [self::r1(1, 1, 3, self::SID2)['package'], self::r1(2, 1)['package'], self::r1(3, 1)['package']];
        $this->assertSame([2, 3], FrostDkg::qualifiedSet([1, 2, 3], [], $pk));
    }

    /** The rebuttal used is the first that names both the accused and the accuser in the complaint's session. */
    public function testQualifiedSetRebuttalChoice(): void
    {
        $r = [self::r1(1, 2), self::r1(2, 2), self::r1(3, 2)];
        $pk = array_map(static fn(array $x): Obj => $x['package'], $r);
        $s = Pca::b64u(self::SID);
        $z = Pca::b64u(str_repeat("\0", 32));
        $complaint = Obj::of(['accused' => 1, 'accuser' => 2, 'sessionId' => $s, 'revealedShare' => $z, 'shareSig' => 'AAAA']);
        $reb = static fn(int $accuser): Obj => Obj::of(['accused' => 1, 'accuser' => $accuser, 'sessionId' => $s, 'presentedShare' => $z, 'shareSig' => 'AAAA']);
        $this->assertSame([2, 3], FrostDkg::qualifiedSet([1, 2, 3], [$complaint], $pk, [$reb(3), $reb(2)]));
        $valid = FrostDkg::rebut(1, $complaint, $r[0]['state']);
        $this->assertSame([1, 2, 3], FrostDkg::qualifiedSet([1, 2, 3], [$complaint], $pk, [$valid]));
        $this->assertSame([2, 3], FrostDkg::qualifiedSet([1, 2, 3], [$complaint], $pk, [$reb(2), $valid]));
    }

    /** An echo from a participant outside the qualified set is skipped, not the end of the echoes. */
    public function testCheckEchoesSkipsOutsiders(): void
    {
        $e = static fn(int $id): Obj => Obj::of(['identifier' => $id, 'sessionId' => Pca::b64u(self::SID), 'transcriptDigest' => 'd']);
        $r = FrostDkg::checkEchoes([1], [$e(5), $e(1)], self::SID);
        $this->assertSame([true, 'd'], [$r->get('agreed'), $r->get('digest')]);
    }

    /** Finalize refuses each malformed input with its own message. */
    public function testFinalizeRefusals(): void
    {
        $re = \RuntimeException::class;
        $one = self::r1(1, 1, 2);
        $st = $one['state'];
        $p1 = $one['package'];
        $p2 = self::r1(2, 1, 2)['package'];
        $sa = new DkgState('a', 1, 1, self::SID, [Frost::scalarOfId(1)], Obj::of([]));
        $this->throws(fn() => FrostDkg::finalize('a', $sa, [], []), $re, 'dkgFinalize: my own package is missing from allCommitments');
        $this->throws(fn() => FrostDkg::finalize('b', $sa, [], []), $re, 'dkgFinalize: myState.identifier != myIdentifier');
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$p1, $p1]), $re, 'dkgFinalize: duplicate identifiers in commitments');
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$p2]), $re, 'dkgFinalize: my own package is missing from allCommitments');
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$p1, self::r1(2, 1, 2, self::SID2)['package']]), $re, 'dkgFinalize: a round-1 package is from a different session');
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$p1, $p2], [2]), $re, 'dkgFinalize: myIdentifier is not in the qualified set');
        $two = self::r1(1, 2, 2);
        $this->throws(fn() => FrostDkg::finalize(1, $two['state'], [], [$two['package'], self::r1(2, 2, 2)['package']], [1]), $re,
            'dkgFinalize: qualified set (1) is smaller than the threshold t=2');
        $cc = $p1->get('coefficientCommitments');
        $wide = Obj::of(['identifier' => 1, 'sessionId' => Pca::b64u(self::SID), 'coefficientCommitments' => [$cc[0], $cc[0]]]);
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$p2, $wide], [1]), $re, 'dkgFinalize: a participant committed to the wrong number of coefficients, expected t=1');
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$p1, $p2], [2, 1], Obj::of(['echoes' => []])), $re,
            'dkgFinalize: echo-broadcast agreement failed — missing echo from qualified participant 1');
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$p1, $p2]), $re, 'dkgFinalize: missing received share from a qualified participant');
        $junk = Obj::of(['identifier' => 1, 'sessionId' => Pca::b64u(self::SID), 'coefficientCommitments' => [5]]);
        $this->throws(fn() => FrostDkg::finalize(1, $st, [], [$junk]), \InvalidArgumentException::class, 'dkg: bad base64url');
    }

    /** simulate validates t, n and the identifiers with its own messages before any round runs. */
    public function testSimulateRefusals(): void
    {
        $re = \RuntimeException::class;
        $this->throws(fn() => FrostDkg::simulate(1.5, 3), $re, 'frostDkgSimulate: need 1 <= t <= n');
        $this->throws(fn() => FrostDkg::simulate(0, 3), $re, 'frostDkgSimulate: need 1 <= t <= n');
        $this->throws(fn() => FrostDkg::simulate(1, 2, ['identifiers' => [1]]), $re, 'frostDkgSimulate: identifiers.length must equal n');
        $this->throws(fn() => FrostDkg::simulate(1, 2, ['identifiers' => [1, 1]]), $re, 'frostDkgSimulate: identifiers must be distinct');
        $this->throws(fn() => FrostDkg::simulate(1, 2, ['identifiers' => [0, 1]]), $re, 'frostDkgSimulate: identifiers must be positive integers');
    }

    /** A zero proof-of-knowledge nonce (R is the identity) fails the PoP check; a cheater below the threshold leaves too few qualified. */
    public function testSimulateFailures(): void
    {
        $re = \RuntimeException::class;
        $this->throws(fn() => FrostDkg::simulate(1, 1, ['coefficientsByParticipant' => [[Frost::scalarOfId(5)]], 'sessionId' => self::SID,
            'random' => static fn(): string => str_repeat("\0", 32)]), $re, 'frostDkgSimulate: PoP verification failed');
        $this->throws(fn() => FrostDkg::simulate(3, 3, ['cheaters' => [1], 'sessionId' => self::SID, 'random' => self::counter()]), $re,
            'frostDkgSimulate: only 2 qualified participants after the blame round');
    }

    /** An honest ceremony with no equivocator agrees on the echoes and qualifies everyone. */
    public function testSimulateHonest(): void
    {
        $r = FrostDkg::simulate(1, 2, ['sessionId' => self::SID, 'random' => self::counter()]);
        $this->assertSame([1, 2], $r->get('qualified'));
        $this->assertCount(2, $r->get('keyPackages'));
    }
}
