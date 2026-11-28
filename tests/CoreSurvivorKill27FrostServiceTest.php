<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostService.php';

use Atlas\Pca\CoordinatorError;
use Atlas\Pca\Frost;
use Atlas\Pca\FrostNet;
use Atlas\Pca\GuardianSignerService;
use Atlas\Pca\InProcessTransport;
use Atlas\Pca\KeyPair;
use Atlas\Pca\NetworkCoordinator;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SignerTransport;
use Atlas\Pca\Undef;
use PHPUnit\Framework\TestCase;

/** A scripted signer transport: each round answers through its closure (a refusal by default). */
final class K27FsTransport implements SignerTransport
{
    public function __construct(private readonly mixed $id, private readonly ?\Closure $r1 = null, private readonly ?\Closure $r2 = null)
    {
    }

    public function identifier(): mixed
    {
        return $this->id;
    }

    public function round1(Obj $req): mixed
    {
        return $this->r1 !== null ? ($this->r1)($req) : Obj::of(['ok' => false, 'identifier' => $this->id, 'reason' => 'no']);
    }

    public function round2(Obj $req): mixed
    {
        return $this->r2 !== null ? ($this->r2)($req) : Obj::of(['ok' => false, 'identifier' => $this->id, 'reason' => 'no']);
    }
}

/** Guardian signer constructor refusals, the round-2 own-commitment lookup, and the coordinator's selection, refusal and timeout paths. */
final class CoreSurvivorKill27FrostServiceTest extends TestCase
{
    private static function throws(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [get_class($e), $e->getMessage()];
        }
        return ['none', ''];
    }

    private static function policy(): KeyPair
    {
        return new KeyPair(self::policySeed());
    }

    private static function policySeed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/k27-frost-service/policy', true);
    }

    private static function kg(int $t, int $n): array
    {
        static $cache = [];
        return $cache["$t/$n"] ??= Frost::trustedDealerKeygen($t, $n);
    }

    private static function opts(array $kg, int $i, int $t, array $over = []): array
    {
        $o = ['identifier' => $i, 'share' => $kg['participantShares'][$i - 1]['share'], 'groupPublicKey' => $kg['groupPublicKey'], 'threshold' => $t,
            'policyAuthorityPublicKey' => self::policy()->public];
        foreach ($over as $k => $v) {
            $o[$k] = $v;
        }
        return $o;
    }

    private static function coordinator(array $signers, array $extra = []): NetworkCoordinator
    {
        $kg = self::kg(1, 1);
        return new NetworkCoordinator(['groupPublicKey' => $kg['groupPublicKey'], 'threshold' => 1, 'signers' => $signers,
            'verificationShares' => [['identifier' => 1, 'publicKey' => $kg['participantShares'][0]['publicKey']]]] + $extra);
    }

    /** @return list<string> the reasons of a CoordinatorError's refusals */
    private static function refusalReasons(callable $f): array
    {
        try {
            $f();
        } catch (CoordinatorError $e) {
            return array_map(static fn(Obj $r): mixed => $r->get('reason'), $e->refusals);
        }
        return ['no error'];
    }

    /** Each constructor input is refused with its own message; a store must be an object with every nonce-store method. */
    public function testSignerConstructorRefusals(): void
    {
        $kg = self::kg(1, 1);
        $p = 'GuardianSignerService: ';
        $cases = [
            [['identifier' => 0], 'identifier must be a positive integer'],
            [['share' => 'x'], 'share must be 32 bytes'],
            [['groupPublicKey' => 'x'], 'groupPublicKey must be 32 bytes'],
            [['threshold' => 0], 'threshold must be a positive integer'],
            [['policyAuthorityPublicKey' => 'x'], 'policyAuthorityPublicKey must be 32 bytes'],
            [['sessionTtlMs' => 0], 'sessionTtlMs must be a positive finite number'],
            [['sessionTtlMs' => INF], 'sessionTtlMs must be a positive finite number'],
            [['nonceStore' => new \stdClass()], 'nonceStore.create must be a function'],
        ];
        foreach ($cases as [$over, $msg]) {
            $this->assertSame([\RuntimeException::class, $p . $msg], self::throws(static fn() => new GuardianSignerService(self::opts($kg, 1, 1, $over))), $msg);
        }
        $this->assertSame(1, (new GuardianSignerService(self::opts($kg, 1, 1, ['sessionTtlMs' => 1])))->identifier);
    }

    /** The enrollment names the identifier, the raw verification share and the proof of possession. */
    public function testEnrollment(): void
    {
        $s = new GuardianSignerService(self::opts(self::kg(1, 1), 1, 1));
        $e = $s->enrollment();
        $this->assertSame(['identifier', 'publicKey', 'pop'], array_keys($e));
        $this->assertSame([1, $s->verificationShare, $s->proofOfPossession()], array_values($e));
    }

    /** Round 2 checks the FIRST commitment carrying our identifier against round 1; a duplicate after it is left to the signing-set validation. */
    public function testRound2UsesTheFirstOwnCommitment(): void
    {
        $kg = self::kg(1, 1);
        $svc = new GuardianSignerService(self::opts($kg, 1, 1));
        $c = $svc->round1(Obj::of(['typ' => 'pca.frost.round1.v1', 'session_id' => 's']))->get('commitment');
        $swapped = Obj::of(['identifier' => 1, 'hiding' => $c->get('binding'), 'binding' => $c->get('hiding')]);
        $req = static fn(array $cs): Obj => Obj::of(['typ' => 'pca.frost.round2.v1', 'session_id' => 's', 'message' => Pca::b64u('m'),
            'group_pk' => Pca::b64u($kg['groupPublicKey']), 'commitments' => $cs,
            'verification_shares' => [Obj::of(['identifier' => 1, 'publicKey' => Pca::b64u($svc->verificationShare)])],
            'allow' => FrostNet::issueAllowToken(self::policySeed(), Obj::of(['message' => 'm', 'groupPublicKey' => $kg['groupPublicKey']]))]);
        $this->assertSame('frost: duplicate commitment identifier 1', $svc->round2($req([$c, $swapped]))->get('reason'));
        $this->assertTrue($svc->round2($req([$c]))->get('ok'));
    }

    /** Without verification shares or enrollments a coordinator is refused; a non-bytes message is refused before any signer is asked. */
    public function testCoordinatorRefusals(): void
    {
        $kg = self::kg(1, 1);
        $this->assertSame([\RuntimeException::class, 'NetworkCoordinator: provide verificationShares or enroll'],
            self::throws(static fn() => new NetworkCoordinator(['groupPublicKey' => $kg['groupPublicKey'], 'threshold' => 1, 'signers' => []])));
        $this->assertSame([\RuntimeException::class, 'coordinator.sign: message must be bytes'],
            self::throws(static fn() => self::coordinator([new K27FsTransport(1)])->sign(5, null)));
    }

    /** signerIds match an identifier by number value, by identical non-number, or both absent; never across a number and a string. */
    public function testSignerSelection(): void
    {
        $picked = [CoordinatorError::class, 'coordinator: round 1 produced 0 commitment(s), need t=1'];
        $none = [CoordinatorError::class, 'coordinator: only 0 signer(s) selected, need t=1'];
        $cases = [
            ['x', 'x', $picked], ['y', 'x', $none], [new Undef(), 'x', $none], ['x', new Undef(), $none], [new Undef(), new Undef(), $picked],
            ['1', 1, $none], [1.0, 1, $picked],
        ];
        foreach ($cases as $n => [$want, $have, $expect]) {
            $this->assertSame($expect, self::throws(static fn() => self::coordinator([new K27FsTransport($have)])->sign('m', null, ['signerIds' => [$want]])), "case $n");
        }
    }

    /** A signer that throws in round 1 is refused with its message, or "unreachable" when it has none; a null proof of possession is a TypeError. */
    public function testRound1TransportFailures(): void
    {
        foreach (['' => 'unreachable', 'boom' => 'boom'] as $msg => $reason) {
            $t = new K27FsTransport(1, static fn() => throw new \RuntimeException((string)$msg));
            $this->assertSame([$reason], self::refusalReasons(static fn() => self::coordinator([$t])->sign('m', null)));
        }
        $t = new K27FsTransport(1, static fn() => Obj::of(['ok' => true, 'identifier' => 1, 'pop' => null]));
        $this->assertSame([\TypeError::class, "Cannot read properties of null (reading 'identifier')"], self::throws(static fn() => self::coordinator([$t])->sign('m', null)));
    }

    /** A signer that throws in round 2 is refused with its message, or "unreachable" when it has none. */
    public function testRound2TransportFailures(): void
    {
        $inner = new InProcessTransport(new GuardianSignerService(self::opts(self::kg(1, 1), 1, 1)));
        foreach (['' => 'unreachable', 'boom' => 'boom'] as $msg => $reason) {
            $t = new K27FsTransport(1, static fn(Obj $r) => $inner->round1($r), static fn() => throw new \RuntimeException((string)$msg));
            $this->assertSame([$reason], self::refusalReasons(static fn() => self::coordinator([$t])->sign('m', null)));
        }
    }

    /** A round-2 answer without a share is refused and the remaining answers are still examined. */
    public function testRound2KeepsCheckingAfterARefusal(): void
    {
        $kg = self::kg(2, 2);
        $ts = [];
        foreach ([1, 2] as $i) {
            $inner = new InProcessTransport(new GuardianSignerService(self::opts($kg, $i, 2)));
            $ts[] = new K27FsTransport($i, static fn(Obj $r) => $inner->round1($r),
                static fn() => $i === 1 ? Obj::of(['ok' => true, 'identifier' => 1]) : Obj::of(['ok' => false, 'identifier' => 2, 'reason' => 'r2']));
        }
        $vs = array_map(static fn(array $s): array => ['identifier' => $s['identifier'], 'publicKey' => $s['publicKey']], $kg['participantShares']);
        $coord = new NetworkCoordinator(['groupPublicKey' => $kg['groupPublicKey'], 'threshold' => 2, 'signers' => $ts, 'verificationShares' => $vs]);
        $this->assertSame(['equivocation check failed', 'r2'], self::refusalReasons(static fn() => $coord->sign('m', null)));
    }

    /** A session that outlives its window is a timeout naming the window in milliseconds. */
    public function testTimeoutMessage(): void
    {
        $ticks = [0, 10];
        $clock = static function () use (&$ticks): int {
            return array_shift($ticks);
        };
        $this->assertSame([\Atlas\Pca\CoordinatorTimeoutError::class, 'coordinator: signing session did not reach threshold within 5ms'],
            self::throws(static fn() => self::coordinator([new K27FsTransport(1)], ['clock' => $clock, 'timeoutMs' => 5])->sign('m', null)));
    }
}
