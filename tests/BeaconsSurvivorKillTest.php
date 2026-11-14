<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\BeaconAcceptor;
use Atlas\Pca\Beacons;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Exact-result kills for beacon verification (every refusal is the whole array), monotone acceptance and the durable acceptor. */
final class BeaconsSurvivorKillTest extends TestCase
{
    private const NOW = 1800000000000;

    private static function refusal(string $reason): array
    {
        return ['ok' => false, 'reason' => $reason];
    }

    /** A signed beacon; `$over` replaces body members (before signing). */
    private static function beacon(KeyPair $kp, array $over = []): Obj
    {
        return Sign::signArtifact(Beacons::DOMAIN, array_merge([
            'v' => 2, 'instance' => 'inst', 'scope' => '*', 'epoch' => intdiv(self::NOW, 60000), 'seq' => 1,
            'issued_at' => self::NOW, 'not_after' => self::NOW + 300000, 'issuer' => $kp->public,
        ], $over), $kp);
    }

    private static function verify(KeyPair $kp, mixed $b, int $now = self::NOW, ?string $scope = null): array
    {
        return Beacons::verify($b, [$kp->public], $now, 'inst', $scope);
    }

    public function testEveryRefusalIsTheWholeArray(): void
    {
        $kp = KeyPair::generate();
        $b = self::beacon($kp);
        $this->assertSame(['ok' => true], self::verify($kp, $b));
        $this->assertSame(self::refusal('malformed beacon'), self::verify($kp, null));
        $this->assertSame(self::refusal('malformed beacon'), self::verify($kp, 'x'));
        $this->assertSame(self::refusal('wrong instance'), Beacons::verify($b, [$kp->public], self::NOW, 'other'));
        $this->assertSame(self::refusal('issuer not pinned'), Beacons::verify($b, [KeyPair::generate()->public], self::NOW, 'inst'));
        $this->assertSame(self::refusal('not yet valid'), self::verify($kp, $b, self::NOW - 30001));
        $this->assertSame(self::refusal('expired'), self::verify($kp, $b, self::NOW + 300001));
        $sc = self::beacon($kp, ['scope' => 'grant-1']);
        $this->assertSame(self::refusal('scope not covered'), self::verify($kp, $sc, self::NOW, 'grant-2'));
        $t = Obj::of([]);
        foreach ($b->keys() as $k) {
            $t->set($k, $k === 'seq' ? Sign::n(9) : $b->get($k));
        }
        $this->assertSame(self::refusal('bad signature'), self::verify($kp, $t));
    }

    public function testTheVersionMustBeExactlyTheNumberTwo(): void
    {
        $kp = KeyPair::generate();
        $this->assertSame(self::refusal('malformed beacon'), self::verify($kp, self::beacon($kp, ['v' => 3])));
        $this->assertSame(self::refusal('malformed beacon'), self::verify($kp, self::beacon($kp, ['v' => '2'])));
        $this->assertSame(self::refusal('malformed beacon'), self::verify($kp, self::beacon($kp, ['v' => 1])));
        $this->assertSame(['ok' => true], self::verify($kp, self::beacon($kp, ['v' => 2])));
    }

    public function testTheSignatureSuiteMustBeImplemented(): void
    {
        $kp = KeyPair::generate();
        $unknown = self::beacon($kp);
        $unknown->set('alg', 'nope');
        $this->assertSame(self::refusal('malformed beacon'), self::verify($kp, $unknown));
        $explicit = self::beacon($kp);
        $explicit->set('alg', 'ed25519');
        $this->assertSame(['ok' => true], self::verify($kp, $explicit));
    }

    public function testAMemberThatIsNotAnIntegerIsAMalformedWindow(): void
    {
        $kp = KeyPair::generate();
        foreach ([['epoch' => 'x'], ['seq' => 'x'], ['issued_at' => 'x'], ['not_after' => 'x'], ['seq' => -1]] as $i => $over) {
            $this->assertSame(self::refusal('malformed window'), self::verify($kp, self::beacon($kp, $over)), "case $i");
        }
        $this->assertSame(['ok' => true], self::verify($kp, self::beacon($kp, ['seq' => 0])), 'seq 0 is a valid first beacon');
    }

    public function testTheValidityWindowBoundaries(): void
    {
        $kp = KeyPair::generate();
        $zero = self::beacon($kp, ['not_after' => self::NOW]);
        $this->assertSame(self::refusal('validity exceeds the hard maximum'), self::verify($kp, $zero));
        $max = self::beacon($kp, ['not_after' => self::NOW + 3600000]);
        $this->assertSame(['ok' => true], self::verify($kp, $max));
        $over = self::beacon($kp, ['not_after' => self::NOW + 3600001]);
        $this->assertSame(self::refusal('validity exceeds the hard maximum'), self::verify($kp, $over));
    }

    public function testTheEpochIsTheFloorOfIssuedAtOverTheEpochLength(): void
    {
        $kp = KeyPair::generate();
        $iat = self::NOW + 30000; // half way into the epoch: floor, round and ceil disagree
        $b = self::beacon($kp, ['issued_at' => $iat, 'not_after' => $iat + 300000]);
        $this->assertSame(['ok' => true], self::verify($kp, $b, $iat));
        $up = self::beacon($kp, ['issued_at' => $iat, 'not_after' => $iat + 300000, 'epoch' => intdiv(self::NOW, 60000) + 1]);
        $this->assertSame(self::refusal('epoch does not match issued_at'), self::verify($kp, $up, $iat));
    }

    public function testAnUnverifiableBodyIsAMalformedBeaconNotAnException(): void
    {
        $kp = KeyPair::generate();
        $b = Obj::of(['v' => Sign::n(2), 'instance' => 'inst', 'scope' => '*', 'epoch' => 5, 'seq' => Sign::n(1), 'issued_at' => Sign::n(1),
            'not_after' => Sign::n(2), 'issuer' => $kp->public, 'sig' => 'AAAA']);
        $this->assertSame(self::refusal('malformed beacon'), self::verify($kp, $b));
    }

    public function testAcceptReadsNativeAndParsedNumbers(): void
    {
        $this->assertSame(['ok' => true], Beacons::accept(null, Obj::of(['seq' => 5])));
        $this->assertSame(['ok' => true], Beacons::accept(null, Obj::of(['seq' => 5.0])));
        $this->assertSame(['ok' => true], Beacons::accept(null, Obj::of(['seq' => 0])));
        $this->assertSame(['ok' => true], Beacons::accept(null, Obj::of(['seq' => new Num('0')])));
        $this->assertSame(['ok' => true], Beacons::accept(Obj::of(['seq' => 2]), Obj::of(['seq' => 3])));
        $this->assertSame(['ok' => true], Beacons::accept(null, Obj::of(['seq' => new Num('9007199254740991')])));
        foreach ([new Num('-0'), new Num('9007199254740992'), new Num('-1'), new Num('1.5'), 'x', null, true, [1]] as $i => $bad) {
            $this->assertSame(self::refusal('malformed beacon'), Beacons::accept(null, Obj::of(['seq' => $bad])), "seq $i");
        }
        $this->assertSame(self::refusal('malformed beacon'), Beacons::accept(null, Obj::of([])));
        $this->assertSame(self::refusal('malformed beacon'), Beacons::accept(null, 'x'));
    }

    public function testAcceptTreatsOnlyNullAndFalseAsNoPreviousBeacon(): void
    {
        $next = Obj::of(['seq' => 1]);
        $this->assertSame(['ok' => true], Beacons::accept(null, $next));
        $this->assertSame(['ok' => true], Beacons::accept(false, $next));
        $this->assertSame(self::refusal('replayed beacon: seq 1 <= undefined'), Beacons::accept(true, $next));
        $this->assertSame(self::refusal('replayed beacon: seq 1 <= undefined'), Beacons::accept('junk', $next));
        $this->assertSame(self::refusal('replayed beacon: seq 1 <= undefined'), Beacons::accept(Obj::of(['seq' => 'x']), $next));
    }

    public function testAcceptReplayReasonPrintsTheSafeIntegerInFull(): void
    {
        $big = new Num('9007199254740991');
        $this->assertSame(self::refusal('replayed beacon: seq 9007199254740991 <= 9007199254740991'),
            Beacons::accept(Obj::of(['seq' => $big]), Obj::of(['seq' => $big])));
        $this->assertSame(self::refusal('replayed beacon: seq 3 <= 3.5'), Beacons::accept(Obj::of(['seq' => new Num('3.5')]), Obj::of(['seq' => 3])));
    }

    // ---- the durable acceptor -------------------------------------------------------------------------------------------

    private static function kv(?string $prev): object
    {
        return new class ($prev) implements AtomicKv {
            /** @var list<string> */
            public array $keys = [];
            public ?string $out = null;

            public function __construct(private readonly ?string $prev)
            {
            }

            public function get(string $key): ?string
            {
                return $this->prev;
            }

            public function update(string $key, callable $fn): void
            {
                $this->keys[] = $key;
                $this->out = $fn($this->prev);
            }
        };
    }

    private static function check(KeyPair $kp, string $instance = 'inst'): array
    {
        return ['issuers' => [$kp->public], 'now' => self::NOW, 'instance' => $instance];
    }

    public function testTheStoreKeyNamesInstanceScopeAndIssuerWithoutEscaping(): void
    {
        $kp = KeyPair::generate();
        $kv = self::kv(null);
        $b = self::beacon($kp, ['instance' => "i/\u{e9}", 'seq' => 7]);
        $this->assertSame(['ok' => true], (new BeaconAcceptor($kv))->accept($b, self::check($kp, "i/\u{e9}")));
        $this->assertSame(["beacon-seq/v1/[\"i/\u{e9}\",\"*\",\"{$kp->public}\"]"], $kv->keys);
        $this->assertSame('7', $kv->out);
    }

    public function testTheStoredSeqIsComparedAsANumber(): void
    {
        $kp = KeyPair::generate();
        $b = self::beacon($kp, ['seq' => 6]);
        $kv = self::kv('5');
        $this->assertSame(['ok' => true], (new BeaconAcceptor($kv))->accept($b, self::check($kp)));
        $this->assertSame('6', $kv->out);
        $this->assertSame(self::refusal('replayed beacon: seq 6 <= 6'), (new BeaconAcceptor(self::kv('6')))->accept($b, self::check($kp)));
        $this->assertSame(self::refusal('replayed beacon: seq 6 <= 10'), (new BeaconAcceptor(self::kv('10')))->accept($b, self::check($kp)));
    }

    public function testAStoredSeqAtTheSafeIntegerLimitIsNotJunk(): void
    {
        $kp = KeyPair::generate();
        $b = self::beacon($kp, ['seq' => 9007199254740991]);
        $this->assertSame(self::refusal('replayed beacon: seq 9007199254740991 <= 9007199254740991'),
            (new BeaconAcceptor(self::kv('9007199254740991')))->accept($b, self::check($kp)));
        $this->assertSame(self::refusal('beacon state unavailable'), (new BeaconAcceptor(self::kv('9007199254740992')))->accept($b, self::check($kp)));
    }

    public function testAJunkStoredSeqIsStateUnavailable(): void
    {
        $kp = KeyPair::generate();
        $b = self::beacon($kp, ['seq' => 9]);
        foreach (['junk', 'x5', '5x', '', '-1', '01', '1.5', ' 5'] as $junk) {
            $this->assertSame(self::refusal('beacon state unavailable'), (new BeaconAcceptor(self::kv($junk)))->accept($b, self::check($kp)), "stored '$junk'");
        }
    }

    public function testAStoreThatThrowsIsStateUnavailable(): void
    {
        $kp = KeyPair::generate();
        $throwing = new class implements AtomicKv {
            public function get(string $key): ?string
            {
                return null;
            }

            public function update(string $key, callable $fn): void
            {
                throw new \RuntimeException('down');
            }
        };
        $this->assertSame(self::refusal('beacon state unavailable'), (new BeaconAcceptor($throwing))->accept(self::beacon($kp), self::check($kp)));
    }
}
