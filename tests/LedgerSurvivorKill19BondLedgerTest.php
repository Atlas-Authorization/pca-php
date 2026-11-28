<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\BondStore;
use Atlas\Pca\BondStoreError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvBondStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use Atlas\Pca\Payments;
use Atlas\Pca\StoreBondLedger;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/BondLedger.php: typed store failures, the ledger's challenge-window clock, idempotent retries and every gate. */
final class LedgerSurvivorKill19BondLedgerTest extends TestCase
{
    private int|float|string $t = 100000;

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/ledger19-' . $label, true);
    }

    private static function guardian(): KeyPair
    {
        return new KeyPair(self::seed('guardian'));
    }

    private static function pcactn(): Obj
    {
        return Obj::of(['action' => Obj::of(['reversibility_class' => 'reversible'])]);
    }

    private static function agentPublic(): string
    {
        return (new KeyPair(self::seed('agent')))->public;
    }

    /** A signed claim issued at 100000 with a 60000 ms window for bond c1 (overrides win). */
    private static function claim(array $o = []): Obj
    {
        return Payments::openChargeBond(self::pcactn(), $o + ['claimedR' => 0.1, 'serverNow' => 100000, 'bondRef' => 'c1', 'challengeWindowMs' => 60000],
            self::seed('agent'));
    }

    private function ledger(?BondStore $store = null, ?array $windowPolicy = null): StoreBondLedger
    {
        return new StoreBondLedger($store ?? new KvBondStore(new MemoryAtomicKv()), self::guardian(), fn() => $this->t, $windowPolicy);
    }

    /** A funded ledger with claim c1 registered at 100000 (window ends at 160000). @return array{StoreBondLedger,Obj} */
    private function registered(): array
    {
        $l = $this->ledger();
        $l->deposit('alice', 100);
        $claim = self::claim();
        $l->openClaim($claim, self::pcactn(), self::agentPublic(), 10, 'alice');
        return [$l, $claim];
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return (new \ReflectionClass($e))->getShortName() . ': ' . $e->getMessage();
        }
        return 'nothing thrown';
    }

    private static function snap(array $over = []): array
    {
        return $over + ['balances' => [], 'openTotals' => ['count' => 0, 'sum' => 0], 'highWater' => 0];
    }

    private static function fake(array $snap, ?array $out = null): BondStore
    {
        return new class ($snap, $out ?? ['outcome' => 'conflict', 'reason' => 'refused']) implements BondStore {
            public function __construct(private array $snap, private array $out)
            {
            }

            public function read(string $claimId, ?string $depositor = null): array
            {
                return $this->snap;
            }

            public function commit(mixed $plan, mixed $observedAt): array
            {
                return $this->out;
            }

            public function deposit(mixed $account, mixed $amount): float|int
            {
                return 0;
            }
        };
    }

    private static function failing(\Throwable $e): BondStore
    {
        return new class ($e) implements BondStore {
            public function __construct(private \Throwable $e)
            {
            }

            public function read(string $claimId, ?string $depositor = null): array
            {
                throw $this->e;
            }

            public function commit(mixed $plan, mixed $observedAt): array
            {
                throw $this->e;
            }

            public function deposit(mixed $account, mixed $amount): float|int
            {
                throw $this->e;
            }
        };
    }

    private static function windowed(mixed $registeredAt, mixed $windowMs, mixed $highWater = 0): array
    {
        return self::snap(['bond' => ['claimId' => 'c', 'amount' => 5, 'depositor' => 'd', 'status' => 'open',
            'window' => ['registeredAt' => $registeredAt, 'windowMs' => $windowMs, 'claimDigest' => 'x'], 'records' => []], 'highWater' => $highWater]);
    }

    /** The ledger refuses a missing store or guardian by code, and exposes the guardian key the records verify under. */
    public function testConstructorNeedsAStoreAndAGuardian(): void
    {
        $this->assertSame('BondStoreError: store_missing: a BondStore is required (there is no in-memory default)',
            self::thrown(fn() => new StoreBondLedger(new \stdClass(), self::guardian())));
        $this->assertSame('BondStoreError: guardian_key_missing: a guardian secret key is required',
            self::thrown(fn() => new StoreBondLedger(new KvBondStore(new MemoryAtomicKv()), 'not-a-key')));
        $this->assertSame(self::guardian()->public, $this->ledger()->guardianPublicKey());
    }

    /** Without a clock the ledger reads epoch milliseconds. */
    public function testDefaultClockIsEpochMilliseconds(): void
    {
        $l = new StoreBondLedger(self::fake(self::windowed(0, 1000)), self::guardian());
        $before = microtime(true) * 1000;
        $now = $l->challengeStatus('c')['now'];
        $after = microtime(true) * 1000;
        $this->assertGreaterThanOrEqual($before - 1, $now);
        $this->assertLessThanOrEqual($after + 1, $now);
    }

    /** A coded store failure keeps its code; any other failure is store_unavailable with its message (or "store failed"). */
    public function testStoreFailuresAreTyped(): void
    {
        $this->assertSame('BondStoreError: store_corrupt: bad doc',
            self::thrown(fn() => $this->ledger(self::failing(new BondStoreError('store_corrupt', 'bad doc')))->bondStatus('c')));
        $this->assertSame('BondStoreError: store_unavailable: disk gone',
            self::thrown(fn() => $this->ledger(self::failing(new \RuntimeException('disk gone')))->bondStatus('c')));
        $this->assertSame('BondStoreError: store_unavailable: store failed',
            self::thrown(fn() => $this->ledger(self::failing(new \RuntimeException('')))->balanceOf('a')));
    }

    /** The clock must return an int or a float: a string is refused, a fractional float is used as is. */
    public function testClockMustBeANumber(): void
    {
        $store = self::fake(self::windowed(0, 1000));
        $this->t = 'x';
        $this->assertSame('BondStoreError: clock_invalid: the clock returned a non-finite time', self::thrown(fn() => $this->ledger($store)->challengeStatus('c')));
        $this->t = 500.5;
        $this->assertEquals(['phase' => 'open', 'endsAt' => 1000, 'now' => 500.5], $this->ledger($store)->challengeStatus('c'));
    }

    /** challengeStatus: an infinite window is refused; the window is open up to and including its end; the store's high-water mark counts. */
    public function testChallengeStatusBoundsAndFiniteness(): void
    {
        $this->assertSame('BondStoreError: clock_invalid: the challenge window or the clock is not a finite time',
            self::thrown(fn() => $this->ledger(self::fake(self::windowed(0, INF)))->challengeStatus('c')));
        $this->t = 1000;
        $this->assertSame('open', $this->ledger(self::fake(self::windowed(0, 1000)))->challengeStatus('c')['phase']);
        $this->t = 1001;
        $this->assertSame('finalized', $this->ledger(self::fake(self::windowed(0, 1000)))->challengeStatus('c')['phase']);
        $this->t = 1000; // a numeric-string high-water mark above the clock still decides "now"
        $s = $this->ledger(self::fake(self::windowed(0, 1000, '200000')))->challengeStatus('c');
        $this->assertSame(['finalized', '200000'], [$s['phase'], $s['now']]);
        $this->assertSame('open', $this->ledger(self::fake(self::windowed([1], [2])))->challengeStatus('c')['phase']);
    }

    /** Deposits, balances, bond status and rows through the reference store; an unknown account is 0 and an absent bond is "none". */
    public function testBooksAndCounterBondOpen(): void
    {
        $l = $this->ledger();
        $this->assertSame(100.0, $l->deposit('alice', 100));
        $this->assertSame(100.0, $l->balanceOf('alice'));
        $this->assertSame(0, $l->balanceOf('nobody'));
        $this->assertSame('none', $l->bondStatus('cb'));
        $this->assertNull($l->getBond('cb'));
        $rec = $l->openBond('cb', 10, 'alice');
        $this->assertSame(['open', 'cb', 'alice'], [$rec->get('action'), $rec->get('claimId'), $rec->get('from')]);
        $this->assertSame('open', $l->bondStatus('cb'));
        $row = $l->getBond('cb');
        $this->assertSame(['cb', 'alice', 'open'], [$row['claimId'], $row['depositor'], $row['status']]);
        $this->assertArrayNotHasKey('window', $row);
        $this->assertSame([90.0, 10.0], [$l->balanceOf('alice'), $l->balanceOf('escrow')]);
        // a retry with the same terms returns the original record; any other terms are the double-open refusal
        $this->t = 100500;
        $this->assertSame($rec->get('sig'), $l->openBond('cb', 10, 'alice')->get('sig'));
        $this->assertSame('BondStoreError: conflict: openBond: bond cb already exists (double-open refused)', self::thrown(fn() => $l->openBond('cb', 11, 'alice')));
        $l->deposit('bob', 50);
        $this->assertSame('BondStoreError: conflict: openBond: bond cb already exists (double-open refused)', self::thrown(fn() => $l->openBond('cb', 10, 'bob')));
        $this->assertSame(90.0, $l->balanceOf('alice'));
    }

    /** A balance the store does not report is 0, so an unfunded bond of exactly 1 is refused by the planner. */
    public function testUnreportedBalanceIsZero(): void
    {
        $l = $this->ledger(self::fake(self::snap()));
        $this->assertSame(0, $l->balanceOf('a'));
        $this->assertSame('InvalidArgumentException: openBond: insufficient balance for the bond', self::thrown(fn() => $l->openBond('c', 1, 'alice')));
    }

    /** A plan the store refuses is a conflict with the store's reason. */
    public function testStoreConflictIsRaised(): void
    {
        $l = $this->ledger(self::fake(self::snap(['balances' => [['alice', 100]]])));
        $this->assertSame('BondStoreError: conflict: refused', self::thrown(fn() => $l->openBond('c', 5, 'alice')));
    }

    /** The view keys balances and bonds by their string form, whatever scalar type the store reports. */
    public function testViewKeysByStringForm(): void
    {
        $rec = Obj::of(['ok' => true]);
        $committed = ['outcome' => 'committed', 'record' => $rec];
        $this->assertSame($rec, $this->ledger(self::fake(self::snap(['balances' => [[1.5, 100]]]), $committed))->openBond('c', 5, '1.5'));
        $bond = ['claimId' => 7, 'amount' => 5, 'depositor' => 'd', 'status' => 'open', 'records' => []];
        $this->assertSame($rec, $this->ledger(self::fake(self::snap(['bond' => $bond]), $committed))->releaseUnregistered('7'));
    }

    /** The ledger's window policy applies to openClaim (a 60 s window is below a 100 s minimum). */
    public function testWindowPolicyIsApplied(): void
    {
        $l = $this->ledger(null, ['minWindowMs' => 100000, 'maxWindowMs' => 86_400_000, 'defaultWindowMs' => 300_000, 'maxSkewMs' => 5000]);
        $l->deposit('alice', 100);
        $this->assertSame('BondStoreError: invalid_claim: challenge window is below the minimum',
            self::thrown(fn() => $l->openClaim(self::claim(), self::pcactn(), self::agentPublic(), 10, 'alice')));
        $this->assertSame('none', $l->bondStatus('c1'));
    }

    /** openClaim refuses a bad signature, a window under the 30 s floor and a missing bond_ref; exactly 30 s is accepted. */
    public function testOpenClaimRefusals(): void
    {
        $l = $this->ledger();
        $l->deposit('alice', 100);
        $pk = self::agentPublic();
        $this->assertSame('BondStoreError: invalid_claim: claim signature does not verify',
            self::thrown(fn() => $l->openClaim(self::claim(), self::pcactn(), self::guardian()->public, 10, 'alice')));
        $this->assertSame('BondStoreError: invalid_claim: challenge window 20000 ms is below the 30000 ms floor',
            self::thrown(fn() => $l->openClaim(self::claim(['challengeWindowMs' => 20000]), self::pcactn(), $pk, 10, 'alice')));
        foreach ([null, ''] as $ref) {
            $this->assertSame('BondStoreError: invalid_claim: claim has no bond_ref',
                self::thrown(fn() => $l->openClaim(self::claim(['bondRef' => $ref]), self::pcactn(), $pk, 10, 'alice')));
        }
        $rec = $l->openClaim(self::claim(['challengeWindowMs' => 30000]), self::pcactn(), $pk, 10, 'alice');
        $this->assertSame('open', $rec->get('action'));
        $this->assertEquals(['phase' => 'open', 'endsAt' => 130000, 'now' => 100000], $l->challengeStatus('c1'));
    }

    /** The registered window runs from the ledger's registeredAt: open through 160000, release only after it, and a release retry is the stored record. */
    public function testRegisteredClaimReleaseLifecycle(): void
    {
        [$l, $claim] = $this->registered();
        $this->assertSame($l->getBond('c1')['records'][0]->get('sig'), $l->openClaim($claim, self::pcactn(), self::agentPublic(), 10, 'alice')->get('sig'));
        $this->assertSame('BondStoreError: conflict: bond c1 backs a registered claim; use release', self::thrown(fn() => $l->releaseUnregistered('c1')));
        $this->t = 160000;
        $this->assertEquals(['phase' => 'open', 'endsAt' => 160000, 'now' => 160000], $l->challengeStatus('c1'));
        foreach ([100001, 160000] as $t) {
            $this->t = $t;
            $this->assertSame('BondStoreError: window_open: the challenge window of c1 closes at 160000', self::thrown(fn() => $l->release('c1')));
        }
        $this->assertSame('open', $l->bondStatus('c1'));
        $this->t = 160001;
        $this->assertSame('finalized', $l->challengeStatus('c1')['phase']);
        $rel = $l->release('c1');
        $this->assertSame(['release', 'escrow', 'alice'], [$rel->get('action'), $rel->get('from'), $rel->get('to')]);
        $this->assertSame(['released', 100.0, 0.0], [$l->bondStatus('c1'), $l->balanceOf('alice'), $l->balanceOf('escrow')]);
        $this->t = 170000;
        $again = $l->release('c1');
        $this->assertSame([$rel->get('sig'), 'release'], [$again->get('sig'), $again->get('action')]);
        $this->assertSame(100.0, $l->balanceOf('alice'));
    }

    /** Fraud and dispute slashes are gated: the registered claim only, inside the window (its end included); a counter-bond is unregistered. */
    public function testChallengeGate(): void
    {
        [$l, $claim] = $this->registered();
        $other = self::claim(['claimedR' => 0.2]);
        $this->t = 100001;
        $this->assertSame('BondStoreError: claim_mismatch: the claim is not the one registered for c1', self::thrown(fn() => $l->slashBond(['claimId' => 'c1', 'claim' => $other])));
        $this->assertSame('InvalidArgumentException: slashBond: treasury is required', self::thrown(fn() => $l->slashBond(['claimId' => 'c1', 'claim' => $claim])));
        $this->t = 160000;
        $this->assertSame('InvalidArgumentException: slashBond: treasury is required', self::thrown(fn() => $l->slashBond(['claimId' => 'c1', 'claim' => $claim])));
        $this->assertSame('InvalidArgumentException: slashBondOnDispute: treasury is required',
            self::thrown(fn() => $l->slashBondOnDispute(['claimId' => 'c1', 'claim' => $claim])));
        $this->t = 160001;
        $this->assertSame('BondStoreError: window_closed: the challenge window of c1 closed at 160000', self::thrown(fn() => $l->slashBond(['claimId' => 'c1', 'claim' => $claim])));
        $this->assertSame('BondStoreError: window_closed: the challenge window of c1 closed at 160000',
            self::thrown(fn() => $l->slashBondOnDispute(['claimId' => 'c1', 'claim' => $claim])));
        $l->openBond('cb', 10, 'alice');
        $this->assertSame('BondStoreError: unregistered: bond cb has no registered claim', self::thrown(fn() => $l->slashBond(['claimId' => 'cb', 'claim' => $claim])));
        $this->assertSame('BondStoreError: unregistered: bond cb has no registered claim', self::thrown(fn() => $l->challengeStatus('cb')));
        $this->assertSame('BondStoreError: unregistered: bond cb has no registered claim; use releaseUnregistered for a counter-bond',
            self::thrown(fn() => $l->release('cb')));
    }

    /** A counter-bond takes the ungated paths: revocation and counter-bond slashes reach the planner, releaseUnregistered settles it. */
    public function testCounterBondPaths(): void
    {
        $l = $this->ledger();
        $l->deposit('alice', 100);
        $l->openBond('cb', 10, 'alice');
        $this->assertSame('InvalidArgumentException: slashBondOnRevocation: treasury is required',
            self::thrown(fn() => $l->slashBondOnRevocation(['claimId' => 'cb', 'claim' => self::claim()])));
        $this->assertSame('InvalidArgumentException: slashCounterBond: treasury is required', self::thrown(fn() => $l->slashCounterBond(['counterBondId' => 'cb'])));
        $this->assertSame('InvalidArgumentException: slashCounterBond: no counter-bond for nope', self::thrown(fn() => $l->slashCounterBond(['counterBondId' => 'nope'])));
        $this->assertSame('InvalidArgumentException: releaseBond: no bond for nope', self::thrown(fn() => $l->release('nope')));
        $this->assertSame('release', $l->releaseUnregistered('cb')->get('action'));
        $this->assertSame(['released', 100.0], [$l->bondStatus('cb'), $l->balanceOf('alice')]);
    }

    /** A revocation slash needs the registered claim; once slashed, a release is the double-settle refusal. */
    public function testRevocationSlashThenReleaseIsRefused(): void
    {
        [$l, $claim] = $this->registered();
        $p = ['claimId' => 'c1', 'claim' => $claim, 'treasury' => 'treasury', 'revokedCapId' => 'cap-1'];
        $this->assertSame('BondStoreError: claim_mismatch: the claim is not the one registered for c1',
            self::thrown(fn() => $l->slashBondOnRevocation(['claim' => self::claim(['claimedR' => 0.2])] + $p)));
        $rec = $l->slashBondOnRevocation($p);
        $this->assertSame(['slash', 'c1'], [$rec->get('action'), $rec->get('claimId')]);
        $this->assertSame(['slashed', 10.0, 90.0], [$l->bondStatus('c1'), $l->balanceOf('treasury'), $l->balanceOf('alice')]);
        $this->t = 170000;
        $this->assertSame('InvalidArgumentException: releaseBond: bond c1 is already slashed (double-settle refused)', self::thrown(fn() => $l->release('c1')));
        $this->assertSame(10.0, $l->balanceOf('treasury'));
    }

    /** A numeric claim id is read as its string form on every slash path. */
    public function testNumericClaimIdIsCast(): void
    {
        $l = $this->ledger();
        $this->assertSame('InvalidArgumentException: slashBond: no bond for 5', self::thrown(fn() => $l->slashBond(['claimId' => 5])));
        $this->assertSame('InvalidArgumentException: slashBondOnDispute: no bond for 5', self::thrown(fn() => $l->slashBondOnDispute(['claimId' => 5])));
        $this->assertSame('InvalidArgumentException: slashBondOnRevocation: no bond for 5', self::thrown(fn() => $l->slashBondOnRevocation(['claimId' => 5])));
        $this->assertSame('InvalidArgumentException: slashCounterBond: no counter-bond for 5', self::thrown(fn() => $l->slashCounterBond(['counterBondId' => 5])));
    }
}
