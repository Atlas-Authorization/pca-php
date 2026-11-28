<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FenceError;
use Atlas\Pca\FenceGuard;
use Atlas\Pca\Ha;
use Atlas\Pca\Jsx;
use Atlas\Pca\KvLeaseStore;
use Atlas\Pca\LeaseStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Ha: the lease store's corrupt-state refusal and clock, lease options, epochs, store errors, fencing and signer order. */
final class SigSurvivorKill29HaTest extends TestCase
{
    protected function setUp(): void
    {
        Jsx::init();
    }

    protected function tearDown(): void
    {
        KvLeaseStore::$clockHook = null;
    }

    /** A store whose read() answers with `$read` (a value, or a Throwable it throws) and whose clock is 1000. */
    private static function store(mixed $read): LeaseStore
    {
        return new class ($read) implements LeaseStore {
            public function __construct(private readonly mixed $r)
            {
            }

            public function read(): mixed
            {
                if ($this->r instanceof \Throwable) {
                    throw $this->r;
                }
                return $this->r;
            }

            public function cas(mixed $expected, Obj $next): bool
            {
                return true;
            }

            public function now(): int|float
            {
                return 1000;
            }
        };
    }

    public function testFenceErrorMessage(): void
    {
        $e = new FenceError('stale');
        $this->assertSame('stale', $e->reason);
        $this->assertSame('fenced: stale', $e->getMessage());
    }

    public function testKvStoreRefusesACorruptRecord(): void
    {
        $kv = new MemoryAtomicKv();
        $kv->update('ha/lease', static fn (?string $raw): string => '{"holder":5}');
        try {
            (new KvLeaseStore($kv))->read();
            $this->fail('expected a refusal');
        } catch (\RuntimeException $e) {
            $this->assertSame('corrupt lease state', $e->getMessage());
        }
    }

    /** The default store clock is whole wall-clock milliseconds rounded down. */
    public function testKvStoreClockIsWholeMilliseconds(): void
    {
        KvLeaseStore::$clockHook = static fn (): float => 1.0009765625; // 1000.9765625 ms exactly
        $this->assertSame(1000, (new KvLeaseStore(new MemoryAtomicKv()))->now());
        KvLeaseStore::$clockHook = null;
        $now = (new KvLeaseStore(new MemoryAtomicKv()))->now();
        $this->assertIsInt($now);
        $this->assertLessThan(60_000, abs($now - (int)floor(microtime(true) * 1000)));
    }

    public function testFenceGuardStartsAtZero(): void
    {
        $this->assertSame(0.0, (new FenceGuard())->highest());
    }

    /** ttlMs must be an integer of at least 2. */
    public function testLeaseTtl(): void
    {
        $this->assertTrue(Ha::acquireLease(new KvLeaseStore(new MemoryAtomicKv(), 'k', static fn () => 1000), 'h', Obj::of(['ttlMs' => 2, 'skewMs' => 0]))['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'invalid'],
            Ha::acquireLease(new KvLeaseStore(new MemoryAtomicKv(), 'k', static fn () => 1000), 'h', Obj::of(['ttlMs' => 3.5, 'skewMs' => 0])));
    }

    /** A takeover after a release carries the next epoch as an integer. */
    public function testTheNextEpochIsAnInteger(): void
    {
        $s = new KvLeaseStore(new MemoryAtomicKv(), 'k', static fn () => 1000);
        $o = Obj::of(['ttlMs' => 5000]);
        $first = Ha::acquireLease($s, 'h', $o);
        $this->assertSame(1, $first['lease']->get('epoch'));
        $this->assertTrue(Ha::releaseLease($s, $first['lease'])['ok']);
        $this->assertSame(2, Ha::acquireLease($s, 'h', $o)['lease']->get('epoch'));
    }

    /** A record the store hands back that is not a lease is a store error, never a free lease. */
    public function testACorruptSnapshotIsAStoreError(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'store-error', 'detail' => 'corrupt lease state'],
            Ha::acquireLease(self::store(Obj::of(['holder' => 5])), 'h', Obj::of(['ttlMs' => 5000])));
    }

    /** A store failure's message is reported for a RuntimeException or an Error, and hidden for any other exception. */
    public function testStoreErrorDetail(): void
    {
        $o = Obj::of(['ttlMs' => 5000]);
        $this->assertSame('rt', Ha::acquireLease(self::store(new \RuntimeException('rt')), 'h', $o)['detail']);
        $this->assertSame('er', Ha::acquireLease(self::store(new \Error('er')), 'h', $o)['detail']);
        $this->assertSame('unknown', Ha::acquireLease(self::store(new \LogicException('lg')), 'h', $o)['detail']);
    }

    /** Equal leases need both epochs to be numbers: 0 is not equal to an absent epoch. */
    public function testSameLeaseNeedsNumbersOnBothSides(): void
    {
        $this->assertFalse(Ha::sameLease(Obj::of(['holder' => 'h', 'epoch' => 0, 'expiresAt' => 1]), Obj::of(['holder' => 'h', 'epoch' => null, 'expiresAt' => 1])));
        $this->assertTrue(Ha::sameLease(Obj::of(['holder' => 'h', 'epoch' => 1, 'expiresAt' => 1]), Obj::of(['holder' => 'h', 'epoch' => 1.0, 'expiresAt' => 1])));
    }

    /** A signer whose fence fails beforehand never signs. */
    public function testFencedSignerChecksBeforeSigning(): void
    {
        $s = new KvLeaseStore(new MemoryAtomicKv(), 'k', static fn () => 1000);
        $signed = false;
        $f = Ha::fencedSigner($s, static fn () => Obj::of(['holder' => 'h', 'epoch' => 1, 'expiresAt' => 9000]), static function () use (&$signed): string {
            $signed = true;
            return 'sig';
        });
        try {
            $f();
            $this->fail('expected a FenceError');
        } catch (FenceError $e) {
            $this->assertSame('stale', $e->reason);
        }
        $this->assertFalse($signed);
    }

    /** An absent weight counts as 0, below any positive weight. */
    public function testAnAbsentWeightIsZero(): void
    {
        $set = Obj::of(['quorum' => 1, 'guardians' => [Obj::of(['id' => 'a', 'healthy' => true, 'lastSeen' => 1000]),
            Obj::of(['id' => 'b', 'healthy' => true, 'lastSeen' => 1000, 'weight' => 0.5])]]);
        $this->assertSame(['b'], Ha::selectSigners($set, 1000));
    }

    /** Ordering two otherwise-equal guardians needs both ids to be text. */
    public function testANonStringIdIsRefusedWhenOrdering(): void
    {
        $set = Obj::of(['quorum' => 2, 'guardians' => [Obj::of(['id' => 'a', 'healthy' => true, 'lastSeen' => 1000]),
            Obj::of(['id' => 5, 'healthy' => true, 'lastSeen' => 1000])]]);
        try {
            Ha::selectSigners($set, 1000);
            $this->fail('expected a TypeError');
        } catch (\TypeError $e) {
            $this->assertSame('guardian id is not a string', $e->getMessage());
        }
    }
}
