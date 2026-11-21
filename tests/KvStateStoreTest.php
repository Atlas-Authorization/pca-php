<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/KvStateStore.php';

use Atlas\Pca\KvStateStore;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\PcaStateStores;
use PHPUnit\Framework\TestCase;

/** durablePcaStateStore (require-pca.ts): the replay / budget / pin / consume-once store over an atomic kv. */
final class KvStateStoreTest extends TestCase
{
    public function testClaimIsStrictlyIncreasing(): void
    {
        $s = new KvStateStore(new MemoryAtomicKv());
        self::assertSame('shared', $s->scope());
        self::assertNull($s->last('k'));
        self::assertTrue($s->claim('k', 5)->ok);
        self::assertSame(5, $s->last('k'));
        $r = $s->claim('k', 5);
        self::assertFalse($r->ok);
        self::assertSame(5, $r->lastCounter);
        self::assertFalse($s->claim('k', 4)->ok);
        self::assertTrue($s->claim('k', 6)->ok);
        self::assertTrue($s->claim('other', 1)->ok);
    }

    public function testBudgetClaimComparesTheStoredBudget(): void
    {
        $s = new KvStateStore(new MemoryAtomicKv());
        $b1 = ['B' => 10.0, 'tau' => 2.0, 'asOf' => 100.0];
        $b2 = ['B' => 7.5, 'tau' => 2.0, 'asOf' => 200.0];
        self::assertNull($s->budget('k'));
        self::assertTrue($s->claimWithBudget('k', 1, null, $b1)->ok);
        self::assertSame($b1, $s->budget('k'));
        $c = $s->claimWithBudget('k', 2, null, $b2);
        self::assertTrue($c->conflict && !$c->ok, 'the budget changed since it was read');
        self::assertTrue($s->claimWithBudget('k', 2, $b1, $b2)->ok);
        self::assertSame($b2, $s->budget('k'));
        $replay = $s->claimWithBudget('k', 2, $b2, null);
        self::assertFalse($replay->ok);
        self::assertSame(2, $replay->lastCounter);
        self::assertTrue($s->claimWithBudget('k', 3, $b2, null)->ok);
        self::assertSame($b2, $s->budget('k'), 'a null after keeps the stored budget');
    }

    public function testPinsOnlyRise(): void
    {
        $s = new KvStateStore(new MemoryAtomicKv(), 'p:', 'process');
        self::assertSame('process', $s->scope());
        self::assertNull($s->pin('k'));
        $s->raisePin('k', 5);
        $s->raisePin('k', 3);
        self::assertSame(5, $s->pin('k'));
        $s->raisePin('k', 9);
        self::assertSame(9, $s->pin('k'));
        $s->raiseBeaconSeq('k', 4);
        self::assertSame(9, $s->pin('k'), 'the beacon pin is separate');
        self::assertTrue($s->claim('k', 1)->ok, 'a pin write keeps the document usable');
    }

    public function testConsumeOnceAndHelpers(): void
    {
        $s = new KvStateStore(new MemoryAtomicKv());
        self::assertTrue($s->consumeOnce('slot', 2000, 1000));
        self::assertFalse($s->consumeOnce('slot', 1500, 1500));
        self::assertTrue($s->consumeOnce('slot', 4000, 2001), 'the record elapsed');
        self::assertTrue(PcaStateStores::isAtomic($s));
        self::assertTrue(PcaStateStores::isAtomic(PcaStateStores::memory()));
        self::assertFalse(PcaStateStores::isAtomic(new \stdClass()));
        self::assertInstanceOf(KvStateStore::class, PcaStateStores::durable(new MemoryAtomicKv()));
        self::assertInstanceOf(MemoryStateStore::class, PcaStateStores::memory());
    }

    public function testConsumeOnceRefusesBadInput(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new KvStateStore(new MemoryAtomicKv()))->consumeOnce('', 1, 0);
    }
}
