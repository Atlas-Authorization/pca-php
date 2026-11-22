<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryLeaseKv;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\StoreConformance;
use PHPUnit\Framework\TestCase;

/** F11: the kits run against the in-memory stores (all pass) and against stores that break one claim each (the kit must fail). */
final class K05HardStoreKitsTest extends TestCase
{
    private function mem(): array
    {
        return ['shared' => false, 'durable' => false, 'copies' => 6];
    }

    public function testTheKitsPassOnTheMemoryStores(): void
    {
        $kv1 = new MemoryLeaseKv(); // one process-local store: every open() is the same store, as for the state store below
        $r = StoreConformance::runAtomicKv(['open' => static fn() => $kv1] + $this->mem());
        $this->assertTrue($r->ok(), (string)$r);
        $kv2 = new MemoryAtomicKv();
        $r = StoreConformance::runAtomicKv(['open' => static fn() => $kv2] + $this->mem());
        $this->assertTrue($r->ok(), (string)$r);
        $s = new MemoryStateStore();
        $r = StoreConformance::runBudgetStore(['open' => static fn() => $s] + $this->mem());
        $this->assertTrue($r->ok(), (string)$r);
        $r = StoreConformance::runPinStore(['open' => static fn() => $s] + $this->mem());
        $this->assertTrue($r->ok(), (string)$r);
    }

    public function testAKvThatLosesAnUpdateFailsTheRaceCheck(): void
    {
        $lossy = new class () implements AtomicKv {
            private array $m = [];

            public function get(string $key): ?string
            {
                return $this->m[$key] ?? null;
            }

            public function update(string $key, callable $fn): void
            {
                $prev = $this->m[$key] ?? null;
                $this->m[$key] = $fn($prev) ?? $prev; // never keeps an increment after the second
                if (is_numeric($this->m[$key]) && (int)$this->m[$key] > 2) {
                    $this->m[$key] = '2';
                }
            }
        };
        $r = StoreConformance::runAtomicKv(['open' => static fn() => $lossy] + $this->mem());
        $this->assertSame('fail', $r->status('concurrent-updates-lose-nothing'));
    }

    public function testAKvThatIgnoresANullResultFails(): void
    {
        $bad = new class () implements AtomicKv {
            private array $m = [];

            public function get(string $key): ?string
            {
                return $this->m[$key] ?? null;
            }

            public function update(string $key, callable $fn): void
            {
                $this->m[$key] = $fn($this->m[$key] ?? null) ?? '';
            }
        };
        $r = StoreConformance::runAtomicKv(['open' => static fn() => $bad] + $this->mem());
        $this->assertSame('fail', $r->status('update-returning-null-leaves-the-value'));
    }
}
