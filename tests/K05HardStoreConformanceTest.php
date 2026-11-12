<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\OperationRecord;
use Atlas\Pca\OperationStore;
use Atlas\Pca\StoreConformance;
use PHPUnit\Framework\TestCase;

/** H22: a copy that throws on the forked path fails the check (it used to be ignored), and a copy count of zero or less runs one copy. */
final class K05HardStoreConformanceTest extends TestCase
{
    public function testACopyCountBelowOneStillRunsOneCopy(): void
    {
        foreach ([0, -3] as $copies) {
            $rep = StoreConformance::runStateStore(['name' => 'memory', 'open' => static fn() => new MemoryStateStore(), 'copies' => $copies, 'rounds' => 1, 'shared' => false, 'durable' => false]);
            $this->assertSame('pass', $rep->status('claim-concurrent'), "copies $copies\n" . $rep);
            $rep = StoreConformance::runOperationStore(['name' => 'memory', 'open' => static fn() => new MemoryOperationStore(), 'copies' => $copies, 'shared' => false, 'durable' => false]);
            $this->assertSame('pass', $rep->status('create-once'), "copies $copies\n" . $rep);
            $this->assertSame('pass', $rep->status('transition-once'), "copies $copies\n" . $rep);
        }
    }

    public function testAForkedLoserThatThrowsFailsCreateOnce(): void
    {
        if (!function_exists('pcntl_fork') || !function_exists('pcntl_waitpid')) {
            $this->markTestSkipped('pcntl not available');
        }
        $dir = sys_get_temp_dir() . '/k05hard-' . bin2hex(random_bytes(6));
        $open = static fn(): OperationStore => new class ($dir) implements OperationStore {
            public function __construct(private readonly string $dir)
            {
            }

            /** The first copy to make the directory "creates"; every other copy throws instead of being handed the existing record. */
            public function create(OperationRecord $rec): array
            {
                if (@mkdir($this->dir . '-' . $rec->id)) {
                    return [true, null];
                }
                throw new \RuntimeException('the store failed');
            }

            public function get(string $id): ?OperationRecord
            {
                return null;
            }

            public function transition(string $id, string $from, OperationRecord $next): bool
            {
                return false;
            }
        };
        try {
            $rep = StoreConformance::runOperationStore(['name' => 'throwing', 'open' => $open, 'processes' => true, 'copies' => 3, 'shared' => true, 'durable' => false]);
            $this->assertSame('fail', $rep->status('create-once'), (string)$rep);
        } finally {
            foreach (glob($dir . '-*') ?: [] as $d) {
                @rmdir($d);
            }
        }
    }
}
