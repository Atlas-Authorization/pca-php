<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ClaimResult;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\PdoStateStore;
use PHPUnit\Framework\TestCase;

/** The PDO budget side (compare, claim and store in one transaction), budget decoding and the pin prefix. */
final class StateStoreSurvivorKillTest extends TestCase
{
    private static function store(?\PDO $pdo = null): PdoStateStore
    {
        $s = new PdoStateStore($pdo ?? new \PDO('sqlite::memory:'));
        $s->createTable();
        return $s;
    }

    public function testSameBudgetComparesFieldsNotArrayIdentity(): void
    {
        $a = ['B' => 1.0, 'tau' => 2.0, 'asOf' => null];
        $this->assertTrue(MemoryStateStore::sameBudget(null, null));
        $this->assertTrue(MemoryStateStore::sameBudget($a, $a));
        // a missing asOf equals a null one, and the key order does not matter
        $this->assertTrue(MemoryStateStore::sameBudget($a, ['B' => 1.0, 'tau' => 2.0]));
        $this->assertTrue(MemoryStateStore::sameBudget(['tau' => 2.0, 'B' => 1.0], $a));
        $this->assertFalse(MemoryStateStore::sameBudget($a, null));
        $this->assertFalse(MemoryStateStore::sameBudget(null, $a));
        $this->assertFalse(MemoryStateStore::sameBudget($a, ['B' => 1.5, 'tau' => 2.0]));
        $this->assertFalse(MemoryStateStore::sameBudget($a, ['B' => 1.0, 'tau' => 2.5]));
        $this->assertFalse(MemoryStateStore::sameBudget($a, ['B' => 1.0, 'tau' => 2.0, 'asOf' => 3.0]));
    }

    public function testABudgetRoundTripsAndAnAbsentAfterKeepsTheStoredOne(): void
    {
        $s = self::store();
        $this->assertNull($s->budget('k'));
        $b1 = ['B' => 2.5, 'tau' => 3.0, 'asOf' => 4.0];
        $r = $s->claimWithBudget('k', 1, null, $b1);
        $this->assertTrue($r->ok);
        $this->assertSame($b1, $s->budget('k'));
        $r = $s->claimWithBudget('k', 2, $b1, null);
        $this->assertTrue($r->ok);
        $this->assertSame(2, $s->last('k'));
        $this->assertSame($b1, $s->budget('k'), 'a null after stores nothing');
        $b2 = ['B' => 1.0, 'tau' => 3.0, 'asOf' => null];
        $this->assertTrue($s->claimWithBudget('k', 3, $b1, $b2)->ok);
        $this->assertSame($b2, $s->budget('k'));
    }

    public function testAStaleBudgetIsAConflictAndLeavesNothingBehind(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $s = self::store($pdo);
        $b1 = ['B' => 2.5, 'tau' => 3.0, 'asOf' => null];
        $s->claimWithBudget('k', 1, null, $b1);
        $r = $s->claimWithBudget('k', 2, ['B' => 9.0, 'tau' => 3.0, 'asOf' => null], ['B' => 1.0, 'tau' => 3.0, 'asOf' => null]);
        $this->assertFalse($r->ok);
        $this->assertNull($r->lastCounter);
        $this->assertTrue($r->conflict);
        $this->assertFalse($pdo->inTransaction());
        $this->assertSame(1, $s->last('k'));
        $this->assertSame($b1, $s->budget('k'));
    }

    public function testAReplayedCounterRollsBackAndReportsTheStoredOne(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $s = self::store($pdo);
        $b1 = ['B' => 2.5, 'tau' => 3.0, 'asOf' => null];
        $s->claimWithBudget('k', 5, null, $b1);
        $r = $s->claimWithBudget('k', 5, $b1, ['B' => 1.0, 'tau' => 3.0, 'asOf' => null]);
        $this->assertFalse($r->ok);
        $this->assertSame(5, $r->lastCounter);
        $this->assertFalse($r->conflict);
        $this->assertFalse($pdo->inTransaction());
        $this->assertSame($b1, $s->budget('k'));
    }

    public function testAFailureInsideTheTransactionRollsEverythingBackAndRethrows(): void
    {
        $pdo = new class ('sqlite::memory:') extends \PDO {
            public bool $failBudgetWrite = false;

            public function prepare(string $query, array $options = []): \PDOStatement|false
            {
                if ($this->failBudgetWrite && str_contains($query, '_budget (key, b)')) {
                    throw new \RuntimeException('budget write failed');
                }
                return parent::prepare($query, $options);
            }
        };
        $s = self::store($pdo);
        $pdo->failBudgetWrite = true;
        try {
            $s->claimWithBudget('k', 1, null, ['B' => 1.0, 'tau' => 2.0, 'asOf' => null]);
            $this->fail('the failure must propagate');
        } catch (\RuntimeException $e) {
            $this->assertSame('budget write failed', $e->getMessage());
        }
        $this->assertFalse($pdo->inTransaction());
        $this->assertNull($s->last('k'), 'the counter claimed in the transaction was rolled back');
        $pdo->failBudgetWrite = false;
        $this->assertTrue($s->claimWithBudget('k', 1, null, ['B' => 1.0, 'tau' => 2.0, 'asOf' => null])->ok);
    }

    public function testDecodeBudgetReadsOnlyACompleteObject(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $s = self::store($pdo);
        $put = static function (string $key, string $json) use ($pdo): void {
            $pdo->prepare('INSERT INTO pca_replay_budget (key, b) VALUES (?, ?)')->execute([$key, $json]);
        };
        $put('ints', '{"B":2,"tau":3}');
        $put('asof', '{"B":2,"tau":3,"asOf":4}');
        $put('nullasof', '{"B":2,"tau":3,"asOf":null}');
        $this->assertSame(['B' => 2.0, 'tau' => 3.0, 'asOf' => null], $s->budget('ints'));
        $this->assertSame(['B' => 2.0, 'tau' => 3.0, 'asOf' => 4.0], $s->budget('asof'));
        $this->assertSame(['B' => 2.0, 'tau' => 3.0, 'asOf' => null], $s->budget('nullasof'));
        foreach (['noB' => '{"tau":3}', 'noTau' => '{"B":2}', 'nullB' => '{"B":null,"tau":3}', 'nullTau' => '{"B":2,"tau":null}',
            'scalar' => '5', 'str' => '"x"', 'list' => '[2,3]', 'junk' => 'not json'] as $k => $json) {
            $put($k, $json);
            $this->assertNull($s->budget($k), $k);
        }
    }

    public function testAPinIsACounterStreamUnderItsOwnPrefix(): void
    {
        $s = self::store();
        $this->assertNull($s->pin('k'));
        $s->raisePin('k', 5);
        $this->assertSame(5, $s->pin('k'));
        $this->assertNull($s->last('k'), 'the pin does not live under the raw key');
        $this->assertSame(5, $s->last('pca-pin:k'));
        $s->raisePin('k', 3);
        $this->assertSame(5, $s->pin('k'), 'a pin never lowers');
        $s->raisePin('k', 9);
        $this->assertSame(9, $s->pin('k'));
        $s->claim('k', 2);
        $this->assertSame(9, $s->pin('k'));
        $this->assertSame(2, $s->last('k'));
    }
}
