<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\PdoStateStore;
use PHPUnit\Framework\TestCase;

/** k05 survivor kills for StateStore.php (memory consume-once retention and pruning, the PDO store). */
final class K05KillStateStoreTest extends TestCase
{
    private const MAX = 9007199254740991;

    public function testMemoryConsumeOnceRetentionFloor(): void
    {
        $s = new MemoryStateStore();
        // a first record is retained until max(retainUntil, 0)
        $this->assertTrue($s->consumeOnce('neg', -5, -10));
        $this->assertFalse($s->consumeOnce('neg', 0, 0));
        $this->assertTrue($s->consumeOnce('zero', 0, 0));
        $this->assertTrue($s->consumeOnce('zero', 1, 1));
    }

    public function testMemoryConsumeOncePrunesOnlyAboveTenThousandAndOnlyElapsedRecords(): void
    {
        $s = new MemoryStateStore();
        $this->assertTrue($s->consumeOnce('a', 100, 100));
        $this->assertTrue($s->consumeOnce('k0', 200, 200));
        // 'a' (retained until 100) is still remembered: no pruning at two records
        $this->assertFalse($s->consumeOnce('a', 100, 50));
        for ($i = 1; $i < 9999; $i++) {
            $s->consumeOnce("k$i", 200, 200);
        }
        // exactly 10000 records: still no pruning
        $this->assertFalse($s->consumeOnce('a', 100, 50));
        // the 10001st prunes at now = 200: 'a' (100) goes, records retained until exactly 200 stay
        $this->assertTrue($s->consumeOnce('z', 200, 200));
        $this->assertTrue($s->consumeOnce('a', 100, 50));
        $this->assertFalse($s->consumeOnce('k0', 200, 200));
    }

    private static function pdoStore(?\PDO $pdo = null): PdoStateStore
    {
        $s = new PdoStateStore($pdo ?? new \PDO('sqlite::memory:'));
        $s->createTable();
        return $s;
    }

    public function testPdoConstructorAndTable(): void
    {
        $pdo = new \PDO('sqlite::memory:', null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_SILENT]);
        self::pdoStore($pdo);
        $this->assertSame(\PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(\PDO::ATTR_ERRMODE));
        $names = $pdo->query("SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'pca_replay_once'")->fetchAll(\PDO::FETCH_COLUMN);
        $this->assertContains('pca_replay_once_until', $names);
    }

    public function testPdoRejectsABadTableName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoStateStore(new \PDO('sqlite::memory:'), 'bad-name');
    }

    public function testPdoClaimRangeAndLast(): void
    {
        $s = self::pdoStore();
        $this->assertTrue($s->claim('max', self::MAX)->ok);
        $r = $s->claim('neg', -1);
        $this->assertSame([false, null], [$r->ok, $r->lastCounter]);
        $this->assertFalse($s->claim('big', self::MAX + 1)->ok);
        $this->assertNull($s->last('neg'));
        $this->assertTrue($s->claim('k', 5)->ok);
        $this->assertSame(5, $s->last('k'));
        $this->assertNull($s->last('missing'));
        $r = $s->claim('k', 3);
        $this->assertSame([false, 5], [$r->ok, $r->lastCounter]);
    }

    public function testPdoStringifiedFetchesAreIntegers(): void
    {
        $pdo = new \PDO('sqlite::memory:');
        $pdo->setAttribute(\PDO::ATTR_STRINGIFY_FETCHES, true);
        $s = self::pdoStore($pdo);
        $s->claim('k', 5);
        $this->assertSame(5, $s->last('k'));
        $this->assertSame(5, $s->claim('k', 3)->lastCounter);
    }

    public function testPdoClaimWhoseInsertChangedNothingAndNoRowExists(): void
    {
        $pdo = new class ('sqlite::memory:') extends \PDO {
            public function prepare(string $query, array $options = []): \PDOStatement|false
            {
                return str_starts_with($query, 'INSERT')
                    ? parent::prepare('UPDATE swallow SET a = a WHERE 0' . str_repeat(' AND ? IS NOT NULL', substr_count($query, '?')), $options)
                    : parent::prepare($query, $options);
            }
        };
        $pdo->exec('CREATE TABLE swallow (a INTEGER)');
        $r = self::pdoStore($pdo)->claim('k', 5);
        $this->assertSame([false, null], [$r->ok, $r->lastCounter]);
    }

    public function testPdoConsumeOnceBoundsAndPruning(): void
    {
        $s = self::pdoStore();
        $this->assertTrue($s->consumeOnce('max', self::MAX, 0));
        $this->assertTrue($s->consumeOnce('zero-now', 10, 0));
        $this->assertTrue($s->consumeOnce('a', 100, 100));
        // pruned at now = 200 ...
        $this->assertTrue($s->consumeOnce('b', 300, 200));
        // ... so 'a' is new again even for an earlier now
        $this->assertTrue($s->consumeOnce('a', 60, 50));
    }
}
