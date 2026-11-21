<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PdoAtomicKv;
use PHPUnit\Framework\TestCase;

/** k05 survivor kills for AtomicKv.php (PdoAtomicKv construction and the bounded compare-and-swap loop). */
final class K05KillAtomicKvTest extends TestCase
{
    public function testConstructorSetsExceptionMode(): void
    {
        $pdo = new \PDO('sqlite::memory:', null, null, [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_SILENT]);
        new PdoAtomicKv($pdo);
        $this->assertSame(\PDO::ERRMODE_EXCEPTION, $pdo->getAttribute(\PDO::ATTR_ERRMODE));
    }

    public function testBadTableName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PdoAtomicKv(new \PDO('sqlite::memory:'), 'bad-name');
    }

    public function testUpdateThatNeverSettlesGivesUpAfterSixtyFourAttempts(): void
    {
        // every INSERT changes nothing (and leaves no row), so each attempt loses
        $pdo = new class ('sqlite::memory:') extends \PDO {
            public function prepare(string $query, array $options = []): \PDOStatement|false
            {
                return str_starts_with($query, 'INSERT')
                    ? parent::prepare('UPDATE swallow SET a = a WHERE 0' . str_repeat(' AND ? IS NOT NULL', substr_count($query, '?')), $options)
                    : parent::prepare($query, $options);
            }
        };
        $pdo->exec('CREATE TABLE swallow (a INTEGER)');
        $kv = new PdoAtomicKv($pdo);
        $kv->createTable();
        $calls = 0;
        try {
            $kv->update('k', function (?string $prev) use (&$calls): string {
                if (++$calls > 100) {
                    throw new \LogicException('runaway update loop');
                }
                return 'v';
            });
            $this->fail('expected a RuntimeException');
        } catch (\RuntimeException $e) {
            $this->assertSame('PdoAtomicKv: the update did not settle (contention)', $e->getMessage());
        }
        $this->assertSame(64, $calls);
        $this->assertNull($kv->get('k'));
    }
}
