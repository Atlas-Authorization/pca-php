<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\PdoStateStore;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Json.php (the duplicate-refusing parse) and src/StateStore.php (the non-SQLite rollback). */
final class CoreSurvivorKill1SmallTest extends TestCase
{
    private static function jsonError(string $text): JsonError
    {
        try {
            Json::parseNoDuplicates($text);
        } catch (JsonError $e) {
            return $e;
        }
        self::fail('expected JsonError');
    }

    /** parseNoDuplicates refuses invalid UTF-8 by name. */
    public function testInvalidUtf8(): void
    {
        self::assertSame('invalid UTF-8', self::jsonError("\"\xff\"")->getMessage());
    }

    /** 512 levels of nesting parse; 513 do not. */
    public function testDepthLimitIs512(): void
    {
        $v = Json::parseNoDuplicates(str_repeat('[', 512) . str_repeat(']', 512));
        self::assertIsArray($v);
        self::assertSame('nesting too deep at byte 512', self::jsonError(str_repeat('[', 513) . str_repeat(']', 513))->getMessage());
    }

    /** The duplicate key is named as JSON.stringify writes it: slashes and non-ASCII unescaped. */
    public function testDuplicateKeyText(): void
    {
        self::assertSame('duplicate key "a/é"', self::jsonError('{"a/é":1,"a/é":2}')->getMessage());
    }

    /** A surrogate pair escape decodes to its supplementary code point. */
    public function testSurrogatePair(): void
    {
        self::assertSame("\u{1F600}", Json::parseNoDuplicates('"😀"'));
    }

    /** On a driver other than SQLite a refused budget compare rolls the open transaction back. */
    public function testNonSqliteConflictRollsBack(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            self::markTestSkipped('pdo_sqlite not available');
        }
        $pdo = new class ('sqlite::memory:') extends \PDO {
            public function getAttribute(int $attribute): mixed
            {
                return $attribute === \PDO::ATTR_DRIVER_NAME ? 'pgsql' : parent::getAttribute($attribute);
            }
        };
        $s = new PdoStateStore($pdo);
        $s->createTable();
        $r = $s->claimWithBudget('k', 1, ['B' => 1.0, 'tau' => 1.0, 'asOf' => null], ['B' => 1.0, 'tau' => 1.0, 'asOf' => null]);
        self::assertFalse($r->ok);
        self::assertTrue($r->conflict);
        self::assertFalse($pdo->inTransaction());
    }
}
