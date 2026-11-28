<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FileRevocationStore;
use Atlas\Pca\InMemoryRevocationStore;
use Atlas\Pca\Revoke;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Revoke.php: the file store's write failures, entry validation and the conformance runner's report. */
final class CoreSurvivorKill1RevokeTest extends TestCase
{
    private string $dir = '';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-g1-rev-' . bin2hex(random_bytes(6));
        self::assertTrue(mkdir($this->dir));
    }

    protected function tearDown(): void
    {
        $rm = static function (string $p) use (&$rm): void {
            if (is_dir($p) && !is_link($p)) {
                foreach (scandir($p) ?: [] as $f) {
                    if ($f !== '.' && $f !== '..') {
                        $rm($p . DIRECTORY_SEPARATOR . $f);
                    }
                }
                @rmdir($p);
            } elseif (file_exists($p) || is_link($p)) {
                @unlink($p);
            }
        };
        $rm($this->dir);
    }

    private static function entry(): array
    {
        return ['kind' => 'cap', 'value' => 'c1', 'reason' => 'r', 'revokedAt' => 1000];
    }

    private function path(): string
    {
        return $this->dir . DIRECTORY_SEPARATOR . 'rev.json';
    }

    /** The temporary file cannot be opened: the add throws and memory does not claim the entry. */
    public function testUnwritableTempFileThrowsAndRollsBack(): void
    {
        $s = new FileRevocationStore($this->path());
        self::assertTrue(mkdir($this->path() . '.tmp'));
        try {
            $s->add(self::entry());
            self::fail('expected RuntimeException');
        } catch (\RuntimeException $e) {
            self::assertSame('FileRevocationStore: cannot write the revocation file', $e->getMessage());
        }
        self::assertNull($s->get('cap', 'c1'));
    }

    /** The real file cannot be replaced (a non-empty directory holds its name): the add throws and memory does not claim the entry. */
    public function testUnreplaceableFileThrowsAndRollsBack(): void
    {
        $s = new FileRevocationStore($this->path());
        self::assertTrue(mkdir($this->path()));
        self::assertNotFalse(file_put_contents($this->path() . DIRECTORY_SEPARATOR . 'keep', 'x'));
        try {
            $s->add(self::entry());
            self::fail('expected RuntimeException');
        } catch (\RuntimeException $e) {
            self::assertSame('FileRevocationStore: cannot replace the revocation file', $e->getMessage());
        }
        self::assertNull($s->get('cap', 'c1'));
    }

    /** A non-finite notBefore, and a prefix entry without a matching prefix list, are not valid entries. */
    public function testValidEntryRefusals(): void
    {
        self::assertTrue(Revoke::validEntry(self::entry()));
        self::assertFalse(Revoke::validEntry(self::entry() + ['notBefore' => 'x']));
        self::assertFalse(Revoke::validEntry(['kind' => 'prefix', 'value' => 'a', 'reason' => 'r', 'revokedAt' => 1000]));
    }

    /** The conformance runner runs every case and reports a failure as "name: class: a !== b". */
    public function testConformanceFailureReport(): void
    {
        $fail = Revoke::runRevocationStoreConformance(static fn() => new class extends InMemoryRevocationStore {
            public function all(): array
            {
                return ['junk'];
            }
        });
        self::assertNotSame([], $fail);
        self::assertSame('starts empty: UnexpectedValueException: ' . var_export(['junk'], true) . ' !== ' . var_export([], true), $fail[0]);
        self::assertSame([], Revoke::runRevocationStoreConformance(static fn() => new InMemoryRevocationStore()));
    }
}
