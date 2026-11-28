<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

final class ForkedCopyTest extends TestCase
{
    protected function setUp(): void
    {
        if (!function_exists('pcntl_fork') || !function_exists('posix_kill')) {
            $this->markTestSkipped('pcntl and posix are needed to fork copies');
        }
    }

    public function testACopyReturnsItsCodeToTheParent(): void
    {
        $this->assertSame([10, 11, 0], array_map(static fn(int $c): int => ForkedCopy::start(static fn(): int => $c)->wait(), [10, 11, 0]));
    }

    public function testACopyThatThrowsIsCode255(): void
    {
        $this->assertSame(255, ForkedCopy::start(static function (): int {
            throw new \RuntimeException('x');
        })->wait());
    }

    public function testACopyNeverRunsTheDestructorsOfTheParentsObjects(): void
    {
        $marks = tempnam(sys_get_temp_dir(), 'pcamark');
        $parent = getmypid();
        $held = new class ($marks, $parent) {
            public function __construct(private string $marks, private int $parent)
            {
            }

            public function __destruct()
            {
                file_put_contents($this->marks, getmypid() . "\n", FILE_APPEND | LOCK_EX);
            }
        };
        $codes = [ForkedCopy::start(static function () use ($held): int {
            $held::class; // the copy holds the parent's object, as a copy of a test holds the stores its parent opened
            return 7;
        })->wait()];
        $this->assertSame([7], $codes);
        unset($held);
        gc_collect_cycles();
        $seen = array_values(array_filter(explode("\n", (string)file_get_contents($marks))));
        @unlink($marks);
        $this->assertSame([(string)$parent], $seen, 'only the parent ran the destructor: a copy must never run the destructors of what its parent held');
    }
}
