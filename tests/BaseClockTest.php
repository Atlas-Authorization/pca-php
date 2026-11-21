<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

/** The replay clock is the corpus header's clockMs; a header without it (an older corpus) gives the fallback. */
final class BaseClockTest extends TestCase
{
    public function testHeaderClockIsRead(): void
    {
        self::assertSame(1700000000000.0, Base::clockOfHeader('{"about":"a","generator":"g.mts","count":3,"clockMs":1700000000000,"cases":[' . "\n"));
    }

    public function testMissingHeaderClockFallsBack(): void
    {
        self::assertSame(Base::FALLBACK_CLOCK_MS, Base::clockOfHeader('{"about":"a","generator":"g.mts","count":3,"cases":['));
    }
}
