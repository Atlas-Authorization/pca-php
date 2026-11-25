<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

/** The replay clock is the corpus header's clockMs; a header without it gives the contract's default; the clockCases header lists the clock-dependent cases. */
final class BaseClockTest extends TestCase
{
    public function testHeaderClockIsRead(): void
    {
        self::assertSame(1700000000000.0, Base::clockOfHeader('{"about":"a","generator":"g.mts","count":3,"clockMs":1700000000000,"cases":[' . "\n"));
    }

    public function testMissingHeaderClockIsTheDefault(): void
    {
        self::assertSame(Base::DEFAULT_CLOCK_MS, Base::clockOfHeader('{"about":"a","generator":"g.mts","count":3,"cases":['));
    }

    public function testClockCasesAreRead(): void
    {
        self::assertSame(['a/x' => true, 'b' => true], Base::clockCasesOfHeader('{"about":"a","clockMs":5,"clockCases":["a/x","b"],"cases":[' . "\n"));
        self::assertSame([], Base::clockCasesOfHeader('{"about":"a","cases":['));
    }
}
