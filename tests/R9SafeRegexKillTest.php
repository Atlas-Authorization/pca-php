<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SafeRegex.php';

use Atlas\Pca\SafeRegex;
use PHPUnit\Framework\TestCase;

/** Round r9 mutation kills for src/SafeRegex.php. */
final class R9SafeRegexKillTest extends TestCase
{
    public function testRunAndChargeArePublic(): void
    {
        $prog = SafeRegex::compile('a+');
        self::assertNotNull($prog);
        self::assertTrue((new \ReflectionMethod(SafeRegex::class, 'run'))->isPublic());
        self::assertTrue((new \ReflectionMethod(SafeRegex::class, 'charge'))->isPublic());
        self::assertTrue(SafeRegex::run($prog, [0x61, 0x61]));
        self::assertFalse(SafeRegex::run($prog, [0x62]));
        self::assertTrue(SafeRegex::charge('a', 1)); // outside any scope: a fresh single-use budget
    }

    public function testExhaustedRequestBudgetStaysPoisoned(): void
    {
        // The request budget is REGEX_REQUEST_SCALE documents wide. One evaluation whose step cost exceeds it is refused
        // and poisons the budget, so even a trivially cheap pattern is refused afterwards.
        $b = SafeRegex::requestBudget();
        self::assertTrue($b->charge('a', 1));
        self::assertFalse($b->charge('a', SafeRegex::MAX_REGEX_STEPS_PER_DOCUMENT * SafeRegex::REGEX_REQUEST_SCALE));
        self::assertSame(1, $b->refusals);
        self::assertFalse($b->charge('a', 0));
        self::assertFalse($b->charge('b', 0));
        self::assertSame(3, $b->refusals);
    }
}
