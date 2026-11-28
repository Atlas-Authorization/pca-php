<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalFmt.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalFmt;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 36a mutation kills for src/GoalFmt.php: money rendering through the currency exponent. */
final class RestSurvivorKill36aGoalFmtTest extends TestCase
{
    private static function money(string $n): Obj
    {
        return Obj::of(['u' => Obj::of(['k' => 'money', 'ccy' => 'USD']), 'n' => $n]);
    }

    /** A money quantity renders through its currency exponent (padded when short); an unknown unit stays undefined. */
    public function testMoneyQuantityRendersThroughTheExponent(): void
    {
        self::assertSame('USD 1.23', GoalFmt::fmtQuantity(self::money('123')));
        self::assertSame('USD 0.05', GoalFmt::fmtQuantity(self::money('5')));
        self::assertTrue(AnalyzerJs::isUndef(GoalFmt::fmtQuantity(Obj::of(['u' => Obj::of(['k' => 'nope']), 'n' => '1']))));
    }

    /** Every non-money unit tag renders with its own fixed suffix or prefix. */
    public function testEveryUnitTagHasItsRendering(): void
    {
        $got = [];
        foreach (['count', 'duration', 'instant', 'bytes', 'ratio'] as $k) {
            $got[$k] = GoalFmt::fmtQuantity(Obj::of(['u' => Obj::of(['k' => $k]), 'n' => '3']));
        }
        self::assertSame(['count' => '3', 'duration' => '3ms', 'instant' => '@3', 'bytes' => '3B', 'ratio' => '3ppm'], $got);
    }
}
