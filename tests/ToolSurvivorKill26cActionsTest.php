<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Actions::normalizeParam derives a money amount's accumulator key as the reference does (`ccy.toLowerCase()`, every Unicode letter). */
final class ToolSurvivorKill26cActionsTest extends TestCase
{
    private static function normalizeParam(Obj $p): Obj
    {
        $m = new \ReflectionMethod(Actions::class, 'normalizeParam');
        $m->setAccessible(true);
        return $m->invoke(null, $p);
    }

    /** The currency is lowercased per Unicode, not per ASCII only: 'ÉUR' accumulates under 'money.éur', 'USD' under 'money.usd'. */
    public function testAccumulatorKeyLowercasesTheCurrencyAsTheReference(): void
    {
        foreach (['USD' => 'money.usd', 'ÉUR' => 'money.éur'] as $ccy => $key) {
            $p = Obj::of(['role' => 'money.amount', 'unit' => Obj::of(['kind' => 'money', 'ccy' => $ccy])]);
            $this->assertSame([$key], self::normalizeParam($p)->get('accumulates'), $ccy);
        }
    }
}
