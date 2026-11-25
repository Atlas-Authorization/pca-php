<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsDiff;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The action diff compares unit, default, resource id and bindings by value: key order is not meaning, list order is. */
final class ActionsDiffKeyOrderTest extends TestCase
{
    private static function sjv(mixed $v): string
    {
        return (new \ReflectionMethod(ActionsDiff::class, 'sjv'))->invoke(null, $v);
    }

    public function testReversedKeysCompareEqualAtEveryDepth(): void
    {
        $a = Json::parseLax('{"a":1,"b":{"x":[{"p":1,"q":2},3],"y":"s"}}');
        $b = Json::parseLax('{"b":{"y":"s","x":[{"q":2,"p":1},3]},"a":1}');
        $this->assertSame(self::sjv($a), self::sjv($b));
        $this->assertSame(self::sjv(['b' => 1, 'a' => ['d' => 1, 'c' => 2]]), self::sjv(['a' => ['c' => 2, 'd' => 1], 'b' => 1]));
    }

    public function testListOrderStillMatters(): void
    {
        $this->assertNotSame(self::sjv(Json::parseLax('{"v":[1,2]}')), self::sjv(Json::parseLax('{"v":[2,1]}')));
        $this->assertNotSame(self::sjv(Json::parseLax('{"v":1}')), self::sjv(Json::parseLax('{"v":2}')));
    }

    public function testTheComparisonUsedByTheDiffIsOrderBlind(): void
    {
        $same = new \ReflectionMethod(ActionsDiff::class, 'same');
        $o = Obj::of(['unit' => Json::parseLax('{"kind":"money","ccy":"USD"}')]);
        $n = Obj::of(['unit' => Json::parseLax('{"ccy":"USD","kind":"money"}')]);
        $this->assertTrue($same->invoke(null, $o, $n, 'unit'));
        $this->assertFalse($same->invoke(null, $o, Obj::of(['unit' => Json::parseLax('{"ccy":"EUR","kind":"money"}')]), 'unit'));
    }
}
