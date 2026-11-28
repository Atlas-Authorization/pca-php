<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of the analyzer's JavaScript helpers: has / isObj, includes with NaN, reqList, JSON.stringify, uobj, toFixed. */
final class MathSurvivorKill31AnalyzerJsTest extends TestCase
{
    /** has is an own member of an Obj; anything else has no members (and never throws). */
    public function testHasAndIsObj(): void
    {
        $o = Obj::of(['a' => 1]);
        self::assertSame([true, false, false], [AnalyzerJs::has($o, 'a'), AnalyzerJs::has($o, 'b'), AnalyzerJs::has('x', 'a')]);
        self::assertSame([true, false], [AnalyzerJs::isObj($o), AnalyzerJs::isObj(['a' => 1])]);
    }

    /** jsnum of a non-number is 0 (it never throws). */
    public function testJsnumOfNonNumber(): void
    {
        self::assertSame([0.0, 0.0, 2.5], [AnalyzerJs::jsnum('x'), AnalyzerJs::jsnum(null), AnalyzerJs::jsnum(2.5)]);
    }

    /** includes is SameValueZero: NaN finds NaN, but NaN never finds a number nor a number NaN. */
    public function testIncludesNaN(): void
    {
        self::assertTrue(AnalyzerJs::includes([NAN], NAN));
        self::assertFalse(AnalyzerJs::includes([5], NAN));
        self::assertFalse(AnalyzerJs::includes([NAN], 5));
        self::assertTrue(AnalyzerJs::includes([1, 5], 5), 'control');
    }

    /** reqList refuses a non-array and an associative array with its TypeError. */
    public function testReqListRefuses(): void
    {
        foreach (['x', ['a' => 1]] as $bad) {
            try {
                AnalyzerJs::reqList($bad);
                self::fail('accepted');
            } catch (\TypeError $e) {
                self::assertSame('not an array', $e->getMessage());
            }
        }
    }

    /** JSON.stringify: undefined is null alone and in an array, an undefined member is dropped. */
    public function testJsJsonUndefined(): void
    {
        $u = AnalyzerJs::undef();
        self::assertSame('null', AnalyzerJs::jsJson($u));
        self::assertSame('[1,null]', AnalyzerJs::jsJson([1, $u]));
        self::assertSame('{"a":1}', AnalyzerJs::jsJson(Obj::of(['a' => 1, 'b' => $u])));
    }

    /** An object literal with a numeric key has the string key. */
    public function testUobjNumericKey(): void
    {
        self::assertSame(['0'], AnalyzerJs::uobj([0 => 'a'])->keys());
    }

    /** toFixed: two digits by default, a carry out of the top digit, the sign in front, the infinities by sign. */
    public function testToFixed(): void
    {
        self::assertSame('1.25', AnalyzerJs::toFixed(1.25));
        self::assertSame('10.00', AnalyzerJs::toFixed(9.999));
        self::assertSame('-1.50', AnalyzerJs::toFixed(-1.5));
        self::assertSame(['Infinity', '-Infinity'], [AnalyzerJs::toFixed(INF), AnalyzerJs::toFixed(-INF)]);
    }
}
