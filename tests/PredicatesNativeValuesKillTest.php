<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/** Context values built in PHP (native int / float) are numbers like parsed Num lexemes. */
final class PredicatesNativeValuesKillTest extends TestCase
{
    private static function ctx(mixed $n): Obj
    {
        return Obj::of(['action' => Obj::of(['verb' => 'v', 'resource' => 'r', 'params' => Obj::of(['n' => $n])])]);
    }

    private static function cond(string $op, mixed $value): Obj
    {
        return Obj::of(['field' => 'action.params.n', 'op' => $op, 'value' => $value]);
    }

    public function testNativeIntAndFloatCompareNumerically(): void
    {
        $this->assertSame('true', Predicates::evaluateConditionTri(self::cond('gt', 3), self::ctx(5)));
        $this->assertSame('false', Predicates::evaluateConditionTri(self::cond('gt', 7), self::ctx(5)));
        $this->assertSame('true', Predicates::evaluateConditionTri(self::cond('lt', 6.5), self::ctx(5.25)));
        $this->assertSame('false', Predicates::evaluateConditionTri(self::cond('lt', 5.0), self::ctx(5.25)));
        $this->assertSame('true', Predicates::evaluateConditionTri(self::cond('eq', 5), self::ctx(5.0)));
        $this->assertSame('false', Predicates::evaluateConditionTri(self::cond('eq', 5), self::ctx(6)));
    }
}
