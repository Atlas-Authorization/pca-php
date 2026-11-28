<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AnalyzerCoverage;
use Atlas\Pca\AnalyzerExposure;
use Atlas\Pca\ObjectiveRisk;
use Atlas\Pca\Payments;
use PHPUnit\Framework\TestCase;

/** Every Math.max / Math.min copy orders 0 and -0 as JavaScript does (max is +0, min is -0, in either argument order) and keeps NaN. */
final class JsMaxMinZeroOrderTest extends TestCase
{
    /** @return list<array{class-string, bool}> class, whether its helpers are private */
    public static function owners(): array
    {
        return [[AnalyzerCoverage::class, true], [AnalyzerExposure::class, true], [ObjectiveRisk::class, true], [Payments::class, false]];
    }

    private static function call(string $class, string $fn, float ...$xs): float
    {
        $m = new \ReflectionMethod($class, $fn);
        return $m->invoke(null, ...$xs);
    }

    private static function sign(float $z): int
    {
        return fdiv(1, $z) < 0 ? -1 : 1;
    }

    /** max(0, -0) and max(-0, 0) are +0; min(0, -0) and min(-0, 0) are -0; a NaN argument gives NaN; other values are unchanged. */
    #[\PHPUnit\Framework\Attributes\DataProvider('owners')]
    public function testZeroOrderAndNan(string $class, bool $private): void
    {
        self::assertSame($private, (new \ReflectionMethod($class, 'jsMax'))->isPrivate());
        foreach ([[0.0, -0.0], [-0.0, 0.0]] as [$a, $b]) {
            self::assertSame(1, self::sign(self::call($class, 'jsMax', $a, $b)), "$class max");
            self::assertSame(-1, self::sign(self::call($class, 'jsMin', $a, $b)), "$class min");
        }
        self::assertSame(-1, self::sign(self::call($class, 'jsMax', -0.0, -0.0)));
        self::assertSame(1, self::sign(self::call($class, 'jsMin', 0.0, 0.0)));
        self::assertNan(self::call($class, 'jsMax', 1.0, NAN));
        self::assertNan(self::call($class, 'jsMin', NAN, 1.0));
        self::assertSame(2.5, self::call($class, 'jsMax', -1.0, 2.5));
        self::assertSame(-1.0, self::call($class, 'jsMin', -1.0, 2.5));
    }

    /** The variadic analyzer copies: no arguments give -Infinity / +Infinity, a lone -0 is kept, and NaN anywhere wins. */
    public function testVariadicAnalyzerCopies(): void
    {
        foreach ([AnalyzerCoverage::class, AnalyzerExposure::class] as $class) {
            self::assertSame(-INF, self::call($class, 'jsMax'));
            self::assertSame(INF, self::call($class, 'jsMin'));
            self::assertSame(-1, self::sign(self::call($class, 'jsMax', -0.0)));
            self::assertSame(1, self::sign(self::call($class, 'jsMin', 0.0)));
            self::assertSame(1, self::sign(self::call($class, 'jsMax', -0.0, -5.0, 0.0, -0.0)));
            self::assertSame(-1, self::sign(self::call($class, 'jsMin', 0.0, 5.0, -0.0, 0.0)));
            self::assertNan(self::call($class, 'jsMax', 1.0, NAN, 3.0));
        }
    }
}
