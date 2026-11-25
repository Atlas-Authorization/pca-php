<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMapKit;
use Atlas\Pca\Num;
use PHPUnit\Framework\TestCase;

/**
 * A closeness test on a value an untrusted party supplies is written as the negation of the positive condition: NaN, a missing value
 * and a value of the wrong type are all NOT close (a comparison against NaN is false both ways, so "abs(a - b) > tol" would pass them).
 */
final class FailClosedComparisonTest extends TestCase
{
    private static function within2(mixed $a, mixed $b): bool
    {
        $m = new \ReflectionMethod(IntentMapKit::class, 'within2');
        return $m->invoke(null, $a, $b);
    }

    public function testIntentMapClosenessCountsAMissingOrNonNumericClaimAsAMismatch(): void
    {
        self::assertTrue(self::within2(10, 10));
        self::assertTrue(self::within2(10, 12));
        self::assertTrue(self::within2(new Num('10'), new Num('8')));
        self::assertFalse(self::within2(10, 13));
        foreach ([null, 'x', '5', NAN, INF, true, [], new \stdClass()] as $bad) {
            self::assertFalse(self::within2(10, $bad), 'claim ' . var_export($bad, true));
            self::assertFalse(self::within2($bad, 10), 'replayed ' . var_export($bad, true));
        }
        self::assertFalse(self::within2(NAN, NAN));
    }
}
