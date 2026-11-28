<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\DetMath;
use Atlas\Pca\IntentDriftDetector;
use Atlas\Pca\IntentLearner;
use Atlas\Pca\Wallet;
use PHPUnit\Framework\TestCase;

/** The decisions that sit on a float boundary use the integer-arithmetic math, not libm. */
final class DetMathSitesTest extends TestCase
{
    public function testDriftDetectorThresholdAndIncrementsAreDetLn(): void
    {
        $d = new IntentDriftDetector(null);
        self::assertSame(DetMath::detLn(100.0), $d->h);
        $s = $d->update(true);
        self::assertSame(DetMath::detLn(0.25 / 0.02), $s['statistic']);
        $d2 = new IntentDriftDetector(null);
        $d2->update(false);
        $s2 = $d2->update(true);
        self::assertSame(max(0.0, 0.0 + DetMath::detLn((1 - 0.25) / (1 - 0.02))) + DetMath::detLn(0.25 / 0.02), $s2['statistic']);
    }

    public function testBinaryEntropyOfAHalfIsExactlyOneBit(): void
    {
        $m = new \ReflectionMethod(IntentLearner::class, 'binEnt');
        self::assertSame(1.0, $m->invoke(null, 0.5));
        self::assertSame(0.0, $m->invoke(null, 0.0));
        self::assertSame(0.0, $m->invoke(null, 1.0));
        $p = 0.3;
        $want = -($p * DetMath::detLog2($p) + (1 - $p) * DetMath::detLog2(1 - $p));
        self::assertSame($want, $m->invoke(null, $p));
        self::assertSame($want, $m->invoke(null, $p), 'the memoized value is the same value');
    }

    public function testNoiseUpperBoundsAreTheExactClopperPearsonInversion(): void
    {
        self::assertSame(Wallet::clopperPearsonUpper(2, 7, 0.1), Wallet::betaUpperExact(0.1, 3, 5)); // k = a - 1, n = a + b - 1
        self::assertSame(Wallet::clopperPearsonUpper(0, 1, 0.05), Wallet::betaUpperExact(0.05, 1, 1));
        foreach ([[0.0, 3], [3, 0], [1.5, 3], [3, 2.5], [NAN, 3], [-1, 3]] as [$a, $b]) {
            try {
                Wallet::betaUpperExact(0.1, $a, $b);
                self::fail("a=$a b=$b is refused");
            } catch (\RangeException $e) {
                self::assertSame('betaUpperExact: a and b must be positive integers', $e->getMessage());
            }
        }
    }
}
