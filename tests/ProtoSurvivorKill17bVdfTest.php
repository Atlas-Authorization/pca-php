<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Vdf;
use PHPUnit\Framework\TestCase;

/** Mutation kills for calibrateSteps' timed sample: exactly sampleSquarings squarings of 2, observed through the sample seam. */
final class ProtoSurvivorKill17bVdfTest extends TestCase
{
    protected function tearDown(): void
    {
        Vdf::$sampleHook = null;
    }

    /** Four samples are the squarings 4, 16, 256, 65536 at indices 0..3; one more call stops the run at once. */
    public function testTimedSampleIsExactlyTheRequestedSquarings(): void
    {
        $seen = [];
        Vdf::$sampleHook = static function (int $i, \GMP $y) use (&$seen): void {
            $seen[] = [$i, gmp_strval($y)];
            if (count($seen) > 4) {
                throw new \LogicException('more squarings than requested');
            }
        };
        $ticks = [0.0, 1000.0];
        $c = 0;
        $clock = static function () use (&$c, $ticks): float {
            return $ticks[$c++];
        };
        $r = Vdf::calibrateSteps(gmp_init(1000003), 1.0, 4, 1.0, $clock);
        $this->assertSame([[0, '4'], [1, '16'], [2, '256'], [3, '65536']], $seen);
        $this->assertSame(['steps' => 4, 'measuredSquaringsPerSecond' => 4.0, 'assumedAdversarySquaringsPerSecond' => 4.0], $r);
        $this->assertSame(2, $c);
    }
}
