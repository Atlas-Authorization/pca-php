<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FrontierSignals;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the IEEE minimum / maximum behind tightenRiskInputs. */
final class RestSurvivorKill35FrontierSignalsTest extends TestCase
{
    /** [reversibility, blastRadius] of combining baseline (a) with objective (b) on both members. */
    private static function both(float $a, float $b): array
    {
        $r = FrontierSignals::tightenRiskInputs(Obj::of(['reversibility' => $a, 'blastRadius' => $a]), Obj::of(['reversibility' => $b, 'blastRadius' => $b]));
        return [$r->get('reversibility'), $r->get('blastRadius')];
    }

    private static function neg(float $z): bool
    {
        return fdiv(1, $z) < 0;
    }

    /** The minimum of two zeros is -0 when either is -0; the maximum is -0 only when both are. */
    public function testSignedZeros(): void
    {
        foreach ([[0.0, 0.0, false, false], [0.0, -0.0, true, false], [-0.0, 0.0, true, false], [-0.0, -0.0, true, true]] as [$a, $b, $minNeg, $maxNeg]) {
            [$min, $max] = self::both($a, $b);
            $this->assertSame(0.0, $min);
            $this->assertSame(0.0, $max);
            $this->assertSame([$minNeg, $maxNeg], [self::neg($min), self::neg($max)], var_export([$a, $b], true));
        }
    }

    /** Away from zero the minimum and maximum are the ordinary ones. */
    public function testOrdinaryValues(): void
    {
        $this->assertSame([0.25, 0.75], self::both(0.25, 0.75));
        $this->assertSame([0.25, 0.75], self::both(0.75, 0.25));
    }
}
