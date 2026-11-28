<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentClopper;
use PHPUnit\Framework\TestCase;

/** Group 30 mutation kills for src/IntentClopper.php: the input refusals, the float CDF, the float guess and the certified bracket. */
final class IntentSurvivorKill30IntentClopperTest extends TestCase
{
    private const A = 4503599627370496; // 2^52

    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function refused(\Closure $f): string
    {
        try {
            $f();
        } catch (\InvalidArgumentException $e) {
            return $e->getMessage();
        }
        return 'no refusal';
    }

    /** p = 1 gives the integer 0 directly (no log-space sum). */
    public function testCdfAtPOneIsZero(): void
    {
        $this->assertSame(0, IntentClopper::binomialCdf(0, 2, 1));
        $this->assertSame(1, IntentClopper::binomialCdf(0, 2, 0), 'control');
    }

    /** A caller-supplied log-factorial table is used as given. */
    public function testCdfUsesTheGivenTable(): void
    {
        $this->assertEqualsWithDelta(0.5, IntentClopper::binomialCdf(1, 2, 0.5, [0.0, 0.0, 0.0]), 1e-12);
        $this->assertEqualsWithDelta(0.75, IntentClopper::binomialCdf(1, 2, 0.5), 1e-12, 'control: the real table');
    }

    /** The CDF is capped at exactly 1. */
    public function testCdfCappedAtOne(): void
    {
        $this->assertSame(1, IntentClopper::binomialCdf(1, 2, 0.5, [0.0, -10.0, 0.0]));
    }

    /** A float n is read as its integer part for the table (no type error, no float array key). */
    public function testCdfFloatN(): void
    {
        $this->assertEqualsWithDelta(0.25, IntentClopper::binomialCdf(0, 2.0, 0.5), 1e-12);
        $this->assertEqualsWithDelta(0.5, IntentClopper::binomialCdf(0, 0.5, 0.75), 1e-12);
    }

    /** A fractional k sums the terms up to floor(k). */
    public function testCdfFractionalKFloors(): void
    {
        $this->assertEqualsWithDelta(0.25, IntentClopper::binomialCdf(0.5, 2, 0.5), 1e-12);
    }

    /** A non-number is refused with the dyadic refusal, not a type error. */
    public function testDyadicRefusesNonNumber(): void
    {
        $this->assertSame('doubleToDyadic: need 0 < x < 1', self::refused(static fn() => IntentClopper::doubleToDyadic('x')));
    }

    /** k, n and alpha are each refused with their own reason. */
    public function testCertifiedInputRefusals(): void
    {
        $this->assertSame('clopperPearsonUpper: need integers 0 <= k <= n', self::refused(static fn() => IntentClopper::clopperPearsonCertified('x', 2, 0.05)));
        foreach ([0, 1, 2, -1, 'x'] as $alpha) {
            $this->assertSame('clopperPearsonUpper: alpha must be in (0, 1)', self::refused(static fn() => IntentClopper::clopperPearsonCertified(0, 1, $alpha)), (string)json_encode($alpha));
        }
    }

    /** The float guess keeps hi at a midpoint whose CDF equals alpha exactly (CDF > alpha moves lo, not >=). */
    public function testFloatGuessTieKeepsHi(): void
    {
        $c = IntentClopper::binomialCdf(0, 1, 0.5);
        $g = (new \ReflectionMethod(IntentClopper::class, 'floatGuess'))->invoke(null, 0, 1, $c);
        $this->assertSame(0.5, $g);
    }

    /** When alpha exceeds the CDF at k/n the guess sits far above the bound: the start is guess + tolerance and the bracket follows from it. */
    public function testCertifiedFromAHighStart(): void
    {
        $r = IntentClopper::clopperPearsonCertified(1, 3, 0.985);
        $this->assertSame(326437363426989, $r['upperUnits']);
        $this->assertSame(326437363426818, $r['lowerUnits']);
        $this->assertSame(326437363426989 / 4503599627370496.0, $r['upper']);
    }

    /** The bracket from 0 under a threshold at 1000, and with a hole at 512 (the raise doubles its step). */
    public function testBracketRaisesWithDoublingSteps(): void
    {
        $this->assertSame(['hi' => 1024, 'lo' => 768], IntentClopper::certifyBracket(0, static fn(int $a): bool => $a < 1000));
        $this->assertSame(['hi' => 1024, 'lo' => 768], IntentClopper::certifyBracket(0, static fn(int $a): bool => $a < 1000 && $a !== 512));
        $this->assertSame(['hi' => 1280, 'lo' => 1024], IntentClopper::certifyBracket(0, static fn(int $a): bool => $a < 1000 || $a === 1024));
    }

    /** After the raise the low end starts one tolerance BELOW hi. */
    public function testBracketLowEndStartsBelow(): void
    {
        $this->assertSame(['hi' => 1212, 'lo' => 956], IntentClopper::certifyBracket(700, static fn(int $a): bool => $a < 1000 || $a === 1724));
    }

    /** The raise moves up (a point that only exceeds itself is bracketed just above it). */
    public function testBracketRaiseMovesUp(): void
    {
        $this->assertSame(['hi' => 2256, 'lo' => 2000], IntentClopper::certifyBracket(2000, static fn(int $a): bool => $a === 2000));
    }

    /** The raise is clamped at 2^52. */
    public function testBracketClampedAtTheGridEnd(): void
    {
        $this->assertSame(['hi' => self::A, 'lo' => self::A - 256], IntentClopper::certifyBracket(self::A - 10, static fn(int $a): bool => $a < self::A));
    }

    /** The low end is clamped at 0, and a bracket reaching 0 where 0 exceeds is returned, not refused. */
    public function testBracketClampedAtZero(): void
    {
        $this->assertSame(['hi' => 100, 'lo' => 0], IntentClopper::certifyBracket(100, static fn(int $a): bool => $a < 50));
    }

    /** A predicate false at 0 is refused as unreachable (whatever it says at -1 or 1). */
    public function testBracketUnreachableRefused(): void
    {
        $this->assertSame('clopperPearsonUpper: unreachable (cdfRec(0) = 1)', self::refused(static fn() => IntentClopper::certifyBracket(1000, static fn(int $a): bool => $a === -1 || $a === 1)));
        $this->assertSame('clopperPearsonUpper: unreachable (cdfRec(0) = 1)', self::refused(static fn() => IntentClopper::certifyBracket(1000, static fn(int $a): bool => $a < 0)));
    }
}
