<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ed25519Core;
use Atlas\Pca\MpcEc;
use Atlas\Pca\MpcPointError;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcEc: the reference's text-slicing rule of le() for a negative length, the curve and subgroup refusals of the
 * group law, and every early `false` of schnorrVerify. Group-law tests need the Ed25519 core of ext-sodium (or libsodium over ext-ffi).
 */
final class MpcSurvivorKill34MpcEcTest extends TestCase
{
    private function needCore(): void
    {
        if (!Ed25519Core::available()) {
            $this->markTestSkipped('needs ext-sodium with the Ed25519 core functions (libsodium >= 1.0.18)');
        }
    }

    private static function refuses(string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame(MpcPointError::class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected MpcPointError: $msg");
    }

    /** The order-2 point (0, -1): on the curve, not the identity, outside the prime-order subgroup. */
    private static function order2(): array
    {
        return ['X' => gmp_init(0), 'Y' => gmp_sub(MpcEc::q(), 1), 'Z' => gmp_init(1), 'T' => gmp_init(0)];
    }

    /** A negative length cuts exactly -2*len hex digits off the front, then whole pairs are read little-endian; zero keeps the whole text. */
    public function testLeNegativeLengthCutsTheFrontOfTheHexText(): void
    {
        $v = gmp_init('123456', 16);
        $this->assertSame("\x56\x34", MpcEc::le($v, -1));
        $this->assertSame("\x56", MpcEc::le($v, -2));
        $this->assertSame("\x56\x34\x12", MpcEc::le($v, 0));
        $this->assertSame("\x34\x12", MpcEc::le(gmp_init('12345', 16), 0));
    }

    /** A coordinate pair off the curve (y = 2 has no x) is refused by the group law with the curve message. */
    public function testAddOfAPointOffTheCurveIsRefused(): void
    {
        $this->needCore();
        $off = MpcEc::fromAffine(gmp_init(0), gmp_init(2));
        $this->assertFalse(MpcEc::isOnCurve($off));
        self::refuses('point is not on the curve', static fn() => MpcEc::addPoints($off, MpcEc::base()));
        self::refuses('point is not on the curve', static fn() => MpcEc::sub(MpcEc::base(), $off));
    }

    /** Scalar multiplication of a small-order point is refused (libsodium rejects torsion), never computed. */
    public function testMulOfASmallOrderPointIsRefused(): void
    {
        $this->needCore();
        self::refuses('scalar multiplication refused: point not in the prime-order subgroup', static fn() => MpcEc::mul(gmp_init(3), self::order2()));
    }

    /** A point with Z = 0 is refused as not on the curve, naming the caller's label. */
    public function testAssertInSubgroupNamesTheLabelOffCurve(): void
    {
        self::refuses('peer S: not on curve', static fn() => MpcEc::assertInSubgroup(['X' => gmp_init(0), 'Y' => gmp_init(1), 'Z' => gmp_init(0), 'T' => gmp_init(0)], 'peer S'));
    }

    /** schnorrVerify is false for an empty context, a z outside [0, L) and a statement point the group law refuses; a real proof verifies. */
    public function testSchnorrVerifyEarlyRefusals(): void
    {
        $this->needCore();
        $y = gmp_init(11);
        $S = MpcEc::mulBase($y);
        $proof = MpcEc::schnorrProve($y, $S, static fn(): \GMP => gmp_init(5), 'mpc34');
        $this->assertTrue(MpcEc::schnorrVerify($S, $proof, 'mpc34'));
        $this->assertFalse(MpcEc::schnorrVerify($S, $proof, ''));
        $this->assertFalse(MpcEc::schnorrVerify($S, ['U' => $proof['U'], 'z' => MpcEc::l()], 'mpc34'));
        $this->assertFalse(MpcEc::schnorrVerify($S, ['U' => $proof['U'], 'z' => gmp_init(-1)], 'mpc34'));
        $this->assertFalse(MpcEc::schnorrVerify(self::order2(), ['U' => MpcEc::mulBase(gmp_init(5)), 'z' => gmp_init(7)], 'mpc34'));
    }
}
