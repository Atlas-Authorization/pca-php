<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ed25519Core;
use PHPUnit\Framework\TestCase;

/** libsodium's Ed25519 group primitives over ext-ffi: a fresh load finds the library, refusals are exceptions and points are checked strictly. */
final class CryptoSurvivorKill3Ed25519CoreTest extends TestCase
{
    private static function base(): string
    {
        return "\x58" . str_repeat("\x66", 31);
    }

    /** y = 2 has no x on the curve: not a point. */
    private static function offCurve(): string
    {
        return "\x02" . str_repeat("\0", 31);
    }

    /** A fresh process-wide load (the FFI handle is cached per process) still finds libsodium and checks the base point as safe. */
    public function testFreshLoadFindsLibsodium(): void
    {
        $tried = new \ReflectionProperty(Ed25519Core::class, 'tried');
        $ffi = new \ReflectionProperty(Ed25519Core::class, 'ffi');
        $saved = [$tried->getValue(), $ffi->getValue()];
        $tried->setValue(null, false);
        $ffi->setValue(null, null);
        try {
            $this->assertTrue(Ed25519Core::available());
            $this->assertTrue(Ed25519Core::isSafePoint(self::base()));
            $this->assertNotNull($ffi->getValue());
        } finally {
            $tried->setValue(null, $saved[0]);
            $ffi->setValue(null, $saved[1]);
        }
    }

    /** A wrong-length point is never safe or valid. */
    public function testWrongLengthIsNotSafe(): void
    {
        $this->assertFalse(Ed25519Core::isSafePoint(substr(self::base(), 1)));
        $this->assertFalse(Ed25519Core::isValidPoint(substr(self::base(), 1)));
        $this->assertFalse(Ed25519Core::isSafePoint(self::base() . "\0"));
    }

    /** A 32-byte string that is not on the curve is not safe (libsodium refuses it, which is a refusal, not an acceptance). */
    public function testOffCurveIsNotSafe(): void
    {
        $this->assertFalse(Ed25519Core::isSafePoint(self::offCurve()));
        $this->assertFalse(Ed25519Core::isValidPoint(self::offCurve()));
    }

    /** libsodium's refusal (an off-curve operand, a zero scalar to invert) throws instead of returning the output buffer. */
    public function testRefusedOperationThrows(): void
    {
        try {
            Ed25519Core::add(self::offCurve(), self::base());
            $this->fail('an off-curve operand was added');
        } catch (\SodiumException $e) {
            $this->assertSame('libsodium refused the operation', $e->getMessage());
        }
        $this->expectException(\SodiumException::class);
        $this->expectExceptionMessage('libsodium refused the operation');
        Ed25519Core::scalarInvert(str_repeat("\0", 32));
    }

    /** Operands of the wrong length are refused before libsodium reads them. */
    public function testWrongLengthOperandIsRefused(): void
    {
        $this->expectException(\SodiumException::class);
        $this->expectExceptionMessage('expected 32 bytes');
        Ed25519Core::add(substr(self::base(), 1), self::base());
    }
}
