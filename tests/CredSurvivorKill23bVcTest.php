<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Vc;
use PHPUnit\Framework\TestCase;

/** Vc's Number() coercion for maxAgeSec / nowSec, one assertion per match arm. */
final class CredSurvivorKill23bVcTest extends TestCase
{
    private static function jsNum(mixed $v): float
    {
        return (new \ReflectionMethod(Vc::class, 'jsNum'))->invoke(null, $v);
    }

    /** null is 0. */
    public function testNullArm(): void
    {
        $this->assertSame(0.0, self::jsNum(null));
    }

    /** true is 1 and false is 0. */
    public function testBoolArm(): void
    {
        $this->assertSame(1.0, self::jsNum(true));
        $this->assertSame(0.0, self::jsNum(false));
    }

    /** A number is its own value. */
    public function testNumberArm(): void
    {
        $this->assertSame(300.0, self::jsNum(300));
        $this->assertSame(2.5, self::jsNum(2.5));
    }

    /** A string goes through Number(). */
    public function testStringArm(): void
    {
        $this->assertSame(300.0, self::jsNum('300'));
        $this->assertNan(self::jsNum('x'));
    }

    /** Anything else is NaN rather than an unhandled match. */
    public function testDefaultArm(): void
    {
        $this->assertNan(self::jsNum([]));
        $this->assertNan(self::jsNum(new \stdClass()));
    }
}
