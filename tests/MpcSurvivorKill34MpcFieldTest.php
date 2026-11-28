<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcField;
use Atlas\Pca\MpcFieldRng;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcField::fieldRandom: the CSPRNG by default, the reproducible stream only behind an explicit test seed. */
final class MpcSurvivorKill34MpcFieldTest extends TestCase
{
    private static function isSecure(MpcFieldRng $r): bool
    {
        return (new \ReflectionProperty(MpcFieldRng::class, 'secure'))->getValue($r);
    }

    /** No seed gives the CSPRNG; a seed gives the deterministic SplitMix64 stream of exactly that seed. */
    public function testDefaultIsSecureAndASeedIsReproducible(): void
    {
        $this->assertTrue(self::isSecure(MpcField::fieldRandom()));
        $seeded = MpcField::fieldRandom(gmp_init(34));
        $this->assertFalse(self::isSecure($seeded));
        $ref = new MpcFieldRng(gmp_init(34));
        $this->assertSame(gmp_strval($ref->next()), gmp_strval($seeded->next()));
        $this->assertSame(gmp_strval($ref->next()), gmp_strval($seeded->next()));
    }
}
