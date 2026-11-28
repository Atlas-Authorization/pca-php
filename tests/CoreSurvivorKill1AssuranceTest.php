<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Assurance;
use Atlas\Pca\AssuranceRequirement;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Assurance.php: requirement parsing and the fail-closed reasons for unknown requirement values. */
final class CoreSurvivorKill1AssuranceTest extends TestCase
{
    /** The FIRST unknown key names the refusal. */
    public function testFirstUnknownKeyWins(): void
    {
        self::assertSame('assurance: unknown requirement zzz (fail closed)', AssuranceRequirement::fromJson(['zzz' => 1, 'yyy' => 2])->invalid);
    }

    /** A threshold list must hold only known schemes; a known one is kept. */
    public function testThresholdSchemes(): void
    {
        $bad = AssuranceRequirement::fromJson(['threshold' => ['bogus']]);
        self::assertNull($bad->threshold);
        self::assertStringStartsWith('assurance: unknown threshold requirement ', (string)$bad->invalid);
        $good = AssuranceRequirement::fromJson(['threshold' => ['frost']]);
        self::assertSame(['frost'], $good->threshold);
        self::assertNull($good->invalid);
        self::assertNull(AssuranceRequirement::fromJson([])->invalid);
    }

    /** Unknown values built directly are refused with JSON that keeps slashes and non-ASCII as they are; the threshold renders as a list. */
    public function testUnknownValueReasons(): void
    {
        self::assertSame('assurance: unknown attestation requirement "x/é" (fail closed)', Assurance::unmet([], new AssuranceRequirement('x/é')));
        self::assertSame('assurance: unknown threshold requirement ["b/é"] (fail closed)', Assurance::unmet([], new AssuranceRequirement(null, null, null, [1 => 'b/é'])));
    }
}
