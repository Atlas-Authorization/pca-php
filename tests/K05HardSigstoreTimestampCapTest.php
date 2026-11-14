<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\SigstoreBundle;
use PHPUnit\Framework\TestCase;

/** H6: a bundle carries at most 8 RFC 3161 timestamps (each one is a full CMS + chain + signature check). */
final class K05HardSigstoreTimestampCapTest extends TestCase
{
    private static function viaFixtures(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(K05KillSigstoreBundleTest::class, $name))->invoke(null, ...$args);
    }

    private static function withTimestamps(int $n): array
    {
        $b = self::viaFixtures('fx', 'verifySigstoreBundleCore/dsse/valid');
        $tvd = $b->get('verificationMaterial')->get('timestampVerificationData');
        $one = $tvd->get('rfc3161Timestamps')[0];
        $tvd->set('rfc3161Timestamps', array_fill(0, $n, $one));
        return SigstoreBundle::verifyCore($b, self::viaFixtures('roots'));
    }

    public function testTheCapIsEight(): void
    {
        $this->assertSame(8, SigstoreBundle::MAX_TIMESTAMPS);
    }

    public function testEightTimestampsVerify(): void
    {
        $r = self::withTimestamps(8);
        $this->assertTrue($r['ok'], json_encode($r));
        $this->assertSame(8, $r['core']['timestamps']['tsa']);
    }

    public function testNineTimestampsAreRefusedAtTheTsaStage(): void
    {
        $this->assertSame(['ok' => false, 'code' => 'tsa', 'detail' => 'too many RFC 3161 timestamps (9, at most 8)'], self::withTimestamps(9));
        $this->assertSame(['ok' => false, 'code' => 'tsa', 'detail' => 'too many RFC 3161 timestamps (30, at most 8)'], self::withTimestamps(30));
    }

    public function testOneTimestampStillVerifies(): void
    {
        $this->assertTrue(self::withTimestamps(1)['ok']);
    }
}
