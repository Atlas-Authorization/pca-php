<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PlanRegistry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A NaN or infinite clock is never read as epoch 0 (which is before every approval expiry): a plan whose approval has an expiry is not executable. */
final class NonFiniteClockSiteTest extends TestCase
{
    /** @return list<array{float}> */
    public static function nonFinite(): array
    {
        return [[NAN], [INF], [-INF]];
    }

    #[DataProvider('nonFinite')]
    public function testAPlanWithAnApprovalExpiryIsNotExecutableOnANonFiniteClock(float $bad): void
    {
        $t = 1000.0;
        $reg = new PlanRegistry(null, 'pca-plan:', static function () use (&$t) {
            return $t;
        });
        $d = $reg->draft('g', [['id' => 'n1', 'verb' => 'orders.read', 'resource' => '/orders/1']]);
        $this->assertTrue($d['ok']);
        $root = $d['record']->get('root');
        $this->assertTrue($reg->validate('g', $root)['ok']);
        $this->assertTrue($reg->commit('g', $root)['ok']);
        $this->assertTrue($reg->authorize('g', $root, ['by' => 'p', 'expiresAt' => 5000])['ok']);
        $this->assertTrue($reg->isPlanAuthorized('g', $root)); // a finite clock before the expiry
        $t = $bad;
        $this->assertFalse($reg->isPlanAuthorized('g', $root)); // was: the int cast read the clock as epoch 0, before the expiry
        $this->expectException(\InvalidArgumentException::class);
        $reg->status('g', $root);
    }
}
