<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** The optional core threshold hook is tri-state (enforced+ok, enforced+refused, not enforced) and invisible when absent. */
final class CoreThresholdHookTest extends TestCase
{
    /** @return array{0:\Atlas\Pca\Obj,1:\Atlas\Pca\Obj} */
    private static function signed(): array
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
        $agent = new Agent($key, $grant, 'rs-test');
        return [$agent->act('refund', 'orders/7')->pcactn, $grant];
    }

    private static function core(\Atlas\Pca\Obj $p, \Atlas\Pca\Obj $g, ?\Closure $hook): array
    {
        return Pca::verifyPcactnCore($p, $g, $p->get('iat')->int(), 'rs-test', insecureSkipPlanRootCheck: true, thresholdHook: $hook);
    }

    public function testNoHookLeavesTheReportUnchanged(): void
    {
        [$p, $g] = self::signed();
        $r = self::core($p, $g, null);
        self::assertTrue($r['allow']);
        self::assertArrayNotHasKey('threshold', $r['checks']);
    }

    public function testEnforcedOkPasses(): void
    {
        [$p, $g] = self::signed();
        $r = self::core($p, $g, static fn($x): array => ['enforced' => true, 'ok' => true]);
        self::assertTrue($r['allow']);
        self::assertTrue($r['checks']['threshold']);
    }

    public function testEnforcedRefusalDeniesWithTheReason(): void
    {
        [$p, $g] = self::signed();
        $r = self::core($p, $g, static fn($x): array => ['enforced' => true, 'ok' => false, 'reason' => 'quorum short']);
        self::assertFalse($r['allow']);
        self::assertFalse($r['checks']['threshold']);
        self::assertSame('threshold: quorum short', $r['reason']);
    }

    public function testNotEnforcedIsReportedNotPassed(): void
    {
        [$p, $g] = self::signed();
        $r = self::core($p, $g, static fn($x): array => ['enforced' => false]);
        self::assertTrue($r['allow']);
        self::assertArrayNotHasKey('threshold', $r['checks']);
        self::assertContains('threshold', $r['not_enforced']);
    }
}
