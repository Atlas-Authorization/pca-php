<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Payments;
use PHPUnit\Framework\TestCase;

/** Payments rail-authorizer latency budget (group 10b): the default 1500 ms budget and its strict boundary, on a scripted clock. */
final class MoneySurvivorKill10bPaymentsTest extends TestCase
{
    protected function tearDown(): void
    {
        Payments::$clockHook = null;
    }

    /** The authorizer answer when the clock reads $t0 before the decision and $t1 after it (every value is exact in binary64). */
    private static function answer(float $t0, float $t1): array
    {
        $reads = [$t0, $t1];
        Payments::$clockHook = static function () use (&$reads): float {
            return array_shift($reads);
        };
        // a malformed authorization is answered without touching the store, so only the latency gate can change the result
        $r = Payments::createRailAuthorizer(['instruments' => static fn($id) => null])(['id' => '']);
        return [$r->get('approved'), $r->get('reasons'), $reads];
    }

    /** Exactly the default 1.5 s budget is still inside it; 2^-10 s more is over the 1500 ms budget but under 1501 ms. */
    public function testDefaultBudgetBoundary(): void
    {
        $this->assertSame([false, ['malformed_authorization'], []], self::answer(1000.0, 1001.5));
        $this->assertSame([false, ['latency_budget_exceeded'], []], self::answer(1000.0, 1001.5009765625));
    }
}
