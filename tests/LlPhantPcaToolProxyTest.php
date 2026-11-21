<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LlPhant\PcaToolProxy;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** The LLPhant tool proxy: a granted call runs with a proof (named arguments pass through); an ungranted or unmapped one never runs. */
final class LlPhantPcaToolProxyTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    public function testGrantedCallRunsWithAProofAndRefusedCallsNeverRun(): void
    {
        $tools = new class {
            /** @var list<string> */
            public array $ran = [];

            public function refund(string $order): string
            {
                $this->ran[] = $order;
                return "refunded $order";
            }
        };
        $proofs = [];
        $map = static fn(string $tool, array $a): ?array => $tool === 'refund' ? ['verb' => 'refund', 'resource' => $a['order']] : null;
        $proxy = new PcaToolProxy(self::agent(), $tools, $map, static function ($pca) use (&$proofs) {
            $proofs[] = $pca;
        });
        $this->assertSame('refunded orders/7', $proxy->refund(order: 'orders/7'));
        $this->assertCount(1, $proofs);
        foreach ([['refund', ['order' => 'users/1']], ['missing', []]] as [$name, $args]) {
            try {
                $proxy->{$name}(...$args);
                $this->fail("$name ran");
            } catch (\RuntimeException | \BadMethodCallException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->assertSame(['orders/7'], $tools->ran);
    }
}
