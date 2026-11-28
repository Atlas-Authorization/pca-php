<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\GuardedTool;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** The structural tool wrapper: a granted call runs with a proof and keeps metadata; an ungranted one never runs. */
final class GuardedToolTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    public function testGrantedCallRunsWithAProofAndRefusedCallNeverRuns(): void
    {
        $tool = new class {
            public array $metadata = ['name' => 'refund', 'description' => 'refund an order'];
            public int $ran = 0;

            public function call(array $input): string
            {
                $this->ran++;
                return 'refunded ' . $input['order'];
            }
        };
        $proofs = [];
        $g = GuardedTool::withPca(self::agent(), ['verb' => 'refund', 'resource' => static fn(array $a) => $a['order'], 'onProof' => static function ($pca) use (&$proofs) {
            $proofs[] = $pca;
        }], $tool);
        $this->assertSame(['name' => 'refund', 'description' => 'refund an order'], $g->metadata);
        $this->assertSame('refunded orders/7', $g->call(['order' => 'orders/7']));
        $this->assertCount(1, $proofs);
        try {
            $g->call(['order' => 'users/1']);
            $this->fail('an ungranted call ran');
        } catch (\RuntimeException) {
            $this->addToAssertionCount(1);
        }
        $this->assertSame(1, $tool->ran);
    }
}
