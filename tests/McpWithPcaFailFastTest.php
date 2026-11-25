<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Mcp;
use Atlas\Pca\OpenAi\ToolDispatch;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** failFast (the default): a call outside the grant's predicates is refused before its handler runs. */
final class McpWithPcaFailFastTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    public function testAnOutOfGrantCallNeverRunsTheHandler(): void
    {
        $ran = [];
        $tool = Mcp::withPca(self::agent(), ['verb' => 'refund', 'resourceOf' => static fn($a) => $a['resource']], static function ($a) use (&$ran) {
            $ran[] = $a['resource'];
            return 'ok';
        });
        $this->assertSame('ok', $tool(['resource' => 'orders/1']));
        $denied = $tool(['resource' => 'users/1']);
        $this->assertTrue($denied->get('isError'));
        $this->assertSame(['orders/1'], $ran);
    }

    public function testFailFastFalseRunsTheHandlerAnyway(): void
    {
        $ran = false;
        $tool = Mcp::withPca(self::agent(), ['verb' => 'refund', 'failFast' => false, 'resourceOf' => static fn($a) => $a['resource']], static function () use (&$ran) {
            $ran = true;
            return 'ok';
        });
        $this->assertSame('ok', $tool(['resource' => 'users/1']));
        $this->assertTrue($ran);
    }

    public function testToolDispatchRefusesAnOutOfGrantCall(): void
    {
        $ran = false;
        $call = ['id' => 'c', 'function' => ['name' => 'refund', 'arguments' => '{}']];
        $this->expectException(\RuntimeException::class);
        try {
            ToolDispatch::dispatchToolCall(self::agent(), $call, static fn() => ['verb' => 'refund', 'resource' => 'users/1'], ['refund' => static function () use (&$ran) {
                $ran = true;
            }]);
        } finally {
            $this->assertFalse($ran);
        }
    }
}
