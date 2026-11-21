<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LlPhant\PcaToolProxy;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * The tool proxy against the real LLPhant library (a dev dependency the CI installs): a FunctionInfo whose instance is the proxy runs the
 * tool the way LLPhant does (`$instance->{$name}(...$arguments)` over the model's decoded JSON arguments), once through
 * FunctionInfo::call() and once through FunctionRunner::run(). A missing library FAILS, it never skips.
 */
final class LlPhantRealTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    private function info(object $proxy, string $json): object
    {
        $this->assertTrue(class_exists(\LLPhant\Chat\FunctionInfo\FunctionInfo::class), 'theodo-group/llphant is not installed (composer require-dev)');
        $p = new \LLPhant\Chat\FunctionInfo\Parameter('order', 'string', 'the order to refund');
        $fi = new \LLPhant\Chat\FunctionInfo\FunctionInfo('refund', $proxy, 'refund an order', [$p], [$p]);
        $fi->jsonArgs = $json;
        return $fi;
    }

    public function testFunctionInfoRoundTripRunsTheGrantedToolWithAProof(): void
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
        $map = static fn(string $tool, array $a): ?array => $tool === 'refund' ? ['verb' => 'refund', 'resource' => (string)$a['order']] : null;
        $proxy = new PcaToolProxy(self::agent(), $tools, $map, static function ($pca) use (&$proofs) {
            $proofs[] = $pca;
        });
        $fi = $this->info($proxy, '{"order":"orders/7"}');
        $this->assertSame('refunded orders/7', $fi->call());
        $this->assertSame('refunded orders/7', \LLPhant\Chat\FunctionInfo\FunctionRunner::run($fi));
        $this->assertSame('refunded orders/7', $fi->callWithArguments(['order' => 'orders/7']));
        $this->assertCount(3, $proofs);
        $this->assertSame(['orders/7', 'orders/7', 'orders/7'], $tools->ran);
    }

    public function testFunctionInfoRoundTripRefusesAnUngrantedCallBeforeTheToolRuns(): void
    {
        $tools = new class {
            public int $ran = 0;

            public function refund(string $order): string
            {
                $this->ran++;
                return $order;
            }
        };
        $map = static fn(string $tool, array $a): ?array => ['verb' => 'refund', 'resource' => (string)$a['order']];
        $fi = $this->info(new PcaToolProxy(self::agent(), $tools, $map), '{"order":"users/1"}');
        $this->expectException(\RuntimeException::class);
        try {
            $fi->call();
        } finally {
            $this->assertSame(0, $tools->ran);
        }
    }
}
