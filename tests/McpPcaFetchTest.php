<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Mcp;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** pcaFetch: a tools/call request gets a fresh PCA-Action header, every other request passes through, an unmapped tool goes without a proof. */
final class McpPcaFetchTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    public function testToolsCallCarriesAFreshProofAndOtherRequestsPassThrough(): void
    {
        $seen = [];
        $inner = static function (string $url, array $init) use (&$seen): string {
            $seen[] = $init;
            return 'ok';
        };
        $map = static fn(string $tool, $args): ?array => $tool === 'refund' ? ['refund', 'orders/7'] : null;
        $f = Mcp::pcaFetch(self::agent(), $map, $inner);
        $call = static fn(string $tool): string => json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/call', 'params' => ['name' => $tool, 'arguments' => ['order' => 'orders/7']]]);

        $this->assertSame('ok', $f('http://x/mcp', ['body' => $call('refund'), 'headers' => ['accept' => 'application/json']]));
        $this->assertArrayHasKey('PCA-Action', $seen[0]['headers']);
        $this->assertSame('application/json', $seen[0]['headers']['accept']);

        $f('http://x/mcp', ['body' => $call('refund')]);
        $this->assertNotSame($seen[0]['headers']['PCA-Action'], $seen[1]['headers']['PCA-Action']); // a fresh counter and nonce per call

        $f('http://x/mcp', ['body' => $call('other')]);
        $this->assertArrayNotHasKey('headers', $seen[2]);
        $f('http://x/mcp', ['body' => '{"jsonrpc":"2.0","method":"tools/list"}']);
        $this->assertArrayNotHasKey('headers', $seen[3]);
        $f('http://x/mcp');
        $this->assertSame([], $seen[4]);
    }
}
