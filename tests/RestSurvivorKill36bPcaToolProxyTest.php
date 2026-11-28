<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LlPhant\PcaToolProxy;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** PcaToolProxy: exact refusals for a missing or unmapped tool, string-cast mappings, and the params the proof commits to. */
final class RestSurvivorKill36bPcaToolProxyTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    private static function tools(): object
    {
        return new class {
            public function refund(string $order = 'orders/1'): string
            {
                return "refunded $order";
            }

            public function other(): string
            {
                return 'other ran';
            }
        };
    }

    /** A method the tool object lacks is refused with BadMethodCallException before the mapping or a proof is made. */
    public function testMissingMethodRefusedBeforeMapping(): void
    {
        $calls = 0;
        $map = static function () use (&$calls): array {
            $calls++;
            return ['verb' => 'refund', 'resource' => 'orders/7'];
        };
        $proxy = new PcaToolProxy(self::agent(), self::tools(), $map);
        try {
            $proxy->missing();
            self::fail('missing ran');
        } catch (\BadMethodCallException $e) {
            self::assertSame('PcaToolProxy: the tool object has no method "missing"', $e->getMessage());
        }
        self::assertSame(0, $calls);
    }

    /** A tool the mapping declines is refused with its own message, never signed and never run. */
    public function testUnmappedToolRefused(): void
    {
        $proofs = 0;
        $proxy = new PcaToolProxy(self::agent(), self::tools(), static fn(string $t): ?array => null, static function () use (&$proofs): void {
            $proofs++;
        });
        try {
            $proxy->other();
            self::fail('other ran');
        } catch (\RuntimeException $e) {
            self::assertSame('PcaToolProxy: no PCActn for unmapped tool "other" (the mapping declined)', $e->getMessage());
        }
        self::assertSame(0, $proofs);
    }

    /** A mapping that returns Stringable verb and resource is cast to strings; the proof commits to the named arguments. */
    public function testStringableMappingAndParamsDigest(): void
    {
        $s = static fn(string $v): \Stringable => new class($v) implements \Stringable {
            public function __construct(private readonly string $v)
            {
            }

            public function __toString(): string
            {
                return $this->v;
            }
        };
        $proofs = [];
        $proxy = new PcaToolProxy(self::agent(), self::tools(), static fn(string $t, array $a): array => ['verb' => $s('refund'), 'resource' => $s('orders/7')],
            static function (Action $pca) use (&$proofs): void {
                $proofs[] = $pca;
            });
        self::assertSame('refunded orders/7', $proxy->refund(order: 'orders/7'));
        self::assertCount(1, $proofs);
        $act = $proofs[0]->pcactn->get('action');
        self::assertSame('refund', $act->get('verb'));
        self::assertSame('orders/7', $act->get('resource'));
        self::assertSame(Pca::paramsDigest(Sign::n(['order' => 'orders/7'])), $act->get('params_digest'));
    }

    /** A call with no arguments commits to no params (the empty-object digest), not to an empty list. */
    public function testNoArgumentsCommitsNullParams(): void
    {
        $proofs = [];
        $proxy = new PcaToolProxy(self::agent(), self::tools(), static fn(string $t, array $a): array => ['verb' => 'refund', 'resource' => 'orders/1'],
            static function (Action $pca) use (&$proofs): void {
                $proofs[] = $pca;
            });
        self::assertSame('refunded orders/1', $proxy->refund());
        self::assertCount(1, $proofs);
        $digest = $proofs[0]->pcactn->get('action')->get('params_digest');
        self::assertSame(Pca::paramsDigest(null), $digest);
        self::assertNotSame(Pca::paramsDigest([]), $digest);
    }
}
