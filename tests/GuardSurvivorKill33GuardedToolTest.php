<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GuardedTool.php';

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\GuardedTool;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/GuardedTool.php: the missing call() refusal, string coercion of verb/resource, the params of the proof, failFast off. */
final class GuardSurvivorKill33GuardedToolTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    private static function tool(): object
    {
        return new class {
            public int $ran = 0;

            public function call(mixed $input): string
            {
                $this->ran++;
                return 'ran';
            }
        };
    }

    /** The class of what a call throws (null when it ran). */
    private static function thrown(callable $f): ?string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
        return null;
    }

    /** Wrapping an object without call() is refused at construction with the reference's TypeError. */
    public function testToolWithoutCallIsRefused(): void
    {
        $this->assertSame('TypeError: GuardedTool: the wrapped tool has no call() method',
            self::thrown(fn() => new GuardedTool(self::agent(), ['verb' => 'refund', 'resource' => 'orders/1'], new \stdClass())));
    }

    /** A non-string verb or resource is coerced to a string and refused by the grant, not a TypeError. */
    public function testNonStringVerbAndResourceAreCoerced(): void
    {
        $want = 'RuntimeException: GuardedTool: the grant refuses this call (';
        foreach ([['refund', 7], ['refund', static fn(array $a): int => 7], [7, 'orders/1']] as [$verb, $res]) {
            $tool = self::tool();
            $why = self::thrown(fn() => GuardedTool::withPca(self::agent(), ['verb' => $verb, 'resource' => $res], $tool)->call([]));
            $this->assertIsString($why);
            $this->assertStringStartsWith($want, $why);
            $this->assertSame(0, $tool->ran);
        }
    }

    /** No arguments sign the empty params digest; arguments sign their own digest. */
    public function testProofParamsAreTheArguments(): void
    {
        $proofs = [];
        $tool = self::tool();
        $g = GuardedTool::withPca(self::agent(), ['verb' => 'refund', 'resource' => 'orders/1', 'onProof' => static function (Action $p) use (&$proofs): void {
            $proofs[] = $p->pcactn->get('action')->get('params_digest');
        }], $tool);
        $this->assertSame('ran', $g->call([]));
        $this->assertSame('ran', $g->call(['order' => 'orders/1']));
        $this->assertSame([Pca::paramsDigest(null), Pca::paramsDigest(Sign::n(['order' => 'orders/1']))], $proofs);
        $this->assertNotSame(Pca::paramsDigest(null), Pca::paramsDigest(Sign::n([])), 'an empty list is not the empty params object');
    }

    /** failFast false skips the local refusal: an ungranted call is signed and runs (the server decides). */
    public function testFailFastOffRunsTheCall(): void
    {
        $tool = self::tool();
        $this->assertSame('ran', GuardedTool::withPca(self::agent(), ['verb' => 'refund', 'resource' => 'users/1', 'failFast' => false], $tool)->call([]));
        $this->assertSame(1, $tool->ran);
        $this->assertStringStartsWith('RuntimeException: GuardedTool: the grant refuses this call (',
            (string)self::thrown(fn() => GuardedTool::withPca(self::agent(), ['verb' => 'refund', 'resource' => 'users/1'], self::tool())->call([])), 'control');
    }
}
