<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\Audience;
use Atlas\Pca\KeyPair;
use Atlas\Pca\OpenAi\ToolDispatch;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** The openai-php tool-call adapter: a mapped call is signed and its handler runs with the proof; a declined or malformed one never runs. */
final class OpenAiToolDispatchTest extends TestCase
{
    private static function agent(): array
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
        return [new Agent($key, $grant, 'rs-test'), $grant];
    }

    public function testAMappedCallIsSignedAndItsHandlerGetsTheProof(): void
    {
        [$agent, $grant] = self::agent();
        $map = static fn(string $name, array $args): ?array => $name === 'refund' ? ['verb' => 'refund', 'resource' => 'orders/' . $args['order']] : null;
        $seen = null;
        $calls = [
            ['id' => 'call_1', 'type' => 'function', 'function' => ['name' => 'refund', 'arguments' => '{"order":"7"}']],
            (object)['id' => 'call_2', 'function' => (object)['name' => 'refund', 'arguments' => ' {"order":"8"} ']],
        ];
        $out = ToolDispatch::dispatchToolCalls($agent, $calls, $map, ['refund' => function (array $args, Action $pca) use (&$seen) {
            $seen = $pca;
            return ['ok' => $args['order']];
        }]);
        $this->assertSame([['role' => 'tool', 'tool_call_id' => 'call_1', 'content' => '{"ok":"7"}'], ['role' => 'tool', 'tool_call_id' => 'call_2', 'content' => '{"ok":"8"}']], $out);
        $this->assertSame('orders/8', $seen->pcactn->get('action')->get('resource'));
        $v = Pca::verifyPcactnCore($seen->pcactn, $grant, $seen->pcactn->get('iat')->int(), 'rs-test', insecureSkipPlanRootCheck: true);
        $this->assertTrue($v['allow'], $v['reason']);
        $this->assertFalse(Pca::verifyPcactnCore($seen->pcactn, $grant, $seen->pcactn->get('iat')->int(), null, insecureSkipPlanRootCheck: true)['allow']);
        $this->assertTrue(Pca::verifyPcactnCore($seen->pcactn, $grant, $seen->pcactn->get('iat')->int(), Audience::Any, insecureSkipPlanRootCheck: true)['allow']);
    }

    public function testWithoutAHandlerTheContentCarriesTheHeader(): void
    {
        [$agent] = self::agent();
        $m = ToolDispatch::dispatchToolCall($agent, ['id' => 'c', 'function' => ['name' => 'refund', 'arguments' => '']], static fn() => ['verb' => 'refund', 'resource' => 'orders/1']);
        $this->assertArrayHasKey('pca', json_decode($m['content'], true));
    }

    public function testADeclinedOrMalformedCallNeverRuns(): void
    {
        [$agent] = self::agent();
        $ran = false;
        $h = ['x' => function () use (&$ran) {
            $ran = true;
        }];
        foreach (['{"a":1}' => static fn() => null, '[1]' => static fn() => ['verb' => 'refund', 'resource' => 'orders/1'], 'nope' => static fn() => ['verb' => 'refund', 'resource' => 'orders/1']] as $args => $map) {
            $refused = false;
            try {
                ToolDispatch::dispatchToolCall($agent, ['id' => 'c', 'function' => ['name' => 'x', 'arguments' => $args]], $map, $h);
            } catch (\RuntimeException | \InvalidArgumentException | \JsonException) {
                $refused = true;
            }
            $this->assertTrue($refused, "dispatched with $args");
        }
        $this->assertFalse($ran);
    }
}
