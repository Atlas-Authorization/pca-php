<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\Anthropic\ToolDispatch;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** The Anthropic Messages adapter: a mapped tool_use block is signed and its handler runs with the proof; a declined or malformed one never runs. */
final class AnthropicToolDispatchTest extends TestCase
{
    private static function agent(): array
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
        return [new Agent($key, $grant, 'rs-test'), $grant];
    }

    public function testAMappedBlockIsSignedAndAnObjectBlockWorks(): void
    {
        [$agent, $grant] = self::agent();
        $map = static fn(string $name, array $in): ?array => $name === 'refund' ? ['verb' => 'refund', 'resource' => 'orders/' . $in['order']] : null;
        $seen = null;
        $content = [
            ['type' => 'text', 'text' => 'refunding'],
            ['type' => 'tool_use', 'id' => 'toolu_1', 'name' => 'refund', 'input' => ['order' => '7']],
            (object)['type' => 'tool_use', 'id' => 'toolu_2', 'name' => 'refund', 'input' => (object)['order' => '8']],
        ];
        $msg = ToolDispatch::dispatchToolUses($agent, $content, $map, ['refund' => function (array $in, Action $pca) use (&$seen) {
            $seen = $pca;
            return ['ok' => $in['order']];
        }]);
        $this->assertSame(['role' => 'user', 'content' => [
            ['type' => 'tool_result', 'tool_use_id' => 'toolu_1', 'content' => '{"ok":"7"}'],
            ['type' => 'tool_result', 'tool_use_id' => 'toolu_2', 'content' => '{"ok":"8"}'],
        ]], $msg);
        $this->assertSame('orders/8', $seen->pcactn->get('action')->get('resource'));
        $v = Pca::verifyPcactnCore($seen->pcactn, $grant, $seen->pcactn->get('iat')->int(), 'rs-test', insecureSkipPlanRootCheck: true);
        $this->assertTrue($v['allow'], $v['reason']);
    }

    public function testATurnWithoutToolsYieldsNothing(): void
    {
        [$agent] = self::agent();
        $this->assertNull(ToolDispatch::dispatchToolUses($agent, [['type' => 'text', 'text' => 'hi']], static fn() => null));
    }

    public function testADeclinedOrMalformedBlockNeverRuns(): void
    {
        [$agent] = self::agent();
        $ran = false;
        $h = ['x' => function () use (&$ran) {
            $ran = true;
        }];
        foreach ([
            [['type' => 'tool_use', 'id' => 'a', 'name' => 'x', 'input' => []], static fn() => null],
            [['type' => 'tool_use', 'id' => 'a', 'name' => 'x', 'input' => [1, 2]], static fn() => ['verb' => 'refund', 'resource' => 'orders/1']],
            [['type' => 'text', 'text' => 'x'], static fn() => ['verb' => 'refund', 'resource' => 'orders/1']],
            [['type' => 'tool_use', 'name' => 'x', 'input' => []], static fn() => ['verb' => 'refund', 'resource' => 'orders/1']],
        ] as [$block, $map]) {
            try {
                ToolDispatch::dispatchToolUse($agent, $block, $map, $h);
                $this->fail('expected a refusal');
            } catch (\InvalidArgumentException | \RuntimeException) {
            }
        }
        $this->assertFalse($ran);
    }
}
