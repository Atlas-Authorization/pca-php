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

/** Survivor kills for the Anthropic Messages tool_use adapter. */
final class RestSurvivorKill35AnthropicToolDispatchTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    /** Runs $f with every PHP warning / notice turned into a thrown error. */
    private static function noWarnings(\Closure $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    private static function str(string $s): \Stringable
    {
        return new class ($s) implements \Stringable {
            public function __construct(private string $s)
            {
            }

            public function __toString(): string
            {
                return $this->s;
            }
        };
    }

    private static function map(): \Closure
    {
        return static fn(string $n, array $in): array => ['verb' => 'refund', 'resource' => 'orders/1'];
    }

    /** inputOf is public: an object input with several keys keeps every key, null is {}. */
    public function testInputOfIsPublicAndKeepsEveryKey(): void
    {
        $this->assertSame(['a' => 1, 'b' => 'x'], ToolDispatch::inputOf((object)['a' => 1, 'b' => 'x']));
        $this->assertSame(['a' => 1, 'b' => 2], ToolDispatch::inputOf(['a' => 1, 'b' => 2]));
        $this->assertSame([], ToolDispatch::inputOf(null));
    }

    /** An object input is accepted at exactly the JSON round-trip's default nesting depth (512), never a level less. */
    public function testInputOfObjectDepthMatchesTheDefaultJsonDepth(): void
    {
        foreach ([510, 511, 512, 513] as $n) {
            $o = (object)['leaf' => 1];
            for ($i = 1; $i < $n; $i++) {
                $o = (object)['a' => $o];
            }
            try {
                json_decode(json_encode($o, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
                $want = true;
            } catch (\JsonException) {
                $want = false;
            }
            try {
                $got = is_array(ToolDispatch::inputOf($o));
            } catch (\JsonException) {
                $got = false;
            }
            $this->assertSame($want, $got, "depth $n");
        }
    }

    /** A block without a type field is a tool_use block, and an object block missing it reads no undefined property. */
    public function testAnUntypedObjectBlockDispatchesWithoutWarnings(): void
    {
        $block = (object)['id' => 'toolu_9', 'name' => 'refund', 'input' => (object)['order' => '1']];
        $r = self::noWarnings(static fn() => ToolDispatch::dispatchToolUse(self::agent(), $block, self::map(), ['refund' => static fn(array $in): array => $in]));
        $this->assertSame(['type' => 'tool_result', 'tool_use_id' => 'toolu_9', 'content' => '{"order":"1"}'], $r);
        $r = ToolDispatch::dispatchToolUse(self::agent(), ['id' => 'toolu_8', 'name' => 'refund'], self::map(), ['refund' => static fn(array $in): array => ['n' => count($in)]]);
        $this->assertSame('{"n":0}', $r['content']);
    }

    /** A block of another type is refused with its own reason, before any mapping runs. */
    public function testANonToolUseBlockIsRefusedWithItsReason(): void
    {
        $mapped = false;
        try {
            ToolDispatch::dispatchToolUse(self::agent(), ['type' => 'text', 'id' => 'a', 'name' => 'refund', 'input' => []], static function () use (&$mapped): array {
                $mapped = true;
                return ['verb' => 'refund', 'resource' => 'orders/1'];
            });
            $this->fail('a text block was dispatched');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('dispatchToolUse: the block is not a tool_use block', $e->getMessage());
        }
        $this->assertFalse($mapped);
    }

    /** Stringable verb/resource from the mapping are used as strings; the signed params digest is over the input. */
    public function testMappedStringablesAndParamsDigest(): void
    {
        $seen = null;
        $map = static fn(string $n, array $in): array => ['verb' => self::str('refund'), 'resource' => self::str('orders/7')];
        ToolDispatch::dispatchToolUse(self::agent(), ['type' => 'tool_use', 'id' => 'a', 'name' => 'refund', 'input' => ['order' => '7']], $map, ['refund' => static function (array $in, Action $pca) use (&$seen): string {
            $seen = $pca;
            return 'ok';
        }]);
        $act = $seen->pcactn->get('action');
        $this->assertSame(['refund', 'orders/7'], [$act->get('verb'), $act->get('resource')]);
        $this->assertSame(Pca::paramsDigest(Sign::n(['order' => '7'])), $act->get('params_digest'));
    }

    /** Without a handler the content is {"pca": header}; handler output keeps slashes and unicode unescaped. */
    public function testContentEncoding(): void
    {
        $r = ToolDispatch::dispatchToolUse(self::agent(), ['type' => 'tool_use', 'id' => 'a', 'name' => 'refund', 'input' => []], self::map());
        $d = json_decode($r['content'], true);
        $this->assertSame(['pca'], array_keys($d));
        $this->assertIsString($d['pca']);
        $this->assertNotSame('', $d['pca']);
        $r = ToolDispatch::dispatchToolUse(self::agent(), ['type' => 'tool_use', 'id' => 'a', 'name' => 'refund', 'input' => []], self::map(), ['refund' => static fn(): array => ['u' => "a/b \u{e9}"]]);
        $this->assertSame("{\"u\":\"a/b \u{e9}\"}", $r['content']);
    }
}
