<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\OpenAi\ToolDispatch;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the openai-php tool-call adapter. */
final class RestSurvivorKill35OpenAiToolDispatchTest extends TestCase
{
    private const MSG = 'dispatchToolCall: tool_call arguments must be a JSON object';

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

    private static function map(string $resource = 'orders/1'): \Closure
    {
        return static fn(string $n, array $a): array => ['verb' => 'refund', 'resource' => $resource];
    }

    /** parseArguments is public: null and whitespace are {}, every key of an object is kept. */
    public function testParseArgumentsEmptyAndMultiKey(): void
    {
        $this->assertSame([], ToolDispatch::parseArguments(null));
        $this->assertSame([], ToolDispatch::parseArguments(" \n\t "));
        $this->assertSame(['a' => 1, 'b' => 2], ToolDispatch::parseArguments(' {"a":1,"b":2} '));
        $this->assertSame([], ToolDispatch::parseArguments('{}'));
    }

    /** Non-objects are refused with the exact reason; an object whose keys decode to a PHP list is refused too (fail closed). */
    public function testParseArgumentsRefusesNonObjects(): void
    {
        foreach (['{"0":1}', '{"0":1,"1":2}', '5', '"s"', 'true', 'null', '[]', '[1]'] as $raw) {
            try {
                ToolDispatch::parseArguments($raw);
                $this->fail("accepted $raw");
            } catch (\InvalidArgumentException $e) {
                $this->assertSame(self::MSG, $e->getMessage(), $raw);
            }
        }
    }

    /** Arguments are decoded at exactly the default JSON depth (512): one level more is refused, the limit itself is not. */
    public function testParseArgumentsDepthIsTheDefaultJsonDepth(): void
    {
        foreach ([510, 511, 512, 513, 514] as $n) {
            $raw = str_repeat('{"a":', $n - 1) . '{}' . str_repeat('}', $n - 1);
            try {
                json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
                $want = true;
            } catch (\JsonException) {
                $want = false;
            }
            try {
                $got = is_array(ToolDispatch::parseArguments($raw));
            } catch (\JsonException) {
                $got = false;
            }
            $this->assertSame($want, $got, "depth $n");
        }
    }

    /** A call whose function name is not a string is refused with its reason. */
    public function testANonStringNameIsRefused(): void
    {
        try {
            ToolDispatch::dispatchToolCall(self::agent(), ['id' => 'c', 'function' => ['name' => 5, 'arguments' => '{}']], self::map());
            $this->fail('dispatched');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('dispatchToolCall: tool_call.function.name must be a string', $e->getMessage());
        }
    }

    /** An object call whose function has no arguments property is {} and reads no undefined property; a missing id is ''. */
    public function testAnObjectCallWithoutArgumentsAndId(): void
    {
        $call = (object)['id' => 'c7', 'function' => (object)['name' => 'refund']];
        $r = self::noWarnings(static fn() => ToolDispatch::dispatchToolCall(self::agent(), $call, self::map(), ['refund' => static fn(array $a): array => ['n' => count($a)]]));
        $this->assertSame(['role' => 'tool', 'tool_call_id' => 'c7', 'content' => '{"n":0}'], $r);
        $r = ToolDispatch::dispatchToolCall(self::agent(), ['function' => ['name' => 'refund', 'arguments' => '']], self::map(), ['refund' => static fn(): string => 'x']);
        $this->assertSame('', $r['tool_call_id']);
    }

    /** Stringable verb/resource are used as strings for the refusal check and the signature; the params digest is over the arguments. */
    public function testMappedStringablesAndParamsDigest(): void
    {
        $seen = null;
        $map = static fn(string $n, array $a): array => ['verb' => self::str('refund'), 'resource' => self::str('orders/7')];
        $r = ToolDispatch::dispatchToolCall(self::agent(), ['id' => 'c', 'function' => ['name' => 'refund', 'arguments' => '{"order":"7"}']], $map, ['refund' => static function (array $a, Action $pca) use (&$seen): string {
            $seen = $pca;
            return 'ok';
        }]);
        $this->assertSame('"ok"', $r['content']);
        $act = $seen->pcactn->get('action');
        $this->assertSame(['refund', 'orders/7'], [$act->get('verb'), $act->get('resource')]);
        $this->assertSame(Pca::paramsDigest(Sign::n(['order' => '7'])), $act->get('params_digest'));
    }

    /** Handler output keeps slashes and unicode unescaped. */
    public function testContentEncoding(): void
    {
        $r = ToolDispatch::dispatchToolCall(self::agent(), ['id' => 'c', 'function' => ['name' => 'refund', 'arguments' => '']], self::map(), ['refund' => static fn(): array => ['u' => "a/b \u{e9}"]]);
        $this->assertSame("{\"u\":\"a/b \u{e9}\"}", $r['content']);
    }

    /** dispatchToolCalls refuses a call the grant does not admit by default, and runs it only with failFast off. */
    public function testDispatchToolCallsFailsFastByDefault(): void
    {
        $ran = false;
        $h = ['refund' => static function () use (&$ran): string {
            $ran = true;
            return 'ran';
        }];
        $calls = [['id' => 'c', 'function' => ['name' => 'refund', 'arguments' => '{}']]];
        try {
            ToolDispatch::dispatchToolCalls(self::agent(), $calls, self::map('users/1'), $h);
            $this->fail('a refused call ran');
        } catch (\RuntimeException $e) {
            $this->assertStringStartsWith('dispatchToolCall: the grant refuses this call (', $e->getMessage());
        }
        $this->assertFalse($ran);
        $out = ToolDispatch::dispatchToolCalls(self::agent(), $calls, self::map('users/1'), $h, false);
        $this->assertSame('"ran"', $out[0]['content']);
        $this->assertTrue($ran);
    }
}
