<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\OpenAi\ToolDispatch;
use Atlas\Pca\OpenAiAgents;
use Atlas\Pca\PcaToolDenied;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * The OpenAI adapters against the real openai-php/client library (a dev dependency the CI installs): a chat completion built with the
 * library's own CreateResponse::fake and ClientFake carries a real tool call object (`->id`, `->function->name`, `->function->arguments`),
 * which ToolDispatch signs and runs, and which the agents guard gates on a proof. A missing library FAILS, it never skips.
 */
final class OpenAiPhpRealTest extends TestCase
{
    private const AUD = 'rs-test';

    /** @return array{Agent, \Atlas\Pca\Obj} */
    private static function agent(): array
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
        return [new Agent($key, $grant, self::AUD), $grant];
    }

    /** @return list<object> the tool calls of a real chat completion response */
    private function toolCalls(): array
    {
        $this->assertTrue(class_exists(\OpenAI\Responses\Chat\CreateResponse::class), 'openai-php/client is not installed (composer require-dev)');
        $this->assertTrue(class_exists(\OpenAI\Testing\ClientFake::class), 'openai-php/client has no ClientFake');
        $response = \OpenAI\Responses\Chat\CreateResponse::fake(['choices' => [[
            'index' => 0,
            'message' => ['role' => 'assistant', 'content' => null, 'tool_calls' => [[
                'id' => 'call_1', 'type' => 'function', 'function' => ['name' => 'refund', 'arguments' => '{"order":"7"}'],
            ]]],
            'finish_reason' => 'tool_calls',
        ]]]);
        $client = new \OpenAI\Testing\ClientFake([$response]);
        $res = $client->chat()->create(['model' => 'gpt-4o-mini', 'messages' => [['role' => 'user', 'content' => 'refund order 7']]]);
        $calls = $res->choices[0]->message->toolCalls;
        $this->assertCount(1, $calls);
        $this->assertSame('refund', $calls[0]->function->name);
        return array_values($calls);
    }

    public function testToolDispatchSignsAndRunsARealToolCall(): void
    {
        [$agent] = self::agent();
        $map = static fn(string $name, array $args): ?array => $name === 'refund' ? ['verb' => 'refund', 'resource' => 'orders/' . $args['order']] : null;
        $seen = null;
        $out = ToolDispatch::dispatchToolCalls($agent, $this->toolCalls(), $map, ['refund' => function (array $args, Action $pca) use (&$seen) {
            $seen = $pca;
            return ['refunded' => $args['order']];
        }]);
        $this->assertSame([['role' => 'tool', 'tool_call_id' => 'call_1', 'content' => '{"refunded":"7"}']], $out);
        $this->assertSame('orders/7', $seen->pcactn->get('action')->get('resource'));
    }

    public function testToolDispatchRefusesARealToolCallTheMappingDeclines(): void
    {
        [$agent] = self::agent();
        $ran = false;
        $this->expectException(\RuntimeException::class);
        try {
            ToolDispatch::dispatchToolCalls($agent, $this->toolCalls(), static fn() => null, ['refund' => function () use (&$ran) {
                $ran = true;
            }]);
        } finally {
            $this->assertFalse($ran);
        }
    }

    public function testTheAgentsGuardGatesARealToolCallOnAProof(): void
    {
        [$agent, $grant] = self::agent();
        $call = $this->toolCalls()[0];
        $args = json_decode($call->function->arguments, true, 512, JSON_THROW_ON_ERROR);
        $pca = $agent->act('refund', 'orders/' . $args['order'], $args);
        $ran = [];
        $tool = ['name' => 'refund', 'description' => 'refund an order', 'execute' => static function (array $input, mixed $rc = null) use (&$ran) {
            $ran[] = $input['order'];
            return "refunded {$input['order']}";
        }];
        $guarded = OpenAiAgents::withPcaTool($tool, [
            'mode' => 'signature-only',
            'verify' => ['grant' => $grant, 'insecureSkipPlanRootCheck' => true],
            'audience' => self::AUD,
            'verb' => 'refund',
        ]);
        $ctx = ['context' => ['pca' => $pca->headers[Sign::HEADER]]];
        $this->assertSame('refunded 7', ($guarded['execute'])($args, $ctx));
        $this->assertSame(['7'], $ran);

        foreach ([[], ['context' => ['pca' => 'not a proof']]] as $bad) {
            try {
                ($guarded['execute'])($args, $bad);
                $this->fail('a call without a valid proof must be refused');
            } catch (PcaToolDenied $e) {
                $this->assertContains($e->kind, ['missing', 'malformed']);
            }
        }
        $this->assertSame(['7'], $ran);

        $other = OpenAiAgents::withPcaTool($tool, ['mode' => 'signature-only', 'verify' => ['grant' => $grant, 'insecureSkipPlanRootCheck' => true],
            'audience' => 'someone-else']);
        try {
            ($other['execute'])($args, $ctx);
            $this->fail('a proof for another audience must be refused');
        } catch (PcaToolDenied $e) {
            $this->assertSame('verify', $e->kind);
        }
        $this->assertSame(['7'], $ran);
    }
}
