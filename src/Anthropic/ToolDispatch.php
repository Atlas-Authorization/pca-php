<?php
declare(strict_types=1);

namespace Atlas\Pca\Anthropic;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\Sign;

require_once __DIR__ . '/../Agent.php';

/**
 * Anthropic Messages adapter (anthropic-ai/sdk or any client that returns the Messages API content blocks): turn a `tool_use` block into
 * a signed PCActn, run the mapped tool handler with the proof, and return the `tool_result` block for the next user turn. A block is the
 * SDK's object (`->id`, `->name`, `->input`) or the same shape as an array. This does NOT authorize: it attaches a proof-carrying action;
 * the resource server's verifier decides.
 */
final class ToolDispatch
{
    private static function field(mixed $o, string $k): mixed
    {
        return is_array($o) ? ($o[$k] ?? null) : (is_object($o) && isset($o->{$k}) ? $o->{$k} : null);
    }

    /** A block's `input` as a JSON object (an SDK object or a decoded array; none is {}). @return array<string,mixed> */
    public static function inputOf(mixed $input): array
    {
        if ($input === null) {
            return [];
        }
        if (is_object($input)) {
            $input = json_decode(json_encode($input, JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        }
        if (!is_array($input) || ($input !== [] && array_is_list($input))) {
            throw new \InvalidArgumentException('dispatchToolUse: tool_use input must be a JSON object');
        }
        return $input;
    }

    /**
     * Dispatch one `tool_use` block. `$map(name, input)` returns ['verb' => ..., 'resource' => ...] or null (declined: a tool we cannot
     * produce a PCActn for is refused, never run). `$handlers[name](input, Action $pca)` runs the real tool; without one the content is
     * {"pca": <PCA-Action header value>}.
     * @param callable(string, array<string,mixed>): ?array{verb: string, resource: string} $map
     * @param array<string, callable(array<string,mixed>, Action): mixed> $handlers
     * @return array{type: 'tool_result', tool_use_id: string, content: string}
     */
    public static function dispatchToolUse(Agent $agent, mixed $block, callable $map, array $handlers = []): array
    {
        $type = self::field($block, 'type');
        if ($type !== null && $type !== 'tool_use') {
            throw new \InvalidArgumentException('dispatchToolUse: the block is not a tool_use block');
        }
        $name = self::field($block, 'name');
        $id = self::field($block, 'id');
        if (!is_string($name) || !is_string($id)) {
            throw new \InvalidArgumentException('dispatchToolUse: tool_use.name and tool_use.id must be strings');
        }
        $input = self::inputOf(self::field($block, 'input'));
        $m = $map($name, $input);
        if ($m === null) {
            throw new \RuntimeException("dispatchToolUse: no PCActn for unmapped tool \"$name\" (the mapping declined)");
        }
        $pca = $agent->act((string)$m['verb'], (string)$m['resource'], $input === [] ? null : $input);
        $h = $handlers[$name] ?? null;
        $result = $h !== null ? $h($input, $pca) : null;
        $content = json_encode($result ?? ['pca' => $pca->headers[Sign::HEADER]], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return ['type' => 'tool_result', 'tool_use_id' => $id, 'content' => $content];
    }

    /**
     * Dispatch every `tool_use` block of an assistant message's content, in order (each act() takes the agent's next counter); other
     * blocks (text, thinking) are skipped. Returns the next user message, or null when the turn used no tool.
     * @param iterable<mixed> $content
     * @return array{role: 'user', content: list<array{type: 'tool_result', tool_use_id: string, content: string}>}|null
     */
    public static function dispatchToolUses(Agent $agent, iterable $content, callable $map, array $handlers = []): ?array
    {
        $results = [];
        foreach ($content as $b) {
            if (self::field($b, 'type') === 'tool_use') {
                $results[] = self::dispatchToolUse($agent, $b, $map, $handlers);
            }
        }
        return $results === [] ? null : ['role' => 'user', 'content' => $results];
    }
}
