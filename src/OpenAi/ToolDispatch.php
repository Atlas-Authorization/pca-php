<?php
declare(strict_types=1);

namespace Atlas\Pca\OpenAi;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\Sign;

require_once __DIR__ . '/../Agent.php';

/**
 * openai-php adapter: turn a chat-completion tool call into a signed PCActn, run the mapped tool handler with the proof, and return
 * the `{role: tool, tool_call_id, content}` message for the next model turn. A tool call is the openai-php/client response object
 * (`->id`, `->function->name`, `->function->arguments`) or the same shape as an array. This does NOT authorize: it attaches a
 * proof-carrying action; the resource server's verifier decides.
 */
final class ToolDispatch
{
    private static function field(mixed $o, string $k): mixed
    {
        return is_array($o) ? ($o[$k] ?? null) : (is_object($o) && isset($o->{$k}) ? $o->{$k} : null);
    }

    /** A tool call's `arguments` (JSON text; empty or whitespace is {}). It must be a JSON object. @return array<string,mixed> */
    public static function parseArguments(?string $raw): array
    {
        $t = trim((string)$raw);
        if ($t === '') {
            return [];
        }
        $v = json_decode($t, true, 512, JSON_THROW_ON_ERROR);
        if (!is_array($v) || ($v !== [] && array_is_list($v)) || str_starts_with($t, '[')) {
            throw new \InvalidArgumentException('dispatchToolCall: tool_call arguments must be a JSON object');
        }
        return $v;
    }

    /**
     * Dispatch one tool call. `$map(name, args)` returns ['verb' => ..., 'resource' => ...] or null (declined: a tool we cannot
     * produce a PCActn for is refused, never run). `$handlers[name](args, Action $pca)` runs the real tool; without one the content
     * is {"pca": <PCA-Action header value>}.
     * @param callable(string, array<string,mixed>): ?array{verb: string, resource: string} $map
     * @param array<string, callable(array<string,mixed>, Action): mixed> $handlers
     * @param bool $failFast refuse (throw, handler never runs) a call the grant's predicates and caveats do not admit
     * @return array{role: 'tool', tool_call_id: string, content: string}
     */
    public static function dispatchToolCall(Agent $agent, mixed $call, callable $map, array $handlers = [], bool $failFast = true): array
    {
        $fn = self::field($call, 'function');
        $name = self::field($fn, 'name');
        if (!is_string($name)) {
            throw new \InvalidArgumentException('dispatchToolCall: tool_call.function.name must be a string');
        }
        $args = self::parseArguments(self::field($fn, 'arguments'));
        $m = $map($name, $args);
        if ($m === null) {
            throw new \RuntimeException("dispatchToolCall: no PCActn for unmapped tool \"$name\" (the mapping declined)");
        }
        if ($failFast && ($why = $agent->envelopeRefusal((string)$m['verb'], (string)$m['resource'], $args)) !== null) {
            throw new \RuntimeException("dispatchToolCall: the grant refuses this call ($why)");
        }
        $pca = $agent->act((string)$m['verb'], (string)$m['resource'], $args === [] ? null : $args);
        $h = $handlers[$name] ?? null;
        $result = $h !== null ? $h($args, $pca) : null;
        $content = json_encode($result ?? ['pca' => $pca->headers[Sign::HEADER]], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        return ['role' => 'tool', 'tool_call_id' => (string)self::field($call, 'id'), 'content' => $content];
    }

    /**
     * Dispatch a model turn's tool calls in order (each act() takes the agent's next counter).
     * @param iterable<mixed> $calls @return list<array{role: 'tool', tool_call_id: string, content: string}>
     */
    public static function dispatchToolCalls(Agent $agent, iterable $calls, callable $map, array $handlers = [], bool $failFast = true): array
    {
        $out = [];
        foreach ($calls as $c) {
            $out[] = self::dispatchToolCall($agent, $c, $map, $handlers, $failFast);
        }
        return $out;
    }
}
