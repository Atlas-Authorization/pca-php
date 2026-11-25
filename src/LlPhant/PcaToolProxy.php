<?php
declare(strict_types=1);

namespace Atlas\Pca\LlPhant;

use Atlas\Pca\Action;
use Atlas\Pca\Agent;

require_once __DIR__ . '/../Agent.php';

/**
 * LLPhant adapter: wrap the object a `FunctionInfo` points at, so every tool the model calls is first signed as a proof-carrying
 * action and checked against the grant. LLPhant runs a tool as `$instance->{$name}(...$arguments)` with the model's named arguments;
 * pass `new FunctionInfo($name, new PcaToolProxy($agent, $tools, $map), ...)` in place of `$tools` and nothing else changes. No
 * LLPhant class is referenced, so the proxy works with any version. This does NOT authorize: it attaches the action and refuses
 * what the grant's own predicates and caveats refuse; the resource server's verifier decides.
 *
 * `$map(string $tool, array $args)` returns ['verb' => ..., 'resource' => ...] or null (declined: a tool we cannot produce a PCActn for
 * is refused, never run). `$onProof(Action $pca, string $tool, array $args)` receives the proof (to put in the call's headers).
 * With `$failFast` (default) a call outside the grant throws and the tool never runs.
 */
final class PcaToolProxy
{
    /** @param callable(string, array<mixed>): ?array{verb: string, resource: string} $map  @param ?callable(Action, string, array<mixed>): void $onProof */
    public function __construct(private readonly Agent $agent, private readonly object $tools, private readonly mixed $map,
                                private readonly mixed $onProof = null, private readonly bool $failFast = true)
    {
    }

    /** @param array<mixed> $args the model's arguments (named: string keys) */
    public function __call(string $name, array $args): mixed
    {
        if (!method_exists($this->tools, $name)) {
            throw new \BadMethodCallException("PcaToolProxy: the tool object has no method \"$name\"");
        }
        $m = ($this->map)($name, $args);
        if ($m === null) {
            throw new \RuntimeException("PcaToolProxy: no PCActn for unmapped tool \"$name\" (the mapping declined)");
        }
        $verb = (string)$m['verb'];
        $resource = (string)$m['resource'];
        $params = $args === [] ? null : $args;
        if ($this->failFast && ($why = $this->agent->envelopeRefusal($verb, $resource, $params)) !== null) {
            throw new \RuntimeException("PcaToolProxy: the grant refuses this call ($why)");
        }
        $pca = $this->agent->act($verb, $resource, $params);
        if ($this->onProof !== null) {
            ($this->onProof)($pca, $name, $args);
        }
        return $this->tools->{$name}(...$args);
    }
}
