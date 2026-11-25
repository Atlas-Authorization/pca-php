<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';

/**
 * Generic structural tool wrapper (the LlamaIndex adapter's shape, no framework import): wrap any object with a `metadata` member and a
 * `call($input)` method so each call first signs a proof-carrying action (and, with failFast, refuses a call outside the grant before the
 * tool runs), hands the proof to `onProof`, then runs the original. Every other member of the tool passes through. This does NOT
 * authorize: it attaches the action; the resource server's verifier decides.
 *
 * `$spec`: verb (string), resource (string, or callable(array $args): string), failFast (bool, default true), onProof (callable(Action, array $args)).
 *
 * shortcut: the spec's per-call `aud` of the reference is not offered (the agent's audience is used); pass an agent built for the target.
 */
final class GuardedTool
{
    public readonly mixed $metadata;

    /** @param array{verb: string, resource: string|callable, failFast?: bool, onProof?: callable} $spec */
    public function __construct(private readonly Agent $agent, private readonly array $spec, private readonly object $tool)
    {
        if (!method_exists($tool, 'call')) {
            throw new \TypeError('GuardedTool: the wrapped tool has no call() method');
        }
        $this->metadata = $tool->metadata ?? null;
    }

    /** @param array{verb: string, resource: string|callable, failFast?: bool, onProof?: callable} $spec */
    public static function withPca(Agent $agent, array $spec, object $tool): self
    {
        return new self($agent, $spec, $tool);
    }

    public function call(mixed $input = []): mixed
    {
        $args = is_array($input) ? $input : [];
        $res = $this->spec['resource'];
        $resource = is_callable($res) ? (string)$res($args) : (string)$res;
        $verb = (string)$this->spec['verb'];
        $params = $args === [] ? null : $args;
        if (($this->spec['failFast'] ?? true) && ($why = $this->agent->envelopeRefusal($verb, $resource, $params)) !== null) {
            throw new \RuntimeException("GuardedTool: the grant refuses this call ($why)");
        }
        $pca = $this->agent->act($verb, $resource, $params);
        if (isset($this->spec['onProof'])) {
            ($this->spec['onProof'])($pca, $args);
        }
        return $this->tool->call($input);
    }

    /** Any other method of the tool. @param array<mixed> $args */
    public function __call(string $name, array $args): mixed
    {
        return $this->tool->{$name}(...$args);
    }

    public function __get(string $name): mixed
    {
        return $this->tool->{$name};
    }
}
