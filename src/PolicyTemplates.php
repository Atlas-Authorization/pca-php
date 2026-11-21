<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Facade.php';

/**
 * Policy templates and the fluent builder (policy-templates.ts): a request maps onto a named ROLE template or is composed with a typed
 * builder, both compiled through {@see Facade::createAgent}, so what you author is exactly what the verifier enforces. Pure.
 */
final class PolicyTemplates
{
    /**
     * Built-in role templates: conservative starting points, meant to be narrowed, not widened. Each: name, description, permissions
     * (`connector => [action...]`) and optional limits (`action => '$N/period' | 'N/period'`) and riskPolicy.
     * @var array<string,array{name:string,description:string,permissions:array<string,list<string>>,limits?:array<string,string>,riskPolicy?:array<string,mixed>}>
     */
    public const TEMPLATES = [
        'read-only' => ['name' => 'read-only', 'description' => 'Read access only — no side effects anywhere.',
            'permissions' => ['github' => ['read'], 'slack' => ['read'], 'files' => ['read'], 'http' => ['get']]],
        'support-agent' => ['name' => 'support-agent', 'description' => 'Draft + send customer email and post to Slack, rate-limited.',
            'permissions' => ['gmail' => ['draft', 'send'], 'slack' => ['post_message']], 'limits' => ['send' => '50/day', 'post_message' => '100/day']],
        'finance-bot' => ['name' => 'finance-bot', 'description' => 'Issue reversible refunds within a daily cap; no payouts.',
            'permissions' => ['stripe' => ['refund']], 'limits' => ['refund' => '$500/day']],
        'dev-assistant' => ['name' => 'dev-assistant', 'description' => 'Read repos, open PRs and comment — never merge or delete.',
            'permissions' => ['github' => ['read', 'create_pr', 'comment']], 'limits' => ['create_pr' => '20/day']],
    ];

    /** @return list<array<string,mixed>> the built-in templates in registry order */
    public static function listTemplates(): array
    {
        return array_values(self::TEMPLATES);
    }

    /**
     * Mint an agent from a named template (fromTemplate). `$overrides` (any of permissions, limits, riskPolicy, agentBinding, budgetModel)
     * replace the template's value. Throws on an unknown template.
     * @param array<string,mixed> $overrides
     */
    public static function fromTemplate(string $name, KeyPair $principal, string $goal, ?string $aud = null, ?KeyPair $holder = null, ?int $now = null,
                                        array $overrides = []): AgentHandle
    {
        $t = self::TEMPLATES[$name] ?? null;
        if ($t === null) {
            throw new \InvalidArgumentException("fromTemplate: unknown template '$name' (have: " . implode(', ', array_keys(self::TEMPLATES)) . ')');
        }
        return Facade::createAgent($principal, $goal, $overrides['permissions'] ?? $t['permissions'], $overrides['limits'] ?? ($t['limits'] ?? null), $holder,
            $overrides['agentBinding'] ?? null, $overrides['riskPolicy'] ?? ($t['riskPolicy'] ?? null), $overrides['budgetModel'] ?? null, null, $aud, $now);
    }

    /** Entry point of the fluent builder (`policy()`). */
    public static function policy(): PolicyBuilder
    {
        return new PolicyBuilder();
    }
}

/** A chainable policy builder: `PolicyTemplates::policy()->allow('stripe', ['refund'])->limit('refund', '$500/day')->build()`. */
final class PolicyBuilder
{
    /** @var array<string,list<string>> */
    private array $perms = [];
    /** @var array<string,string> */
    private array $lims = [];
    /** @var array<string,mixed>|null */
    private ?array $riskOverride = null;

    /** Start from a named template (its permissions, limits and risk seed the builder). */
    public static function from(string $name): self
    {
        $t = PolicyTemplates::TEMPLATES[$name] ?? throw new \InvalidArgumentException("PolicyBuilder.from: unknown template '$name'");
        $b = new self();
        foreach ($t['permissions'] as $c => $acts) {
            $b->allow($c, $acts);
        }
        foreach ($t['limits'] ?? [] as $k => $v) {
            $b->limit($k, $v);
        }
        if (isset($t['riskPolicy'])) {
            $b->risk($t['riskPolicy']);
        }
        return $b;
    }

    /** @param list<string> $actions */
    public function allow(string $connector, array $actions): self
    {
        $this->perms[$connector] = array_values(array_unique(array_merge($this->perms[$connector] ?? [], $actions)));
        return $this;
    }

    public function limit(string $verbOrAction, string $spec): self
    {
        $this->lims[$verbOrAction] = $spec;
        return $this;
    }

    /** @param array<string,mixed> $partial */
    public function risk(array $partial): self
    {
        $this->riskOverride = array_merge($this->riskOverride ?? [], $partial);
        return $this;
    }

    /** @return array{permissions:array<string,list<string>>,limits:array<string,string>,riskPolicy?:array<string,mixed>} */
    public function build(): array
    {
        if ($this->perms === []) {
            throw new \LogicException('PolicyBuilder: no permissions added');
        }
        $out = ['permissions' => $this->perms, 'limits' => $this->lims];
        if ($this->riskOverride !== null) {
            $out['riskPolicy'] = $this->riskOverride;
        }
        return $out;
    }

    /** Mint an agent directly from the built policy. */
    public function agent(KeyPair $principal, string $goal, ?string $aud = null, ?KeyPair $holder = null, ?int $now = null): AgentHandle
    {
        $b = $this->build();
        return Facade::createAgent($principal, $goal, $b['permissions'], $b['limits'], $holder, null, $b['riskPolicy'] ?? null, null, null, $aud, $now);
    }
}
