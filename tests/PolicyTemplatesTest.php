<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PolicyTemplates.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\PolicyBuilder;
use Atlas\Pca\PolicyTemplates;
use PHPUnit\Framework\TestCase;

/** policy-templates.ts: the named templates, fromTemplate and the fluent builder. */
final class PolicyTemplatesTest extends TestCase
{
    public function testListAndUnknown(): void
    {
        self::assertSame(['read-only', 'support-agent', 'finance-bot', 'dev-assistant'], array_column(PolicyTemplates::listTemplates(), 'name'));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("unknown template 'nope' (have: read-only, support-agent, finance-bot, dev-assistant)");
        PolicyTemplates::fromTemplate('nope', KeyPair::generate(), 'g');
    }

    public function testFromTemplateMintsAGrantAndOverridesReplace(): void
    {
        $p = new KeyPair(str_repeat("\1", 32));
        $a = PolicyTemplates::fromTemplate('finance-bot', $p, 'refund orders', 'rs', null, 1800000000000);
        self::assertSame($p->public, $a->grant->get('issuer'));
        self::assertNotEmpty($a->policy['predicates']);
        $b = PolicyTemplates::fromTemplate('finance-bot', $p, 'refund orders', 'rs', null, 1800000000000, ['limits' => ['refund' => '$50/day']]);
        self::assertNotSame($a->policy['limits'] ?? null, $b->policy['limits'] ?? null);
    }

    public function testBuilder(): void
    {
        $b = PolicyTemplates::policy()->allow('stripe', ['refund'])->allow('stripe', ['refund', 'payout'])->limit('refund', '$500/day')->risk(['theta1' => 0.2])->risk(['theta2' => 0.5]);
        self::assertSame(['permissions' => ['stripe' => ['refund', 'payout']], 'limits' => ['refund' => '$500/day'], 'riskPolicy' => ['theta1' => 0.2, 'theta2' => 0.5]], $b->build());
        $seed = PolicyBuilder::from('support-agent')->build();
        self::assertSame(['gmail' => ['draft', 'send'], 'slack' => ['post_message']], $seed['permissions']);
        self::assertSame(['send' => '50/day', 'post_message' => '100/day'], $seed['limits']);
        self::assertArrayNotHasKey('riskPolicy', $seed);
        $h = PolicyBuilder::from('read-only')->agent(new KeyPair(str_repeat("\2", 32)), 'look around', 'rs', null, 1800000000000);
        self::assertNotEmpty($h->policy['predicates']);
        try {
            (new PolicyBuilder())->build();
            self::fail('an empty builder is refused');
        } catch (\LogicException) {
            self::assertTrue(true);
        }
        $this->expectException(\InvalidArgumentException::class);
        PolicyBuilder::from('nope');
    }
}
