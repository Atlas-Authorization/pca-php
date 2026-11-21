<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Facade.php';

use Atlas\Pca\Agent;
use Atlas\Pca\AgentHandle;
use Atlas\Pca\Catalog;
use Atlas\Pca\Facade;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** The agent facade: limit grammar, policy compile, and a signed act that this package's verifier admits. */
final class FacadeTest extends TestCase
{
    private function refuses(string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\InvalidArgumentException $e) {
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("no exception: $msg");
    }

    public function testParseLimit(): void
    {
        self::assertSame(['amount' => 500, 'unit' => 'usd', 'periodMs' => 86400000], Facade::parseLimit('$500/day'));
        self::assertSame(['amount' => 500, 'unit' => 'usd'], Facade::parseLimit(' $ 500 '));
        self::assertSame(['amount' => 1.5, 'unit' => 'usd'], Facade::parseLimit('$1.5'));
        self::assertSame(['amount' => 10, 'unit' => 'count', 'periodMs' => 3600000], Facade::parseLimit('10 / HOUR'));
        self::assertSame(['amount' => 3, 'unit' => 'count', 'periodMs' => 60000], Facade::parseLimit('3/min'));
        self::assertSame(['amount' => 7, 'unit' => 'count'], Facade::parseLimit("\u{A0}7\u{3000}"));
        foreach (['s' => 1000, 'w' => 604800000, 'mo' => 2592000000, 'months' => 2592000000] as $p => $ms) {
            self::assertSame($ms, Facade::parseLimit("1/$p")['periodMs'], $p);
        }
        $this->refuses('parseLimit: empty limit', fn() => Facade::parseLimit('  '));
        $this->refuses('parseLimit: empty limit', fn() => Facade::parseLimit(5));
        $this->refuses('parseLimit: limit is longer than 64 characters', fn() => Facade::parseLimit(str_repeat('1', 65)));
        self::assertSame(['amount' => (int)str_repeat('1', 16), 'unit' => 'count'], Facade::parseLimit(str_repeat('1', 16)));
        $this->refuses("parseLimit: cannot parse limit 'five dollars'", fn() => Facade::parseLimit('five dollars'));
        $this->refuses("parseLimit: cannot parse limit '\$-5'", fn() => Facade::parseLimit('$-5'));
        $this->refuses("parseLimit: unknown period 'fortnight' in '\$5/fortnight'", fn() => Facade::parseLimit('$5/fortnight'));
    }

    public function testCompilePolicy(): void
    {
        $p = Facade::compilePolicy(['stripe' => ['refund'], 'gmail' => ['draft']], ['refund' => '$500/day'], now: 1000);
        self::assertSame([['verb' => 'stripe.refund', 'resource' => '*', 'where' => [['field' => 'action.params.amount', 'op' => 'lte', 'value' => 500],
            ['field' => 'action.params.amount', 'op' => 'gte', 'value' => 0]]], ['verb' => 'gmail.draft', 'resource' => '*']], $p['predicates']);
        self::assertSame([['type' => 'reversibility_max', 'class' => 'irreversible'], ['type' => 'expires', 'at' => 1000 + 86400000]], $p['caveats']);
        self::assertSame('dollars', $p['budgetModel']);
        self::assertSame(500, $p['riskPolicy']['kappa']);
        self::assertSame(['stripe.refund: $500/period is a per-call ceiling plus a one-period grant lifetime, not a renewing window cap'], $p['approximations']);
        $c = Facade::compilePolicy(['slack' => ['post_message']], ['post_message' => '10/hour'], now: 0);
        self::assertSame(['type' => 'rate', 'max' => 10, 'per_secs' => 3600], $c['caveats'][2]);
        self::assertSame('risk', $c['budgetModel']);
        $u = Facade::compilePolicy(['crm' => ['export']], now: 0);
        self::assertSame('irreversible', $u['caveats'][0]['class']);
        $this->refuses('compilePolicy: no permissions granted', fn() => Facade::compilePolicy([], now: 0));
        $this->refuses('compilePolicy: permissions.x must be an array', fn() => Facade::compilePolicy(['x' => 'read'], now: 0));
        $this->refuses("compilePolicy: '\$' limit on 'gmail.send' but the catalog gives that verb no amount field, so the limit could not be enforced",
            fn() => Facade::compilePolicy(['gmail' => ['send']], ['send' => '$10'], now: 0));
        $this->refuses('compilePolicy: derived risk policy invalid: risk_policy.kappa must be > 0',
            fn() => Facade::compilePolicy(['gmail' => ['draft']], null, null, null, ['kappa' => 0], 0));
    }

    public function testCatalogLookups(): void
    {
        $c = new Catalog();
        self::assertSame('stripe.refund', Facade::specFor($c, 'stripe.issue_refund')['verb']);
        self::assertSame('stripe.refund', $c->get('stripe.refund')['verb']);
        self::assertNull($c->get('stripe.issue_refund'));
        $u = Facade::specFor($c, 'crm.export');
        self::assertSame(['crm', 'export', 'irreversible', 0.8], [$u['connector'], $u['action'], $u['reversibility'], $u['blastRadius']]);
        self::assertSame('noconnector', Facade::specFor($c, 'noconnector')['action']);
    }

    public function testAgentActVerifies(): void
    {
        $principal = KeyPair::generate();
        $h = Agent::fromPrincipal(principal: $principal, goal: 'refund order 1', permissions: ['stripe' => ['refund']], limits: ['refund' => '$500/day'],
            aud: 'rs-test', now: 1800000000000);
        self::assertInstanceOf(AgentHandle::class, $h);
        self::assertSame(['B' => 500, 'tau' => 1800000000000, 'asOf' => 1800000000000], $h->budget);
        $h->provenance->principal('refund order 1');
        $r = $h->act('stripe.refund', 'charge:ch_1', ['amount' => 42, 'currency' => 'usd'], now: 1800000000000);
        self::assertSame(1, $r['pcactn']->get('counter')->int());
        self::assertSame(Json::canonicalizeLenient($r['pcactn']), $r['encoded']);
        self::assertSame(['PCA-Action', 'PCA-Provenance'], array_keys($r['headers']));
        self::assertTrue($r['dryRun']['allowed']);
        $v = Pca::verifyPcactnCore($r['pcactn'], $h->grant, 1800000000000, 'rs-test', insecureSkipPlanRootCheck: true);
        self::assertTrue($v['allow'], (string)($v['reason'] ?? ''));
        self::assertFalse($h->dryRun('gmail.send', 'x', null, 1800000000000)['allowed']);
        self::assertSame(5, $h->act('stripe.refund', 'charge:ch_2', ['amount' => 1], counter: 5, now: 1800000000000)['pcactn']->get('counter')->int());
        self::assertSame(6, $h->act('stripe.refund', 'charge:ch_3', ['amount' => 1], now: 1800000000000)['pcactn']->get('counter')->int());
        $sub = $h->subAgent();
        self::assertCount(2, $sub->chain);
        $s = $sub->act('stripe.refund', 'charge:ch_4', ['amount' => 1], now: 1800000000000);
        self::assertTrue(Pca::verifyPcactnCore($s['pcactn'], $h->grant, 1800000000000, 'rs-test', insecureSkipPlanRootCheck: true)['allow']);
        $this->refuses('act: aud (resource-server / instance id) is required (pass aud here or to createAgent)',
            fn() => Facade::createAgent($principal, 'g', ['files' => ['read']])->act('files.read', 'x'));
    }
}
