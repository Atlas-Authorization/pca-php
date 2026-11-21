<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Decide.php';
require_once __DIR__ . '/../src/Authorize.php';
require_once __DIR__ . '/../src/Predicates.php';

use Atlas\Pca\Authorize;
use Atlas\Pca\Decide;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/** policy-vm.ts / predicates.ts public helpers: toolCallOf, agentCaveatContext, resolveReversibilityClass, namedUnmetLimitReason. */
final class PolicyVmSmallTest extends TestCase
{
    public function testToolCallOfAndAgentContext(): void
    {
        $a = Json::parseLax('{"action":{"verb":"pay","resource":"acct","params":{"amount":10}},"toolBinding":"dig"}');
        $t = Authorize::toolCallOf($a);
        self::assertSame('pay', $t['tool']);
        self::assertSame('dig', $t['toolSignatureDigest']);
        self::assertInstanceOf(Obj::class, $t['args']);
        $bare = Authorize::toolCallOf(Json::parseLax('{"action":{"verb":5,"params":[1]}}'));
        self::assertSame('', $bare['tool']);
        self::assertSame([], $bare['args']->keys());
        self::assertArrayNotHasKey('toolSignatureDigest', $bare);
        $base = Json::parseLax('{"now":5,"action":{"verb":"evil"}}');
        [$ctx, $call] = Authorize::agentCaveatContext($base, $a);
        self::assertSame('pay', $ctx->get('action')->get('verb'), 'the derived action wins');
        self::assertSame('evil', $base->get('action')->get('verb'), 'the base is not mutated');
        self::assertSame('pay', $call['tool']);
    }

    public function testResolveReversibilityClass(): void
    {
        $own = Json::parseLax('{"reversibility_class":"costly"}');
        $none = Json::parseLax('{}');
        $plan = Json::parseLax('[{"id":"a","reversibility_class":"reversible"},{"id":"b"}]');
        self::assertSame('costly', Decide::resolveReversibilityClass($own, $plan, 'a'));
        self::assertSame('reversible', Decide::resolveReversibilityClass($none, $plan, 'a'));
        self::assertNull(Decide::resolveReversibilityClass($none, $plan, 'b'));
        self::assertNull(Decide::resolveReversibilityClass($none, $plan, 'zz'));
        self::assertNull(Decide::resolveReversibilityClass($none, $plan, null));
        self::assertNull(Decide::resolveReversibilityClass(null, null, 'a'));
    }

    public function testNamedUnmetLimitReason(): void
    {
        $ctx = Json::parseLax('{"action":{"verb":"pay","resource":"acct","params":{"amount":10}}}');
        $over = Json::parseLax('[{"verb":"pay","resource":"acct","where":[{"field":"action.params.amount","op":"lte","value":5}]}]');
        self::assertSame('amount <= 5 not satisfied for pay on acct', Predicates::namedUnmetLimitReason($over, $ctx));
        $fits = Json::parseLax('[{"verb":"pay","resource":"acct","where":[{"field":"action.params.amount","op":"lte","value":50}]}]');
        self::assertNull(Predicates::namedUnmetLimitReason($fits, $ctx));
        self::assertNull(Predicates::namedUnmetLimitReason('nope', $ctx));
        self::assertNull(Predicates::namedUnmetLimitReason(Json::parseLax('[{"verb":"other","where":[]}]'), $ctx));
    }
}
