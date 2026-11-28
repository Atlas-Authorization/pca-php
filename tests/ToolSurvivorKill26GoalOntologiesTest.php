<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalOntologies.php';
require_once __DIR__ . '/../src/Js.php';

use Atlas\Pca\GoalOntologies as G;
use Atlas\Pca\Js;
use PHPUnit\Framework\TestCase;

/** The shipped ontology lookups (fresh copies, non-string names) and the exact shape of every authoring dsl helper. */
final class ToolSurvivorKill26GoalOntologiesTest extends TestCase
{
    /** A non-string name is unknown (null), never a TypeError from the map lookup; an unknown string is null too. */
    public function testLookupNames(): void
    {
        self::assertNull(G::shippedOntology(5));
        self::assertNull(G::shippedCatalog(5));
        self::assertNull(G::shippedOntology('nope'));
        self::assertSame('payments', G::shippedOntology('payments')->get('domain'), 'control');
    }

    /** Every lookup is a deep copy: mutating a returned object, or an object inside a returned list, never leaks into the next lookup. */
    public function testLookupsAreDeepCopies(): void
    {
        $a = G::shippedOntology('calendar_travel');
        $a->set('domain', 'changed');
        $a->get('types')[0]->set('id', 'changed');
        $b = G::shippedOntology('calendar_travel');
        self::assertSame('calendar_travel', $b->get('domain'));
        self::assertSame('trip', $b->get('types')[0]->get('id'));
    }

    /** The per-domain shortcuts are public and return their own domain. */
    public function testDomainShortcuts(): void
    {
        self::assertSame('payments', G::payments()->get('domain'));
        self::assertSame('email', G::email()->get('domain'));
        self::assertSame('calendar_travel', G::travel()->get('domain'));
        self::assertSame('code_repos', G::code()->get('domain'));
        self::assertSame('data_access', G::data()->get('domain'));
    }

    /** Condition helpers build the exact IR nodes of the reference dsl. */
    public function testConditionHelpers(): void
    {
        self::assertSame('{"k":"true"}', Js::stringify(G::t()));
        self::assertSame('{"k":"cmp","op":"lt","l":{"k":"param","path":"amount"},"r":{"k":"slot","slot":"max"}}',
            Js::stringify(G::cmp('lt', 'amount', 'max')));
        self::assertSame('{"k":"cmp","op":"eq","l":{"k":"param","path":"to"},"r":{"k":"lit","v":{"k":"s","s":"x"}}}',
            Js::stringify(G::cmpEnum('eq', 'to', 'x')));
        self::assertSame('{"k":"cmp","op":"in","l":{"k":"param","path":"d"},"r":{"k":"lit","v":{"k":"set","items":[{"k":"s","s":"X"},{"k":"s","s":"Y"}]}}}',
            Js::stringify(G::inEnum('d', ['a' => 'X', 'b' => 'Y'])));
    }

    /** `and` left-folds; one argument is returned as is; no argument throws the reference's reduce error. */
    public function testAndFold(): void
    {
        $a = G::exact('a');
        self::assertSame($a, G::and($a));
        self::assertSame('{"k":"and","a":{"k":"and","a":{"k":"true"},"b":{"k":"exact","id":"$a"}},"b":{"k":"exact","id":"$b"}}',
            Js::stringify(G::and(G::t(), $a, G::exact('b'))));
        try {
            G::and();
            self::fail('no throw');
        } catch (\TypeError $e) {
            self::assertSame('Reduce of empty array with no initial value', $e->getMessage());
        }
    }

    /** Resource helpers: `$`-prefixed slot references, and `all_of` parts as a list even when passed by name. */
    public function testResourceHelpers(): void
    {
        self::assertSame('{"k":"exact","id":"$r"}', Js::stringify(G::exact('r')));
        self::assertSame('{"k":"related","rel":"owns","anchor":"$a"}', Js::stringify(G::related('owns', 'a')));
        self::assertSame('{"k":"all_of","parts":[{"k":"exact","id":"$x"},{"k":"exact","id":"$y"}]}',
            Js::stringify(G::both(p: G::exact('x'), q: G::exact('y'))));
    }

    /** Grants default to the true condition and keep a given one; bans are one blanket prohibition per verb, as a list. */
    public function testGrantAndBan(): void
    {
        self::assertSame('{"gid":"g","verb":"v","res":{"k":"exact","id":"$r"},"cond":{"k":"true"}}',
            Js::stringify(G::grant('g', 'v', G::exact('r'))));
        self::assertSame('{"gid":"g","verb":"v","res":{"k":"exact","id":"$r"},"cond":{"k":"exact","id":"$c"}}',
            Js::stringify(G::grant('g', 'v', G::exact('r'), G::exact('c'))));
        self::assertSame('[{"pid":"no-send","target":{"k":"verb","verb":"send"},"res":{"k":"any","reason":"blanket"},"cond":{"k":"true"}},'
            . '{"pid":"no-pay","target":{"k":"verb","verb":"pay"},"res":{"k":"any","reason":"blanket"},"cond":{"k":"true"}}]',
            Js::stringify(G::ban(a: 'send', b: 'pay')));
    }

    /** Budget helpers: cap_slot only for a non-empty slot; a sum cap is in the money unit with n 0. */
    public function testBudgetHelpers(): void
    {
        $base = '{"bid":"b","agg":"count","over":"x","cap":{"u":{"k":"count"},"n":3},"onExceed":"deny"';
        self::assertSame($base . '}', Js::stringify(G::countCap('b', 'x', 3)));
        self::assertSame($base . '}', Js::stringify(G::countCap('b', 'x', 3, '')));
        self::assertSame($base . ',"cap_slot":"s"}', Js::stringify(G::countCap('b', 'x', 3, 's')));
        self::assertSame('{"bid":"b","agg":"sum","over":["x"],"param":"amount","cap":{"u":{"k":"money","ccy":"USD"},"n":0},"onExceed":"deny","cap_slot":"cap"}',
            Js::stringify(G::sumCap('b', ['x'], 'amount', 'USD', 'cap')));
    }

    /** The money units: USD, EUR and GBP have exponent 2, JPY 0. */
    public function testUnitsMoney(): void
    {
        self::assertSame('{"USD":{"kind":"money","exponent":2},"EUR":{"kind":"money","exponent":2},"GBP":{"kind":"money","exponent":2},"JPY":{"kind":"money","exponent":0}}',
            Js::stringify(G::unitsMoney()));
    }
}
