<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsDerive.php';
require_once __DIR__ . '/../src/ActionsBuiltin.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsBuiltin;
use Atlas\Pca\ActionsDerive as D;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Derived views of a def: clamps, the schema verb, the card text, role lookups, the schema doc, operations, risk, predicates, ontology params. */
final class ToolSurvivorKill26ActionsDeriveTest extends TestCase
{
    private static function j(string $s): mixed
    {
        return Json::parseStrict($s);
    }

    private static function def(string $verb): Obj
    {
        foreach (ActionsBuiltin::builtinDefs() as $d) {
            if ($d->get('verb') === $verb) {
                return Json::parseStrict(Js::stringify($d));
            }
        }
        throw new \LogicException("no def $verb");
    }

    private static function err(callable $f): string
    {
        try {
            $f();
        } catch (ActionKitError $e) {
            return $e->codeName . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    private static function meta(): Obj
    {
        return Obj::of(['site' => 'https://example.invalid', 'aud' => 'example', 'version' => '0']);
    }

    /** A declared blast below the hint floor is reported as a blast_ppm clamp. */
    public function testBlastClamp(): void
    {
        $d = self::def('stripe.charge');
        $d->set('blast', self::j('{"radius":"one","ppm":1000}'));
        self::assertSame([['field' => 'blast_ppm', 'declared' => 50000, 'floor' => 700000]], D::effectiveWith($d, Actions::coreRegistry())['clamps']);
    }

    /** The unit id of a money param lowercases its currency Unicode-aware. */
    public function testUnitIdLowercase(): void
    {
        $d = self::def('stripe.charge');
        $d->get('params')->get('amount')->get('unit')->set('ccy', "\u{C9}UR");
        self::assertSame(["money.\u{e9}ur"], D::toSchemaVerb($d, Actions::coreRegistry())->get('units')->keys());
    }

    /** A def without a review block derives a schema verb (no confirmation). */
    public function testNoReview(): void
    {
        $v = D::toSchemaVerb(self::def('stripe.charge')->without('review'), Actions::coreRegistry())->get('verb');
        self::assertFalse($v->has('confirmation'));
        self::assertSame('stripe.charge', $v->get('verb'));
    }

    /** A param-dependent reversibility becomes reversibility_by with the param path, the map and the default only when declared. */
    public function testReversibilityBy(): void
    {
        $d = self::def('stripe.charge');
        $d->get('params')->set('mode', self::j('{"type":"string","values":["a","b"]}'));
        $d->set('reversibility', self::j('{"by":"mode","map":{"a":"reversible","b":"irreversible"},"default":"rate_limited"}'));
        $v = D::toSchemaVerb($d, Actions::coreRegistry())->get('verb');
        self::assertFalse($v->has('reversibility'));
        self::assertSame('{"param":"action.params.mode","map":{"a":"reversible","b":"irreversible"},"default":"rate_limited"}', Js::stringify($v->get('reversibility_by')));
        $d->set('reversibility', self::j('{"by":"mode","map":{"a":"reversible","b":"irreversible"}}'));
        self::assertSame('{"param":"action.params.mode","map":{"a":"reversible","b":"irreversible"}}',
            Js::stringify(D::toSchemaVerb($d, Actions::coreRegistry())->get('verb')->get('reversibility_by')));
    }

    /** MCP and OpenAPI bindings keep only the tool / operationId; an empty binding stays an empty object. */
    public function testBindings(): void
    {
        $d = self::def('stripe.charge');
        $d->set('bindings', self::j('{"mcp":{"tool":"t"},"openapi":{"operationId":"op","method":"GET","path":"/x"}}'));
        $v = D::toSchemaVerb($d, Actions::coreRegistry())->get('verb');
        self::assertSame('{"tool":"t"}', Js::stringify($v->get('mcp')));
        self::assertSame('{"operationId":"op"}', Js::stringify($v->get('openapi')));
        $d->set('bindings', self::j('{"mcp":{},"openapi":{}}'));
        $v = D::toSchemaVerb($d, Actions::coreRegistry())->get('verb');
        self::assertSame('{}', Js::stringify($v->get('mcp')));
        self::assertSame('{}', Js::stringify($v->get('openapi')));
    }

    /** No effects is not read-only: the effect class comes from the reversibility. */
    public function testNoEffectsIsNotReadOnly(): void
    {
        $d = self::def('stripe.charge');
        $d->set('effects', []);
        self::assertSame('irreversible', D::effectClass($d));
    }

    /** The card title gets a full stop unless it already ends with one of . ! ? */
    public function testCardSentence(): void
    {
        $d = self::def('stripe.charge');
        $eff = D::effectiveWith($d, Actions::coreRegistry());
        $d->set('title', 'Hi!');
        self::assertStringStartsWith('Hi! This action', D::cardOf($d, $eff, Actions::coreRegistry())->get('text'));
        $d->set('title', 'Hi');
        self::assertStringStartsWith('Hi. This action', D::cardOf($d, $eff, Actions::coreRegistry())->get('text'));
    }

    /** Card phrases shared by two traits are listed once, in risk order. */
    public function testCardPhrasesDistinct(): void
    {
        $reg = Actions::coreRegistry();
        $reg['pca.money_moving']['card_phrase'] = $reg['pca.destructive']['card_phrase'];
        $d = self::def('stripe.charge');
        $eff = D::effectiveWith($d, Actions::coreRegistry());
        $eff['traits'] = ['pca.destructive', 'pca.irreversible', 'pca.money_moving'];
        $eff['confirmed'] = true;
        self::assertSame('Charge a customer. This action deletes or destroys data and cannot be undone.', D::cardOf($d, $eff, $reg)->get('text'));
    }

    /** paramByRole refuses a missing and an ambiguous role with the verb in the message. */
    public function testParamByRole(): void
    {
        $d = self::def('stripe.charge');
        self::assertSame('amount', D::paramByRole($d, 'money.amount'), 'control');
        self::assertSame("no_param: 'stripe.charge' has no parameter with role money.fee", self::err(fn() => D::paramByRole($d, 'money.fee')));
        $d->get('params')->set('amount2', self::j('{"type":"integer","role":"money.amount"}'));
        self::assertSame("ambiguous_param: 'stripe.charge' has several parameters with role money.amount", self::err(fn() => D::paramByRole($d, 'money.amount')));
    }

    /** The schema doc refuses a verb given twice and a unit redefined with another exponent. */
    public function testSchemaDocRefusals(): void
    {
        $d = self::def('stripe.charge');
        $reg = Actions::coreRegistry();
        self::assertSame("duplicate_verb: verb 'stripe.charge' appears twice", self::err(fn() => D::toSchemaDoc([$d, $d], $reg, self::meta())));
        $e = self::def('stripe.charge');
        $e->set('verb', 'stripe.charge2');
        $e->get('params')->get('amount')->get('unit')->set('exp', new Num('0'));
        self::assertSame("unit_conflict: unit 'money.usd' is declared with two different definitions", self::err(fn() => D::toSchemaDoc([$d, $e], $reg, self::meta())));
    }

    /** Custom traits are carried as trait objects sorted by id. */
    public function testSchemaDocCustomTraits(): void
    {
        $reg = Actions::coreRegistry();
        $floor = $reg['pca.bulk']['floor'];
        $reg['zeta.b'] = ['id' => 'zeta.b', 'implies' => [], 'floor' => $floor, 'card_phrase' => 'b'];
        $reg['acme.a'] = ['id' => 'acme.a', 'implies' => [], 'floor' => $floor, 'card_phrase' => 'a'];
        $doc = D::toSchemaDoc([self::def('stripe.charge')], $reg, self::meta());
        $tds = $doc->get('trait_defs');
        self::assertCount(2, $tds);
        self::assertInstanceOf(Obj::class, $tds[0]);
        self::assertSame(['acme.a', 'zeta.b'], [$tds[0]->get('id'), $tds[1]->get('id')]);
    }

    /** An exact resource id names the resource as type:exact, in operations and in the matcher. */
    public function testExactResource(): void
    {
        $d = self::def('gmail.delete');
        $d->get('resource')->set('id', Obj::of(['exact' => 'only']));
        $op = D::operationOf($d, self::j('{"params":{"message":"m1"}}'));
        self::assertTrue($op['ok']);
        self::assertSame('gmail.message:only', $op['op']->get('resource'));
        self::assertSame('gmail.message:only', D::resourceMatcher($d));
    }

    /** With two id params of the resource type, the first in key order names the resource. */
    public function testFirstIdParam(): void
    {
        $d = self::def('gmail.delete');
        $d->get('params')->set('b2', self::j('{"type":"string","role":"id.gmail.message"}'));
        $op = D::operationOf($d, self::j('{"params":{"message":"m1","b2":"x2"}}'));
        self::assertSame('gmail.message:x2', $op['op']->get('resource'));
    }

    /** Blast from the amount: 0 is a valid amount (blast 0); a zero kappa is invalid (worst case 1). */
    public function testRiskBlast(): void
    {
        $d = self::def('stripe.charge');
        $eff = D::effectiveWith($d, Actions::coreRegistry());
        self::assertSame(0.0, D::riskOf($d, $eff, self::j('{"amount":0}'), self::j('{"kappa":100}'))['blastRadius']);
        self::assertSame(0.5, D::riskOf($d, $eff, self::j('{"amount":50}'), self::j('{"kappa":100}'))['blastRadius'], 'control');
        self::assertSame(1, D::riskOf($d, $eff, self::j('{"amount":5}'), self::j('{"kappa":0}'))['blastRadius']);
    }

    /** max_amount must be a non-negative safe integer: -0 and a non-number refuse, the largest safe integer is accepted. */
    public function testPredicateLimit(): void
    {
        $d = self::def('stripe.charge');
        $bad = 'bad_limit: max_amount must be a non-negative safe integer';
        self::assertSame($bad, self::err(fn() => D::predicatesOf($d, self::j('{"max_amount":-0}'))));
        self::assertSame($bad, self::err(fn() => D::predicatesOf($d, self::j('{"max_amount":"x"}'))));
        $p = D::predicatesOf($d, self::j('{"max_amount":9007199254740991}'));
        self::assertSame('9007199254740991', $p->get('where')[0]->get('value')->lexeme);
    }

    private static function ont(Obj $d, string $p): string
    {
        return Js::stringify((new \ReflectionMethod(D::class, 'ontParam'))->invoke(null, $d, self::j($p)));
    }

    /** Ontology terms of params: a currency param's values (sorted), id formats, and one kind per declared type. */
    public function testOntParam(): void
    {
        $d = self::j('{"params":{"cur":{"type":"string","values":["USD","EUR"]},"bare":{"type":"string"}}}');
        self::assertSame('{"kind":"money","ccys":["EUR","USD"]}', self::ont($d, '{"unit":{"kind":"money","ccy":{"from":"cur"}}}'));
        self::assertSame('{"kind":"money","ccys":[]}', self::ont($d, '{"unit":{"kind":"money","ccy":{"from":"bare"}}}'));
        self::assertSame('{"kind":"money","ccys":[]}', self::ont($d, '{"unit":{"kind":"money","ccy":{"from":"zz"}}}'));
        self::assertSame('{"kind":"id","of":"foo"}', self::ont($d, '{"type":"string","format":"id:foo"}'));
        self::assertSame('{"kind":"duration"}', self::ont($d, '{"type":"duration"}'));
        self::assertSame('{"kind":"instant"}', self::ont($d, '{"type":"datetime"}'));
        self::assertSame('{"kind":"instant"}', self::ont($d, '{"type":"date"}'));
        self::assertSame('{"kind":"count"}', self::ont($d, '{"type":"integer"}'));
        self::assertSame('{"kind":"enum","values":["false","true"]}', self::ont($d, '{"type":"boolean"}'));
        self::assertSame('{"kind":"enum","values":["a","b"]}', self::ont($d, '{"type":"set","values":["b","a"]}'));
        self::assertSame('{"kind":"enum","values":[]}', self::ont($d, '{"type":"set"}'));
        self::assertSame('{"kind":"text"}', self::ont($d, '{"type":"array"}'));
    }
}
