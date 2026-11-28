<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsAuthor;
use Atlas\Pca\ActionsRulesValidate;
use Atlas\Pca\ActionsYamlError;
use Atlas\Pca\ActionsYamlLoad;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsAuthor.php';

/** Authoring shorthands, entry expansion and the document loaders of ActionsAuthor: exact expansions and exact refusals. */
final class SchemaSurvivorKill12AuthorTest extends TestCase
{
    private const PAY = '{"v":1,"kind":"pca-action-def","verb":"acme.pay.send","aliases":["charge_customer","bill"],"title":"Charge a customer","description":"Charge a customer. Refundable in practice, but a charge is treated as final.","effects":["pay"],"resource":{"type":"stripe.customer","id":{"prefix":"cus_","class":"any_safe","len":[8,64]},"scope":"one"},"params":{"amount":{"type":"integer","role":"money.amount","min":1,"max":100000000,"unit":{"kind":"money","ccy":{"from":"currency"},"exp":2}},"currency":{"type":"string","role":"money.currency","format":"iso_currency","values":["USD","EUR","GBP"],"max_len":3},"to":{"type":"string","role":"contact.email","format":"email","max_len":254},"cc":{"type":"array","items":"string","max_items":3},"many":{"type":"array","items":"string","max_items":200},"customer":{"type":"string","role":"id.acme.customer","max_len":64},"note":{"type":"string","max_len":100,"required":false},"count":{"type":"integer","min":0,"max":9},"idempotency_key":{"type":"string","max_len":128}},"reversibility":"irreversible","blast":{"radius":"tenant","ppm":900000},"idempotency":{"mode":"key_param","param":"idempotency_key"},"review":{"state":"authored"},"since":"0.5.0"}';

    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    private static function c(mixed $v): string
    {
        return Json::canonicalizeStrict($v);
    }

    /** The PAY def as a shorthand-form entry (no v, kind or since). */
    private static function payEntry(): Obj
    {
        return self::j(self::PAY)->without('v', 'kind', 'since');
    }

    private function refusal(callable $f, string $code = 'bad_shorthand'): string
    {
        try {
            $f();
        } catch (ActionKitError $e) {
            $this->assertSame($code, $e->codeName, $e->getMessage());
            return $e->getMessage();
        }
        $this->fail("no $code refusal");
    }

    private static function p(string $s): string
    {
        return self::c(ActionsAuthor::parseParamShorthand($s));
    }

    private function pErr(string $s): string
    {
        return $this->refusal(static fn() => ActionsAuthor::parseParamShorthand($s));
    }

    // ---- param shorthands --------------------------------------------------------------------------------------------------

    /** Every argument-free shorthand expands to its exact param; `?` makes it optional. */
    public function testBareShorthands(): void
    {
        $this->assertSame('{"format":"email","max_len":254,"role":"contact.email","tags":["pii"],"type":"string"}', self::p('email'));
        $this->assertSame('{"format":"phone_e164","max_len":16,"role":"contact.phone","tags":["pii"],"type":"string"}', self::p('phone'));
        $this->assertSame('{"format":"url","max_len":2048,"role":"url.target","type":"string"}', self::p('url'));
        $this->assertSame('{"format":"uuid","max_len":36,"type":"string"}', self::p('uuid'));
        $this->assertSame('{"format":"iso_currency","max_len":3,"role":"money.currency","type":"string"}', self::p('ccy'));
        $this->assertSame('{"format":"iso_country","max_len":2,"type":"string"}', self::p('country'));
        $this->assertSame('{"max_len":512,"role":"credential.secret","tags":["secret"],"type":"string"}', self::p('secret'));
        $this->assertSame('{"type":"boolean"}', self::p('bool'));
        $this->assertSame('{"type":"date"}', self::p('date'));
        $this->assertSame('{"type":"datetime"}', self::p('datetime'));
        $this->assertSame('{"max_len":64,"role":"id.user","type":"string"}', self::p('id:user'));
        $this->assertSame('{"format":"email","max_len":254,"required":false,"role":"contact.email","tags":["pii"],"type":"string"}', self::p(' email? '));
    }

    /** An argument-free shorthand given arguments is refused by name. */
    public function testBareShorthandsTakeNoArguments(): void
    {
        foreach (['email', 'phone', 'url', 'uuid', 'ccy', 'country', 'secret', 'bool', 'date', 'datetime', 'id:user'] as $n) {
            $this->assertSame("'$n' takes no arguments", $this->pErr("$n(x)"));
        }
    }

    /** Unknown or malformed shorthands are refused with the source or the name. */
    public function testUnknownShorthands(): void
    {
        $this->assertSame("unknown param shorthand 'Email'", $this->pErr('Email'));
        $this->assertSame("unknown param shorthand 'foo'", $this->pErr('foo'));
    }

    /** duration, text/string and message: the optional size, the one-argument limit, and integer checking. */
    public function testSizedShorthands(): void
    {
        $this->assertSame('{"type":"duration"}', self::p('duration'));
        $this->assertSame('{"max":5000,"min":0,"type":"duration"}', self::p('duration(5000)'));
        $this->assertSame("'duration' takes at most 1 positional argument(s)", $this->pErr('duration(1,2)'));
        $this->assertSame("'duration' has no option 'x'", $this->pErr('duration(x=1)'));
        $this->assertSame("duration max (ms) must be an integer, got 'abc'", $this->pErr('duration(abc)'));
        $this->assertSame("duration max (ms) must be an integer, got '=5'", $this->pErr('duration(=5)'));
        $this->assertSame('{"type":"string"}', self::p('text'));
        $this->assertSame('{"max_len":80,"type":"string"}', self::p('text(80)'));
        $this->assertSame('{"max_len":5,"type":"string"}', self::p('string(5)'));
        $this->assertSame("'text' takes at most 1 positional argument(s)", $this->pErr('text(1,2)'));
        $this->assertSame("'string' takes at most 1 positional argument(s)", $this->pErr('string(1,2)'));
        $this->assertSame('{"max_len":1024,"role":"text.message","tags":["free_text_outbound"],"type":"string"}', self::p('message'));
        $this->assertSame('{"max_len":200,"role":"text.message","tags":["free_text_outbound"],"type":"string"}', self::p('message(200)'));
        $this->assertSame("'message' takes at most 1 positional argument(s)", $this->pErr('message(1,2)'));
    }

    /** int, count: ranges, defaults and refusals. */
    public function testIntegerShorthands(): void
    {
        $this->assertSame('{"type":"integer"}', self::p('int'));
        $this->assertSame('{"max":100,"min":3,"type":"integer"}', self::p('int(3..100)'));
        $this->assertSame('{"max":5,"min":-5,"type":"integer"}', self::p('int(-5..5)'));
        $this->assertSame('int takes MIN..MAX, for example int(0..100)', $this->pErr('int(5)'));
        $this->assertSame("'int' takes at most 1 positional argument(s)", $this->pErr('int(1..2,3)'));
        $this->assertSame('{"min":1,"role":"count.limit","type":"integer","unit":{"kind":"count"}}', self::p('count'));
        $this->assertSame('{"max":10,"min":1,"role":"count.limit","type":"integer","unit":{"kind":"count"}}', self::p('count(10)'));
        $this->assertSame("'count' takes at most 1 positional argument(s)", $this->pErr('count(1,2)'));
    }

    /** money: literal or param currency, every option, its defaults, and each refusal. */
    public function testMoneyShorthand(): void
    {
        $this->assertSame('{"min":1,"provenance_min":"first_party","role":"money.amount","type":"integer","unit":{"ccy":"USD","exp":2,"kind":"money"}}', self::p('money(USD)'));
        $this->assertSame('{"max":500,"min":5,"provenance_min":"agent","role":"money.amount","type":"integer","unit":{"ccy":{"from":"cur"},"exp":0,"kind":"money"}}',
            self::p('money(@cur, max=500, min=5, exp=0, provenance=agent)'));
        $this->assertSame('{"max":5,"min":1,"provenance_min":"first_party","role":"money.amount","type":"integer","unit":{"ccy":"USD","exp":2,"kind":"money"}}', self::p('money(USD,,max=5)'));
        $this->assertSame('{"max":50,"min":1,"provenance_min":"first_party","role":"money.amount","type":"integer","unit":{"ccy":"USD","exp":2,"kind":"money"}}', self::p('money( USD , max = 50 )'));
        $this->assertSame('money needs a currency: money(USD) or money(@currency_param)', $this->pErr('money'));
        $this->assertSame('money provenance must be one of first_party, tool, agent', $this->pErr('money(USD, provenance=bot)'));
        $this->assertSame("'money' takes at most 1 positional argument(s)", $this->pErr('money(USD,EUR)'));
        $this->assertSame("'money' has no option 'foo'", $this->pErr('money(USD, foo=1)'));
        $this->assertSame("money max must be an integer, got 'x'", $this->pErr('money(USD, max=x)'));
    }

    /** enum / set values are trimmed and all kept; an empty value or no values are refused. */
    public function testEnumAndSet(): void
    {
        $this->assertSame('{"type":"string","values":["a","b"]}', self::p('enum( a | b )'));
        $this->assertSame('{"type":"set","values":["a","b","c"]}', self::p('set(a|b|c)'));
        $this->assertSame('enum needs values: enum(a|b|c)', $this->pErr('enum'));
        $this->assertSame('set needs values: set(a|b|c)', $this->pErr('set'));
        $this->assertSame("'enum' needs values separated by |", $this->pErr('enum(a||b)'));
    }

    /** array: string or integer items, both bounds, and the refusals. */
    public function testArrayShorthand(): void
    {
        $this->assertSame('{"items":"string","type":"array"}', self::p('array(string)'));
        $this->assertSame('{"items":"integer","max_items":5,"min_items":1,"type":"array"}', self::p('array(integer, min=1, max=5)'));
        $this->assertSame('{"items":"string","max_items":3,"type":"array"}', self::p('array(string, max=3)'));
        $this->assertSame('array(items): items is string or integer', $this->pErr('array'));
        $this->assertSame('array(items): items is string or integer', $this->pErr('array(bool)'));
        $this->assertSame("'array' takes at most 1 positional argument(s)", $this->pErr('array(string,integer)'));
    }

    // ---- resource shorthands -----------------------------------------------------------------------------------------------

    private static function r(string $s): string
    {
        return self::c(ActionsAuthor::parseResourceShorthand($s));
    }

    /** Each resource form with its default scope and with an explicit one. */
    public function testResourceShorthands(): void
    {
        $this->assertSame('{"id":"*","scope":"tenant","type":"invoice"}', self::r('invoice'));
        $this->assertSame('{"id":"*","scope":"one","type":"invoice"}', self::r(' invoice@one '));
        $this->assertSame('{"id":"*","scope":"set","type":"inv\nx"}', self::r("inv\nx@set"));
        $this->assertSame('{"id":"*","scope":"set","type":"invoice"}', self::r('invoice:*'));
        $this->assertSame('{"id":"*","scope":"one","type":"invoice"}', self::r('invoice:*@one'));
        $this->assertSame('{"id":{"exact":"inv_123"},"scope":"one","type":"invoice"}', self::r('invoice:inv_123'));
        $this->assertSame('{"id":{"exact":"inv_123"},"scope":"set","type":"invoice"}', self::r('invoice:inv_123@set'));
        $this->assertSame('{"id":{"class":"alnum","len":[8,32],"prefix":"in_"},"scope":"one","type":"invoice"}', self::r('invoice:in_*'));
        $this->assertSame('{"id":{"class":"hex","len":[4,16],"prefix":"in_"},"scope":"global","type":"invoice"}', self::r('invoice:in_*{hex,4..16}@global'));
        $this->assertSame('{"id":{"class":"uuid","len":[36,36],"prefix":""},"scope":"tenant","type":"a"}', self::r('a:*{uuid,36..36}@tenant'));
    }

    /** Resource refusals name the scope or the id source. */
    public function testResourceRefusals(): void
    {
        $this->assertSame("unknown resource scope '@bogus'", $this->refusal(static fn() => ActionsAuthor::parseResourceShorthand('invoice@bogus')));
        $this->assertSame("resource id 'in_*{bogus,1..2}': expected prefix*{class,min..max}", $this->refusal(static fn() => ActionsAuthor::parseResourceShorthand('invoice:in_*{bogus,1..2}')));
        $this->assertSame("resource id 'in_*x': expected prefix*{class,min..max}", $this->refusal(static fn() => ActionsAuthor::parseResourceShorthand('invoice:in_*x')));
    }

    /** The default title puts the action first, spaces the underscores and upper-cases the first code point. */
    public function testDefaultTitle(): void
    {
        $this->assertSame('Send invoice', ActionsAuthor::defaultTitle('acme.invoice.send'));
        $this->assertSame('Mark paid bulk item', ActionsAuthor::defaultTitle('acme.bulk_item.mark_paid'));
        $this->assertSame('C a b', ActionsAuthor::defaultTitle('acme.a.b.c'));
        $this->assertSame('Acme', ActionsAuthor::defaultTitle('acme'));
        $this->assertSame("\u{c9}ta thing", ActionsAuthor::defaultTitle("acme.thing.\u{e9}ta"));
    }

    // ---- entries ------------------------------------------------------------------------------------------------------------

    /** A shorthand entry: every member is carried or expanded, a send action gets the idempotency key and a note. */
    public function testExpandShorthandEntry(): void
    {
        $e = self::j('{"verb":"acme.invoice.send","aliases":"send_invoice","description":"d","effects":"send","resource":"invoice:in_*",'
            . '"params":{"to":"email","note":{"type":"string"}},"reversibility":"irreversible","blast":"tenant","side_effects":["s"],"context":"c",'
            . '"traits":"pca.x","audience":"a","compensates":"acme.invoice.void","bindings":{"b":1},"examples":[1],"source":{"s":1}}');
        $x = ActionsAuthor::expandAction($e);
        $want = self::j('{"v":1,"kind":"pca-action-def","verb":"acme.invoice.send","aliases":["send_invoice"],"title":"Send invoice","description":"d","effects":["send"],'
            . '"resource":{"type":"invoice","id":{"prefix":"in_","class":"alnum","len":[8,32]},"scope":"one"},'
            . '"params":{"to":{"type":"string","role":"contact.email","format":"email","tags":["pii"],"max_len":254},"note":{"type":"string"},"idempotency_key":{"type":"string","max_len":64}},'
            . '"reversibility":"irreversible","blast":{"radius":"tenant"},"side_effects":["s"],"idempotency":{"mode":"key_param","param":"idempotency_key"},'
            . '"context":["c"],"traits":["pca.x"],"audience":"a","compensates":"acme.invoice.void","bindings":{"b":1},"examples":[1],"source":{"s":1},"review":{"state":"authored"}}');
        $this->assertSame(self::c($want), self::c($x['def']));
        $this->assertSame('[{"message":"idempotency_key auto-added","verb":"acme.invoice.send"}]', self::c($x['notes']));
    }

    /** title, review and since: given values win; since falls back to the document's. */
    public function testExpandGivenValues(): void
    {
        $d = ActionsAuthor::expandAction(self::j('{"verb":"acme.x.read","title":"T","review":{"state":"x"},"since":"s1"}'), 's0')['def'];
        $this->assertSame(['T', '{"state":"x"}', 's1'], [$d->get('title'), self::c($d->get('review')), $d->get('since')]);
        $d = ActionsAuthor::expandAction(self::j('{"verb":"acme.x.read"}'), 's0')['def'];
        $this->assertSame('s0', $d->get('since'));
        $d = ActionsAuthor::expandAction(self::j('{"verb":"acme.x.read"}'))['def'];
        $this->assertFalse($d->has('since'));
        $this->assertSame('{"kind":"pca-action-def","params":{},"review":{"state":"authored"},"title":"Read x","v":1,"verb":"acme.x.read"}', self::c($d));
    }

    private static function ex(string $entry): array
    {
        $x = ActionsAuthor::expandAction(self::j($entry));
        $d = $x['def'];
        return [$d->has('idempotency') ? self::c($d->get('idempotency')) : null, self::c($d->get('params')), count($x['notes'])];
    }

    /** Idempotency: strings expand, an object passes through, the key param is added only for key_param on idempotency_key when absent. */
    public function testIdempotency(): void
    {
        $this->assertSame([null, '{}', 0], self::ex('{"verb":"acme.x.read","effects":"read"}'));
        $this->assertSame(['{"mode":"natural"}', '{}', 0], self::ex('{"verb":"acme.x.send","effects":"send","idempotency":"natural"}'));
        $this->assertSame(['{"mode":"natural"}', '{}', 0], self::ex('{"verb":"acme.x.read","effects":"read","idempotency":"natural"}'));
        $this->assertSame(['{"mode":"key_param","param":"idempotency_key"}', '{"idempotency_key":{"max_len":64,"type":"string"}}', 0],
            self::ex('{"verb":"acme.x.read","effects":"read","idempotency":"key_param"}'));
        $this->assertSame(['{"mode":"key_param","param":"k"}', '{}', 0], self::ex('{"verb":"acme.x.read","effects":"read","idempotency":{"mode":"key_param","param":"k"}}'));
        $this->assertSame(['{"mode":"key_param","param":"idempotency_key"}', '{"idempotency_key":{"max_len":10,"type":"string"}}', 1],
            self::ex('{"verb":"acme.x.send","effects":"send","params":{"idempotency_key":"text(10)"}}'));
        $this->assertSame([null, '{}', 0], self::ex('{"verb":"acme.x.read","effects":[{},"read"]}'));
    }

    /** Blast: a radius name becomes {radius}, an object passes, an unknown name is refused. */
    public function testBlast(): void
    {
        $this->assertSame('{"radius":"one"}', self::c(ActionsAuthor::expandAction(self::j('{"verb":"acme.x.read","blast":{"radius":"one"}}'))['def']->get('blast')));
        $this->assertSame("unknown blast radius 'huge'", $this->refusal(fn() => ActionsAuthor::expandAction(self::j('{"verb":"acme.x.read","blast":"huge"}')), 'bad_action'));
    }

    /** Entry refusals: shape, unknown member, version (only the number 1), kind, verb, params, strict JSON. */
    public function testExpandRefusals(): void
    {
        $r = fn(mixed $e): string => $this->refusal(static fn() => ActionsAuthor::expandAction($e), 'bad_action');
        $this->assertSame('an action must be an object', $r('x'));
        $this->assertSame("unknown member 'foo'", $r(self::j('{"verb":"acme.x.read","foo":1}')));
        $this->assertSame('unsupported def version', $r(self::j('{"verb":"acme.x.read","v":2}')));
        $this->assertSame('unsupported def version', $r(self::j('{"verb":"acme.x.read","v":"1"}')));
        $this->assertSame('unsupported def version', $r(Obj::of(['verb' => 'acme.x.read', 'v' => 1])));
        $this->assertSame("kind must be 'pca-action-def'", $r(self::j('{"verb":"acme.x.read","kind":"other"}')));
        $this->assertSame('verb is required', $r(self::j('{"effects":"read"}')));
        $this->assertSame('params must be an object', $r(self::j('{"verb":"acme.x.read","params":"x"}')));
        $this->assertSame('not strict JSON: numbers must be safe integers (no floats, no -0)', $r(self::j('{"verb":"acme.x.read","description":1.5}')));
        $this->assertSame('not strict JSON: numbers must be safe integers (no floats, no -0)', $r(self::j('{"kind":"pca-action-def","verb":"acme.x.read","title":1.5}')));
        $this->assertSame('Read x', ActionsAuthor::expandAction(Obj::of(['verb' => 'acme.x.read', 'v' => 1.0]))['def']->get('title'));
        $this->assertSame('Read x', ActionsAuthor::expandAction(self::j('{"verb":"acme.x.read","v":1}'))['def']->get('title'));
    }

    /** A full def (with kind) is taken as written, with v 1 first. */
    public function testFullForm(): void
    {
        $x = ActionsAuthor::expandAction(self::j('{"kind":"pca-action-def","verb":"acme.x.read","title":"t"}'), 's0');
        $this->assertSame(['v', 'kind', 'verb', 'title'], $x['def']->keys());
        $this->assertSame('1', $x['def']->get('v')->lexeme);
        $this->assertSame([], $x['notes']);
    }

    // ---- documents ----------------------------------------------------------------------------------------------------------

    private static function load(mixed $doc): string
    {
        return self::c(ActionsAuthor::loadActionsValue($doc));
    }

    private static function failed(string $msg, string $ns = ''): string
    {
        return '{"defs":[],"errors":[{"message":' . json_encode($msg) . '}],"locs":{},"notes":[]' . ($ns !== '' ? ',"ns":"' . $ns . '"' : '') . ',"rules":{}}';
    }

    /** Document-level refusals replace the errors with one message and keep what was read. */
    public function testDocumentRefusals(): void
    {
        $this->assertSame(self::failed('the document must be an object'), self::load([1]));
        $this->assertSame(self::failed("unknown top-level member 'foo' (expected ns, since, actions)"), self::load(self::j('{"ns":"acme","foo":1}')));
        $this->assertSame(self::failed('ns must be a lowercase identifier'), self::load(self::j('{"ns":"Acme","actions":[]}')));
        $this->assertSame(self::failed('ns must be a lowercase identifier'), self::load(self::j('{"actions":[]}')));
        $this->assertSame(self::failed('since must be a string', 'acme'), self::load(self::j('{"ns":"acme","since":5,"actions":[]}')));
        $this->assertSame(self::failed('actions must be a list', 'acme'), self::load(self::j('{"ns":"acme"}')));
        $this->assertSame(self::failed("the document contains a '__proto__' member or nests deeper than 40"), self::load(self::j('{"ns":"acme","actions":[{"x":{"__proto__":1}}]}')));
        $this->assertSame(self::failed("the document contains a '__proto__' member or nests deeper than 40"), self::load(Obj::of(['__proto__' => new Num('1')])));
    }

    /** Nesting: a value at depth 40 is allowed, one at depth 41 is refused (lists and objects). */
    public function testNestingBound(): void
    {
        $proto = self::failed("the document contains a '__proto__' member or nests deeper than 40");
        $this->assertSame(self::failed('the document must be an object'), self::load(self::j(str_repeat('[', 41) . str_repeat(']', 41))));
        $this->assertSame($proto, self::load(self::j(str_repeat('[', 42) . str_repeat(']', 42))));
        $this->assertSame(self::failed("unknown top-level member 'a' (expected ns, since, actions)"), self::load(self::j(str_repeat('{"a":', 40) . '{}' . str_repeat('}', 40))));
        $this->assertSame($proto, self::load(self::j(str_repeat('{"a":', 41) . '{}' . str_repeat('}', 41))));
    }

    /** Entries: each failure is reported by index (and verb when it has one) and the rest still load, with since from the document. */
    public function testEntriesAndErrors(): void
    {
        $bad = self::j('{"verb":"acme.bad.thing.read"}');
        $badMsg = Actions::validateDef(ActionsAuthor::expandAction($bad, '0.9.0')['def']);
        $this->assertIsString($badMsg);
        $doc = Obj::of(['ns' => 'acme', 'since' => '0.9.0', 'actions' => ['x', $bad, self::payEntry(), self::j('{"verb":"acme.y.z","foo":1}'), self::j('{"verb":"","foo":1}')]]);
        $res = ActionsAuthor::loadActionsValue($doc);
        $def = ActionsAuthor::expandAction(self::payEntry(), '0.9.0')['def'];
        $this->assertNull(Actions::validateDef($def));
        $this->assertSame('0.9.0', $def->get('since'));
        $this->assertSame(self::c([$def]), self::c($res->get('defs')));
        $this->assertSame([], $res->get('notes'));
        $this->assertSame(self::c([
            Obj::of(['index' => new Num('0'), 'message' => 'an action must be an object']),
            Obj::of(['index' => new Num('1'), 'verb' => 'acme.bad.thing.read', 'message' => $badMsg]),
            Obj::of(['index' => new Num('3'), 'verb' => 'acme.y.z', 'message' => "unknown member 'foo'"]),
            Obj::of(['index' => new Num('4'), 'message' => "unknown member 'foo'"]),
        ]), self::c($res->get('errors')));
        $this->assertSame('acme', $res->get('ns'));
    }

    /** Rules on an entry: a bad block is that entry's error, a good one is kept by verb; notes of loaded entries are collected. */
    public function testEntryRules(): void
    {
        $rules = self::j('{"amount":{"max":{"USD":1}}}');
        $auto = self::payEntry()->without('idempotency');
        $def = ActionsAuthor::expandAction($auto, '0.5.0')['def'];
        $this->assertNull(ActionsRulesValidate::error($def, $rules));
        $badMsg = ActionsRulesValidate::error($def, new Num('5'));
        $this->assertIsString($badMsg);
        $e0 = self::payEntry();
        $e0->set('rules', new Num('5'));
        $e1 = $auto->without();
        $e1->set('rules', $rules);
        $res = ActionsAuthor::loadActionsValue(Obj::of(['ns' => 'acme', 'since' => '0.5.0', 'actions' => [$e0, $e1, $auto]]));
        $this->assertSame(self::c([Obj::of(['index' => new Num('0'), 'verb' => 'acme.pay.send', 'message' => $badMsg])]), self::c($res->get('errors')));
        $this->assertSame(self::c([$def, $def]), self::c($res->get('defs')));
        $this->assertSame('{"acme.pay.send":{"amount":{"max":{"USD":1}}}}', self::c($res->get('rules')));
        $note = '{"message":"idempotency_key auto-added","verb":"acme.pay.send"}';
        $this->assertSame("[$note,$note]", self::c($res->get('notes')));
    }

    /** A single raw def is a document of one entry, taken as written. */
    public function testRawDefDocument(): void
    {
        $res = ActionsAuthor::loadActionsValue(self::j(self::PAY));
        $this->assertSame([], $res->get('errors'));
        $this->assertSame(self::c([self::j(self::PAY)]), self::c($res->get('defs')));
        $this->assertFalse($res->has('ns'));
    }

    // ---- text ---------------------------------------------------------------------------------------------------------------

    private static function textFailed(string $msg): string
    {
        return '{"defs":[],"errors":[{"column":1,"line":1,"message":' . json_encode($msg) . '}],"locs":{},"notes":[],"rules":{}}';
    }

    /** The size bound is inclusive; JSON must be UTF-8; parse errors keep the parser's message. */
    public function testTextBoundsAndJsonErrors(): void
    {
        $this->assertSame(self::textFailed('not JSON: invalid UTF-8'), self::c(ActionsAuthor::loadActionsText("\xFF" . str_repeat(' ', ActionsAuthor::MAX_AUTHOR_BYTES - 1), 'json')));
        $this->assertSame(self::textFailed('the file is larger than 1048576 bytes'), self::c(ActionsAuthor::loadActionsText(str_repeat(' ', ActionsAuthor::MAX_AUTHOR_BYTES + 1), 'json')));
        $m = ActionsAuthor::loadActionsText('{', 'json')->get('errors')[0]->get('message');
        $this->assertStringStartsWith('not JSON: ', $m);
        $this->assertGreaterThan(strlen('not JSON: '), strlen($m));
    }

    /** JSON nesting: 512 levels parse (then fail the 40-level document bound), 513 are a JSON error. */
    public function testJsonDepth(): void
    {
        $nest = static fn(int $n): string => str_repeat('{"a":', $n - 1) . '{}' . str_repeat('}', $n - 1);
        $this->assertSame("the document contains a '__proto__' member or nests deeper than 40", ActionsAuthor::loadActionsText($nest(512), 'json')->get('errors')[0]->get('message'));
        $this->assertStringStartsWith('not JSON: nesting too deep', ActionsAuthor::loadActionsText($nest(513), 'json')->get('errors')[0]->get('message'));
    }

    /** Positions of a JSON file: only surrogate \u escapes are masked, so other escapes keep every column. */
    public function testJsonPositionsKeepColumns(): void
    {
        $pay = self::c(self::payEntry());
        $a = ActionsAuthor::loadActionsText('{"ns":"acme","since":"0","actions":[' . $pay . ']}', 'json');
        $b = ActionsAuthor::loadActionsText('{"ns":"acme","since":"000000","actions":[' . $pay . ']}', 'json');
        $this->assertSame([], $a->get('errors'));
        $this->assertTrue($a->get('locs')->has('acme.pay.send'));
        $this->assertSame(self::c($b->get('locs')), self::c($a->get('locs')));
    }

    /** A YAML syntax error carries the parser's message and its position. */
    public function testYamlSyntaxError(): void
    {
        $text = "ns: acme\nsince: x\nns: b\n";
        try {
            ActionsYamlLoad::parseDocument($text);
            $this->fail('the YAML must not parse');
        } catch (ActionsYamlError $e) {
            $want = [$e->getMessage(), $e->yamlLine, $e->yamlColumn];
        }
        $this->assertGreaterThan(1, $want[1]);
        $err = ActionsAuthor::loadActionsText($text)->get('errors')[0];
        $this->assertSame('not YAML: ' . $want[0], $err->get('message'));
        $this->assertSame([$want[1], $want[2]], [$err->get('line')->int(), $err->get('column')->int()]);
    }

    /** An entry error whose index has no position (a raw def with an empty actions list) gets no line. */
    public function testErrorWithoutPosition(): void
    {
        $res = ActionsAuthor::loadActionsText("kind: pca-action-def\nverb: acme.x.read\nactions: []\n");
        $this->assertSame('[{"index":0,"message":"unknown member \'actions\'","verb":"acme.x.read"}]', self::c($res->get('errors')));
    }

    // ---- typed constructor --------------------------------------------------------------------------------------------------

    /** action() builds from the verb and spec, and refuses an invalid def naming the verb. */
    public function testActionConstructor(): void
    {
        $spec = self::payEntry()->without('verb');
        $d = ActionsAuthor::action('acme.pay.send', $spec);
        $this->assertSame(self::c(ActionsAuthor::expandAction(self::payEntry())['def']), self::c($d));
        $bad = Actions::validateDef(ActionsAuthor::expandAction(self::j('{"verb":"acme.x.read"}'))['def']);
        $this->assertIsString($bad);
        $this->assertSame("acme.x.read: $bad", $this->refusal(static fn() => ActionsAuthor::action('acme.x.read', new Obj()), 'bad_action'));
    }
}
