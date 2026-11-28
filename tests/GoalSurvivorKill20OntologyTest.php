<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalOntologies.php';
require_once __DIR__ . '/../src/GoalOntology.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalJsSet;
use Atlas\Pca\GoalOntologies;
use Atlas\Pca\GoalOntology as O;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The intent ontology: JS Set keys, projection, anchors, slot typing, instantiation, the checker and human amount parsing. */
final class GoalSurvivorKill20OntologyTest extends TestCase
{
    private static function refusal(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    private static function j(mixed $x): string
    {
        return is_string($x) ? $x : Js::stringify($x);
    }

    /** SameValueZero keys: objects by identity, arrays by identity, numbers by value (+0 = -0), strings and booleans by value. */
    public function testSetKeys(): void
    {
        $o = new Obj();
        self::assertSame('o' . spl_object_id($o), GoalJsSet::key($o));
        self::assertMatchesRegularExpression('/\Aa[1-9][0-9]*\z/', GoalJsSet::key([1]));
        self::assertSame(2, (new GoalJsSet([[1], [1]]))->length());
        self::assertSame('b1', GoalJsSet::key(true));
        self::assertSame('b0', GoalJsSet::key(false));
        self::assertSame('n1', GoalJsSet::key(1));
        self::assertSame('n2.5', GoalJsSet::key(2.5));
        self::assertSame('n0', GoalJsSet::key(0));
        self::assertSame('n0', GoalJsSet::key(-0.0));
        self::assertSame('nNaN', GoalJsSet::key(NAN));
        self::assertSame('sx', GoalJsSet::key('x'));
        self::assertFalse((new GoalJsSet(['n1']))->has(1));
        self::assertTrue((new GoalJsSet([false]))->has(false));
        self::assertFalse((new GoalJsSet([false]))->has(true));
    }

    /** Signing and verifying ontologies are part of the public surface; a non-string verb word refuses with its own reason. */
    public function testPublicSurface(): void
    {
        self::assertTrue((new \ReflectionMethod(O::class, 'signOntology'))->isPublic());
        self::assertTrue((new \ReflectionMethod(O::class, 'verifyOntology'))->isPublic());
        self::assertSame('TypeError: word.trim is not a function', self::refusal(fn() => O::resolveVerb(new Obj(), 5)));
    }

    private static function money(string $ccy, int $n = 5): Obj
    {
        return Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'money', 'ccy' => $ccy]), 'n' => $n])])]);
    }

    private static function cmp(Obj $l, Obj $r, string $op = 'lte'): Obj
    {
        return Obj::of(['k' => 'cmp', 'op' => $op, 'l' => $l, 'r' => $r]);
    }

    private static function param(string $p = 'amount'): Obj
    {
        return Obj::of(['k' => 'param', 'path' => $p]);
    }

    private static function goal(array $grants, array $prohibits = []): Obj
    {
        return Obj::of(['grants' => array_map(static fn(Obj $c) => Obj::of(['cond' => $c]), $grants),
            'prohibits' => array_map(static fn(Obj $c) => Obj::of(['cond' => $c]), $prohibits), 'escalateOn' => [], 'bounds' => []]);
    }

    /** A goal's currency is found on either side of a comparison, inside and/or, and in prohibitions. */
    public function testGoalCcy(): void
    {
        self::assertSame('EUR', O::goalCcy(self::goal([self::cmp(self::money('EUR'), self::param())])));
        self::assertSame('EUR', O::goalCcy(self::goal([Obj::of(['k' => 'and', 'a' => Obj::of(['k' => 'true']), 'b' => self::cmp(self::param(), self::money('EUR'))])])));
        self::assertSame('GBP', O::goalCcy(self::goal([], [self::cmp(self::param(), self::money('GBP'))])));
    }

    /** Money parameters project to the requested currency when accepted, else USD when accepted, else the first listed. */
    public function testIrProjection(): void
    {
        $o = Obj::of(['verbs' => [Obj::of(['id' => 'v', 'effect' => 'read', 'params' => Obj::of([
            'a' => Obj::of(['kind' => 'money', 'ccys' => ['EUR', 'GBP']]), 'b' => Obj::of(['kind' => 'money', 'ccys' => ['EUR', 'USD']])])])]]);
        $ty = static fn(string $c) => '{"k":"q","u":{"k":"money","ccy":"' . $c . '"}}';
        self::assertSame('{"verbs":[{"verb":"v","cls":"read","params":[{"path":"a","ty":' . $ty('EUR') . '},{"path":"b","ty":' . $ty('USD') . '}]}],"rels":[]}',
            self::j(O::toIrOntology($o)));
        self::assertSame('{"verbs":[{"verb":"v","cls":"read","params":[{"path":"a","ty":' . $ty('GBP') . '},{"path":"b","ty":' . $ty('USD') . '}]}],"rels":[]}',
            self::j(O::toIrOntology($o, Obj::of(['ccy' => 'GBP']))));
        $g = self::goal([self::cmp(self::param('b'), self::money('EUR'))]);
        self::assertSame('{"verbs":[{"verb":"v","cls":"read","params":[{"path":"a","ty":' . $ty('EUR') . '},{"path":"b","ty":' . $ty('EUR') . '}]}],"rels":["R"]}',
            self::j(O::ontologyForGoal($o, $g, ['R'])));
        self::assertSame([], O::ontologyForGoal($o, self::goal([]))->get('rels'));
    }

    /** Anchors are keyed by relation and anchor apart, so ("ab","c") and ("a","bc") stay two anchors. */
    public function testGoalAnchorsKeepRelationAndAnchorApart(): void
    {
        $rel = static fn(string $r, string $a) => Obj::of(['res' => Obj::of(['k' => 'related', 'rel' => $r, 'anchor' => $a])]);
        $a = O::goalAnchors(Obj::of(['grants' => [$rel('ab', 'c'), $rel('a', 'bc')], 'prohibits' => []]));
        self::assertSame('[{"rel":"a","anchor":"bc","members":[]},{"rel":"ab","anchor":"c","members":[]}]', self::j($a));
    }

    /** Slot typing: each quantity kind needs its own member and a safe integer (instants may be negative, -0 never), lists need members. */
    public function testSlotLits(): void
    {
        $o = GoalOntologies::shippedOntology('payments');
        $l = static fn(array $s, mixed $v) => self::j(O::slotLits($o, Obj::of($s), $v));
        $q = static fn(string $k, string $n) => '[{"k":"q","q":{"u":{"k":"' . $k . '"},"n":' . $n . '}}]';
        self::assertSame($q('count', '5'), $l(['kind' => 'count'], Obj::of(['n' => 5])));
        self::assertSame($q('count', '9007199254740991'), $l(['kind' => 'count'], Obj::of(['n' => 9007199254740991])));
        foreach ([Obj::of(['n' => -0.0]), Obj::of(['n' => '5']), Obj::of(['minor' => 5]), Obj::of(['ms' => 5]), Obj::of(['n' => -1])] as $v) {
            self::assertSame('ill-typed', $l(['kind' => 'count'], $v), self::j($v));
        }
        self::assertSame("TypeError: cannot use 'in' operator on a non-object", self::refusal(fn() => O::slotLits($o, Obj::of(['kind' => 'count']), 5)));
        self::assertSame($q('duration', '5'), $l(['kind' => 'duration'], Obj::of(['ms' => 5])));
        self::assertSame('ill-typed', $l(['kind' => 'duration'], Obj::of(['ms' => -5])));
        self::assertSame($q('instant', '-5'), $l(['kind' => 'instant'], Obj::of(['epoch_ms' => -5])));
        self::assertSame($q('instant', '-5'), $l(['kind' => 'instant', 'max' => 0], Obj::of(['epoch_ms' => -5])));
        self::assertSame('above the template maximum', $l(['kind' => 'instant', 'max' => -1], Obj::of(['epoch_ms' => 5])));
        self::assertSame('ill-typed', $l(['kind' => 'enum', 'values' => [5]], 5));
        $el = ['kind' => 'enum_list', 'values' => ['a', 'b']];
        self::assertSame('[{"k":"s","s":"a"}]', $l($el, ['a']));
        foreach ([[], ['z'], ['a', 'z']] as $v) {
            self::assertSame('ill-typed', $l($el, $v), json_encode($v));
        }
        self::assertSame('ill-typed', $l(['kind' => 'text_list'], ['']));
        self::assertSame('[{"k":"s","s":"x"}]', $l(['kind' => 'text_list'], ['x']));
    }

    private static function opts(): Obj
    {
        return Obj::of(['principal' => 'p', 'nl' => 'x']);
    }

    private static function vals(array $extra = []): Obj
    {
        return Obj::of(['customer' => 'cus_1', 'charge' => 'ch_1'] + $extra);
    }

    /** @return array{0:Obj,1:Obj} the payments ontology and its refund_duplicate template (mutable in place) */
    private static function fresh(): array
    {
        $o = GoalOntologies::shippedOntology('payments');
        return [$o, $o->get('templates')[0]];
    }

    /** Instantiation refusals: an unknown template, values that are null or undefined, an undeclared parameter, an untypeable slot. */
    public function testInstantiationRefusals(): void
    {
        [$o, $t] = self::fresh();
        self::assertSame('InvalidArgumentException: unknown template zz', self::refusal(fn() => O::instantiateTemplate($o, 'zz', self::vals(), self::opts())));
        self::assertSame('TypeError: cannot read properties of null', self::refusal(fn() => O::instantiateTemplate($o, 'refund_duplicate', null, self::opts())));
        self::assertSame('TypeError: cannot read properties of null', self::refusal(fn() => O::instantiateTemplate($o, 'refund_duplicate', AnalyzerJs::undef(), self::opts())));
        self::assertSame('accepted', self::refusal(fn() => O::instantiateTemplate($o, 'refund_duplicate', self::vals(), self::opts())), 'control');
        $g = $t->get('grants')[0];
        $g->set('cond', self::cmp(self::param('nope'), Obj::of(['k' => 'slot', 'slot' => 'max_amount'])));
        self::assertSame('InvalidArgumentException: parameter nope is not declared by any verb',
            self::refusal(fn() => O::instantiateTemplate($o, 'refund_duplicate', self::vals(['max_amount' => Obj::of(['ccy' => 'USD', 'minor' => 100])]), self::opts())));
        [$o, $t] = self::fresh();
        $t->set('slots', [$t->get('slots')[0], $t->get('slots')[1], Obj::of(['name' => 'x', 'kind' => 'bogus', 'mandatory' => true])]);
        $t->get('grants')[0]->set('cond', self::cmp(self::param(), Obj::of(['k' => 'slot', 'slot' => 'x'])));
        self::assertSame("TypeError: cannot read properties of undefined (reading '0')",
            self::refusal(fn() => O::instantiateTemplate($o, 'refund_duplicate', self::vals(['x' => 5]), self::opts())));
    }

    /** Conditions instantiate structurally (not keeps its operand); a money literal on the left types the parameter on the right. */
    public function testInstantiatedConditions(): void
    {
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', Obj::of(['k' => 'not', 'c' => Obj::of(['k' => 'true'])]));
        $g = O::instantiateTemplate($o, 'refund_duplicate', self::vals(), self::opts());
        self::assertSame('{"k":"not","c":{"k":"true"}}', self::j($g->get('grants')[0]->get('cond')));
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', self::cmp(self::money('EUR'), self::param()));
        $g = O::instantiateTemplate($o, 'refund_duplicate', self::vals(), self::opts());
        self::assertSame('{"k":"param","path":"amount","ty":{"k":"q","u":{"k":"money","ccy":"EUR"}}}', self::j($g->get('grants')[0]->get('cond')->get('r')));
    }

    /** A prohibition that depends on a hole widens to every resource with a true condition. */
    public function testHoleDependentProhibitionWidens(): void
    {
        [$o, $t] = self::fresh();
        $t->get('prohibits')[0]->set('cond', self::cmp(self::param(), Obj::of(['k' => 'slot', 'slot' => 'max_amount'])));
        $g = O::instantiateTemplate($o, 'refund_duplicate', self::vals(), self::opts());
        $p = null;
        foreach ($g->get('prohibits') as $x) {
            if ($x->get('pid') === 'no-transfer') {
                $p = $x;
            }
        }
        self::assertSame('{"pid":"no-transfer","target":{"k":"verb","verb":"transfer"},"res":{"k":"any","reason":"hole"},"cond":{"k":"true"}}', self::j($p));
    }

    /** @return list<string> */
    private static function issues(Obj $o): array
    {
        return array_map(static fn(Obj $i) => $i->get('code') . '|' . AnalyzerJs::jsStr($i->get('where')) . '|' . $i->get('msg'), O::checkOntology($o));
    }

    private static function res(Obj ...$parts): Obj
    {
        return Obj::of(['k' => 'all_of', 'parts' => $parts]);
    }

    private static function exact(string $id): Obj
    {
        return Obj::of(['k' => 'exact', 'id' => $id]);
    }

    private static function rel(string $rel = 'charges_of'): Obj
    {
        return Obj::of(['k' => 'related', 'rel' => $rel, 'anchor' => '$customer']);
    }

    /** The checker: the shipped ontology is clean, and each resource, condition, bound and alias rule reports its own issue. */
    public function testChecker(): void
    {
        $w = 'template:refund_duplicate';
        $gw = $w . '.refund-one';
        self::assertSame([], self::issues(GoalOntologies::shippedOntology('payments')));
        $with = static function (callable $edit, bool $hole = true): array {
            [$o, $t] = self::fresh();
            $edit($o, $t, $t->get('grants')[0]);
            if ($hole) { // the example leaves the charge a hole, so the checker stops before the Allow witness
                $ex = $t->get('example');
                $t->set('example', Obj::of(['customer' => $ex->get('customer'), 'max_amount' => $ex->get('max_amount')]));
            }
            return self::issues($o);
        };
        $res = static fn(Obj $r) => $with(static fn($o, $t, $g) => $g->set('res', $r));
        $cond = static fn(Obj $c) => $with(static fn($o, $t, $g) => $g->set('cond', $c));

        self::assertNotContains('resource_type|' . $gw . '|exact resource id has the wrong type prefix', $res(self::res(self::exact('ch_9'), self::rel())));
        self::assertContains('resource_type|' . $gw . '|exact resource id has the wrong type prefix', $res(self::res(self::exact('zz'), self::rel())));
        self::assertContains('resource_type|' . $gw . '|one_of member has the wrong type prefix', $res(self::res(Obj::of(['k' => 'oneof', 'ids' => ['zz']]), self::rel())));
        self::assertContains('relation_type|' . $gw . '|relation target type differs from the verb resource type', $res(self::res(self::exact('$charge'), self::rel('subscriptions_of'))));
        self::assertContains('unbounded|' . $gw . '|non-read grant on a related set needs an aggregate bound',
            $with(static function ($o, $t, $g): void {
                $g->set('res', self::rel());
                $t->set('bounds', []);
            }));

        $slot = Obj::of(['k' => 'slot', 'slot' => 'max_amount']);
        $any = Obj::of(['k' => 'any']);
        $true = Obj::of(['k' => 'true']);
        $unused = 'slot_unused|' . $w . '.max_amount|declared slot is never used';
        self::assertContains('unbounded|' . $gw . '|wildcard resource in a template', $res($any));
        self::assertContains('unbounded|' . $w . '.g1|wildcard resource in a template', $with(static fn($o, $t, $g) => $t->set('grants', [
            Obj::of(['gid' => 'g0', 'verb' => 'nope', 'res' => $any, 'cond' => $true]), Obj::of(['gid' => 'g1', 'verb' => 'refund', 'res' => $any, 'cond' => $true])])));
        self::assertContains('dup_gid|' . $w . '|duplicate grant id', $with(static fn($o, $t, $g) => $t->set('grants', [$g, $g])));
        self::assertContains('bound_value|' . $w . '.one-refund|sum bound has no value parameter', $with(static fn($o, $t, $g) => $t->get('bounds')[0]->set('agg', 'sum')));
        self::assertContains('cond_term|' . $gw . '|unsupported right-hand term', $cond(self::cmp(self::param(), Obj::of(['k' => 'zz']))));
        self::assertNotContains($unused, $cond(self::cmp($slot, self::param())), 'a slot on the left is a use');
        self::assertNotContains($unused, $with(static function ($o, $t, $g) use ($slot, $true): void {
            $g->set('cond', $true);
            $t->get('prohibits')[0]->set('cond', self::cmp(self::param(), $slot));
        }), 'a slot used only by a prohibition is a use');
        self::assertNotContains($unused, $with(static fn($o, $t, $g) => $t->set('grants', [$g,
            Obj::of(['gid' => 'g2', 'verb' => 'refund', 'res' => self::res(self::exact('$charge'), self::rel()), 'cond' => $true])])), 'every grant counts');
        self::assertContains($unused, $cond($true), 'control');
        self::assertSame('TypeError: startsWith needs strings', self::refusal(fn() => $res(self::res(self::exact('x'), Obj::of(['k' => 'exact', 'id' => 5])))));
        self::assertSame('TypeError: not iterable', self::refusal(fn() => O::checkOntology(Obj::of(['types' => 5]))));
        foreach ([Obj::of(['k' => 'and', 'a' => Obj::of(['k' => 'true']), 'b' => self::cmp(self::money('USD'), $slot)]),
            Obj::of(['k' => 'not', 'c' => self::cmp(self::money('USD'), $slot)])] as $c) {
            self::assertContains('cond_param|' . $gw . '|left side of a comparison must be a declared parameter of the verb', $cond($c));
        }
        $set = static fn(array $items) => Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'set', 'items' => $items])]);
        $usd = self::money('USD')->get('v');
        self::assertContains('cond_type|' . $gw . '|empty literal list', $cond(self::cmp(self::param(), $set([]), 'in')));
        self::assertContains('cond_type|' . $gw . '|a literal set pairs with in/nin', $cond(self::cmp(self::param(), $set([$usd]))));
        self::assertContains('cond_type|' . $gw . '|in/nin needs a list', $cond(self::cmp(self::param(), self::money('USD'), 'in')));
        self::assertContains('cond_type|' . $gw . '|nested literal set', $cond(self::cmp(self::param(), $set([Obj::of(['k' => 'set', 'items' => []])]), 'in')));
        $count = Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'count']), 'n' => 1])])]);
        self::assertContains('cond_type|' . $gw . '|literal kind differs from the parameter kind', $cond(self::cmp(self::param(), $count)));
        $ok = $cond(self::cmp(self::param(), self::money('USD')));
        self::assertSame([], array_values(array_filter($ok, static fn(string $s) => str_starts_with($s, 'cond_'))), 'a USD literal is accepted');

        $text = $with(static function ($o, $t, $g): void {
            $o->get('verbs')[1]->get('params')->set('reason', Obj::of(['kind' => 'text']));
            $g->set('cond', self::cmp(self::param('reason'), Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 's', 's' => 'x'])]), 'lt'));
        });
        self::assertContains('cond_order|' . $gw . '|ordering on a text/enum/id parameter', $text);

        $over = $with(static fn($o, $t, $g) => $t->get('bounds')[0]->set('over', ['x', 'y']));
        self::assertCount(1, array_filter($over, static fn(string $s) => str_starts_with($s, 'bound_over|')));
        self::assertContains('bound_cap|' . $w . '.one-refund|cap slot must be money or count', $with(static fn($o, $t, $g) => $t->get('bounds')[0]->set('cap_slot', 'customer')));
        self::assertContains('unit_exponent|USD|money unit needs an integer exponent 0..4', $with(static fn($o, $t, $g) => $o->get('units')->get('USD')->set('exponent', 5)));
        self::assertNotContains('unit_exponent|USD|money unit needs an integer exponent 0..4', $with(static fn($o, $t, $g) => $o->get('units')->get('USD')->set('exponent', 4)));

        self::assertSame([], $with(static fn($o, $t, $g) => $o->get('aliases')->set('payé', 'refund'), false), 'a normalized non-ASCII alias key is accepted');
        self::assertSame([], $with(static fn($o, $t, $g) => $o->set('aliases', ['refund']), false), 'list aliases have no alias chain');
    }

    /** Human amounts: type refusals, lone surrogates kept out of normalization, grouping rules and leading zeros. */
    public function testHumanAmounts(): void
    {
        $p = static fn(mixed $t, mixed $e = 2) => self::j(O::parseHumanAmount($t, $e));
        self::assertSame('TypeError: text.normalize is not a function', self::refusal(fn() => O::parseHumanAmount(5, 2)));
        self::assertSame('TypeError: exponent is not a number', self::refusal(fn() => O::parseHumanAmount('5', '2')));
        $s = "\xED\xA0\x80";
        self::assertSame('{"ok":true,"minor":1200}', $p("1{$s}2"));
        self::assertSame('{"ok":true,"minor":12500}', $p("1{$s}2{$s}\u{FF15}"));
        self::assertSame('InvalidArgumentException: cannot normalize', self::refusal(fn() => O::parseHumanAmount("\xFF5", 2)));
        self::assertSame('{"ok":false,"reason":"malformed grouping"}', $p('1234,567,890', 0));
        self::assertSame('{"ok":true,"minor":1234567890}', $p('1,234,567,890', 0), 'control');
        self::assertSame('{"ok":true,"minor":1}', $p('00000000000000001', 0));
        self::assertSame('{"minor":123450}', self::j(O::parseMoney('1,234.5', 2, AnalyzerJs::undef())));
    }
}
