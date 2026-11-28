<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalOntologies.php';
require_once __DIR__ . '/../src/GoalOntology.php';
require_once __DIR__ . '/../src/GoalInterpret.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalInterpret as I;
use Atlas\Pca\GoalJs;
use Atlas\Pca\GoalOntologies;
use Atlas\Pca\GoalOntology as O;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Template instantiation typing and bounds, the checker's slot/parameter kind rules, JS key reads, and PCRE-failure handling. */
final class GoalSurvivorKill20bOntologyTest extends TestCase
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
        return Js::stringify($x);
    }

    /** @return array{0:Obj,1:Obj} the payments ontology and its refund_duplicate template (mutable in place) */
    private static function fresh(): array
    {
        $o = GoalOntologies::shippedOntology('payments');
        return [$o, $o->get('templates')[0]];
    }

    private static function verb(Obj $o, int $i): Obj
    {
        return $o->get('verbs')[$i];
    }

    private static function cmp(Obj $l, Obj $r, string $op = 'lte'): Obj
    {
        return Obj::of(['k' => 'cmp', 'op' => $op, 'l' => $l, 'r' => $r]);
    }

    private static function param(string $p = 'amount'): Obj
    {
        return Obj::of(['k' => 'param', 'path' => $p]);
    }

    private static function countLit(): Obj
    {
        return Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'count']), 'n' => 1])])]);
    }

    private static function inst(Obj $o, array $vals = []): Obj
    {
        return O::instantiateTemplate($o, 'refund_duplicate', Obj::of(['customer' => 'cus_1', 'charge' => 'ch_1'] + $vals), Obj::of(['principal' => 'p', 'nl' => 'x']));
    }

    private static function find(array $xs, string $field, string $id): Obj
    {
        foreach ($xs as $x) {
            if ($x->get($field) === $id) {
                return $x;
            }
        }
        self::fail("no $id");
    }

    private const MONEY_USD = '{"k":"q","u":{"k":"money","ccy":"USD"}}';
    private const COUNT = '{"k":"q","u":{"k":"count"}}';

    /**
     * A parameter is typed by the clause's own verb when it declares it, else by the first verb (in order) that does; a prohibition on
     * an effect class types by the first verb of that class; a verb-less prohibition falls back the same way.
     */
    public function testParameterTypingFollowsTheClauseVerb(): void
    {
        [$o, $t] = self::fresh();
        self::verb($o, 3)->get('params')->set('amount', Obj::of(['kind' => 'count'])); // transfer
        self::verb($o, 4)->get('params')->set('amount', Obj::of(['kind' => 'duration'])); // payout
        self::verb($o, 5)->get('params')->set('amount', Obj::of(['kind' => 'count'])); // cancel_subscription (reversible)
        $dup = Obj::of(['id' => 'transfer', 'effect' => 'irreversible', 'resource_type' => 'account', 'params' => Obj::of(['amount' => Obj::of(['kind' => 'duration'])])]);
        $o->set('verbs', [...$o->get('verbs'), $dup, Obj::of(['id' => null, 'effect' => 'read', 'params' => Obj::of(['amount' => Obj::of(['kind' => 'instant'])])])]);
        $c = self::cmp(self::param(), self::countLit());
        $any = Obj::of(['k' => 'any']);
        $g = $t->get('grants')[0];
        $g->set('verb', 'nope');
        $g->set('cond', $c);
        $t->get('prohibits')[0]->set('cond', $c); // no-transfer
        $t->set('prohibits', [...$t->get('prohibits'),
            Obj::of(['pid' => 'x-ext', 'target' => Obj::of(['k' => 'effect', 'cls' => 'external_send']), 'res' => $any, 'cond' => $c]),
            Obj::of(['pid' => 'x-rev', 'target' => Obj::of(['k' => 'effect', 'cls' => 'reversible']), 'res' => $any, 'cond' => $c])]);
        $out = self::inst($o);
        $ty = static fn(Obj $x) => self::j($x->get('cond')->get('l')->get('ty'));
        self::assertSame(self::MONEY_USD, $ty(self::find($out->get('grants'), 'gid', 'refund-one')), 'an undeclared verb falls back to refund');
        self::assertSame(self::COUNT, $ty(self::find($out->get('prohibits'), 'pid', 'no-transfer')), "transfer's own parameter");
        self::assertSame(self::MONEY_USD, $ty(self::find($out->get('prohibits'), 'pid', 'x-ext')), 'no verb of the class: the first declaring verb');
        self::assertSame(self::COUNT, $ty(self::find($out->get('prohibits'), 'pid', 'x-rev')), 'the first verb of the class');
    }

    /** A bound whose cap slot is a hole drops the grants it covers; skipped bounds never stop later ones; values are typed per aggregate. */
    public function testBounds(): void
    {
        $true = Obj::of(['k' => 'true']);
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', $true);
        self::assertSame('{"k":"lit","v":{"k":"q","q":{"u":{"k":"count"},"n":1}}}', self::j(self::inst($o)->get('bounds')[0]->get('value')));
        $t->get('bounds')[0]->set('cap_slot', 'max_amount');
        self::assertSame([], self::inst($o)->get('grants'));
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', $true);
        $base = $t->get('bounds')[0];
        $b0 = Obj::of(['bid' => 'b0', 'agg' => 'count', 'over' => ['zz'], 'cap_slot' => 'max_amount', 'cap' => Obj::of(['u' => Obj::of(['k' => 'count']), 'n' => 1]), 'onExceed' => 'deny']);
        $t->set('bounds', [$b0, $base]);
        self::assertSame(['one-refund'], array_map(static fn(Obj $b) => $b->get('bid'), self::inst($o)->get('bounds')), 'a bound with a hole cap is skipped');
        $t->set('bounds', [Obj::of(['bid' => 'b0', 'agg' => 'count', 'over' => ['zz'], 'cap' => $b0->get('cap'), 'onExceed' => 'deny']), $base]);
        self::assertSame(['one-refund'], array_map(static fn(Obj $b) => $b->get('bid'), self::inst($o)->get('bounds')), 'a bound over no kept grant is skipped');
    }

    /** A sum bound types its value by the verb of the first grant with the selected id; a grant with a null verb refuses. */
    public function testSumBoundVerb(): void
    {
        [$o, $t] = self::fresh();
        self::verb($o, 3)->get('params')->set('amount', Obj::of(['kind' => 'count']));
        $g = $t->get('grants')[0];
        $g->set('cond', Obj::of(['k' => 'true']));
        $g2 = AnalyzerJs::copy($g);
        $g2->set('verb', 'transfer');
        $t->set('grants', [$g, $g2]);
        $t->set('bounds', [Obj::of(['bid' => 'b', 'agg' => 'sum', 'over' => 'all', 'param' => 'amount',
            'cap' => Obj::of(['u' => Obj::of(['k' => 'money', 'ccy' => 'USD']), 'n' => 100]), 'onExceed' => 'deny'])]);
        $b = self::inst($o)->get('bounds')[0];
        self::assertSame('{"k":"param","path":"amount","ty":' . self::MONEY_USD . '}', self::j($b->get('value')));
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', Obj::of(['k' => 'true']));
        $t->get('grants')[0]->set('verb', null);
        self::assertSame("TypeError: cannot read properties of undefined (reading 'verb')", self::refusal(fn() => self::inst($o)));
    }

    private static function eur(): Obj
    {
        return Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'money', 'ccy' => 'EUR']), 'n' => 100])])]);
    }

    /** A money literal on either side names the parameter's currency (the left one first); a negation keeps its shape. */
    public function testCurrencyHintAndNegation(): void
    {
        $eurTy = '{"k":"q","u":{"k":"money","ccy":"EUR"}}';
        $lit = '{"k":"lit","v":{"k":"q","q":{"u":{"k":"money","ccy":"EUR"},"n":100}}}';
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', self::cmp(self::param(), self::eur()));
        self::assertSame('{"k":"cmp","op":"lte","l":{"k":"param","path":"amount","ty":' . $eurTy . '},"r":' . $lit . '}',
            self::j(self::inst($o)->get('grants')[0]->get('cond')));
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', Obj::of(['k' => 'not', 'c' => self::cmp(self::eur(), self::param())]));
        self::assertSame('{"k":"not","c":{"k":"cmp","op":"lte","l":' . $lit . ',"r":{"k":"param","path":"amount","ty":' . $eurTy . '}}}',
            self::j(self::inst($o)->get('grants')[0]->get('cond')));
    }

    /** A parameter no verb declares refuses by name; a prohibition whose slots are holes becomes a blanket prohibition. */
    public function testUndeclaredParameterAndHoleProhibition(): void
    {
        [$o, $t] = self::fresh();
        $t->get('grants')[0]->set('cond', self::cmp(self::param('zzz'), self::countLit()));
        self::assertSame('InvalidArgumentException: parameter zzz is not declared by any verb', self::refusal(fn() => self::inst($o)));
        [$o, $t] = self::fresh();
        $t->get('prohibits')[0]->set('cond', self::cmp(self::param(), Obj::of(['k' => 'slot', 'slot' => 'max_amount'])));
        self::assertSame('{"pid":"no-transfer","target":{"k":"verb","verb":"transfer"},"res":{"k":"any","reason":"hole"},"cond":{"k":"true"}}',
            self::j(self::find(self::inst($o)->get('prohibits'), 'pid', 'no-transfer')));
    }

    /** An alias key already in NFKC form passes even when it is not ASCII; a compatibility character (the fi ligature) is flagged. */
    public function testAliasKeyNormalForm(): void
    {
        [$o] = self::fresh();
        $o->get('aliases')->set("caf\u{e9}", 'refund');
        $o->get('aliases')->set("\u{fb01}x", 'refund');
        $issues = self::issues($o);
        self::assertNotContains("alias_key|caf\u{e9}|alias key is not in normalized form", $issues);
        self::assertContains("alias_key|\u{fb01}x|alias key is not in normalized form", $issues);
    }

    /** @return list<string> */
    private static function issues(Obj $o): array
    {
        return array_map(static fn(Obj $i) => $i->get('code') . '|' . AnalyzerJs::jsStr($i->get('where')) . '|' . $i->get('msg'), O::checkOntology($o));
    }

    /** Runs $edit on a fresh payments ontology whose example leaves the charge a hole (the checker then stops before the Allow witness). */
    private static function check(callable $edit): array
    {
        [$o, $t] = self::fresh();
        $edit($o, $t, $t->get('grants')[0]);
        $ex = $t->get('example');
        $t->set('example', Obj::of(['customer' => $ex->get('customer'), 'max_amount' => $ex->get('max_amount')]));
        return self::issues($o);
    }

    /** Slot kinds type-check against parameter kinds: enum takes enum lists, id takes id lists, text takes text lists, nothing else. */
    public function testSlotParameterKinds(): void
    {
        $gw = 'template:refund_duplicate.refund-one';
        $cases = [['tier', 'enum', 'el', 'enum_list', true], ['who', 'id', 'el', 'enum_list', false], ['who', 'id', 'tl', 'text_list', false],
            ['who', 'id', 'il', 'id_list', true], ['tier', 'enum', 'il', 'id_list', false], ['tier', 'enum', 'tl', 'text_list', false],
            ['reason', 'text', 'tl', 'text_list', true], ['reason', 'text', 'el', 'enum_list', false]];
        foreach ($cases as [$p, $pk, $s, $sk, $ok]) {
            $issues = self::check(static function (Obj $o, Obj $t, Obj $g) use ($p, $s): void {
                $params = self::verb($o, 1)->get('params');
                $params->set('tier', Obj::of(['kind' => 'enum', 'values' => ['a', 'b']]));
                $params->set('who', Obj::of(['kind' => 'id', 'of' => 'customer']));
                $params->set('reason', Obj::of(['kind' => 'text']));
                $t->set('slots', [...$t->get('slots'), Obj::of(['name' => 'el', 'kind' => 'enum_list', 'values' => ['a'], 'mandatory' => true]),
                    Obj::of(['name' => 'il', 'kind' => 'id_list', 'of' => 'customer', 'mandatory' => true]), Obj::of(['name' => 'tl', 'kind' => 'text_list', 'mandatory' => true])]);
                $g->set('cond', self::cmp(self::param($p), Obj::of(['k' => 'slot', 'slot' => $s]), 'in'));
            });
            $bad = "cond_type|$gw|slot $s ($sk) does not type-check against parameter kind $pk";
            $list = "cond_type|$gw|list slots pair with in/nin and scalar slots with the other operators";
            self::assertSame($ok ? [false, false] : [true, false], [in_array($bad, $issues, true), in_array($list, $issues, true)], "$p/$s");
        }
    }

    /** An undeclared parameter on the left is a checker issue, not a crash; a nameless slot's example hole is listed by an empty id. */
    public function testCheckerEdges(): void
    {
        $gw = 'template:refund_duplicate.refund-one';
        self::assertContains("cond_param|$gw|left side of a comparison must be a declared parameter of the verb",
            self::check(static fn($o, $t, $g) => $g->set('cond', self::cmp(self::param('nope'), Obj::of(['k' => 'slot', 'slot' => 'max_amount'])))));
        [$o, $t] = self::fresh();
        $t->set('slots', [...$t->get('slots'), Obj::of(['kind' => 'count', 'mandatory' => true])]);
        self::assertContains('example_holes|template:refund_duplicate|example leaves holes: ', self::issues($o));
    }

    /** Object.keys-style reads: only a canonical array index names an element ("01", "x", out of range are absent); null elements stay null. */
    public function testKeyReads(): void
    {
        $u = AnalyzerJs::undef();
        foreach ([['0', 'a'], ['1', 'b'], ['01', $u], ['x', $u], ['2', $u], ['-1', $u], ['1.0', $u]] as [$k, $want]) {
            self::assertSame($want, GoalJs::kget(['a', 'b'], $k), "list $k");
            self::assertSame($want, GoalJs::kget('ab', $k), "string $k");
        }
        self::assertNull(GoalJs::kget([null], '0'));
        self::assertSame($u, GoalJs::kget(5, '0'));
    }

    /** Runs $f with the PCRE interpreter (no JIT) and a backtracking limit of $limit, restoring both settings. */
    private static function withPcreLimit(string $limit, callable $f): mixed
    {
        $jit = ini_get('pcre.jit');
        $bt = ini_get('pcre.backtrack_limit');
        ini_set('pcre.jit', '0');
        ini_set('pcre.backtrack_limit', $limit);
        try {
            return $f();
        } finally {
            ini_set('pcre.backtrack_limit', (string)$bt);
            ini_set('pcre.jit', (string)$jit);
        }
    }

    /** A PCRE failure (a match limit of 0 fails every match) inside stem extraction or verb trimming degrades to empty text, never a type error. */
    public function testPcreFailuresDegradeToEmptyText(): void
    {
        $o = GoalOntologies::shippedOntology('payments');
        $name = Obj::of(['name' => 'max_items']);
        self::assertSame([], self::withPcreLimit('0', fn() => I::slotStems($name)));
        self::assertNull(self::withPcreLimit('0', fn() => O::resolveVerb($o, ' refund ')));
        self::assertSame(['item'], I::slotStems(Obj::of(['name' => 'max_items'])), 'control');
        self::assertSame('refund', O::resolveVerb(GoalOntologies::shippedOntology('payments'), ' refund '), 'control');
    }

    /** When the surrogate split itself fails, lower-casing and NFKC fall back to the whole text (never an empty result or a warning). */
    public function testSurrogateSplitFailureFallsBackToWholeText(): void
    {
        $o = GoalOntologies::shippedOntology('payments');
        $slot = Obj::of(['kind' => 'text_list']);
        self::assertStringStartsWith('a', self::withPcreLimit('0', fn() => GoalJs::lower("A\xED\xA0\x80")));
        self::assertSame('[{"k":"s","s":"abc"}]', self::j(self::withPcreLimit('0', fn() => O::slotLits($o, $slot, ['abc']))));
        self::assertSame('[{"k":"s","s":"abc"}]', self::j(O::slotLits($o, $slot, ['abc'])), 'control');
    }
}
