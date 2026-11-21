<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Approval.php';

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Approval;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Approval: UTF-16 id order, the value-type arms, render refusals and their messages, PSD2 linking and the batch totals. */
final class K05KillApprovalTest extends TestCase
{
    private const DD = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    private static function def(string $params): Obj
    {
        $d = Json::parseLax('{"v":1,"kind":"pca-action-def","verb":"bank.transfer.send","title":"Send a transfer","effects":["pay"],'
            . '"resource":{"type":"bank.account","id":"*","scope":"one"},"params":' . $params
            . ',"reversibility":"irreversible","idempotency":{"mode":"natural"},"review":{"state":"authored"}}');
        self::assertInstanceOf(Obj::class, $d);
        return $d;
    }

    private static function transfer(): Obj
    {
        return self::def('{"amount":{"type":"integer","min":1,"max":100000000,"role":"money.amount","unit":{"kind":"money","ccy":{"from":"currency"},"exp":2}},'
            . '"currency":{"type":"string","role":"money.currency","format":"iso_currency"},"payee":{"type":"string","role":"party.payee","max_len":64},'
            . '"memo":{"type":"string","max_len":140,"required":false}}');
    }

    private static function obj(string $json): Obj
    {
        $o = Json::parseLax($json);
        self::assertInstanceOf(Obj::class, $o);
        return $o;
    }

    /** @return array{0:string,1:string} [code, message] of the ActionKitError `$f` throws */
    private static function refusal(callable $f): array
    {
        try {
            $f();
        } catch (ActionKitError $e) {
            return [$e->codeName, $e->getMessage()];
        }
        self::fail('expected an ActionKitError');
    }

    /** @param list<string> $ids */
    private static function shape(array $ids, mixed $v = null): Obj
    {
        return Obj::of(['v' => $v ?? new Num('1'), 'kind' => 'pca-approval-render', 'verb' => 'a.b', 'def_digest' => self::DD, 'unreviewed' => true,
            'fields' => array_map(static fn(string $id): Obj => Obj::of(['id' => $id, 'class' => 'c', 'value' => true]), $ids)]);
    }

    public function testFieldIdsSortByUtf16CodeUnitsWithLoneSurrogates(): void
    {
        $s = static fn(int $u): string => chr(0xE0 | ($u >> 12)) . chr(0x80 | (($u >> 6) & 0x3F)) . chr(0x80 | ($u & 0x3F));
        $astral = "\u{10000}"; // D800 DC00
        // [lower, higher] in UTF-16 order: each pair splits a different set of mis-decodings of the surrogate unit
        $pairs = [[$astral, $s(0xD801)], [$s(0xD800), $astral], [$s(0xD800), $s(0xD840)],
            [$s(0xD800) . 'a' . $s(0xDC00) . 'zzz', $s(0xD800) . 'a' . $s(0xDC01) . 'aaa']];
        foreach ($pairs as $i => [$lo, $hi]) {
            self::assertNull(Approval::renderShapeError(self::shape([$lo, $hi])), "pair $i in order");
            self::assertSame('fields must be sorted by id and unique', Approval::renderShapeError(self::shape([$hi, $lo])), "pair $i reversed");
        }
    }

    public function testPhpIntVersionIsAccepted(): void
    {
        self::assertNull(Approval::renderShapeError(self::shape(['a'], 1)));
        self::assertSame('not a pca-approval-render v1', Approval::renderShapeError(self::shape(['a'], 2)));
    }

    public function testEveryParameterTypeHasItsCanonicalDomain(): void
    {
        $d = self::def('{"i":{"type":"integer"},"du":{"type":"duration"},"b":{"type":"boolean"},"s":{"type":"string"},"da":{"type":"date"},'
            . '"dt":{"type":"datetime"},"o":{"type":"object_ref"},"se":{"type":"set","values":["x","y"]},"ar":{"type":"array"}}');
        $r = Approval::render($d, self::obj('{"i":5,"du":60,"b":true,"s":"x","da":"2020-01-01","dt":"2020-01-01T00:00:00Z","o":"r1","se":["x"],"ar":[1,"a",false]}'));
        self::assertSame(['ar', 'b', 'da', 'dt', 'du', 'i', 'o', 's', 'se'], array_map(static fn(Obj $f) => $f->get('id'), $r->get('fields')));
        // an unknown type has no canonical domain
        self::assertSame(['render_bad_value', "'n' is not a number in the canonical domain"],
            self::refusal(fn() => Approval::render(self::def('{"n":{"type":"number"}}'), self::obj('{"n":1}'))));
    }

    public function testUnconfirmedIsTheDefault(): void
    {
        $p = self::obj('{"amount":12500,"currency":"EUR","payee":"Acme GmbH"}');
        self::assertTrue(Approval::render(self::transfer(), $p)->get('unreviewed'));
        self::assertFalse(Approval::render(self::transfer(), $p, true)->get('unreviewed'));
    }

    public function testRefusalMessages(): void
    {
        self::assertSame(['render_undeclared_param', "'zz' is not a parameter of bank.transfer.send"],
            self::refusal(fn() => Approval::render(self::transfer(), self::obj('{"zz":1}'))));
        self::assertSame(['render_missing_param', "required parameter 'amount' of bank.transfer.send is missing"],
            self::refusal(fn() => Approval::render(self::transfer(), self::obj('{"currency":"EUR","payee":"P"}'))));
        self::assertSame(['render_bad_value', "'amount' is not a integer in the canonical domain"],
            self::refusal(fn() => Approval::render(self::transfer(), self::obj('{"amount":"x","currency":"EUR","payee":"P"}'))));
    }

    public function testNumericParameterNamesStayStrings(): void
    {
        $r = Approval::render(self::def('{"5":{"type":"string"},"7":{"type":"string"}}'), self::obj('{"7":"y","5":"x"}'));
        $ids = array_map(static fn(Obj $f) => $f->get('id'), $r->get('fields'));
        self::assertSame(['5', '7'], $ids);
    }

    public function testCurrencyFromIsReadAsAPropertyKey(): void
    {
        // ccy.from false is never the parameter "0" (a bool array offset would read $flat[0])
        $d = self::def('{"amount":{"type":"integer","role":"money.amount","unit":{"kind":"money","ccy":{"from":false},"exp":2}},"0":{"type":"string"}}');
        self::assertSame('render_unresolved_currency', self::refusal(fn() => Approval::render($d, self::obj('{"amount":5,"0":"EUR"}')))[0]);
        // a ccy that is neither a string nor {from} resolves to nothing
        $d = self::def('{"amount":{"type":"integer","role":"money.amount","unit":{"kind":"money","ccy":7,"exp":2}}}');
        self::assertSame('render_unresolved_currency', self::refusal(fn() => Approval::render($d, self::obj('{"amount":5}')))[0]);
    }

    private static function payment(mixed $unreviewed, Num $amount, string $ccy, Num $exp, string $payee): Obj
    {
        return Obj::of(['v' => new Num('1'), 'kind' => 'pca-approval-render', 'verb' => 'bank.pay', 'def_digest' => self::DD, 'unreviewed' => $unreviewed, 'fields' => [
            Obj::of(['id' => 'amount', 'class' => 'money.amount', 'value' => $amount, 'unit' => Obj::of(['kind' => 'money', 'ccy' => $ccy, 'exp' => $exp])]),
            Obj::of(['id' => 'payee', 'class' => 'party.payee', 'value' => $payee]),
        ]]);
    }

    public function testUnreviewedNumUsesItsNumericValue(): void
    {
        // (float)'0x1' is 0: a zero number is falsy, like the reference's truthiness
        $l = Approval::psd2Linking(self::payment(new Num('0x1'), new Num('100'), 'EUR', new Num('2'), 'Acme'));
        self::assertSame('Acme', $l->get('payee'));
        self::assertSame('EUR', $l->get('currency'));
    }

    public function testBatchTotalsAreIntegerLexemes(): void
    {
        $b = Approval::batch([Obj::of(['action_digest' => self::DD, 'render' => self::payment(false, new Num('1e15'), 'EUR', new Num('2.0'), 'Acme')])]);
        $t = $b->get('batch')->get('totals');
        self::assertCount(1, $t);
        self::assertSame('EUR', $t[0]->get('ccy'));
        self::assertSame('2', $t[0]->get('exp')->lexeme);
        self::assertSame('1000000000000000', $t[0]->get('minor')->lexeme);
    }

    public function testNumericCurrenciesStayStrings(): void
    {
        $b = Approval::batch([
            Obj::of(['action_digest' => self::DD, 'render' => self::payment(false, new Num('100'), '978', new Num('2'), '222')]),
            Obj::of(['action_digest' => self::DD, 'render' => self::payment(false, new Num('50'), '840', new Num('2'), '111')]),
        ]);
        $t = $b->get('batch')->get('totals');
        self::assertSame(['840', '978'], [$t[0]->get('ccy'), $t[1]->get('ccy')]);
        self::assertSame(['50', '100'], [$t[0]->get('minor')->lexeme, $t[1]->get('minor')->lexeme]);
    }
}
