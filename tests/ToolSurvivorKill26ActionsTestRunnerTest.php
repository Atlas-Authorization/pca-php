<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsTestRunner.php';
require_once __DIR__ . '/../src/ActionsBuiltin.php';

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsAuthor;
use Atlas\Pca\ActionsBuiltin;
use Atlas\Pca\ActionsTestRunner as R;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The example runner: selector matching (grantOf), the example decision, the schema mutations, the property checks and the text report. */
final class ToolSurvivorKill26ActionsTestRunnerTest extends TestCase
{
    private const SEL_ALLOW = '{"verb":"stripe.charge","caveats":["amount_cap","count_cap","window"],"context":["idempotency","fresh_revocation"]}';
    private const PAY_PARAMS = '{"customer":"cus_12345678","amount":100,"idempotency_key":"k_1"}';

    private static function call(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(R::class, $m))->invoke(null, ...$a);
    }

    private static function j(string $s): mixed
    {
        return Json::parseStrict($s);
    }

    /** A fresh copy of a shipped def (builtin or domain) by verb. */
    private static function def(string $verb): Obj
    {
        foreach ([...ActionsBuiltin::builtinDefs(), ...ActionsBuiltin::domainDefs()] as $d) {
            if ($d->get('verb') === $verb) {
                return Json::parseStrict(Js::stringify($d));
            }
        }
        throw new \LogicException("no def $verb");
    }

    /** @return array{got:string,why:string} */
    private static function decide(Obj $d, string $params, ?string $under = null): array
    {
        $ex = self::j('{"params":' . $params . ($under !== null ? ',"under":' . $under : '') . ',"expect":"allow"}');
        return R::decideExample($d, $ex, Actions::coreRegistry(), [$d]);
    }

    /** The domain part of an address is lowercased Unicode-aware; a value without '@' is the whole value lowercased. */
    public function testDomainOf(): void
    {
        self::assertSame('b.com', self::call('domainOf', 'a@B.Com'));
        self::assertSame('c.de', self::call('domainOf', 'x@y@C.DE'));
        self::assertSame('noat', self::call('domainOf', 'NoAt'));
        self::assertSame("\u{e9}x.com", self::call('domainOf', "a@\u{c9}X.com"));
    }

    private static function grantDef(): Obj
    {
        return self::j('{"verb":"a.b","params":{"to":{"role":"contact.email"},"payee":{"role":"party.payee"},"amt":{"role":"money.amount"},'
            . '"n":{"role":"count.limit"},"id":{"role":"id.x"},"plain":{"role":"other"}}}');
    }

    private static function grant(string $sel, string $flat, array $closure = []): ?array
    {
        return self::call('grantOf', self::j($sel), self::grantDef(), self::j($flat), ['closure' => $closure]);
    }

    /** A trait selector matches by bare or full id against the closure; a non-string trait is its string form, never a type error. */
    public function testGrantTrait(): void
    {
        $cl = ['pca.money_moving'];
        self::assertSame([], self::grant('{"trait":"money_moving"}', '{}', $cl));
        self::assertSame([], self::grant('{"trait":"pca.money_moving"}', '{}', $cl));
        self::assertNull(self::grant('{"trait":"destructive"}', '{}', $cl));
        self::assertSame([], self::call('grantOf', Obj::of(['trait' => 5]), self::grantDef(), new Obj(), ['closure' => ['pca.5', '5']]));
    }

    /** A verb selector matches only its own verb; the selector caveats are carried. */
    public function testGrantVerb(): void
    {
        self::assertNull(self::grant('{"verb":"a.c"}', '{}'));
        self::assertSame(['window'], self::grant('{"verb":"a.b","caveats":["window"]}', '{}'));
    }

    /** where lists: exact values, or the lowercased domain for a `.domain` key; a miss, a non-string value or an undeclared param refuses. */
    public function testGrantWhereLists(): void
    {
        self::assertSame(['recipient_scope'], self::grant('{"verb":"a.b","where":{"to.domain":["b.com"]}}', '{"to":"x@B.com"}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"to.domain":["b.com"]}}', '{"to":"x@c.com"}'));
        self::assertSame(['recipient_scope'], self::grant('{"verb":"a.b","where":{"to":["x@b.com"]}}', '{"to":"x@b.com"}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"to":["b.com"]}}', '{"to":"x@b.com"}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"to":["x@b.com"]}}', '{"to":"x@c.com"}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"amt":["5"]}}', '{"amt":5}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"zz":["x"]}}', '{"zz":"x"}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"to":["x"]}}', '{}'));
    }

    /** where bounds are inclusive at exactly max and exactly min. */
    public function testGrantWhereBounds(): void
    {
        self::assertSame(['amount_cap'], self::grant('{"verb":"a.b","where":{"amt":{"max":5}}}', '{"amt":5}'));
        self::assertSame(['amount_cap'], self::grant('{"verb":"a.b","where":{"amt":{"min":5}}}', '{"amt":5}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"amt":{"max":4}}}', '{"amt":5}'));
        self::assertNull(self::grant('{"verb":"a.b","where":{"amt":{"min":6}}}', '{"amt":5}'));
    }

    /** Each param role adds its caveat: contact and payee recipient scope, amount and count caps, ids resource scope, others none. */
    public function testGrantRoleCaveats(): void
    {
        $w = static fn(string $p, string $v): ?array => self::grant('{"verb":"a.b","where":{"' . $p . '":["' . $v . '"]}}', '{"' . $p . '":"' . $v . '"}');
        self::assertSame(['recipient_scope'], $w('to', 'v'));
        self::assertSame(['recipient_scope'], $w('payee', 'v'));
        self::assertSame(['count_cap'], $w('n', 'v'));
        self::assertSame(['resource_scope'], $w('id', 'v'));
        self::assertSame([], $w('plain', 'v'));
    }

    /** A non-matching selector is skipped and a later one still grants; the caveats of every matching selector are merged. */
    public function testDecideSelectorList(): void
    {
        $ok = ['got' => 'allow', 'why' => 'floor satisfied'];
        $d = self::def('stripe.charge');
        self::assertSame($ok, self::decide($d, self::PAY_PARAMS, '{"allow":' . self::SEL_ALLOW . '}'), 'control');
        self::assertSame($ok, self::decide($d, self::PAY_PARAMS, '{"allow":[{"verb":"x.y"},' . self::SEL_ALLOW . ']}'));
        self::assertSame($ok, self::decide($d, self::PAY_PARAMS, '{"allow":[{"verb":"stripe.charge","caveats":["amount_cap","count_cap"]},'
            . '{"verb":"stripe.charge","caveats":["window"],"context":["idempotency","fresh_revocation"]}]}'));
    }

    /** Natural idempotency supplies the idempotency context by itself. */
    public function testDecideNaturalIdempotency(): void
    {
        $d = self::def('stripe.charge');
        $d->set('idempotency', Obj::of(['mode' => 'natural']));
        self::assertSame(['got' => 'allow', 'why' => 'floor satisfied'], self::decide($d, self::PAY_PARAMS,
            '{"allow":{"verb":"stripe.charge","caveats":["amount_cap","count_cap","window"],"context":["fresh_revocation"]}}'));
    }

    /** With every caveat and context met but no grant, the reason names the escalation tier; a matching grant pre-authorizes tier 3. */
    public function testDecideEscalationTier(): void
    {
        $d = self::def('repo.release');
        self::assertSame(['got' => 'escalate', 'why' => 'floor needs escalation tier 1'], self::decide($d, '{"repo":"repo_abcd"}'));
        $d->set('effects', ['sign']);
        self::assertSame(['got' => 'allow', 'why' => 'floor satisfied'], self::decide($d, '{"repo":"repo_abcd"}', '{"allow":{"verb":"repo.release"}}'));
    }

    /** The schema mutations: in key order, undeclared keys skipped, optional params not removed, one type swap per kind, bounds just outside. */
    public function testMutations(): void
    {
        $d = self::j('{"params":{"a_str":{"type":"string","values":["p","q"],"max_len":3,"required":false},"b_num":{"type":"integer","max":10,"min":2},'
            . '"c_bool":{"type":"boolean"},"d_obj":{"type":"object"},"e_float":{"type":"number","max":5},"f_numstr":{"type":"string","values":["x"],"max_len":2}}}');
        $flat = self::j('{"f_numstr":7,"d_obj":{},"c_bool":true,"b_num":5,"a_str":"p","a0":"u","e_float":1}');
        $ms = self::call('mutations', $d, $flat);
        $names = array_map(static fn(array $m): string => $m['name'], $ms);
        self::assertSame(['extra param', 'type swap a_str', 'outside values a_str', 'too long a_str', 'missing b_num', 'type swap b_num', 'above max b_num',
            'below min b_num', 'missing c_bool', 'type swap c_bool', 'missing d_obj', 'type swap d_obj', 'missing e_float', 'type swap e_float',
            'missing f_numstr', 'type swap f_numstr'], $names);
        $by = array_combine($names, array_map(static fn(array $m): Obj => $m['params'], $ms));
        self::assertSame('x', $by['extra param']->get('zz_undeclared'));
        self::assertSame('12345', $by['type swap a_str']->get('a_str')->lexeme);
        self::assertSame('not_a_listed_value_zz', $by['outside values a_str']->get('a_str'));
        self::assertSame('xxxx', $by['too long a_str']->get('a_str'));
        self::assertFalse($by['missing b_num']->has('b_num'));
        self::assertTrue($by['missing b_num']->has('a_str'));
        self::assertSame('x', $by['type swap b_num']->get('b_num'));
        self::assertSame('11', $by['above max b_num']->get('b_num')->lexeme);
        self::assertSame('1', $by['below min b_num']->get('b_num')->lexeme);
        self::assertSame('x', $by['type swap c_bool']->get('c_bool'));
        self::assertInstanceOf(Obj::class, $by['type swap d_obj']->get('d_obj'));
        self::assertSame('x', $by['type swap e_float']->get('e_float'));
        self::assertSame('x', $by['type swap f_numstr']->get('f_numstr'));
    }

    /** A load is ok only with no errors, at least one def and the wanted digest; the reason is the first error, else "digest differs". */
    public function testLoadedOkAndWhy(): void
    {
        $d = self::def('gmail.send');
        $want = Actions::defDigest($d);
        $m = Obj::of(['message' => 'm']);
        self::assertTrue(self::call('loadedOk', Obj::of(['errors' => [], 'defs' => [$d]]), $want), 'control');
        self::assertFalse(self::call('loadedOk', Obj::of(['errors' => [], 'defs' => []]), $want));
        self::assertFalse(self::call('loadedOk', Obj::of(['errors' => [$m], 'defs' => [$d]]), $want));
        self::assertSame('ok', self::call('loadedWhy', Obj::of(['errors' => []]), true));
        self::assertSame('digest differs', self::call('loadedWhy', Obj::of(['errors' => []]), false));
        self::assertSame('m', self::call('loadedWhy', Obj::of(['errors' => [$m]]), false));
    }

    /** A failing YAML form fails the digest property with both reasons, and the whole run. */
    public function testDigestPropertyFailure(): void
    {
        $bad = static fn(Obj $d): Obj => Obj::of(['errors' => [Obj::of(['message' => 'boom'])], 'defs' => []]);
        $r = R::runDefTests([self::def('gmail.send')], Actions::coreRegistry(), null, $bad);
        self::assertSame('one digest across JSON and YAML forms', $r['props'][2]['name']);
        self::assertFalse($r['props'][2]['ok']);
        self::assertSame('json ok; yaml boom', $r['props'][2]['detail']);
        self::assertFalse($r['ok']);
    }

    /** The built-in YAML round trip names the namespace after the first verb segment (a second segment need not be an identifier). */
    public function testYamlFormNamespace(): void
    {
        $d = self::def('gmail.send');
        $d->set('verb', 'acme.2send');
        $r = R::runDefTests([$d], Actions::coreRegistry());
        self::assertSame('one digest across JSON and YAML forms', $r['props'][2]['name']);
        self::assertTrue($r['props'][2]['ok']);
    }

    /** A mutation the schema accepts fails the round trip and is named once, even when several examples produce it. */
    public function testRoundTripAcceptedMutation(): void
    {
        $d = self::def('repo.release');
        $d->get('params')->set('mode', self::j('{"type":"string","values":["a","not_a_listed_value_zz"]}'));
        $d->set('examples', self::j('[{"params":{"repo":"repo_abcd","mode":"a"},"expect":"escalate"},{"params":{"repo":"repo_abcd","mode":"a"},"expect":"escalate"}]'));
        $json = static fn(Obj $x): Obj => ActionsAuthor::loadActionsText(Js::stringify($x), 'json');
        $r = R::runDefTests([$d], Actions::coreRegistry(), null, $json);
        self::assertSame('schema round trip', $r['props'][3]['name']);
        self::assertFalse($r['props'][3]['ok']);
        self::assertSame('accepted: outside values mode', $r['props'][3]['detail']);
    }

    /** By default at most 256 trait subsets are tried; the subset count is capped at 2^20 masks. */
    public function testSubsetLimit(): void
    {
        self::assertSame(20, R::SUBSET_BITS);
        $d = self::def('gmail.send');
        $d->set('traits', ['pca.money_moving', 'pca.destructive', 'pca.irreversible', 'pca.external_communication', 'pca.data_export',
            'pca.privilege_change', 'pca.code_execution', 'pca.credential_access', 'pca.bulk']);
        $json = static fn(Obj $x): Obj => ActionsAuthor::loadActionsText(Js::stringify($x), 'json');
        $r = R::runDefTests([$d], Actions::coreRegistry(), null, $json);
        self::assertSame('floors are monotone over trait subsets', $r['props'][1]['name']);
        self::assertSame('256 subsets, 0 violations', $r['props'][1]['detail']);
    }

    /** The text report reads the runner's own (array) report, and numbers an example index + 1 in JavaScript form. */
    public function testText(): void
    {
        self::assertSame('0 passed, 0 failed', R::testText(['examples' => [], 'props' => [], 'ok' => true]));
        $e = ['verb' => 'v', 'index' => 1.5, 'expect' => 'allow', 'got' => 'allow', 'ok' => true, 'why' => 'w'];
        self::assertSame("PASS  v example 2.5: expected allow, got allow (w)\n1 passed, 0 failed", R::testText(['examples' => [$e], 'props' => []]));
        $e['index'] = new Num('0');
        self::assertSame("PASS  v example 1: expected allow, got allow (w)\n1 passed, 0 failed", R::testText(['examples' => [$e], 'props' => []]));
    }
}
