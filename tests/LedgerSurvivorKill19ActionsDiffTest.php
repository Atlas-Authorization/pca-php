<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsDiff;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/ActionsDiff.php: domain containment per type, the authoring param diff and its messages, the grant-pin diff reasons and the pack diff. */
final class LedgerSurvivorKill19ActionsDiffTest extends TestCase
{
    private static function obj(string $json): Obj
    {
        $o = Json::parseLax($json);
        self::assertInstanceOf(Obj::class, $o);
        return $o;
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(ActionsDiff::class, $m))->invoke(null, ...$a);
    }

    private static function dc(string $outer, string $inner): bool
    {
        return self::priv('domainContains', self::obj($outer), self::obj($inner));
    }

    /** @return array{0:list<string>,1:list<string>,2:list<string>} [wide, narrow, incomparable] */
    private static function pd(Obj $x, Obj $y): array
    {
        $w = [];
        $n = [];
        $i = [];
        (new \ReflectionMethod(ActionsDiff::class, 'paramDiff'))->invokeArgs(null, ['p', $x, $y, &$w, &$n, &$i]);
        return [$w, $n, $i];
    }

    /** @param array<string,string> $over member => JSON */
    private static function def(array $over = []): Obj
    {
        $d = self::obj('{"v":1,"kind":"pca-action-def","verb":"bank.transfer.send","title":"Send","effects":["pay"],'
            . '"resource":{"type":"bank.account","id":"*","scope":"one"},"params":{"a":{"type":"string"}},"reversibility":"irreversible",'
            . '"idempotency":{"mode":"natural"},"review":{"state":"authored"}}');
        foreach ($over as $k => $json) {
            $d->set($k, Json::parseLax($json));
        }
        return $d;
    }

    private static function sjv(mixed $v): string
    {
        return self::priv('sjv', $v);
    }

    /** Object keys of a PHP map are sorted as strings and each member keeps its own value. */
    public function testSortKeysOfAPhpMap(): void
    {
        $this->assertSame('{"2":"a","b":1}', self::sjv(['b' => 1, 2 => 'a']));
        $this->assertSame('{"0":"zero","b":1}', self::sjv([0 => 'zero', 'b' => 1]));
    }

    /** Strings and refs: same type only, a non-numeric bound reads as 0, and an enumerated outer needs an enumerated inner inside it. */
    public function testStringDomains(): void
    {
        $this->assertFalse(self::dc('{"type":"string"}', '{"type":"integer"}'));
        $this->assertFalse(self::dc('{"type":"string","max_len":"x"}', '{"type":"string"}'));
        $this->assertTrue(self::dc('{"type":"string","values":["a","b"]}', '{"type":"string","values":["a"]}'));
        $this->assertFalse(self::dc('{"type":"string","values":["a","b"]}', '{"type":"string"}'));
        $this->assertFalse(self::dc('{"type":"string","values":["a","b"]}', '{"type":"string","values":["c"]}'));
        $this->assertTrue(self::dc('{"type":"boolean"}', '{"type":"boolean"}'));
    }

    /** Durations: bounds clamp at 0 and are inclusive at both ends. */
    public function testDurationDomains(): void
    {
        $this->assertFalse(self::dc('{"type":"duration","max":10}', '{"type":"duration","max":20}'));
        $this->assertTrue(self::dc('{"type":"duration","max":10}', '{"type":"duration","min":-5,"max":5}'));
        $this->assertTrue(self::dc('{"type":"duration","min":2,"max":5}', '{"type":"duration","min":2,"max":5}'));
        $this->assertTrue(self::dc('{"type":"duration","max":10}', '{"type":"duration","max":5}'));
        $this->assertFalse(self::dc('{"type":"duration","min":1,"max":10}', '{"type":"duration","max":5}'));
    }

    /** Sets: inner values inside the outer ones, min_items no lower (absent = 0) and the effective max no higher. */
    public function testSetDomains(): void
    {
        $this->assertTrue(self::dc('{"type":"set","values":["a","b"]}', '{"type":"set","values":["a"]}'));
        $this->assertFalse(self::dc('{"type":"set","values":["a"]}', '{"type":"set","values":["b"]}'));
        $this->assertFalse(self::dc('{"type":"set","values":["a","b"]}', '{"type":"set","values":["a"],"min_items":-1}'));
        $this->assertFalse(self::dc('{"type":"set","values":["a","b"],"min_items":1}', '{"type":"set","values":["a"]}'));
        $this->assertTrue(self::dc('{"type":"set","values":["a","b"]}', '{"type":"set","values":["a","b"]}'));
        $this->assertFalse(self::dc('{"type":"set","values":["a","b"],"max_items":1}', '{"type":"set","values":["a","b"]}'));
    }

    /** Arrays: item type, item counts (inclusive, default 0..64), integer bounds for integer items, max_len otherwise. */
    public function testArrayDomains(): void
    {
        $this->assertTrue(self::dc('{"type":"array"}', '{"type":"array"}'));
        $this->assertFalse(self::dc('{"type":"array","items":"string"}', '{"type":"array","items":"integer"}'));
        $this->assertTrue(self::dc('{"type":"array","items":"integer"}', '{"type":"array","items":"integer"}'));
        $this->assertFalse(self::dc('{"type":"array","items":"integer","min":0}', '{"type":"array","items":"integer","min":-1}'));
        $this->assertFalse(self::dc('{"type":"array","min_items":1}', '{"type":"array"}'));
        $this->assertFalse(self::dc('{"type":"array"}', '{"type":"array","min_items":-1}'));
        $this->assertFalse(self::dc('{"type":"array","items":"integer","max":10}', '{"type":"array","items":"integer","max":20}'));
        $this->assertFalse(self::dc('{"type":"array"}', '{"type":"array","max_len":2000}'));
    }

    /** An absent provenance_min ranks as the loosest (agent); an unknown one as the strictest. */
    public function testProvenanceRank(): void
    {
        $this->assertSame([2, 0, 1], [self::priv('provRank', null), self::priv('provRank', 'bogus'), self::priv('provRank', 'tool')]);
    }

    /** The authoring param diff: numeric bounds with absent/infinite ends, the item counts' directions, value-set changes and provenance. */
    public function testParamDiffMessages(): void
    {
        $o = static fn(array $a): Obj => Obj::of(['type' => 'integer'] + $a);
        $this->assertSame([[], [], []], self::pd($o(['min' => 'a']), $o(['min' => 0])));
        $this->assertSame([[], [], []], self::pd($o(['min' => 0]), $o(['min' => 'a'])));
        $this->assertSame([[], ['param p: min undefined to 0'], []], self::pd($o([]), $o(['min' => 0])));
        $this->assertSame([['param p: min 0 to undefined'], [], []], self::pd($o(['min' => 0]), $o([])));
        $this->assertSame([[], ['param p: max undefined to Infinity'], []], self::pd($o([]), $o(['max' => INF])));
        $this->assertSame([[], ['param p: min undefined to -Infinity'], []], self::pd($o([]), $o(['min' => -INF])));
        $this->assertSame([['param p: max_items 5 to 10'], [], []], self::pd($o(['max_items' => 5]), $o(['max_items' => 10])));
        $this->assertSame([[], ['param p: min_items 1 to 2'], []], self::pd($o(['min_items' => 1]), $o(['min_items' => 2])));
        $this->assertSame([['param p: values unrestricted'], [], []], self::pd($o(['values' => ['a']]), $o([])));
        $this->assertSame([[], ['param p: values restricted'], []], self::pd($o([]), $o(['values' => ['a']])));
        $this->assertSame([['param p: values added (c)'], ['param p: values removed (a)'], []], self::pd($o(['values' => ['a', 'b']]), $o(['values' => ['b', 'c']])));
        $this->assertSame([['param p: values added (false)'], ['param p: values removed (true)'], []], self::pd($o(['values' => [true]]), $o(['values' => [false]])));
        $this->assertSame([['param p: provenance_min loosened'], [], []], self::pd($o(['provenance_min' => 'bogus']), $o(['provenance_min' => 'first_party'])));
        $this->assertSame([['param p: provenance_min loosened'], [], []], self::pd($o(['provenance_min' => 'first_party']), $o(['provenance_min' => 'agent'])));
    }

    /** diffDefs: two verbs are refused by name; a changed default, idempotency gained, side effects and the given registry all count. */
    public function testDiffDefsReasons(): void
    {
        try {
            ActionsDiff::diffDefs(self::def(), self::def(['verb' => '"other.verb"']));
            $this->fail('two verbs must be refused');
        } catch (ActionKitError $e) {
            $this->assertSame(['diff_verb', "diff compares two versions of one verb, not 'bank.transfer.send' and 'other.verb'"], [$e->codeName, $e->getMessage()]);
        }
        $this->assertContains('params.a.default: incomparable',
            ActionsDiff::diffDefs(self::def(), self::def(['params' => '{"a":{"type":"string","default":"x"}}']))['reasons']);
        $this->assertContains('idempotency: narrow',
            ActionsDiff::diffDefs(self::def(), self::def(['idempotency' => '{"mode":"key_param","param":"a"}']))['reasons']);
        $se = static fn(string $json): Obj => self::def(['side_effects' => $json]);
        foreach ([['[{"target":"ab","kind":"c"}]', '[{"target":"a","kind":"bc"}]'], ['[{"target":"t","kind":"x"}]', '[{"target":"t","kind":"y"}]'],
            ['[{"target":"t1","kind":"k"}]', '[{"target":"t2","kind":"k"}]']] as [$a, $b]) {
            $this->assertContains('side_effects: incomparable', ActionsDiff::diffDefs($se($a), $se($b))['reasons'], "$a -> $b");
        }
        $same = '[{"target":"t","kind":"k"}]';
        $this->assertSame(['class' => 'equal', 'reasons' => []], ActionsDiff::diffDefs($se($same), $se($same)));
        $traited = self::def(['traits' => '["pca.irreversible"]']);
        $this->assertSame(['class' => 'equal', 'reasons' => []], ActionsDiff::diffDefs($traited, $traited));
        try {
            ActionsDiff::diffDefs($traited, $traited, []);
            $this->fail('an empty registry knows no trait');
        } catch (ActionKitError $e) {
            $this->assertSame('unknown_trait', $e->codeName);
        }
    }

    /** diffDefsAuthoring: removed effects and declared traits widen, added traits narrow, and new params are reported with their breaking flag. */
    public function testDiffDefsAuthoringReasons(): void
    {
        $reg = Actions::coreRegistry();
        $this->assertContains('widen: effect send removed', ActionsDiff::diffDefsAuthoring(self::def(['effects' => '["pay","send"]']), self::def(), $reg)['reasons']);
        $one = self::def(['traits' => '["pca.irreversible"]']);
        $two = self::def(['traits' => '["pca.irreversible","pca.money_moving"]']);
        $up = ActionsDiff::diffDefsAuthoring($one, $two, $reg)['reasons'];
        $this->assertContains('narrow: declared trait pca.money_moving added', $up);
        $this->assertNotContains('widen: declared trait pca.irreversible removed', $up);
        $this->assertNotContains('narrow: declared trait pca.irreversible added', $up);
        $down = ActionsDiff::diffDefsAuthoring($two, $one, $reg)['reasons'];
        $this->assertContains('widen: declared trait pca.money_moving removed', $down);
        $this->assertNotContains('widen: declared trait pca.irreversible removed', $down);
        $opt = ActionsDiff::diffDefsAuthoring(self::def(), self::def(['params' => '{"a":{"type":"string"},"b":{"type":"string","required":false}}']), $reg);
        $this->assertContains('widen: optional param b added', $opt['reasons']);
        $this->assertFalse($opt['breaking']);
        $req = ActionsDiff::diffDefsAuthoring(self::def(), self::def(['params' => '{"a":{"type":"string"},"c":{"type":"string"}}']), $reg);
        $this->assertContains('narrow: required param c added', $req['reasons']);
        $this->assertNotContains('widen: optional param c added', $req['reasons']);
        $this->assertTrue($req['breaking']);
    }

    /** diffPacks reports added and removed verbs by their string names, numeric-looking ones included. */
    public function testDiffPacksVerbNames(): void
    {
        $reg = Actions::coreRegistry();
        $this->assertSame([['verb' => '7', 'class' => 'added', 'breaking' => false, 'reasons' => []]], ActionsDiff::diffPacks([], [self::def(['verb' => '"7"'])], $reg));
        $this->assertSame([['verb' => '8', 'class' => 'removed', 'breaking' => true, 'reasons' => ['verb removed']]], ActionsDiff::diffPacks([self::def(['verb' => '"8"'])], [], $reg));
    }
}
