<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalOntologies.php';
require_once __DIR__ . '/../src/GoalInterpret.php';

use Atlas\Pca\GoalInterpret as I;
use Atlas\Pca\GoalOntologies;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The goal interpreters: candidate extraction, slot filling, grounding, prompts, strict model-output parsing and recorded completions. */
final class GoalSurvivorKill20InterpretTest extends TestCase
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

    private static function noTypes(): Obj
    {
        return Obj::of(['types' => []]);
    }

    /** @return list<int> */
    private static function counts(string $text): array
    {
        return array_map(static fn(Obj $c) => $c->get('n'), I::extractCandidates($text, self::noTypes())->get('counts'));
    }

    /** Runs $f with the PCRE interpreter (no JIT) and a backtracking limit of $limit, restoring both settings. */
    private static function withPcreLimit(string $limit, callable $f): string
    {
        $jit = ini_get('pcre.jit');
        $bt = ini_get('pcre.backtrack_limit');
        ini_set('pcre.jit', '0');
        ini_set('pcre.backtrack_limit', $limit);
        try {
            return self::refusal($f);
        } finally {
            ini_set('pcre.backtrack_limit', (string)$bt);
            ini_set('pcre.jit', (string)$jit);
        }
    }

    private static function c(array $extra): Obj
    {
        return Obj::of(['amounts' => [], 'ambiguousAmounts' => 0, 'counts' => [], 'ids' => [], 'words' => '', 'domains' => []] + $extra);
    }

    /** A currency code glued to a preceding word is not a currency; a leading symbol wins over a trailing currency word. */
    public function testAmountCurrencyBoundariesAndPrecedence(): void
    {
        self::assertSame([], I::extractCandidates('xusd 5', self::noTypes())->get('amounts'));
        $a = I::extractCandidates('usd 5', self::noTypes())->get('amounts');
        self::assertCount(1, $a, 'control: a free-standing code is a currency');
        self::assertSame('USD', $a[0]->get('ccy'));
        $e = I::extractCandidates('€5 dollars', self::noTypes())->get('amounts');
        self::assertCount(1, $e);
        self::assertSame('EUR', $e[0]->get('ccy'));
        self::assertSame(500, $e[0]->get('minor'));
    }

    /** A count word must end at a word boundary; a count after '.' or ':' and one glued to '-' follow their exact rules. */
    public function testCountBoundaries(): void
    {
        self::assertSame([], self::counts('twicex'));
        self::assertSame([2], self::counts('twice'), 'control');
        self::assertSame([7], self::counts('x .5 then 7'));
        self::assertSame([7], self::counts('5-fold then 7'));
        self::assertSame([2], self::counts('twice-daily'));
        self::assertSame([5], self::counts("5\u{12D}"));
        self::assertSame([5], self::counts('x:5'));
    }

    /** Lone surrogates and the 1/2/3-byte boundaries of the scan text never break the scan. */
    public function testScanTextEncodesEveryUnitAsValidUtf8(): void
    {
        foreach (["\xED\xA0\x80", "\xED\xBF\xBF", "\u{80}", "\u{800}", "a\xED\xB0\x80b"] as $t) {
            $c = I::extractCandidates($t, self::noTypes());
            self::assertSame([], $c->get('counts'), bin2hex($t));
            self::assertSame([], $c->get('amounts'), bin2hex($t));
        }
    }

    /** A surrogate unit is shifted into the private use area (+0x800) and every other unit keeps its own code point when words are matched. */
    public function testWordMatchingKeepsUnitsDistinct(): void
    {
        $g = static fn(string $words, string $v): bool => I::grounded(Obj::of(['kind' => 'enum']), $v, self::c(['words' => $words]));
        self::assertFalse($g("\xED\xA0\x80", "\xED\xB0\x80"));
        self::assertTrue($g("\xED\xA0\x80", "\xED\xA0\x80"), 'control');
        self::assertTrue($g("\xED\xA0\x80", "\u{E000}"), 'U+D800 is matched as U+E000');
        self::assertFalse($g("\xED\xA0\x80", "\u{D000}"));
        self::assertFalse($g("\u{80}", "\u{81}"));
        self::assertFalse($g("\u{800}", "\u{801}"));
        self::assertFalse($g("\u{800}", "\u{840}"));
        self::assertFalse($g('abc', 'a.c'), 'the word is quoted, not a pattern');
        self::assertTrue($g('gift card', 'gift_card'));
        self::assertFalse($g('giftcard', 'gift_card'));
    }

    /** A failing scan or word match refuses (fail closed), never reads as "nothing found". */
    public function testPatternFailuresRefuse(): void
    {
        // prefixes and words unique to this test, so their patterns are compiled here without JIT and the limit applies
        $o = Obj::of(['types' => [Obj::of(['id' => 't', 'id_prefix' => 'qzv20_'])]]);
        self::assertSame('RuntimeException: pattern scan failed', self::withPcreLimit('1', fn() => I::extractCandidates('pay qzv20_a', $o)));
        self::assertSame('RuntimeException: pattern match failed',
            self::withPcreLimit('1', fn() => I::grounded(Obj::of(['kind' => 'enum']), 'qzv20w', self::c(['words' => 'xx qzv20w qzv20w']))));
        self::assertSame(['qzv20_a'], I::extractCandidates('pay qzv20_a', $o)->get('ids'), 'control');
        self::assertTrue(I::grounded(Obj::of(['kind' => 'enum']), 'qzv20w', self::c(['words' => 'xx qzv20w qzv20w'])), 'control');
    }

    /** Slot stems: `max_` is dropped, a plural ending is stripped and only stems longer than two units count, all of them. */
    public function testSlotStems(): void
    {
        self::assertSame([], I::slotStems(Obj::of(['name' => 'max_ab'])));
        self::assertSame(['abc'], I::slotStems(Obj::of(['name' => 'max_abc'])));
        self::assertSame(['big', 'item'], I::slotStems(Obj::of(['name' => 'max_big_items'])));
    }

    private static function fill(array $slots, string $text, ?Obj $o = null): Obj
    {
        return I::fillTemplate(Obj::of(['slots' => array_map(static fn(array $s) => Obj::of($s), $slots)]), $o ?? self::noTypes(), $text);
    }

    /** An id slot reads the first type with its id; an unknown type admits any id; duplicates collapse; a quoted prefix is literal. */
    public function testIdSlots(): void
    {
        $o = Obj::of(['types' => [Obj::of(['id' => 'order', 'id_prefix' => 'ord_']), Obj::of(['id' => 'order', 'id_prefix' => 'xx_'])]]);
        self::assertSame('ord_1', self::fill([['name' => 'o', 'kind' => 'id', 'of' => 'order']], 'ord_1', $o)->get('values')->get('o'));
        self::assertSame('ord_1', self::fill([['name' => 'o', 'kind' => 'id', 'of' => 'nothing']], 'ord_1', $o)->get('values')->get('o'));
        $f = self::fill([['name' => 'o', 'kind' => 'id', 'of' => 'order']], 'ord_1 and ord_1', $o);
        self::assertSame('ord_1', $f->get('values')->get('o'));
        self::assertSame([], $f->get('notes'));
        self::assertSame(['ord_1', 'ord_2'], self::fill([['name' => 'l', 'kind' => 'id_list', 'of' => 'order']], 'ord_1 ord_1 ord_2', $o)->get('values')->get('l'));
        $dot = Obj::of(['types' => [Obj::of(['id' => 't', 'id_prefix' => 'a.b'])]]);
        self::assertSame(['a.b2'], I::extractCandidates('axb1 a.b2', $dot)->get('ids'));
        self::assertSame('a.b2', self::fill([['name' => 'o', 'kind' => 'id', 'of' => 't']], 'axb1 a.b2', $dot)->get('values')->get('o'));
    }

    /** A lone count fills an uncued count slot; an empty or non-list cue is no cue; another slot naming the count takes it away. */
    public function testCountSlots(): void
    {
        foreach ([null, [], 5] as $cue) {
            $s = ['name' => 'max_q', 'kind' => 'count'];
            if ($cue !== null) {
                $s['cue'] = $cue;
            }
            $f = self::fill([$s], 'up to 5');
            self::assertTrue($f->get('values')->has('max_q'), json_encode($cue));
            self::assertSame('5', $f->get('values')->get('max_q')->get('n')->lexeme);
            self::assertSame([], $f->get('unattributed'));
        }
        $f = self::fill([['name' => 'max_q', 'kind' => 'count', 'cue' => ['up to']], ['name' => 'widget', 'kind' => 'text_list']], 'up to 5 widget');
        self::assertSame('5', $f->get('values')->get('max_q')->get('n')->lexeme);
        self::assertSame(['widget: not found'], $f->get('notes'));
    }

    /** Enum values match with '_' read as a space; an enum list keeps every hit; a domain list is de-duplicated into a list. */
    public function testEnumAndTextSlots(): void
    {
        self::assertSame('gift_card', self::fill([['name' => 'm', 'kind' => 'enum', 'values' => ['gift_card', 'cash']]], 'use a gift card')->get('values')->get('m'));
        self::assertSame(['gift_card', 'cash'], self::fill([['name' => 'm', 'kind' => 'enum_list', 'values' => ['gift_card', 'cash', 'wire']]], 'gift card or cash')->get('values')->get('m'));
        self::assertSame(['m: not found'], self::fill([['name' => 'm', 'kind' => 'enum_list', 'values' => ['wire']]], 'gift card')->get('notes'));
        self::assertSame(['a.com', 'b.com'], self::fill([['name' => 'd', 'kind' => 'text_list']], 'a.com, a.com, b.com')->get('values')->get('d'));
    }

    /** Durations and instants are never read from free text; an unknown slot kind refuses. */
    public function testUnsupportedAndUnknownSlotKinds(): void
    {
        self::assertSame(['d: unsupported in free text'], self::fill([['name' => 'd', 'kind' => 'duration']], 'for 5 days')->get('notes'));
        self::assertSame(['i: unsupported in free text'], self::fill([['name' => 'i', 'kind' => 'instant']], 'at noon')->get('notes'));
        self::assertSame('InvalidArgumentException: unknown slot kind', self::refusal(fn() => self::fill([['name' => 'b', 'kind' => 'bogus']], 'x')));
    }

    /** Money grounding: every amount in the text must share the value's currency; a non-object value is never grounded. */
    public function testMoneyGrounding(): void
    {
        $s = Obj::of(['kind' => 'money']);
        $usd = Obj::of(['ccy' => 'USD', 'minor' => 500]);
        $v = Obj::of(['ccy' => 'USD', 'minor' => 500]);
        self::assertTrue(I::grounded($s, $v, self::c(['amounts' => [$usd]])), 'control');
        self::assertFalse(I::grounded($s, $v, self::c(['amounts' => [$usd, Obj::of(['ccy' => 'EUR', 'minor' => 300])]])));
        self::assertFalse(I::grounded($s, 'x', self::c([])));
    }

    /** List grounding: only a real list whose every member is a candidate is grounded. */
    public function testListGrounding(): void
    {
        $idl = Obj::of(['kind' => 'id_list']);
        $c = self::c(['ids' => ['a', 'b']]);
        self::assertTrue(I::grounded($idl, ['a', 'b'], $c));
        self::assertFalse(I::grounded($idl, ['a', 'z'], $c));
        self::assertFalse(I::grounded($idl, 'a', $c));
        self::assertFalse(I::grounded($idl, ['x' => 'a'], $c));
        $el = Obj::of(['kind' => 'enum_list']);
        $w = self::c(['words' => 'gift card and cash']);
        self::assertTrue(I::grounded($el, ['gift_card', 'cash'], $w));
        self::assertFalse(I::grounded($el, ['gift_card', 'wire'], $w));
        self::assertFalse(I::grounded($el, 'cash', $w));
        self::assertFalse(I::grounded($el, ['x' => 'cash'], $w));
        self::assertTrue(I::grounded(Obj::of(['kind' => 'enum']), 'gift_card', $w));
        self::assertFalse(I::grounded(Obj::of(['kind' => 'bogus']), 'cash', $w));
    }

    /** Two templates matched by equally long phrases are a blocking question naming both, in order; the rule reader is deterministic. */
    public function testAmbiguousTemplateQuestion(): void
    {
        $t = static fn(string $id, string $title) => Obj::of(['id' => $id, 'title' => $title, 'phrases' => ['pay'], 'slots' => []]);
        $ont = Obj::of(['types' => [], 'templates' => [$t('a', 'Alpha'), $t('b', 'Beta')]]);
        $rule = I::ruleInterpreter();
        self::assertTrue($rule->deterministic);
        self::assertTrue(I::formInterpreter()->deterministic);
        $r = $rule->interpret(Obj::of(['principal' => 'p1', 'text' => 'please pay', 'ontology' => $ont]));
        self::assertSame(['ambiguous template'], $r->get('notes'));
        self::assertTrue($r->get('deterministic'));
        $holes = $r->get('goal')->get('holes');
        self::assertCount(1, $holes);
        self::assertSame('Is this "Alpha" or "Beta"?', $holes[0]->get('q'));
    }

    /** The prompt quotes sources only when asked; a non-list sources value is skipped when empty-like and refused when a string. */
    public function testBuildPromptSources(): void
    {
        $ont = Obj::of(['templates' => [Obj::of(['id' => 't', 'slots' => [Obj::of(['name' => 'a'])]])]]);
        $req = static fn(mixed $src) => Obj::of(['text' => 'hi', 'ontology' => $ont, 'sources' => $src]);
        $plain = "<principal_request>\nhi\n</principal_request>";
        self::assertSame($plain, I::buildPrompt($req(['DOC']))->get('user'));
        self::assertSame($plain . "\n<untrusted_data index=\"0\">\nDOC\n</untrusted_data>", I::buildPrompt($req(['DOC']), true)->get('user'));
        self::assertSame($plain, I::buildPrompt($req(5), true)->get('user'));
        self::assertSame($plain, I::buildPrompt($req(''), true)->get('user'));
        self::assertSame('TypeError: not an array', self::refusal(fn() => I::buildPrompt($req('abc'), true)));
        self::assertStringEndsWith('Domain: undefined. Templates: [{"template":"t","slots":[{"name":"a"}]}]', I::buildPrompt($req(null))->get('system'));
    }

    /** The model output is trimmed of exactly the JS whitespace set before the strict JSON parse. */
    public function testModelOutputTrimSet(): void
    {
        $j = '{"template":null,"slots":{}}';
        foreach (["\x0B", "\x0C", "\u{A0}", "\u{1680}", "\u{2000}", "\u{2001}", "\u{200A}", "\u{2028}", "\u{2029}", "\u{202F}", "\u{205F}", "\u{3000}", "\u{FEFF}", " \t\r\n", " \x0B", "\t\x0B", "\r\x0B", "\n\x0B"] as $w) {
            self::assertInstanceOf(Obj::class, I::parseTemplateJSON($w . $j . $w), bin2hex($w));
        }
        foreach (["\x1F", '!', "\x01", "\u{200B}", "\u{85}", "\u{1681}"] as $w) {
            self::assertSame('not JSON', I::parseTemplateJSON($w . $j), bin2hex($w));
        }
    }

    /** The model reader takes the first template with the named id, is non-deterministic and omits sources from the prompt by default. */
    public function testLlmInterpreter(): void
    {
        $ont = GoalOntologies::shippedOntology('payments');
        $tpls = $ont->get('templates');
        $dup = new Obj();
        foreach ($tpls[0]->keys() as $k) {
            $dup->set($k, $tpls[0]->get($k));
        }
        $dup->set('slots', []);
        $tpls[] = $dup;
        $ont->set('templates', $tpls);
        $seen = [];
        $llm = I::llmInterpreter('m', 'fam', static function (Obj $p) use (&$seen): string {
            $seen[] = $p->get('user');
            return '{"template":"refund_duplicate","slots":{"customer":"cus_1"}}';
        });
        self::assertFalse($llm->deterministic);
        $r = $llm->interpret(Obj::of(['principal' => 'p1', 'text' => 'refund cus_1', 'ontology' => $ont, 'sources' => ['DOC']]));
        self::assertSame([], $r->get('notes'));
        self::assertSame(["<principal_request>\nrefund cus_1\n</principal_request>"], $seen);
    }

    /** A missing recording refuses with the model id and the first 12 hex digits of the prompt key; recording stores under that key. */
    public function testRecordedCompletions(): void
    {
        $p = Obj::of(['system' => 's', 'user' => 'u']);
        $k = I::promptKey('m', $p);
        $want = 'InvalidArgumentException: no recorded output for m ' . substr($k, 0, 12);
        self::assertSame($want, self::refusal(fn() => I::replayCompletion('m', null)($p)));
        self::assertSame($want, self::refusal(fn() => I::replayCompletion('m', new Obj())($p)));
        $store = new Obj();
        self::assertSame('out', I::recordingCompletion('m', static fn($x) => 'out', $store)($p));
        self::assertSame([$k], $store->keys());
        self::assertSame('out', $store->get($k));
        self::assertSame('out', I::replayCompletion('m', $store)($p));
    }

    /** The Anthropic request asks for 1024 output tokens by default. */
    public function testAnthropicDefaultMaxTokens(): void
    {
        $bodies = [];
        $fetch = static function (string $url, Obj $init) use (&$bodies): object {
            $bodies[] = $init->get('body');
            return (object)['ok' => true, 'status' => 200, 'json' => Obj::of(['content' => [Obj::of(['type' => 'text', 'text' => 'hi'])]])];
        };
        self::assertSame('hi', I::anthropicCompletion('key', 'mod', $fetch)(Obj::of(['system' => 's', 'user' => 'u'])));
        self::assertCount(1, $bodies);
        self::assertStringStartsWith('{"model":"mod","max_tokens":1024,', $bodies[0]);
    }

    /** The typed refund form writes its integer limits as exact integer lexemes. */
    public function testRefundFormLimits(): void
    {
        $f = Obj::of(['template' => 'refund_duplicate', 'slots' => Obj::of(['ccy' => 'USD', 'customer' => 'cust:C1', 'max_amount_minor' => 500, 'max_refunds' => 3])]);
        $r = I::interpretForm($f, new Obj());
        self::assertTrue($r->get('ok'));
        $g = $r->get('goal');
        self::assertSame('500', $g->get('grants')[0]->get('cond')->get('r')->get('v')->get('q')->get('n')->lexeme);
        self::assertSame('3', $g->get('bounds')[0]->get('cap')->get('n')->lexeme);
    }
}
