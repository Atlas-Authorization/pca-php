<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionsImportSuggest.php';

use Atlas\Pca\ActionsImportSuggest as S;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The suggestion rules: rule-set validation at its exact limits, the signature check, the facts of a def, matching and applying. */
final class ToolSurvivorKill26ActionsImportSuggestTest extends TestCase
{
    private static function j(string $s): mixed
    {
        return Json::parseStrict($s);
    }

    private static function rule(string $match = '{"methods":["GET"]}', string $adds = '["pca.destructive"]', string $id = 'SR-001'): Obj
    {
        return self::j('{"id":"' . $id . '","match":' . $match . ',"adds":' . $adds . ',"note":"n"}');
    }

    private static function doc(array $rules): Obj
    {
        return Obj::of(['v' => new Num('1'), 'kind' => S::SUGGEST_RULES_KIND, 'version' => '1.0.0', 'rules' => $rules]);
    }

    private static function err(Obj $rule): ?string
    {
        return S::suggestRulesError(self::doc([$rule]));
    }

    private static function list(string $x, int $n): string
    {
        return json_encode(array_fill(0, $n, $x));
    }

    /** v must be the JSON number 1, not a native int. */
    public function testVersionMember(): void
    {
        self::assertNull(self::err(self::rule()), 'control');
        $d = self::doc([self::rule()]);
        $d->set('v', 1);
        self::assertSame('not a suggest-rules document (v 1)', S::suggestRulesError($d));
    }

    /** String lists hold up to 64 entries of up to 64 characters; methods are uppercase Unicode-aware. */
    public function testStringListLimits(): void
    {
        self::assertNull(self::err(self::rule('{"methods":' . self::list('GET', 64) . '}')));
        self::assertSame('SR-001: match.methods must be 1..64 short strings', self::err(self::rule('{"methods":' . self::list('GET', 65) . '}')));
        self::assertNull(self::err(self::rule('{"methods":["' . str_repeat('A', 64) . '"]}')));
        self::assertSame('SR-001: match.methods must be 1..64 short strings', self::err(self::rule('{"methods":["' . str_repeat('A', 65) . '"]}')));
        self::assertSame('SR-001: methods are uppercase', self::err(self::rule('{"methods":["é"]}')));
    }

    /** A rule set holds exactly up to MAX_RULES rules. */
    public function testRuleCountLimit(): void
    {
        $rules = [];
        for ($i = 0; $i < S::MAX_RULES; $i++) {
            $rules[] = self::rule('{"methods":["GET"]}', '["pca.destructive"]', sprintf('SR-%04d', $i));
        }
        self::assertNull(S::suggestRulesError(self::doc($rules)));
    }

    /** A note is 1..200 characters. */
    public function testNoteLimits(): void
    {
        $r = self::rule();
        $r->set('note', '');
        self::assertSame('SR-001: note must be 1..200 characters', self::err($r));
        $r->set('note', str_repeat('n', 200));
        self::assertNull(self::err($r));
    }

    /** effects lists up to 12 entries; path_re up to 128 characters; adds up to 16 entries. */
    public function testOtherLimits(): void
    {
        self::assertNull(self::err(self::rule('{"effects":' . self::list('read', 12) . '}')));
        self::assertSame('SR-001: match.effects must be a list of effects', self::err(self::rule('{"effects":' . self::list('read', 13) . '}')));
        self::assertNull(self::err(self::rule('{"path_re":"' . str_repeat('a', 128) . '"}')));
        self::assertNull(self::err(self::rule('{"methods":["GET"]}', self::list('pca.destructive', 16))));
        self::assertSame('SR-001: adds must be 1..16 entries', self::err(self::rule('{"methods":["GET"]}', self::list('pca.destructive', 17))));
    }

    /** A tag or a role needs a param matcher; param_types alone is refused. */
    public function testParamMatcherRules(): void
    {
        self::assertSame('SR-001: a tag needs a param matcher', self::err(self::rule('{"methods":["GET"]}', '["tag:pii"]')));
        self::assertNull(self::err(self::rule('{"param_names":["email"]}', '["tag:pii"]')), 'control');
        self::assertSame('SR-001: param_types needs param_names, param_names_all or param_formats', self::err(self::rule('{"param_types":["string"]}')));
    }

    /** A signed rule set verifies against the first pin with its kid; a non-object pin is skipped; a thrown check is reported, never raised. */
    public function testVerifyRules(): void
    {
        $seed = hash('sha256', 'atlas-pca-conformance/suggest-rules', true);
        $other = new KeyPair(hash('sha256', 'atlas-pca-conformance/suggest-rules-other', true));
        $signed = S::signRules(self::doc([self::rule()]), 'k1', $seed);
        $pin = Obj::of(['kid' => 'k1', 'pk' => (new KeyPair($seed))->public]);
        self::assertTrue(S::verifyRules($signed, [5, $pin])->get('ok'));
        self::assertTrue(S::verifyRules($signed, [$pin, Obj::of(['kid' => 'k1', 'pk' => $other->public])])->get('ok'));
        $bad = self::doc([self::rule()]);
        $bad->set('v', new Num('1e0'));
        $bad->set('sig', Obj::of(['kid' => 'k1']));
        $r = S::verifyRules($bad, [$pin]);
        self::assertFalse($r->get('ok'));
        self::assertStringStartsWith('rules verification error: ', $r->get('reason'));
        self::assertNotSame('rules verification error: ', $r->get('reason'));
    }

    /** The shipped rules are parsed once. */
    public function testDefaultRulesCached(): void
    {
        self::assertSame(S::defaultRules(), S::defaultRules());
    }

    /** -ed folding keeps a stem that itself ends in e for the final e-fold (agreed -> agr). */
    public function testStem(): void
    {
        self::assertSame('agr', S::stem('agreed'));
        self::assertSame('charg', S::stem('charged'), 'control');
    }

    private static function facts(string $bindings, string $effects = '["read"]'): array
    {
        $d = self::j('{"verb":"acme.thing.do","title":"T","params":{},"effects":' . $effects . ($bindings !== '' ? ',"bindings":' . $bindings : '') . '}');
        return S::factsOf($d);
    }

    /** Facts: methods from http and asyncapi (Unicode uppercased), grpc locations, locations cut to 512 units, distinct effects. */
    public function testFacts(): void
    {
        self::assertSame([], self::facts('')['methods']);
        self::assertSame(['GET'], self::facts('{"http":{"method":"get","path":"/a"}}')['methods']);
        self::assertSame(["\u{c9}"], self::facts('{"http":{"method":"é","path":"/a"}}')['methods']);
        self::assertSame(['SEND'], self::facts('{"asyncapi":{"channel":"c","op":"send"}}')['methods']);
        self::assertSame(['S/M'], self::facts('{"grpc":{"service":"S","method":"M"}}')['locs']);
        self::assertSame(['/' . str_repeat('a', 511)], self::facts('{"http":{"method":"get","path":"/' . str_repeat('a', 599) . '"}}')['locs']);
        self::assertSame(['create', 'update'], self::facts('', '["create","create","update"]')['effects']);
    }

    /** A path segment holding either brace is a template, not tokens. */
    public function testPathTemplateSegments(): void
    {
        self::assertSame(self::facts('{"http":{"method":"get","path":"/{x}"}}')['tokens'], self::facts('{"http":{"method":"get","path":"/{abc"}}')['tokens']);
        self::assertSame(self::facts('{"http":{"method":"get","path":"/{x}"}}')['tokens'], self::facts('{"http":{"method":"get","path":"/abc}"}}')['tokens']);
    }

    /** Private helpers: an empty pattern never matches; only a string role fits; time roles fit dates. */
    public function testHelpers(): void
    {
        $call = static fn(string $m, mixed ...$a): mixed => (new \ReflectionMethod(S::class, $m))->invoke(null, ...$a);
        self::assertFalse($call('hasSeq', ['a'], []));
        self::assertFalse($call('roleFits', 5, 'string'));
        self::assertTrue($call('roleFits', 'time.at', 'date'));
    }

    private static function suggest(string $params, array $rules): Obj
    {
        $d = self::j('{"verb":"acme.thing.do","title":"T","params":' . $params . ',"effects":["update"]}');
        return S::suggestWithRules($d, Obj::of(['rules' => $rules]));
    }

    /** A roles matcher fires on a param carrying one of its roles. */
    public function testSuggestRoles(): void
    {
        $s = self::suggest('{"amount":{"type":"integer","role":"money.amount"}}', [self::rule('{"roles":["money.amount"]}')]);
        self::assertSame(['SR-001'], $s->get('fired'));
        self::assertSame(['pca.destructive'], $s->get('traits'));
    }

    /** Tags from several rules accumulate per param, params sorted by name. */
    public function testSuggestTags(): void
    {
        $s = self::suggest('{"alpha":{"type":"string"},"bravo":{"type":"string"}}', [
            self::rule('{"param_names":["bravo"]}', '["tag:pii"]', 'SR-001'),
            self::rule('{"param_names":["bravo"]}', '["tag:path"]', 'SR-002'),
            self::rule('{"param_names":["alpha"]}', '["tag:pii"]', 'SR-003'),
        ]);
        self::assertSame('{"alpha":["pii"],"bravo":["path","pii"]}', Js::stringify($s->get('tags')));
    }

    /** A role is suggested only for a param without one, and the first suggestion wins. */
    public function testSuggestRolesFirstWins(): void
    {
        $s = self::suggest('{"count":{"type":"integer"},"fee":{"type":"integer","role":"money.fee"}}', [
            self::rule('{"param_names":["count"]}', '["count.limit"]', 'SR-001'),
            self::rule('{"param_names":["count"]}', '["money.amount"]', 'SR-002'),
            self::rule('{"param_names":["fee"]}', '["money.amount"]', 'SR-003'),
        ]);
        self::assertSame('{"count":"count.limit"}', Js::stringify($s->get('roles')));
    }

    /** Applying keeps a param's own role, adds only new tags (recording only those), and merges the provenance (new rules win, models append). */
    public function testApplySuggestion(): void
    {
        $d = self::j('{"verb":"acme.thing.do","params":{"amount":{"type":"integer","role":"money.fee"},"to":{"type":"string","tags":["pii"]},'
            . '"x":{"type":"string","tags":["code"]}},"review":{"state":"unreviewed","suggested_by":{"rules":{"version":"1"},"models":["m1"]}}}');
        $s = self::j('{"traits":[],"roles":{"amount":"money.amount"},"tags":{"to":["pii"],"x":["path"]},"fired":[]}');
        $out = S::applySuggestion($d, $s, self::j('{"rules":{"version":"2"},"models":["m2"]}'));
        self::assertSame('money.fee', $out->get('params')->get('amount')->get('role'));
        self::assertSame(['code', 'path'], $out->get('params')->get('x')->get('tags'));
        $sb = $out->get('review')->get('suggested_by');
        self::assertSame('{"x":["path"]}', Js::stringify($sb->get('added')->get('tags')));
        self::assertSame('2', $sb->get('rules')->get('version'));
        self::assertSame(['m1', 'm2'], $sb->get('models'));
        self::assertSame('suggested', $out->get('review')->get('state'));
    }

    /** A non-object idempotency is left as it is when money moving is suggested. */
    public function testApplyMoneyIdempotencyNonObject(): void
    {
        $d = self::j('{"verb":"acme.thing.do","params":{},"idempotency":"none","review":{"state":"authored"}}');
        $out = S::applySuggestion($d, self::j('{"traits":["pca.money_moving"],"roles":{},"tags":{},"fired":[]}'), new Obj());
        self::assertSame('none', $out->get('idempotency'));
    }
}
