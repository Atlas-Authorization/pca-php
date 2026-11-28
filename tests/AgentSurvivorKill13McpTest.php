<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Action;
use Atlas\Pca\Agent;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Mcp;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\ProvenanceRecorder;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for the MCP adapter: UTF-16 unit splitting in todo texts and 1024-unit clips, the JSON-pointer walk, schema
 * flattening (allOf / anyOf / oneOf / const / depth and node budgets), the draft's parameter declarations, decision application,
 * tool lookup, the proof header on tools/call, the response recorder and the WWW-Authenticate step-up parser.
 */
final class AgentSurvivorKill13McpTest extends TestCase
{
    private static function agent(): Agent
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return new Agent($key, Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'], 'rs-test');
    }

    /** Runs $f and asserts it raised no PHP warning or notice. */
    private static function quiet(callable $f): mixed
    {
        $w = [];
        set_error_handler(static function (int $no, string $msg) use (&$w): bool {
            $w[] = $msg;
            return true;
        });
        try {
            $r = $f();
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $w);
        return $r;
    }

    private static function draft(mixed $schema, array $tool = []): Obj
    {
        $t = Obj::of(['name' => 't', 'inputSchema' => is_string($schema) ? Js::parse($schema) : $schema] + $tool);
        return Mcp::draftActionSchemaFromMcp([$t], Obj::of(['site' => 's']));
    }

    private static function decl(Obj $r, string $name): ?Obj
    {
        return $r->get('schema')->get('verbs')[0]->get('params')->get("action.params.$name");
    }

    private static function nest(string $kw, string $inner, int $n): string
    {
        for ($i = 0; $i < $n; $i++) {
            $inner = '{"' . $kw . '":[' . $inner . ']}';
        }
        return $inner;
    }

    // ---- UTF-16 units ----

    /** An unresolvable $ref is quoted by its first 120 UTF-16 units, astral characters as WTF-8 surrogate halves. */
    public function testRefTodoQuotesTheFirst120Utf16Units(): void
    {
        $ref = '#/' . "\x80a" . 'éa' . "\u{800}\u{1F601}" . '€😀' . 'é😀' . "\u{10FFFF}\u{40000}\u{C0000}\u{1F600}\u{2ABCD}" . str_repeat('z', 200) . "\xF0\x9F";
        $r = self::quiet(fn() => self::draft(Obj::of(['$ref' => $ref])));
        $quoted = hex2bin('232f8061c3a961e0a080eda0bdedb881e282aceda0bdedb880c3a9eda0bdedb880edafbfedbfbfeda380edb080edab80edb080eda0bdedb880eda1aaedbf8d') . str_repeat('z', 96);
        self::assertSame(["t: inputSchema: reference '$quoted' is not a local reference that resolves (declared string; refine or drop)", 't: reversibility (drafted irreversible)'], $r->get('todo'));
    }

    /** Descriptions clip to 1024 UTF-16 units: exactly 1024 stays untouched, 1025 keeps the first 1024, a list keeps 1024 items. */
    public function testDescriptionClip(): void
    {
        $desc = static fn(mixed $d): mixed => self::draft('{}', ['description' => $d])->get('schema')->get('verbs')[0]->get('description');
        $s = str_repeat('a', 1022) . '😀';
        self::assertSame($s, $desc($s));
        self::assertSame('b' . str_repeat('a', 1023), $desc('b' . str_repeat('a', 1024)));
        self::assertSame(range(0, 1023), $desc(range(0, 1024)));
        try {
            $desc(5);
            self::fail('a number has no slice');
        } catch (\TypeError $e) {
            self::assertSame('slice is not a function', $e->getMessage());
        }
    }

    // ---- schema flattening ----

    /** JSON-pointer walk: ~1 and ~0 unescape, list indices resolve, a scalar target does not. */
    public function testPointerWalk(): void
    {
        $r = self::draft('{"properties":{"p":{"$ref":"#/$defs/a~1b"},"q":{"$ref":"#/$defs/c~0d"},"r":{"$ref":"#/$defs/arr/0"},"s":{"$ref":"#/$defs/str"}},'
            . '"$defs":{"a/b":{"type":"integer"},"c~d":{"type":"boolean"},"arr":[{"type":"integer"}],"str":"x"}}');
        self::assertSame(['integer', 'boolean', 'integer'], [self::decl($r, 'p')->get('type'), self::decl($r, 'q')->get('type'), self::decl($r, 'r')->get('type')]);
        $todo = $r->get('todo');
        self::assertContains("action.params.s: reference '#/\$defs/str' is not a local reference that resolves (declared string; refine or drop)", $todo);
        self::assertCount(1, array_filter($todo, static fn(string $t): bool => str_contains($t, 'reference')));
    }

    /** A list index past the end or not a number does not resolve, and reads no missing element. */
    public function testPointerIndexOutOfRange(): void
    {
        $r = self::quiet(fn() => self::draft('{"properties":{"p":{"$ref":"#/$defs/arr/1"},"q":{"$ref":"#/$defs/arr/x"}},"$defs":{"arr":[{"type":"integer"}]}}'));
        self::assertContains("action.params.p: reference '#/\$defs/arr/1' is not a local reference that resolves (declared string; refine or drop)", $r->get('todo'));
        self::assertContains("action.params.q: reference '#/\$defs/arr/x' is not a local reference that resolves (declared string; refine or drop)", $r->get('todo'));
    }

    /** Depth: a $ref chain of 5 and an anyOf nest of 5 resolve; 9 levels stop with the depth todo; a non-schema leaf at depth 9 is silent. */
    public function testDepthLimits(): void
    {
        $deep = 'action.params.p: schema nesting or reference chain deeper than 8 (declared string; refine or drop)';
        $r = self::draft('{"properties":{"p":{"$ref":"#/$defs/d1"}},"$defs":{"d1":{"$ref":"#/$defs/d2"},"d2":{"$ref":"#/$defs/d3"},"d3":{"$ref":"#/$defs/d4"},"d4":{"$ref":"#/$defs/d5"},"d5":{"type":"integer"}}}');
        self::assertSame('integer', self::decl($r, 'p')->get('type'));
        $r = self::draft('{"properties":{"p":' . self::nest('anyOf', '{"type":"integer"}', 5) . '}}');
        self::assertSame('integer', self::decl($r, 'p')->get('type'));
        self::assertContains($deep, self::draft('{"properties":{"p":' . self::nest('anyOf', '{}', 9) . '}}')->get('todo'));
        self::assertContains($deep, self::draft('{"properties":{"p":' . self::nest('allOf', '[]', 9) . '}}')->get('todo'));
        self::assertNotContains($deep, self::draft('{"properties":{"p":' . self::nest('allOf', '"x"', 9) . '}}')->get('todo'));
    }

    /** The 20000-node budget: node 20000 is still expanded, node 20001 stops with exactly one todo. */
    public function testNodeBudget(): void
    {
        $parts = [];
        for ($i = 1; $i <= 19999; $i++) {
            $parts[] = $i === 19998 ? Obj::of(['type' => 'integer']) : new Obj();
        }
        $r = self::draft(Obj::of(['properties' => Obj::of(['p' => Obj::of(['allOf' => $parts])])]));
        self::assertSame('integer', self::decl($r, 'p')->get('type'));
        $stop = array_values(array_filter($r->get('todo'), static fn(string $t): bool => str_contains($t, 'expansion')));
        self::assertSame(['action.params.p: schema expansion stopped after 20000 nodes (declared string; refine or drop)'], $stop);
    }

    /** allOf merges every part's properties and required lists. */
    public function testAllOfMerge(): void
    {
        $r = self::draft('{"allOf":[{"properties":{"a":{"type":"string"}},"required":["a"]},{"properties":{"b":{"type":"string"}},"required":["b"]}]}');
        self::assertNotNull(self::decl($r, 'a'));
        self::assertNotNull(self::decl($r, 'b'));
        self::assertFalse(self::decl($r, 'a')->has('required'));
        self::assertFalse(self::decl($r, 'b')->has('required'));
    }

    /** Parameter declarations: const / enum, items, unions, the safe-integer bound, a string `required`. */
    public function testParameterDeclarations(): void
    {
        $r = self::draft('{"properties":{'
            . '"a":{"type":"string","const":"a"},'
            . '"b":{"type":"string","const":"a","enum":["a","b"]},'
            . '"c":{"type":"array","items":{"$ref":"#/nope"}},'
            . '"d":{"type":"array","items":{"enum":["a","b"]}},'
            . '"e":{"type":"array","items":{"type":["integer","null"]}},'
            . '"f":{"type":"array","items":{},"minItems":1},'
            . '"g":{"type":"integer","minimum":9007199254740991},'
            . '"h":{"anyOf":[{"type":"integer"}],"oneOf":[{"type":"boolean"}]},'
            . '"i":{"anyOf":[{"type":"string"}],"description":"D"},'
            . '"j":{"anyOf":[{"const":"a"},{"const":"a"},{"const":"b"}]},'
            . '"k":{"anyOf":[{"type":["null"]},{"type":"integer"}]}'
            . '},"required":"ab"}');
        self::assertSame(['a'], self::decl($r, 'a')->get('values'));
        self::assertFalse(self::decl($r, 'a')->has('required'));
        self::assertSame(['a', 'b'], self::decl($r, 'b')->get('values'));
        self::assertFalse(self::decl($r, 'b')->has('required'));
        self::assertFalse(self::decl($r, 'c')->get('required'));
        self::assertContains("action.params.c[]: reference '#/nope' is not a local reference that resolves (declared string; refine or drop)", $r->get('todo'));
        self::assertSame('array', self::decl($r, 'd')->get('type'));
        self::assertSame('integer', self::decl($r, 'e')->get('items'));
        self::assertSame(1.0, Js::num(self::decl($r, 'f')->get('min_items')));
        self::assertSame(9007199254740991.0, Js::num(self::decl($r, 'g')->get('min')));
        self::assertSame('integer', self::decl($r, 'h')->get('type'));
        self::assertSame('D', self::decl($r, 'i')->get('description'));
        self::assertSame(['a', 'b'], self::decl($r, 'j')->get('values'));
        self::assertSame('integer', self::decl($r, 'k')->get('type'));
    }

    /** properties given as a list name their indices; a non-iterable required is the reference's TypeError. */
    public function testListPropertiesAndBadRequired(): void
    {
        self::assertSame('integer', self::decl(self::draft('{"properties":[{"type":"integer"}]}'), '0')->get('type'));
        try {
            self::draft('{"required":5}');
            self::fail('required 5');
        } catch (\TypeError $e) {
            self::assertSame('value is not iterable', $e->getMessage());
        }
    }

    /** The tool list may be a closure or an object with `tools`; anything else and a null site are the reference's TypeErrors. */
    public function testDraftToolSources(): void
    {
        $tool = Obj::of(['name' => 't', 'inputSchema' => new Obj()]);
        self::assertCount(1, Mcp::draftActionSchemaFromMcp(static fn() => Obj::of(['tools' => [$tool]]), new Obj())->get('schema')->get('verbs'));
        self::assertCount(1, Mcp::draftActionSchemaFromMcp(Obj::of(['tools' => [$tool]]), new Obj())->get('schema')->get('verbs'));
        foreach ([[Obj::of(['tools' => 5]), new Obj(), 'tools is not iterable'], [[], null, "Cannot read properties of null (reading 'site')"]] as [$tools, $site, $msg]) {
            try {
                Mcp::draftActionSchemaFromMcp($tools, $site);
                self::fail($msg);
            } catch (\TypeError $e) {
                self::assertSame($msg, $e->getMessage());
            }
        }
    }

    // ---- applySchemaDecisions ----

    /** Decisions apply to a deep copy (the draft is untouched), to the FIRST verb of a name, and skip non-object entries. */
    public function testApplyDecisionsCopiesAndPicksTheFirstVerb(): void
    {
        $draft = Js::parse('{"verbs":[5,{"verb":"v","params":{"action.params.a":{"type":"string"},"action.params.b":"s"}},{"verb":"v"}]}');
        $d = Js::parse('{"verbs":{"v":{"reversibility":"reversible","params":{"action.params.a":{"semantic":"x"},"action.params.b":{"semantic":"y"}}}}}');
        $out = Mcp::applySchemaDecisions($draft, $d);
        self::assertSame('reversible', $out->get('verbs')[1]->get('reversibility'));
        self::assertSame('x', $out->get('verbs')[1]->get('params')->get('action.params.a')->get('semantic'));
        self::assertFalse($out->get('verbs')[2]->has('reversibility'));
        self::assertFalse($draft->get('verbs')[1]->has('reversibility'));
        self::assertFalse($draft->get('verbs')[1]->get('params')->get('action.params.a')->has('semantic'));
        // decisions keyed by a string's indices: each decision is that character
        self::assertInstanceOf(Obj::class, Mcp::applySchemaDecisions(Js::parse('{"verbs":[{"verb":"0"}]}'), Obj::of(['verbs' => 'x'])));
    }

    /** applySchemaDecisions refusals keep their class and message. */
    public function testApplyDecisionsRefusals(): void
    {
        $cases = [
            [Js::parse('{}'), null, \TypeError::class, "Cannot read properties of null (reading 'units')"],
            [[], Js::parse('{"units":{"u":"x"},"verbs":{}}'), \TypeError::class, 'draft is not an object'],
            [Js::parse('{"verbs":5}'), Js::parse('{"verbs":{"x":{}}}'), \TypeError::class, 'out.verbs.find is not a function'],
            [Js::parse('{"verbs":[null,{"verb":"x"}]}'), Js::parse('{"verbs":{"x":{}}}'), \TypeError::class, "Cannot read properties of null (reading 'verb')"],
            [Js::parse('{"verbs":[{"verb":"x","params":5}]}'), Js::parse('{"verbs":{"x":{"params":{"p":{}}}}}'), \InvalidArgumentException::class, "applySchemaDecisions: verb 'x' has no parameter 'p'"],
        ];
        foreach ($cases as [$draft, $d, $class, $msg]) {
            try {
                Mcp::applySchemaDecisions($draft, $d);
                self::fail($msg);
            } catch (\Throwable $e) {
                self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            }
        }
    }

    // ---- tool lookup ----

    /** verbOfTool: a verb without an mcp.tool never matches a null name, a non-object entry is not returned, nulls throw. */
    public function testVerbOfTool(): void
    {
        self::assertNull(Mcp::verbOfTool(Js::parse('{"verbs":[{"verb":"v","mcp":{}}]}'), null));
        self::assertNull(Mcp::verbOfTool(Obj::of(['verbs' => [['verb' => 'v', 'mcp' => ['tool' => 't']]]]), 't'));
        foreach ([[null, "Cannot read properties of null (reading 'verbs')"], [Obj::of(['verbs' => [null]]), "Cannot read properties of null (reading 'mcp')"]] as [$schema, $msg]) {
            try {
                Mcp::verbOfTool($schema, 't');
                self::fail($msg);
            } catch (\TypeError $e) {
                self::assertSame($msg, $e->getMessage());
            }
        }
    }

    /** importActionDefsFromMcp takes a listTools() object or a {tools} object; array options reach the importer (and fail its ns check). */
    public function testImportSources(): void
    {
        $tools = [Js::parse('{"name":"t","inputSchema":{"type":"object"}}')];
        $lister = new class ($tools) {
            public function __construct(private array $t)
            {
            }

            public function listTools(): Obj
            {
                return Obj::of(['tools' => $this->t]);
            }
        };
        $opts = Obj::of(['ns' => 'x']);
        self::assertCount(1, Mcp::importActionDefsFromMcp($lister, $opts)->get('defs'));
        self::assertCount(1, Mcp::importActionDefsFromMcp(Obj::of(['tools' => $tools]), $opts)->get('defs'));
        try {
            Mcp::importActionDefsFromMcp($tools, ['ns' => 'x']);
            self::fail('array options are not an Obj');
        } catch (ActionKitError $e) {
            self::assertSame('bad_ns', $e->codeName);
        }
    }

    // ---- tool results and proofs ----

    /** deniedResult is one text item marked type "text". */
    public function testDeniedResult(): void
    {
        $r = Mcp::deniedResult('no');
        self::assertSame(['text', 'no'], [$r->get('content')[0]->get('type'), $r->get('content')[0]->get('text')]);
        self::assertTrue($r->get('isError'));
    }

    /** withPca stringifies a non-string verb / resource before the envelope check and before signing, and calls onProof. */
    public function testWithPcaStringifiesAndCallsOnProof(): void
    {
        $ok = static fn(): string => 'ok';
        $tool = Mcp::withPca(self::agent(), ['verb' => 'refund', 'resourceOf' => static fn($a) => 7], $ok);
        self::assertTrue($tool(['r' => 1])->get('isError'));
        $tool = Mcp::withPca(self::agent(), ['verb' => 5, 'resource' => 'orders/1'], $ok);
        self::assertTrue($tool(['r' => 1])->get('isError'));
        self::assertSame('ok', Mcp::withPca(self::agent(), ['verb' => 'refund', 'failFast' => false, 'resourceOf' => static fn($a) => 7], $ok)(['r' => 1]));
        self::assertSame('ok', Mcp::withPca(self::agent(), ['verb' => 5, 'failFast' => false, 'resource' => 'orders/1'], $ok)(['r' => 1]));
        $seen = [];
        $tool = Mcp::withPca(self::agent(), ['verb' => 'refund', 'resource' => 'orders/1', 'onProof' => static function ($pca, $args) use (&$seen): void {
            $seen[] = [$pca instanceof Action, $args];
        }], $ok);
        self::assertSame('ok', $tool(['r' => 1]));
        self::assertSame([[true, ['r' => 1]]], $seen);
    }

    private static function call(string $tool): string
    {
        return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/call', 'params' => ['name' => $tool, 'arguments' => ['order' => 'orders/7']]]);
    }

    private static function proofText(string $header): string
    {
        return (string)Pca::unb64u($header);
    }

    /** withProof adds the signed header (verb, resource from the tool action) to the headers; other requests pass through unchanged. */
    public function testWithProof(): void
    {
        $map = static fn(string $tool, Obj $args): ?array => $tool === 'refund' ? ['refund', 'orders/7'] : null;
        $h = ['x' => '1', 'y' => '2'];
        $out = Mcp::withProof(self::agent(), $map, self::call('refund'), $h);
        self::assertSame(['x', 'y', 'PCA-Action'], array_keys($out));
        self::assertSame(['1', '2'], [$out['x'], $out['y']]);
        $text = self::proofText($out['PCA-Action']);
        self::assertStringContainsString('"resource":"orders/7"', $text);
        self::assertStringContainsString('"verb":"refund"', $text);
        self::assertSame($h, Mcp::withProof(self::agent(), $map, self::call('other'), $h));
        self::assertSame($h, Mcp::withProof(self::agent(), $map, '{"jsonrpc":"2.0","method":"tools/list"}', $h));
    }

    /** pcaFetch signs the tool action's verb and resource. */
    public function testPcaFetchSignsTheMappedAction(): void
    {
        $seen = [];
        $f = Mcp::pcaFetch(self::agent(), static fn(string $tool, $args): ?array => ['refund', 'orders/7'], static function (string $url, array $init) use (&$seen): string {
            $seen[] = $init;
            return 'ok';
        });
        $f('http://x/mcp', ['body' => self::call('refund')]);
        $text = self::proofText($seen[0]['headers']['PCA-Action']);
        self::assertStringContainsString('"resource":"orders/7"', $text);
        self::assertStringContainsString('"verb":"refund"', $text);
    }

    private static function recorded(mixed $res): string
    {
        $rec = new ProvenanceRecorder('m', 'k', new KeyPair(str_repeat("\x03", 32)), null, static fn(): int => 1000);
        $f = Mcp::pcaFetch(self::agent(), static fn(string $tool, $args): ?array => ['refund', 'orders/7'], static fn(string $url, array $init): mixed => $res, $rec);
        self::assertSame($res, $f('http://x/mcp', ['body' => self::call('refund')]));
        self::assertCount(1, $rec->receipts());
        self::assertSame('refund', $rec->receipts()[0]->get('source'));
        return $rec->receipts()[0]->get('content_digest');
    }

    /** The recorder gets the body of a readable response, but only the origin of an event stream; a non-string content-type is text. */
    public function testRecorderContent(): void
    {
        $res = static fn(mixed $ct): object => new class ($ct) {
            public function __construct(private mixed $ct)
            {
            }

            public function header(string $n): mixed
            {
                return $this->ct;
            }

            public function text(): string
            {
                return 'BODY';
            }
        };
        $body = IntentWb::valueDigest('BODY');
        $origin = IntentWb::valueDigest(Json::canonicalizeLenient(Sign::n(Obj::of(['tool' => 'refund', 'stream' => 'http://x/mcp']))));
        self::assertSame($origin, self::recorded($res('text/event-stream')));
        self::assertSame($body, self::recorded($res('application/json')));
        self::assertSame($body, self::recorded($res(5)));
    }

    // ---- WWW-Authenticate ----

    /** A header that is not UTF-8 still yields its pca_need through the ASCII-only pattern. */
    public function testPcaNeedFromNonUtf8Header(): void
    {
        self::assertSame(['ok' => false, 'code' => 'bad_base64'], Mcp::pcaNeedFromChallenge("Bearer pca_need=\"!\", x=\"\xff\""));
    }

    /** Challenge names lower-case even when not UTF-8; a backslash escapes inside a quoted value but a trailing one is kept. */
    public function testParseChallenges(): void
    {
        self::assertSame("bearer\xff", Mcp::parseChallenges("BEARER\xff")[0]->get('scheme'));
        $v = static fn(string $h): mixed => self::quiet(static fn() => Mcp::parseChallenges($h))[0]->get('params')->get('a');
        self::assertSame('x\\', $v('Bearer a="x\\'));
        self::assertSame('x"', $v('Bearer a="x\\"'));
    }

    /** planStepUp: the FIRST bearer challenge decides; the union is sorted by UTF-16 units and stays a list of strings. */
    public function testPlanStepUp(): void
    {
        $st = static fn(array $req): array => ['requested' => $req, 'attempts' => 0];
        self::assertSame(['action' => 'scope', 'scopes' => ['a'], 'attempts' => 1.0],
            Mcp::planStepUp(403, 'Bearer error="insufficient_scope", scope="a", Bearer error="other"', $st([])));
        self::assertSame(['action' => 'scope', 'scopes' => ['x', '𐀀', '｡'], 'attempts' => 1.0],
            Mcp::planStepUp(403, 'Bearer error="insufficient_scope", scope="x"', $st(['｡', '𐀀'])));
        self::assertSame(['action' => 'scope', 'scopes' => ['1', '2'], 'attempts' => 1.0],
            Mcp::planStepUp(403, 'Bearer error="insufficient_scope", scope="2"', $st(['1'])));
    }
}
