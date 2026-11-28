<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ActionSchemaDraft.php';

use Atlas\Pca\ActionSchemaDraft as A;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The drafting importers: safe integers, value-dependent reversibility, reference resolution, flattening limits and the MCP / OpenAPI drafts. */
final class ToolSurvivorKill26ActionSchemaDraftTest extends TestCase
{
    private static function j(string $s): mixed
    {
        return Json::parseStrict($s);
    }

    private static function call(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(A::class, $m))->invoke(null, ...$a);
    }

    private static function site(): Obj
    {
        return Obj::of(['site' => 's', 'aud' => 'a', 'version' => '1']);
    }

    /** Draft one read-only MCP tool with these input properties. @return array{0:Obj,1:list<string>} [params, todo] */
    private static function mcp(Obj $props, ?Obj $defs = null): array
    {
        $input = Obj::of(['type' => 'object', 'properties' => $props]);
        if ($defs !== null) {
            $input->set('$defs', $defs);
        }
        $r = A::draftSchemaFromMcpTools([Obj::of(['name' => 't', 'inputSchema' => $input, 'annotations' => Obj::of(['readOnlyHint' => true])])], self::site());
        return [$r->get('schema')->get('verbs')[0]->get('params'), $r->get('todo')];
    }

    /** The declaration of the single property p. */
    private static function p(string $schema): Obj
    {
        return self::mcp(Obj::of(['p' => self::j($schema)]))[0]->get('action.params.p');
    }

    private static function todoOf(string $schema): array
    {
        return self::mcp(Obj::of(['p' => self::j($schema)]))[1];
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'accepted';
    }

    /** A safe integer reaches exactly 2^53-1; isInt refuses negative zero only. */
    public function testSafeIntAndIsInt(): void
    {
        self::assertTrue(self::call('safeInt', new Num('9007199254740991')));
        self::assertFalse(self::call('safeInt', new Num('9007199254740992')));
        self::assertFalse(self::call('isInt', new Num('-0')));
        self::assertTrue(self::call('isInt', new Num('0')));
        self::assertTrue(self::call('isInt', new Num('-5')));
        self::assertTrue(self::call('isInt', new Num('5')));
    }

    /** reversibility_by: params that are not an object give the default; a non-string param refuses with the reference's error; names slice by characters. */
    public function testReversibilityBy(): void
    {
        $v = self::j('{"reversibility_by":{"param":"action.params.n","map":{"a":"reversible"},"default":"rate_limited"}}');
        self::assertSame('reversible', A::reversibilityOf($v, self::j('{"n":"a"}')), 'control');
        self::assertSame('rate_limited', A::reversibilityOf($v, null));
        self::assertSame('TypeError: param.slice is not a function', self::thrown(fn() => A::reversibilityOf(self::j('{"reversibility_by":{"param":5}}'), null)));
        $u = self::j('{"reversibility_by":{"param":"' . str_repeat("\u{e9}", 14) . 'n","map":{"a":"reversible"}}}');
        self::assertSame('reversible', A::reversibilityOf($u, self::j('{"n":"a"}')));
    }

    /** A non-string semantic refuses with the reference's error. */
    public function testFloorAppliesNonString(): void
    {
        self::assertSame('TypeError: semantic.startsWith is not a function', self::thrown(fn() => A::floorApplies(5)));
    }

    /** Local references: list indexes resolve in range only (no leading zero), a scalar is never a target, long references are clipped by character. */
    public function testReferences(): void
    {
        $refs = ['p' => '#/$defs/L/0', 'q' => '#/$defs/L/2', 'r' => '#/$defs/L/01', 's' => '#/$defs/S/0', 'u' => '#/$defs/S', 'v' => '#/' . str_repeat("\u{e9}", 130)];
        $props = new Obj();
        foreach ($refs as $k => $r) {
            $props->set($k, Obj::of(['$ref' => $r]));
        }
        $errs = [];
        set_error_handler(static function (int $no, string $msg) use (&$errs): bool {
            $errs[] = $msg;
            return true;
        });
        try {
            [$params, $todo] = self::mcp($props, self::j('{"L":[{"type":"integer"},{"type":"boolean"}],"S":"str"}'));
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $errs, 'an out-of-range index is refused before it is read');
        self::assertSame('integer', $params->get('action.params.p')->get('type'));
        foreach (['q' => '#/$defs/L/2', 'r' => '#/$defs/L/01', 's' => '#/$defs/S/0', 'u' => '#/$defs/S', 'v' => '#/' . str_repeat("\u{e9}", 118)] as $k => $shown) {
            self::assertContains("action.params.$k: reference '$shown' is not a local reference that resolves (declared string; refine or drop)", $todo);
        }
    }

    /** A $ref keeps its sibling members; a list or scalar schema is an empty schema. */
    public function testRefSiblingsAndNonObjects(): void
    {
        [$params] = self::mcp(Obj::of(['p' => self::j('{"$ref":"#/$defs/A","description":"d"}')]), self::j('{"A":{"type":"string"}}'));
        self::assertSame('string', $params->get('action.params.p')->get('type'));
        self::assertSame('d', $params->get('action.params.p')->get('description'));
        self::assertSame('string', self::p('[1]')->get('type'));
    }

    /** allOf and anyOf chains expand to depth 8 and stop past it; a scalar past the depth is just an empty schema. */
    public function testDepthLimit(): void
    {
        $chain = static function (string $key, int $n, string $inner): string {
            return str_repeat('{"' . $key . '":[', $n) . $inner . str_repeat(']}', $n);
        };
        $deeper = 'action.params.p: schema nesting or reference chain deeper than 8 (declared string; refine or drop)';
        foreach (['allOf', 'anyOf'] as $key) {
            self::assertSame('integer', self::p($chain($key, 8, '{"type":"integer"}'))->get('type'), $key);
            self::assertNotContains($deeper, self::todoOf($chain($key, 8, '{"type":"integer"}')), $key);
            self::assertContains($deeper, self::todoOf($chain($key, 9, '{"type":"integer"}')), $key);
        }
        self::assertNotContains($deeper, self::todoOf($chain('allOf', 9, '"x"')));
    }

    /** One draft expands at most 20000 schema nodes: the last allowed node is expanded, the next one stops with a single note. */
    public function testNodeBudget(): void
    {
        $null = Obj::of(['type' => 'null']);
        $run = static function (int $alts) use ($null): array {
            $xs = array_fill(0, $alts - 1, $null);
            $xs[] = Obj::of(['type' => 'string', 'const' => 'a']);
            return self::mcp(Obj::of(['p' => Obj::of(['anyOf' => $xs])]));
        };
        $stop = 'action.params.p: schema expansion stopped after 20000 nodes (declared string; refine or drop)';
        // nodes: the input schema, p, then one per alternative
        [$params, $todo] = $run(19998);
        self::assertSame(['a'], $params->get('action.params.p')->get('values'));
        self::assertNotContains($stop, $todo);
        [$params, $todo] = $run(19999);
        self::assertFalse($params->get('action.params.p')->has('values'));
        self::assertSame(1, count(array_keys($todo, $stop, true)));
    }

    /** Unions: a ['null'] type is null; one live variant keeps the siblings; mixed enums are not a string union. */
    public function testUnions(): void
    {
        self::assertSame('integer', self::p('{"anyOf":[{"type":["null"]},{"type":"integer"}]}')->get('type'));
        $p = self::p('{"anyOf":[{"type":"integer"},{"type":"null"}],"description":"d"}');
        self::assertSame('integer', $p->get('type'));
        self::assertSame('d', $p->get('description'));
        self::assertContains('action.params.p: a union of 2 schemas has no schema representation (declared string; refine or drop)', self::todoOf('{"anyOf":[{"enum":["a"]},{"enum":[1]}]}'));
    }

    /** const becomes the enum only when no enum is declared. */
    public function testConstKeepsEnum(): void
    {
        self::assertSame(['b'], self::p('{"type":"string","const":"a","enum":["b"]}')->get('values'));
    }

    /** A type list takes its first non-null member. */
    public function testTypeList(): void
    {
        self::assertSame('integer', self::p('{"type":["null","integer","string"]}')->get('type'));
    }

    /** Arrays: item notes are placed at name[]; enum items without uniqueItems stay an array; an integer-or-null item type is integer. */
    public function testArrays(): void
    {
        self::assertContains("action.params.p[]: reference '#/nope' is not a local reference that resolves (declared string; refine or drop)",
            self::todoOf('{"type":"array","items":{"$ref":"#/nope"}}'));
        self::assertSame('array', self::p('{"type":"array","items":{"type":"string","enum":["a"]}}')->get('type'));
        self::assertSame('integer', self::p('{"type":"array","items":{"type":["integer","null"]}}')->get('items'));
    }

    /** A non-string tool description refuses with the reference's error. */
    public function testDescriptionNonString(): void
    {
        $tool = Obj::of(['name' => 't', 'description' => 5, 'inputSchema' => self::j('{"type":"object"}')]);
        self::assertSame('TypeError: s.description.slice is not a function', self::thrown(fn() => A::draftSchemaFromMcpTools([$tool], self::site())));
    }

    private static function openApi(string $paths): Obj
    {
        return A::draftSchemaFromOpenApi(self::j('{"paths":' . $paths . '}'), self::site());
    }

    /** Request bodies: a +json media type matches case-insensitively, and the first in order wins. */
    public function testJsonBodyMediaType(): void
    {
        $body = static fn(string $ct, string $prop): string => '"' . $ct . '":{"schema":{"type":"object","properties":{"' . $prop . '":{"type":"string"}}}}';
        $r = self::openApi('{"/x":{"post":{"operationId":"op","requestBody":{"content":{' . $body('application/vnd.x+JSON', 'a') . '}}}}}');
        self::assertTrue($r->get('schema')->get('verbs')[0]->get('params')->has('action.params.a'));
        $r = self::openApi('{"/x":{"post":{"operationId":"op","requestBody":{"content":{' . $body('application/b+json', 'b') . ',' . $body('application/a+json', 'a') . '}}}}}');
        $ps = $r->get('schema')->get('verbs')[0]->get('params');
        self::assertTrue($ps->has('action.params.a'));
        self::assertFalse($ps->has('action.params.b'));
    }

    /** An unresolved parameter reference is noted, clipped to 120 characters. */
    public function testParameterRefNote(): void
    {
        $r = self::openApi('{"/x":{"get":{"operationId":"op","parameters":[{"$ref":"#/' . str_repeat('x', 125) . '"}]}}}');
        self::assertContains("reference '#/" . str_repeat('x', 118) . "' is not a local reference that resolves", $r->get('todo'));
    }

    /** HEAD is a read in any letter case. */
    public function testHeadIsRead(): void
    {
        self::assertSame('read', self::openApi('{"/x":{"HEAD":{"operationId":"op"}}}')->get('schema')->get('verbs')[0]->get('kind'));
    }

    /** Parameters are keyed by location and name with a separator: path x and a 'pat' parameter 'hx' never collide. */
    public function testParameterKeys(): void
    {
        $r = self::openApi('{"/x":{"get":{"operationId":"op","parameters":[{"in":"path","name":"x","schema":{"type":"string"}},{"in":"pat","name":"hx"}]}}}');
        self::assertTrue($r->get('schema')->get('verbs')[0]->get('params')->has('action.params.x'));
    }
}
