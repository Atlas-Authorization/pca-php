<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\ActionsImport;
use Atlas\Pca\ActionsImportGraphql;
use Atlas\Pca\GraphqlSdlParser;
use Atlas\Pca\ImportBudget;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsImportGraphql.php';

/** mutation kills for src/ActionsImportGraphql.php: the SDL lexer's strings, escapes and limits, the parser's refusals and nesting bounds, introspection depth and the import notes. */
final class LedgerSurvivorKill19ActionsImportGraphqlTest extends TestCase
{
    /** "code: message" of the ActionKitError $f throws, or 'ok'. */
    private static function refusal(callable $f): string
    {
        try {
            $f();
        } catch (ActionKitError $e) {
            return $e->codeName . ': ' . $e->getMessage();
        }
        return 'ok';
    }

    private static function sdl(string $src, int $maxTokens = 2000000): string
    {
        return self::refusal(static fn() => ActionsImportGraphql::parseGraphqlSdl($src, $maxTokens));
    }

    /** @return array<string,mixed> the parsed typedef $name */
    private static function typeOf(string $src, string $name): array
    {
        $t = ActionsImportGraphql::parseGraphqlSdl($src)->get('types')->get($name);
        self::assertIsArray($t);
        return $t;
    }

    /** The description of field a of `type T { "<lit>" a: Int }`. */
    private static function fieldDesc(string $lit): mixed
    {
        return self::typeOf('type T { "' . $lit . '" a: Int }', 'T')['fields'][0]['desc'] ?? null;
    }

    private static function import(string $src, array $limits = []): Obj
    {
        $o = Obj::of(['ns' => 'x']);
        if ($limits) {
            $o->set('limits', Obj::of($limits));
        }
        return ActionsImportGraphql::importGraphql($src, $o);
    }

    /** @return list<array{0:string,1:string,2:string}> [where, code, message] of each import note */
    private static function todos(Obj $out): array
    {
        return array_map(static fn(Obj $t): array => [$t->get('where'), $t->get('code'), $t->get('message')], $out->get('todo'));
    }

    /** The parser's current token is readable from outside. */
    public function testCurIsPublic(): void
    {
        $this->assertSame(['eof', ''], (new GraphqlSdlParser([['eof', '']], new Obj(), 32))->cur());
    }

    /** A name token spelled 'eof' is an ordinary name; a string token never counts as punctuation. */
    public function testTokenKindNotValue(): void
    {
        $this->assertSame(['eof'], ActionsImportGraphql::parseGraphqlSdl('type eof { a: Int }')->get('types')->keys());
        $this->assertSame(['A'], self::typeOf('enum E { "}" A }', 'E')['values']);
    }

    /** Parse refusals name the token they met, clipped to 30 bytes. */
    public function testParseRefusalMessages(): void
    {
        $b40 = str_repeat('B', 40);
        $this->assertSame("bad_source: GraphQL parse error: expected ':' near '" . str_repeat('B', 30) . "'", self::sdl("type T { a $b40 }"));
        $this->assertSame("bad_source: GraphQL parse error: expected a name near '" . str_repeat('x', 30) . "'", self::sdl('type "' . str_repeat('x', 40) . '"'));
        $this->assertSame("bad_source: GraphQL parse error: unsupported definition '" . str_repeat('B', 30) . "' (only type-system definitions are imported)", self::sdl($b40));
        $this->assertSame("bad_source: GraphQL parse error: unexpected '...'", self::sdl('type Q { f(a: Int = ...): Int }'));
        $this->assertSame("bad_source: GraphQL parse error: expected ']' near ''", self::sdl('type Q { f(a: Int = [1'));
        $this->assertSame("bad_source: GraphQL parse error: expected '}' near ''", self::sdl('type Q { f(a: Int = {a: 1'));
        $this->assertSame("bad_source: GraphQL parse error: expected ')' near ''", self::sdl('type Q { f: Int @d(a: 1'));
        $this->assertSame('bad_source: GraphQL parse error: unterminated argument list', self::sdl('type Q { f(a: Int'));
        $this->assertSame('bad_source: GraphQL parse error: unterminated field list', self::sdl('type Q { a: Int'));
        $this->assertSame('bad_source: GraphQL parse error: unterminated schema block', self::sdl('schema { query: Q'));
        $this->assertSame('bad_source: GraphQL parse error: unterminated enum', self::sdl('enum E { A'));
        $this->assertSame("bad_source: GraphQL parse error: expected a name near ''", self::sdl('extend'));
        $this->assertSame("bad_source: GraphQL parse error: expected a name near '1'", self::sdl('1'));
        $this->assertSame("bad_source: GraphQL parse error: expected a name near '12'", self::sdl('type 12 x'));
        $this->assertSame("bad_source: GraphQL parse error: expected a name near '...'", self::sdl('type ...'));
    }

    /** Type and value nesting allow 32 levels and refuse the 33rd. */
    public function testNestingBounds(): void
    {
        $ty = static fn(int $k): string => 'type Q { f: ' . str_repeat('[', $k) . 'Int' . str_repeat(']', $k) . ' }';
        $this->assertSame('ok', self::sdl($ty(32)));
        $this->assertSame('import_limit: GraphQL type nesting is too deep', self::sdl($ty(33)));
        $list = static fn(int $k): string => 'type Q { f(a: Int = ' . str_repeat('[', $k) . '1' . str_repeat(']', $k) . '): Int }';
        $this->assertSame('ok', self::sdl($list(32)));
        $this->assertSame('import_limit: GraphQL value nesting is too deep', self::sdl($list(33)));
        $obj = static fn(int $k): string => 'type Q { f(a: Int = ' . str_repeat('{a: ', $k) . '1' . str_repeat('}', $k) . '): Int }';
        $this->assertSame('ok', self::sdl($obj(32)));
        $this->assertSame('import_limit: GraphQL value nesting is too deep', self::sdl($obj(33)));
    }

    /** Every argument and field is kept, directives are skipped where they may appear, and a repeated enum merges its values. */
    public function testDefinitionsParse(): void
    {
        $q = self::typeOf('type Query { f(a: Int, b: Int @deprecated): Int g: Int }', 'Query');
        $this->assertSame(['f', 'g'], array_column($q['fields'], 'name'));
        $this->assertSame(['a', 'b'], array_column($q['fields'][0]['args'], 'name'));
        $this->assertSame('Q', ActionsImportGraphql::parseGraphqlSdl('schema @d { query: Q }')->get('query'));
        $this->assertSame(['S', 'T'], ActionsImportGraphql::parseGraphqlSdl('scalar S @d scalar T')->get('types')->keys());
        $this->assertSame('object', self::typeOf('type T implements & A { a: Int }', 'T')['kind']);
        $this->assertSame(['U', 'V'], ActionsImportGraphql::parseGraphqlSdl('union U @d = A | B scalar V')->get('types')->keys());
        $this->assertSame(['A'], self::typeOf('enum E @d { A }', 'E')['values']);
        $this->assertSame(['A'], self::typeOf('enum E { "doc" A }', 'E')['values']);
        $this->assertSame(['A', 'B'], self::typeOf('enum E { A } extend enum E { B }', 'E')['values']);
    }

    /** An escape takes the whole UTF-8 character after the backslash, sized by its lead byte, even when that swallows a quote. */
    public function testStringEscapes(): void
    {
        $this->assertSame('"', self::fieldDesc('\\"'));
        $this->assertSame('é', self::fieldDesc("\\\u{E9}"));
        $this->assertSame('€', self::fieldDesc("\\\u{20AC}"));
        $this->assertSame("\u{1F600}", self::fieldDesc("\\\u{1F600}"));
        $this->assertSame("\xF0xy\"z", self::fieldDesc("\\\xF0xy\"z"));
        $this->assertSame("\xE0x\"z", self::fieldDesc("\\\xE0x\"z"));
        $this->assertSame("\xC0\"z", self::fieldDesc("\\\xC0\"z"));
        $this->assertSame("x\xE2", self::fieldDesc("\\x\xE2"));
        $this->assertSame("\xC3x", self::fieldDesc("\xC3\\x"));
        $this->assertSame('ab""" cd', self::fieldDesc('""ab\\""" cd""'));
    }

    /** Unterminated strings are refused; a lone trailing backslash is not an escape. */
    public function testUnterminatedStrings(): void
    {
        $this->assertSame('bad_source: unterminated GraphQL block string', self::sdl('type T { """abc'));
        $this->assertSame('bad_source: unterminated GraphQL string', self::sdl("type T { \"ab\ncd\" a: Int }"));
        $this->assertSame('bad_source: unterminated GraphQL string', self::sdl('type T { "abc\\'));
        $this->assertSame('bad_source: unterminated GraphQL string', self::sdl('type T { "abc'));
    }

    /** The lexer: the token cap counts the end token, only a real BOM is skipped, '...' is one token, and a bad character is placed in UTF-16 units. */
    public function testLexer(): void
    {
        $this->assertSame('ok', self::sdl('scalar S', 3));
        $this->assertSame('import_limit: the GraphQL source has too many tokens', self::sdl('scalar S', 2));
        $this->assertSame('bad_source: unexpected character in GraphQL source at offset 0', self::sdl("\u{FF01}"));
        $this->assertSame('bad_source: unexpected character in GraphQL source at offset 6', self::sdl("ab ...\x01", 50));
        $this->assertSame('bad_source: unexpected character in GraphQL source at offset 4', self::sdl("\"x\" \u{1F600}"));
    }

    private static function introspection(mixed $type, mixed $args = []): Obj
    {
        $doc = Json::parseLax('{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"f"}]}]}}');
        self::assertInstanceOf(Obj::class, $doc);
        $f = $doc->get('__schema')->get('types')[0]->get('fields')[0];
        $f->set('type', $type);
        $f->set('args', $args);
        return $doc;
    }

    private static function wrapped(string $kind, int $k): Obj
    {
        $t = Obj::of(['kind' => 'SCALAR', 'name' => 'Int']);
        for ($i = 0; $i < $k; $i++) {
            $t = Obj::of(['kind' => $kind, 'ofType' => $t]);
        }
        return $t;
    }

    /** Introspection type references nest 16 deep (lists and non-nulls alike); malformed references and arguments are refused or skipped. */
    public function testIntrospectionTypeRefs(): void
    {
        $bad = 'bad_source: malformed introspection type reference';
        foreach (['LIST', 'NON_NULL'] as $kind) {
            $this->assertSame('ok', self::refusal(static fn() => ActionsImportGraphql::fromIntrospection(self::introspection(self::wrapped($kind, 16)))), $kind);
            $this->assertSame($bad, self::refusal(static fn() => ActionsImportGraphql::fromIntrospection(self::introspection(self::wrapped($kind, 17)))), $kind);
        }
        $int = Obj::of(['kind' => 'SCALAR', 'name' => 'Int']);
        $this->assertSame($bad, self::refusal(static fn() => ActionsImportGraphql::fromIntrospection(self::introspection($int, [Obj::of(['name' => 'a', 'type' => 5])]))));
        $s = ActionsImportGraphql::fromIntrospection(self::introspection($int, [5, Obj::of(['type' => $int])]));
        $this->assertSame([], $s->get('types')->get('Query')['fields'][0]['args']);
    }

    /** schemaOf: enum values are de-duplicated into a list, custom scalars are strings, input objects keep their required members. */
    public function testSchemaOfShapes(): void
    {
        $gs = ActionsImportGraphql::parseGraphqlSdl('enum E { A A B } scalar S input I { x: Int! } type O { z: Int }');
        $c = ActionsImport::newCtx('graphql', 'x', Obj::of(['ns' => 'x']));
        $m = new \ReflectionMethod(ActionsImportGraphql::class, 'schemaOf');
        $of = static fn(array $t): array => $m->invoke(null, $t, $gs, $c, new ImportBudget(100), [], 'w');
        $e = $of(['k' => 'named', 'name' => 'E']);
        $this->assertSame([['A', 'B'], false], [$e[0]->get('enum'), $e[1]]);
        $s = $of(['k' => 'nonnull', 'of' => ['k' => 'named', 'name' => 'S']]);
        $this->assertSame(['string', true], [$s[0]->get('type'), $s[1]]);
        $i = $of(['k' => 'named', 'name' => 'I']);
        $this->assertSame(['object', ['x'], false], [$i[0]->get('type'), $i[0]->get('required'), $i[1]]);
        $o = $of(['k' => 'named', 'name' => 'O']);
        $this->assertSame([[], false], [$o[0]->keys(), $o[1]]);
    }

    /** Import notes: the node budget, unknown, recursive and output types (names clipped to 60 bytes), and the field name clipped in `where` and the binding. */
    public function testImportNotes(): void
    {
        $this->assertContains(['query f(b)', 'ref_budget', 'type expansion stopped at the node budget (declared string; refine or drop)'],
            self::todos(self::import('type Query { f(a: Int, b: Int): Int }', ['max_ref_nodes' => 1])));
        $u = str_repeat('U', 70);
        $this->assertContains(['query f(a)', 'unknown_type', "type '" . str_repeat('U', 60) . "' is not defined in the schema (declared string)"],
            self::todos(self::import("type Query { f(a: $u): Int }")));
        $l = str_repeat('L', 70);
        $this->assertContains(['query f(a)', 'cyclic_ref', "input type '" . str_repeat('L', 60) . "' is recursive (declared string; refine or drop)"],
            self::todos(self::import("input $l { x: $l } type Query { f(a: $l): Int }")));
        $o = str_repeat('O', 70);
        $this->assertContains(['query f(a)', 'output_type', "type '" . str_repeat('O', 60) . "' is an output type and cannot be an argument (declared string)"],
            self::todos(self::import("type $o { z: Int } type Query { f(a: $o): Int }")));
        $g = str_repeat('g', 205);
        $out = self::import("type Query { $g(a: Zz): Int }");
        $this->assertContains(['query ' . str_repeat('g', 80) . '(a)', 'unknown_type', "type 'Zz' is not defined in the schema (declared string)"], self::todos($out));
        $this->assertSame(str_repeat('g', 200), $out->get('defs')[0]->get('bindings')->get('graphql')->get('field'));
    }
}
