<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionKitError;
use Atlas\Pca\Actions;
use Atlas\Pca\ActionsImport;
use Atlas\Pca\ActionsImportSuggest;
use Atlas\Pca\Bytes;
use Atlas\Pca\ImportCtx;
use Atlas\Pca\Json;
use Atlas\Pca\ModelAdapter;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsImport.php';
require_once __DIR__ . '/../src/ModelAdapter.php';

/** Importer bounds, refusals with their exact reasons, text hygiene, naming, schema flattening and the OpenAPI / AsyncAPI / MCP / JSONL paths of ActionsImport. */
final class SchemaSurvivorKill12ImportTest extends TestCase
{
    private static function j(string $s): mixed
    {
        return Json::parseLax($s);
    }

    private static function opts(string $extra = ''): Obj
    {
        return self::j('{"ns":"acme"' . $extra . '}');
    }

    private static function c(mixed $v): string
    {
        return Json::canonicalizeStrict($v);
    }

    /** @return array<string,int> */
    private static function lim(array $over): array
    {
        return array_replace(ActionsImport::DEFAULT_IMPORT_LIMITS, $over);
    }

    /** The message of the ActionKitError $f throws with $code. */
    private function err(callable $f, string $code): string
    {
        try {
            $f();
        } catch (ActionKitError $e) {
            $this->assertSame($code, $e->codeName, $e->getMessage());
            return $e->getMessage();
        }
        $this->fail("no $code refusal");
    }

    /** @param list<Obj> $todos @return list<array{0:string,1:string}> [where, message] of the notes with $code */
    private static function notes(array $todos, string $code): array
    {
        $out = [];
        foreach ($todos as $t) {
            if ($t->get('code') === $code) {
                $out[] = [$t->get('where'), $t->get('message')];
            }
        }
        return $out;
    }

    /** @return array{0:Obj,1:list<Obj>} the flattened params of $schema and the notes */
    private static function flat(string $schema, string $extra = ''): array
    {
        $s = self::j($schema);
        $c = ActionsImport::newCtx('jsonschema', $s, self::opts($extra));
        $out = new Obj();
        ActionsImport::flattenObject($s, $c, ActionsImport::newBudget($c), 'w', $out);
        return [$out, $c->todo];
    }

    private static function call(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(ActionsImport::class, $m))->invoke(null, ...$a);
    }

    // ---- limits, size and shape checks -------------------------------------------------------------------------------------

    /** A limit of exactly 2^53-1 is a safe integer (clamped to the hard limit), never refused. */
    public function testLimitAtTheSafeIntegerEdgeIsClamped(): void
    {
        $l = ActionsImport::resolveLimits(self::j('{"max_ops":9007199254740991}'));
        $this->assertSame(50000, $l['max_ops']);
        $this->assertSame(64, $l['max_json_depth']);
    }

    private static function sizeErr(mixed $text, int $max): ?string
    {
        try {
            ActionsImport::textSizeCheck($text, self::lim(['max_bytes' => $max]));
            return null;
        } catch (ActionKitError $e) {
            return $e->codeName . ': ' . $e->getMessage();
        }
    }

    /** Text size counts UTF-8 bytes: exactly the limit passes, one byte more is refused; a non-string is refused as such. */
    public function testTextSizeCheckBoundaries(): void
    {
        $this->assertNull(self::sizeErr('aaaa', 4));
        $this->assertNull(self::sizeErr('aa', 5));
        $this->assertNull(self::sizeErr("\u{20AC}\u{20AC}", 6));
        $this->assertSame('import_limit: the source is larger than 5 bytes', self::sizeErr("\u{20AC}\u{20AC}", 5));
        $this->assertSame('bad_source: the source must be text', self::sizeErr(new Num('5'), 5));
    }

    /** The parsed-size estimate is exact per value kind: the total passes at the limit and is refused one below. */
    public function testCheckParsedSizeIsExact(): void
    {
        $root = self::j('{"a":[null,true,5,"abc",{"k":"x"}]}');
        $this->assertSame(8, ActionsImport::checkParsed($root, self::lim(['max_bytes' => 37])));
        $this->assertSame('the source is larger than 36 bytes', $this->err(fn() => ActionsImport::checkParsed($root, self::lim(['max_bytes' => 36])), 'import_limit'));
    }

    /** Depth starts at 0 for the root, node counts include the root; each refusal names its limit. */
    public function testCheckParsedDepthNodesAndKinds(): void
    {
        $this->assertSame(3, ActionsImport::checkParsed(self::j('[[1]]'), self::lim(['max_json_depth' => 2])));
        $this->assertSame('the source nests deeper than 1', $this->err(fn() => ActionsImport::checkParsed(self::j('[[1]]'), self::lim(['max_json_depth' => 1])), 'import_limit'));
        $this->assertSame(3, ActionsImport::checkParsed(self::j('[1,2]'), self::lim(['max_nodes' => 3])));
        $this->assertSame('the source has more than 2 nodes', $this->err(fn() => ActionsImport::checkParsed(self::j('[1,2]'), self::lim(['max_nodes' => 2])), 'import_limit'));
        $this->assertSame('the source holds a stdClass', $this->err(fn() => ActionsImport::checkParsed(new \stdClass(), self::lim([])), 'bad_source'));
        $this->assertSame('the source holds a non-finite number', $this->err(fn() => ActionsImport::checkParsed([INF], self::lim([])), 'bad_source'));
    }

    /** Options that are not an object have no ns; text and binary sources are size checked; the extension list is split or refused. */
    public function testNewCtxOptionsAndSources(): void
    {
        $this->assertSame('ns must match [a-z][a-z0-9_]{0,31}', $this->err(fn() => ActionsImport::newCtx('mcp', [], null), 'bad_ns'));
        $this->assertSame('the source is larger than 3 bytes', $this->err(fn() => ActionsImport::newCtx('mcp', 'abcd', self::opts(',"limits":{"max_bytes":3}')), 'import_limit'));
        $this->assertSame('grpc', ActionsImport::newCtx('grpc', new Bytes('abc'), self::opts(',"limits":{"max_bytes":3}'))->kind);
        $this->assertSame('the source is larger than 3 bytes', $this->err(fn() => ActionsImport::newCtx('grpc', new Bytes('abcd'), self::opts(',"limits":{"max_bytes":3}')), 'import_limit'));
        $this->assertSame(['a' => true, 'b' => true], ActionsImport::newCtx('mcp', [], self::opts(',"allowExtensions":"ab"'))->ext);
        $o = self::opts();
        $o->set('allowExtensions', [1.5]);
        $this->assertSame(['1.5' => true], ActionsImport::newCtx('mcp', [], $o)->ext);
        $this->assertSame(['x-pca-verb' => true, 'x-pca-role' => true, 'x-pca-internal' => true], ActionsImport::newCtx('mcp', [], self::opts())->ext);
        foreach (['{}', '5'] as $bad) {
            try {
                ActionsImport::newCtx('mcp', [], self::opts(',"allowExtensions":' . $bad));
                $this->fail('no TypeError');
            } catch (\TypeError $e) {
                $this->assertSame('allowExtensions is not iterable', $e->getMessage());
            }
        }
    }

    /** The source record clips uri to 2048 and licence to 128 bytes, and keeps a 2^53-1 import time as an integer lexeme. */
    public function testNewCtxSourceRecord(): void
    {
        $o = self::opts(',"now":9007199254740991');
        $o->set('uri', str_repeat('u', 2049));
        $o->set('licence', str_repeat('l', 129));
        $src = ActionsImport::newCtx('mcp', [], $o)->source;
        $this->assertSame(str_repeat('u', 2048), $src->get('uri'));
        $this->assertSame(str_repeat('l', 128), $src->get('licence'));
        $this->assertSame('9007199254740991', $src->get('imported_at')->lexeme);
        $o = self::opts();
        $o->set('uri', str_repeat('u', 2048));
        $this->assertSame(str_repeat('u', 2048), ActionsImport::newCtx('mcp', [], $o)->source->get('uri'));
    }

    /** Notes keep 5000 entries and one sentinel; where and message are clipped to 200 and 400 bytes. */
    public function testTodoCapAndClips(): void
    {
        $c = ActionsImport::newCtx('mcp', [], self::opts());
        ActionsImport::addTodo($c, str_repeat('w', 201), 'c0', str_repeat('m', 401));
        $this->assertSame(str_repeat('w', 200), $c->todo[0]->get('where'));
        $this->assertSame(str_repeat('m', 400), $c->todo[0]->get('message'));
        for ($i = 1; $i < 5002; $i++) {
            ActionsImport::addTodo($c, 'w', 'c', 'm');
        }
        $this->assertCount(5001, $c->todo);
        $this->assertSame('c', $c->todo[4999]->get('code'));
        $this->assertSame(['*', 'todo_truncated', 'further notes omitted'], [$c->todo[5000]->get('where'), $c->todo[5000]->get('code'), $c->todo[5000]->get('message')]);
    }

    /** clip keeps a string that fits even when it is not UTF-8, and stops at the first code point that does not fit. */
    public function testClipEdges(): void
    {
        $this->assertSame("a\xFF", ActionsImport::clip("a\xFF", 2));
        $this->assertSame('a', ActionsImport::clip("a\u{20AC}b", 3));
        $this->assertSame([], ActionsImport::tokensOf("a\xFFb"));
        $this->assertSame('5', ActionsImport::paramSeg(5));
    }

    // ---- verbs and aliases ------------------------------------------------------------------------------------------------

    /** Verb naming: a 32-char segment is kept, an empty leading part is ignored, a bad namespace falls back to ns.op, 128 bytes is the cap. */
    public function testVerbOfEdges(): void
    {
        $this->assertSame('acme.' . str_repeat('a', 32), ActionsImport::verbOf('acme', str_repeat('a', 32)));
        $this->assertSame('acme.foo', ActionsImport::verbOf('acme', '.foo'));
        $this->assertSame('X.op', ActionsImport::verbOf('X', 'foo'));
        $raw = implode('.', array_map(static fn(string $ch): string => str_repeat($ch, 20), ['b', 'c', 'd', 'e', 'f']));
        $v = ActionsImport::verbOf(str_repeat('a', 23), $raw);
        $this->assertSame(128, strlen($v));
        $this->assertSame(str_repeat('a', 23) . '.' . $raw, $v);
        $this->assertSame(str_repeat('a', 24) . '.op', ActionsImport::verbOf(str_repeat('a', 24), $raw));
    }

    /** A taken verb gets the first free `_n` suffix within 32 chars and a note; when every suffix is taken the import is refused. */
    public function testUniqueVerb(): void
    {
        $c = ActionsImport::newCtx('mcp', [], self::opts());
        $verb = 'acme.' . str_repeat('a', 32);
        $c->verbs[$verb] = true;
        $want = 'acme.' . str_repeat('a', 30) . '_2';
        $this->assertSame($want, self::call('uniqueVerb', $c, $verb, 'here'));
        $this->assertSame([['here', "verb '$verb' is taken by an earlier operation; this one is '$want'"]], self::notes($c->todo, 'duplicate_verb'));
        $c = ActionsImport::newCtx('mcp', [], self::opts());
        $c->verbs['acme.x'] = true;
        for ($n = 2; $n < 100000; $n++) {
            $c->verbs["acme.x_$n"] = true;
        }
        $this->assertSame('too many operations map to one verb', $this->err(fn() => self::call('uniqueVerb', $c, 'acme.x', 'here'), 'import_limit'));
    }

    /** {...v} and [...v] of lists and strings, and the refusal of a non-iterable. */
    public function testSpreads(): void
    {
        $o = self::call('spreadObj', [new Num('7'), 'x']);
        $this->assertSame(['0', '1'], $o->keys());
        $this->assertSame('x', $o->get('1'));
        $o = self::call('spreadObj', "ab\u{20AC}");
        $this->assertSame(['0', '1', '2'], $o->keys());
        $this->assertSame(['a', 'b', "\u{20AC}"], [$o->get('0'), $o->get('1'), $o->get('2')]);
        $this->assertSame(['p', 'q'], self::call('spreadArr', ['p', 'q']));
        $this->assertSame(['a', 'b'], self::call('spreadArr', 'ab'));
        try {
            self::call('spreadArr', new Num('1'));
            $this->fail('no TypeError');
        } catch (\TypeError $e) {
            $this->assertSame('value is not iterable', $e->getMessage());
        }
    }

    /** A pointer segment with a stray % or that decodes to invalid UTF-8 is used as written. */
    public function testPointerDecoding(): void
    {
        $m = static fn(string $x): Obj => Obj::of(['m' => $x]);
        $root = Obj::of(['%41%z' => $m('raw'), 'A%z' => $m('decoded'), '%FF' => $m('raw-ff'), "\xFF" => $m('byte-ff'), 'A' => $m('A')]);
        $this->assertSame('raw', ActionsImport::pointer($root, '#/%41%z')->get('m'));
        $this->assertSame('raw-ff', ActionsImport::pointer($root, '#/%FF')->get('m'));
        $this->assertSame('A', ActionsImport::pointer($root, '#/%41')->get('m'));
    }

    // ---- JSON Schema -> params ----------------------------------------------------------------------------------------------

    /** Integer bounds: inclusive, boolean-exclusive (+-1), numeric-exclusive, ignored without a bound, dropped when crossed, int32/int64 numbers. */
    public function testIntegerBounds(): void
    {
        [$p] = self::flat('{"properties":{"a":{"type":"integer","minimum":1,"maximum":9},'
            . '"b":{"type":"integer","minimum":1,"exclusiveMinimum":true,"maximum":9,"exclusiveMaximum":true},'
            . '"c":{"type":"integer","exclusiveMinimum":0,"exclusiveMaximum":10},"d":{"type":"integer","exclusiveMinimum":true,"exclusiveMaximum":true},'
            . '"e":{"type":"integer","minimum":5,"maximum":4},"f":{"type":"integer","minimum":5,"maximum":5},'
            . '"g":{"type":"number","format":"int32"},"h":{"type":"number","format":"int64","minimum":2}}}');
        $i = static fn(string $b): string => '{' . $b . ($b === '' ? '' : ',') . '"required":false,"type":"integer"}';
        $this->assertSame('{"a":' . $i('"max":9,"min":1') . ',"b":' . $i('"max":8,"min":2') . ',"c":' . $i('"max":9,"min":1') . ',"d":' . $i('')
            . ',"e":' . $i('') . ',"f":' . $i('"max":5,"min":5') . ',"g":' . $i('') . ',"h":' . $i('"min":2') . '}', self::c($p));
    }

    /** String params: the max length cap, formats, deduplicated values, and a note for a non-string enum. */
    public function testStringParams(): void
    {
        [$p, $t] = self::flat('{"properties":{"s":{"type":"string","maxLength":16777216},"t":{"type":"string","format":"email","enum":["a","a","b"]},'
            . '"u":{"type":"string","enum":[1,2]},"v":{"type":"string","maxLength":16777217},"x":{"type":"string","const":"a","enum":["b"]}}}');
        $this->assertSame('{"s":{"max_len":16777216,"required":false,"type":"string"},"t":{"format":"email","required":false,"type":"string","values":["a","b"]},'
            . '"u":{"required":false,"type":"string"},"v":{"required":false,"type":"string"},"x":{"required":false,"type":"string","values":["b"]}}', self::c($p));
        $this->assertSame([['w: u', 'enum values are not 1..256 plain strings (declared as a free string; refine)']], self::notes($t, 'enum_dropped'));
    }

    /** An enum of exactly 256 values, or with a 256-byte value, is kept; 257 is not. */
    public function testEnumBounds(): void
    {
        $vals = array_map(static fn(int $i): string => "v$i", range(0, 255));
        $s = Obj::of(['properties' => Obj::of([
            'a' => Obj::of(['enum' => $vals]),
            'b' => Obj::of(['type' => 'string', 'enum' => [str_repeat('e', 256)]]),
            'c' => Obj::of(['type' => 'string', 'enum' => array_merge($vals, ['v256'])]),
            'd' => Obj::of(['type' => 'string', 'enum' => [str_repeat('e', 257)]]),
        ])]);
        $c = ActionsImport::newCtx('jsonschema', $s, self::opts());
        $out = new Obj();
        ActionsImport::flattenObject($s, $c, ActionsImport::newBudget($c), 'w', $out);
        $this->assertSame($vals, $out->get('a')->get('values'));
        $this->assertSame([str_repeat('e', 256)], $out->get('b')->get('values'));
        $this->assertFalse($out->get('c')->has('values'));
        $this->assertFalse($out->get('d')->has('values'));
    }

    /** Array params: item kinds, inclusive item bounds (0 allowed, equal kept, crossed dropped), items without a type, notes at `name[]`. */
    public function testArrayParams(): void
    {
        $q = str_repeat('q', 41);
        [$p, $t] = self::flat('{"properties":{"a1":{"type":"array","items":{"type":"integer"},"maxItems":0,"minItems":0},'
            . '"a2":{"type":"array","items":{"type":"string"},"minItems":2,"maxItems":2},"a3":{"type":"array","items":{"type":"string"},"minItems":3,"maxItems":1},'
            . '"a4":{"type":"array","items":{"type":"string"},"minItems":1,"maxItems":3},"a5":{"items":{"type":"boolean"}},'
            . '"a6":{"type":"array","items":{"$ref":"#/nope"}},"a7":{"type":"array","items":{"type":"' . $q . '"}}}}');
        $this->assertSame('{"a1":{"items":"integer","max_items":0,"min_items":0,"required":false,"type":"array"},'
            . '"a2":{"items":"string","max_items":2,"min_items":2,"required":false,"type":"array"},"a3":{"items":"string","required":false,"type":"array"},'
            . '"a4":{"items":"string","max_items":3,"min_items":1,"required":false,"type":"array"},"a5":{"items":"boolean","required":false,"type":"array"},'
            . '"a6":{"required":false,"type":"array"},"a7":{"required":false,"type":"array"}}', self::c($p));
        $this->assertSame([['w: a6[]', "reference '#/nope' is not a local reference that resolves (declared string; refine or drop)"]], self::notes($t, 'unresolved_ref'));
        $this->assertSame([['w: a7', "array items of type '" . str_repeat('q', 40) . "' are not declared (items left open)"]], self::notes($t, 'array_items'));
    }

    /** Descriptions, the object placeholder, an ignored role and an unknown type: exact clips and notes; `type` stays the first member. */
    public function testLeafNotesAndClips(): void
    {
        $s = Obj::of(['properties' => Obj::of([
            'bool' => Obj::of(['type' => 'boolean', 'description' => str_repeat('a', 281)]),
            'obj' => Obj::of(['type' => 'object', 'description' => str_repeat('d', 281)]),
            'role' => Obj::of(['type' => 'string', 'x-pca-role' => str_repeat('z', 65)]),
            'weird' => Obj::of(['type' => str_repeat('x', 41)]),
        ])]);
        $c = ActionsImport::newCtx('jsonschema', $s, self::opts());
        $p = new Obj();
        ActionsImport::flattenObject($s, $c, ActionsImport::newBudget($c), 'w', $p);
        $this->assertSame(['type', 'required', 'description'], $p->get('bool')->keys());
        $this->assertSame(str_repeat('a', 280), $p->get('bool')->get('description'));
        $this->assertSame('{"description":"' . str_repeat('d', 280) . '","required":false,"type":"string"}', self::c($p->get('obj')));
        $this->assertSame('{"required":false,"type":"string"}', self::c($p->get('role')));
        $this->assertSame('{"required":false,"type":"string"}', self::c($p->get('weird')));
        $this->assertSame([['w: obj', 'an object with no (or too deeply nested) properties has no representation (declared string; refine or drop)']], self::notes($c->todo, 'object_leaf'));
        $this->assertSame([['w: role', "x-pca-role '" . str_repeat('z', 64) . "' is not valid for a string parameter"]], self::notes($c->todo, 'role_ignored'));
        $this->assertSame([['w: weird', "type '" . str_repeat('x', 40) . "' has no representation (declared string; refine or drop)"]], self::notes($c->todo, 'unsupported_type'));
    }

    /** Reserved names are dropped with a note and the walk goes on; a renamed parameter's note clips the name to 80 bytes. */
    public function testReservedAndRenamed(): void
    {
        $long = 'b-' . str_repeat('c', 79);
        [$p, $t] = self::flat('{"properties":{"__proto__":{"type":"string"},"constructor":{"type":"string"},"zeta":{"type":"string"},"' . $long . '":{"type":"string"}}}');
        $this->assertSame(['b_' . str_repeat('c', 62), 'zeta'], $p->keys());
        $this->assertSame([['w: __proto__', "parameter name '__proto__' is reserved; dropped"], ['w: constructor', "parameter name 'constructor' is reserved; dropped"]], self::notes($t, 'skipped_param'));
        $this->assertSame([["w: $long", "parameter '" . substr($long, 0, 80) . "' is declared as 'b_" . str_repeat('c', 62) . "'"]], self::notes($t, 'renamed_param'));
    }

    /** A name that is a prefix of another (either order) collides: the first is kept, noted, and the walk goes on. */
    public function testPrefixCollisions(): void
    {
        [$p, $t] = self::flat('{"properties":{"-":{"type":"string"},"p":{"type":"object","properties":{"q":{"type":"string"}}}}}');
        $this->assertSame(['p'], $p->keys());
        $this->assertSame([['w: p: p.q', "parameter 'p.q' collides with another; kept the first"]], self::notes($t, 'skipped_param'));
        [$p, $t] = self::flat('{"properties":{"p":{"type":"object","properties":{"q":{"type":"string"}}},"{":{"type":"string"},"~a":{"type":"string"}}}');
        $this->assertSame(['p.q', '_a'], $p->keys());
        $this->assertSame([['w: p', "parameter 'p' collides with another; kept the first"]], self::notes($t, 'skipped_param'));
    }

    /** allOf merges both members' required lists; a null-only alternative is dropped from a union; unions of string constants become an enum. */
    public function testAllOfAndUnions(): void
    {
        [$p] = self::flat('{"required":["o"],"properties":{"o":{"allOf":[{"required":["a"],"properties":{"a":{"type":"string"}}},{"required":["b"],"properties":{"b":{"type":"string"}}}]}}}');
        $this->assertSame('{"o.a":{"type":"string"},"o.b":{"type":"string"}}', self::c($p));
        [$p, $t] = self::flat('{"properties":{"p1":{"anyOf":[{"type":["null"]},{"type":"integer"}]},"p2":{"anyOf":[{"type":["string","integer"]},{"type":"integer"}]},'
            . '"r1":{"anyOf":[{"enum":["a","b"]},{"const":"c"}]},"r2":{"anyOf":[{"enum":["a"]},{"enum":["b",1]}]},'
            . '"r3":{"type":"integer","anyOf":[{"const":"a"},{"const":"b"}]},"r4":{"anyOf":[{"const":"a"},{"enum":["a","b"]}]}}}');
        $this->assertSame('{"p1":{"required":false,"type":"integer"},"p2":{"required":false,"type":"string"},"r1":{"required":false,"type":"string","values":["a","b","c"]},'
            . '"r2":{"required":false,"type":"string"},"r3":{"required":false,"type":"string","values":["a","b"]},"r4":{"required":false,"type":"string","values":["a","b"]}}', self::c($p));
        $this->assertSame([['w: p2', 'a union of 2 schemas has no representation (declared string; refine or drop)'], ['w: r2', 'a union of 2 schemas has no representation (declared string; refine or drop)']],
            self::notes($t, 'union'));
    }

    /** The union of two equal 200-value enums is deduplicated before the 256-value check. */
    public function testUnionEnumIsDeduplicated(): void
    {
        $vals = array_map(static fn(int $i): string => "v$i", range(0, 199));
        $s = Obj::of(['properties' => Obj::of(['u' => Obj::of(['anyOf' => [Obj::of(['enum' => $vals]), Obj::of(['enum' => $vals])]])])]);
        $c = ActionsImport::newCtx('jsonschema', $s, self::opts());
        $p = new Obj();
        ActionsImport::flattenObject($s, $c, ActionsImport::newBudget($c), 'w', $p);
        $this->assertSame($vals, $p->get('u')->get('values'));
    }

    /** allOf / anyOf members count one level of depth each: one level fits a depth limit of 1, two do not. */
    public function testCompositionDepth(): void
    {
        [$p, $t] = self::flat('{"properties":{"p1":{"allOf":[{"type":"string","maxLength":3}]},"p2":{"allOf":[{"allOf":[{"type":"string","maxLength":3}]}]},'
            . '"q1":{"anyOf":[{"type":"string","maxLength":3}]},"q2":{"anyOf":[{"anyOf":[{"type":"string","maxLength":3}]}]}}}', ',"limits":{"max_ref_depth":1}');
        $this->assertSame('{"max_len":3,"required":false,"type":"string"}', self::c($p->get('p1')));
        $this->assertSame('{"max_len":3,"required":false,"type":"string"}', self::c($p->get('q1')));
        $this->assertSame('{"required":false,"type":"string"}', self::c($p->get('p2')));
        $this->assertSame('{"required":false,"type":"string"}', self::c($p->get('q2')));
        $d = 'schema nesting or reference chain deeper than 1 (declared string; refine or drop)';
        $this->assertSame([['w: p2', $d], ['w: q2', $d]], self::notes($t, 'ref_depth'));
    }

    /** Reference notes clip the reference to 120 bytes (unresolved and cyclic). */
    public function testReferenceNotesClip(): void
    {
        $k = str_repeat('k', 120);
        [, $t] = self::flat('{"properties":{"a":{"$ref":"#/' . str_repeat('r', 120) . '"},"b":{"$ref":"#/' . $k . '"}},"' . $k . '":{"$ref":"#/' . $k . '"}}');
        $this->assertSame([['w: a', "reference '#/" . str_repeat('r', 118) . "' is not a local reference that resolves (declared string; refine or drop)"]], self::notes($t, 'unresolved_ref'));
        $this->assertSame([['w: b', "reference '#/" . str_repeat('k', 118) . "' is cyclic (declared string; refine or drop)"]], self::notes($t, 'cyclic_ref'));
    }

    // ---- emitted defs -------------------------------------------------------------------------------------------------------

    /** The JSON Schema importer checks the verb is in `ns.` and dedupes effects; descriptions are clipped to 600 bytes. */
    public function testJsonSchemaImport(): void
    {
        $this->assertSame("verb must be a valid verb in namespace 'acme'", $this->err(fn() => ActionsImport::importJsonSchema(self::j('{"type":"object"}'), self::opts(',"verb":"acmex.thing"')), 'bad_verb'));
        $o = self::opts(',"verb":"acme.thing.update","effects":["update","update"]');
        $o->set('description', str_repeat('a', 601));
        $s = self::j('{"type":"object","properties":{}}');
        $s->set('description', str_repeat('r', 601));
        $d = ActionsImport::importJsonSchema($s, $o)->get('defs')[0];
        $this->assertSame(['update'], $d->get('effects'));
        $this->assertSame(str_repeat('a', 600), $d->get('description'));
        $d = ActionsImport::importJsonSchema($s, self::opts(',"verb":"acme.thing.update"'))->get('defs')[0];
        $this->assertSame(str_repeat('r', 600), $d->get('description'));
    }

    /** emitDef stores traits deduplicated and sorted; withTrait adds one trait once. */
    public function testTraits(): void
    {
        $c = ActionsImport::newCtx('mcp', [], self::opts());
        $d = ActionsImport::emitDef($c, 'thing', ['update'], 'one', new Obj(), new Obj(), null, null, null, null, ['pca.network_egress', 'pca.data_export', 'pca.data_export']);
        $this->assertSame(['pca.data_export', 'pca.network_egress'], $d->get('traits'));
        $this->assertSame(['a', 'b'], ActionsImport::withTrait(['a', 'a'], 'b'));
        $this->assertSame(['a', 'b'], ActionsImport::withTrait(['a', 'b'], 'a'));
        $this->assertSame(['x'], ActionsImport::withTrait(null, 'x'));
    }

    /** MCP: a 256-unit name is usable; the tool binding clips the name to 256 bytes; more than max_ops tools are refused. */
    public function testMcpNamesAndLimit(): void
    {
        $r = ActionsImport::importMcp([Obj::of(['name' => str_repeat('a', 256)])], self::opts());
        $this->assertCount(1, $r->get('defs'));
        $this->assertSame(str_repeat('a', 256), $r->get('defs')[0]->get('bindings')->get('mcp')->get('tool'));
        $name = 'a' . str_repeat("\u{e9}", 128);
        $r = ActionsImport::importMcp([Obj::of(['name' => $name])], self::opts());
        $this->assertSame('a' . str_repeat("\u{e9}", 127), $r->get('defs')[0]->get('bindings')->get('mcp')->get('tool'));
        $this->assertSame('more than 1 operations', $this->err(fn() => ActionsImport::importMcp(self::j('[{"name":"a"},{"name":"b"}]'), self::opts(',"limits":{"max_ops":1}')), 'import_limit'));
    }

    // ---- pipeline -----------------------------------------------------------------------------------------------------------

    /** @return list<Obj> */
    private static function twoDefs(): array
    {
        return ActionsImport::importActions('mcp', self::j('[{"name":"beta_tool"},{"name":"alpha_tool"}]'), self::opts())->get('defs');
    }

    /** importActions dispatches by kind and refuses an unknown kind with the list of kinds. */
    public function testImportActionsKinds(): void
    {
        $this->assertSame(['acme.beta_tool', 'acme.alpha_tool'], array_map(static fn(Obj $d) => $d->get('verb'), self::twoDefs()));
        $this->assertSame("unknown import kind 'bogus' (one of openapi, mcp, graphql, grpc, asyncapi, jsonschema)", $this->err(fn() => ActionsImport::importActions('bogus', [], self::opts()), 'bad_kind'));
    }

    /** JSONL: one canonical def per line sorted by verb; parsing skips blank lines, keeps every def and names the first bad line. */
    public function testJsonlRoundTrip(): void
    {
        $defs = self::twoDefs();
        $a = self::c($defs[1]);
        $b = self::c($defs[0]);
        $this->assertSame("$a\n$b\n", ActionsImport::defsToJsonl($defs));
        $this->assertSame('', ActionsImport::defsToJsonl([]));
        $this->assertSame([$a, $b], array_map(self::c(...), ActionsImport::jsonlToDefs("$a\n\n$b\n")));
        $this->assertSame('line 4: not JSON', $this->err(fn() => ActionsImport::jsonlToDefs("$a\n$b\n  \nnope"), 'bad_defs'));
        $this->assertSame('line 2: ' . Actions::validateDef(self::j('{"v":1}')), $this->err(fn() => ActionsImport::jsonlToDefs("$a\n{\"v\":1}"), 'bad_defs'));
    }

    /** Suggestion: mode none returns the defs as a list; import-and-suggest marks defs suggested and reports suggestErrors; custom rules are used. */
    public function testSuggest(): void
    {
        $defs = self::twoDefs();
        $this->assertSame([$defs[0]], ActionsImport::suggestDefs([5 => $defs[0]], Obj::of(['mode' => 'none']))->get('defs'));
        $r = ActionsImport::importAndSuggest('mcp', self::j('[{"name":"beta_tool"}]'), self::opts(), Obj::of(['mode' => 'none']));
        $this->assertSame([], $r->get('suggestErrors'));
        $r = ActionsImport::importAndSuggest('mcp', self::j('[{"name":"beta_tool"}]'), self::opts());
        $this->assertSame('suggested', $r->get('defs')[0]->get('review')->get('state'));
        $this->assertSame([], $r->get('suggestErrors'));
        $rules = ActionsImportSuggest::defaultRules()->without();
        $rules->set('version', '9.8.7');
        $s = ActionsImport::suggestDefs([$defs[0]], Obj::of(['rules' => $rules]))->get('defs')[0];
        $this->assertSame('9.8.7', $s->get('review')->get('suggested_by')->get('rules')->get('version'));
    }

    /** Model mode: rule and model traits are unioned, the model record is kept, a failing model is reported with the verb, and a caller registry limits the vocabulary. */
    public function testSuggestWithModels(): void
    {
        $ok = new class implements ModelAdapter {
            public function id(): string
            {
                return 'ok-model';
            }

            public function version(): ?string
            {
                return null;
            }

            public function complete(Obj $req): mixed
            {
                return '["pca.network_egress","pca.data_export"]';
            }
        };
        $bad = new class implements ModelAdapter {
            public function id(): string
            {
                return 'bad-model';
            }

            public function version(): ?string
            {
                return null;
            }

            public function complete(Obj $req): mixed
            {
                throw new \RuntimeException('boom');
            }
        };
        $d = ActionsImport::importMcp(self::j('[{"name":"bulk_tool"}]'), self::opts())->get('defs')[0];
        $this->assertContains('pca.bulk', ActionsImport::suggestDefs([$d])->get('defs')[0]->get('traits'));
        $r = ActionsImport::suggestDefs([$d], Obj::of(['mode' => 'model', 'models' => [$ok, $bad]]));
        $this->assertSame('[{"error":"boom","model":"bad-model","verb":"acme.bulk_tool"}]', self::c($r->get('errors')));
        $s = $r->get('defs')[0];
        foreach (['pca.bulk', 'pca.network_egress', 'pca.data_export'] as $t) {
            $this->assertContains($t, $s->get('traits'));
        }
        $models = $s->get('review')->get('suggested_by')->get('models');
        $this->assertCount(1, $models);
        $this->assertSame('ok-model', $models[0]->get('id'));
        $reg = Actions::coreRegistry();
        unset($reg['pca.data_export']);
        $s = ActionsImport::suggestDefs([$d], Obj::of(['mode' => 'model', 'models' => [$ok], 'registry' => $reg]))->get('defs')[0];
        $this->assertContains('pca.network_egress', $s->get('traits'));
        $this->assertNotContains('pca.data_export', $s->get('traits'));
    }

    // ---- OpenAPI ------------------------------------------------------------------------------------------------------------

    private static function oa(string $paths, string $extra = '', string $opts = ''): Obj
    {
        return ActionsImport::importOpenApi(self::j('{"openapi":"3.0.0","paths":' . $paths . $extra . '}'), self::opts($opts));
    }

    private static function obj(string $props): string
    {
        return '{"schema":{"type":"object","properties":' . $props . '}}';
    }

    /** The body media type is the first form/JSON type in that order, else the first +json type (case-insensitive); others are noted, clipped. */
    public function testOpenApiBodyMediaType(): void
    {
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","requestBody":{"content":{"application/json":' . self::obj('{"j":{"type":"string"}}')
            . ',"multipart/form-data":' . self::obj('{"m":{"type":"string"}}') . '}}}}}');
        $this->assertSame(['j'], $r->get('defs')[0]->get('params')->keys());
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","requestBody":{"content":{"APPLICATION/VND.B+JSON":' . self::obj('{"b":{"type":"string"}}')
            . ',"application/vnd.a+json":' . self::obj('{"a":{"type":"string"}}') . '}}}}}');
        $this->assertSame(['b'], $r->get('defs')[0]->get('params')->keys());
        $path = '/' . str_repeat('p', 120);
        $long = 'text/' . str_repeat('a', 36);
        $r = self::oa('{"' . $path . '":{"post":{"operationId":"make_w","requestBody":{"content":{"' . $long . '":{},"text/b":{},"text/c":{},"text/d":{}}}}}}');
        $this->assertSame([['POST /' . str_repeat('p', 119), 'request body media types (text/' . str_repeat('a', 35) . ', text/b, text/c) are not form or JSON; the body is not declared']],
            self::notes($r->get('todo'), 'body_type'));
    }

    /** Verb sources: an empty operationId is no operationId; x-pca-verb must start with `ns.`; a path names its last two plain segments. */
    public function testOpenApiVerbs(): void
    {
        $this->assertSame('acme.widgets.list', self::oa('{"/widgets":{"get":{"operationId":""}}}')->get('defs')[0]->get('verb'));
        $this->assertSame('acme.w.make', self::oa('{"/w":{"post":{"operationId":"make_w","x-pca-verb":"acmex.thing"}}}')->get('defs')[0]->get('verb'));
        $this->assertSame('acme.b.c.list', self::oa('{"/a/b/c":{"get":{}}}')->get('defs')[0]->get('verb'));
        $this->assertSame('acme.c.list', self::oa('{"/a{b/c":{"get":{}}}')->get('defs')[0]->get('verb'));
    }

    /** Parameters are keyed by location and name; a body-location entry is skipped, an unknown location noted (clipped), a clash noted. */
    public function testOpenApiParameters(): void
    {
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","parameters":[{"in":"query","name":"ab"},{"in":"querya","name":"b"}]}}}');
        $this->assertSame(['ab'], $r->get('defs')[0]->get('params')->keys());
        $this->assertSame([['POST /w', "querya parameter 'b' is not an action parameter (path, query and body only)"]], self::notes($r->get('todo'), 'param_location'));
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","parameters":[{"in":"path","name":"x","required":true},{"in":"query","name":"x"}]}}}');
        $this->assertSame([['POST /w: x', "'x' is declared by the body and by a query parameter; kept the body's"]], self::notes($r->get('todo'), 'skipped_param'));
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","parameters":[{"in":"body","name":"a"},{"in":"query","name":"z"}]}}}');
        $this->assertSame(['z'], $r->get('defs')[0]->get('params')->keys());
        $n = str_repeat('n', 61);
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","parameters":[{"in":"abcdefghijklm","name":"' . $n . '"}]}}}');
        $this->assertSame([['POST /w', "abcdefghijkl parameter '" . str_repeat('n', 60) . "' is not an action parameter (path, query and body only)"]], self::notes($r->get('todo'), 'param_location'));
        $long = 'b-' . str_repeat('c', 79);
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","parameters":[{"in":"query","name":"' . $long . '"}]}}}');
        $this->assertSame([["POST /w: $long", "parameter '" . substr($long, 0, 80) . "' is declared as 'b_" . str_repeat('c', 62) . "'"]], self::notes($r->get('todo'), 'renamed_param'));
        $r = self::oa('{"/w":{"post":{"operationId":"make_w","requestBody":{"content":{"application/json":' . self::obj('{"x":{"type":"object","properties":{"y":{"type":"string"}}}}')
            . '}},"parameters":[{"in":"query","name":"x"},{"in":"query","name":"zz"}]}}}');
        $this->assertSame(['x.y', 'zz'], $r->get('defs')[0]->get('params')->keys());
        $this->assertSame([['POST /w: x', "'x' is declared by the body and by a query parameter; kept the body's"]], self::notes($r->get('todo'), 'skipped_param'));
    }

    /** Scopes are listed sorted, at most 12, each clipped to 60 bytes (a numeric scope keeps its text); one note for unlisted extensions, clipped. */
    public function testOpenApiScopesAndExtensions(): void
    {
        $scopes = array_merge(['1', str_repeat('b', 61)], array_map(static fn(int $i): string => sprintf('c%02d', $i), range(1, 11)));
        $op = Obj::of(['operationId' => 'make_w', 'security' => [Obj::of(['oauth' => $scopes])], 'x-' . str_repeat('e', 59) => true, 'x-other' => true]);
        $doc = self::j('{"openapi":"3.0.0","paths":{"/w":{}}}');
        $doc->get('paths')->get('/w')->set('post', $op);
        $r = ActionsImport::importOpenApi($doc, self::opts());
        $want = 'requires scope: 1, ' . str_repeat('b', 60) . ', ' . implode(', ', array_map(static fn(int $i): string => sprintf('c%02d', $i), range(1, 10)));
        $this->assertSame([['POST /w', $want]], self::notes($r->get('todo'), 'required_scope'));
        $this->assertSame([['POST /w', "extension 'x-" . str_repeat('e', 58) . "' is ignored (not allow-listed)"]], self::notes($r->get('todo'), 'extension_ignored'));
    }

    /** Without an operationId the binding names method_path clipped to 200 bytes and the path clipped to 240. */
    public function testOpenApiBindingClips(): void
    {
        $path = '/' . str_repeat('q', 240);
        $b = self::oa('{"' . $path . '":{"get":{}}}')->get('defs')[0]->get('bindings')->get('openapi');
        $this->assertSame('get_/' . str_repeat('q', 195), $b->get('operationId'));
        $this->assertSame('/' . str_repeat('q', 239), $b->get('path'));
    }

    /** A path-item reference chain may take max_ref_depth+1 hops; one more is refused with a note; an unresolved one is noted, clipped. */
    public function testOpenApiRefChains(): void
    {
        $two = self::oa('{"/w":{"$ref":"#/x/a"}}', ',"x":{"a":{"$ref":"#/x/b"},"b":{"get":{"operationId":"get_w"}}}', ',"limits":{"max_ref_depth":1}');
        $this->assertCount(1, $two->get('defs'));
        $three = self::oa('{"/w":{"$ref":"#/x/a"}}', ',"x":{"a":{"$ref":"#/x/b"},"b":{"$ref":"#/x/c"},"c":{"get":{"operationId":"get_w"}}}', ',"limits":{"max_ref_depth":1}');
        $this->assertCount(0, $three->get('defs'));
        $this->assertSame([['/w', 'a reference chain is cyclic or too deep']], self::notes($three->get('todo'), 'cyclic_ref'));
        $r = self::oa('{"/w":{"$ref":"#/' . str_repeat('r', 121) . '"}}');
        $this->assertSame([['/w', "reference '#/" . str_repeat('r', 118) . "' does not resolve locally"]], self::notes($r->get('todo'), 'unresolved_ref'));
    }

    /** A Swagger 2 body parameter without a schema declares no body. */
    public function testSwaggerBodyWithoutSchema(): void
    {
        $r = ActionsImport::importOpenApi(self::j('{"swagger":"2.0","paths":{"/w":{"post":{"operationId":"make_w","parameters":[{"in":"body","name":"b"}]}}}}'), self::opts());
        $this->assertSame([], self::notes($r->get('todo'), 'body_shape'));
        $this->assertSame([], $r->get('defs')[0]->get('params')->keys());
    }

    // ---- AsyncAPI -----------------------------------------------------------------------------------------------------------

    private static function aa(string $doc, string $opts = ''): Obj
    {
        return ActionsImport::importAsyncApi(self::j($doc), self::opts($opts));
    }

    /** A channel reference chain may take max_ref_depth+1 hops; one more is refused with a note; an unresolved one is noted, clipped. */
    public function testAsyncRefDepth(): void
    {
        $two = self::aa('{"asyncapi":"2.6.0","channels":{"ch":{"$ref":"#/components/channels/c1"}},"components":{"channels":{"c1":{"$ref":"#/components/channels/c2"},'
            . '"c2":{"publish":{"operationId":"pub_it"}}}}}', ',"limits":{"max_ref_depth":1}');
        $this->assertCount(1, $two->get('defs'));
        $this->assertSame([], self::notes($two->get('todo'), 'ref_depth'));
        $three = self::aa('{"asyncapi":"2.6.0","channels":{"ch":{"$ref":"#/components/channels/c1"}},"components":{"channels":{"c1":{"$ref":"#/components/channels/c2"},'
            . '"c2":{"$ref":"#/components/channels/c3"},"c3":{"publish":{"operationId":"pub_it"}}}}}', ',"limits":{"max_ref_depth":1}');
        $this->assertCount(0, $three->get('defs'));
        $this->assertSame([['ch', 'a reference chain is too deep']], self::notes($three->get('todo'), 'ref_depth'));
        $r = self::aa('{"asyncapi":"2.6.0","channels":{"ch":{"$ref":"#/' . str_repeat('r', 121) . '"}}}');
        $this->assertSame([['ch', "reference '#/" . str_repeat('r', 118) . "' does not resolve locally"]], self::notes($r->get('todo'), 'unresolved_ref'));
    }

    /** Channel parameters: a second name with the same param segment is skipped and the rest still declared. */
    public function testAsyncChannelParams(): void
    {
        $r = self::aa('{"asyncapi":"2.6.0","channels":{"ch":{"parameters":{"a-b":{},"a_b":{},"z":{}},"publish":{"operationId":"pub_it"}}}}');
        $this->assertSame('{"a_b":{"max_len":256,"type":"string"},"z":{"max_len":256,"type":"string"}}', self::c($r->get('defs')[0]->get('params')));
    }

    /** The note location clips the channel to 100 bytes and the binding to 250. */
    public function testAsyncChannelClips(): void
    {
        $ch = str_repeat('c', 251);
        $r = self::aa('{"asyncapi":"2.6.0","channels":{"' . $ch . '":{"publish":{"message":{"oneOf":[{"payload":{"type":"object","properties":{"a":{"type":"string"}}}},{}]}}}}}');
        $this->assertSame([['send ' . str_repeat('c', 100), '2 message variants: only the first is declared']], self::notes($r->get('todo'), 'message_variants'));
        $this->assertSame(str_repeat('c', 250), $r->get('defs')[0]->get('bindings')->get('asyncapi')->get('channel'));
    }

    /** AsyncAPI 3: an empty operation message list falls back to the channel's messages. */
    public function testAsyncV3EmptyMessages(): void
    {
        $r = self::aa('{"asyncapi":"3.0.0","channels":{"ch":{"address":"a/b","messages":{"m":{"payload":{"type":"object","properties":{"a":{"type":"string"}}}}}}},'
            . '"operations":{"op1":{"action":"send","channel":{"$ref":"#/channels/ch"},"messages":[]}}}');
        $this->assertSame(['a'], $r->get('defs')[0]->get('params')->keys());
    }
}
