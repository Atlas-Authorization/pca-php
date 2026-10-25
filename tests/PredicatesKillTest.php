<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Predicates.php';

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use Atlas\Pca\SafeRegex;
use Atlas\Pca\SafeRegexBudget;
use PHPUnit\Framework\TestCase;

/**
 * Mutation-kill tests for src/Predicates.php (the predicate DSL evaluator and the Intent Layer v2 `layers` check) and
 * src/SafeRegex.php (the linear-time regex engine, the safe-source guard and the per-document regex budget). Every op,
 * every cap at max and max+1, the tri-valued fail-closed logic, the check order and the ceiling order are pinned.
 */
final class PredicatesKillTest extends TestCase
{
    private const NOPRED = 'envelope grants no predicates';

    // ---- fixtures ---------------------------------------------------------------------------------------------------

    private static function j(string $json): mixed
    {
        return Json::parseLax($json);
    }

    private static function o(mixed $a): mixed
    {
        return Json::parseLax(json_encode($a, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION));
    }

    /** A context whose action is read / "/acct/1" with params `$params` (JSON) and env `$env` (JSON). */
    private static function ctx(string $params = '{}', string $env = '{}', string $extra = ''): Obj
    {
        return self::j('{"action":{"verb":"read","resource":"/acct/1","params":' . $params . '},"env":' . $env
            . ($extra === '' ? '' : ',' . $extra) . '}');
    }

    /** Tri-valued verdict of a condition given as JSON. */
    private static function tri(string $cond, ?Obj $ctx = null): string
    {
        return Predicates::evaluateConditionTri(self::j($cond), $ctx ?? self::ctx());
    }

    /** A leaf over env.v with literal operand (both JSON). */
    private static function leaf(string $v, string $op, string $operand): string
    {
        return self::tri('{"field":"env.v","op":"' . $op . '","value":' . $operand . '}', self::ctx('{}', '{"v":' . $v . '}'));
    }

    private static function str(string $s): string
    {
        return json_encode($s, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    // ---- resolvePath ------------------------------------------------------------------------------------------------

    public function testResolvePath(): void
    {
        $c = self::ctx('{"a":[10,{"b":null}],"":"empty"}', '{"x":1}', '"subject":{"id":"u"}');
        self::assertSame(['found' => false], Predicates::resolvePath($c, ''));
        self::assertSame(['found' => false], Predicates::resolvePath($c, 7));
        self::assertSame(['found' => false], Predicates::resolvePath($c, 'other.x'));
        self::assertTrue(Predicates::resolvePath($c, 'subject.id')['found']);
        self::assertSame('u', Predicates::resolvePath($c, 'subject.id')['value']);
        self::assertTrue(Predicates::resolvePath($c, 'action.params.a.1.b')['found']); // null is found
        self::assertNull(Predicates::resolvePath($c, 'action.params.a.1.b')['value']);
        self::assertSame('10', Predicates::resolvePath($c, 'action.params.a.0')['value']->lexeme);
        self::assertFalse(Predicates::resolvePath($c, 'action.params.a.2')['found']); // index == length
        self::assertFalse(Predicates::resolvePath($c, 'action.params.a.01')['found']); // leading zero
        self::assertFalse(Predicates::resolvePath($c, 'action.params.a.-1')['found']);
        self::assertFalse(Predicates::resolvePath($c, 'action.params.a.99999999999999999999')['found']);
        self::assertFalse(Predicates::resolvePath($c, 'action.params.a.length')['found']);
        self::assertSame('empty', Predicates::resolvePath($c, 'action.params.')['value']); // "" is an ordinary key
        self::assertFalse(Predicates::resolvePath($c, 'env.x.y')['found']); // a number has no members
        self::assertFalse(Predicates::resolvePath($c, 'action.params.a.1.b.c')['found']); // null has no members
        self::assertFalse(Predicates::resolvePath(self::j('{"env":{"__proto__":{"a":1}}}'), 'env.__proto__.a')['found']);
        self::assertFalse(Predicates::resolvePath(self::j('{"env":{"constructor":1}}'), 'env.constructor')['found']);
        self::assertFalse(Predicates::resolvePath(self::j('{"env":{"prototype":1}}'), 'env.prototype')['found']);
        self::assertFalse(Predicates::resolvePath(self::j('{"env":{}}'), 'subject')['found']);
        self::assertFalse(Predicates::resolvePath(self::j('{"env":{}}'), 'env.toString')['found']); // own members only
    }

    // ---- eq / ne / in / nin -----------------------------------------------------------------------------------------

    public function testEqualityIsCanonicalJsonEquality(): void
    {
        self::assertSame('true', self::leaf('2', 'eq', '2.0'));
        self::assertSame('true', self::leaf('2', 'eq', '2e0'));
        self::assertSame('true', self::leaf('0', 'eq', '-0'));
        self::assertSame('false', self::leaf('2', 'eq', '"2"'));
        self::assertSame('false', self::leaf('true', 'eq', '1'));
        self::assertSame('false', self::leaf('null', 'eq', 'false'));
        self::assertSame('true', self::leaf('null', 'eq', 'null'));
        self::assertSame('true', self::leaf('9007199254740993', 'eq', '9007199254740992')); // binary64 rounding
        self::assertSame('false', self::leaf('9007199254740991', 'eq', '9007199254740990'));
        self::assertSame('true', self::leaf('{"a":1,"b":[1,2]}', 'eq', '{"b":[1.0,2],"a":1}'));
        self::assertSame('false', self::leaf('{"a":1}', 'eq', '{"a":1,"b":1}'));
        self::assertSame('false', self::leaf('[1,2]', 'eq', '[2,1]'));
        self::assertSame('false', self::leaf('[]', 'eq', '{}'));
        self::assertSame('false', self::leaf('"\ud800"', 'eq', '"\ud801"'));
        self::assertSame('true', self::leaf('"😀"', 'eq', '"😀"'));
        // a non-finite number anywhere: canonicalize throws, deepEq is false
        self::assertSame('false', self::leaf('1e400', 'eq', '1e400'));
        self::assertSame('true', self::leaf('1e400', 'ne', '1e400'));
        self::assertSame('false', self::leaf('[1,1e400]', 'eq', '[2,1e400]'));
        self::assertSame('true', self::leaf('[1,{"x":-1e999}]', 'ne', '[1,{"x":-1e999}]'));
        self::assertSame('false', self::leaf('2', 'ne', '2.0'));
    }

    public function testInNin(): void
    {
        self::assertSame('true', self::leaf('2', 'in', '["2",2.0]'));
        self::assertSame('false', self::leaf('2', 'in', '["2",true]'));
        self::assertSame('false', self::leaf('2', 'in', '[]'));
        self::assertSame('unknown', self::leaf('2', 'in', '2'));
        self::assertSame('unknown', self::leaf('2', 'in', '{"0":2}'));
        self::assertSame('true', self::leaf('2', 'nin', '["2"]'));
        self::assertSame('false', self::leaf('2', 'nin', '[3,2]'));
        self::assertSame('unknown', self::leaf('2', 'nin', '"2"'));
        self::assertSame('true', self::leaf('[1]', 'in', '[[1.0]]'));
    }

    // ---- order ------------------------------------------------------------------------------------------------------

    public function testNumericOrder(): void
    {
        foreach ([['lt', 'false', 'true'], ['lte', 'true', 'true'], ['gt', 'false', 'false'], ['gte', 'true', 'false']] as [$op, $eq, $less]) {
            self::assertSame($eq, self::leaf('5', $op, '5.0'), "$op equal");
            self::assertSame($less, self::leaf('4.999', $op, '5'), "$op less");
        }
        self::assertSame('true', self::leaf('-0', 'gte', '0'));
        self::assertSame('false', self::leaf('-0', 'lt', '0'));
        self::assertSame('unknown', self::leaf('true', 'lt', '2')); // a bool is never a number
        self::assertSame('unknown', self::leaf('1', 'lt', '"2"'));
        self::assertSame('unknown', self::leaf('1e400', 'gt', '1'));
        self::assertSame('unknown', self::leaf('null', 'lte', '1'));
        self::assertSame('unknown', self::leaf('[1]', 'lt', '[2]'));
        self::assertSame('true', self::leaf('9007199254740993', 'lte', '9007199254740992'));
    }

    public function testStringOrderIsUtf8ByteOrder(): void
    {
        $vec = json_decode((string)file_get_contents(__DIR__ . '/../../../packages/pca-conformance/predicate-string-order.json'), true);
        foreach ($vec['vectors'] as $t) {
            $a = self::str($t['a']);
            $b = self::str($t['b']);
            self::assertSame($t['cmp'] < 0 ? 'true' : 'false', self::leaf($a, 'lt', $b), $t['name']);
            self::assertSame($t['cmp'] <= 0 ? 'true' : 'false', self::leaf($a, 'lte', $b), $t['name']);
            self::assertSame($t['cmp'] > 0 ? 'true' : 'false', self::leaf($a, 'gt', $b), $t['name']);
            self::assertSame($t['cmp'] >= 0 ? 'true' : 'false', self::leaf($a, 'gte', $b), $t['name']);
        }
        // U+FFFF < U+10000 by code point (JS `<` on UTF-16 would say the opposite)
        self::assertSame('true', self::leaf('"￿"', 'lt', '"𐀀"'));
        // a lone surrogate has no order
        self::assertSame('unknown', self::leaf('"\ud800"', 'lt', '"a"'));
        self::assertSame('unknown', self::leaf('"a"', 'gte', '"\udfff"'));
    }

    // ---- prefix / like ----------------------------------------------------------------------------------------------

    public function testPrefix(): void
    {
        self::assertSame('true', self::leaf('"/acct/1"', 'prefix', '"/acct/"'));
        self::assertSame('true', self::leaf('"/acct/1"', 'prefix', '""'));
        self::assertSame('false', self::leaf('"/acc"', 'prefix', '"/acct/"'));
        self::assertSame('unknown', self::leaf('1', 'prefix', '"1"'));
        self::assertSame('unknown', self::leaf('"1"', 'prefix', '1'));
        // UTF-16 code units: a lone high surrogate is a prefix of the astral character it starts
        self::assertSame('true', self::leaf('"😀x"', 'prefix', '"\ud83d"'));
        self::assertSame('false', self::leaf('"😀x"', 'prefix', '"\ud83e"'));
    }

    public function testLikeGlob(): void
    {
        self::assertSame('true', self::leaf('"/acct/1/items"', 'like', '"/acct/*/items"'));
        self::assertSame('true', self::leaf('"abc"', 'like', '"a?c"'));
        self::assertSame('false', self::leaf('"abbc"', 'like', '"a?c"'));
        self::assertSame('true', self::leaf('"a*c"', 'like', '"a\\\\*c"'));
        self::assertSame('false', self::leaf('"abc"', 'like', '"a\\\\*c"'));
        self::assertSame('true', self::leaf('""', 'like', '"***"'));
        self::assertSame('false', self::leaf('""', 'like', '"?"'));
        self::assertSame('true', self::leaf('"a\nb"', 'like', '"a?b"')); // ? matches a line terminator
        self::assertSame('unknown', self::leaf('"ab"', 'like', '"ab\\\\"')); // dangling backslash
        self::assertSame('true', self::leaf('"aaaaaaaaaaaaaaaaaaaaaaab"', 'like', '"*a*a*a*b"'));
        self::assertSame('false', self::leaf('"aaaaaaaaaaaaaaaaaaaaaaaa"', 'like', '"*a*a*a*b"'));
        // ? is ONE UTF-16 code unit: an astral character is two
        self::assertSame('true', self::leaf('"😀"', 'like', '"??"'));
        self::assertSame('false', self::leaf('"😀"', 'like', '"?"'));
        self::assertSame('unknown', self::leaf('1', 'like', '"*"'));
        // caps: pattern <= 512 units, subject <= 512 units
        self::assertSame('true', self::leaf(self::str(str_repeat('a', 512)), 'like', self::str(str_repeat('?', 512))));
        self::assertSame('unknown', self::leaf(self::str('a'), 'like', self::str(str_repeat('*', 513))));
        self::assertSame('unknown', self::leaf(self::str(str_repeat('a', 513)), 'like', '"*"'));
        self::assertSame('true', self::leaf(self::str(str_repeat('😀', 256)), 'like', '"*"'));
        self::assertSame('unknown', self::leaf(self::str(str_repeat('😀', 256) . 'a'), 'like', '"*"'));
        self::assertSame('true', self::leaf('"a"', 'like', self::str(str_repeat('*', 511) . 'a')));
    }

    // ---- matches ----------------------------------------------------------------------------------------------------

    public function testMatches(): void
    {
        self::assertSame('true', self::leaf('"/acct/7/items/42"', 'matches', '"/acct/[^/]+/items/\\\\d+"'));
        self::assertSame('false', self::leaf('"x/acct/7/items/42"', 'matches', '"/acct/[^/]+/items/\\\\d+"')); // anchored
        self::assertSame('false', self::leaf('"abc\n"', 'matches', '"abc"')); // no match before a trailing newline
        self::assertSame('false', self::leaf('"abc\n"', 'matches', '"abc$"'));
        self::assertSame('true', self::leaf('"GET /x"', 'matches', '"(?:GET|POST) /x"'));
        self::assertSame('unknown', self::leaf('"aaaa"', 'matches', '"(a+)+"')); // unsafe
        self::assertSame('unknown', self::leaf('"aa"', 'matches', '"(a)\\\\1"')); // backreference
        self::assertSame('unknown', self::leaf('"a"', 'matches', '"(?=a)a"')); // lookaround
        self::assertSame('unknown', self::leaf('"a"', 'matches', '"\\\\ba"')); // \b
        self::assertSame('unknown', self::leaf('1', 'matches', '"1"'));
        self::assertSame('unknown', self::leaf('"1"', 'matches', '1'));
        // caps: source <= 200 units, subject <= 512 units
        self::assertSame('true', self::leaf(self::str(str_repeat('a', 200)), 'matches', self::str(str_repeat('a', 200))));
        self::assertSame('unknown', self::leaf(self::str(str_repeat('a', 201)), 'matches', self::str(str_repeat('a', 201))));
        self::assertSame('true', self::leaf(self::str(str_repeat('a', 512)), 'matches', '"a*"'));
        self::assertSame('unknown', self::leaf(self::str(str_repeat('a', 513)), 'matches', '"a*"'));
        self::assertSame('true', self::leaf(self::str(str_repeat('😀', 256)), 'matches', '"[^]*"'));
        self::assertSame('unknown', self::leaf(self::str(str_repeat('😀', 256) . 'a'), 'matches', '"[^]*"'));
        $sub = self::str(str_repeat('😀', 99) . 'x');
        self::assertSame('true', self::leaf($sub, 'matches', self::str(str_repeat('😀', 99) . 'x?'))); // 200 units
        self::assertSame('unknown', self::leaf($sub, 'matches', self::str(str_repeat('😀', 99) . 'xy?'))); // 201 units
    }

    // ---- is_a -------------------------------------------------------------------------------------------------------

    public function testIsA(): void
    {
        self::assertSame('true', self::leaf('"Doc"', 'is_a', '"Doc"'));
        self::assertSame('true', self::leaf('"Doc::42"', 'is_a', '"Doc"'));
        self::assertSame('false', self::leaf('"Docx"', 'is_a', '"Doc"'));
        self::assertSame('false', self::leaf('"Doc:42"', 'is_a', '"Doc"'));
        self::assertSame('true', self::leaf('{"type":"Doc::a"}', 'is_a', '"Doc"'));
        self::assertSame('true', self::leaf('{"type":"X","tags":["Doc"]}', 'is_a', '"Doc"'));
        self::assertSame('false', self::leaf('{"type":"X","tags":["Do"]}', 'is_a', '"Doc"'));
        self::assertSame('false', self::leaf('{"type":7,"tags":[]}', 'is_a', '"Doc"')); // decidable via tags
        self::assertSame('unknown', self::leaf('{"type":7,"tags":"Doc"}', 'is_a', '"Doc"'));
        self::assertSame('unknown', self::leaf('{}', 'is_a', '"Doc"'));
        self::assertSame('unknown', self::leaf('["Doc"]', 'is_a', '"Doc"'));
        self::assertSame('unknown', self::leaf('5', 'is_a', '"Doc"'));
        self::assertSame('unknown', self::leaf('"Doc"', 'is_a', '""'));
        self::assertSame('unknown', self::leaf('"Doc"', 'is_a', '["Doc"]'));
    }

    // ---- member_of --------------------------------------------------------------------------------------------------

    private static function mem(string $v, string $extra): string
    {
        $env = '{"v":' . $v . ',"g":{"alice":"eng","eng":["staff",7],"staff":"all","all":"eng","__proto__":"root"},"t":"all"}';
        return self::tri('{"field":"env.v","op":"member_of","collection":"env.g",' . $extra . '}', self::ctx('{}', $env));
    }

    public function testMemberOf(): void
    {
        self::assertSame('true', self::mem('"alice"', '"value":"all"')); // transitive, cycle-guarded
        self::assertSame('true', self::mem('"alice"', '"value":"alice"')); // reflexive
        self::assertSame('false', self::mem('"alice"', '"value":"root"'));
        self::assertSame('false', self::mem('"__proto__"', '"value":"root"')); // forbidden node has no neighbours
        self::assertSame('true', self::mem('"alice"', '"value":[1,"nope","staff"]'));
        self::assertSame('unknown', self::mem('"alice"', '"value":[1,2]')); // no string targets
        self::assertSame('unknown', self::mem('"alice"', '"value":5'));
        self::assertSame('true', self::mem('"alice"', '"ref":"env.t"'));
        self::assertSame('unknown', self::mem('"alice"', '"ref":"env.missing","value":"all"')); // ref wins, unresolved
        self::assertSame('unknown', self::mem('"alice"', '"ref":null,"value":"all"')); // present non-string ref
        self::assertSame('unknown', self::mem('"alice"', '"x":1')); // no operand
        self::assertSame('unknown', self::mem('7', '"value":"all"')); // field must be a string
        $env = '{"v":"a","g":["x"]}';
        self::assertSame('unknown', self::tri('{"field":"env.v","op":"member_of","collection":"env.g","value":"a"}', self::ctx('{}', $env)));
        self::assertSame('unknown', self::tri('{"field":"env.v","op":"member_of","collection":"","value":"a"}', self::ctx('{}', $env)));
        self::assertSame('unknown', self::tri('{"field":"env.v","op":"member_of","value":"a"}', self::ctx('{}', $env)));
    }

    public function testMemberClosureNodeCap(): void
    {
        // a chain n0 -> n1 -> ... : the closure visits at most MAX_MEMBER_CLOSURE_NODES nodes
        $max = Predicates::MAX_MEMBER_CLOSURE_NODES;
        $g = [];
        for ($i = 0; $i <= $max + 1; $i++) {
            $g['n' . $i] = 'n' . ($i + 1);
        }
        $ctx = self::o(['action' => ['verb' => 'r', 'resource' => '/', 'params' => new \stdClass()], 'env' => ['v' => 'n0', 'g' => $g]]);
        $c = static fn(string $t): string => Predicates::evaluateConditionTri(
            self::o(['field' => 'env.v', 'op' => 'member_of', 'collection' => 'env.g', 'value' => $t]),
            $ctx
        );
        self::assertSame('true', $c('n' . $max)); // discovered as a neighbour of the last visited node
        self::assertSame('false', $c('n' . ($max + 1)));
    }

    // ---- exists / params availability / leaf shape and check order -------------------------------------------------

    public function testExistsAndParamsAvailability(): void
    {
        self::assertSame('true', self::tri('{"field":"env.v","op":"exists"}', self::ctx('{}', '{"v":null}')));
        self::assertSame('false', self::tri('{"field":"env.v","op":"exists"}'));
        self::assertSame('true', self::tri('{"field":"env.v","op":"exists","value":false}'));
        self::assertSame('false', self::tri('{"field":"env.v","op":"exists","value":false}', self::ctx('{}', '{"v":1}')));
        self::assertSame('false', self::tri('{"field":"env.v","op":"exists","value":0}')); // only `false` means absent
        // params unavailable is NOT absent (fails closed BEFORE `exists` runs)
        $noParams = self::j('{"action":{"verb":"read","resource":"/"},"env":{"x":1}}');
        $nullParams = self::j('{"action":{"verb":"read","resource":"/","params":null},"env":{"x":1}}');
        $strParams = self::j('{"action":{"verb":"read","resource":"/","params":"p"},"env":{"x":1}}');
        foreach ([$noParams, $nullParams, $strParams] as $c) {
            self::assertSame('unknown', self::tri('{"field":"action.params.x","op":"exists","value":false}', $c));
            self::assertSame('unknown', self::tri('{"field":"action.params","op":"exists","value":false}', $c));
            self::assertSame('unknown', self::tri('{"field":"env.x","op":"eq","ref":"action.params.y"}', $c));
            self::assertSame('true', self::tri('{"field":"action.paramsx","op":"exists","value":false}', $c));
        }
        self::assertSame('true', self::tri('{"field":"action.params.x","op":"exists","value":false}', self::ctx('[]')));
        self::assertSame('true', self::tri('{"field":"action.params.x","op":"exists","value":false}'));
        // leaf shape
        self::assertSame('unknown', self::tri('{"field":"","op":"exists"}'));
        self::assertSame('unknown', self::tri('{"field":1,"op":"exists"}'));
        self::assertSame('unknown', self::tri('{"field":"env.v","op":1}'));
        self::assertSame('unknown', self::tri('{"field":"env.v","op":"eq","value":1}')); // unresolved field
        self::assertSame('unknown', self::tri('{"field":"env.v","op":"bogus","value":1}', self::ctx('{}', '{"v":1}')));
        self::assertSame('unknown', self::tri('{"field":"env.v","op":"eq"}', self::ctx('{}', '{"v":1}'))); // no operand
        self::assertSame('true', self::tri('{"field":"env.v","op":"eq","value":null}', self::ctx('{}', '{"v":null}')));
        self::assertSame('true', self::tri('{"field":"env.v","op":"eq","ref":"env.w"}', self::ctx('{}', '{"v":1,"w":1.0}')));
        self::assertSame('unknown', self::tri('{"field":"env.v","op":"eq","ref":"env.w","value":1}', self::ctx('{}', '{"v":1}')));
        self::assertSame('unknown', self::tri('[{"field":"env.v","op":"exists"}]'));
        self::assertSame('unknown', self::tri('"env.v"'));
        self::assertSame('unknown', self::tri('null'));
    }

    // ---- groups -----------------------------------------------------------------------------------------------------

    public function testGroupsAreTriValued(): void
    {
        $T = '{"field":"env.v","op":"exists"}';
        $F = '{"field":"env.nope","op":"exists"}';
        $U = '{"field":"env.v","op":"bogus","value":1}';
        $c = self::ctx('{}', '{"v":1}');
        self::assertSame('true', self::tri("{\"all_of\":[$T,$T]}", $c));
        self::assertSame('false', self::tri("{\"all_of\":[$U,$F]}", $c)); // false wins over unknown
        self::assertSame('unknown', self::tri("{\"all_of\":[$T,$U]}", $c));
        self::assertSame('unknown', self::tri('{"all_of":[]}', $c));
        self::assertSame('unknown', self::tri('{"all_of":{}}', $c));
        self::assertSame('true', self::tri("{\"any_of\":[$U,$T]}", $c)); // true wins over unknown
        self::assertSame('unknown', self::tri("{\"any_of\":[$F,$U]}", $c));
        self::assertSame('false', self::tri("{\"any_of\":[$F,$F]}", $c));
        self::assertSame('unknown', self::tri('{"any_of":[]}', $c));
        self::assertSame('false', self::tri("{\"not\":$T}", $c));
        self::assertSame('true', self::tri("{\"not\":$F}", $c));
        self::assertSame('unknown', self::tri("{\"not\":$U}", $c)); // never satisfied by an unknown child
        self::assertSame('unknown', self::tri('{"not":null}', $c));
        // precedence: all_of, then any_of, then not
        self::assertSame('true', self::tri("{\"all_of\":[$T],\"any_of\":[$F],\"not\":$T}", $c));
        self::assertSame('false', self::tri("{\"any_of\":[$F],\"not\":$F}", $c));
        // a group key wins over a leaf shape
        self::assertSame('false', self::tri("{\"not\":$T,\"field\":\"env.v\",\"op\":\"exists\"}", $c));
        self::assertFalse(Predicates::evaluateCondition(self::j("{\"not\":$U}"), $c));
        self::assertTrue(Predicates::evaluateCondition(self::j("{\"not\":{\"not\":$T}}"), $c));
        self::assertTrue(Predicates::isGroupCondition(self::j('{"not":1}')));
        self::assertFalse(Predicates::isGroupCondition(self::j('[]')));
        self::assertTrue(Predicates::isLeafCondition(self::j('{"field":"x"}')));
        self::assertFalse(Predicates::isLeafCondition(self::j('{"field":1}')));
        self::assertFalse(Predicates::isLeafCondition(self::j('{"field":"x","not":1}')));
    }

    // ---- predicates -------------------------------------------------------------------------------------------------

    private static function pm(string $p, ?Obj $ctx = null): bool
    {
        return Predicates::predicateMatches(self::j($p), $ctx ?? self::ctx());
    }

    public function testVerbAndResource(): void
    {
        self::assertTrue(self::pm('{"verb":"read"}'));
        self::assertTrue(self::pm('{"verb":"*"}'));
        self::assertTrue(self::pm('{"verb":["write",1,"read"]}'));
        self::assertTrue(self::pm('{"verb":["*"]}'));
        self::assertFalse(self::pm('{"verb":"Read"}'));
        self::assertFalse(self::pm('{"verb":["write"]}'));
        self::assertFalse(self::pm('{"verb":1}'));
        self::assertFalse(self::pm('{}'));
        self::assertFalse(self::pm('[{"verb":"*"}]'));
        self::assertFalse(self::pm('"*"'));
        self::assertTrue(self::pm('{"verb":"*","resource":"*"}'));
        self::assertTrue(self::pm('{"verb":"*","resource":"/acct/1"}'));
        self::assertFalse(self::pm('{"verb":"*","resource":"/acct/"}'));
        self::assertTrue(self::pm('{"verb":"*","resource":"/acct/*"}'));
        self::assertTrue(self::pm('{"verb":"*","resource":"/acct/1*"}'));
        self::assertFalse(self::pm('{"verb":"*","resource":"/acct/2*"}'));
        self::assertFalse(self::pm('{"verb":"*","resource":null}'));
        self::assertFalse(self::pm('{"verb":"*","resource":["*"]}'));
        // the action must carry string verb and resource
        self::assertFalse(self::pm('{"verb":"*"}', self::j('{"action":{"verb":"read"}}')));
        self::assertFalse(self::pm('{"verb":"*"}', self::j('{"action":{"verb":1,"resource":"/"}}')));
        self::assertFalse(self::pm('{"verb":"*"}', self::j('{"action":"read"}')));
        self::assertFalse(self::pm('{"verb":"*"}', self::j('{}')));
    }

    public function testReResource(): void
    {
        self::assertTrue(self::pm('{"verb":"*","resource":"re:/acct/\\\\d+"}'));
        self::assertFalse(self::pm('{"verb":"*","resource":"re:/acct"}')); // full match
        self::assertFalse(self::pm('{"verb":"*","resource":"re:(a+)+"}', self::j('{"action":{"verb":"r","resource":"aaa"}}')));
        $ctx = static fn(string $r): Obj => self::o(['action' => ['verb' => 'r', 'resource' => $r]]);
        // pattern <= 200 units
        self::assertTrue(self::pm(self::str200('re:', 200), $ctx(str_repeat('a', 200))));
        self::assertFalse(self::pm(self::str200('re:', 201), $ctx(str_repeat('a', 201))));
        // resource <= 512 units
        self::assertTrue(self::pm('{"verb":"*","resource":"re:a*"}', $ctx(str_repeat('a', 512))));
        self::assertFalse(self::pm('{"verb":"*","resource":"re:a*"}', $ctx(str_repeat('a', 513))));
        self::assertFalse(self::pm('{"verb":"*","resource":"re:[^]*"}', $ctx(str_repeat('😀', 256) . 'a')));
        self::assertTrue(self::pm('{"verb":"*","resource":"re:[^]*"}', $ctx(str_repeat('😀', 256))));
        // `re:` with a trailing `*` is a regex, never a prefix
        self::assertFalse(self::pm('{"verb":"*","resource":"re:/acct*"}', $ctx('/acct/1')));
        self::assertTrue(self::pm('{"verb":"*","resource":"re:/acct*"}', $ctx('/acc')));
    }

    private static function str200(string $prefix, int $n): string
    {
        return '{"verb":"*","resource":' . self::str($prefix . str_repeat('a', $n)) . '}';
    }

    public function testWhere(): void
    {
        $c = self::ctx('{"amt":5}');
        self::assertTrue(self::pm('{"verb":"*","where":[]}', $c));
        self::assertTrue(self::pm('{"verb":"*","where":[{"field":"action.params.amt","op":"lte","value":5}]}', $c));
        self::assertFalse(self::pm('{"verb":"*","where":[{"field":"action.params.amt","op":"lt","value":5}]}', $c));
        self::assertFalse(self::pm('{"verb":"*","where":[{"field":"action.params.amt","op":"lte","value":5},{"bogus":1}]}', $c));
        self::assertFalse(self::pm('{"verb":"*","where":null}', $c));
        self::assertFalse(self::pm('{"verb":"*","where":{"field":"action.params.amt","op":"exists"}}', $c));
        // verb is checked before resource and where (a bad where never matters when the verb fails)
        self::assertFalse(self::pm('{"verb":"x","resource":"*","where":[]}', $c));
    }

    public function testEvaluatePredicates(): void
    {
        $c = self::ctx();
        self::assertSame(['allowed' => false, 'reason' => self::NOPRED], Predicates::evaluatePredicates([], $c));
        self::assertSame(['allowed' => false, 'reason' => self::NOPRED], Predicates::evaluatePredicates(self::j('{}'), $c));
        self::assertSame(['allowed' => false, 'reason' => self::NOPRED], Predicates::evaluatePredicates(null, $c));
        $ps = self::j('[{"verb":"write"},{"verb":"read","resource":"/acct/*"},{"verb":"*"}]');
        $r = Predicates::evaluatePredicates($ps, $c);
        self::assertTrue($r['allowed']);
        self::assertSame($ps[1], $r['matched']); // the FIRST matching predicate
        self::assertSame(['allowed' => false, 'reason' => 'no predicate permits read on /acct/1'],
            Predicates::evaluatePredicates(self::j('[{"verb":"write"}]'), $c));
        self::assertSame(['allowed' => false, 'reason' => 'no predicate permits undefined on undefined'],
            Predicates::evaluatePredicates(self::j('[{"verb":"*"}]'), self::j('{"action":null}')));
        self::assertSame(['allowed' => false, 'reason' => 'no predicate permits 1.5 on true'],
            Predicates::evaluatePredicates(self::j('[{"verb":"*"}]'), self::j('{"action":{"verb":1.50,"resource":true}}')));
        self::assertSame(['allowed' => false, 'reason' => 'no predicate permits a,b on [object Object]'],
            Predicates::evaluatePredicates(self::j('[{"verb":"*"}]'), self::j('{"action":{"verb":["a","b"],"resource":{}}}')));
    }

    // ---- safe regex -------------------------------------------------------------------------------------------------

    public function testSafeRegexSourceGuard(): void
    {
        foreach (['/acct/[^/]+/items/\d+', '(?:GET|POST) /x', 'a*b+', 'a{64}', 'a{0,64}', '[]', '[^](a)', 'a|', '\\(', 'a+?',
            '^a$', '(a)(b)', '[a-z\d-]', '\x41A\cJ\0', 'a{2,}b*'] as $ok) {
            self::assertTrue(SafeRegex::isSafeRegexSource($ok), $ok);
        }
        foreach (['(a+)+', '(a*)*', '(a|aa)+', '(.*a){10}', '\1', '\k<a>', '(?=a)', '(?<n>a)', '(?!a)', 'a{65}', 'a{1,65}',
            'a{2,1}', '{', 'a{', 'a{1', 'a{x}', '*a', 'a**', '(a', 'a)', '[a', '\\', '\b', '\B', '\p{L}', '\q', '\_', '\00',
            '\x4', '\u004', '\c1', '^*', '[^](a+)+]', 'a*b*c*', '[z-a]'] as $bad) {
            self::assertFalse(SafeRegex::isSafeRegexSource($bad), $bad);
        }
        // cost budget: 22 bits. Two unbounded quantifiers (16) + 6 alternations = 22 ok; one more bit refused
        self::assertTrue(SafeRegex::isSafeRegexSource('a*b*c|d|e|f|g|h|i'));
        self::assertFalse(SafeRegex::isSafeRegexSource('a*b*c|d|e|f|g|h|i|j'));
        // `?` costs 1 bit; {m,n} costs ceil(log2(n-m+1)); {n} costs 0
        self::assertTrue(SafeRegex::isSafeRegexSource(str_repeat('a?', 22)));
        self::assertFalse(SafeRegex::isSafeRegexSource(str_repeat('a?', 23)));
        self::assertTrue(SafeRegex::isSafeRegexSource(str_repeat('a{1,4}', 11))); // 2 bits each
        self::assertFalse(SafeRegex::isSafeRegexSource(str_repeat('a{1,4}', 11) . 'b?'));
        self::assertTrue(SafeRegex::isSafeRegexSource(str_repeat('a{1,5}', 7) . 'b')); // 3 bits each = 21
        self::assertFalse(SafeRegex::isSafeRegexSource(str_repeat('a{1,5}', 8)));
        self::assertTrue(SafeRegex::isSafeRegexSource(str_repeat('a{3}', 40)));
        self::assertFalse(SafeRegex::isSafeRegexSource(7));
    }

    private static function fm(string $src, string $subject): ?bool
    {
        return SafeRegex::fullMatch($src, $subject);
    }

    public function testSafeRegexSemantics(): void
    {
        self::assertTrue(self::fm('[^]', "\n"));
        self::assertFalse(self::fm('[]', 'a'));
        self::assertTrue(self::fm('[]|a', 'a'));
        self::assertFalse(self::fm('.', "\n"));
        self::assertFalse(self::fm('.', "\r"));
        self::assertFalse(self::fm('.', "\u{2028}"));
        self::assertTrue(self::fm('.', "\u{2027}"));
        self::assertTrue(self::fm('..', '😀')); // two UTF-16 code units
        self::assertFalse(self::fm('.', '😀'));
        self::assertTrue(self::fm('😀', '😀'));
        self::assertTrue(self::fm('[\d-z]+', '1-z'));
        self::assertFalse(self::fm('[\d-z]', 'a')); // Annex B: '-' literal, not a range
        self::assertTrue(self::fm('[a-]', '-'));
        self::assertTrue(self::fm('[\b]', "\x08"));
        self::assertTrue(self::fm('\cJ', "\n"));
        self::assertTrue(self::fm('\x41B', 'AB'));
        self::assertTrue(self::fm('\0', "\0"));
        self::assertTrue(self::fm('\s', "\u{FEFF}"));
        self::assertFalse(self::fm('\s', "\u{200B}"));
        self::assertTrue(self::fm('\W', '-'));
        self::assertTrue(self::fm('[\W]', 'é'));
        self::assertFalse(self::fm('\w', 'é'));
        self::assertTrue(self::fm('a|', ''));
        self::assertTrue(self::fm('^a$', 'a'));
        self::assertFalse(self::fm('a$', "a\n"));
        self::assertFalse(self::fm('a', "a\n"));
        self::assertFalse(self::fm('a^b', 'ab'));
        self::assertTrue(self::fm('a{2,3}', 'aaa'));
        self::assertFalse(self::fm('a{2,3}', 'aaaa'));
        self::assertTrue(self::fm('a{2,}', 'aaaaa'));
        self::assertFalse(self::fm('a{2,}', 'a'));
        self::assertTrue(self::fm('(?:ab)*?c', 'ababc'));
        self::assertTrue(self::fm('x{1}', 'x'));
        self::assertTrue(self::fm('}', '}'));
        self::assertTrue(self::fm(']', ']'));
        self::assertNull(self::fm('(a', 'a'));
        self::assertNull(self::fm('\\', '\\'));
        self::assertTrue(self::fm('(a+)+', 'aaaa')); // the ENGINE is linear on any pattern (the guard refuses it)
        self::assertFalse(self::fm('(a*)*b', str_repeat('a', 400)));
    }

    public function testSafeRegexSizeAndStepCaps(): void
    {
        // NFA: (a{64}){63} = 4032 sets + Match ok; {64} = 4097 instructions refused
        self::assertNotNull(SafeRegex::compile('(?:a{64}){63}'));
        self::assertNull(SafeRegex::compile('(?:a{64}){64}'));
        self::assertCount(4033, SafeRegex::compile('(?:a{64}){63}'));
        self::assertNull(SafeRegex::compile('a{65}'));
        self::assertNull(SafeRegex::compile('a{0,65}'));
        self::assertNull(SafeRegex::compile('a{1,0}'));
        self::assertNull(SafeRegex::compile('a{12345}'));
        self::assertCount(65, SafeRegex::compile('a{64}'));
        self::assertNull(SafeRegex::compile(1));
        // steps: program 100 instructions x (n + 1) <= 2,000,000
        $src = str_repeat('a', 99);
        self::assertCount(100, SafeRegex::compile($src));
        self::assertFalse(self::fm($src, str_repeat('a', 19999)));
        self::assertNull(self::fm($src, str_repeat('a', 20000)));
        self::assertNull(self::fm($src, str_repeat('😀', 10000))); // 20000 units
    }

    // ---- regex budget -----------------------------------------------------------------------------------------------

    /** `$n` `matches` leaves (each source `$src`) over env.s = `$subject`, joined by `$group`. */
    private static function many(string $group, int $n, string $src, string $subject, string $tail = ''): string
    {
        $leaf = '{"field":"env.s","op":"matches","value":' . self::str($src) . '}';
        $items = array_fill(0, $n, $leaf);
        if ($tail !== '') {
            $items[] = '{"field":"env.s","op":"matches","value":' . self::str($tail) . '}';
        }
        return self::tri('{"' . $group . '":[' . implode(',', $items) . ']}',
            self::ctx('{}', '{"s":' . self::str($subject) . '}'));
    }

    public function testRegexBudgetPerDocument(): void
    {
        // evaluations: 64 per document
        self::assertSame('true', self::many('all_of', 64, 'a', 'a'));
        self::assertSame('unknown', self::many('all_of', 65, 'a', 'a'));
        // source chars: 8192 per document (40 x 200 = 8000 ok; 41 x 200 = 8200 refused)
        $big = str_repeat('a', 200);
        self::assertSame('true', self::many('all_of', 40, $big, $big));
        self::assertSame('unknown', self::many('all_of', 41, $big, $big));
        // poisoned: after a refusal, a cheaper (and matching) pattern is refused too
        $miss = str_repeat('a', 199) . 'b';
        self::assertSame('unknown', self::many('any_of', 41, $miss, $big, 'a*'));
        self::assertSame('true', self::many('any_of', 40, $miss, $big, 'a*'));
        // each top-level call is its own document, and the scope is closed afterwards
        self::assertSame('true', self::many('all_of', 40, $big, $big));
        self::assertNull(SafeRegex::currentBudget());
        // an unsafe pattern is refused by the guard before it is charged
        self::assertSame('true', self::many('any_of', 64, '(a+)+', 'a', 'a'));
        // the predicate evaluator opens ONE document across predicates and their where conditions
        $leaf = '{"field":"env.s","op":"matches","value":"a"}';
        $p = '{"verb":"*","where":[' . implode(',', array_fill(0, 33, $leaf)) . ']}';
        $ctx = self::ctx('{}', '{"s":"a"}');
        self::assertTrue(Predicates::evaluatePredicates(self::j("[$p]"), $ctx)['allowed']);
        $p2 = '{"verb":"*","where":[' . implode(',', array_fill(0, 32, $leaf)) . ',{"field":"env.nope","op":"exists"}]}';
        self::assertFalse(Predicates::evaluatePredicates(self::j("[$p2,$p]"), $ctx)['allowed']); // 32 + 33 = 65
        self::assertTrue(Predicates::evaluatePredicates(self::j("[$p2]"), $ctx)['allowed'] === false);
        self::assertNull(SafeRegex::currentBudget());
    }

    public function testRegexBudgetObject(): void
    {
        $b = new SafeRegexBudget();
        for ($i = 0; $i < SafeRegex::MAX_REGEX_EVALUATIONS_PER_DOCUMENT; $i++) {
            self::assertTrue($b->charge('a', 1));
        }
        self::assertFalse($b->charge('a', 1));
        self::assertSame(1, $b->refusals);
        self::assertSame(SafeRegex::MAX_REGEX_EVALUATIONS_PER_DOCUMENT + 1, $b->evaluations);
        // steps: program length x (subject + 1); `a` compiles to 2 instructions
        $s = new SafeRegexBudget();
        self::assertTrue($s->charge('a', 2499999)); // 2 x 2,500,000 = 5,000,000
        self::assertFalse($s->charge('a', 0));
        $s2 = new SafeRegexBudget();
        self::assertFalse($s2->charge('a', 2500000));
        // a non-compiling source is refused without being charged
        $u = new SafeRegexBudget();
        self::assertFalse($u->charge('(', 1));
        self::assertSame(0, $u->evaluations);
        self::assertSame(1, $u->refusals);
        // request budget: scale 4, document budgets inside it also charge it
        $req = SafeRegex::requestBudget();
        $ok = $req->run(static function (): array {
            $r = [];
            for ($d = 0; $d < 5; $d++) {
                $r[] = SafeRegex::withBudget(static function (): bool {
                    $all = true;
                    for ($i = 0; $i < 64; $i++) {
                        $all = SafeRegex::charge('a', 1) && $all;
                    }
                    return $all;
                });
            }
            return $r;
        });
        self::assertSame([true, true, true, true, false], $ok);
        self::assertNull(SafeRegex::currentBudget());
        // the scope is restored even when the body throws
        try {
            (new SafeRegexBudget())->run(static function (): never {
                throw new \RuntimeException('x');
            });
        } catch (\RuntimeException) {
        }
        self::assertNull(SafeRegex::currentBudget());
        // outside any scope each charge gets a fresh single-use budget
        for ($i = 0; $i < 100; $i++) {
            self::assertTrue(SafeRegex::charge('a', 1));
        }
    }

    // ---- layers -----------------------------------------------------------------------------------------------------

    private static function cap(int $max): string
    {
        return '{"predicates":[{"verb":"*","where":[{"field":"action.params.amt","op":"lte","value":' . $max . '}]}]}';
    }

    private static function ceil(string $layers, int $amt): array
    {
        return Predicates::decideLayerCeilings(self::j($layers), self::ctx('{"amt":' . $amt . '}'));
    }

    private static function failAt(string $k): array
    {
        return ['status' => 'fail', 'layer' => $k, 'reason' => "layers: the action is outside the $k ceiling (a ceiling is never a question)"];
    }

    private static function malformed(string $k): array
    {
        return ['status' => 'fail', 'layer' => $k, 'reason' => "layers: the $k ceiling is malformed (null or not {predicates: [...]})"];
    }

    public function testLayerCeilings(): void
    {
        self::assertSame(['org', 'site', 'std'], Predicates::LAYER_CEILINGS);
        $all = '{"std":' . self::cap(300) . ',"site":' . self::cap(400) . ',"org":' . self::cap(500) . '}';
        self::assertSame(self::failAt('org'), self::ceil($all, 600)); // org first, whatever the key order
        self::assertSame(self::failAt('site'), self::ceil($all, 450));
        self::assertSame(self::failAt('std'), self::ceil($all, 350));
        self::assertSame(['status' => 'pass'], self::ceil($all, 300));
        // ABSENT = no constraint
        self::assertSame(['status' => 'pass'], self::ceil('{}', 10000));
        self::assertSame(self::failAt('std'), self::ceil('{"std":' . self::cap(300) . '}', 350));
        // PRESENT with null or a non-layer value is MALFORMED and fails as that ceiling (never "no constraint")
        self::assertSame(self::malformed('org'), self::ceil('{"org":null,"site":null,"std":null}', 1));
        self::assertSame(self::malformed('site'), self::ceil('{"org":' . self::cap(500) . ',"site":null}', 1));
        self::assertSame(self::malformed('std'), self::ceil('{"std":null}', 1));
        self::assertSame(self::malformed('org'), self::ceil('{"org":{}}', 1));
        self::assertSame(self::malformed('org'), self::ceil('{"org":false}', 1));
        self::assertSame(self::malformed('org'), self::ceil('{"org":[{"verb":"*"}]}', 1));
        self::assertSame(self::malformed('std'), self::ceil('{"std":{"predicates":{"verb":"*"}}}', 1));
        self::assertSame(self::malformed('site'), self::ceil('{"site":{"predicates":null}}', 1));
        // check order: an earlier ceiling that DENIES wins over a later malformed one; an earlier malformed one wins too
        self::assertSame(self::failAt('org'), self::ceil('{"org":' . self::cap(1) . ',"site":null}', 5));
        self::assertSame(self::malformed('org'), self::ceil('{"org":null,"site":' . self::cap(1) . '}', 5));
        // an empty predicate list is well formed but admits nothing
        self::assertSame(self::failAt('site'), self::ceil('{"site":{"predicates":[]}}', 1));
        self::assertSame(['status' => 'pass'], self::ceil('{"org":{"predicates":[{"verb":"*"}]}}', 1));
        // closed member sets: a layer is EXACTLY {predicates}; the layers object is {org?, site?, std?}
        self::assertSame(self::malformed('org'), self::ceil('{"org":{"predicates":[{"verb":"*"}],"extra":1}}', 1));
        self::assertSame(self::malformed('site'), self::ceil('{"site":{"predicates":[{"verb":"*"}],"note":"x"}}', 1));
        $unknown = ['status' => 'fail', 'layer' => 'org', 'reason' => 'layers: unknown member (the layers object is {org?, site?, std?})'];
        self::assertSame($unknown, self::ceil('{"org":' . self::cap(500) . ',"extra":' . self::cap(1) . '}', 1));
        self::assertSame($unknown, self::ceil('{"task":[]}', 1));
        self::assertSame($unknown, self::ceil('{"__proto__":null}', 1));
        // the unknown-member check runs BEFORE any ceiling (it wins over a denying / malformed org)
        self::assertSame($unknown, self::ceil('{"org":' . self::cap(1) . ',"x":1}', 5));
        self::assertSame($unknown, self::ceil('{"org":null,"x":1}', 5));
        // a non-object layers value is malformed (named org)
        $bad = ['status' => 'fail', 'layer' => 'org', 'reason' => 'layers: the layers member is malformed (not an object)'];
        foreach (['null', '[]', '"x"', '1', 'true'] as $l) {
            self::assertSame($bad, self::ceil($l, 1), $l);
        }
        // the ceiling sees the verifier env (env.canon) through the ordinary evaluator
        $env = Predicates::decideLayerCeilings(
            self::j('{"org":{"predicates":[{"verb":"*","where":[{"field":"env.canon.k","op":"eq","value":1}]}]}}'),
            self::ctx('{}', '{"canon":{"k":1}}')
        );
        self::assertSame(['status' => 'pass'], $env);
        self::assertTrue(Predicates::isLayerPolicy(self::j('{"predicates":[]}')));
        self::assertFalse(Predicates::isLayerPolicy(self::j('{"predicate":[]}')));
        self::assertFalse(Predicates::isLayerPolicy(self::j('[[]]')));
        self::assertFalse(Predicates::isLayerPolicy(self::j('{"predicates":[],"x":1}')));
    }

    public function testDecideLayers(): void
    {
        $ctx = self::ctx('{"amt":50}');
        $d = static fn(string $g): array => Predicates::decideLayers(self::j($g), $ctx);
        $yes = '{"predicates":[{"verb":"*"}]}';
        $no = '{"predicates":[{"verb":"nope"}]}';
        $denied = ['decision' => 'intent_denied'];
        $required = ['decision' => 'intent_required'];
        self::assertSame(['decision' => 'ceiling', 'layer' => 'site'], $d('{"site":' . self::cap(10) . ',"denied":[' . $yes . '],"task":[' . $yes . ']}'));
        self::assertSame(['decision' => 'ceiling', 'layer' => 'std'], $d('{"std":null,"task":[' . $yes . ']}')); // malformed ceiling
        self::assertSame(['decision' => 'ceiling', 'layer' => 'org'], $d('null')); // a non-object grant
        self::assertSame(['decision' => 'ceiling', 'layer' => 'org'], $d('[]'));
        self::assertSame($denied, $d('{"org":' . self::cap(100) . ',"denied":[' . $no . ',' . $yes . '],"task":[' . $yes . ']}'));
        self::assertSame(['decision' => 'admit', 'by' => 0], $d('{"denied":[' . $no . '],"task":[' . $yes . ',' . $yes . ']}'));
        self::assertSame(['decision' => 'admit', 'by' => 2], $d('{"task":[' . $no . ',{"predicates":[]},' . $yes . ']}'));
        self::assertSame(['decision' => 'admit', 'by' => 0], $d('{"denied":[],"task":[' . $yes . ']}'));
        self::assertSame($required, $d('{"task":[' . $no . ']}'));
        self::assertSame($required, $d('{"task":[]}'));
        // task is REQUIRED and must be an array; denied absent = [], present must be an array
        self::assertSame($denied, $d('{}'));
        self::assertSame($denied, $d('{"task":' . $yes . '}'));
        self::assertSame($denied, $d('{"task":null}'));
        self::assertSame($denied, $d('{"denied":null,"task":[' . $yes . ']}'));
        self::assertSame($denied, $d('{"denied":"x","task":[' . $yes . ']}')); // never iterated
        self::assertSame($denied, $d('{"denied":{},"task":[' . $yes . ']}'));
        // closed grant {org?, site?, std?, task, denied?}: an unknown member is intent_denied, checked FIRST
        self::assertSame($denied, $d('{"task":[' . $yes . '],"extra":[]}'));
        self::assertSame($denied, $d('{"org":' . self::cap(1) . ',"task":[' . $yes . '],"x":1}')); // not `ceiling`
        self::assertSame($denied, $d('{"task":[{"predicates":[{"verb":"*"}],"caveats":[]}]}')); // a layer is exactly {predicates}
        self::assertSame(['decision' => 'ceiling', 'layer' => 'org'], $d('{"org":{"predicates":[],"x":1},"task":[' . $yes . ']}'));
        // a malformed ENTRY anywhere refuses, even when an earlier task entry would admit
        self::assertSame($denied, $d('{"task":[' . $yes . ',{}]}'));
        self::assertSame($denied, $d('{"task":[' . $yes . ',null]}'));
        self::assertSame($denied, $d('{"denied":[' . $no . ',[]],"task":[' . $yes . ']}'));
        self::assertSame($denied, $d('{"denied":[' . $no . '],"task":[' . $yes . ',{"predicates":"*"}]}'));
    }
}
