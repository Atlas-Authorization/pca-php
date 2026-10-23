<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentV2;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Exact-behaviour tests of the IntentV2 value / canonical-form helpers (JS String / Number / Object.keys semantics). */
final class IntentV2HelperKillTest extends TestCase
{
    private static function priv(string $name, mixed ...$args): mixed
    {
        $m = new \ReflectionMethod(IntentV2::class, $name);
        return $m->invoke(null, ...$args);
    }

    private static function lone(): string
    {
        return "a\xED\xA0\x80b"; // WTF-8 lone high surrogate
    }

    public function testU16len(): void
    {
        $this->assertSame(0, IntentV2::u16len(''));
        $this->assertSame(3, IntentV2::u16len('abc'));
        $this->assertSame(1, IntentV2::u16len("\xC3\xA9"));          // e-acute
        $this->assertSame(1, IntentV2::u16len("\xE2\x82\xAC"));      // euro
        $this->assertSame(2, IntentV2::u16len("\xF0\x9F\x98\x80"));  // astral = surrogate pair
        $this->assertSame(1 + 1 + 2 + 1, IntentV2::u16len("a\xC3\xA9\xF0\x9F\x98\x80z"));
        $this->assertSame(3, IntentV2::u16len(self::lone()));        // a lone surrogate is one unit
        $this->assertSame(4, IntentV2::u16len(str_repeat("\xF0\x9F\x98\x80", 2)));
    }

    public function testParamNameDropsExactlyThePrefix(): void
    {
        $this->assertSame('total', self::priv('paramName', 'action.params.total'));
        $this->assertSame('', self::priv('paramName', 'action.params.'));
    }

    public function testNumbersByValue(): void
    {
        $this->assertSame(5.0, self::priv('f', new Num('5.0')));
        $this->assertSame(5.0, self::priv('f', 5));
        $this->assertSame(2.5, self::priv('f', 2.5));
        $this->assertNull(self::priv('f', true));
        $this->assertNull(self::priv('f', '5'));
        $this->assertTrue(self::priv('negZero', -0.0));
        $this->assertFalse(self::priv('negZero', 0.0));
        $this->assertFalse(self::priv('negZero', -1.0));
        $this->assertFalse(self::priv('negZero', 1.0));
        foreach ([new Num('0'), new Num('5.0'), new Num('9007199254740991'), 7, 7.0, new Num('-3'), new Num('1e3')] as $ok) {
            $this->assertTrue(self::priv('isInt', $ok), json_encode($ok instanceof Num ? $ok->lexeme : $ok));
        }
        foreach ([new Num('-0'), new Num('1.5'), new Num('9007199254740992'), new Num('1e400'), 'x', null, true, 0.5, NAN, INF] as $bad) {
            $this->assertFalse(self::priv('isInt', $bad));
        }
        $this->assertTrue(self::priv('isNonNeg', new Num('0')));
        $this->assertTrue(self::priv('isNonNeg', 4));
        $this->assertFalse(self::priv('isNonNeg', new Num('-1')));
        $this->assertSame(7, self::priv('iv', new Num('7')));
        $this->assertSame(-7, self::priv('iv', -7.0));
    }

    public function testScalarStrictEquality(): void
    {
        $u = IntentV2::undef();
        $o = new Obj();
        $cases = [
            [$u, $u, true], [$u, null, false], [null, $u, false], [null, null, true], [null, 0, false], [0, null, false],
            [new Num('1'), new Num('1.0'), true], [new Num('1'), 1, true], [1, 1.0, true], [new Num('1'), new Num('2'), false],
            [new Num('1'), '1', false], ['1', new Num('1'), false], [1, true, false], [true, 1, false], [true, true, true], [true, false, false],
            [false, false, true], ['a', 'a', true], ['a', 'b', false], ['a', null, false], [null, 'a', false], [true, null, false],
            [null, false, false], [false, null, false], [$o, $o, true], [$o, new Obj(), false], [$o, null, false], [null, $o, false],
            [[1], [1], false], ['', false, false], [false, '', false], [false, 0, false], [0, false, false],
        ];
        foreach ($cases as $i => [$a, $b, $want]) {
            $this->assertSame($want, self::priv('eq', $a, $b), "case $i");
        }
    }

    public function testIndexKeysAndJsKeysOrder(): void
    {
        foreach (['0', '1', '10', '4294967294'] as $k) {
            $this->assertTrue(self::priv('isIndexKey', $k), $k);
        }
        foreach (['', '01', '-1', '4294967295', '1.5', 'a', '12345678901', ' 1', '1 ', "1\n"] as $k) {
            $this->assertFalse(self::priv('isIndexKey', $k), json_encode($k));
        }
        $o = new Obj();
        foreach (['b', '10', 'a', '2', '01', '1'] as $k) {
            $o->set($k, 1);
        }
        $this->assertSame(['1', '2', '10', 'b', 'a', '01'], IntentV2::jsKeys($o));
    }

    public function testCompareUtf8(): void
    {
        $this->assertSame(0, IntentV2::compareUtf8('a', 'a'));
        $this->assertSame(-1, IntentV2::compareUtf8('a', 'b'));
        $this->assertSame(1, IntentV2::compareUtf8('b', 'a'));
        $this->assertSame(-1, IntentV2::compareUtf8('a', 'ab'));
        $this->assertSame(1, IntentV2::compareUtf8('ab', 'a'));
        $this->assertSame(2, IntentV2::compareUtf8('abc', 'a'));
        $this->assertSame(-2, IntentV2::compareUtf8('a', 'abc'));
        // UTF-8 byte order puts an astral character above U+FFFF (UTF-16 order would not)
        $this->assertGreaterThan(0, IntentV2::compareUtf8("\xF0\x9F\x98\x80", "\xEF\xBF\xBF"));
        $this->assertGreaterThan(0, IntentV2::compareUtf8("\xEF\xBF\xBF", "\xE0\xA0\x80"));
        // a lone surrogate compares as U+FFFD
        $this->assertSame(0, IntentV2::compareUtf8("\xED\xA0\x80", "\xEF\xBF\xBD"));
        $this->assertSame(0, IntentV2::compareUtf8("x\xED\xB0\x80", "x\xED\xA0\x80"));
        $this->assertSame(['a', "\xF0\x9F\x98\x80"], (new \ReflectionMethod(IntentV2::class, 'sortUtf8'))->invoke(null, ["\xF0\x9F\x98\x80", 'a']));
    }

    public function testJsNumStr(): void
    {
        $this->assertSame('Infinity', IntentV2::jsNumStr(INF));
        $this->assertSame('-Infinity', IntentV2::jsNumStr(-INF));
        $this->assertSame('NaN', IntentV2::jsNumStr(NAN));
        $this->assertSame('0', IntentV2::jsNumStr(-0.0));
        $this->assertSame('-1', IntentV2::jsNumStr(-1.0));
        $this->assertSame('-1.5', IntentV2::jsNumStr(-1.5));
        $this->assertSame('1e+21', IntentV2::jsNumStr(1e21));
        $this->assertSame('1.5e+21', IntentV2::jsNumStr(1.5e21));
        $this->assertSame('100000000000000000000', IntentV2::jsNumStr(1e20));
        $this->assertSame('1e-7', IntentV2::jsNumStr(1e-7));
        $this->assertSame('-1.5e-7', IntentV2::jsNumStr(-1.5e-7));
        $this->assertSame('0.000001', IntentV2::jsNumStr(1e-6));
        $this->assertSame('1.2345e+25', IntentV2::jsNumStr(1.2345e25));
        $this->assertSame('123.456', IntentV2::jsNumStr(123.456));
        $this->assertSame('1.7976931348623157e+308', IntentV2::jsNumStr(1.7976931348623157e308));
        $this->assertSame('5e-324', IntentV2::jsNumStr(5e-324));
    }

    public function testTxtFollowsStringOfJavaScript(): void
    {
        $this->assertSame('1.5', self::priv('txt', new Num('1.50')));
        $this->assertSame('abc', self::priv('txt', 'abc'));
        $this->assertSame('true', self::priv('txt', true));
        $this->assertSame('false', self::priv('txt', false));
        $this->assertSame('null', self::priv('txt', null));
        $this->assertSame('undefined', self::priv('txt', IntentV2::undef()));
        $this->assertSame('[object Object]', self::priv('txt', new Obj()));
        $this->assertSame('1,,x,,3', self::priv('txt', [new Num('1'), null, 'x', IntentV2::undef(), 3]));
        $this->assertSame('a,b,c', self::priv('txt', ['a', ['b', 'c']]));
        $this->assertSame('', self::priv('txt', []));
        $this->assertSame('stdClass', self::priv('txt', new \stdClass()));
    }

    private function refusal(callable $f): string
    {
        try {
            $f();
        } catch (JsonError $e) {
            return $e->getMessage();
        }
        $this->fail('no JsonError');
    }

    public function testCanonicalizeScalarsAndOrder(): void
    {
        $this->assertSame('null', IntentV2::canonicalize(null));
        $this->assertSame('true', IntentV2::canonicalize(true));
        $this->assertSame('false', IntentV2::canonicalize(false));
        $this->assertSame('"a\"b"', IntentV2::canonicalize('a"b'));
        $this->assertSame('0', IntentV2::canonicalize(new Num('0')));
        $this->assertSame('1', IntentV2::canonicalize(new Num('1.0')));
        $this->assertSame('1000', IntentV2::canonicalize(new Num('1e3')));
        $this->assertSame('-12', IntentV2::canonicalize(-12));
        $this->assertSame('9007199254740991', IntentV2::canonicalize(new Num('9007199254740991')));
        $this->assertSame('0.5', IntentV2::canonicalize(0.5));
        $this->assertSame('-0.5', IntentV2::canonicalize(-0.5));
        $this->assertSame('0.000001', IntentV2::canonicalize(0.000001));
        $this->assertSame('123456789012345', IntentV2::canonicalize(123456789012345.0));
        $this->assertSame('1.23456789012345', IntentV2::canonicalize(1.23456789012345));
        $this->assertSame('[1,[2,[]],{}]', IntentV2::canonicalize([1, [2, []], new Obj()]));
        $o = Obj::of(['b' => 1, 'a' => [true, null], "\xF0\x9F\x98\x80" => 2, "\xEF\xBF\xBF" => 3, '10' => 4, '9' => 5]);
        $this->assertSame("{\"10\":4,\"9\":5,\"a\":[true,null],\"b\":1,\"\xEF\xBF\xBF\":3,\"\xF0\x9F\x98\x80\":2}", IntentV2::canonicalize($o));
        $this->assertSame('{"a":1,"b":2}', IntentV2::canonicalize(['b' => 2, 'a' => 1])); // a PHP assoc array is an object
        $this->assertSame(IntentV2::hashCanonical($o), \Atlas\Pca\Pca::b64u(hash('sha256', IntentV2::canonicalize($o), true)));
    }

    public function testCanonicalizeRefusals(): void
    {
        $c = IntentV2::canonicalize(...);
        $this->assertSame('canonicalize: non-finite number', $this->refusal(fn() => $c(NAN)));
        $this->assertSame('canonicalize: non-finite number', $this->refusal(fn() => $c(INF)));
        $this->assertSame('canonicalize: non-finite number', $this->refusal(fn() => $c(new Num('1e400'))));
        $this->assertSame('canonicalize: negative zero', $this->refusal(fn() => $c(new Num('-0'))));
        $this->assertSame('canonicalize: integer outside the safe range (|n| > 2^53-1)', $this->refusal(fn() => $c(new Num('9007199254740992'))));
        $this->assertSame('canonicalize: non-integer magnitude below 1e-6', $this->refusal(fn() => $c(0.0000001)));
        $this->assertSame('canonicalize: non-integer magnitude below 1e-6', $this->refusal(fn() => $c(-0.0000009)));
        $this->assertSame('canonicalize: non-integer number has more than 15 significant digits', $this->refusal(fn() => $c(1.2345678901234567)));
        $this->assertSame('canonicalize: non-integer number has more than 15 significant digits', $this->refusal(fn() => $c(-1.2345678901234567)));
        $this->assertSame('canonicalize: lone surrogate in string', $this->refusal(fn() => $c(self::lone())));
        $this->assertSame('canonicalize: lone surrogate in key', $this->refusal(fn() => $c(Obj::of([self::lone() => 1]))));
        $this->assertSame('canonicalize: unsupported type undefined', $this->refusal(fn() => $c(IntentV2::undef())));
        $this->assertSame('canonicalize: unsupported type stdClass', $this->refusal(fn() => $c(new \stdClass())));
        $this->assertSame('canonicalize: unsupported type Closure', $this->refusal(fn() => $c(fn() => 1)));
    }

    public function testCanonicalizeDepthBoundary(): void
    {
        $nest = function (int $n): mixed {
            $v = 1;
            for ($i = 0; $i < $n; $i++) {
                $v = [$v];
            }
            return $v;
        };
        $max = Json::MAX_DEPTH;
        $this->assertSame(str_repeat('[', $max) . '1' . str_repeat(']', $max), IntentV2::canonicalize($nest($max)));
        $this->assertSame('canonicalize: nesting too deep', $this->refusal(fn() => IntentV2::canonicalize($nest($max + 1))));
        $obj = function (int $n): mixed {
            $v = 1;
            for ($i = 0; $i < $n; $i++) {
                $v = Obj::of(['k' => $v]);
            }
            return $v;
        };
        $this->assertStringStartsWith('{"k":', IntentV2::canonicalize($obj($max)));
        $this->assertSame('canonicalize: nesting too deep', $this->refusal(fn() => IntentV2::canonicalize($obj($max + 1))));
        // depth counts through list elements and through object members alike
        $mixed = [Obj::of(['k' => [Obj::of(['k' => 1])]])];
        $this->assertSame('[{"k":[{"k":1}]}]', IntentV2::canonicalize($mixed));
    }

    public function testSuiteHelpers(): void
    {
        $this->assertNull(IntentV2::suiteError(IntentV2::undef()));
        $this->assertSame('alg must be a string', IntentV2::suiteError(5));
        $this->assertSame('alg must be a string', IntentV2::suiteError(null));
        $this->assertNull(IntentV2::suiteError('ed25519'));
        $this->assertSame("unsupported_suite: 'nope'", IntentV2::suiteError('nope'));
        $this->assertSame('ed25519', self::priv('suiteOf', IntentV2::undef()));
        $this->assertSame('ml-dsa-65', self::priv('suiteOf', 'ml-dsa-65'));
        $this->assertNull(self::priv('suiteKnownError', IntentV2::undef()));
        $this->assertSame('alg must be a string', self::priv('suiteKnownError', 5));
        $this->assertNull(self::priv('suiteKnownError', 'ml-dsa-87'));
        $this->assertSame("unsupported_suite: 'nope'", self::priv('suiteKnownError', 'nope'));
        $base = Obj::of(['a' => 1]);
        $this->assertSame($base, self::priv('bindSuite', $base, IntentV2::undef(), 'x'));
        $b = self::priv('bindSuite', $base, 'ml-dsa-65', 'PK');
        $this->assertSame(['a', 'alg', 'pq_pk'], $b->keys());
        $this->assertSame(['a'], $base->keys());
        $this->assertSame('PK', $b->get('pq_pk'));
    }

    public function testVerifyPinnedGuards(): void
    {
        $u = IntentV2::undef();
        $v = fn(...$a) => self::priv('verifyPinned', ...$a);
        $this->assertFalse($v($u, 5, $u, 'm', $u, $u));
        // a pin for another key, or a pin that is not a string: refused before any crypto
        $this->assertFalse($v($u, 'K', $u, 'm', 'sig', $u, 'OTHER', 'pq'));
        $this->assertFalse($v($u, 'K', $u, 'm', 'sig', $u, 'K', 5));
        $this->assertFalse($v($u, 'K', $u, 'm', 'sig', $u, 'K', null));
        $this->assertFalse($v($u, 'K', $u, 'm', 'sig', $u));
    }
}
