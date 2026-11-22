<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\JsError;
use Atlas\Pca\Attest\JsJson;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * 0.5 mutation-kill tests of the JSON.parse port (src/Attest/JsJson.php). Expected "Unexpected token" texts were produced by Node's
 * JSON.parse; error texts that Node 24 words differently (it appends " (line L column C)" and names structural faults) are only
 * pinned by the prefix both agree on. UTF-8 expectations come from PHP's own json_decode. Any PHP warning is turned into an
 * exception so an out-of-range string offset read by a mutant fails the test.
 */
final class K05KillAttestJsJson1Test extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
            throw new \ErrorException($msg, 0, $no, $file, $line);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function msg(string $text): string
    {
        try {
            JsJson::parse($text);
        } catch (JsError $e) {
            return $e->getMessage();
        }
        self::fail('parsed ' . json_encode($text));
    }

    private static function plain(mixed $v): mixed
    {
        if ($v instanceof Num) {
            return 'N' . $v->lexeme;
        }
        if ($v instanceof Obj) {
            $o = [];
            foreach ($v->keys() as $k) {
                $o[$k] = self::plain($v->get($k));
            }
            return ['obj' => $o, 'keys' => $v->keys()];
        }
        return is_array($v) ? array_map(self::plain(...), $v) : $v;
    }

    public function testTokenWordingAndContextWindow(): void
    {
        $cases = [
            "xabcdefghijklmnopqrs" => "Unexpected token 'x', \"xabcdefghijklmnopqrs\" is not valid JSON",
            "xabcdefghijklmnopqrst" => "Unexpected token 'x', \"xabcdefghi\"... is not valid JSON",
            "xabcdefghijklmnopqrstuvwq" => "Unexpected token 'x', \"xabcdefghi\"... is not valid JSON",
            "xabcdefghijklmnopqrstuvwqyz" => "Unexpected token 'x', \"xabcdefghi\"... is not valid JSON",
            "[2,4,xabcdefghijklmnopqrstuvwqy" => "Unexpected token 'x', \"[2,4,xabcdefghi\"... is not valid JSON",
            "[2,4,6,8,xabcdefghijklmnopqrstuvwqy" => "Unexpected token 'x', \"[2,4,6,8,xabcdefghi\"... is not valid JSON",
            "[10,5,7,9,xabcdefghijklmnopqrstuvwqy" => "Unexpected token 'x', ...\"[10,5,7,9,xabcdefghi\"... is not valid JSON",
            "[2,4,6,8,1,xabcdefghijklmnopqrstuvwqy" => "Unexpected token 'x', ...\"2,4,6,8,1,xabcdefghi\"... is not valid JSON",
            "[10,5,7,9,2,4,xabcdefghi" => "Unexpected token 'x', ...\"5,7,9,2,4,xabcdefghi\" is not valid JSON",
            "[10,5,7,9,2,4,xabcdefghij" => "Unexpected token 'x', ...\"5,7,9,2,4,xabcdefghi\"... is not valid JSON",
            "[2,4,6,8,1,3,xabcdefg" => "Unexpected token 'x', ...\"4,6,8,1,3,xabcdefg\" is not valid JSON",
            "[2,4,6,8,1,3,xabcdef" => "Unexpected token 'x', \"[2,4,6,8,1,3,xabcdef\" is not valid JSON",
            "[10,5,7,9,2,4,xabcdefgh" => "Unexpected token 'x', ...\"5,7,9,2,4,xabcdefgh\" is not valid JSON",
            "[10,5,7,9,2,4,6,x" => "Unexpected token 'x', \"[10,5,7,9,2,4,6,x\" is not valid JSON",
            "[10,5,7,9,2,4,6,8,1,x" => "Unexpected token 'x', ...\"2,4,6,8,1,x\" is not valid JSON",
            "[2,4,6,8,1,3,5,xabcde" => "Unexpected token 'x', ...\"6,8,1,3,5,xabcde\" is not valid JSON",
        ];
        foreach ($cases as $text => $want) {
            $this->assertSame($want, self::msg((string)$text), (string)$text);
        }
    }

    public function testBrokenLiteralNamesTheBreakingCharacter(): void
    {
        $this->assertSame("Unexpected token 'x', \"nulx\" is not valid JSON", self::msg('nulx'));
        $this->assertSame("Unexpected token 'x', \" nulx\" is not valid JSON", self::msg(' nulx'));
        $this->assertSame('Unexpected end of JSON input', self::msg(' nul'));
        $this->assertSame('Unexpected end of JSON input', self::msg('  nul'));
        $this->assertSame('Unexpected end of JSON input', self::msg('nul'));
        $this->assertSame('Unexpected end of JSON input', self::msg("\t\ntru"));
        // a complete literal followed by text is trailing data, not a broken literal
        $this->assertStringStartsWith('Unexpected non-whitespace character after JSON at position 4', self::msg('nullx'));
        $this->assertStringStartsWith('Unexpected non-whitespace character after JSON at position 5', self::msg(' true1'));
    }

    public function testDigitAfterAValueIsAnUnexpectedNumber(): void
    {
        $this->assertStringStartsWith('Unexpected number in JSON at position 2', self::msg('[01]'));
    }

    public function testWhitespaceEverywhere(): void
    {
        $this->assertSame('N1', self::plain(JsJson::parse(" \n1\t")));
        $this->assertSame([], self::plain(JsJson::parse(' [ ] ')));
        $this->assertSame(['N1', 'N2', 'N3'], self::plain(JsJson::parse("[ 1 , 2,\n3 ]")));
        $this->assertSame(['obj' => [], 'keys' => []], self::plain(JsJson::parse('{ }')));
        $this->assertSame(
            ['obj' => ['a' => 'N1', 'b' => ['N1', 'N2']], 'keys' => ['a', 'b']],
            self::plain(JsJson::parse(" { \"a\" : 1 , \"b\" : [ 1 , 2 ] } ")),
        );
        $this->assertSame(['obj' => ['a' => 'N1'], 'keys' => ['a']], self::plain(JsJson::parse('{"a" :1 }')));
    }

    public function testStructuralFaultsAreRefused(): void
    {
        // each input would parse if the guarded check were gone (the offending byte is skipped as if it were the delimiter)
        foreach ([
            '{xy":1}',
            '{"a"x1}',
            '{"a":1x"b":2}',
            '{"a":1,xb":2}',
            '[1x2]',
            '[1 2]',
            '{"a":1,}',
            '{"a" 1}',
        ] as $bad) {
            $this->assertNotSame('', self::msg($bad), $bad);
        }
    }

    public function testStringFaultsAreRefused(): void
    {
        foreach (['"abc', '"abc\\', '"\\', "\"a\x01b\"", "\"a\x1fb\"", '"\\x"', '"\\u00zz"', '"\\u12"', '"\\u12', '"\\uzzzz"', '"\\ud800\\uzzzz"'] as $bad) {
            $this->assertNotSame('', self::msg($bad), json_encode($bad));
        }
    }

    public function testEscapes(): void
    {
        $j = <<<'J'
"a\"b\\c\/d\be\ff\ng\rh\ti"
J;
        $this->assertSame("a\"b\\c/d\x08e\x0cf\ng\rh\ti", JsJson::parse($j));
        $this->assertSame("a\n", JsJson::parse('"a\\n"'));
        $this->assertSame('"', JsJson::parse('"\\""'));
        $this->assertSame("\x7f ", JsJson::parse("\"\x7f \""));
    }

    public function testEscapeAndUnicodeLoopsTerminate(): void
    {
        $this->assertSame('ok', K05Deadline::run(static fn() => JsJson::parse('"\\n"')));
        $this->assertSame('ok', K05Deadline::run(static fn() => JsJson::parse('"a\\u0041b\\ud83d\\ude00c\\"d"')));
        $this->assertSame("\n", JsJson::parse('"\\n"'));
    }

    public function testEveryBmpCodePointEncodesLikeJsonDecode(): void
    {
        $cps = [0, 0x41, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xe000, 0xfffe, 0xffff];
        for ($cp = 0; $cp < 0x800; $cp++) {
            $cps[] = $cp;
        }
        for ($cp = 0x800; $cp < 0x10000; $cp += 3) {
            $cps[] = $cp;
        }
        foreach ($cps as $cp) {
            if ($cp >= 0xd800 && $cp <= 0xdfff) {
                continue;
            }
            $hex = sprintf($cp % 2 === 0 ? '%04x' : '%04X', $cp);
            $text = '"x\\u' . $hex . 'Y"';
            $want = 'x' . json_decode('"\\u' . $hex . '"') . 'Y';
            $this->assertSame($want, JsJson::parse($text), $hex);
        }
    }

    public function testSurrogatePairsCombine(): void
    {
        $pairs = [[0xd800, 0xdc00], [0xd800, 0xdfff], [0xdbff, 0xdc00], [0xdbff, 0xdfff], [0xd83d, 0xde00]];
        for ($hi = 0xd800; $hi <= 0xdbff; $hi += 31) {
            for ($lo = 0xdc00; $lo <= 0xdfff; $lo += 29) {
                $pairs[] = [$hi, $lo];
            }
        }
        foreach ($pairs as [$hi, $lo]) {
            $esc = sprintf('\\u%04x\\u%04X', $hi, $lo);
            $this->assertSame('x' . json_decode('"' . $esc . '"') . 'Y', JsJson::parse('"x' . $esc . 'Y"'), $esc);
        }
        $this->assertSame("\xF0\x90\x80\x80", JsJson::parse('"\\ud800\\udc00"'));
        $this->assertSame("\xF4\x8F\xBF\xBF", JsJson::parse('"\\udbff\\udfff"'));
    }

    public function testLoneSurrogatesStayAlone(): void
    {
        $this->assertSame("\xED\xA0\x80", JsJson::parse('"\\ud800"'));
        $this->assertSame("\xED\xA0\x80A", JsJson::parse('"\\ud800\\u0041"'));
        $this->assertSame("\xED\xA0\x80\xEE\x80\x80", JsJson::parse('"\\ud800\\ue000"'));
        $this->assertSame("\xED\xA0\x80b", JsJson::parse('"\\ud800b"'));
        $this->assertSame("A\xED\xB0\x80", JsJson::parse('"\\u0041\\udc00"'));
        $this->assertSame("\xED\xB0\x80", JsJson::parse('"\\udc00"'));
        $this->assertSame("A\xED\xB0\x80", JsJson::parse('"\\u0041\\udc00"'));
        $this->assertSame("\xED\x9F\xBF\xED\xB0\x80", JsJson::parse('"\\ud7ff\\udc00"'));
    }

    public function testSiblingContainersDoNotAccumulateDepth(): void
    {
        $arr = JsJson::parse('[' . str_repeat('[],', 599) . '[]]');
        $this->assertCount(600, $arr);
        $obj = JsJson::parse('[' . str_repeat('{},', 599) . '{}]');
        $this->assertCount(600, $obj);
    }
}
