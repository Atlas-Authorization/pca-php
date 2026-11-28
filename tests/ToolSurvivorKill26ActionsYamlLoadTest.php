<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsYamlError;
use Atlas\Pca\ActionsYamlLoad as L;
use Atlas\Pca\Num;
use PHPUnit\Framework\TestCase;

/** The authoring-file YAML loader: refusal texts and positions, the nesting limit, tags on collections, core-schema numbers, positions. */
final class ToolSurvivorKill26ActionsYamlLoadTest extends TestCase
{
    private static function refusal(string $text, bool $strict = true): ?ActionsYamlError
    {
        try {
            L::parseDocument($text, $strict);
        } catch (ActionsYamlError $e) {
            return $e;
        }
        return null;
    }

    private static function msg(string $text, bool $strict = true): string
    {
        $e = self::refusal($text, $strict);
        return $e === null ? 'accepted' : $e->getMessage();
    }

    private static function lex(string $t): string
    {
        $v = L::resolve($t);
        self::assertInstanceOf(Num::class, $v);
        return $v->lexeme;
    }

    /** A bare carriage return refuses before parsing, with its message and the default position 1:1. */
    public function testBareCarriageReturn(): void
    {
        $e = self::refusal("a: 1\rb: 2\n");
        self::assertNotNull($e);
        self::assertSame('bare carriage return is not accepted as a line break', $e->getMessage());
        self::assertSame(1, $e->yamlLine);
        self::assertSame(1, $e->yamlColumn);
    }

    /** A libyaml syntax error carries libyaml's problem text and its 1-based line and column. */
    public function testSyntaxErrorPosition(): void
    {
        $e = self::refusal("a: b\nc: @d\n");
        self::assertNotNull($e);
        self::assertSame('found character that cannot start any token', $e->getMessage());
        self::assertSame(2, $e->yamlLine);
        self::assertSame(4, $e->yamlColumn);
    }

    /** An alias refuses with its own reason. */
    public function testAliasRefusal(): void
    {
        $e = self::refusal("a: &x 1\nb: *x\n");
        self::assertNotNull($e);
        self::assertSame('Alias resolution is disabled', $e->getMessage());
    }

    /** An unsupported tag on a flow sequence or a flow mapping refuses like one on a scalar; !!seq and !!map are accepted. */
    public function testCollectionTags(): void
    {
        self::assertSame('Unresolved or unsupported tag: !foo', self::msg("a: !foo [1]\n"));
        self::assertSame('Unresolved or unsupported tag: !foo', self::msg("a: !foo {b: 1}\n"));
        self::assertNull(self::refusal("a: !!seq [1]\nb: !!map {c: 1}\n"), 'control');
    }

    /** Nesting is accepted to exactly 1000 levels and refused past it, through sequences, mapping values and mapping keys. */
    public function testNestingLimit(): void
    {
        $seq = static fn(int $n): string => str_repeat('[', $n) . 'x' . str_repeat(']', $n);
        $val = static fn(int $n): string => str_repeat('{a: ', $n) . 'x' . str_repeat('}', $n);
        $key = static fn(int $n): string => str_repeat('{? ', $n) . 'x' . str_repeat(' : 1}', $n);
        self::assertNull(self::refusal($seq(1000)));
        self::assertSame('nesting is too deep', self::msg($seq(1001)));
        self::assertNull(self::refusal($val(1000)));
        self::assertSame('nesting is too deep', self::msg($val(1001)));
        self::assertNull(self::refusal($key(1000), false));
        self::assertSame('nesting is too deep', self::msg($key(1001), false));
    }

    /** A second byte order mark after the first is libyaml's own: the first is stripped, so the text still starts at column 1. */
    public function testByteOrderMark(): void
    {
        self::assertSame([[1, 1, []]], L::positionsOf(L::parseDocument("\xEF\xBB\xBF\xEF\xBB\xBFk: v\n")));
    }

    /** Positions: only a scalar `actions` key selects the entries and only a scalar `params` key the params; without them the root is the entry. */
    public function testPositionsKeys(): void
    {
        self::assertSame([[1, 1, []]], L::positionsOf(L::parseDocument("x: [a]\n")));
        self::assertSame([[1, 1, []]], L::positionsOf(L::parseDocument("verb: a\nx: {b: 1}\n")));
    }

    /** jsKey and resolve are public; jsKey is JavaScript's String() of a resolved scalar. */
    public function testPublicHelpers(): void
    {
        self::assertSame('a', L::jsKey('a'));
        self::assertSame('true', L::jsKey(true));
        self::assertSame('null', L::jsKey(null));
        self::assertNull(L::resolve('~'));
    }

    /** Decimal integers: exact up to 2^53, the binary64 form beyond (also past 16 digits), the sign kept. */
    public function testDecimalIntegers(): void
    {
        self::assertSame('-5', self::lex('-5'));
        self::assertSame('9007199254740992', self::lex('9007199254740992'));
        self::assertSame('9007199254740992', self::lex('9007199254740993'));
        self::assertSame('10000000000000000', self::lex('10000000000000001'));
        self::assertSame('100000000000000000', self::lex('99999999999999999'));
    }

    /** Floats: negative zero only for a zero value, integral values as plain digits, large ones in JavaScript form. */
    public function testFloats(): void
    {
        self::assertSame('-1.5', self::lex('-1.5'));
        self::assertSame('-0', self::lex('-0.0'));
        self::assertSame('1000000000000000', self::lex('1e15'));
        self::assertSame('100000000000000000000', self::lex('1e20'));
    }

    /** 0o / 0x integers: exact up to 2^53, the binary64 form beyond (an int past 2^53 and a float past PHP_INT_MAX), with no deprecation. */
    public function testRadixIntegers(): void
    {
        $errs = [];
        set_error_handler(static function (int $no, string $msg) use (&$errs): bool {
            $errs[] = $msg;
            return true;
        });
        try {
            self::assertSame('15', self::lex('0o17'));
            self::assertSame('31', self::lex('0x1F'));
        } finally {
            restore_error_handler();
        }
        self::assertSame([], $errs);
        self::assertSame('9007199254740992', self::lex('0x20000000000001'));
        self::assertSame('18446744073709552000', self::lex('0x10000000000000000'));
    }
}
