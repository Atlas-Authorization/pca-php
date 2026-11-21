<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsAuthor;
use Atlas\Pca\ActionsYamlLoad;
use Atlas\Pca\ActionsYamlError;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The authoring-file text loader (YAML 1.2 core schema and JSON, with source positions) against the reference corpus
 * test-data/ref-actions-yaml-load.json.gz. A syntax error is compared by class (the parser's wording is its own); a result where this
 * loader is deliberately STRICTER than the reference (see ActionsYamlLoad) must be a single "not YAML" refusal on a text that uses one of
 * the documented constructs, never a different successful value.
 */
final class RefActionsYamlLoadTest extends TestCase
{
    private const FILE = 'ref-actions-yaml-load.json.gz';
    private const SYNTAX = ['not YAML', 'YAML warning', 'not JSON'];
    /** A tag other than !!str / !!map / !!seq (and !!binary), a complex key, a bare carriage return (the Python and Ruby loaders' set). */
    private const STRICTER = '/(^|\s)!(?!!(str|map|seq)\b)\S|\? \[|\r(?!\n)|!!binary/';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function norm(Obj $r): string
    {
        $o = new Obj();
        foreach (['defs', 'notes', 'errors', 'locs', 'rules', 'ns'] as $k) {
            if ($r->has($k)) {
                $o->set($k, $r->get($k));
            }
        }
        return Base::canon($o);
    }

    private static function firstMessage(Obj $r): string
    {
        $errs = $r->get('errors');
        return is_array($errs) && isset($errs[0]) && $errs[0] instanceof Obj && is_string($errs[0]->get('message')) ? $errs[0]->get('message') : '';
    }

    #[DataProvider('provide')]
    public function testMatchesTheReference(string $file, string $fn, int $k): void
    {
        $bad = [];
        $n = 0;
        foreach (Base::cases($file, $fn, $k) as $c) {
            $n++;
            [$text, $fmt] = $c->get('args');
            $got = ActionsAuthor::loadActionsText($text, $fmt);
            $exp = $c->get('out');
            $e0 = self::firstMessage($exp);
            $gotErrors = $got->get('errors');
            $isSyntax = false;
            foreach (self::SYNTAX as $p) {
                $isSyntax = $isSyntax || str_starts_with($e0, $p);
            }
            if ($isSyntax) {
                $ok = count($gotErrors) === 1 && $got->get('defs') === [] && str_starts_with(self::firstMessage($got), $fmt === 'yaml' ? 'not YAML' : 'not JSON');
            } elseif (self::norm($got) === self::norm($exp)) {
                $ok = true;
            } else {
                $ok = preg_match(self::STRICTER, $text) === 1 && count($gotErrors) === 1 && str_starts_with(self::firstMessage($got), 'not YAML') && $got->get('defs') === [];
            }
            if (!$ok) {
                $bad[] = [(string)$c->get('name'), substr($text, 0, 80), substr(self::norm($got), 0, 300), substr(self::norm($exp), 0, 300)];
            }
        }
        self::assertGreaterThan(0, $n);
        self::assertSame([], array_slice($bad, 0, 12), count($bad) . " of $n differ");
    }

    public function testCoreSchemaScalars(): void
    {
        $v = static fn(string $t): mixed => ActionsYamlLoad::toValue(ActionsYamlLoad::parseDocument("k: $t\n"))->get('k');
        self::assertNull($v('~'));
        self::assertNull($v('NULL'));
        self::assertSame('nULL', $v('nULL'));
        self::assertTrue($v('True'));
        self::assertSame('yes', $v('yes'));
        self::assertSame('2001-12-14', $v('2001-12-14'));
        self::assertSame('1_000', $v('1_000'));
        self::assertSame('0b11', $v('0b11'));
        self::assertSame('10', $v('010')->lexeme);
        self::assertSame('8', $v('0o10')->lexeme);
        self::assertSame('31', $v('0x1F')->lexeme);
        self::assertSame('-0', $v('-0')->lexeme);
        self::assertSame('12', $v('+12')->lexeme);
        self::assertSame('1000', $v('1e3')->lexeme);
        self::assertSame('0.0015', $v('1.5E-3')->lexeme);
        self::assertSame('0', $v('0.')->lexeme);
        self::assertSame('0.5', $v('.5')->lexeme);
        self::assertSame(INF, $v('.inf'));
        self::assertSame(-INF, $v('-.INF'));
        self::assertNan($v('.NaN'));
        self::assertSame(INF, $v('1e400'));
        self::assertInstanceOf(Num::class, $v('12345678901234567890'));
        self::assertSame('7', $v('!!str 7'));
    }

    public function testBlockScalarsAndFolding(): void
    {
        $y = "a: |\n  one\n   two\n\n  three\nb: >-\n  x\n  y\n\n  z\n   more\n  tail\nc: |+\n  k\n\nd: |-\n  e\ne: \"p\n  q\n\n  r \\\n  s\"\nf: 'it''s\n  ok'\ng: plain\n  folded\n\n  text\n";
        $o = ActionsYamlLoad::toValue(ActionsYamlLoad::parseDocument($y));
        self::assertSame("one\n two\n\nthree\n", $o->get('a'));
        self::assertSame("x y\nz\n more\ntail", $o->get('b'));
        self::assertSame("k\n\n", $o->get('c'));
        self::assertSame('e', $o->get('d'));
        self::assertSame("p q\nr s", $o->get('e'));
        self::assertSame("it's ok", $o->get('f'));
        self::assertSame("plain folded\ntext", $o->get('g'));
    }

    public function testAnchorsAndExplicitKeysAreAccepted(): void
    {
        $o = ActionsYamlLoad::toValue(ActionsYamlLoad::parseDocument("a: &x 1\n? k\n: v\nm: !!map {b: c}\n"));
        self::assertSame('1', $o->get('a')->lexeme);
        self::assertSame('v', $o->get('k'));
    }

    public function testPositionsAndRefusals(): void
    {
        $root = ActionsYamlLoad::parseDocument("ns: acme\nactions:\n  - verb: a.b\n    params:\n      id: text\n      \"q\": text\n");
        self::assertSame([[3, 5, [['id', 5, 7], ['q', 6, 7]]]], ActionsYamlLoad::positionsOf($root));
        foreach (["a: *x\n", "a: !!int 1\n", "a: 1\na: 2\n", "a: b\n---\nc: d\n", "a: [1, 2\n", "a: \"x\n", "a: 1\rb: 2\n", "a: {[x]: 1}\n", "a: !foo 1\n"] as $bad) {
            try {
                ActionsYamlLoad::parseDocument($bad);
                self::fail('accepted: ' . json_encode($bad));
            } catch (ActionsYamlError) {
                self::addToAssertionCount(1);
            }
        }
    }
}
