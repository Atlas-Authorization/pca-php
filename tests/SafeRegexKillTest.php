<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\SafeRegex;
use Atlas\Pca\SafeRegexBudget;
use PHPUnit\Framework\TestCase;

/** Unit-level kills for SafeRegex.php: UTF-16 views, brace scanning, guard cost boundary, budgets, the compile cache. */
final class SafeRegexKillTest extends TestCase
{
    private static function longClass(int $n): string
    {
        return '[' . str_repeat('a', $n - 2) . ']';
    }

    public function testUnitsDecodeEveryLengthAndBoundary(): void
    {
        $cases = [
            ["\x00", [0]], ["\x7F", [0x7F]], ["\xC2\x80", [0x80]], ["\xDF\xBF", [0x7FF]], ["\xE0\xA0\x80", [0x800]],
            ["\xEF\xBF\xBF", [0xFFFF]], ["\xF0\x90\x80\x80", [0xD800, 0xDC00]], ["\xF4\x8F\xBF\xBF", [0xDBFF, 0xDFFF]],
            ["\xF7\xBF\xBF\xBF", [0xDFBF, 0xDFFF]], ["\xF0\x9F\x98\x80", [0xD83D, 0xDE00]],
            ["\xED\xA0\xBD\xED\xB8\x80", [0xD83D, 0xDE00]],           // WTF-8 lone surrogates stay single units
            ["\xE2\x82\xAC", [0x20AC]], ["\xC3\xA9", [0xE9]],
            // malformed input is U+FFFD per bad byte and decoding resumes at the next byte
            ["\x80", [0xFFFD]], ["\xBF", [0xFFFD]], ["\xC0\x80", [0xFFFD, 0xFFFD]], ["\xC1\xBF", [0xFFFD, 0xFFFD]],
            ["\xC2", [0xFFFD]], ["\xC2A", [0xFFFD, 0x41]], ["\xE2\x82", [0xFFFD, 0xFFFD]], ["\xE2A\x82", [0xFFFD, 0x41, 0xFFFD]],
            ["\xF0\x9F\x98", [0xFFFD, 0xFFFD, 0xFFFD]], ["\xF8\x88\x80\x80\x80", [0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD, 0xFFFD]],
            ["\xFF", [0xFFFD]], ["\xE0\xC0\x80", [0xFFFD, 0xFFFD, 0xFFFD]], ["a\xC2", [0x61, 0xFFFD]],
            ["\xC2\x80\xC2", [0x80, 0xFFFD]], ["\xEF\xBF", [0xFFFD, 0xFFFD]],
        ];
        foreach ($cases as [$s, $want]) {
            $this->assertSame($want, SafeRegex::units($s), bin2hex($s));
        }
        $this->assertSame([], SafeRegex::units(''));
    }

    public function testUtf16Len(): void
    {
        $this->assertSame(0, SafeRegex::utf16Len(''));
        $this->assertSame(2, SafeRegex::utf16Len("a\xC3\xA9"));
        $this->assertSame(2, SafeRegex::utf16Len("\xF0\x9F\x98\x80"));
        $this->assertSame(1, SafeRegex::utf16Len("\xED\xA0\xBD"));
        $this->assertSame(5, SafeRegex::utf16Len("ab\xE2\x82\xAC\xF0\x9F\x98\x80"));
    }

    public function testStartsWithUnitsIsOverCodeUnits(): void
    {
        $this->assertTrue(SafeRegex::startsWithUnits('abc', 'ab'));
        $this->assertTrue(SafeRegex::startsWithUnits('abc', ''));
        $this->assertFalse(SafeRegex::startsWithUnits('ab', 'abc'));
        $this->assertFalse(SafeRegex::startsWithUnits('abc', 'abd'));
        // not a byte prefix, but a code-unit prefix / equal
        $astral = "\xF0\x9F\x98\x80";
        $this->assertTrue(SafeRegex::startsWithUnits($astral, "\xED\xA0\xBD"));
        $this->assertTrue(SafeRegex::startsWithUnits("\xED\xA0\xBD\xED\xB8\x80", $astral));
        $this->assertTrue(SafeRegex::startsWithUnits($astral, "\xED\xA0\xBD\xED\xB8\x80"));
        $this->assertFalse(SafeRegex::startsWithUnits("\xED\xA0\xBD", $astral));
        $this->assertFalse(SafeRegex::startsWithUnits($astral, "\xED\xA0\xBE"));
    }

    /** the guard: brace forms, digit limits, lazy modifier and the 22-bit cost budget (boundary on both sides) */
    public function testGuardBraceAndCostBoundaries(): void
    {
        $safe = fn(string $s) => SafeRegex::isSafeRegexSource($s);
        $this->assertTrue($safe('a{3}'));
        $this->assertTrue($safe('a{3,}'));
        $this->assertTrue($safe('a{3,5}'));
        $this->assertFalse($safe('a{5,3}'));
        $this->assertFalse($safe('a{,3}'));
        $this->assertFalse($safe('a{3'));
        $this->assertFalse($safe('a{3,x}'));
        $this->assertFalse($safe('{3}'));
        $this->assertTrue($safe('a{64}'));
        $this->assertFalse($safe('a{65}'));
        $this->assertFalse($safe('a{1,65}'));
        $this->assertTrue($safe('a{64,}'));
        // cost: each unbounded quantifier 8 bits, `|` 1 bit, `x?` 1 bit, `x{1,3}` 2 bits; limit 22
        $this->assertTrue($safe('a*b*' . str_repeat('|', 6)));      // 16 + 6 = 22
        $this->assertFalse($safe('a*b*' . str_repeat('|', 7)));     // 23
        $this->assertTrue($safe('a*b*c{3}?|||||| '));               // lazy `{3}?` costs nothing: 22
        $this->assertFalse($safe('a*b*c{3}?||||||| '));
        $this->assertTrue($safe('a*b*c{1,3}||||'));                 // 16 + 2 + 4 = 22
        $this->assertFalse($safe('a*b*c{1,3}|||||'));
        $this->assertTrue($safe('a*b*c?' . str_repeat('|', 5)));    // 16 + 1 + 5 = 22
        $this->assertFalse($safe('a*b*c?' . str_repeat('|', 6)));
        // a `?` right after a quantifier is lazy (no cost)
        $this->assertTrue($safe('a*?b*?' . str_repeat('|', 6)));
        // references, lookaround, nesting
        $this->assertFalse($safe('(a)\\1'));
        $this->assertFalse($safe('\\k<n>'));
        $this->assertFalse($safe('(?=a)'));
        $this->assertTrue($safe('(?:a)b'));
        $this->assertFalse($safe('(a*)*'));
        $this->assertFalse($safe('(a|b)*'));
        $this->assertTrue($safe('(a|b)'));
        $this->assertFalse($safe('(a'));
        $this->assertFalse($safe('a)'));
        $this->assertFalse($safe('*a'));
        $this->assertFalse($safe('a\\'));
        $this->assertFalse($safe('[a'));
        $this->assertTrue($safe('[a\\]]'));
        $this->assertFalse($safe('\\1'));
        $this->assertTrue($safe('\\0'));
        $this->assertFalse($safe('\\9'));
        $this->assertFalse($safe('a**'));
    }

    public function testCompileCacheIsBoundedAndKeyed(): void
    {
        $r = new \ReflectionProperty(SafeRegex::class, 'cache');
        $r->setValue(null, []);
        for ($i = 0; $i < 1024; $i++) {
            SafeRegex::compileCached('x' . $i);
        }
        $this->assertCount(1024, $r->getValue());
        SafeRegex::compileCached('x0'); // a hit: no growth, nothing evicted
        $this->assertCount(1024, $r->getValue());
        SafeRegex::compileCached('fresh');
        $this->assertCount(1024, $r->getValue());
        $keys = array_keys($r->getValue());
        $this->assertNotContains('kx0', $keys); // the oldest entry went
        $this->assertContains('kx1', $keys);
        $this->assertContains('kfresh', $keys);
        // the key is the source itself: two sources never share a program
        $this->assertSame(2, SafeRegex::progLen('a'));
        $this->assertSame(3, SafeRegex::progLen('ab'));
        $this->assertNull(SafeRegex::progLen('(?='));
        $r->setValue(null, []);
    }

    public function testBudgetDefaultsAndScopes(): void
    {
        $b = new SafeRegexBudget();
        $this->assertTrue($b->isDocument);
        for ($i = 0; $i < 64; $i++) {
            $this->assertTrue($b->charge('a', 0), "eval $i");
        }
        $this->assertFalse($b->charge('a', 0));
        $this->assertSame(1, $b->refusals);
        $this->assertNull($b->parentBudget());
        $req = SafeRegex::requestBudget();
        $this->assertFalse($req->isDocument);
        for ($i = 0; $i < 256; $i++) {
            $this->assertTrue($req->charge('a', 0));
        }
        $this->assertFalse($req->charge('a', 0));
        // a document under a request budget draws on both
        $parent = new SafeRegexBudget(2, null, false);
        $doc = new SafeRegexBudget(1, $parent, true);
        $this->assertSame($parent, $doc->parentBudget());
        for ($i = 0; $i < 64; $i++) {
            $this->assertTrue($doc->charge('a', 0));
        }
        $this->assertFalse($doc->charge('a', 0));
        $this->assertSame(64, $parent->evaluations);
        // scale multiplies all three limits
        $s = new SafeRegexBudget(2, null, true);
        $this->assertTrue($s->charge('a', 3_000_000));   // 6M steps: over one document, under two
        $s1 = new SafeRegexBudget(1, null, true);
        $this->assertFalse($s1->charge('a', 3_000_000));
        $this->assertFalse((new SafeRegexBudget(1, null, true))->charge(self::longClass(8193), 0));
        $this->assertTrue((new SafeRegexBudget(2, null, true))->charge(self::longClass(8193), 0));
        $this->assertFalse((new SafeRegexBudget(2, null, true))->charge(self::longClass(16385), 0));
        // a refusal poisons the budget: a later cheap pattern is refused too
        $p = new SafeRegexBudget();
        $this->assertFalse($p->charge('a', 6_000_000));
        $this->assertFalse($p->charge('a', 0));
        // an uncompilable pattern is refused and counted, not charged
        $q = new SafeRegexBudget();
        $this->assertFalse($q->charge('(?=a)', 0));
        $this->assertSame(1, $q->refusals);
        $this->assertSame(0, $q->evaluations);
        $this->assertTrue($q->charge('a', 0));
    }

    public function testWithBudgetAndGlobalScope(): void
    {
        $this->assertNull(SafeRegex::currentBudget());
        $this->assertSame(0, SafeRegex::regexRefusals());
        // outside any scope: a fresh single-use document budget of scale 1
        $this->assertFalse(SafeRegex::charge('a', 3_000_000));
        $this->assertTrue(SafeRegex::charge('a', 10));
        $seen = SafeRegex::withBudget(function () {
            $outer = SafeRegex::currentBudget();
            $this->assertNotNull($outer);
            $this->assertTrue($outer->isDocument);
            // joins the open document scope
            SafeRegex::withBudget(fn() => $this->assertSame($outer, SafeRegex::currentBudget()));
            $this->assertFalse(SafeRegex::charge('(?=a)', 0));
            $this->assertSame(1, SafeRegex::regexRefusals());
            $this->assertTrue(SafeRegex::charge('a', 0));
            $this->assertSame(1, $outer->evaluations);
            return 'done';
        });
        $this->assertSame('done', $seen);
        $this->assertNull(SafeRegex::currentBudget());
        // under a request budget a fresh document is opened, chained to it, and the scope is restored afterwards
        $req = SafeRegex::requestBudget();
        $req->run(function () use ($req) {
            $this->assertSame($req, SafeRegex::currentBudget());
            SafeRegex::withBudget(function () use ($req) {
                $doc = SafeRegex::currentBudget();
                $this->assertNotSame($req, $doc);
                $this->assertSame($req, $doc->parentBudget());
                $this->assertTrue($doc->isDocument);
                $this->assertTrue(SafeRegex::charge('a', 0));
            });
            $this->assertSame($req, SafeRegex::currentBudget());
            $this->assertSame(1, $req->evaluations);
        });
        $explicit = new SafeRegexBudget();
        SafeRegex::withBudget(fn() => $this->assertSame($explicit, SafeRegex::currentBudget()), $explicit);
        $this->assertNull(SafeRegex::currentBudget());
        // restored even when the body throws
        try {
            SafeRegex::withBudget(function () {
                throw new \RuntimeException('x');
            });
        } catch (\RuntimeException) {
        }
        $this->assertNull(SafeRegex::currentBudget());
    }

    public function testRunBoundariesAndRefusals(): void
    {
        $this->assertNull(SafeRegex::fullMatch('a', str_repeat('a', 2_000_000)));  // 2 * 2000001 > 2M steps
        $this->assertTrue(SafeRegex::fullMatch('a*', str_repeat('a', 500)));
        $this->assertFalse(SafeRegex::fullMatch('a', 'b'));
        $this->assertNull(SafeRegex::fullMatch('(?=a)', 'a'));
        $this->assertNull(SafeRegex::compile(5));
        $this->assertNull(SafeRegex::compile('a{65}'));
        $this->assertNull(SafeRegex::compile('a{5,3}'));
        $this->assertNull(SafeRegex::compile('^*'));
        $this->assertNull(SafeRegex::compile('$*'));
        $this->assertNotNull(SafeRegex::compile('a{64}'));
        // program size cap: a{64} nested twice via classes is 64*64 = 4096 + match > cap
        $this->assertNull(SafeRegex::compile('(?:a{64}){64}'));
        $this->assertNotNull(SafeRegex::compile('(?:a{16}){64}'));
    }

    public function testCharsetNormalizeAndComplement(): void
    {
        $this->assertSame([[0, 5]], \Atlas\Pca\SafeRegexParser::normalize([[3, 5], [0, 2]]));        // adjacent ranges merge
        $this->assertSame([[0, 2], [4, 5]], \Atlas\Pca\SafeRegexParser::normalize([[4, 5], [0, 2]]));
        $this->assertSame([[0, 9]], \Atlas\Pca\SafeRegexParser::normalize([[0, 9], [2, 3]]));
        $this->assertSame([[0xFFFF, 0xFFFF]], \Atlas\Pca\SafeRegexParser::complement([[0, 0xFFFE]]));
        $this->assertSame([], \Atlas\Pca\SafeRegexParser::complement([[0, 0xFFFF]]));
        $this->assertSame([[0, 0xFFFF]], \Atlas\Pca\SafeRegexParser::complement([]));
        $this->assertSame([[0, 0], [2, 0xFFFF]], \Atlas\Pca\SafeRegexParser::complement([[1, 1]]));
        $this->assertSame([[0, 0xFFFE]], \Atlas\Pca\SafeRegexParser::complement([[0xFFFF, 0xFFFF]]));
    }
}
