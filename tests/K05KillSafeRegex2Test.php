<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\SafeRegex;
use Atlas\Pca\SafeRegexParser;
use Atlas\Pca\SafeRegexRefuse;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for SafeRegex (round 2): the source guard's own verdict, the emitted program, the parser AST. */
final class K05KillSafeRegex2Test extends TestCase
{
    /**
     * isSafeRegexSource with the compiled-program cache seeded to "compiles": isolates the backtracking-cost guard from
     * the compile backstop, so a guard refusal is visible even where the parser would refuse the source too.
     */
    private static function guardOnly(string $src): bool
    {
        $r = new \ReflectionProperty(SafeRegex::class, 'cache');
        $saved = $r->getValue();
        $seeded = $saved;
        $seeded['k' . $src] = [[SafeRegex::OP_MATCH, 0, 0, null, false]];
        $r->setValue(null, $seeded);
        try {
            return SafeRegex::isSafeRegexSource($src);
        } finally {
            $r->setValue(null, $saved);
        }
    }

    public function testTheGuardRefusesBackreferencesAndATrailingBackslash(): void
    {
        $this->assertFalse(self::guardOnly('a\\'));
        $this->assertFalse(self::guardOnly('\\1'));
        $this->assertFalse(self::guardOnly('\\9'));
        $this->assertFalse(self::guardOnly('\\k'));
        $this->assertTrue(self::guardOnly('\\0'), 'control: \\0 is not a backreference');
        $this->assertTrue(self::guardOnly('\\j'), 'control');
        $this->assertTrue(self::guardOnly('\\l'), 'control');
    }

    public function testTheGuardScansClassesAndNonCapturingGroups(): void
    {
        $this->assertFalse(self::guardOnly('[\\]'), 'the backslash escapes the ], so the class is unterminated');
        $this->assertFalse(self::guardOnly('[ab'));
        $this->assertTrue(self::guardOnly('[ab]'), 'control');
        $this->assertFalse(self::guardOnly('(?:*)'), 'the (?: prefix is not an atom to repeat');
        $this->assertTrue(self::guardOnly('(?:a*)'), 'control');
    }

    public function testAnAlternationBeforeANestedGroupStillMakesTheOuterGroupUnrepeatable(): void
    {
        $this->assertFalse(SafeRegex::isSafeRegexSource('(a|(b))*'));
        $this->assertTrue(SafeRegex::isSafeRegexSource('(a|(b))c*'), 'control');
    }

    public function testTheBoundedRepeatCapIsSixtyFour(): void
    {
        $this->assertFalse(self::guardOnly('a{65}'));
        $this->assertFalse(self::guardOnly('a{0,65}'));
        $this->assertTrue(SafeRegex::isSafeRegexSource('a{64}'));
        $this->assertTrue(SafeRegex::isSafeRegexSource('a{1,64}'));
    }

    /** Number('9' x 400) is Infinity in JS and (float) gives INF here: a bound that large reads as unbounded (8 bits). */
    public function testAnOverflowingBoundReadsAsUnbounded(): void
    {
        $nines = str_repeat('9', 400);
        $this->assertTrue(self::guardOnly('a{' . $nines . '}'));
        $this->assertTrue(self::guardOnly('a{1,' . $nines . '}'));
        $this->assertFalse(SafeRegex::isSafeRegexSource('a{' . $nines . '}'), 'the parser still refuses it');
    }

    public function testAnExactRepeatCostsNoBits(): void
    {
        $this->assertTrue(SafeRegex::isSafeRegexSource(str_repeat('a?', 22) . 'a{3}'));
        $this->assertFalse(SafeRegex::isSafeRegexSource(str_repeat('a?', 23)), 'control: 23 bits is over budget');
    }

    public function testTheEmittedProgramIsExact(): void
    {
        $a = [SafeRegex::OP_SET, 0, 0, [[97, 97]], false];
        $b = [SafeRegex::OP_SET, 0, 0, [[98, 98]], false];
        $match = [SafeRegex::OP_MATCH, 0, 0, null, false];
        $this->assertSame([$a, $match], SafeRegex::compile('a'));
        $this->assertSame([[SafeRegex::OP_BOL, 0, 0, null, false], [SafeRegex::OP_EOL, 0, 0, null, false], $match],
            SafeRegex::compile('^$'));
        $this->assertSame([[SafeRegex::OP_SPLIT, 1, 3, null, false], $a, [SafeRegex::OP_JMP, 4, 0, null, false], $b, $match],
            SafeRegex::compile('a|b'));
        $this->assertSame([[SafeRegex::OP_SPLIT, 1, 3, null, false], $a, [SafeRegex::OP_JMP, 0, 0, null, false], $match],
            SafeRegex::compile('a*'));
        $this->assertSame([[SafeRegex::OP_SPLIT, 1, 2, null, false], $a, $match], SafeRegex::compile('a?'));
        $this->assertSame([[SafeRegex::OP_SPLIT, 1, 4, null, false], $a, [SafeRegex::OP_SPLIT, 3, 4, null, false], $a, $match],
            SafeRegex::compile('a{0,2}'));
    }

    private static function emit(array $node, array &$prog): void
    {
        (new \ReflectionMethod(SafeRegex::class, 'emit'))->invokeArgs(null, [$node, &$prog]);
    }

    /** emit refuses only once the program is OVER the instruction cap; exactly at the cap is still fine. */
    public function testEmitAllowsAProgramExactlyAtTheCap(): void
    {
        $set = [SafeRegex::OP_SET, 0, 0, [[97, 97]], false];
        $prog = array_fill(0, SafeRegex::MAX_NFA_INSTRUCTIONS, $set);
        self::emit(['cat', []], $prog);
        $this->assertCount(SafeRegex::MAX_NFA_INSTRUCTIONS, $prog);

        $prog = array_fill(0, SafeRegex::MAX_NFA_INSTRUCTIONS - 1, $set);
        self::emit(['rep', ['set', [[97, 97]], false], 1, 1], $prog);
        $this->assertCount(SafeRegex::MAX_NFA_INSTRUCTIONS, $prog);

        try {
            self::emit(['rep', ['set', [[97, 97]], false], 1, 1], $prog);
            $this->fail('emitted past the cap');
        } catch (SafeRegexRefuse $e) {
            $this->assertSame('pattern too large', $e->getMessage());
        }
    }

    private static function parse(string $src): array
    {
        return (new SafeRegexParser(SafeRegex::units($src)))->parse();
    }

    public function testTheParserRepeatBoundsAreIntegers(): void
    {
        $a = ['set', [[97, 97]], false];
        $this->assertSame(['cat', [['rep', $a, 0, null]]], self::parse('a*'));
        $this->assertSame(['cat', [['rep', $a, 3, 3]]], self::parse('a{3}'));
        $this->assertSame(['cat', [['rep', $a, 2, 5]]], self::parse('a{2,5}'));
        $this->assertSame(['cat', [['rep', $a, 2, null]]], self::parse('a{2,}'));
    }

    public function testIsAlnumIncludesZero(): void
    {
        $m = new \ReflectionMethod(SafeRegexParser::class, 'isAlnum');
        $this->assertTrue($m->invoke(null, 0x30));
        $this->assertFalse($m->invoke(null, 0x2F));
    }
}
