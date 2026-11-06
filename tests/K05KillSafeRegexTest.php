<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\SafeRegex;
use Atlas\Pca\SafeRegexBudget;
use Atlas\Pca\SafeRegexParser;
use Atlas\Pca\SafeRegexRefuse;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for SafeRegex: the public matcher / charge entry points and the budget's defaults. */
final class K05KillSafeRegexTest extends TestCase
{
    public function testPublicRunAndChargeAndBudgetDefaults(): void
    {
        $prog = SafeRegex::compile('ab');
        $this->assertNotNull($prog);
        $this->assertTrue(SafeRegex::run($prog, SafeRegex::units('ab')));
        $this->assertFalse(SafeRegex::run($prog, SafeRegex::units('a')));
        $this->assertTrue(SafeRegex::charge('a', 0));
        $b = new SafeRegexBudget();
        $this->assertTrue($b->isDocument);
        for ($i = 0; $i < SafeRegex::MAX_REGEX_EVALUATIONS_PER_DOCUMENT; $i++) {
            $this->assertTrue($b->charge('a', 0), "evaluation $i");
        }
        $this->assertFalse($b->charge('a', 0), 'scale 1: the 65th evaluation is over the document budget');
    }

    public function testTheSafeSourceCheckFailsClosedWhenTheCacheIsCorrupt(): void
    {
        $this->assertTrue(SafeRegex::isSafeRegexSource('zq'), 'control');
        $r = new \ReflectionProperty(SafeRegex::class, 'cache');
        $saved = $r->getValue();
        $bad = $saved;
        $bad['kzq'] = 'not a program'; // compileCached's ?array return type throws inside isSafeRegexSourceInner
        $r->setValue(null, $bad);
        try {
            $this->assertFalse(SafeRegex::isSafeRegexSource('zq'));
        } finally {
            $r->setValue(null, $saved);
        }
    }

    public function testEmitRefusesAnUnknownNode(): void
    {
        $prog = [];
        try {
            (new \ReflectionMethod(SafeRegex::class, 'emit'))->invokeArgs(null, [['bogus'], &$prog]);
            $this->fail('emitted an unknown node');
        } catch (SafeRegexRefuse $e) {
            $this->assertSame('unknown node', $e->getMessage());
        }
    }

    private static function parseRefusal(string $src): string
    {
        try {
            (new SafeRegexParser(SafeRegex::units($src)))->parse();
        } catch (SafeRegexRefuse $e) {
            return $e->getMessage();
        }
        return '(parsed)';
    }

    public function testParserRefusalMessages(): void
    {
        $this->assertSame('(parsed)', self::parseRefusal('ab'));
        $this->assertSame('nothing to repeat', self::parseRefusal('*'));
        $this->assertSame('trailing backslash', self::parseRefusal('\\'));
        $this->assertSame('word-boundary assertions are not supported', self::parseRefusal('\\b'));
    }
}
