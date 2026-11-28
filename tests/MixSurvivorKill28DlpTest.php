<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Dlp.php';

use Atlas\Pca\Dlp;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in Dlp: the reference TypeErrors, class specificity and tie-break, and verb SameValueZero matching. */
final class MixSurvivorKill28DlpTest extends TestCase
{
    private static function ctx(mixed $resource, mixed $verb = 'send', mixed $taint = 3): Obj
    {
        return Obj::of(['verb' => $verb, 'resource' => $resource, 'taint' => $taint]);
    }

    private static function refuses(string $msg, Obj $policy, Obj $ctx): void
    {
        try {
            Dlp::evaluateDlp($policy, $ctx);
            self::fail('expected a TypeError');
        } catch (\TypeError $e) {
            self::assertSame($msg, $e->getMessage());
        }
    }

    /** Does a class with these `verbs` apply to `$verb`? (it does exactly when the result names it) */
    private static function verbApplies(array $verbs, mixed $verb): bool
    {
        $p = Obj::of(['classes' => [Obj::of(['name' => 'c', 'resource' => '*', 'verbs' => $verbs, 'maxTaintForAuto' => 0])]]);
        $r = Dlp::evaluateDlp($p, self::ctx('r', $verb, 5));
        return $r->get('outcome') === 'step_up' && $r->get('class') === 'c';
    }

    /** A non-string pattern, a non-string resource under a prefix, and a verbs value that is neither list nor string are the reference's TypeErrors. */
    public function testReferenceTypeErrors(): void
    {
        self::refuses('pattern.endsWith is not a function', Obj::of(['classes' => [Obj::of(['resource' => 5])]]), self::ctx('r'));
        self::refuses('resource.startsWith is not a function', Obj::of(['classes' => [Obj::of(['resource' => 'a*'])]]), self::ctx(5));
        self::refuses('c.verbs.includes is not a function', Obj::of(['classes' => [Obj::of(['resource' => '*', 'verbs' => 5])]]), self::ctx('r'));
    }

    /** A matching prefix beats `*` even when `*` is stricter. */
    public function testPrefixBeatsWildcard(): void
    {
        $p = Obj::of(['classes' => [Obj::of(['name' => 'any', 'resource' => '*', 'maxTaintForAuto' => 0]),
            Obj::of(['name' => 'pre', 'resource' => 'a*', 'maxTaintForAuto' => 5])]]);
        $r = Dlp::evaluateDlp($p, self::ctx('ab'));
        self::assertSame(['allow', 'pre'], [$r->get('outcome'), $r->get('class')]);
    }

    /** A prefix whose stem counts zero UTF-16 units scores like `*`, so the stricter of the two wins. */
    public function testZeroLengthStemTiesWithWildcard(): void
    {
        $p = Obj::of(['classes' => [Obj::of(['name' => 'any', 'resource' => '*', 'maxTaintForAuto' => 0]),
            Obj::of(['name' => 'pre', 'resource' => "\xA9*", 'maxTaintForAuto' => 5])]]);
        $r = Dlp::evaluateDlp($p, self::ctx("\xA9x"));
        self::assertSame(['step_up', 'any'], [$r->get('outcome'), $r->get('class')]);
    }

    /** Of equally specific, equally strict classes the first listed wins. */
    public function testFullTieKeepsTheFirst(): void
    {
        $p = Obj::of(['classes' => [Obj::of(['name' => 'first', 'resource' => 'a*', 'maxTaintForAuto' => 1]),
            Obj::of(['name' => 'second', 'resource' => 'a*', 'maxTaintForAuto' => 1])]]);
        $r = Dlp::evaluateDlp($p, self::ctx('ab', 'send', 0));
        self::assertSame(['allow', 'first'], [$r->get('outcome'), $r->get('class')]);
    }

    /** Verb lists match by SameValueZero: equal numbers (and NaN with NaN), never a number against a non-number. */
    public function testNumericVerbs(): void
    {
        self::assertTrue(self::verbApplies([5], 5));
        self::assertTrue(self::verbApplies([5], 5.0));
        self::assertTrue(self::verbApplies([NAN], NAN));
        self::assertFalse(self::verbApplies([1], 2));
        self::assertFalse(self::verbApplies([NAN], 1));
        self::assertFalse(self::verbApplies([1], NAN));
        self::assertFalse(self::verbApplies([0], 'send'));
        self::assertFalse(self::verbApplies(['5'], 5));
    }

    /** null and booleans match only themselves; arrays and objects never match, not even an identical one. */
    public function testNonNumericVerbs(): void
    {
        self::assertTrue(self::verbApplies([null], null));
        self::assertTrue(self::verbApplies([true], true));
        self::assertFalse(self::verbApplies([true], false));
        self::assertFalse(self::verbApplies([null], 'send'));
        self::assertFalse(self::verbApplies([[]], []));
        self::assertFalse(self::verbApplies([[]], 'send'));
        $o = Obj::of(['a' => 1]);
        self::assertFalse(self::verbApplies([$o], $o));
        self::assertTrue(self::verbApplies(['send'], 'send'));
    }
}
