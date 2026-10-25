<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Predicates.php';

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use PHPUnit\Framework\TestCase;

/** Round r9 mutation kills for src/Predicates.php. */
final class R9PredicatesKillTest extends TestCase
{
    private static function j(string $json): mixed
    {
        return Json::parseLax($json);
    }

    private static function ctx(string $env = '{}'): Obj
    {
        return self::j('{"action":{"verb":"read","resource":"/acct/1","params":{}},"env":' . $env . '}');
    }

    public function testEmptyArrayIsNotEqualToEmptyObject(): void
    {
        // jeq: an array and an object with the same (zero) member count are not equal
        $c = self::ctx('{"v":[]}');
        self::assertSame('false', Predicates::evaluateConditionTri(self::j('{"field":"env.v","op":"eq","value":{}}'), $c));
        self::assertSame('true', Predicates::evaluateConditionTri(self::j('{"field":"env.v","op":"ne","value":{}}'), $c));
        $c = self::ctx('{"v":{}}');
        self::assertSame('false', Predicates::evaluateConditionTri(self::j('{"field":"env.v","op":"eq","value":[]}'), $c));
        self::assertSame('true', Predicates::evaluateConditionTri(self::j('{"field":"env.v","op":"eq","value":{}}'), $c));
    }

    public function testIsLeafConditionIsTotalOnNonObjects(): void
    {
        foreach ([null, 'field', 5, true, [], [self::j('{"field":"a"}')]] as $x) {
            self::assertFalse(Predicates::isLeafCondition($x));
        }
        self::assertTrue(Predicates::isLeafCondition(self::j('{"field":"a"}')));
        self::assertFalse(Predicates::isLeafCondition(self::j('{"field":1}')));
        self::assertFalse(Predicates::isLeafCondition(self::j('{"field":"a","not":{}}')));
    }

    public function testReasonPrintsNestedArraysLikeJavaScript(): void
    {
        // String([1, true, null, [2, "x"]]) === "1,true,,2,x"
        $r = Predicates::evaluatePredicates(
            self::j('[{"verb":"zzz"}]'),
            self::j('{"action":{"verb":[1,true,null,[2,"x"],{}],"resource":[[],[null]]}}')
        );
        self::assertSame(['allowed' => false, 'reason' => 'no predicate permits 1,true,,2,x,[object Object] on ,'], $r);
    }

    public function testMalformedDeniedEntryRefusesEvenWhenItWouldNotAdmit(): void
    {
        $ctx = self::ctx();
        $yes = '{"predicates":[{"verb":"*"}]}';
        $no = '{"predicates":[{"verb":"nope"}],"extra":1}';
        // the denied entry is an object that does not admit (and is malformed): the whole grant is refused
        self::assertSame(['decision' => 'intent_denied'],
            Predicates::decideLayers(self::j('{"denied":[' . $no . '],"task":[' . $yes . ']}'), $ctx));
    }

    private static function priv(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Predicates::class, $name))->invoke(null, ...$args);
    }

    public function testOrderedIsExactlyMinusOneZeroOne(): void
    {
        self::assertSame(-1, self::priv('ordered', 1, 2));
        self::assertSame(1, self::priv('ordered', 2, 1));
        self::assertSame(0, self::priv('ordered', 2, 2));
        self::assertSame(-1, self::priv('ordered', 'a', 'b'));
        self::assertSame(1, self::priv('ordered', 'b', 'a'));
        self::assertNull(self::priv('ordered', 1, 'a'));
    }

    public function testParseGlobTokens(): void
    {
        $u = static fn(string $g): array => \Atlas\Pca\SafeRegex::units($g);
        self::assertSame([[0, 0x61], [1], [2], [0, 0x62]], self::priv('parseGlob', $u('a?*b')));
        self::assertSame([[0, 0x61], [2], [0, 0x62]], self::priv('parseGlob', $u('a***b'))); // consecutive stars collapse
        self::assertSame([[2], [0, 0x2A], [0, 0x5C], [0, 0x3F]], self::priv('parseGlob', $u('*\*\\\\\?')));
        self::assertNull(self::priv('parseGlob', $u('a\\')));
    }
}
