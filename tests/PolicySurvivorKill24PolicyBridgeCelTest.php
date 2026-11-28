<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\PolicyBridgeCel;
use Atlas\Pca\PolicyBridgeCelParser;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24) for src/PolicyBridgeCel.php: UTF-16 units, the limits, timestamps, surrogate re-pairing and the batch / predicate errors. */
final class PolicySurvivorKill24PolicyBridgeCelTest extends TestCase
{
    private static function schema(): Obj
    {
        return Obj::of(['vars' => Obj::of([
            'a' => Obj::of(['path' => 'action.params.a', 'type' => 'int']),
            's' => Obj::of(['path' => 'action.params.s', 'type' => 'string']),
        ])]);
    }

    /** @return array{0:bool,1:mixed} ok and (ast or code) of parseCel */
    private static function p(string $src): array
    {
        $r = PolicyBridgeCel::parseCel($src);
        return [$r->get('ok'), $r->get('ok') ? $r->get('ast') : $r->get('code')];
    }

    private static function ts(string $iso): mixed
    {
        $r = PolicyBridgeCel::parseCel('timestamp("' . $iso . '")');
        return $r->get('ok') ? $r->get('ast')->get('v') : $r->get('message');
    }

    /** One WTF-8 unit per UTF-16 unit, at every encoding-length boundary; an astral code point is two surrogate halves. */
    public function testUnitsAtEveryBoundary(): void
    {
        $this->assertSame(["\xC2\x80"], PolicyBridgeCelParser::units("\xC2\x80"));
        $this->assertSame(["\xE0\xA0\x80"], PolicyBridgeCelParser::units("\xE0\xA0\x80"));
        $this->assertSame(["\xE1\x81\x81"], PolicyBridgeCelParser::units("\xE1\x81\x81"));
        $this->assertSame(["\xED\xA3\x84", "\xED\xB1\x81"], PolicyBridgeCelParser::units("\xF1\x81\x81\x81"));
        $this->assertSame(["\xED\xA3\x84", "\xED\xB1\x81", 'x'], PolicyBridgeCelParser::units("\xF1\x81\x81\x81x"));
        // a stray continuation byte reads as a two-byte lead
        $this->assertSame(["\x01"], PolicyBridgeCelParser::units("\x80A"));
    }

    /** An expression of exactly 4096 units is allowed; one more is too complex. */
    public function testExpressionLengthLimitIsInclusive(): void
    {
        $this->assertTrue(self::p(str_pad('a == 1', 4096))[0]);
        $this->assertSame([false, 'too_complex'], self::p(str_pad('a == 1', 4097)));
    }

    /** Nesting deeper than 32 at the end of input is reported at offset 0. */
    public function testDepthAtEndOfInputIsAtZero(): void
    {
        $r = PolicyBridgeCel::parseCel(str_repeat('(', 33));
        $this->assertSame(['too_complex', 'nesting deeper than 32', 0], [$r->get('code'), $r->get('message'), $r->get('at')]);
    }

    /** A second call argument nests one level deeper than the call. */
    public function testSecondArgumentDepth(): void
    {
        $this->assertSame([false, 'too_complex'], self::p('has(x, ' . str_repeat('(', 32) . 'x' . str_repeat(')', 32) . ')'));
        $this->assertSame([false, 'syntax'], self::p('has(x, ' . str_repeat('(', 31) . 'x' . str_repeat(')', 31) . ')'));
    }

    /** A list item nests one level deeper than the list. */
    public function testListItemDepth(): void
    {
        $this->assertSame([false, 'too_complex'], self::p('x in [' . str_repeat('(', 32) . '1' . str_repeat(')', 32) . ']'));
        $this->assertTrue(self::p('x in [' . str_repeat('(', 31) . '1' . str_repeat(')', 31) . ']')[0]);
    }

    /** Every node kind counts toward the 256-node limit ('!', methods, lists, booleans, variables). */
    public function testEveryNodeKindCounts(): void
    {
        foreach ([['!a', 86], ['s.startsWith("a")', 65], ['x in [1]', 52], ['b == true', 65], ['a == 1', 65]] as [$term, $k]) {
            $this->assertSame([false, 'too_complex'], self::p(implode(' && ', array_fill(0, $k, $term))), $term);
        }
        $this->assertTrue(self::p('!a && a == 1')[0], 'control');
    }

    /** An integer literal is an int node, never a float. */
    public function testIntegerLiteralIsAnInt(): void
    {
        $this->assertSame(5, self::p('a == 5')[1]->get('r')->get('v'));
    }

    /** Surrogate halves in a result are re-paired into the astral character; list items are converted too. */
    public function testResultsArePairedAndConverted(): void
    {
        $ch = mb_chr(0x20041, 'UTF-8');
        $this->assertSame($ch, self::p('"' . $ch . '"')[1]->get('v'));
        $this->assertSame('plain', self::p('"plain"')[1]->get('v'));
        $items = self::p('[a]')[1]->get('items');
        $this->assertInstanceOf(Obj::class, $items[0]);
        $this->assertSame('a', $items[0]->get('name'));
    }

    /** RFC 3339 instants: era, month offsets, leap centuries and minutes vs seconds. */
    public function testTimestampValues(): void
    {
        $this->assertSame(-62135596800000, self::ts('0001-01-01T00:00:00Z'));
        $this->assertSame(951868800000, self::ts('2000-03-01T00:00:00Z'));
        $this->assertSame(962409600000, self::ts('2000-07-01T00:00:00Z'));
        $this->assertSame(-2203891200000, self::ts('1900-03-01T00:00:00Z'));
        $this->assertSame(975628862000, self::ts('2000-12-01T00:01:02Z'));
        $this->assertSame(975628862500, self::ts('2000-12-01T00:01:02.5Z'));
    }

    /** Every month's last day is real and the day after it is not; leap years follow the Gregorian century rule. */
    public function testTimestampCalendar(): void
    {
        $bad = 'timestamp() is not a real instant';
        foreach ([31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as $i => $last) {
            $mo = sprintf('%02d', $i + 1);
            $this->assertIsInt(self::ts("2023-$mo-{$last}T00:00:00Z"), "2023-$mo-$last");
            $this->assertSame($bad, self::ts("2023-$mo-" . ($last + 1) . 'T00:00:00Z'), "2023-$mo-" . ($last + 1));
        }
        $this->assertIsInt(self::ts('2024-02-29T00:00:00Z'));
        $this->assertSame($bad, self::ts('2024-02-30T00:00:00Z'));
        $this->assertIsInt(self::ts('2000-02-29T00:00:00Z'));
        $this->assertSame($bad, self::ts('1900-02-29T00:00:00Z'));
        $this->assertSame($bad, self::ts('2023-13-01T00:00:00Z'));
    }

    /** A glob of exactly 512 units is allowed; 513 is too long. */
    public function testGlobLengthLimit(): void
    {
        $r = PolicyBridgeCel::celToCondition('s.endsWith("' . str_repeat('*', 255) . 'a")', self::schema());
        $this->assertTrue($r->get('ok'));
        $this->assertSame('*' . str_repeat('\\*', 255) . 'a', $r->get('condition')->get('value'));
        $r = PolicyBridgeCel::celToCondition('s.endsWith("' . str_repeat('*', 256) . '")', self::schema());
        $this->assertSame([false, 'too_complex', 'literal too long for a glob'], [$r->get('ok'), $r->get('code'), $r->get('message')]);
    }

    /** A predicate needs an object scope (the reference's TypeError). */
    public function testPredicateNeedsAnObjectScope(): void
    {
        $this->assertTrue(PolicyBridgeCel::celToPredicate('a == 1', self::schema(), new Obj())->get('ok'), 'control');
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("cannot read properties of null (reading 'verb')");
        PolicyBridgeCel::celToPredicate('a == 1', self::schema(), null);
    }

    /** A boolean item name is reported as true / false. */
    public function testBooleanNamesInTheReport(): void
    {
        $r = PolicyBridgeCel::celConditionsToPca([Obj::of(['name' => true, 'verb' => 'v', 'expression' => 'a == 1'])], self::schema());
        $this->assertSame(['true: translated exactly (reads action.params.a)'], $r->get('report')->get('translated'));
    }

    /** The batch needs a list of objects. */
    public function testBatchShapeErrors(): void
    {
        $item = Obj::of(['name' => 'n', 'expression' => 'a == 1']);
        foreach (['x', ['k' => $item]] as $items) {
            try {
                PolicyBridgeCel::celConditionsToPca($items, self::schema());
                $this->fail('accepted a non-list');
            } catch (\TypeError $e) {
                $this->assertSame('items is not iterable', $e->getMessage());
            }
        }
        try {
            PolicyBridgeCel::celConditionsToPca([5], self::schema());
            $this->fail('accepted a non-object item');
        } catch (\TypeError $e) {
            $this->assertSame('item is not an object', $e->getMessage());
        }
    }
}
