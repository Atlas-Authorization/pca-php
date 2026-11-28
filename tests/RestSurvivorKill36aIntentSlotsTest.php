<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentSlots.php';

use Atlas\Pca\IntentSlots;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 36a mutation kills for src/IntentSlots.php: which slot constraints compile to conditions, and how alternatives combine. */
final class RestSurvivorKill36aIntentSlotsTest extends TestCase
{
    /** @param array<string,mixed> $c */
    private static function predicate(array $c): Obj
    {
        $p = IntentSlots::slotsToPolicy(Obj::of(['verbs' => ['pay'], 'constraints' => [Obj::of(['path' => 'amount'] + $c)]]));
        return $p->get('predicates')[0];
    }

    /** An empty oneOf list and an empty noneOf string constrain nothing: the predicate has no where at all. */
    public function testEmptySetsConstrainNothing(): void
    {
        $pr = self::predicate(['oneOf' => [], 'noneOf' => '']);
        self::assertSame(['verb', 'resource'], $pr->keys());
        self::assertSame('*', $pr->get('resource'));
    }

    /** A non-empty string is a set of its characters (JS spread), exactly as a list is. */
    public function testNonEmptyStringIsACharacterSet(): void
    {
        $where = self::predicate(['noneOf' => 'ab'])->get('where');
        self::assertCount(1, $where);
        self::assertSame(['field' => 'amount', 'op' => 'nin', 'value' => ['a', 'b']],
            ['field' => $where[0]->get('field'), 'op' => $where[0]->get('op'), 'value' => $where[0]->get('value')]);
        $in = self::predicate(['oneOf' => 'x'])->get('where');
        self::assertSame('in', $in[0]->get('op'));
        self::assertSame(['x'], $in[0]->get('value'));
    }

    /** A prefixOneOf that is not a list is refused, never silently ignored. */
    public function testNonListPrefixOneOfThrows(): void
    {
        try {
            self::predicate(['prefixOneOf' => 'abc']);
            self::fail('a string prefixOneOf compiled');
        } catch (\TypeError $e) {
            self::assertSame('prefixOneOf is not iterable', $e->getMessage());
        }
    }

    /** oneOf plus a prefix alternative compile to ONE any_of carrying both alternatives. */
    public function testAlternativesCompileToOneAnyOf(): void
    {
        $where = self::predicate(['oneOf' => ['a'], 'prefixOneOf' => ['p']])->get('where');
        self::assertCount(1, $where);
        self::assertSame(['any_of'], $where[0]->keys());
        $alts = $where[0]->get('any_of');
        self::assertCount(2, $alts);
        self::assertSame(['in', ['a']], [$alts[0]->get('op'), $alts[0]->get('value')]);
        self::assertSame(['prefix', 'p'], [$alts[1]->get('op'), $alts[1]->get('value')]);
    }
}
