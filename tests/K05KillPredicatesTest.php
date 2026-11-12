<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\Predicates;
use Atlas\Pca\SafeRegex;
use Atlas\Pca\SafeRegexBudget;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Predicates: the denial reason (nested-group depth, non-object conditions / predicates) and fail closed. */
final class K05KillPredicatesTest extends TestCase
{
    private static function ctx(): Obj
    {
        return Json::parseLax('{"action":{"verb":"pay","resource":"acct","params":{"amount":10}}}');
    }

    private static function deny(string $predicates): array
    {
        return Predicates::evaluatePredicates(Json::parseLax($predicates), self::ctx());
    }

    public function testNestedGroupsAreDescribedToDepthTwo(): void
    {
        $leaf = '{"field":"action.params.amount","op":"lte","value":5}';
        $this->assertSame(['allowed' => false, 'reason' => 'any of (any of ((...))) not satisfied for pay on acct'],
            self::deny('[{"verb":"pay","resource":"acct","where":[{"any_of":[{"any_of":[{"any_of":[' . $leaf . ']}]}]}]}]'));
        $this->assertSame(['allowed' => false, 'reason' => 'any of (amount <= 5) not satisfied for pay on acct'],
            self::deny('[{"verb":"pay","resource":"acct","where":[{"any_of":[' . $leaf . ']}]}]'));
    }

    public function testANonObjectConditionOrPredicateIsDescribedNotThrown(): void
    {
        $this->assertSame(['allowed' => false, 'reason' => '<field> <condition> not satisfied for pay on acct'],
            self::deny('[{"verb":"pay","resource":"acct","where":[[]]}]'));
        $this->assertSame(['allowed' => false, 'reason' => 'no predicate permits pay on acct'], self::deny('[5]'));
        $this->assertSame(['allowed' => false, 'reason' => 'no predicate permits pay on acct'], self::deny('["x", [1]]'));
    }

    /**
     * An engine error while building the reason fails closed: a self-referencing verb (a PHP reference cycle a host can build)
     * would make the reason's String(verb) recurse forever; the depth bound throws and the denial is the fail-closed one.
     */
    public function testAnErrorWhileExplainingIsAFailClosedDenial(): void
    {
        $cyc = [];
        $cyc[0] = &$cyc;
        $action = Obj::of(['verb' => $cyc, 'resource' => 'acct']);
        $r = Predicates::evaluatePredicates(Json::parseLax('[{"verb":"pay"}]'), Obj::of(['action' => $action]));
        $this->assertSame(['allowed' => false, 'reason' => 'predicate evaluation error (fail closed)'], $r);
    }

    /** String(verb) renders arrays nested Json::MAX_DEPTH deep (the deepest a parsed value can be) and refuses one level more. */
    public function testTheReasonRendersArraysUpToTheParserDepthBound(): void
    {
        $nest = static function (int $n): array {
            $v = 'x';
            for ($i = 0; $i < $n; $i++) {
                $v = [$v];
            }
            return $v;
        };
        $deny = static fn(array $verb): array => Predicates::evaluatePredicates(Json::parseLax('[{"verb":"pay"}]'),
            Obj::of(['action' => Obj::of(['verb' => $verb, 'resource' => 'acct'])]));
        $this->assertSame(32, Json::MAX_DEPTH);
        $this->assertSame(['allowed' => false, 'reason' => 'no predicate permits x on acct'], $deny($nest(32)));
        $this->assertSame(['allowed' => false, 'reason' => 'predicate evaluation error (fail closed)'], $deny($nest(33)));
    }

    /** A host value that only looks like an Obj (keys / has / get) is not a JSON object. */
    private static function lookalike(array $d): object
    {
        return new class ($d) {
            public function __construct(private readonly array $d)
            {
            }

            public function keys(): array
            {
                return array_map('strval', array_keys($this->d));
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->d);
            }

            public function get(string $k): mixed
            {
                return $this->d[$k] ?? null;
            }
        };
    }

    private static function hostCtx(mixed $v): Obj
    {
        return Obj::of(['action' => Obj::of(['verb' => 'pay', 'resource' => 'acct', 'params' => Obj::of(['x' => $v])])]);
    }

    private static function tri(mixed $fieldValue, string $op, mixed $value): string
    {
        return Predicates::evaluateConditionTri(Obj::of(['field' => 'action.params.x', 'op' => $op, 'value' => $value]),
            self::hostCtx($fieldValue));
    }

    public function testOnlyJsonObjectsAndArraysCompareStructurally(): void
    {
        $obj = Json::parseLax('{"k":1}');
        $fake = self::lookalike(['k' => Json::parseLax('1')]);
        $this->assertSame('false', self::tri($obj, 'eq', $fake));
        $this->assertSame('false', self::tri($fake, 'eq', $obj));
        $this->assertSame('true', self::tri($obj, 'ne', $fake));
        $this->assertSame('true', self::tri($obj, 'eq', Json::parseLax('{"k":1}')), 'control: two objects compare');
        $list = Json::parseLax('[1]');
        $this->assertSame('false', self::tri(new \ArrayObject([1]), 'eq', $list));
        $this->assertSame('false', self::tri($list, 'eq', self::lookalike([0 => 1])));
        $this->assertSame('true', self::tri([1], 'eq', $list), 'control: two arrays compare');
    }

    public function testIsAOnAHostObjectThatIsNotAJsonObjectIsUnknown(): void
    {
        $this->assertSame('unknown', self::tri(self::lookalike(['type' => 'T', 'tags' => ['T']]), 'is_a', 'T'));
        $this->assertSame('true', self::tri(Json::parseLax('{"type":"T"}'), 'is_a', 'T'), 'control');
    }

    private static function leaf(array $c): string
    {
        return (new \ReflectionMethod(Predicates::class, 'triLeaf'))->invoke(null, Obj::of($c), self::ctx());
    }

    /** triLeaf itself answers 'unknown' for mismatched operand types (it does not lean on triInner's catch). */
    public function testTriLeafTypeGuardsAnswerUnknownWithoutThrowing(): void
    {
        // a member_of collection that resolves to a non-object
        $this->assertSame('unknown', self::leaf(['field' => 'action.verb', 'op' => 'member_of', 'collection' => 'action.resource', 'value' => 'x']));
        $this->assertSame('true', self::leaf(['field' => 'action.verb', 'op' => 'prefix', 'value' => 'pa']), 'control');
        foreach (['prefix', 'like', 'matches'] as $op) {
            $this->assertSame('unknown', self::leaf(['field' => 'action.verb', 'op' => $op, 'value' => 5]), $op);
            $this->assertSame('unknown', self::leaf(['field' => 'action.params.amount', 'op' => $op, 'value' => 'p']), $op);
        }
    }

    public function testNeighboursAreAListAndTheClosureIsATrueSet(): void
    {
        $adj = Obj::of(['a' => [5, 'b'], 'b' => 'c']);
        $this->assertSame(['b'], (new \ReflectionMethod(Predicates::class, 'neighboursOf'))->invoke(null, $adj, 'a'));
        $this->assertSame(['ka' => true, 'kb' => true, 'kc' => true],
            (new \ReflectionMethod(Predicates::class, 'memberClosure'))->invoke(null, 'a', $adj));
    }

    /** A budget built without its constructor: reading its readonly members throws an Error. */
    private static function brokenBudget(): SafeRegexBudget
    {
        return (new \ReflectionClass(SafeRegexBudget::class))->newInstanceWithoutConstructor();
    }

    public function testThePredicateCatchesFailClosed(): void
    {
        $p = Json::parseLax('{"verb":"pay","resource":"re:acct"}');
        $ctx = self::ctx();
        $this->assertTrue(Predicates::predicateMatches($p, $ctx), 'control');
        // as the open scope: withBudget throws before the inner try (the outer catches answer)
        $prev = SafeRegex::swapBudget(self::brokenBudget());
        try {
            $this->assertFalse(Predicates::predicateMatches($p, $ctx));
            $this->assertSame(['allowed' => false, 'reason' => 'predicate evaluation error (fail closed)'],
                Predicates::evaluatePredicates([$p], $ctx));
        } finally {
            SafeRegex::swapBudget($prev);
        }
        // as the parent of the open request scope: the re: charge throws inside predicateMatchesInner
        $prev = SafeRegex::swapBudget(new SafeRegexBudget(1, self::brokenBudget(), false));
        try {
            $this->assertFalse(Predicates::predicateMatches($p, $ctx));
        } finally {
            SafeRegex::swapBudget($prev);
        }
    }

    public function testTheLayerCatchesFailClosed(): void
    {
        $ctx = self::ctx();
        $ceil = Json::parseLax('{"org":{"predicates":[{"verb":"pay"}]}}');
        $task = Json::parseLax('{"task":[{"predicates":[{"verb":"pay"}]}]}');
        $this->assertSame(['status' => 'pass'], Predicates::decideLayerCeilings($ceil, $ctx), 'control');
        $this->assertSame(['decision' => 'admit', 'by' => 0], Predicates::decideLayers($task, $ctx), 'control');
        Predicates::$layerHook = static function (): void {
            throw new \RuntimeException('boom');
        };
        try {
            $this->assertSame(['status' => 'fail', 'layer' => 'org', 'reason' => 'layers: evaluation error (fail closed): boom'],
                Predicates::decideLayerCeilings($ceil, $ctx));
            $this->assertSame(['decision' => 'intent_denied'], Predicates::decideLayers($task, $ctx));
        } finally {
            Predicates::$layerHook = null;
        }
    }
}
