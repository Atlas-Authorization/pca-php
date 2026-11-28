<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentPolicy;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 32 mutation kills for src/IntentPolicy.php: policy normalisation, the outcome as an action, the array-policy admitter and vsOf. */
final class IntentSurvivorKill32IntentPolicyTest extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    /** A truthy primitive policy is refused with the runtime's `in` TypeError wording, naming the value. */
    public function testATruthyPrimitivePolicyIsATypeErrorNamingTheValue(): void
    {
        self::assertSame('{"predicates":[],"caveats":[]}', Json::stringify(IntentPolicy::normalizePolicy(null)), 'a falsy policy is empty');
        try {
            IntentPolicy::normalizePolicy('abc');
            self::fail('a string policy must throw');
        } catch (\TypeError $e) {
            self::assertSame("Cannot use 'in' operator to search for 'caveats' in abc", $e->getMessage());
        }
    }

    /** Dotted paths build nested params / env / subject trees; a scalar on the way is replaced, a shared prefix is reused, paths outside the three roots are ignored. */
    public function testOutcomeToActionBuildsTheThreeTrees(): void
    {
        $values = Obj::of([
            'action.params.a' => 'scalar',
            'action.params.a.b' => 'B',
            'action.params.a.c' => 'C',
            'env.e.f' => 'F',
            'subject.s' => 'S',
            'action.resource' => 'r1',
            'action.params' => 'ignored-1',
            'x.params.y' => 'ignored-2',
            'env' => 'ignored-3',
            'subject' => 'ignored-4',
            'foo.bar' => 'ignored-5',
        ]);
        $a = IntentPolicy::outcomeToAction(Obj::of(['verb' => 'v', 'reversibility' => 'reversible']), Obj::of(['verb' => 'v', 'values' => $values]));
        self::assertSame('{"verb":"v","resource":"r1","params":{"a":{"b":"B","c":"C"}},"reversibilityClass":"reversible","env":{"e":{"f":"F"}},"subject":{"s":"S"}}', Json::stringify($a));
    }

    /** No env / subject values and no reversibility in the verb space: the action carries none of the three members. */
    public function testOutcomeToActionOmitsEmptyRootsAndAbsentReversibility(): void
    {
        $a = IntentPolicy::outcomeToAction(Obj::of(['verb' => 'v']), Obj::of(['verb' => 'v', 'values' => new Obj()]));
        self::assertSame('{"verb":"v","resource":"resource:any","params":{}}', Json::stringify($a));
    }

    /** An associative-array policy whose predicates are themselves associative arrays (and which has an integer key) is read as the object policy. */
    public function testAnAdmitterFromANestedArrayPolicyReadsItsPredicates(): void
    {
        $adm = IntentPolicy::admitter([
            'predicates' => [['verb' => 'v.a', 'resource' => '*', 'where' => [['field' => 'action.params.a', 'op' => 'lte', 'value' => new Num('5')]]]],
            'caveats' => [],
            7 => 'unused',
        ]);
        $vs = Obj::of(['verb' => 'v.a', 'reversibility' => 'reversible', 'dims' => []]);
        $at = static fn(int $a): Obj => Obj::of(['verb' => 'v.a', 'values' => Obj::of(['action.params.a' => $a])]);
        self::assertTrue($adm->admits($vs, $at(3)), 'inside the policy');
        self::assertFalse($adm->admits($vs, $at(9)), 'outside the policy');
    }

    /** vsOf returns the verb space of the outcome's own verb, or null. */
    public function testVsOfFindsTheMatchingVerb(): void
    {
        $a = Obj::of(['verb' => 'a']);
        $b = Obj::of(['verb' => 'b']);
        $omega = Obj::of(['verbs' => [$a, $b]]);
        self::assertSame($b, IntentPolicy::vsOf($omega, Obj::of(['verb' => 'b'])));
        self::assertSame($a, IntentPolicy::vsOf($omega, Obj::of(['verb' => 'a'])));
        self::assertNull(IntentPolicy::vsOf($omega, Obj::of(['verb' => 'c'])));
    }
}
