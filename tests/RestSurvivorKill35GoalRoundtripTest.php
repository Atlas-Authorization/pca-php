<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalRoundtrip;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the goal round-trip detector. */
final class RestSurvivorKill35GoalRoundtripTest extends TestCase
{
    /** The scaled cap amount after widen_cap of a money cap with amount lexeme $n. */
    private static function widened(string $n): mixed
    {
        $g = Obj::of(['bounds' => [Obj::of(['cap' => Obj::of(['u' => Obj::of(['k' => 'money']), 'n' => new Num($n)])])]]);
        return GoalRoundtrip::mutateGoal($g, 'widen_cap', new Obj())->get('bounds')[0]->get('cap')->get('n');
    }

    /** A safe integer becomes an int, a fraction stays a float, and 2^53 is not a safe integer. */
    public function testScaledAmountTypes(): void
    {
        $this->assertSame(30, self::widened('3'));
        $this->assertSame(-30, self::widened('-3'));
        $this->assertSame(2.5, self::widened('0.25'));
        $this->assertSame(9007199254740992.0, self::widened('900719925474099.2'));
    }

    /** The reference explainer and comparator are public, with their ids. */
    public function testReferencePairIsPublic(): void
    {
        $e = GoalRoundtrip::deterministicExplainer();
        $this->assertSame(['card-prose', "a\nb"], [$e->id(), $e->explain(['a', 'b'])]);
        $c = GoalRoundtrip::lexicalComparator(Obj::of(['types' => [Obj::of(['id_prefix' => 'ord_'])]]));
        $this->assertSame(['lexical', 'rule'], [$c->id(), $c->family()]);
    }

    /** The comparator compares the id sets, not the order they are written in. */
    public function testIdsAreComparedAsSets(): void
    {
        $c = GoalRoundtrip::lexicalComparator(Obj::of(['types' => [Obj::of(['id_prefix' => 'ord_'])]]));
        $this->assertTrue($c->equivalent('refund ord_b and ord_a', 'refund ord_a and ord_b')->get('equivalent'));
        $this->assertFalse($c->equivalent('refund ord_a', 'refund ord_b')->get('equivalent'));
    }
}
