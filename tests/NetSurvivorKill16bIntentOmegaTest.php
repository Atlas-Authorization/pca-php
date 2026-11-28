<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentOmega;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * The intent outcome space at the edges of binary64: integers past 2^53 (where an int and its float differ, and int + 1 rounds
 * differently from float + 1), numeric catalog verbs from JSON, and the default harm model's interval mean.
 */
final class NetSurvivorKill16bIntentOmegaTest extends TestCase
{
    /** An int bound past 2^53 weighs exactly what its float does (the bound is made a float before the + 1). */
    public function testAnIntegerBoundPast2To53WeighsAsItsFloat(): void
    {
        $b = 9007199254741017; // 2^53 + 25: (float)$b + 1 and (float)($b + 1) are different doubles, and their ln round apart
        $this->assertNotSame((float)$b + 1, (float)($b + 1));
        $d = ['dist' => 'loguniform', 'lo' => 0];
        $this->assertSame(IntentOmega::intervalWeight($d, 0, (float)$b), IntentOmega::intervalWeight($d, 0, $b));
    }

    /** A log-uniform draw from a cell starting past 2^53 is the same for an int lo as for its float. */
    public function testALogUniformDrawPast2To53(): void
    {
        $lo = 18014398509481986; // 2^54 + 2 (doubles 4 apart here): (float)$lo + 1 is 2^54, (float)($lo + 1) is 2^54 + 4
        $this->assertNotSame((float)$lo + 1, (float)($lo + 1));
        $draw = static function (int|float $lo, int $hi): mixed {
            $d = ['kind' => 'num', 'path' => 'q', 'lo' => $lo, 'hi' => $hi, 'cuts' => [], 'dist' => 'loguniform'];
            $u = [0.0, 0.5];
            [, $o] = IntentOmega::sampleOutcome(['verbs' => [['verb' => 'v', 'weight' => 1, 'dims' => [$d]]]], static function () use (&$u): float {
                return array_shift($u);
            });
            return $o->get('values')->get('q');
        };
        $x = $draw($lo, $lo + 20000);
        $this->assertGreaterThan((float)$lo + 1000, $x, 'the draw is inside the cell, not clamped to its bounds');
        $this->assertSame($draw((float)$lo, $lo + 20000), $x);
    }

    /** Catalog verbs that JSON gives as numbers stay distinct (1.5 is not 1). */
    public function testNumericCatalogVerbsStayDistinct(): void
    {
        $omega = IntentOmega::deriveOmega(['catalog' => [['connector' => 'c', 'verb' => new Num('1.5')], ['connector' => 'c', 'verb' => new Num('1')]],
            'policies' => [['predicates' => [['verb' => '*']]]]]);
        $verbs = array_map(static fn(Obj $v): mixed => $v->get('verb'), $omega->get('verbs'));
        sort($verbs);
        $this->assertSame([1, 1.5], $verbs);
    }

    /** The default interval mean: no harm beyond 1 off an amount path, and the log-uniform mean from 0 (the x = 0 term included). */
    public function testTheDefaultIntervalMean(): void
    {
        $mean = IntentOmega::defaultHarm()->dimMean;
        $this->assertSame(1, $mean(['kind' => 'num', 'path' => 'x'], 0, 1));
        $amount = ['kind' => 'num', 'path' => 'action.params.amount', 'lo' => 0, 'hi' => 5000, 'dist' => 'loguniform'];
        $this->assertSame(3.3375701480670505, $mean($amount, 0, 1908));
    }
}
