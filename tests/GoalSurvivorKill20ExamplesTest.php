<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalExamples.php';

use Atlas\Pca\GoalExamples;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The example space: every quantity literal a goal compares against is kept as its exact JSON number text. */
final class GoalSurvivorKill20ExamplesTest extends TestCase
{
    /** Integral values print as integers, fractions and huge values as JS numbers, non-finite ones as null. */
    public function testSpaceQuantitiesKeepTheirNumberText(): void
    {
        $vals = ['p1' => 5, 'p2' => 1.5, 'p3' => 123456789012345, 'p4' => 1e300, 'p5' => NAN, 'p6' => INF, 'p7' => -2.5];
        $grants = [];
        foreach ($vals as $p => $n) {
            $lit = Obj::of(['k' => 'lit', 'v' => Obj::of(['k' => 'q', 'q' => Obj::of(['u' => Obj::of(['k' => 'count']), 'n' => $n])])]);
            $grants[] = Obj::of(['verb' => 'v', 'res' => Obj::of(['k' => 'any']),
                'cond' => Obj::of(['k' => 'cmp', 'op' => 'lte', 'l' => Obj::of(['k' => 'param', 'path' => $p]), 'r' => $lit])]);
        }
        $sp = GoalExamples::buildSpace([Obj::of(['grants' => $grants, 'prohibits' => [], 'escalateOn' => [], 'bounds' => []])]);
        $got = [];
        foreach (array_keys($vals) as $p) {
            $got[$p] = array_map(static fn($x) => $x->lexeme, $sp->get('q')->get($p)->get('count'));
        }
        self::assertSame(['p1' => ['5'], 'p2' => ['1.5'], 'p3' => ['123456789012345'], 'p4' => ['1e+300'], 'p5' => ['null'], 'p6' => ['null'], 'p7' => ['-2.5']], $got);
    }
}
