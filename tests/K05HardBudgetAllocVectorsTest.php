<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** budget-alloc-vectors.json: the monotone budget_alloc rule over the flattened caveat list, reason by reason. */
final class K05HardBudgetAllocVectorsTest extends TestCase
{
    public function testEveryRow(): void
    {
        $rows = Vectors::load('budget-alloc-vectors.json')->get('budget_alloc');
        $this->assertGreaterThanOrEqual(24, count($rows));
        $m = new \ReflectionMethod(Pca::class, 'allocationsError');
        foreach ($rows as $c) {
            $why = $m->invoke(null, $c->get('caveats'));
            $x = $c->get('expect');
            if ($x->get('ok') === true) {
                $this->assertNull($why, $c->get('name'));
            } else {
                $this->assertSame($x->get('reason'), $why, $c->get('name'));
            }
        }
    }
}
