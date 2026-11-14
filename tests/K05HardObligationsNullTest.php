<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obligations;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** F6: a JSON null obligations list is a present value and is refused (TS `obligations must be an array`); only an absent list is empty. */
final class K05HardObligationsNullTest extends TestCase
{
    public function testAbsentIsTheEmptyListAndNullIsRefused(): void
    {
        $this->assertNull(Obligations::listError(Obligations::absent()));
        $this->assertNull(Obligations::listError([]));
        $this->assertSame('obligations must be an array', Obligations::listError(null));
        $this->assertSame('obligations must be an array', Obligations::listError('x'));
        $this->assertSame(Obligations::absent(), Obligations::absent(), 'one marker');
    }

    public function testGate(): void
    {
        $this->assertSame(['decision' => 'allow', 'perform' => [], 'unsupported' => []], Obligations::gate('allow', false, Obligations::absent(), []));
        $r = Obligations::gate('allow', false, null, []);
        $this->assertSame('deny', $r['decision']);
        $this->assertSame('malformed obligations: obligations must be an array', $r['reason']);
        $this->assertSame([], $r['perform']);
    }

    public function testMerge(): void
    {
        $log = Obj::of(['kind' => 'require_receipt']);
        $m = Obligations::merge([$log], Obligations::absent());
        $this->assertTrue($m['ok']);
        $this->assertCount(1, $m['obligations']);
        $this->assertSame(['ok' => false, 'reason' => 'obligations must be an array'], Obligations::merge([$log], null));
    }

    public function testOutcome(): void
    {
        $this->assertSame(['outcome' => 'ok', 'overdue' => []], Obligations::outcome(Obligations::absent(), [], 5));
        $r = Obligations::outcome(null, [], 5);
        $this->assertSame('escalate', $r['outcome']);
        $this->assertSame('obligation_unmet', $r['status']);
    }
}
