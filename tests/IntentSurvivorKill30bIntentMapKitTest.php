<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 30b mutation kill for src/IntentMapKit.php: the population weight's log sum starts at 0 (weight exp(sum), not e * exp(sum)). */
final class IntentSurvivorKill30bIntentMapKitTest extends TestCase
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

    /**
     * 1076 cells with q = 1/2: every hypothesis has log weight 1076 ln(1/2) ~ -745.83, below detExp's underflow (-745.2), so every
     * population weight is 0 and the prior is left as it is (acceptance 0.8 from the null mass 0.2). Starting the sum at 1 instead
     * gives ~ -744.83, whose exp is the smallest subnormal: the weights would then be equal and non-zero and mix the prior to 0.65.
     */
    public function testUnderflowedPopulationLeavesThePrior(): void
    {
        $vs = Obj::of(['verb' => 'x.do', 'reversibility' => 'reversible', 'weight' => 1, 'dims' => []]);
        $omega = Obj::of(['v' => 1, 'approximate' => [], 'verbs' => [$vs]]);
        $cells = array_fill(0, 1076, ['verb' => 'x.do', 'cell' => 0, 'q' => 0.5]);
        $l = IntentMapKit::createLearner($omega, ['priorMix' => ['beta' => 0.5, 'cells' => $cells]]);
        $this->assertEqualsWithDelta(0.8, $l->acceptance(IntentOmega::cellRep($vs, [])), 1e-12);
        $c = IntentMapKit::createLearner($omega, ['priorMix' => ['beta' => 0.5, 'cells' => array_slice($cells, 0, 1)]]);
        $this->assertEqualsWithDelta(0.65, $c->acceptance(IntentOmega::cellRep($vs, [])), 1e-12, 'control: equal non-zero weights mix to 0.65');
    }
}
