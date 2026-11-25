<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentWorld;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The intent outcome space and its world dimensions against the TS reference: test-data/ref-intent-omega.json.gz and
 * ref-intent-world.json.gz. The policy / slots / region functions of the omega corpus belong to the policy and region modules.
 */
final class RefIntentOmegaDifferentialTest extends TestCase
{
    public static function provide(): array
    {
        return Base::datasets('ref-intent-omega.json.gz');
    }

    #[DataProvider('provide')]
    public function testOmegaAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $r = static fn(callable $f) => static fn(array $a, Obj $c) => RefIntentRound::close($f($a), $c);
        $rcell = static fn($f) => static fn(array $a) => $f($a);
        $skip = static fn() => [Base::SKIP, 'policy / slots / region module'];
        Base::run($file, $fn, $k, [
            'deriveOmega' => fn(array $a) => IntentOmega::deriveOmega($a[0]),
            'numCells' => fn(array $a) => IntentOmega::numCells($a[0]),
            'cellCount' => fn(array $a) => IntentOmega::cellCount($a[0]),
            'verbCellCount' => fn(array $a) => IntentOmega::verbCellCount($a[0]),
            'decodeCell' => fn(array $a) => IntentOmega::decodeCell($a[0], $a[1]),
            'encodeCell' => fn(array $a) => IntentOmega::encodeCell($a[0], $a[1]),
            'catCellOf' => fn(array $a) => IntentOmega::catCellOf($a[0], $a[1]),
            'cellOfValue' => fn(array $a) => IntentOmega::cellOfValue($a[0], $a[1]),
            'cellOf' => fn(array $a) => IntentOmega::cellOf($a[0], $a[1]),
            'catRep' => fn(array $a) => IntentOmega::catRep($a[0], $a[1]),
            'numRep' => fn(array $a) => IntentOmega::numRep($a[0], $a[1]),
            'repValue' => fn(array $a) => IntentOmega::repValue($a[0], $a[1]),
            'cellRep' => fn(array $a) => IntentOmega::cellRep($a[0], $a[1]),
            'seeded' => fn(array $a) => IntentOmega::cellRep($a[0], $a[1]),
            'verbSpace' => fn(array $a) => IntentOmega::verbSpace($a[0], $a[1]),
            'harmMax' => $r(fn(array $a) => IntentOmega::harmMax($a[0])),
            'intervalWeight' => $r(fn(array $a) => IntentOmega::intervalWeight($a[0], $a[1], $a[2])),
            'dimCellStats' => $r(fn(array $a) => IntentOmega::dimCellStats($a[0], $a[1])),
            'cellStats' => $r(fn(array $a) => IntentOmega::cellStats($a[0], $a[1])),
            'harmOf' => $r(fn(array $a) => IntentOmega::harmOf($a[0], $a[1])),
            'rngSeq' => function (array $a) {
                $g = IntentOmega::rng(Js::num($a[0]));
                return array_map(static fn() => $g(), range(1, (int)Js::num($a[1])));
            },
            'sampleOutcomes' => function (array $a) {
                $g = IntentOmega::rng(Js::num($a[1]));
                $out = [];
                for ($i = 0, $n = (int)Js::num($a[2]); $i < $n; $i++) {
                    $out[] = IntentOmega::sampleOutcome($a[0], $g)[1];
                }
                return $out;
            },
            'normalizePolicy' => $skip, 'slotsToPolicy' => $skip, 'outcomeToAction' => $skip, 'admits' => $skip,
            'regionOfCell' => $skip, 'regionCells' => $skip, 'valueInRegionDim' => $skip, 'restrictRegion' => $skip, 'dimCellsIn' => $skip,
        ]);
    }

    public static function provideWorld(): array
    {
        return Base::datasets('ref-intent-world.json.gz');
    }

    #[DataProvider('provideWorld')]
    public function testWorldAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'worldDim' => fn(array $a) => IntentWorld::worldDim($a[0], $a[1]),
            'excessDim' => fn(array $a) => IntentWorld::excessDim($a[0], $a[1], $a[2] ?? null),
            'optimalityCondition' => fn(array $a) => count($a) > 1 ? IntentWorld::optimalityCondition($a[0], $a[1]) : IntentWorld::optimalityCondition($a[0]),
            'provenanceDim' => fn(array $a) => IntentWorld::provenanceDim($a[0]),
            'classifierDim' => fn(array $a) => IntentWorld::classifierDim($a[0], $a[1]),
            'withDims' => fn(array $a) => IntentWorld::withDims($a[0], $a[1], $a[2]),
            'liftOutcome' => fn(array $a) => IntentWorld::liftOutcome($a[0], $a[1], $a[2]),
        ]);
    }
}
