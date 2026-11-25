<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentTrajectory;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Trajectory intent (augmented space, lift, step rule, default accumulators) against the TS reference: test-data/ref-intent-trajectory.json.gz. */
final class RefIntentTrajectoryDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-trajectory.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function lift(array $a): Obj
    {
        $tilde = IntentTrajectory::augmentOmega($a[0], $a[1], $a[2]);
        $lifted = IntentTrajectory::liftAction($tilde, $a[1], $a[3], $a[4], $a[5] ?? null);
        $c = $lifted !== null ? IntentTrajectory::liftedCell($tilde, $lifted) : null;
        return Obj::of(['lifted' => $lifted, 'cell' => $c === null ? null : Obj::of(['verb' => Js::opt($c['vs'], 'verb'), 'cell' => $c['cell']])]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $grants = [
            'all' => fn(string $v, array $c) => true,
            'none' => fn(string $v, array $c) => false,
            'cell0' => fn(string $v, array $c) => count(array_filter($c, fn($x) => $x !== 0)) === 0,
            'firstLow' => fn(string $v, array $c) => $c[0] <= 1,
        ];
        Base::run($file, $fn, $k, [
            'dimKindOf' => fn(array $a) => IntentTrajectory::dimKindOf($a[0]),
            'accDimPath' => fn(array $a) => IntentTrajectory::accDimPath($a[0]),
            'monDimPath' => fn(array $a) => IntentTrajectory::monDimPath($a[0]),
            'trajectoryHarmRange' => fn(array $a) => IntentTrajectory::trajectoryHarmRange($a[0], $a[1]),
            'augment' => fn(array $a) => IntentTrajectory::augmentOmega($a[0], $a[1], $a[2] ?? null),
            'liftScenario' => fn(array $a) => self::lift($a),
            'stepScenario' => function (array $a) use ($grants): array {
                $tilde = IntentTrajectory::augmentOmega($a[0], $a[1], $a[2]);
                return IntentTrajectory::stepTrajectory($tilde, $a[1], $a[3], $a[4], $grants[$a[5]], $a[6] ?? null);
            },
            'defaultAccumulators' => fn(array $a) => IntentTrajectory::defaultAccumulators($a[0], $a[1]),
            'describeAccCell' => fn(array $a) => IntentTrajectory::describeAccCell($a[0], $a[1], $a[2], $a[3] ?? null,
                ($a[4] ?? 'plain') === 'bracket' ? fn($x) => '[' . \Atlas\Pca\Js::str($x) . ']' : null),
        ]);
    }
}
