<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentFrames;
use Atlas\Pca\IntentLearner;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Frame and side-effect constraints against the TS reference: test-data/ref-intent-frames.json.gz. */
final class RefIntentFramesDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-frames.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'stateDigest' => fn(array $a) => IntentFrames::stateDigest($a[0]),
            'snapshotState' => fn(array $a) => IntentFrames::snapshotState($a[0], $a[1] ?? true),
            'checkFrame' => function (array $a): Obj {
                $r = IntentFrames::checkFrame($a[0], $a[1], $a[2], $a[3], $a[4] ?? null);
                // the oracle keeps only the argument-validation message; any other thrown text compares as "error: error"
                $r->set('missing', array_map(fn($m) => str_starts_with($m, 'error: ') && !str_starts_with($m, 'error: spec, action') ? 'error: error' : $m, $r->get('missing')));
                return $r;
            },
            'applyScenario' => function (array $a): array {
                $l = new IntentLearner(WalletOmega::plain($a[0]), $a[1] instanceof Obj ? RefIntentLearnerDifferentialTest::options(WalletOmega::plain($a[1])) : $a[1]);
                foreach ($a[2] as $x) {
                    $x = WalletOmega::plain($x);
                    $l->observe(Obj::of(['verb' => $x->get('verb'), 'values' => $x->get('values')]), (int)\Atlas\Pca\Js::num($x->get('y')), (string)$x->get('source'));
                }
                return ['result' => IntentFrames::applyFrameReport($l, WalletOmega::plain($a[3]), $a[4]), 'metrics' => $l->metrics()];
            },
        ]);
    }
}
