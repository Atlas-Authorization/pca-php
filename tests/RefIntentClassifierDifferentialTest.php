<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentClassifier;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Classifier error in the residual risk against the TS reference: test-data/ref-intent-classifier.json.gz (confusion calibration, digest,
 * published error rate, card note, the explicit-array risk and bounds, the classifier-aware residual risk of a learner, the JIT gate).
 * Doubles are compared to 1e-12 relative.
 */
final class RefIntentClassifierDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-classifier.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function learner(array $a): \Atlas\Pca\IntentLearner
    {
        $l = IntentMapKit::createLearner(WalletOmega::plain($a[0]), WalletOmega::plain($a[1]));
        foreach (WalletOmega::plain($a[2]) as $x) {
            $src = $x->get('source');
            $l->observe(Obj::of(['verb' => $x->get('verb'), 'values' => $x->get('values')]), (int)\Atlas\Pca\Js::num($x->get('y')), is_string($src) ? $src : 'elicitation', $x->get('region'));
        }
        return $l;
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        $p = static fn($x) => WalletOmega::plain($x);
        Base::run($file, $fn, $k, [
            'calibrate' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(
                IntentClassifier::calibrateConfusion($p($a[0]), $p($a[1]), array_key_exists(2, $a) ? $p($a[2]) : 0.05), $c),
            'confusionDigest' => static fn(array $a) => IntentClassifier::confusionDigest($p($a[0])),
            'publishedErrorRate' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(IntentClassifier::publishedErrorRate($p($a[0])), $c),
            'classifierCardNote' => static fn(array $a) => IntentClassifier::classifierCardNote($a[0], $p($a[1])),
            'riskArrays' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(match ($a[0]) {
                'risk' => IntentClassifier::classifierRisk($p($a[1])),
                'sound' => IntentClassifier::labelSound($p($a[1])),
                default => IntentClassifier::labelSoundBound($p($a[1]), $p($a[2])),
            }, $c),
            'awareScenario' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(IntentClassifier::classifierAwareResidualRisk(self::learner($a), $p($a[3])), $c),
            'jitScenario' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(IntentClassifier::classifierJitCells(self::learner($a), $p($a[3]), $p($a[4])), $c),
        ]);
    }
}
