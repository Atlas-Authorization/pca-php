<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentClassifier.php';

use Atlas\Pca\IntentClassifier;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Group 31 survivors of classifier.ts: calibration refusals, the digest model, the classifier-aware risk and the JIT cells. */
final class MathSurvivorKill31IntentClassifierTest extends TestCase
{
    private static function err(string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\InvalidArgumentException $e) {
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("no InvalidArgumentException ($msg)");
    }

    /** Each calibration refusal carries its message; delta 0 is refused. */
    public function testCalibrationRefusals(): void
    {
        self::err('calibrateConfusion: empty label set', fn() => IntentClassifier::calibrateConfusion([], []));
        self::err('calibrateConfusion: delta must be in (0, 1)', fn() => IntentClassifier::calibrateConfusion([], ['a'], 0));
        self::err('calibrateConfusion: label outside L (x / a)', fn() => IntentClassifier::calibrateConfusion([['truth' => 'x', 'predicted' => 'a']], ['a']));
    }

    /** delta_ppm is the integer Math.round(delta * 10^6). */
    public function testDeltaPpm(): void
    {
        self::assertSame(900000, IntentClassifier::calibrateConfusion([], ['a'], 0.9)['delta_ppm']);
    }

    /** The digest model writes every number as the reference's number, also an integral float of 10^15 or more and one inside a list. */
    public function testDigestModel(): void
    {
        $c = ['labels' => ['a'], 'counts' => [[1e15, 2.5, 1.0]], 'delta_ppm' => -0.0];
        $want = Pca::hashCanonical(Obj::of(['d' => 'atlas-pca/intent-classifier-calibration/v1', 'labels' => ['a'],
            'counts' => [[new Num('1000000000000000'), new Num('2.5'), new Num('1')]], 'delta_ppm' => new Num('0')]));
        self::assertSame($want, IntentClassifier::confusionDigest($c));
        self::err('non-finite number', fn() => IntentClassifier::confusionDigest(['labels' => ['a'], 'counts' => [[INF]], 'delta_ppm' => 1]));
    }

    private static function learner(array $omega, array $cells): object
    {
        return new class($omega, $cells) {
            public function __construct(public mixed $omega, private array $c)
            {
            }

            public function cells(): array
            {
                return $this->c;
            }
        };
    }

    /** v: kind (a, b exact labels; c exact but uncalibrated; o not exact) x region (p, q) x a non-categorical dimension sharing the path; then a second v entry. */
    private static function omega(): array
    {
        $kind = ['path' => 'kind', 'kind' => 'cat', 'values' => [['kind' => 'exact', 'value' => 'a'], ['kind' => 'exact', 'value' => 'b'], ['kind' => 'exact', 'value' => 'c'], ['kind' => 'other']]];
        $region = ['path' => 'region', 'kind' => 'cat', 'values' => [['kind' => 'exact', 'value' => 'p'], ['kind' => 'exact', 'value' => 'q']]];
        $shadow = ['path' => 'kind', 'kind' => 'list', 'values' => [['kind' => 'exact', 'value' => 'z']]];
        return ['verbs' => [['verb' => 'v', 'dims' => [$kind, $region, $shadow]], ['verb' => 'v', 'dims' => []]]];
    }

    private static function spec(string $verb = 'v', string $path = 'kind'): array
    {
        return ['verb' => $verb, 'path' => $path, 'cal' => ['labels' => ['a', 'b'], 'gammaBar' => [[0.25, 0.125], [0.0625, 0.5]]]];
    }

    private static function cell(string $verb, array $cell, bool $in, float $mass = 1.0, float $p = 0.0, float $harm = 1.0): array
    {
        return ['verb' => $verb, 'cell' => $cell, 'p' => $p, 'mass' => $mass, 'harm' => $harm, 'inGrant' => $in];
    }

    /** A wrong verb or path is refused with its message (the first Omega entry and the first dimension with the path count). */
    public function testGroupRefusals(): void
    {
        $l = self::learner(self::omega(), []);
        self::err("classifier: no verb zz in \u{03A9}", fn() => IntentClassifier::classifierAwareResidualRisk($l, [self::spec('zz')]));
        self::err('classifier: v has no categorical dimension nope', fn() => IntentClassifier::classifierAwareResidualRisk($l, [self::spec('v', 'nope')]));
        self::assertSame(0.0, IntentClassifier::classifierAwareResidualRisk($l, [self::spec()])['perVerb']->get('v'));
    }

    /**
     * Every kind cell admitted: a true a sums 0.25 + 0.125 (an uncalibrated or non-exact predicted label adds 0), a true b 0.0625 + 0.5,
     * a true label without a calibrated row is capped at 1. Another verb adds mass x (1 - p) x harm per admitted cell, in cell order.
     */
    public function testAwareResidualRisk(): void
    {
        $cells = [];
        foreach ([0, 1, 2, 3] as $i) {
            $cells[] = self::cell('v', [$i, 0, 0], true);
        }
        $cells[] = self::cell('w', [0], true, 1.0, 0.5, 2.0);
        $cells[] = self::cell('w', [1], true, 0.5, 0.5, 2.0);
        $cells[] = self::cell('w', [2], false, 4.0, 0.5, 2.0);
        $r = IntentClassifier::classifierAwareResidualRisk(self::learner(self::omega(), $cells), [self::spec()]);
        self::assertSame(['w', 'v'], $r['perVerb']->keys());
        self::assertSame([1.5, 2.9375], [$r['perVerb']->get('w'), $r['perVerb']->get('v')]);
        self::assertSame(4.4375, $r['total']);
    }

    /** Admitted a cells whose unadmitted b neighbour is mislabelled above gamma_max go to JIT, sorted by flat index (region q came first). */
    public function testJitCellsSorted(): void
    {
        $cells = [];
        foreach ([1, 0] as $reg) {
            $cells[] = self::cell('v', [0, $reg, 0], true);
            $cells[] = self::cell('v', [1, $reg, 0], false);
        }
        $out = IntentClassifier::classifierJitCells(self::learner(self::omega(), $cells), self::spec(), 0.05);
        self::assertSame([['verb' => 'v', 'cell' => [0, 0, 0], 'flat' => 0], ['verb' => 'v', 'cell' => [0, 1, 0], 'flat' => 1]], $out);
    }
}
