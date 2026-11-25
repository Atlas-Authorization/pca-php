<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentDriftDetector;
use Atlas\Pca\IntentEffects;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentObservation;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentRamp;
use Atlas\Pca\IntentRuntime;
use Atlas\Pca\IntentTrustRamp;
use Atlas\Pca\IntentUx;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Runtime digests, effect postconditions, the trust ramp's drift detector and the question cards against the TS reference:
 * test-data/ref-intent-runtime.json.gz; the ramp scenarios (record / observe / rebase / state ops) and the signed observation sign / verify functions from ref-intent-ramp.json.gz (the signing keys are "$seed:<label>" placeholders: sha256("atlas-pca-conformance/" + label)). The learner-bound
 * functions take a stub learner in the reference ({omega, acceptance}); the native takes (verb space, outcome, p).
 */
final class RefIntentRuntimeDifferentialTest extends TestCase
{
    public static function provide(): array
    {
        return Base::datasets('ref-intent-runtime.json.gz');
    }

    #[DataProvider('provide')]
    public function testRuntimeAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $vsOf = static fn($omega, $o) => IntentOmega::verbSpace($omega, Js::opt($o, 'verb'));
        Base::run($file, $fn, $k, [
            'pcactnActionOf' => fn(array $a) => IntentRuntime::pcactnActionOf($a[0], $a[1]),
            'judgeInputOf' => fn(array $a) => IntentRuntime::judgeInputOf($vsOf($a[0], $a[1]), $a[1], $a[2], $a[3]),
            'jitConsentRequest' => fn(array $a) => IntentRuntime::jitConsentRequest($vsOf($a[0], $a[1]), $a[1], $a[2], Js::opt($a[3], 'intentRef'), Js::opt($a[3], 'mapDigest')),
            'jitConsentDigest' => fn(array $a) => IntentRuntime::jitConsentDigest($a[0]),
            'calibrationDigest' => fn(array $a) => IntentRuntime::calibrationDigest($a[0]),
            'icAttDigest' => fn(array $a) => IntentRuntime::icAttDigest($a[0]),
            'foldSemanticRisk' => fn(array $a) => IntentRuntime::foldSemanticRisk($a[0], $a[1]),
            'defaultPostconditions' => fn(array $a) => IntentEffects::defaultPostconditions(),
            'effectContext' => fn(array $a) => IntentEffects::effectContext($a[0], $a[1], $a[2]),
            'checkPostconditions' => fn(array $a) => IntentEffects::checkPostconditions($a[0], $a[1], $a[2], $a[3] ?? null),
            'signalLabel' => fn(array $a) => IntentRamp::signalLabel($a[0]),
            'narrowStart' => fn(array $a) => IntentRamp::narrowStart($a[0], $a[1], $a[2] ?? null),
            'driftRun' => function (array $a, Obj $c) {
                $d = new IntentDriftDetector($a[0]);
                $out = [];
                foreach ($a[1] as $x) {
                    $out[] = $d->update($x === true);
                }
                $out[] = $d->state();
                $d->reset();
                $out[] = $d->state();
                return $out; // the drift statistic gates a freeze: exact
            },
            'questionCard' => fn(array $a) => IntentUx::questionCard($a[0], $a[1]),
            'parseCardAnswer' => fn(array $a) => IntentUx::parseCardAnswer($a[0], $a[1]),
        ]);
    }

    public static function provideRamp(): array
    {
        return Base::datasets('ref-intent-ramp.json.gz');
    }

    private static function learner(mixed $omega, mixed $mapOpts, mixed $observations): \Atlas\Pca\IntentLearner
    {
        $l = IntentMapKit::createLearner($omega, $mapOpts);
        foreach ($observations as $x) {
            $l->observe(Obj::of(['verb' => Js::opt($x, 'verb'), 'values' => Js::opt($x, 'values')]), (int)Js::num(Js::opt($x, 'y')), (string)Js::opt($x, 'source'));
        }
        return $l;
    }

    #[DataProvider('provideRamp')]
    public function testRampAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'signObservation' => static function (array $a) {
                return IntentObservation::sign($a[0], Base::seedBytes($a[1]));
            },
            'verifyObservation' => static fn(array $a) => IntentObservation::verify($a[0], $a[1]),
            'rampScenario' => function (array $a, Obj $c) {
                $a = WalletOmega::plain($a);
                $ramp = new IntentTrustRamp(self::learner($a[0], $a[1], $a[2]), $a[3]);
                $out = [];
                $live = []; // the state entries of the current pending array; a rebase replaces that array, so they keep the list as it ended there
                $settle = static function () use (&$out, &$live, $ramp): void {
                    foreach ($live as $i) {
                        $out[$i]['pending'] = $ramp->pending();
                        unset($out[$i]['_live']);
                    }
                    $live = [];
                };
                foreach ($a[4] as $op) {
                    $kind = Js::opt($op, 'op');
                    if ($kind === 'record') {
                        $out[] = $ramp->record(Js::opt($op, 'outcome'), Js::opt($op, 'signal'));
                    } elseif ($kind === 'observe') {
                        $out[] = $ramp->recordObservation(Js::opt($op, 'obs'), Js::opt($op, 'ctx'));
                    } elseif ($kind === 'rebase') {
                        $settle();
                        $ramp->rebase(self::learner(Js::opt($op, 'omega'), Js::opt($op, 'mapOpts'), Js::opt($op, 'observations')));
                        $out[] = ['frozen' => $ramp->frozen(), 'pending' => count($ramp->pending())];
                    } else {
                        $live[] = count($out);
                        $out[] = ['frozen' => $ramp->frozen(), 'pending' => $ramp->pending(), 'drift' => $ramp->drift->state(), '_live' => true];
                    }
                }
                // the reference hands out its live pending array: every state entry is serialized with the list as it ends
                $settle();
                return [$out, ['log' => $ramp->log, 'frozen' => $ramp->frozen(), 'pending' => $ramp->pending(), 'metrics' => $ramp->learner()->metrics()]]; // drift statistics and the freeze decision: exact
            },
        ]);
    }
}
