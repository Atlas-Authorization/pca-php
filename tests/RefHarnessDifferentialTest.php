<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Harness;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The attested orchestration harness (plan inclusion, taint fold, trust budget, signing; the allowlisting verifier) against the TS reference: test-data/ref-harness.json.gz. */
final class RefHarnessDifferentialTest extends TestCase
{
    private const FILE = 'ref-harness.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function scenario(Obj $spec): Obj
    {
        $op = $spec->get('opts');
        $t = 1_800_000_000_000;
        $k = 0;
        try {
            $h = new Harness(
                $op->get('grant'), hash('sha256', 'atlas-pca-conformance/' . $op->get('label'), true), $op->get('plan'), $op->get('audience'), $op->get('budget'),
                $op->has('chain') ? $op->get('chain') : null, $op->has('policy') ? $op->get('policy') : null, $op->has('baseRisk') ? $op->get('baseRisk') : null,
                static function () use (&$t): int {
                    return $t;
                },
                $op->has('ttlMs') ? (int)$op->get('ttlMs')->float() : null, $op->has('manifest') ? $op->get('manifest') : null,
                static function () use (&$k): string {
                    return 'n' . $k++;
                },
                $op->has('attestation') ? $op->get('attestation') : null
            );
        } catch (\Throwable) { // a refused construction is the reference's {$err}
            return Obj::of(['$err' => true]);
        }
        $outs = [];
        foreach ($spec->get('steps') as $st) {
            if ($st->get('op') === 'now') {
                $t = (int)$st->get('t')->float();
                $outs[] = null;
                continue;
            }
            $orc = $st->get('oracle');
            $outs[] = $h->step(static function () use ($orc) {
                if ($orc->get('kind') === 'throw') {
                    throw new \Exception((string)$orc->get('msg'));
                }
                return $orc->get('kind') === 'bad' ? $orc->get('v') : $orc->get('c');
            });
        }
        return Obj::of(['steps' => $outs, 'budget' => $h->budget(), 'counter' => $h->counter(), 'planRoot' => $h->planRoot(), 'measurement' => $h->harnessMeasurement()]);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'consts' => fn(array $a) => ['HARNESS_VERSION' => Harness::HARNESS_VERSION, 'HARNESS_MODEL_ID' => Harness::HARNESS_MODEL_ID, 'ENFORCED_CHECKS' => Harness::ENFORCED_CHECKS],
            // JSON cannot carry an undefined argument: that case reaches PHP as null, which the reference never saw
            'computeHarnessMeasurement' => function (array $a, Obj $c) {
                if (str_starts_with((string)$c->get('name'), 'undefined-checks')) {
                    return [Base::SKIP, 'undefined argument'];
                }
                return Harness::computeHarnessMeasurement(...$a);
            },
            'harnessAttest' => fn(array $a) => (Harness::createHarnessAttestationVerifier($a[0]))($a[1]),
            'harness' => fn(array $a) => self::scenario($a[0]),
        ]);
    }
}
