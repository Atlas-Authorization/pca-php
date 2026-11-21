<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentLearner;
use Atlas\Pca\IntentPolicy;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The intent learner against the TS reference: test-data/ref-intent-learner.json.gz (scenario scripts over box / union / decision-list
 * classes and every option, elicit, audit, boxesToPredicates, hypothesisCellSets, hypothesisClassName). Doubles from transcendental
 * functions are compared to 1e-12 relative.
 */
final class RefIntentLearnerDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-learner.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'scenario' => static fn(array $a, Obj $c) => RefWalletDifferentialTest::close(self::scenario($a), $c),
            'boxesToPredicates' => static fn(array $a) => IntentLearner::boxesToPredicates(WalletOmega::plain($a[0]), WalletOmega::plain($a[1])),
            'hypothesisCellSets' => static function (array $a, Obj $c) {
                $r = IntentLearner::hypothesisCellSets(WalletOmega::plain($a[0]), WalletOmega::plain($a[1] ?? null), WalletOmega::plain($a[2] ?? null));
                return $c->get('out') instanceof Obj ? $r : count($r['sets']);
            },
            'hypothesisClassName' => static fn(array $a) => IntentLearner::hypothesisClassName(WalletOmega::plain($a[0])),
        ]);
    }

    public static function options(Obj $opts): array
    {
        $o = [];
        foreach ($opts->keys() as $k) {
            $o[$k] = $opts->get($k);
        }
        if (($o['nullMassFn'] ?? null) === 'byRev') {
            $o['nullMass'] = static fn($vs) => Js::opt($vs, 'reversibility') === 'reversible' ? 0.1 : 0.3;
        }
        unset($o['nullMassFn']);
        if (isset($o['priorMix'])) {
            $kind = $o['priorMix']->get('weight');
            $wt = match ($kind) {
                'size' => static function ($vs, \Closure $has): int {
                    $k = 1;
                    for ($c = 0; $c < 64; $c++) {
                        if ($has($c)) {
                            $k++;
                        }
                    }
                    return $k;
                },
                'neg' => static fn() => -1,
                default => static fn() => 0,
            };
            $o['priorMix'] = ['beta' => $o['priorMix']->get('beta'), 'weight' => $wt];
        }
        return $o;
    }

    /** The question as the oracle serialises it. */
    private static function jqo(?array $q): ?array
    {
        if ($q === null) {
            return null;
        }
        return ['verb' => $q['verb'], 'cell' => $q['cell'], 'outcome' => $q['outcome'], 'p' => $q['p'], 'score' => $q['score']];
    }

    private static function scenario(array $a): array
    {
        $omega = WalletOmega::plain($a[0]);
        $opts = $a[1];
        $lopts = self::options(WalletOmega::plain($opts));
        $l = new IntentLearner($omega, $lopts);
        $out = [];
        foreach ($a[2] as $op) {
            $op = WalletOmega::plain($op);
            switch ($op->get('op')) {
                case 'observe':
                    $out[] = $l->observe(Obj::of(['verb' => $op->get('verb'), 'values' => $op->get('values')]), (int)$op->get('y'), $op->has('source') && $op->get('source') !== null ? $op->get('source') : 'elicitation', $op->get('region'));
                    break;
                case 'probe':
                    $oc = Obj::of(['verb' => $op->get('verb'), 'values' => $op->get('values')]);
                    $out[] = [$l->acceptance($oc), $l->admitsOutcome($oc), $l->isVetoed($oc)];
                    break;
                case 'next':
                    $out[] = self::jqo($l->nextQuestion());
                    break;
                case 'metrics':
                    $out[] = $l->metrics();
                    break;
                case 'cells':
                    $out[] = $l->cells();
                    break;
                case 'unconfirmed':
                    $out[] = $l->unconfirmedGrantCells();
                    break;
                case 'synth':
                    $out[] = $l->synthesize();
                    break;
                case 'vetoed':
                    $out[] = $l->vetoedCells();
                    break;
                case 'observations':
                    $out[] = $l->observations;
                    break;
                case 'replay':
                    $out[] = IntentLearner::replay($omega, $lopts, $l->observations)->metrics();
                    break;
                case 'elicit':
                    $adm = IntentPolicy::admitter($op->get('policy'));
                    $k = 0;
                    $flip = $op->get('flipEvery');
                    $ans = static function (array $q) use ($omega, $adm, &$k, $flip): int {
                        $vs = null;
                        foreach ($omega->get('verbs') as $v) {
                            if ($v->get('verb') === $q['verb']) {
                                $vs = $v;
                                break;
                            }
                        }
                        $y = $adm->admits($vs, $q['outcome']) ? 1 : 0;
                        $k++;
                        return Js::truthy($flip) && $k % $flip === 0 ? 1 - $y : $y;
                    };
                    $eo = [];
                    foreach (['epsRisk', 'epsBurden', 'maxQuestions', 'audit', 'seed'] as $f) {
                        $eo[$f] = $op->get($f);
                    }
                    $r = IntentLearner::elicit($l, $ans, $eo);
                    $out[] = ['stop' => $r['stop'], 'questions' => $r['questions'], 'auditQuestions' => $r['auditQuestions'], 'seedQuestions' => $r['seedQuestions'],
                        'asked' => array_map(self::jqo(...), $r['asked']), 'metrics' => $l->metrics()];
                    break;
                default:
                    throw new \RuntimeException('bad op');
            }
        }
        return $out;
    }
}
