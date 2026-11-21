<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentLearner;
use Atlas\Pca\IntentMapKit;
use Atlas\Pca\IntentOmega;
use Atlas\Pca\IntentPolicy;
use Atlas\Pca\IntentRefine;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Cut refinement, partial answers and adaptive elicitation against the TS reference: test-data/ref-intent-refine.json.gz. */
final class RefIntentRefineDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-refine.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function mk(mixed $omega, mixed $mapOpts, mixed $observations): IntentLearner
    {
        $l = IntentMapKit::createLearner($omega, $mapOpts);
        foreach ($observations as $x) {
            $l->observe(Obj::of(['verb' => Js::opt($x, 'verb'), 'values' => Js::opt($x, 'values')]), (int)Js::num(Js::opt($x, 'y')), (string)Js::opt($x, 'source'), Js::opt($x, 'region'));
        }
        return $l;
    }

    private static function cellsOf(IntentLearner $l): array
    {
        return array_map(static fn(array $c) => ['verb' => $c['verb'], 'cell' => $c['cell'], 'p' => $c['p']], $l->cells());
    }

    private static function vsOf(mixed $omega, mixed $verb): mixed
    {
        foreach (Js::opt($omega, 'verbs') as $v) {
            if (Js::opt($v, 'verb') === $verb) {
                return $v;
            }
        }
        return null;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $P = static fn($x) => WalletOmega::plain($x);
        Base::run($file, $fn, $k, [
            'refineOmega' => fn(array $a) => IntentRefine::refineOmega($a[0], $a[1]),
            'regionsOf' => function (array $a) use ($P) {
                $omega = $P($a[0]);
                $l = self::mk($omega, $P($a[1]), $P($a[2]));
                $base = $l->omega;
                if ($a[3] === true) {
                    $base = Obj::of(['v' => Js::opt($omega, 'v'), 'verbs' => [], 'approximate' => Js::opt($omega, 'approximate')]);
                }
                return array_map(static fn($o) => IntentRefine::regionOfObservation($base, $o), $l->observations);
            },
            'refineScenario' => function (array $a, Obj $c) use ($P) {
                $l = self::mk($P($a[0]), $P($a[1]), $P($a[2]));
                $nl = IntentRefine::refineLearner($l, $a[3]);
                return RefIntentRound::close(['omega' => $nl->omega, 'observations' => $nl->observations, 'metrics' => $nl->metrics(), 'cells' => self::cellsOf($nl)], $c);
            },
            'partialScenario' => function (array $a, Obj $c) use ($P) {
                $omega = $P($a[0]);
                $l = self::mk($omega, $P($a[1]), $P($a[2]));
                $q = $P($a[3]);
                $svs = self::vsOf($omega, Js::opt($q, 'verb'));
                if ($svs === null) {
                    throw new \TypeError('no verb space');
                }
                $oc = IntentOmega::cellRep($svs, Js::opt($q, 'cell'));
                $r = IntentRefine::answerPartial($l, Obj::of(['verb' => Js::opt($q, 'verb'), 'cell' => Js::opt($q, 'cell'), 'outcome' => $oc, 'p' => $l->acceptance($oc), 'score' => 0]), $a[4]);
                return RefIntentRound::close(['omega' => $r['learner']->omega, 'added' => $r['added'], 'observations' => $r['learner']->observations,
                    'metrics' => $r['learner']->metrics(), 'synth' => $r['learner']->synthesize()], $c);
            },
            'adaptiveScenario' => function (array $a, Obj $c) use ($P) {
                $omega = $P($a[0]);
                $partials = $P($a[3]);
                $every = (int)Js::num($a[4]);
                $adm = IntentPolicy::admitter($a[2]);
                $n = 0;
                $pi = 0;
                $answer = static function (array $q, IntentLearner $l) use (&$n, &$pi, $partials, $every, $adm) {
                    $n++;
                    if ($n % $every === 0 && $pi < count($partials) && $q['verb'] === 'stripe.refund') {
                        return $partials[$pi++];
                    }
                    return $adm->admits(self::vsOf($l->omega, $q['verb']), $q['outcome']) ? 1 : 0;
                };
                $o = Obj::of(['epsRisk' => 0.001, 'epsBurden' => 0.01, 'maxQuestions' => 25]);
                $extra = $P($a[5]);
                foreach ($extra instanceof Obj ? $extra->keys() : [] as $key) {
                    $o->set($key, $extra->get($key));
                }
                $r = IntentRefine::elicitAdaptive(IntentMapKit::createLearner($omega, $P($a[1])), $answer, $o);
                return RefIntentRound::close(['stop' => $r['stop'], 'questions' => $r['questions'], 'auditQuestions' => $r['auditQuestions'],
                    'seedQuestions' => $r['seedQuestions'], 'refinements' => $r['refinements'],
                    'asked' => array_map(static fn(array $q) => ['verb' => $q['verb'], 'cell' => $q['cell'], 'outcome' => $q['outcome'], 'p' => $q['p'], 'score' => $q['score']], $r['asked']),
                    'omega' => $r['learner']->omega, 'metrics' => $r['learner']->metrics(), 'observations' => $r['learner']->observations], $c);
            },
        ]);
    }
}
