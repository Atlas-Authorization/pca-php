<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ControlBlue;
use Atlas\Pca\ControlEnv;
use Atlas\Pca\ControlEvals;
use Atlas\Pca\Obj;
use Atlas\Pca\RedPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The empirical control-evaluation harness against the TS reference: test-data/ref-control-evals.json.gz (blue decisions are replayed from the reference's recordings). */
final class RefControlEvalsDifferentialTest extends TestCase
{
    private const FILE = 'ref-control-evals.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function red(string $name): RedPolicy
    {
        return match ($name) {
            'over-cap' => ControlEvals::overCapRed(), 'off-verb' => ControlEvals::offVerbRed(), 'slow-burn' => ControlEvals::slowBurnRed(),
            'taint-exfil' => ControlEvals::taintExfilRed(), 'replay' => ControlEvals::replayRed(), 'immune-probe' => ControlEvals::immuneProbeBurstRed(),
            'benign' => ControlEvals::benignBaselineRed(), 'gap-exploit' => ControlEvals::gapExploitRed(),
        };
    }

    private static function env(string $name): ControlEnv
    {
        if ($name === 'example') {
            return ControlEvals::exampleEnv();
        }
        return $name === 'gap-aware' ? ControlEvals::gapAwareEnv() : ControlEvals::gapAwareEnv(substr($name, strlen('gap-aware:')));
    }

    private static function stub(Obj $spec, array $recs): ControlBlue
    {
        return new class($spec, $recs) extends ControlBlue {
            /** @param list<Obj> $recs */
            public function __construct(Obj $spec, private array $recs)
            {
                $this->startMs = $spec->get('startMs')->float();
                $this->stepMs = $spec->get('stepMs')->float();
                $this->analyticBound = $spec->get('analyticBound');
            }

            public function newEpisode(): object
            {
                $rec = array_shift($this->recs);
                return new class($rec) {
                    private int $i = -1;

                    public function __construct(private Obj $rec)
                    {
                    }

                    public function decide(mixed $action, mixed $at): Obj
                    {
                        $this->i++;
                        return $this->rec->get('steps')[$this->i]->without('money');
                    }

                    public function moneyAmount(mixed $action): mixed
                    {
                        return $this->rec->get('steps')[$this->i]->get('money');
                    }

                    public function endBudget(): mixed
                    {
                        return $this->rec->get('endBudget');
                    }
                };
            }
        };
    }

    private static function episode(Obj $spec): Obj
    {
        return ControlEvals::runEpisode(self::red($spec->get('red')), self::stub($spec, [$spec->get('recorded')]), self::env($spec->get('env')), $spec->get('seed'));
    }

    private static function eval(Obj $spec): Obj
    {
        $r = $spec->get('reds');
        $reds = is_array($r) ? array_map(fn($k) => self::red($k), $r) : $r;
        $recs = [];
        foreach ($spec->get('recorded') as $perRed) {
            foreach ($perRed as $x) {
                $recs[] = $x;
            }
        }
        return ControlEvals::controlEval($reds, self::stub($spec, $recs), self::env($spec->get('env')), $spec->get('episodes'), $spec->get('seed'));
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'mulberry32' => function (array $a) {
                $g = ControlEvals::mulberry32($a[0]);
                $out = [];
                for ($i = 0; $i < (int)$a[1]->float(); $i++) {
                    $out[] = $g();
                }
                return $out;
            },
            'mixSeed' => fn(array $a) => ControlEvals::mixSeed(...$a),
            'wilsonLowerBound' => fn(array $a) => ControlEvals::wilsonLowerBound(...$a),
            'assertControlGate' => function (array $a) {
                ControlEvals::assertControlGate($a[0], $a[1]);
                return null;
            },
            'redGen' => function (array $a) {
                $r = self::red($a[0]);
                return Obj::of(['name' => $r->name, 'strategy' => $r->strategy, 'actions' => $r->gen(['env' => ControlEvals::exampleEnv(), 'rng' => ControlEvals::mulberry32(1), 'now' => 0])]);
            },
            'gapExploitCustom' => function (array $a) {
                $r = ControlEvals::gapExploitRed('file:x');
                return Obj::of(['name' => $r->name, 'actions' => $r->gen([])]);
            },
            'redLists' => fn(array $a) => Obj::of([
                'builtin' => array_map(fn(RedPolicy $r) => $r->strategy, ControlEvals::builtinRedPolicies()),
                'example' => array_map(fn(RedPolicy $r) => $r->strategy, ControlEvals::exampleRedPolicies()),
            ]),
            'exampleDlpPolicy' => fn(array $a) => ControlEvals::exampleDlpPolicy(),
            'envJudge' => fn(array $a) => self::env($a[0])->unacceptableIfAllowed($a[1], $a[2]),
            'runEpisode' => fn(array $a) => self::episode($a[0]),
            'controlEval' => fn(array $a) => self::eval($a[0]),
        ]);
    }
}
