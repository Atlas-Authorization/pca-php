<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalBench.php';

use Atlas\Pca\GoalBench;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The benchmark against the TS reference: test-data/ref-goal-bench.json.gz (seeded cases, simulated model fixtures, the four-level
 * evaluation and the calibration report).
 */
final class RefGoalBenchDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-bench.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function items(array $cases): array
    {
        $items = [];
        foreach ($cases as $c) {
            $goal = GoalBench::truthGoal($c);
            $items[] = Obj::of(['goal' => $goal, 'ont' => GoalBench::truthOnt($c, $goal)]);
        }
        return $items;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'rngSeq' => function (array $a) {
                $r = GoalBench::rng($a[0]);
                $out = [];
                for ($i = 0, $n = (int)\Atlas\Pca\Js::num($a[1]); $i < $n; $i++) {
                    $out[] = $r->next();
                }
                return $out;
            },
            'generateCases' => function (array $a) {
                $o = new Obj();
                if (($a[3] ?? null) !== null) {
                    $o->set('hostileEvery', $a[3]);
                }
                if (($a[4] ?? false) === true) {
                    $o->set('hostileOnly', true);
                }
                return GoalBench::generateCases($a[0], $a[1], $a[2], $o);
            },
            'truthGoalOf' => fn(array $a) => GoalBench::truthGoal($a[0]),
            'simulateOutputOf' => function (array $a) {
                foreach (GoalBench::simSpecs() as $s) {
                    if ($s->get('id') === $a[1]) {
                        return GoalBench::simulateOutput($a[0], $s);
                    }
                }
                throw new \InvalidArgumentException('unknown model');
            },
            'recordFixturesOf' => fn(array $a) => GoalBench::recordFixtures($a[0]),
            'caseSetDigest' => fn(array $a) => GoalBench::caseSetDigest($a[0]),
            'evalCaseOf' => fn(array $a) => GoalBench::evalCase($a[0], GoalBench::completionsFrom(GoalBench::recordFixtures([$a[0]]))),
            'compileWideningOf' => fn(array $a) => GoalBench::compileWideningCount(self::items($a[0])),
            'summarizeOf' => fn(array $a) => GoalBench::summarize($a[0], $a[1], $a[2], $a[3] ?? null),
            'runDomainOf' => fn(array $a) => GoalBench::runDomain($a[0], $a[1], GoalBench::recordFixtures($a[1])),
        ]);
    }
}
