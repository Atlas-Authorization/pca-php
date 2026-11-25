<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalCompiler;
use Atlas\Pca\GoalDigests;
use Atlas\Pca\GoalSelectors;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/GoalSelectors.php';
require_once __DIR__ . '/../src/GoalCompiler.php';
require_once __DIR__ . '/../src/GoalDigests.php';

/**
 * The shared selector-goal conformance vectors: the expansion of every selector goal against its pinned catalog must be the vector's
 * goal, the goal digest must match, a well-typed selector goal has no selector reasons, and compiling it gives the vector's verdict
 * and policy digest. A missing vector directory FAILS (set PCA_GOAL_VECTORS to the `goal` vector directory to override the search).
 */
final class GoalSelectVectorsTest extends TestCase
{
    private static function dir(): string
    {
        $cands = [];
        $env = getenv('PCA_GOAL_VECTORS');
        if (is_string($env) && $env !== '') {
            $cands[] = dirname($env) . '/goal-select';
        }
        $cands[] = __DIR__ . '/../../../packages/pca-conformance/vectors/goal-select';
        $cands[] = __DIR__ . '/../conformance/goal-select';
        foreach ($cands as $c) {
            if (is_dir($c)) {
                return $c;
            }
        }
        self::fail('selector vectors not found (looked in ' . implode(', ', $cands) . ')');
    }

    public function testSelectorVectors(): void
    {
        $dir = self::dir();
        $files = glob($dir . '/*.json') ?: [];
        sort($files);
        $n = 0;
        $bad = [];
        foreach ($files as $f) {
            if (basename($f) === 'index.json') {
                continue;
            }
            $v = (new Parser((string)file_get_contents($f), PHP_INT_MAX))->run();
            self::assertInstanceOf(Obj::class, $v);
            $n++;
            $id = (string)$v->get('id');
            $sel = $v->get('sel');
            $ont = $v->get('ontology');
            $goal = $v->get('goal');
            $x = GoalSelectors::expandSelGoal($sel->get('goal'), $ont, $sel->get('catalog'));
            if (Base::canon($x->get('goal')) !== Base::canon($goal)) {
                $bad[] = "$id:expansion";
            }
            if (GoalDigests::goalDigest($goal) !== $v->get('goal_digest')) {
                $bad[] = "$id:goal_digest";
            }
            $compile = $v->get('compile');
            if ($compile->get('ok') !== true) {
                continue;
            }
            $reasons = GoalSelectors::selReasons($sel->get('goal'), $ont, $sel->get('catalog'));
            if ($reasons !== []) {
                $bad[] = "$id:reasons " . implode(',', $reasons);
                continue;
            }
            $c = GoalSelectors::compileSelGoal($sel->get('goal'), $ont, $sel->get('catalog'), GoalCompiler::compileGoal(...));
            if ($c->get('ok') !== true || GoalCompiler::policyDigest($c->get('policy')) !== $v->get('policy_digest')) {
                $bad[] = "$id:compile";
            }
        }
        self::assertGreaterThanOrEqual(48, $n);
        self::assertSame([], array_slice($bad, 0, 20));
    }
}
