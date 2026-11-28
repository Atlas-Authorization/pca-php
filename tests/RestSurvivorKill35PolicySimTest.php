<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PolicySim.php';

use Atlas\Pca\Catalog;
use Atlas\Pca\PolicySim;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the policy simulator and its static lints. */
final class RestSurvivorKill35PolicySimTest extends TestCase
{
    private static function cat(): Catalog
    {
        return Catalog::buildCatalog([
            Catalog::defineAction(['connector' => 't', 'action' => 'one', 'reversibility' => 'reversible', 'blastRadius' => 1]),
            Catalog::defineAction(['connector' => 't', 'action' => 'low', 'reversibility' => 'reversible', 'blastRadius' => 0.3]),
        ]);
    }

    private static function policy(array $rp = [], array $caveats = []): array
    {
        return ['riskPolicy' => $rp + Sign::defaultRiskPolicy(), 'budgetModel' => 'risk', 'caveats' => $caveats,
            'predicates' => [['verb' => 't.one', 'resource' => '*'], ['verb' => 't.low', 'resource' => '*'], ['verb' => 'u.x', 'resource' => '*']]];
    }

    private static function order(array $sim): array
    {
        return array_map(static fn(array $r): string => $r['action']['resource'], $sim['results']);
    }

    /** With no action the end budget is the policy's bMax as a float. */
    public function testEndBudgetIsAFloat(): void
    {
        $this->assertSame(1.0, PolicySim::simulate(self::policy(), [], self::cat())['endBudget']);
    }

    /** The risk of an action is always a float, even when the clamp returns an integer bound. */
    public function testRiskIsAFloat(): void
    {
        $s = PolicySim::simulate(self::policy(), [['verb' => 't.one', 'resource' => 'r']], self::cat(), 0);
        $this->assertSame(1.0, $s['results'][0]['r']);
        $this->assertSame(1.0, $s['peakRisk']);
    }

    /** An action without `at` occurs at the default start time 0 plus its position in the list (not its array key). */
    public function testDefaultStartAndPositionalTimes(): void
    {
        $a = ['verb' => 't.low', 'resource' => 'a'];
        $b = ['verb' => 't.low', 'resource' => 'b', 'at' => -0.5];
        $c = ['verb' => 't.low', 'resource' => 'c', 'at' => 0.5];
        $this->assertSame(['b', 'a', 'c'], self::order(PolicySim::simulate(self::policy(), [$a, $b, $c], self::cat())));
        $this->assertSame(['a', 'c'], self::order(PolicySim::simulate(self::policy(), [1 => $a, 0 => $c], self::cat())));
    }

    /** The blast radius seen by caveats is the catalog's, and 1 for an uncatalogued verb. */
    public function testCaveatBlastRadius(): void
    {
        $half = self::policy([], [['type' => 'max_blast_radius', 'max' => 0.5]]);
        $s = PolicySim::simulate($half, [['verb' => 't.low', 'resource' => 'r'], ['verb' => 'u.x', 'resource' => 'r', 'at' => 1]], self::cat(), 0);
        $this->assertSame(['step_up', 'deny'], array_column($s['results'], 'outcome'));
        $this->assertStringStartsWith('caveat(s) failed: ', $s['results'][1]['reason']);
        $one = self::policy([], [['type' => 'max_blast_radius', 'max' => 1]]);
        $s = PolicySim::simulate($one, [['verb' => 'u.x', 'resource' => 'r']], self::cat(), 0);
        $this->assertSame('step_up', $s['results'][0]['outcome']);
    }

    /** A budget exactly equal to the cost still admits the action on its own. */
    public function testBudgetEqualToCostAdmits(): void
    {
        $p = self::policy(['bMax' => 0.8, 'kappa' => 1, 'lambda' => 0, 'theta1' => 0.9, 'theta2' => 0.95]);
        $s = PolicySim::simulate($p, [['verb' => 'u.x', 'resource' => 'r']], self::cat(), 0);
        $this->assertSame('auto', $s['results'][0]['outcome']);
        $this->assertSame(1, $s['auto']);
    }

    private static function lintPolicy(array $actions, array $predicates, array $rp = []): array
    {
        return ['actions' => $actions, 'inputLimits' => [], 'limits' => [], 'predicates' => $predicates, 'riskPolicy' => $rp + Sign::defaultRiskPolicy()];
    }

    private static function codes(array $lints, string $code): array
    {
        return array_values(array_map(static fn(array $l): string => $l['message'], array_filter($lints, static fn(array $l): bool => $l['code'] === $code)));
    }

    /** broad-resource uses the FIRST predicate of the same verb and fires from rate_limited up; an unknown class never fires. */
    public function testBroadResourceLint(): void
    {
        $act = static fn(string $v, string $rev): array => ['verb' => "t.$v", 'action' => $v, 'reversibility' => $rev];
        $p = self::lintPolicy(
            [$act('a', 'irreversible'), $act('b', 'irreversible'), $act('c', 'rate_limited'), $act('d', 'reversible'), $act('e', 'weird')],
            [['verb' => 't.a', 'resource' => '*'], ['verb' => 't.b', 'resource' => 'x/*'], ['verb' => 't.b', 'resource' => '*'],
                ['verb' => 't.c', 'resource' => '*'], ['verb' => 't.d', 'resource' => '*'], ['verb' => 't.e', 'resource' => '*']],
        );
        $this->assertSame([
            "'t.a' (irreversible) matches ANY resource — consider a resource prefix",
            "'t.c' (rate_limited) matches ANY resource — consider a resource prefix",
        ], self::codes(PolicySim::lintPolicy($p, self::cat()), 'broad-resource'));
    }

    /** large-autonomy fires strictly above 100, never for kappa 0, and reports bMax / kappa. */
    public function testLargeAutonomyLint(): void
    {
        $acts = [['verb' => 't.d', 'action' => 'd', 'reversibility' => 'reversible']];
        $preds = [['verb' => 't.d', 'resource' => 'x/*']];
        $this->assertSame([], self::codes(PolicySim::lintPolicy(self::lintPolicy($acts, $preds, ['bMax' => 100, 'kappa' => 1]), self::cat()), 'large-autonomy'));
        $this->assertSame([], self::codes(PolicySim::lintPolicy(self::lintPolicy($acts, $preds, ['bMax' => 5, 'kappa' => 0]), self::cat()), 'large-autonomy'));
        $this->assertSame(['autonomous bound is 100× a max-risk action between human co-signs'],
            self::codes(PolicySim::lintPolicy(self::lintPolicy($acts, $preds, ['bMax' => 200, 'kappa' => 2]), self::cat()), 'large-autonomy'));
    }
}
