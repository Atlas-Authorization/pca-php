<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsDerive;
use Atlas\Pca\ActionsDiff;
use Atlas\Pca\ActionsEffective;
use Atlas\Pca\ActionsIdPattern;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsDiff.php';

/** Id patterns, effective profiles, structural param rules and semantic diffs against the TS reference: test-data/ref-actions-diff.json.gz. */
final class RefActionsDiffDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-diff.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        $p = static fn($x) => Actions::profFromObj($x);
        Base::run($file, $fn, $k, [
            'idMatches' => fn(array $a) => ActionsIdPattern::idMatches($a[0], $a[1]),
            'idPatternContains' => fn(array $a) => ActionsIdPattern::idPatternContains($a[0], $a[1]),
            'join' => fn(array $a) => Actions::profObj(Actions::join($p($a[0]), $p($a[1]))),
            'leq' => fn(array $a) => Actions::leq($p($a[0]), $p($a[1])),
            'profileEq' => fn(array $a) => ActionsEffective::profileEq($p($a[0]), $p($a[1])),
            'effective' => fn(array $a) => self::effectiveOut(ActionsDerive::effectiveWith($a[0], $core, static fn() => $a[1])),
            'hintTraits' => fn(array $a) => Actions::hintTraits($a[0]),
            'prulesViolations' => fn(array $a) => ActionsEffective::prulesViolations($a[0]),
            'effWithTrait' => fn(array $a) => Actions::profObj(ActionsEffective::effWithTrait($a[0], $a[1], $core)),
            'requiredPrulesViolated' => fn(array $a) => ActionsEffective::requiredPrulesViolated($a[0], $p($a[1])),
            'diffDefs' => fn(array $a) => ActionsDiff::diffDefs($a[0], $a[1], $core, static fn() => $a[2] ?? null),
            'diffDefsAuthoring' => fn(array $a) => ActionsDiff::diffDefsAuthoring($a[0], $a[1], $core),
            'diffIsFree' => fn(array $a) => ActionsDiff::diffIsFree($a[0]),
            'diffPacks' => fn(array $a) => ActionsDiff::diffPacks($a[0], $a[1], $core),
        ]);
    }

    /** The effective view with every profile as the oracle's object. */
    private static function effectiveOut(array $e): array
    {
        foreach (['floor', 'eff', 'decl'] as $k) {
            $e[$k] = Actions::profObj($e[$k]);
        }
        foreach (['floor', 'eff'] as $k) {
            $e['hint'][$k] = Actions::profObj($e['hint'][$k]);
        }
        return $e;
    }
}
