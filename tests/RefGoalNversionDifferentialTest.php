<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalNversion.php';
require_once __DIR__ . '/../src/GoalDisambiguate.php';

use Atlas\Pca\GoalDisambiguate;
use Atlas\Pca\GoalNversion;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * N-version interpretation against the TS reference: test-data/ref-goal-nversion.json.gz (the semantic meet of readings, the panel
 * check, N-version interpretation, witness questions and version-space halving). Injected answerers are chosen by mode name.
 */
final class RefGoalNversionDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-nversion.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'meet' => fn(array $a) => GoalNversion::meet($a[0]),
            'meetGrants' => fn(array $a) => GoalNversion::meetGrants($a[0], $a[1]),
            'checkPanel' => fn(array $a) => GoalNversion::checkPanel($a[0]),
            'nVersion' => function (array $a) {
                $o = Obj::of(['ont' => $a[1]]);
                if (($a[2] ?? null) !== null) {
                    $o->set('massThreshold', $a[2]);
                }
                return GoalNversion::nVersion($a[0], $o);
            },
            'questions' => fn(array $a) => GoalDisambiguate::questions($a[0], Obj::of(['ont' => $a[1]])),
            'disagreementMass' => fn(array $a) => GoalDisambiguate::disagreementMass($a[0], $a[1]),
            'allowsWitness' => fn(array $a) => GoalDisambiguate::allowsWitness($a[0], $a[1], $a[2]),
            'disambiguate' => function (array $a) {
                [$readings, $ont, $mode] = $a;
                $ask = static function (mixed $q) use ($readings, $ont, $mode): string {
                    if ($mode === 'allow' || $mode === 'deny') {
                        return $mode;
                    }
                    return GoalDisambiguate::allowsWitness($readings[(int)substr((string)$mode, 6)]->get('goal'), $ont, $q) ? 'allow' : 'deny';
                };
                $opts = Obj::of(['ont' => $ont]);
                if (($a[3] ?? null) !== null) {
                    $opts->set('budget', $a[3]);
                }
                return GoalDisambiguate::disambiguate($readings, $ask, $opts);
            },
        ]);
    }
}
