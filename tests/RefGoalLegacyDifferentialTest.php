<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalLegacy.php';

use Atlas\Pca\AnalyzerJs;
use Atlas\Pca\GoalLegacy;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** liftLegacy against the TS reference: test-data/ref-goal-legacy.json.gz (the facade's {permissions, limits} lifted to a Goal and IR ontology). */
final class RefGoalLegacyDifferentialTest extends TestCase
{
    private const FILE = 'ref-goal-legacy.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'liftLegacy' => function (array $a) {
                [$permissions, $limits, $principal, $notAfter, $notBefore, $nl] = $a + [null, null, null, null, null, null];
                $o = Obj::of(['permissions' => $permissions, 'principal' => $principal]);
                foreach (['limits' => AnalyzerJs::truthy($limits) ? $limits : null, 'notAfter' => $notAfter, 'notBefore' => $notBefore, 'nlDigest' => $nl] as $key => $v) {
                    if ($v !== null) {
                        $o->set($key, $v);
                    }
                }
                return GoalLegacy::liftLegacy($o);
            },
        ]);
    }
}
