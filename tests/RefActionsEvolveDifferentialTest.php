<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsEvolve;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsEvolve.php';

/** Pack evolution records, registry signing and the whole-change check against the TS reference: test-data/ref-actions-evolve.json.gz. */
final class RefActionsEvolveDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-evolve.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        Base::run($file, $fn, $k, [
            'evolutionRecords' => fn(array $a) => ActionsEvolve::evolutionRecords($a[0], $a[1], $a[2], $core, static fn() => $a[3]),
            'signEvolution' => fn(array $a) => ActionsEvolve::signEvolution($a[0], $a[1], Base::bytes($a[2])),
            'evolutionError' => fn(array $a) => ActionsEvolve::evolutionError($a[0], $a[1], $a[2], $a[3], $a[4], $core, static fn() => $a[5]),
        ]);
    }
}
