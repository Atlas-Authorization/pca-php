<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsTestRunner;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsTestRunner.php';

/** The example and property runner of the action packs against the TS reference: test-data/ref-actions-test-runner.json.gz. */
final class RefActionsTestRunnerDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-test-runner.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        Base::run($file, $fn, $k, [
            'decideExample' => fn(array $a) => ActionsTestRunner::decideExample($a[0], $a[1], $core, $a[2]),
            'runDefTests' => fn(array $a) => ActionsTestRunner::runDefTests($a[0], $core, isset($a[1]) ? (int)$a[1]->int() : null),
            'testText' => fn(array $a) => ActionsTestRunner::testText($a[0]),
        ]);
    }
}
