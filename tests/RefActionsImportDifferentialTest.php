<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsImport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsImport.php';

/** The OpenAPI / MCP / JSON Schema / AsyncAPI importers and their shared helpers against the TS reference: test-data/ref-actions-import-core.json.gz. */
final class RefActionsImportDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-import-core.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'tokensOf' => fn(array $a) => ActionsImport::tokensOf($a[0]),
            'humanize' => fn(array $a) => ActionsImport::humanize($a[0]),
            'verbOf' => fn(array $a) => ActionsImport::verbOf($a[0], $a[1]),
            'aliasOf' => fn(array $a) => ActionsImport::aliasOf($a[0], $a[1]),
            'paramSeg' => fn(array $a) => ActionsImport::paramSeg($a[0]),
            'clip' => fn(array $a) => ActionsImport::clip($a[0], (int)$a[1]->int()),
            'pointer' => fn(array $a) => ActionsImport::pointer($a[0], $a[1]),
            'resolveLimits' => fn(array $a) => ActionsImport::resolveLimits($a[0] ?? null),
            'checkParsed' => fn(array $a) => ActionsImport::checkParsed($a[0], ActionsImport::resolveLimits($a[1])),
            'textSizeCheck' => function (array $a) {
                ActionsImport::textSizeCheck($a[0], ActionsImport::resolveLimits($a[1]));
                return null;
            },
            'importOpenApi' => fn(array $a) => ActionsImport::importOpenApi($a[0], $a[1]),
            'importMcp' => fn(array $a) => ActionsImport::importMcp($a[0], $a[1]),
            'importJsonSchema' => fn(array $a) => ActionsImport::importJsonSchema($a[0], $a[1]),
            'importAsyncApi' => fn(array $a) => ActionsImport::importAsyncApi($a[0], $a[1]),
        ]);
    }
}
