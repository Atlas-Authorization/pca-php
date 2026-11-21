<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PcaSchema;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The PCA wire schemas and the structural validator against the TS reference: test-data/ref-schema-dotnet.json.gz. */
final class RefSchemaDifferentialTest extends TestCase
{
    private const FILE = 'ref-schema-dotnet.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'validate' => fn(array $a) => PcaSchema::validate($a[0], $a[1]),
            'schemas' => fn(array $a) => PcaSchema::allSchemas(),
        ]);
    }
}
