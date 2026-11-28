<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentSchema;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The schema-derived outcome space against the TS reference: test-data/ref-intent-schema.json.gz. */
final class RefIntentSchemaDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-schema.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'deriveSchemaOmega' => fn(array $a) => IntentSchema::deriveOmegaFromSchema($a[0]),
            'canonValue' => fn(array $a) => IntentSchema::canonValue($a[0], $a[1]),
            'effectiveSensitivity' => fn(array $a) => IntentSchema::effectiveSensitivity($a[0], $a[1] ?? null),
            'verbReversibility' => fn(array $a) => IntentSchema::verbReversibility($a[0]),
            'walletFloorOverrides' => fn(array $a) => IntentSchema::walletFloorOverrides(Obj::of(['verbs' => $a[0]]), $a[1] ?? null),
        ]);
    }
}
