<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Rag;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The retrieval filter core (ACL metadata, policy compilation, principal, fail-closed filter and decision digest) against the TS reference: test-data/ref-rag.json.gz. */
final class RefRagDifferentialTest extends TestCase
{
    private const FILE = 'ref-rag.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'aclsFromMetadata' => fn(array $a) => Rag::aclsFromMetadata($a[0] ?? null, $a[1] ?? null),
            'compilePolicy' => fn(array $a) => Rag::compilePolicy($a[0] ?? null),
            'principalFromPCActn' => fn(array $a) => Rag::principalFromPCActn($a[0] ?? null, $a[1] ?? null),
            'filterDocuments' => function (array $a): Obj {
                $r = Rag::filterDocuments($a[0] ?? null, $a[1] ?? null, $a[2] ?? null);
                return Obj::of(['documents' => $r['documents'], 'decision' => $r['decision']]);
            },
        ]);
    }
}
