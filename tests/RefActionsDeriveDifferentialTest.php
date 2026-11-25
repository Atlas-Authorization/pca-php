<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsDerive;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The signed schema verb and the policy card of an ActionDef against the TS reference: test-data/ref-actions-derive.json.gz (a constant stands for the confirmation verifier): schema verb and document, operation binding, risk, predicates, ontology, card, MCP annotations and the explanation. */
final class RefActionsDeriveDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-derive.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        Base::run($file, $fn, $k, [
            'flattenParams' => fn(array $a) => ActionsDerive::flattenParams($a[0]),
            'paramByRole' => fn(array $a) => ActionsDerive::paramByRole($a[0], $a[1]),
            'effectClass' => fn(array $a) => ActionsDerive::effectClass($a[0]),
            'toSchemaDoc' => fn(array $a) => ActionsDerive::toSchemaDoc($a[0], $a[3] === null ? $core : Actions::extendRegistry($core, $a[3]), $a[1], static fn() => $a[2]),
            'operationOf' => fn(array $a) => ActionsDerive::operationOf($a[0], Obj::of(['params' => $a[1]])),
            'riskOf' => fn(array $a) => ActionsDerive::riskOf($a[0], ActionsDerive::effectiveWith($a[0], $core, static fn() => $a[1]), $a[2], $a[3]),
            'resourceMatcher' => fn(array $a) => ActionsDerive::resourceMatcher($a[0]),
            'predicatesOf' => fn(array $a) => ActionsDerive::predicatesOf($a[0], $a[1] ?? null),
            'toOntology' => fn(array $a) => ActionsDerive::toOntology($a[0], $core, static fn() => $a[1]),
            'escalationOf' => fn(array $a) => ActionsDerive::escalationOf(ActionsDerive::effectiveWith($a[0], $core, static fn() => $a[1])),
            'mcpAnnotationsOf' => fn(array $a) => ActionsDerive::mcpAnnotationsOf($a[0], ActionsDerive::effectiveWith($a[0], $core, static fn() => $a[1])),
            'explainDef' => fn(array $a) => ActionsDerive::explainDef($a[0], $core, static fn() => $a[1]),
            'REVERSIBILITY_SCORE' => fn(array $a) => ActionsDerive::REVERSIBILITY_SCORE,
            'toSchemaVerb' => fn(array $a) => ActionsDerive::toSchemaVerb($a[0], $core, static fn() => $a[1]),
            'cardOf' => fn(array $a) => ActionsDerive::cardOf($a[0], ActionsDerive::effectiveWith($a[0], $core, static fn() => $a[1]), $core),
        ]);
    }
}
