<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ActionsRender;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsRender.php';

/** Approval-render wrappers, facade specs and provenance facts against the TS reference: test-data/ref-actions-render-facade.json.gz. */
final class RefActionsRenderDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-render-facade.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'renderApproval' => fn(array $a) => ActionsRender::renderApprovalWith($a[0], $a[1], static fn() => $a[2]),
            'renderDigestForAction' => fn(array $a) => ActionsRender::renderDigestForAction($a[0], $a[1], $a[2], static fn() => $a[3]),
            'approverRenderCheck' => fn(array $a) => ActionsRender::approverRenderCheck($a[0], $a[1], $a[2], static fn() => $a[3]),
            'singleTapAllowed' => fn(array $a) => ActionsRender::singleTapAllowed($a[0]),
            'renderersFromDefs' => fn(array $a) => (ActionsRender::renderersFromDefs($a[0], static fn() => $a[3]))($a[1], '', $a[2]),
            'specOfDef' => fn(array $a) => ActionsRender::specOfDef($a[0], null, static fn() => $a[2], $a[1]),
            'facadeSpecs' => fn(array $a) => ActionsRender::facadeSpecs($a[0], null, static fn() => $a[2], $a[1]),
            'provenanceInfoOf' => fn(array $a) => ActionsRender::provenanceInfoOf($a[0], null, static fn() => $a[1]),
            'provenanceActions' => function (array $a) {
                $f = ActionsRender::provenanceActions($a[0], null, static fn() => $a[1]);
                return array_map(static fn($v) => $f(\Atlas\Pca\Obj::of(['verb' => $v])), $a[2]);
            },
        ]);
    }
}
