<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsBuild;
use Atlas\Pca\ActionsBuiltin;
use Atlas\Pca\ActionsSync;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsBuild.php';
require_once __DIR__ . '/../src/ActionsSync.php';
require_once __DIR__ . '/../src/ActionsBuiltin.php';

/** Pack build, signing and verification, source sync and the domain bindings against the TS reference: test-data/ref-actions-build-py.json.gz. */
final class RefActionsBuildDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-build-py.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        $sync = static fn(array $a) => ActionsSync::syncSource($a[0]->get('current'), $a[0]->get('imported'), $a[0]->get('specDigest'), $a[0]->get('now'),
            $a[0]->get('lock'), $core, static fn() => $a[1]);
        Base::run($file, $fn, $k, [
            'buildArtifacts' => fn(array $a) => ActionsBuild::buildArtifacts($a[0], $a[1], $core, static fn() => $a[2]),
            'toolActionMapOf' => fn(array $a) => (ActionsBuild::toolActionMapOf($a[0]))($a[1], $a[2]),
            'generateTypes' => fn(array $a) => ActionsBuild::generateTypes($a[0]),
            'packConsistencyError' => fn(array $a) => ActionsBuild::packConsistencyError($a[0], $core),
            'signPack' => fn(array $a) => ActionsBuild::signPack($a[0], $a[1], Base::bytes($a[2]), $core),
            'verifyPack' => fn(array $a) => ActionsBuild::verifySignedPack($a[0], $a[1], $core),
            'packKeyOf' => fn(array $a) => ActionsBuild::packKeyOf($a[0], Base::bytes($a[1])),
            'syncSource' => $sync,
            'syncText' => fn(array $a) => ActionsSync::syncText($sync($a)),
            'domainVerbs' => fn(array $a) => ActionsBuiltin::domainVerbs($a[0]),
            'domainRoles' => fn(array $a) => ActionsBuiltin::domainRoles($a[0]),
        ]);
    }
}
