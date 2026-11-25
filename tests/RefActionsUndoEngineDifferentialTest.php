<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsReview;
use Atlas\Pca\ActionsUndoEngine;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../src/ActionsUndoEngine.php';

/** The confirmation-gated undo plan and the attestation check against the TS reference: test-data/ref-actions-undo-engine.json.gz. */
final class RefActionsUndoEngineDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-undo-engine.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        Base::run($file, $fn, $k, [
            'undoPlan' => fn(array $a) => (ActionsUndoEngine::undoEngine($a[0], $a[1], null))($a[2]),
            'attested' => fn(array $a) => (ActionsReview::attestationVerifier($core, $a[1]))($a[0]),
        ]);
    }
}
