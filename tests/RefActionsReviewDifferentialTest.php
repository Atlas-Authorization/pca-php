<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\ActionsReview;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The review flow (attestation verdicts, status, queue, view, confirm) against the TS reference: test-data/ref-actions-review.json.gz.
 * The reviewer secret in a confirmDef case is a {"$bytes"} member (the loader resolves its seed label).
 */
final class RefActionsReviewDifferentialTest extends TestCase
{
    private const FILE = 'ref-actions-review.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function reg(mixed $regDefs): array
    {
        return $regDefs === null ? Actions::coreRegistry() : Actions::extendRegistry(Actions::coreRegistry(), $regDefs);
    }

    private static function confirm(Obj $d, Obj $oo): Obj
    {
        $o = ['registry' => self::reg($oo->get('regDefs')), 'reviewer' => ['kid' => $oo->get('kid'), 'secret' => Base::bytes($oo->get('seed'))],
            'finalTraits' => $oo->get('finalTraits'), 'ts' => $oo->get('ts')];
        if ($oo->get('pins') !== null) {
            $o['pins'] = $oo->get('pins');
        }
        if ($oo->get('dismissed')) {
            $o['dismissed'] = $oo->get('dismissed');
        }
        return ActionsReview::confirmDef($d, $o);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $core = Actions::coreRegistry();
        Base::run($file, $fn, $k, [
            'verifyAttestation' => fn(array $a) => ActionsReview::verifyAttestationVerdict($a[0], self::reg($a[2]), $a[1]),
            'reviewStatus' => fn(array $a) => ActionsReview::reviewStatus($a[0], self::reg($a[2]), $a[1]),
            'revertStale' => fn(array $a) => ActionsReview::revertStale($a[0], self::reg($a[2]), $a[1]),
            'reviewPriority' => fn(array $a) => ActionsReview::reviewPriority($a[0], $core),
            'reviewQueueOrder' => fn(array $a) => array_map(fn($d) => $d->get('verb'), ActionsReview::reviewQueueOrder($a[0], $core)),
            'prepareReview' => fn(array $a) => ActionsReview::prepareReview($a[0], $core, $a[1] ?? null),
            'confirmDef' => fn(array $a) => self::confirm($a[0], $a[1]),
        ]);
    }
}
