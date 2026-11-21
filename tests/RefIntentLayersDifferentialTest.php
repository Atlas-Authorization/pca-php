<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Sign;
use Atlas\Pca\IntentLayersWallet;
use Atlas\Pca\IntentMulti;
use Atlas\Pca\IntentMetrics;
use Atlas\Pca\IntentPolicy;
use Atlas\Pca\WalletOmega;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Wallet-side layers (ceilings, cell sets, owner risk, quorum approvals) and grant measurement against the TS reference:
 * test-data/ref-intent-layers.json.gz. The multi-principal rule functions (normalizeRule, effectiveVetoers, ruleAdmits, jointAcceptance, commonRefinement) replay on IntentMulti.
 */
final class RefIntentLayersDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-layers.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(string $b64u): string
    {
        return (string)Pca::unb64u($b64u, 32);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $rule = static fn($x) => Sign::plain($x);
        Base::run($file, $fn, $k, [
            'ceilingOf' => fn(array $a) => IntentLayersWallet::ceilingOf(IntentLayersWallet::ceilingAdmitters($a[0]), $a[1], $a[2]),
            'assertAskable' => function (array $a) {
                IntentLayersWallet::assertAskable($a[0], $a[1]);
                return null;
            },
            'layerCells' => fn(array $a) => IntentLayersWallet::layerCells($a[0], IntentPolicy::admitter($a[1])),
            'ownerRisk' => fn(array $a) => IntentLayersWallet::ownerRisk($a[0], $a[1], IntentMetrics::acceptabilityOf($a[2])),
            'cellKeyOf' => fn(array $a) => IntentLayersWallet::cellKeyOf($a[0], $a[1]),
            'signLayerApproval' => fn(array $a) => IntentLayersWallet::signLayerApproval($a[0], self::seed($a[1])),
            'verifyQuorumApprovals' => fn(array $a) => IntentLayersWallet::verifyQuorumApprovals($a[0], $a[1], $a[2], $a[3]),
            'measureGrant' => fn(array $a) => IntentMetrics::measureGrant($a[0], $a[1], IntentMetrics::acceptabilityOf($a[2]), $a[3]),
            'measureGrantExact' => fn(array $a) => IntentMetrics::measureGrantExact($a[0], $a[1], IntentMetrics::acceptabilityOf($a[2])),
            'normalizeRule' => static fn(array $a) => IntentMulti::normalizeRule($a[0], $a[1]),
            'effectiveVetoers' => static fn(array $a) => IntentMulti::effectiveVetoers($a[0], $a[1]),
            'ruleAdmits' => static fn(array $a) => IntentMulti::ruleAdmits($rule($a[0]), $a[1]),
            'jointAcceptance' => static fn(array $a, \Atlas\Pca\Obj $c) => RefWalletDifferentialTest::close(IntentMulti::jointAcceptance($rule($a[0]), array_map(static fn($x) => (float)WalletOmega::plain($x), $a[1])), $c),
            'commonRefinement' => static fn(array $a, \Atlas\Pca\Obj $c) => RefWalletDifferentialTest::close(IntentMulti::commonRefinement(WalletOmega::plain($a[0])), $c),
        ]);
    }
}
