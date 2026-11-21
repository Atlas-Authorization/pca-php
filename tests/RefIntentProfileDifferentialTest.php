<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\IntentProfile;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\WalletOmega;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Intent profiles against the TS reference: test-data/ref-intent-profile.json.gz (signing, closed shape checks over hostile variants,
 * signature verification, digest, succession, scope / standing deny + permit, veto cells, ceiling, revocation). The signing seeds are
 * placeholders {"$seed:<label>"} resolved to sha256("atlas-pca-conformance/" + label).
 */
final class RefIntentProfileDifferentialTest extends TestCase
{
    private const FILE = 'ref-intent-profile.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function seed(mixed $s): string
    {
        if (is_string($s) && str_starts_with($s, '$seed:')) {
            return hash('sha256', 'atlas-pca-conformance/' . substr($s, 6), true);
        }
        return Pca::unb64u($s);
    }

    #[DataProvider('provide')]
    public function testReplay(string $file, string $fn, int $k): void
    {
        $p = static fn($x) => WalletOmega::plain($x);
        Base::run($file, $fn, $k, [
            'signIntentProfile' => static fn(array $a) => IntentProfile::signIntentProfile($a[0], self::seed($a[1])),
            'intentProfileShapeError' => static fn(array $a) => IntentProfile::intentProfileShapeError($a[0], !(($a[1] ?? null) instanceof Obj && $a[1]->get('signed') === false)),
            'verifyIntentProfile' => static fn(array $a) => IntentProfile::verifyIntentProfile($a[0]),
            'profileUsable' => static fn(array $a) => IntentProfile::profileUsable($a[0], $a[1]),
            'intentProfileDigest' => static fn(array $a) => IntentProfile::intentProfileDigest($a[0]),
            'verifyProfileSuccession' => static fn(array $a) => IntentProfile::verifyProfileSuccession($a[0], $a[1]),
            'profileApplies' => static fn(array $a) => IntentProfile::profileApplies($a[0], $a[1]),
            'standingAdmits' => static fn(array $a) => IntentProfile::standingAdmits($a[0], $a[1], $a[2]),
            'standingPermits' => static fn(array $a) => IntentProfile::standingPermits($a[0], $a[1], $a[2]),
            'profileVetoCells' => static fn(array $a) => IntentProfile::profileVetoCells($a[0], $p($a[1])),
            'profileCeiling' => static fn(array $a) => (IntentProfile::profileCeiling($a[0], $a[1]))($a[2], $a[3]),
        ]);
    }
}
