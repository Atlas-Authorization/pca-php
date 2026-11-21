<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FheRiskPolicy;
use Atlas\Pca\FheSeal;
use Atlas\Pca\FheVerdict;
use PHPUnit\Framework\TestCase;

/**
 * BFV risk gate on Microsoft SEAL (ext-ffi over libsealc): replay of the node-seal corpus plus a native round trip. Needs libsealc
 * (ATLAS_PCA_LIBSEALC) and, for the replay, the corpus the reference generates (PCA_FHE_SEAL_CORPUS). Absence skips; with
 * PCA_FHE_SEAL_REQUIRED=1 (the FHE workflow) it fails instead.
 */
final class FheSealTest extends TestCase
{
    private static function required(): bool
    {
        return getenv('PCA_FHE_SEAL_REQUIRED') === '1';
    }

    protected function setUp(): void
    {
        if (!FheSeal::available()) {
            self::required() ? $this->fail('libsealc must load (ATLAS_PCA_LIBSEALC, ffi.enable=true)') : $this->markTestSkipped('libsealc not available');
        }
    }

    private static function policy(float $kappa, float $budget): FheRiskPolicy
    {
        $w = [0.25, 0.2, 0.2, 0.2, 0.1, 0.05];
        return new FheRiskPolicy(
            1000,
            6,
            array_map(static fn(float $v): int => (int) round($v * 1000), $w),
            array_map(static fn(float $v): int => (int) round($kappa * $v * 1000), $w),
            (int) round($budget * 1e6),
            $kappa,
        );
    }

    public function testReplaysTheReferenceCiphertextsToTheReferenceResults(): void
    {
        $path = getenv('PCA_FHE_SEAL_CORPUS');
        if ($path === false || $path === '') {
            self::required() ? $this->fail('PCA_FHE_SEAL_CORPUS must point at the node-seal corpus') : $this->markTestSkipped('no corpus');
        }
        $corpus = json_decode((string) gzdecode((string) file_get_contents($path)), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(FheSeal::POLY_MODULUS_DEGREE, $corpus['seal']['polyModulusDegree']);
        self::assertSame(FheSeal::PLAIN_MODULUS, $corpus['seal']['plainModulus']);
        self::assertGreaterThanOrEqual(6, count($corpus['cases']));
        foreach ($corpus['cases'] as $c) {
            $p = $c['policy'];
            $pol = new FheRiskPolicy($p['scale'], $p['dim'], $p['weightsScaled'], $p['kappaWeightsScaled'], $p['budgetScaled'], (float) $p['kappa']);
            $gate = FheSeal::evalRiskGate($corpus['publicKey'], $corpus['galoisKeys'], $c['encInputs'], $pol);
            // deterministic evaluation: byte-equal once both are re-saved uncompressed
            self::assertSame(FheSeal::canonicalCipher($c['encRiskRaw']), FheSeal::canonicalCipher($gate->encRiskRaw), $c['name']);
            self::assertSame(FheSeal::canonicalCipher($c['encSlack']), FheSeal::canonicalCipher($gate->encSlack), $c['name']);
        }
    }

    /** @return list<array{list<int>, float, float}> */
    public static function roundTripCases(): array
    {
        return [[[100, 900, 100, 100, 100, 100], 1.0, 0.6], [[1000, 1000, 1000, 1000, 1000, 1000], 1.0, 0.5], [[0, 0, 0, 0, 0, 0], 1.5, 0.25]];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('roundTripCases')]
    public function testNativeRoundTripMatchesPlaintextArithmetic(array $x, float $kappa, float $budget): void
    {
        $keys = FheSeal::keygen();
        $pol = self::policy($kappa, $budget);
        $gate = FheSeal::evalRiskGate($keys->publicKey, $keys->galoisKeys, FheSeal::encryptRiskInputs($keys->publicKey, $x), $pol);
        $v = FheSeal::decryptVerdict($keys->secretKey, $gate->encRiskRaw, $gate->encSlack, $pol);
        $raw = $kr = 0;
        foreach ($x as $i => $xi) {
            $raw += $pol->weightsScaled[$i] * $xi;
            $kr += $pol->kappaWeightsScaled[$i] * $xi;
        }
        self::assertEquals(new FheVerdict($raw, $pol->budgetScaled - $kr, $pol->budgetScaled - $kr >= 0), $v);
    }

    public function testAllZeroWeightsEvaluateToZero(): void
    {
        $keys = FheSeal::keygen();
        $z = [0, 0, 0, 0, 0, 0];
        $pol = new FheRiskPolicy(1000, 6, $z, $z, 5000);
        $gate = FheSeal::evalRiskGate($keys->publicKey, $keys->galoisKeys, FheSeal::encryptRiskInputs($keys->publicKey, [5, 5, 5, 5, 5, 5]), $pol);
        self::assertEquals(new FheVerdict(0, 5000, true), FheSeal::decryptVerdict($keys->secretKey, $gate->encRiskRaw, $gate->encSlack, $pol));
    }

    public function testWrongKeyFailsClosed(): void
    {
        $a = FheSeal::keygen();
        $b = FheSeal::keygen();
        $pol = self::policy(1.0, 0.6);
        $gate = FheSeal::evalRiskGate($a->publicKey, $a->galoisKeys, FheSeal::encryptRiskInputs($a->publicKey, [1, 2, 3, 4, 5, 6]), $pol);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/noise budget/');
        FheSeal::decryptVerdict($b->secretKey, $gate->encRiskRaw, $gate->encSlack, $pol);
    }

    public function testMalformedBlobsAndPoliciesAreRefused(): void
    {
        $keys = FheSeal::keygen();
        $good = FheSeal::encryptRiskInputs($keys->publicKey, [1, 2, 3, 4, 5, 6]);
        foreach ([substr($good, 0, -8), $good . 'AAAA', 'AAAA', str_repeat('A', 64)] as $bad) {
            try {
                FheSeal::assertSealBlob($bad, 'x');
                self::fail('a malformed blob must be refused');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
        $z = [0, 0, 0, 0, 0, 0];
        foreach ([new FheRiskPolicy(1000, 5, $z, $z, 0), new FheRiskPolicy(1000, 6, $z, $z, FheSeal::SIGNED_BOUND), new FheRiskPolicy(0, 6, $z, $z, 0), new FheRiskPolicy(1000, 6, [0, 0, 0, 0, 0], $z, 0)] as $pol) {
            try {
                FheSeal::requirePolicy($pol);
                self::fail('a bad policy must be refused');
            } catch (\InvalidArgumentException) {
                self::addToAssertionCount(1);
            }
        }
    }
}
