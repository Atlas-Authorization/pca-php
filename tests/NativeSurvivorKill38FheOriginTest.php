<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FheEncryptedGate;
use Atlas\Pca\FheOrigin;
use Atlas\Pca\FheRiskPolicy;
use Atlas\Pca\FheSeal;
use Atlas\Pca\FheVerdict;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the success path of evalSignedRiskClaim on real SEAL keys (needs libsealc; PCA_FHE_SEAL_REQUIRED=1 fails instead of skipping). */
final class NativeSurvivorKill38FheOriginTest extends TestCase
{
    protected function setUp(): void
    {
        if (!FheSeal::available()) {
            getenv('PCA_FHE_SEAL_REQUIRED') === '1' ? $this->fail('libsealc must load (ATLAS_PCA_LIBSEALC, ffi.enable=true)') : $this->markTestSkipped('libsealc not available');
        }
    }

    /** A verified claim is evaluated: ok is true, the gate opens to the plaintext arithmetic and the digest is the signed claim's. */
    public function testVerifiedClaimIsEvaluated(): void
    {
        $keys = FheSeal::keygen();
        $w = [250, 200, 200, 200, 100, 50];
        $nums = static fn(array $l): array => array_map(static fn(int $x): Num => new Num((string) $x), $l);
        $p = Obj::of(['scale' => new Num('1000'), 'dim' => new Num('6'), 'weightsScaled' => $nums($w), 'kappaWeightsScaled' => $nums($w),
            'budgetScaled' => new Num('600000'), 'kappa' => new Num('1')]);
        $b = Obj::of(['action' => 'a1']);
        $enc = FheSeal::encryptRiskInputs($keys->publicKey, [100, 900, 100, 100, 100, 100]);
        $seed = hash('sha256', 'atlas-pca-conformance/fhe-38n/encryptor', true);
        $s = FheOrigin::signRiskClaim(Obj::of(['binding' => $b, 'policy' => $p, 'encInputs' => $enc]), $seed, 'ctx', str_repeat("\x03", 16));
        $r = FheOrigin::evalSignedRiskClaim($keys->publicKey, $keys->galoisKeys, $s, [$s->get('signer')], 'ctx', $b, $p, FheOrigin::memoryNonceGuard());
        $this->assertSame(['ok', 'gate', 'claimDigest'], array_keys($r));
        $this->assertTrue($r['ok']);
        $this->assertSame(FheOrigin::signedClaimDigest($s), $r['claimDigest']);
        $this->assertInstanceOf(FheEncryptedGate::class, $r['gate']);
        // raw = 250*100 + 200*900 + 200*100 + 200*100 + 100*100 + 50*100 = 260000; slack = 600000 - 260000 (kappa weights equal the weights)
        $pol = new FheRiskPolicy(1000, 6, $w, $w, 600000, 1.0);
        $this->assertEquals(new FheVerdict(260000, 340000, true), FheSeal::decryptVerdict($keys->secretKey, $r['gate']->encRiskRaw, $r['gate']->encSlack, $pol));
    }
}
