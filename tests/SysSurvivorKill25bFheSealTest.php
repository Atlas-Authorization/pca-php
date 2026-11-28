<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FheRiskPolicy;
use Atlas\Pca\FheSeal;
use PHPUnit\Framework\TestCase;

/** Group 25b kills for src/FheSeal.php: the ext-ffi guard, and the noise budget floor of exactly 16 bits. */
final class SysSurvivorKill25bFheSealTest extends TestCase
{
    protected function tearDown(): void
    {
        FheSeal::$extensionHook = null;
        FheSeal::$noiseBudgetHook = null;
    }

    public function testWithoutFfiNothingLoads(): void
    {
        $prop = new \ReflectionProperty(FheSeal::class, 'lib');
        $saved = $prop->getValue();
        FheSeal::$extensionHook = static fn(string $name): bool => $name !== 'ffi';
        $prop->setValue(null, null);
        try {
            FheSeal::keygen();
            $this->fail('no ext-ffi must be refused');
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertSame('ext-ffi is required for FheSeal', $e->getMessage());
        } finally {
            $prop->setValue(null, $saved);
        }
    }

    /** A ciphertext with 15 bits of budget left is refused; 16 and 17 decrypt. */
    public function testNoiseBudgetFloorIsSixteenBits(): void
    {
        if (!FheSeal::available()) {
            if (getenv('PCA_FHE_SEAL_REQUIRED') === '1') {
                $this->fail('libsealc must load (ATLAS_PCA_LIBSEALC, ffi.enable=true)');
            }
            $this->markTestSkipped('libsealc not available');
        }
        $keys = FheSeal::keygen();
        $pol = new FheRiskPolicy(1000, 6, [0, 0, 0, 0, 0, 0], [0, 0, 0, 0, 0, 0], 7);
        $gate = FheSeal::evalRiskGate($keys->publicKey, $keys->galoisKeys, FheSeal::encryptRiskInputs($keys->publicKey, [3, 3, 3, 3, 3, 3]), $pol);
        $decrypt = static function (int $bits) use ($keys, $gate, $pol) {
            FheSeal::$noiseBudgetHook = static fn(int $real): int => $bits;
            return FheSeal::decryptVerdict($keys->secretKey, $gate->encRiskRaw, $gate->encSlack, $pol);
        };
        try {
            $decrypt(15);
            $this->fail('15 bits of budget must be refused');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('decryptVerdict: ciphertext has no noise budget left (wrong key, corrupted, or not produced by the gate)', $e->getMessage());
        }
        foreach ([16, 17] as $bits) {
            $v = $decrypt($bits);
            $this->assertSame([0, 7, true], [$v->rScaled, $v->slack, $v->admit], "$bits bits");
        }
    }
}
