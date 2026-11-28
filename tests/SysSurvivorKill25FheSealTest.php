<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FheRiskPolicy;
use Atlas\Pca\FheSeal;
use Atlas\Pca\NativeDir;
use PHPUnit\Framework\TestCase;

/**
 * Group 25 kills for src/FheSeal.php: the SEAL envelope gate and the policy/input gates (no library needed), and with libsealc
 * (ATLAS_PCA_LIBSEALC; PCA_FHE_SEAL_REQUIRED=1 makes absence a failure) the library lookup, HRESULT text, unseeded key streams and the
 * verdict boundaries.
 */
final class SysSurvivorKill25FheSealTest extends TestCase
{
    private const Z = [0, 0, 0, 0, 0, 0];

    private function needLib(): void
    {
        if (FheSeal::available()) {
            return;
        }
        if (getenv('PCA_FHE_SEAL_REQUIRED') === '1') {
            $this->fail('libsealc must load (ATLAS_PCA_LIBSEALC, ffi.enable=true)');
        }
        $this->markTestSkipped('libsealc not available');
    }

    /** A SEAL stream envelope: magic, header size 16, version, compression mode, reserved, then the declared size (little-endian). */
    private static function blob(int $b0 = 0x5E, int $b1 = 0xA1, int $b2 = 16, int $b3 = 4, int $b4 = 7, int $b5 = 2, int $b6 = 0, int $b7 = 0, ?int $size = null, string $body = ''): string
    {
        $len = 16 + strlen($body);
        return base64_encode(pack('C8', $b0, $b1, $b2, $b3, $b4, $b5, $b6, $b7) . pack('P', $size ?? $len) . $body);
    }

    /** @param \Closure():mixed $f */
    private function refuses(string $message, \Closure $f, string $class = \InvalidArgumentException::class): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class, $e->getMessage());
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected: $message");
    }

    private static function libProp(): \ReflectionProperty
    {
        return new \ReflectionProperty(FheSeal::class, 'lib');
    }

    /** The smallest well-formed envelope (16 bytes, 24 characters) is accepted and decoded exactly; any other version/minor byte is not the gate's business. */
    public function testSmallestEnvelopeIsAccepted(): void
    {
        $b = self::blob();
        $this->assertSame(24, strlen($b));
        $this->assertSame(base64_decode($b, true), FheSeal::assertSealBlob($b, 'x'));
        $body = str_repeat("\x11", 8);
        $this->assertSame(base64_decode(self::blob(b5: 0, body: $body), true), FheSeal::assertSealBlob(self::blob(b5: 0, body: $body), 'x'));
    }

    /** Encoding refusals: not a string, too short, not a multiple of 4, characters outside base64 anywhere (start, end, a final newline). */
    public function testEncodingRefusals(): void
    {
        $msg = 'x: not a serialized SEAL object (bad encoding)';
        $this->refuses($msg, static fn() => FheSeal::assertSealBlob(42, 'x'));
        $this->refuses($msg, static fn() => FheSeal::assertSealBlob(str_repeat('A', 20), 'x'));
        $this->refuses($msg, static fn() => FheSeal::assertSealBlob(str_repeat('A', 26), 'x'));
        $this->refuses($msg, static fn() => FheSeal::assertSealBlob('!' . str_repeat('A', 27), 'x'));
        $this->refuses($msg, static fn() => FheSeal::assertSealBlob(str_repeat('A', 27) . '!', 'x'));
        $this->refuses($msg, static fn() => FheSeal::assertSealBlob(str_repeat('A', 27) . "\n", 'x'));
    }

    /** Each header field on its own is enough to refuse the envelope. */
    public function testEachHeaderFieldIsChecked(): void
    {
        $msg = 'h: not a serialized SEAL object (bad header)';
        foreach ([['b0' => 0x5F], ['b1' => 0xA0], ['b2' => 17], ['b5' => 3], ['b6' => 1], ['b7' => 1]] as $bad) {
            $this->refuses($msg, static fn() => FheSeal::assertSealBlob(self::blob(...$bad), 'h'));
        }
    }

    /** A declared size that differs from the decoded length is refused with both numbers. */
    public function testDeclaredSizeMustMatch(): void
    {
        $this->refuses('s: truncated or padded SEAL object (declared 17 bytes, got 24)', static fn() => FheSeal::assertSealBlob(self::blob(size: 17, body: str_repeat("\0", 8)), 's'));
    }

    /** Policy gates, each with its exact message: type, integer coefficients in either vector, the bound on every coefficient, dim and lengths. */
    public function testPolicyRefusals(): void
    {
        $this->refuses('policy must be an FheRiskPolicy', static fn() => FheSeal::requirePolicy('policy'));
        $ints = 'policy coefficients must be integers';
        $this->refuses($ints, static fn() => FheSeal::requirePolicy(new FheRiskPolicy(1000, 6, [0, 0, 1.5, 0, 0, 0], self::Z, 0)));
        $this->refuses($ints, static fn() => FheSeal::requirePolicy(new FheRiskPolicy(1000, 6, self::Z, [0, 0, 0, '1', 0, 0], 0)));
        $bound = 'policy coefficients must be integers with |value| < SIGNED_BOUND';
        $this->refuses($bound, static fn() => FheSeal::requirePolicy(new FheRiskPolicy(1000, 6, self::Z, self::Z, -FheSeal::SIGNED_BOUND)));
        $this->refuses($bound, static fn() => FheSeal::requirePolicy(new FheRiskPolicy(1000, 6, [0, FheSeal::SIGNED_BOUND, 0, 0, 0, 0], self::Z, 0)));
        $this->refuses($bound, static fn() => FheSeal::requirePolicy(new FheRiskPolicy(1000, 6, self::Z, [0, 0, 0, 0, 0, -FheSeal::SIGNED_BOUND], 0)));
        $this->refuses('policy.dim must be 6', static fn() => FheSeal::requirePolicy(new FheRiskPolicy(1000, 5, self::Z, self::Z, 0)));
        $this->refuses('policy weight vectors must have length 6', static fn() => FheSeal::requirePolicy(new FheRiskPolicy(1000, 6, self::Z, [0, 0, 0, 0, 0], 0)));
        // control: the extremes inside the bound are accepted, and kappa defaults to 1
        $ok = new FheRiskPolicy(1000, 6, [FheSeal::SIGNED_BOUND - 1, 0, 0, 0, 0, 0], self::Z, 1 - FheSeal::SIGNED_BOUND);
        FheSeal::requirePolicy($ok);
        $this->assertSame(1.0, $ok->kappa);
    }

    /** The gate entry points check the policy before touching any key material. */
    public function testGateEntryPointsCheckThePolicyFirst(): void
    {
        $bad = new FheRiskPolicy(1000, 5, self::Z, self::Z, 0);
        $this->refuses('policy.dim must be 6', static fn() => FheSeal::evalRiskGate('x', 'x', 'x', $bad));
        $this->refuses('policy.dim must be 6', static fn() => FheSeal::decryptVerdict('x', 'x', 'x', $bad));
    }

    /** Input gates: exactly six non-negative integers below the signed bound. */
    public function testInputRefusals(): void
    {
        $this->refuses('inputsScaled must have length 6', static fn() => FheSeal::encryptRiskInputs('x', [1, 2, 3, 4, 5]));
        $each = 'each scaled input must be a non-negative integer below the signed bound';
        foreach ([[0, 0, 0, 0, 0, -1], [FheSeal::SIGNED_BOUND, 0, 0, 0, 0, 0], [0, 0, 1.5, 0, 0, 0]] as $in) {
            $this->refuses($each, static fn() => FheSeal::encryptRiskInputs('x', $in));
        }
    }

    /** A library that cannot be loaded makes available() false, never true. */
    public function testUnloadableLibraryIsNotAvailable(): void
    {
        $prop = self::libProp();
        $saved = $prop->getValue();
        $env = getenv('ATLAS_PCA_LIBSEALC');
        try {
            putenv('ATLAS_PCA_LIBSEALC=' . sys_get_temp_dir() . '/pca-k25-no-such-dir/libsealc-missing.so');
            $prop->setValue(null, null);
            $this->assertFalse(FheSeal::available());
        } finally {
            putenv($env === false ? 'ATLAS_PCA_LIBSEALC' : 'ATLAS_PCA_LIBSEALC=' . $env);
            $prop->setValue(null, $saved);
        }
    }

    /** Without ATLAS_PCA_LIBSEALC the packaged library is the one loaded. */
    public function testPackagedLibraryIsUsedWithoutTheVariable(): void
    {
        $this->needLib();
        $env = getenv('ATLAS_PCA_LIBSEALC');
        if ($env === false || $env === '' || NativeDir::lib('sealc') !== null) {
            $this->markTestSkipped('needs ATLAS_PCA_LIBSEALC and no packaged libsealc');
        }
        $dir = NativeDir::dir();
        $name = PHP_OS_FAMILY === 'Windows' ? 'sealc.dll' : (PHP_OS_FAMILY === 'Darwin' ? 'libsealc.dylib' : 'libsealc.so');
        $lock = fopen(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k25-packaged-sealc.lock', 'c');
        $this->assertIsResource($lock);
        flock($lock, LOCK_EX);
        $prop = self::libProp();
        $saved = $prop->getValue();
        $made = false;
        try {
            $made = !is_dir($dir) && @mkdir($dir, 0777, true);
            $this->assertTrue(copy($env, $dir . '/' . $name));
            putenv('ATLAS_PCA_LIBSEALC');
            $prop->setValue(null, null);
            $this->assertTrue(FheSeal::available());
        } finally {
            @unlink($dir . '/' . $name);
            if ($made) {
                @rmdir($dir);
            }
            putenv('ATLAS_PCA_LIBSEALC=' . $env);
            $prop->setValue(null, $saved);
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** SEAL's refusal of a stream surfaces as the call's name and its 32-bit HRESULT. */
    public function testLoadFailureNamesTheCallAndItsHresult(): void
    {
        $this->needLib();
        // a well-formed envelope from a SEAL major version that does not exist
        $blob = self::blob(b3: 0, b4: 0, b5: 0);
        try {
            FheSeal::encryptRiskInputs($blob, self::Z);
            $this->fail('a foreign stream must be refused');
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertMatchesRegularExpression('/\Aseal PublicKey_Load failed: 0x(8[0-9a-f]{7})\z/', $e->getMessage());
            // E_POINTER, E_UNEXPECTED, E_OUTOFMEMORY, E_INVALIDARG, COR_E_INVALIDOPERATION, COR_E_IO: the codes the SEAL C API returns
            $this->assertContains(substr($e->getMessage(), -8), ['80004003', '8000ffff', '8007000e', '80070057', '80131509', '80131620']);
        }
    }

    /**
     * Keys are saved unseeded, as the reference saves them: each stream is at least the entropy of its uniform polynomials (two per
     * public key, over five primes of 42+ bits), more than a seeded stream (one polynomial and a seed) can be. Then the verdict
     * boundaries: a negative raw risk clamps to exactly 0, a slack of exactly 0 admits, and inputs keyed 10..15 are read in order.
     */
    public function testUnseededKeysAndVerdictBoundaries(): void
    {
        $this->needLib();
        $keys = FheSeal::keygen();
        $this->assertGreaterThan(385000, strlen((string) base64_decode($keys->publicKey, true)));
        $this->assertGreaterThan(1540000, strlen((string) base64_decode($keys->relinKeys, true)));
        $this->assertGreaterThan(38500000, strlen((string) base64_decode($keys->galoisKeys, true)));
        $pol = new FheRiskPolicy(1000, 6, [-1, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 0], 5);
        foreach ([[5, 1, 1, 1, 1, 1], [10 => 5, 11 => 1, 12 => 1, 13 => 1, 14 => 1, 15 => 1]] as $x) {
            $gate = FheSeal::evalRiskGate($keys->publicKey, $keys->galoisKeys, FheSeal::encryptRiskInputs($keys->publicKey, $x), $pol);
            $v = FheSeal::decryptVerdict($keys->secretKey, $gate->encRiskRaw, $gate->encSlack, $pol);
            $this->assertSame(0, $v->rScaled);
            $this->assertSame(0, $v->slack);
            $this->assertTrue($v->admit);
        }
    }

    /** All-zero weight vectors are a fresh encryption of zero (SEAL refuses a multiply by an all-zero plaintext). */
    public function testAllZeroWeightsAreAnEncryptionOfZero(): void
    {
        $this->needLib();
        $keys = FheSeal::keygen();
        $pol = new FheRiskPolicy(1000, 6, self::Z, self::Z, 7);
        $gate = FheSeal::evalRiskGate($keys->publicKey, $keys->galoisKeys, FheSeal::encryptRiskInputs($keys->publicKey, [3, 3, 3, 3, 3, 3]), $pol);
        $v = FheSeal::decryptVerdict($keys->secretKey, $gate->encRiskRaw, $gate->encSlack, $pol);
        $this->assertSame([0, 7, true], [$v->rScaled, $v->slack, $v->admit]);
    }
}
