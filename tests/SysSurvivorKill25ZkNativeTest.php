<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ZkNative.php';

use Atlas\Pca\NativeDir;
use Atlas\Pca\ZkBackendMissing;
use Atlas\Pca\ZkNative;
use PHPUnit\Framework\TestCase;

/**
 * Group 25 kills for src/ZkNative.php: argument refusals before the library, exact verify verdicts over the bundled BN254 sample,
 * the strict/compat flag, prover error text, and how the library is located. Library tests skip without libpcazk
 * (ATLAS_PCA_LIBPCAZK_REQUIRED=1 makes that a failure).
 */
final class SysSurvivorKill25ZkNativeTest extends TestCase
{
    private const LOAD_PREFIX = 'libpcazk could not be loaded (set ATLAS_PCA_LIBPCAZK to the library): ';
    private const EMPTY_PROVE = 'zk native: the wasm, the zkey and the input must not be empty';
    private const CURVE_MSG = 'zk native: the curve is CURVE_BN254 or CURVE_BLS12_381 (CURVE_FROM_KEY only for verify in the default mode)';

    private function needLib(): void
    {
        if (ZkNative::available()) {
            return;
        }
        if (getenv('ATLAS_PCA_LIBPCAZK_REQUIRED') === '1') {
            $this->fail('libpcazk is required here (ATLAS_PCA_LIBPCAZK)');
        }
        $this->markTestSkipped('needs libpcazk (ATLAS_PCA_LIBPCAZK)');
    }

    /** @return array{0:string,1:string,2:string} the bundled BN254 key, the sample proof and its public signals as JSON text */
    private static function sample(): array
    {
        $dir = dirname(__DIR__) . '/circuits';
        $p = json_decode((string) file_get_contents($dir . '/policyvm_sample_proof.json'), true, 512, JSON_THROW_ON_ERROR);
        return [(string) file_get_contents($dir . '/policyvm_vkey.json'), json_encode($p['proof'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            json_encode($p['publicSignals'], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)];
    }

    private static function libProp(): \ReflectionProperty
    {
        return new \ReflectionProperty(ZkNative::class, 'lib');
    }

    /** @param \Closure():mixed $f */
    private function throwsExactly(string $class, string $message, \Closure $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class, $e->getMessage());
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected $class");
    }

    /** @param \Closure():mixed $f */
    private function proveFailsWithText(int $code, string $textPrefix, \Closure $f): void
    {
        try {
            $f();
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertStringStartsWith("zk native: prove failed with code $code: $textPrefix", $e->getMessage());
            return;
        }
        $this->fail('expected the library\'s prove error');
    }

    /** Usage errors of prove are refused in PHP with their exact message, before the library is touched. */
    public function testProveArgumentRefusals(): void
    {
        $this->throwsExactly(\InvalidArgumentException::class, self::CURVE_MSG, static fn() => ZkNative::prove(ZkNative::CURVE_FROM_KEY, 'w', 'z', '{}'));
        $this->throwsExactly(\InvalidArgumentException::class, self::CURVE_MSG, static fn() => ZkNative::prove(7, 'w', 'z', '{}'));
        $this->throwsExactly(\InvalidArgumentException::class, 'zk native: a seed is 32 bytes', static fn() => ZkNative::prove(ZkNative::CURVE_BN254, 'w', 'z', '{}', str_repeat("\1", 31)));
        $this->throwsExactly(\InvalidArgumentException::class, 'zk native: a seed is 32 bytes', static fn() => ZkNative::prove(ZkNative::CURVE_BN254, 'w', 'z', '{}', str_repeat("\1", 33)));
        $this->throwsExactly(\InvalidArgumentException::class, self::EMPTY_PROVE, static fn() => ZkNative::prove(ZkNative::CURVE_BN254, '', 'z', '{}'));
        $this->throwsExactly(\InvalidArgumentException::class, self::EMPTY_PROVE, static fn() => ZkNative::prove(ZkNative::CURVE_BN254, 'w', '', '{}'));
        $this->throwsExactly(\InvalidArgumentException::class, self::EMPTY_PROVE, static fn() => ZkNative::prove(ZkNative::CURVE_BLS12_381, 'w', 'z', ''));
    }

    /** Usage errors of verify are refused in PHP: an unknown curve in either mode, CURVE_FROM_KEY in strict mode. */
    public function testVerifyCurveRefusals(): void
    {
        $this->throwsExactly(\InvalidArgumentException::class, self::CURVE_MSG, static fn() => ZkNative::verify(7, '{}', '{}', '[]'));
        $this->throwsExactly(\InvalidArgumentException::class, self::CURVE_MSG, static fn() => ZkNative::verify(-1, '{}', '{}', '[]', true));
        $this->throwsExactly(\InvalidArgumentException::class, self::CURVE_MSG, static fn() => ZkNative::verify(ZkNative::CURVE_FROM_KEY, '{}', '{}', '[]', true));
    }

    /** The library's prove error is surfaced with its code and message, whether or not a seed is given. */
    public function testProveErrorCarriesTheLibraryText(): void
    {
        $this->needLib();
        $this->proveFailsWithText(-6, 'input is not JSON: ', static fn() => ZkNative::prove(ZkNative::CURVE_BN254, 'w', 'z', 'not json'));
        $this->proveFailsWithText(-6, 'input is not JSON: ', static fn() => ZkNative::prove(ZkNative::CURVE_BLS12_381, 'w', 'z', 'not json', str_repeat("\7", 32)));
    }

    /** Exact verdicts: the sample verifies in both modes, a changed signal fails the pairing, and an empty argument is bad_json. */
    public function testVerifyVerdicts(): void
    {
        $this->needLib();
        $this->assertNotSame('', ZkNative::version());
        [$vk, $proof, $signals] = self::sample();
        $ok = ['ok' => true, 'reason' => null];
        $this->assertSame($ok, ZkNative::verify(ZkNative::CURVE_BN254, $vk, $proof, $signals));
        $this->assertSame($ok, ZkNative::verify(ZkNative::CURVE_BN254, $vk, $proof, $signals, true));
        $this->assertSame($ok, ZkNative::verify(ZkNative::CURVE_FROM_KEY, $vk, $proof, $signals));
        $ps = json_decode($signals, true, 512, JSON_THROW_ON_ERROR);
        $ps[0] = $ps[0] === '1' ? '2' : '1';
        $this->assertSame(['ok' => false, 'reason' => 'pairing equation does not hold'],
            ZkNative::verify(ZkNative::CURVE_BN254, $vk, $proof, json_encode($ps, JSON_THROW_ON_ERROR)));
        $bad = ['ok' => false, 'reason' => 'bad_json'];
        $this->assertSame($bad, ZkNative::verify(ZkNative::CURVE_BN254, '', $proof, $signals));
        $this->assertSame($bad, ZkNative::verify(ZkNative::CURVE_BN254, $vk, '', $signals));
        $this->assertSame($bad, ZkNative::verify(ZkNative::CURVE_BN254, $vk, $proof, ''));
        $this->assertSame($bad, ZkNative::verify(ZkNative::CURVE_BLS12_381, $vk, '', $signals, true));
    }

    /** A key with an IC entry beyond signals + 1 is what snarkjs accepts (default mode) and what strict mode refuses. */
    public function testStrictFlagReachesTheLibrary(): void
    {
        $this->needLib();
        [$vk, $proof, $signals] = self::sample();
        $key = json_decode($vk, true, 512, JSON_THROW_ON_ERROR);
        $key['IC'][] = $key['IC'][0];
        $extra = json_encode($key, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $this->assertSame(['ok' => true, 'reason' => null], ZkNative::verify(ZkNative::CURVE_BN254, $extra, $proof, $signals));
        $this->assertSame(['ok' => true, 'reason' => null], ZkNative::verify(ZkNative::CURVE_FROM_KEY, $extra, $proof, $signals));
        $strict = ZkNative::verify(ZkNative::CURVE_BN254, $extra, $proof, $signals, true);
        $this->assertFalse($strict['ok']);
        $this->assertIsString($strict['reason']);
    }

    /**
     * Without ATLAS_PCA_LIBPCAZK the library is the packaged one, else libpcazk.so; a load failure is ZkBackendMissing with the
     * loader's message after the hint, never a verdict.
     */
    public function testLibraryLocation(): void
    {
        $this->needLib();
        $env = getenv('ATLAS_PCA_LIBPCAZK');
        if ($env === false || $env === '' || NativeDir::lib('pcazk') !== null) {
            $this->markTestSkipped('needs ATLAS_PCA_LIBPCAZK and no packaged libpcazk');
        }
        $dir = NativeDir::dir();
        $name = PHP_OS_FAMILY === 'Windows' ? 'pcazk.dll' : (PHP_OS_FAMILY === 'Darwin' ? 'libpcazk.dylib' : 'libpcazk.so');
        // parallel mutation workers share the package directory: one at a time
        $lock = fopen(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k25-packaged-zk.lock', 'c');
        $this->assertIsResource($lock);
        flock($lock, LOCK_EX);
        $prop = self::libProp();
        $saved = $prop->getValue();
        $made = false;
        try {
            putenv('ATLAS_PCA_LIBPCAZK');
            $prop->setValue(null, null);
            try {
                ZkNative::version();
                $this->markTestSkipped('libpcazk.so is on the loader path here');
            } catch (ZkBackendMissing $e) {
                $prev = $e->getPrevious();
                $this->assertInstanceOf(\Throwable::class, $prev);
                $this->assertSame(self::LOAD_PREFIX . $prev->getMessage(), $e->getMessage());
                $this->assertSame(0, $e->getCode());
            }
            $this->assertFalse(ZkNative::available());
            $made = !is_dir($dir) && @mkdir($dir, 0777, true);
            $this->assertTrue(copy($env, $dir . '/' . $name));
            $prop->setValue(null, null);
            $this->assertTrue(ZkNative::available(), 'the packaged library is used when ATLAS_PCA_LIBPCAZK is unset');
            $this->assertNotSame('', ZkNative::version());
        } finally {
            @unlink($dir . '/' . $name);
            if ($made) {
                @rmdir($dir);
            }
            putenv('ATLAS_PCA_LIBPCAZK=' . $env);
            $prop->setValue(null, $saved);
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
