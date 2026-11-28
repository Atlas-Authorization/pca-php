<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ZkNative.php';

use Atlas\Pca\ZkBackendMissing;
use Atlas\Pca\ZkNative;
use PHPUnit\Framework\TestCase;

/** Group 25b kill for src/ZkNative.php: without ext-ffi the backend is missing, with the exact reason. */
final class SysSurvivorKill25bZkNativeTest extends TestCase
{
    protected function tearDown(): void
    {
        ZkNative::$extensionHook = null;
        ZkNative::$proveHook = null;
    }

    public function testWithoutFfiTheBackendIsMissing(): void
    {
        $prop = new \ReflectionProperty(ZkNative::class, 'lib');
        $saved = $prop->getValue();
        $asked = [];
        ZkNative::$extensionHook = static function (string $name) use (&$asked): bool {
            $asked[] = $name;
            return false;
        };
        $prop->setValue(null, null);
        try {
            ZkNative::version();
            $this->fail('no ext-ffi must be refused');
        } catch (ZkBackendMissing $e) {
            $this->assertSame('Groth16 needs ext-ffi (ffi.enable=true)', $e->getMessage());
            $this->assertNull($e->getPrevious());
        } finally {
            $prop->setValue(null, $saved);
        }
        $this->assertSame(['FFI'], $asked);
    }

    /**
     * A failed prove throws with the library's code (pca-zk capi.rs: the input JSON is parsed first, then the zkey): a garbage zkey with
     * valid input is PCA_ZK_ERR_ZKEY (-5), bad input JSON is PCA_ZK_ERR_INPUT (-6) whatever the wasm and zkey are.
     */
    public function testFailedProveCarriesTheLibraryCode(): void
    {
        if (!ZkNative::available()) {
            if (getenv('ATLAS_PCA_LIBPCAZK_REQUIRED') === '1') {
                $this->fail('libpcazk is required here (ATLAS_PCA_LIBPCAZK)');
            }
            $this->markTestSkipped('needs libpcazk (ATLAS_PCA_LIBPCAZK)');
        }
        foreach ([['{}', 'zk native: prove failed with code -5: not a zkey file (bad magic)'], ['not json', 'zk native: prove failed with code -6: input is not JSON: ']] as [$input, $prefix]) {
            try {
                ZkNative::prove(ZkNative::CURVE_BN254, 'garbage wasm', 'garbage zkey', $input);
                $this->fail('a garbage proving key must fail');
            } catch (\RuntimeException $e) {
                $this->assertSame(\RuntimeException::class, $e::class);
                $this->assertStringStartsWith($prefix, $e->getMessage());
            }
        }
    }

    /** A library return code of 0 is success: prove returns the (here empty) output text instead of throwing; -1 is still a failure. */
    public function testReturnCodeZeroIsSuccess(): void
    {
        if (!ZkNative::available()) {
            if (getenv('ATLAS_PCA_LIBPCAZK_REQUIRED') === '1') {
                $this->fail('libpcazk is required here (ATLAS_PCA_LIBPCAZK)');
            }
            $this->markTestSkipped('needs libpcazk (ATLAS_PCA_LIBPCAZK)');
        }
        $curves = [];
        ZkNative::$proveHook = static function (int $curve) use (&$curves): int {
            $curves[] = $curve;
            return 0;
        };
        $this->assertSame('', ZkNative::prove(ZkNative::CURVE_BN254, 'w', 'z', '{}'));
        $this->assertSame([ZkNative::CURVE_BN254], $curves);
        ZkNative::$proveHook = static fn(int $curve): int => -1;
        try {
            ZkNative::prove(ZkNative::CURVE_BN254, 'w', 'z', '{}');
            $this->fail('code -1 must be refused');
        } catch (\RuntimeException $e) {
            $this->assertSame('zk native: prove failed with code -1', $e->getMessage());
        }
    }
}
