<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Fndsa;
use Atlas\Pca\FndsaNative;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * fn-dsa-512 / fn-dsa-1024 as pure suites of the core dispatch (Pca::verifyPinnedSuite / verifySuiteUnderKey): with no backend
 * registered they are refused (never accepted); with the libfndsa backend registered the known-answer signatures verify.
 * Real-backend cases need ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA); ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping.
 */
final class RefFndsaCoreTest extends TestCase
{
    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    public static function cSigned(): array
    {
        $j = json_decode((string) file_get_contents(__DIR__ . '/../test-data/ref-fndsa-kat.json'), true, 512, JSON_THROW_ON_ERROR);
        $o = [];
        foreach ($j['c_signed'] as $i => $c) {
            $o["c_signed #$i " . $c['variant']] = [$c];
        }
        return $o;
    }

    private function real(): void
    {
        if (!FndsaNative::available()) {
            if (getenv('ATLAS_PCA_LIBFNDSA_REQUIRED') === '1') {
                $this->fail('libfndsa must load (ATLAS_PCA_LIBFNDSA, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA)');
        }
        Fndsa::setFalconBackend(FndsaNative::backend());
    }

    private static function core(array $c, ?string $vk = null, ?string $msg = null, ?string $sig = null): bool|string
    {
        $pk = Pca::b64u($vk ?? hex2bin($c['vk']));
        return Pca::verifyPinnedSuite($c['variant'], 'signer', $pk, $msg ?? hex2bin($c['msg']), Pca::b64u($sig ?? hex2bin($c['sig'])), null, $pk);
    }

    #[DataProvider('cSigned')]
    public function testNoBackendNeverAccepts(array $c): void
    {
        $this->assertFalse(Pca::suiteAvailable($c['variant']));
        $this->assertSame('unsupported_suite', self::core($c));
        $this->assertFalse(Pca::verifySuiteUnderKey($c['variant'], null, Pca::b64u(hex2bin($c['vk'])), hex2bin($c['msg']), Pca::b64u(hex2bin($c['sig'])), null));
    }

    #[DataProvider('cSigned')]
    public function testBackendVerifiesAndDeniesTampering(array $c): void
    {
        $this->real();
        $vk = hex2bin($c['vk']);
        $msg = hex2bin($c['msg']);
        $sig = hex2bin($c['sig']);
        $this->assertTrue(Pca::suiteAvailable($c['variant']));
        $this->assertTrue(self::core($c));
        $this->assertTrue(Pca::verifySuiteUnderKey($c['variant'], null, Pca::b64u($vk), $msg, Pca::b64u($sig), null));
        $flip = static function (string $b): string {
            $b[0] = chr(ord($b[0]) ^ 1);
            return $b;
        };
        $this->assertFalse(self::core($c, null, null, $flip($sig)));
        $this->assertFalse(self::core($c, null, $msg === '' ? "\x00" : $flip($msg), null)); // an empty message has no byte to flip
        $this->assertFalse(self::core($c, $flip($vk)));
        $this->assertFalse(self::core($c, $vk . "\x00"));
        $this->assertFalse(self::core($c, null, null, $sig . "\x00"));
    }

    public function testBackendThatThrowsDenies(): void
    {
        Fndsa::setFalconBackend(new \Atlas\Pca\FalconBackend(static fn() => throw new \RuntimeException('boom')));
        $c = array_values(self::cSigned())[0][0];
        $this->assertFalse(self::core($c));
    }
}
