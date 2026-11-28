<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcLweLattice;
use Atlas\Pca\NativeDir;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcLweLattice: every size refusal before the library is called (they run everywhere), the return-code check, the
 * hash-input cap, and with liblweot how the library is located and that a load failure reads as unavailable.
 * ATLAS_PCA_LIBLWEOT_REQUIRED=1 (the lwe-ot workflow) fails instead of skipping.
 */
final class MpcSurvivorKill34MpcLweLatticeTest extends TestCase
{
    private function needLattice(): void
    {
        if (!MpcLweLattice::available()) {
            if (getenv('ATLAS_PCA_LIBLWEOT_REQUIRED') === '1') {
                $this->fail('liblweot must load (ATLAS_PCA_LIBLWEOT, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and liblweot (ATLAS_PCA_LIBLWEOT)');
        }
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame($class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected $class: $msg");
    }

    private static function libProp(): \ReflectionProperty
    {
        return new \ReflectionProperty(MpcLweLattice::class, 'lib');
    }

    /** A wrong-size seed, key, ciphertext or ring operand is refused in PHP with its exact message, never handed to the library. */
    public function testSizesAreRefusedBeforeTheLibrary(): void
    {
        $iae = \InvalidArgumentException::class;
        $sym = str_repeat("\1", MpcLweLattice::SYM_BYTES);
        $tv = str_repeat("\1", MpcLweLattice::TVEC_BYTES);
        self::refuses($iae, 'lattice: seed must be exactly 32 bytes', static fn() => MpcLweLattice::keygen(str_repeat("\1", 31)));
        self::refuses($iae, 'lattice: seed must be exactly 32 bytes', static fn() => MpcLweLattice::keygenFips203(str_repeat("\1", 31)));
        self::refuses($iae, 'lattice: public key must be exactly 1184 bytes', static fn() => MpcLweLattice::enc(str_repeat("\1", 1183), $sym, $sym));
        self::refuses($iae, 'lattice: secret key must be exactly 1152 bytes', static fn() => MpcLweLattice::dec(str_repeat("\1", 1151), str_repeat("\1", MpcLweLattice::CT_BYTES)));
        self::refuses($iae, 'lattice: a must be exactly 1152 bytes', static fn() => MpcLweLattice::ringAdd(str_repeat("\1", 1151), $tv));
        self::refuses($iae, 'lattice: a must be exactly 1152 bytes', static fn() => MpcLweLattice::ringSub(str_repeat("\1", 1151), $tv));
    }

    /** More than 4096 hash input bytes are refused in PHP with the cap in the message. */
    public function testHashInputCap(): void
    {
        self::refuses(\InvalidArgumentException::class, 'lattice: hash input must be at most 4096 bytes', static fn() => MpcLweLattice::hashToRing(str_repeat('a', 4097)));
    }

    /** A non-zero library return code is a refusal naming the operation and the code. */
    public function testNonZeroReturnCodeIsARefusal(): void
    {
        $ok = new \ReflectionMethod(MpcLweLattice::class, 'ok');
        self::refuses(\RuntimeException::class, 'lattice: enc refused (-1)', static fn() => $ok->invoke(null, -1, 'enc'));
        $ok->invoke(null, 0, 'enc');
        $this->assertTrue(true, 'rc 0 passes');
    }

    /**
     * A library that cannot be loaded reads as unavailable. Without ATLAS_PCA_LIBLWEOT the library is the packaged one (native/<os>-<arch>),
     * else liblweot.so on the loader path.
     */
    public function testLoadFailureAndLibraryLocation(): void
    {
        $this->needLattice();
        $env = getenv('ATLAS_PCA_LIBLWEOT');
        $prop = self::libProp();
        $saved = $prop->getValue();
        $lock = fopen(sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k34-packaged-lweot.lock', 'c');
        $this->assertIsResource($lock);
        flock($lock, LOCK_EX);
        $dir = NativeDir::dir();
        $name = PHP_OS_FAMILY === 'Windows' ? 'lweot.dll' : (PHP_OS_FAMILY === 'Darwin' ? 'liblweot.dylib' : 'liblweot.so');
        $made = [];
        $copied = false;
        try {
            putenv('ATLAS_PCA_LIBLWEOT=' . sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-k34-no-such-liblweot.so');
            $prop->setValue(null, null);
            $this->assertFalse(MpcLweLattice::available(), 'a library that fails to load is unavailable');
            if ($env === false || $env === '' || NativeDir::lib('lweot') !== null) {
                $this->markTestSkipped('the location half needs ATLAS_PCA_LIBLWEOT and no packaged liblweot');
            }
            putenv('ATLAS_PCA_LIBLWEOT');
            $prop->setValue(null, null);
            if (MpcLweLattice::available()) {
                $this->markTestSkipped('liblweot.so is on the loader path here');
            }
            foreach ([dirname($dir), $dir] as $d) {
                if (!is_dir($d) && @mkdir($d, 0777)) {
                    $made[] = $d;
                }
            }
            $copied = copy($env, $dir . '/' . $name);
            $this->assertTrue($copied);
            $prop->setValue(null, null);
            $this->assertTrue(MpcLweLattice::available(), 'the packaged library is used when ATLAS_PCA_LIBLWEOT is unset');
            $this->assertSame(MpcLweLattice::TVEC_BYTES, strlen(MpcLweLattice::hashToRing('mpc34')));
        } finally {
            if ($copied) {
                @unlink($dir . '/' . $name);
            }
            foreach (array_reverse($made) as $d) {
                @rmdir($d);
            }
            putenv($env === false ? 'ATLAS_PCA_LIBLWEOT' : 'ATLAS_PCA_LIBLWEOT=' . $env);
            $prop->setValue(null, $saved);
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }
}
