<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcShake256;
use Atlas\Pca\OpensslPq;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcShake256: the output-length refusal, a fresh load finds the libcrypto (the FIPS 202 empty-message vector), a host
 * with ext-ffi never gets the missing-ext-ffi refusal, and a failing libcrypto digest call is raised. The cached handles are reset for
 * each load and restored afterwards.
 */
final class MpcSurvivorKill34MpcShake256Test extends TestCase
{
    /** SHAKE256 of the empty message, first 32 bytes (FIPS 202 / NIST example values). */
    private const EMPTY_32 = '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f';

    /** Whether some OpensslPq candidate libcrypto exposes SHAKE256 (probed here, independently of the class under test). */
    private static function libcryptoHasShake(): bool
    {
        if (!extension_loaded('FFI')) {
            return false;
        }
        foreach (OpensslPq::candidates() as $path) {
            try {
                $f = \FFI::cdef('void* EVP_MD_fetch(void* libctx, const char* algorithm, const char* properties);', $path);
                $md = $f->EVP_MD_fetch(null, 'SHAKE256', null);
                if ($md !== null && !\FFI::isNull($md)) {
                    return true;
                }
            } catch (\Throwable) {
                // next candidate
            }
        }
        return false;
    }

    /** @param \Closure():void $f runs with the cached library handles cleared; they are restored afterwards */
    private static function fresh(\Closure $f): void
    {
        $ffi = new \ReflectionProperty(MpcShake256::class, 'ffi');
        $md = new \ReflectionProperty(MpcShake256::class, 'md');
        $saved = [$ffi->getValue(), $md->getValue()];
        $ffi->setValue(null, null);
        $md->setValue(null, null);
        try {
            $f();
        } finally {
            $ffi->setValue(null, $saved[0]);
            $md->setValue(null, $saved[1]);
        }
    }

    /** An output length below 1 is refused before any library work. */
    public function testOutputLengthMustBePositive(): void
    {
        foreach ([0, -1] as $n) {
            try {
                MpcShake256::hash('m', $n);
                $this->fail('a non-positive length must be refused');
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('SHAKE256 output length must be positive', $e->getMessage());
            }
        }
    }

    /** With ext-ffi loaded a fresh load never refuses for a missing ext-ffi (it loads, or names the missing libcrypto). */
    public function testWithFfiTheRefusalIsNeverMissingFfi(): void
    {
        if (!extension_loaded('FFI')) {
            $this->markTestSkipped('needs ext-ffi');
        }
        self::fresh(function (): void {
            try {
                $this->assertSame(16, strlen(MpcShake256::hash('m', 16)));
            } catch (\RuntimeException $e) {
                $this->assertSame('no libcrypto with SHAKE256 (set ATLAS_PCA_LIBCRYPTO)', $e->getMessage());
            }
        });
    }

    /** When a candidate libcrypto has SHAKE256, a fresh load finds it and produces the standard digest. */
    public function testAFreshLoadFindsTheLibrary(): void
    {
        if (!self::libcryptoHasShake()) {
            $this->markTestSkipped('needs ext-ffi and a libcrypto with SHAKE256');
        }
        self::fresh(function (): void {
            $this->assertTrue(MpcShake256::available());
            $this->assertSame(self::EMPTY_32, bin2hex(MpcShake256::hash('', 32)));
        });
    }

    /** A digest call libcrypto refuses (no digest set) is raised as 'SHAKE256 failed', never returned as output. */
    public function testAFailingDigestCallIsRaised(): void
    {
        if (!self::libcryptoHasShake()) {
            $this->markTestSkipped('needs ext-ffi and a libcrypto with SHAKE256');
        }
        $this->assertTrue(MpcShake256::available());
        $md = new \ReflectionProperty(MpcShake256::class, 'md');
        $saved = $md->getValue();
        $md->setValue(null, \FFI::cdef()->new('void*')); // a NULL digest type
        try {
            MpcShake256::hash('m', 16);
            $this->fail('a refused digest call must raise');
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertSame('SHAKE256 failed', $e->getMessage());
        } finally {
            $md->setValue(null, $saved);
        }
    }
}
