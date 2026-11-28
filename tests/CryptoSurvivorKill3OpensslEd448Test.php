<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\OpensslEd448;
use Atlas\Pca\OpensslPq;
use PHPUnit\Framework\TestCase;

/** Ed448 over libcrypto: exact key / signature lengths (never a prefix), fail closed without a backend, the loader's candidate list. */
final class CryptoSurvivorKill3OpensslEd448Test extends TestCase
{
    private static function seed(): string
    {
        return substr(hash('sha512', 'atlas-pca-conformance/ed448-php/a', true), 0, 57);
    }

    /** The public key of seed() (JoseEd448Pss256Test's independent vector). */
    private static function pub(): string
    {
        return (string)base64_decode(strtr('cZ_je9oGAxBnW6xt8Dg8MankL6dx-NMTZ1czHJT5OQw3OJzsgmrPe8a8aSm8SS3ZLVF5-U90huiA', '-_', '+/'), true);
    }

    private function needEd448(): void
    {
        if (!OpensslEd448::available()) {
            $this->assertNotSame('1', getenv('PCA_REQUIRE_MLDSA'), 'Ed448 must be available on the OpenSSL >= 3.5 CI promises');
            $this->markTestSkipped('Ed448 needs ext-ffi and an OpenSSL libcrypto');
        }
    }

    /** Run `$f` with the backend forced absent (as on a host without ext-ffi / libcrypto), restoring the loaded handle after. */
    private static function withoutBackend(callable $f): mixed
    {
        $tried = new \ReflectionProperty(OpensslEd448::class, 'tried');
        $ffi = new \ReflectionProperty(OpensslEd448::class, 'ffi');
        $saved = [$tried->getValue(), $ffi->getValue()];
        $tried->setValue(null, true);
        $ffi->setValue(null, null);
        try {
            return $f();
        } finally {
            $tried->setValue(null, $saved[0]);
            $ffi->setValue(null, $saved[1]);
        }
    }

    /** Off Windows the candidates are exactly the post-quantum loader's, all of them, in order. */
    public function testCandidatesAreThePqLoaders(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            $this->markTestSkipped('Windows appends PHP\'s own libcrypto');
        }
        $this->assertSame(OpensslPq::candidates(), OpensslEd448::candidates());
    }

    /** Without a backend: unavailable, nothing verifies, signing throws its reason. */
    public function testFailsClosedWithoutBackend(): void
    {
        $r = self::withoutBackend(static function (): array {
            $msg = '';
            try {
                OpensslEd448::sign(self::seed(), 'm');
            } catch (\RuntimeException $e) {
                $msg = $e->getMessage();
            }
            return [OpensslEd448::available(), OpensslEd448::verify(self::pub(), str_repeat("\0", 114), 'm'), $msg];
        });
        $this->assertSame([false, false, 'Ed448 needs ext-ffi and an OpenSSL libcrypto (set ATLAS_PCA_LIBCRYPTO)'], $r);
    }

    /** A private key that is not 57 bytes is refused before libcrypto reads it. */
    public function testShortPrivateKeyIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('an Ed448 private key is 57 bytes');
        OpensslEd448::sign(substr(self::seed(), 1), 'm');
    }

    /** A valid signature under a key or signature carrying one extra byte is refused: the lengths are exact, never a prefix. */
    public function testOverlongKeyOrSignatureIsRefused(): void
    {
        $this->needEd448();
        $sig = OpensslEd448::sign(self::seed(), 'atlas ed448 vector');
        $this->assertTrue(OpensslEd448::verify(self::pub(), $sig, 'atlas ed448 vector'));
        $this->assertFalse(OpensslEd448::verify(self::pub() . "\0", $sig, 'atlas ed448 vector'));
        $this->assertFalse(OpensslEd448::verify(self::pub(), $sig . "\0", 'atlas ed448 vector'));
    }

    /** The empty message signs and verifies. */
    public function testEmptyMessageRoundTrip(): void
    {
        $this->needEd448();
        $sig = OpensslEd448::sign(self::seed(), '');
        $this->assertSame(114, strlen($sig));
        $this->assertTrue(OpensslEd448::verify(self::pub(), $sig, ''));
        $this->assertFalse(OpensslEd448::verify(self::pub(), $sig, "\0"));
    }

    /** Where CI promises OpenSSL >= 3.5, a fresh load reports Ed448 available. */
    public function testFreshLoadIsAvailableWhereCiPromisesIt(): void
    {
        if (getenv('PCA_REQUIRE_MLDSA') !== '1') {
            $this->markTestSkipped('PCA_REQUIRE_MLDSA is not set');
        }
        $tried = new \ReflectionProperty(OpensslEd448::class, 'tried');
        $ffi = new \ReflectionProperty(OpensslEd448::class, 'ffi');
        $saved = [$tried->getValue(), $ffi->getValue()];
        $tried->setValue(null, false);
        $ffi->setValue(null, null);
        try {
            $this->assertTrue(OpensslEd448::available());
        } finally {
            $tried->setValue(null, $saved[0]);
            $ffi->setValue(null, $saved[1]);
        }
    }
}
