<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcMlKem768;
use PHPUnit\Framework\TestCase;

/**
 * The MPC transcripts' ML-KEM-768 over libcrypto: the FIPS 203 known answer for the probe's own seed and message, the
 * encapsulation-key modulus check, libcrypto's refusals (short seed, short ikme, a public-only key at decapsulation), the
 * length gates and the no-backend paths. The known answer and the refusals were taken from OpenSSL 3.6 libcrypto directly.
 */
final class PqSurvivorKill14MpcMlKemTest extends TestCase
{
    private const EK_SHA256 = 'e68d60857f9cb41f88c278ca430e472c6df5679fd5bac3ce872334293c5d0c42';
    private const CT_SHA256 = 'cf2e49c7b792b92c9353575dea79546722b22d4ca66c7b7caef0454c49082934';
    private const SS = 'adb494c04fc78a643c632686e4c76ea471b4b7c30a14a5592dd3b0b8e6730359';

    /** The loaded libcrypto handle; on the OpenSSL >= 3.5 lane (PCA_REQUIRE_MLDSA=1) ML-KEM must be available, elsewhere the test skips. */
    private function need(): \FFI
    {
        if (!MpcMlKem768::available()) {
            $this->assertNotSame('1', getenv('PCA_REQUIRE_MLDSA'), 'ML-KEM-768 must be available on the OpenSSL >= 3.5 lane');
            $this->markTestSkipped('ML-KEM-768 needs ext-ffi and OpenSSL >= 3.5');
        }
        $f = (new \ReflectionProperty(MpcMlKem768::class, 'ffi'))->getValue();
        $this->assertInstanceOf(\FFI::class, $f);
        return $f;
    }

    private static function call(string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(MpcMlKem768::class, $method))->invoke(null, ...$args);
    }

    private function refuses(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $message], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail("expected $class: $message");
    }

    /** Seed 0x01 x 64 and message 0x02 x 32 (the probe's own inputs) reproduce the FIPS 203 answer, and decapsulation returns it. */
    public function testKnownAnswer(): void
    {
        $this->need();
        $k = MpcMlKem768::keygen(str_repeat("\x01", 64));
        $e = MpcMlKem768::encapsulate($k['publicKey'], str_repeat("\x02", 32));
        $this->assertSame([self::EK_SHA256, self::CT_SHA256, self::SS], [hash('sha256', $k['publicKey']), hash('sha256', $e['cipherText']), bin2hex($e['sharedSecret'])]);
        $this->assertSame(self::SS, bin2hex(MpcMlKem768::decapsulate($e['cipherText'], $k['secretKey'])));
        MpcMlKem768::free($k['secretKey']);
    }

    /** An encapsulation key with a coefficient >= q is refused at import. */
    public function testEncapsulationKeyModulusCheck(): void
    {
        $this->need();
        $bad = MpcMlKem768::keygen(str_repeat("\x01", 64))['publicKey'];
        $bad[0] = "\xFF";
        $bad[1] = chr(ord($bad[1]) | 0x0F);
        $this->refuses(\RuntimeException::class, 'ml-kem encapsulate: invalid public key', static fn() => MpcMlKem768::encapsulate($bad, str_repeat("\x02", 32)));
    }

    /** libcrypto's refusals keep their reason: a short seed, a short ikme, and a public-only key at decapsulation. */
    public function testLibcryptoRefusalsKeepTheirReason(): void
    {
        $f = $this->need();
        $k = MpcMlKem768::keygen(str_repeat("\x01", 64));
        $ct = MpcMlKem768::encapsulate($k['publicKey'], str_repeat("\x02", 32))['cipherText'];
        $this->refuses(\RuntimeException::class, 'ML-KEM-768 keygen refused the seed', static fn() => self::call('keygenWith', $f, "\x01"));
        $this->refuses(\RuntimeException::class, 'ml-kem encapsulate: init refused', static fn() => self::call('encapsulateWith', $f, $k['publicKey'], "\x02"));
        $pub = $f->EVP_PKEY_new_raw_public_key_ex(null, 'ML-KEM-768', null, self::call('bytes', $f, $k['publicKey']), 1184);
        $this->assertNotNull($pub);
        try {
            $this->refuses(\RuntimeException::class, 'ml-kem decapsulate: init refused', static fn() => MpcMlKem768::decapsulate($ct, $pub));
        } finally {
            $f->EVP_PKEY_free($pub);
        }
    }

    /** A ciphertext of the wrong length is refused before libcrypto sees it. */
    public function testDecapsulateLengthGate(): void
    {
        $this->need();
        $k = MpcMlKem768::keygen(str_repeat("\x01", 64));
        $ct = MpcMlKem768::encapsulate($k['publicKey'], str_repeat("\x02", 32))['cipherText'];
        $msg = 'ml-kem decapsulate: ciphertext must be exactly 1088 bytes';
        $this->refuses(\InvalidArgumentException::class, $msg, static fn() => MpcMlKem768::decapsulate(substr($ct, 1), $k['secretKey']));
        $this->refuses(\InvalidArgumentException::class, $msg, static fn() => MpcMlKem768::decapsulate($ct . "\0", $k['secretKey']));
    }

    /** The probe is false for a handle that lacks the ML-KEM calls (the throw is caught) and true for the real library. */
    public function testProbeIsARealRoundTrip(): void
    {
        $f = $this->need();
        $this->assertTrue(self::call('probe', $f));
        $this->assertFalse(self::call('probe', \FFI::cdef('')));
    }

    /** The argument gates in front of libcrypto (no library needed). */
    public function testArgumentGates(): void
    {
        $this->refuses(\InvalidArgumentException::class, 'ml-kem keygen: seed must be exactly 64 bytes', static fn() => MpcMlKem768::keygen(str_repeat("\1", 63)));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem encapsulate: message must be exactly 32 bytes', static fn() => MpcMlKem768::encapsulate(str_repeat("\0", 1184), str_repeat("\2", 31)));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem encapsulate: public key must be exactly 1184 bytes', static fn() => MpcMlKem768::encapsulate(str_repeat("\0", 1183), str_repeat("\2", 32)));
    }

    /** Without a backend every operation fails closed with the install hint, and free() is a no-op. */
    public function testNoBackendFailsClosed(): void
    {
        if (!extension_loaded('FFI')) {
            $this->markTestSkipped('needs ext-ffi for a CData handle');
        }
        $handle = \FFI::cdef('')->new('int');
        $tried = new \ReflectionProperty(MpcMlKem768::class, 'tried');
        $ffi = new \ReflectionProperty(MpcMlKem768::class, 'ffi');
        $saved = [$tried->getValue(), $ffi->getValue()];
        $tried->setValue(null, true);
        $ffi->setValue(null, null);
        try {
            $this->assertFalse(MpcMlKem768::available());
            $this->refuses(\RuntimeException::class, 'ML-KEM-768 needs ext-ffi and OpenSSL >= 3.5 (set ATLAS_PCA_LIBCRYPTO)', static fn() => MpcMlKem768::keygen(str_repeat("\1", 64)));
            MpcMlKem768::free($handle);
        } finally {
            $tried->setValue(null, $saved[0]);
            $ffi->setValue(null, $saved[1]);
        }
    }
}
