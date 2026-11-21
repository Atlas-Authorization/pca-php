<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Jose;
use Atlas\Pca\JoseError;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslEd448;
use PHPUnit\Framework\TestCase;

/** Ed448 (OpenSSL over ext-ffi) and PS256 signing (phpseclib): a deterministic Ed448 vector and a PS256 round trip. */
final class JoseEd448Pss256Test extends TestCase
{
    /** key = first 57 bytes of sha512("atlas-pca-conformance/ed448-php/a"); x and sig from an independent implementation */
    private const X = 'cZ_je9oGAxBnW6xt8Dg8MankL6dx-NMTZ1czHJT5OQw3OJzsgmrPe8a8aSm8SS3ZLVF5-U90huiA';
    private const SIG = 'ZqHq9zEqT81P0RYCqm9wqoHIOqBj98zrXWnt-Ed1_Xcy-ULDEhQ1CwMPoYR0D82Wc6KhASyWMvOA2uHGb8e-uFnKmij2wy9IPw1VmTagk2nTupQKMT_r1EZzCJzrYjF6RGw3BoTeCVQcGeJjprXtMSAA';

    private static function seed(): string
    {
        return substr(hash('sha512', 'atlas-pca-conformance/ed448-php/a', true), 0, 57);
    }

    private function needEd448(): void
    {
        if (!OpensslEd448::available()) {
            $this->markTestSkipped('Ed448 needs ext-ffi and an OpenSSL libcrypto');
        }
    }

    public function testEd448SignatureMatchesTheIndependentVector(): void
    {
        $this->needEd448();
        $sig = OpensslEd448::sign(self::seed(), 'atlas ed448 vector');
        $this->assertSame(self::SIG, Jose::b64u($sig));
        $pub = Jose::lenientB64d(self::X);
        $this->assertTrue(OpensslEd448::verify($pub, $sig, 'atlas ed448 vector'));
        $this->assertFalse(OpensslEd448::verify($pub, $sig, 'atlas ed448 vectoR'));
        $bad = $sig;
        $bad[5] = chr(ord($bad[5]) ^ 1);
        $this->assertFalse(OpensslEd448::verify($pub, $bad, 'atlas ed448 vector'));
        $this->assertFalse(OpensslEd448::verify(substr($pub, 1), $sig, 'atlas ed448 vector'));
        $this->assertFalse(OpensslEd448::verify($pub, substr($sig, 1), 'atlas ed448 vector'));
    }

    public function testEdDsaJwsRoundTripOnAnEd448Jwk(): void
    {
        $this->needEd448();
        $priv = Obj::of(['kty' => 'OKP', 'crv' => 'Ed448', 'x' => self::X, 'd' => Jose::b64u(self::seed())]);
        $pub = Obj::of(['kty' => 'OKP', 'crv' => 'Ed448', 'x' => self::X]);
        $sig = Jose::jwsSign('EdDSA', $priv, 'payload');
        $this->assertSame(114, strlen($sig));
        $this->assertTrue(Jose::jwsVerify('EdDSA', $pub, $sig, 'payload'));
        $this->assertFalse(Jose::jwsVerify('EdDSA', $pub, $sig, 'payloaD'));
    }

    public function testPs256SignVerifyRoundTrip(): void
    {
        $this->assertTrue(class_exists(\phpseclib3\Crypt\RSA::class), 'phpseclib/phpseclib is not installed (composer require)');
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $this->assertNotFalse($key);
        $sig = Jose::jwsSign('PS256', $key, 'payload');
        $this->assertSame(256, strlen($sig));
        $this->assertTrue(Jose::jwsVerify('PS256', $key, $sig, 'payload'));
        $this->assertFalse(Jose::jwsVerify('PS256', $key, $sig, 'payloaD'));
        $this->expectException(JoseError::class);
        Jose::jwsSign('PS256', 'not a key', 'payload');
    }
}
