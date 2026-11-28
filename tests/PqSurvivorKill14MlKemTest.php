<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\OpensslMlKem;
use PHPUnit\Framework\TestCase;

/**
 * ML-KEM-768 / -1024 over libcrypto: FIPS 203 known answers (seeded keygen, derandomised encapsulation, decapsulation and the
 * implicit-rejection secret), the expanded-key import rules (a damaged H(ek) is refused, an out-of-range s coefficient names its
 * residue, a damaged s gives the rejection secret), the encapsulation-key modulus check and every length / level gate.
 * The known answers come from the OpenSSL CLI (genpkey hexseed, pkeyutl -encap hexikme / -decap).
 */
final class PqSurvivorKill14MlKemTest extends TestCase
{
    /** level => [seed byte, message byte, sha256(ek), sha256(dk), sha256(ct), ss, ss of ct with byte 0 ^ 1, ss with s[0] + 1] */
    private const KAT = [
        768 => [1, 2, 'e68d60857f9cb41f88c278ca430e472c6df5679fd5bac3ce872334293c5d0c42',
            '8f324ffc8b6ca7d213f8a62912863b0776a2a5c6a0548dbb9a229f5db1ba4225',
            'cf2e49c7b792b92c9353575dea79546722b22d4ca66c7b7caef0454c49082934',
            'adb494c04fc78a643c632686e4c76ea471b4b7c30a14a5592dd3b0b8e6730359',
            '8f93d09b6ee99bd05521029b15bf11c73e16abd0bf2f1d4a0073b5db6f4be687',
            'e042103c8d4d1696d3e2aba601a8290369e23b1255af6be9226e2788152f11c3'],
        1024 => [3, 4, 'c689a514187dc91fc071566cbb4ecd867d8ea0b74880e42bd16bb81bd6ba6264',
            '841cf8a0c8f51578e38586ad0cb75fc239648c8f8ea218b0d84ec8ea6be04d45',
            '35d00f4a573eba0a3d4146e9b1fd3dc9f29045a87eacefec6140f8e5d13ef340',
            '610c0853b4ec1c401be9485db8440b96dd3bae7afa7bf613bb727dfd8d7a7d9e',
            'e9b5329d8e7e669c1029b6e20c0d583d19e80c4a3e444fabbbc4d79da414bc2a',
            '096296d3582388cc9a2fb46855741b39c3e5dbeebfd8cb0ab317a55585ecc7f8'],
    ];

    /** The loaded libcrypto handle; on the OpenSSL >= 3.5 lane (PCA_REQUIRE_MLDSA=1) ML-KEM must be available, elsewhere the test skips. */
    private function need(): \FFI
    {
        if (!OpensslMlKem::available()) {
            $this->assertNotSame('1', getenv('PCA_REQUIRE_MLDSA'), 'ML-KEM must be available on the OpenSSL >= 3.5 lane');
            $this->markTestSkipped('ML-KEM needs ext-ffi and OpenSSL >= 3.5');
        }
        $f = (new \ReflectionProperty(OpensslMlKem::class, 'ffi'))->getValue();
        $this->assertInstanceOf(\FFI::class, $f);
        return $f;
    }

    private static function call(string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(OpensslMlKem::class, $method))->invoke(null, ...$args);
    }

    /** @return array{0:string,1:string,2:string,3:string} [ek, dk, ct, ss] of the level's known-answer seed and message */
    private static function kat(int $level): array
    {
        [$sb, $mb] = self::KAT[$level];
        $k = OpensslMlKem::keygen($level, str_repeat(chr($sb), 64));
        $e = OpensslMlKem::encapsulate($level, $k['publicKey'], str_repeat(chr($mb), 32));
        return [$k['publicKey'], $k['secretKey'], $e['cipherText'], $e['sharedSecret']];
    }

    private static function pack(int $c0, int $c1): string
    {
        return chr($c0 & 0xFF) . chr((($c0 >> 8) & 0x0F) | (($c1 & 0x0F) << 4)) . chr(($c1 >> 4) & 0xFF);
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

    /** Seeded keygen, derandomised encapsulation and decapsulation reproduce the FIPS 203 answers at both levels. */
    public function testKnownAnswersAtBothLevels(): void
    {
        $this->need();
        foreach (self::KAT as $level => [$sb, $mb, $ekH, $dkH, $ctH, $ss]) {
            [$ek, $dk, $ct, $got] = self::kat($level);
            $k = $level === 768 ? 3 : 4;
            $this->assertSame([$ekH, $dkH, $ctH, $ss], [hash('sha256', $ek), hash('sha256', $dk), hash('sha256', $ct), bin2hex($got)], "level $level");
            $this->assertSame([OpensslMlKem::LEVELS[$level][2], OpensslMlKem::LEVELS[$level][4], OpensslMlKem::LEVELS[$level][3]], [strlen($ek), strlen($dk), strlen($ct)]);
            // FIPS 203: dk = dkPKE || ek || H(ek) || z, and K = G(m || H(ek))[0..32)
            $this->assertSame($ek, substr($dk, 384 * $k, strlen($ek)));
            $this->assertSame(hash('sha3-256', $ek, true) . str_repeat(chr($sb), 32), substr($dk, -64));
            $this->assertSame(substr(hash('sha3-512', str_repeat(chr($mb), 32) . hash('sha3-256', $ek, true), true), 0, 32), $got);
            $this->assertSame($got, OpensslMlKem::decapsulate($level, $ct, $dk));
            $this->assertSame(['cipherText' => $ct, 'sharedSecret' => $got], OpensslMlKem::encapsulate($level, $ek, str_repeat(chr($mb), 32)), 'derandomised: the same message gives the same ciphertext');
        }
    }

    /** A ciphertext that is not the key's gets the implicit-rejection secret J(z || c), never the real secret or a failure. */
    public function testImplicitRejectionSecret(): void
    {
        $this->need();
        foreach ([768, 1024] as $level) {
            [, $dk, $ct, $ss] = self::kat($level);
            $bad = $ct;
            $bad[0] = chr(ord($bad[0]) ^ 1);
            $rej = OpensslMlKem::decapsulate($level, $bad, $dk);
            $this->assertSame(self::KAT[$level][6], bin2hex($rej), "level $level");
            $this->assertNotSame($ss, $rej);
        }
    }

    /** A damaged s (still in range) is imported (no pairwise test) and answers the rejection secret; a damaged H(ek) is refused. */
    public function testDamagedDecapsulationKeys(): void
    {
        $this->need();
        foreach ([768, 1024] as $level) {
            [$ek, $dk, $ct] = self::kat($level);
            $c0 = ord($dk[0]) | ((ord($dk[1]) & 0x0F) << 8);
            $n0 = ($c0 + 1) % 3329;
            $d = $dk;
            $d[0] = chr($n0 & 0xFF);
            $d[1] = chr((ord($d[1]) & 0xF0) | ($n0 >> 8));
            $this->assertSame(self::KAT[$level][7], bin2hex(OpensslMlKem::decapsulate($level, $ct, $d)), "level $level");
            $h = $dk;
            $at = 384 * ($level === 768 ? 3 : 4) + strlen($ek);
            $h[$at] = chr(ord($h[$at]) ^ 0x69);
            $this->refuses(\InvalidArgumentException::class, 'ml-kem decapsulate: invalid decapsulation key', static fn() => OpensslMlKem::decapsulate($level, $ct, $h));
        }
    }

    /** An s coefficient written as c + q (12-bit, >= q) names the same key: decapsulation still gives the real secret. */
    public function testOutOfRangeCoefficientNamesItsResidue(): void
    {
        $this->need();
        foreach ([768, 1024] as $level) {
            [, $dk, $ct, $ss] = self::kat($level);
            $n = 384 * ($level === 768 ? 3 : 4);
            $hit = null;
            for ($i = 0; $i < $n; $i += 3) {
                $c0 = ord($dk[$i]) | ((ord($dk[$i + 1]) & 0x0F) << 8);
                if ($c0 < 4096 - 3329) {
                    $hit = $i;
                    break;
                }
            }
            $this->assertNotNull($hit);
            $c0 = ord($dk[$hit]) | ((ord($dk[$hit + 1]) & 0x0F) << 8);
            $hi = $c0 + 3329;
            $d = $dk;
            $d[$hit] = chr($hi & 0xFF);
            $d[$hit + 1] = chr((ord($d[$hit + 1]) & 0xF0) | ($hi >> 8));
            $this->assertNotSame($dk, $d);
            $this->assertSame($ss, OpensslMlKem::decapsulate($level, $ct, $d), "level $level");
        }
    }

    /** canonicalDkPke reduces every triple of the 384k-byte half, the first and the last, and nothing past it (k = 3). */
    public function testCanonicalDkPkeCoversExactlyTheDecryptionHalf(): void
    {
        $mid = str_repeat(self::pack(1, 2), 382);
        $dk = self::pack(4095, 3329) . $mid . self::pack(3330, 4000) . self::pack(4095, 4095) . 'tail';
        $this->assertSame(1152 + 7, strlen($dk));
        $want = self::pack(766, 0) . $mid . self::pack(1, 671) . self::pack(4095, 4095) . 'tail';
        $this->assertSame($want, OpensslMlKem::canonicalDkPke($dk, 3));
    }

    /** An encapsulation key with a coefficient >= q fails the FIPS 203 modulus check: libcrypto refuses it. */
    public function testEncapsulationKeyModulusCheck(): void
    {
        $this->need();
        [$ek] = self::kat(768);
        $bad = $ek;
        $bad[0] = "\xFF";
        $bad[1] = chr(ord($bad[1]) | 0x0F);
        $this->refuses(\RuntimeException::class, 'ml-kem encapsulate: invalid encapsulation key', static fn() => OpensslMlKem::encapsulate(768, $bad, str_repeat("\x02", 32)));
    }

    /** Wrong-sized ciphertexts and decapsulation keys are refused with their exact reason, ciphertext first. */
    public function testDecapsulateLengthGates(): void
    {
        $this->need();
        [, $dk, $ct] = self::kat(768);
        $ctMsg = 'ml-kem decapsulate: ciphertext must be exactly 1088 bytes';
        $dkMsg = 'ml-kem decapsulate: decapsulation key must be exactly 2400 bytes';
        $this->refuses(\InvalidArgumentException::class, $ctMsg, static fn() => OpensslMlKem::decapsulate(768, substr($ct, 1), $dk));
        $this->refuses(\InvalidArgumentException::class, $ctMsg, static fn() => OpensslMlKem::decapsulate(768, $ct . "\0", $dk));
        $this->refuses(\InvalidArgumentException::class, $ctMsg, static fn() => OpensslMlKem::decapsulate(768, substr($ct, 1), substr($dk, 1)));
        $this->refuses(\InvalidArgumentException::class, $dkMsg, static fn() => OpensslMlKem::decapsulate(768, $ct, substr($dk, 1)));
        $this->refuses(\InvalidArgumentException::class, $dkMsg, static fn() => OpensslMlKem::decapsulate(768, $ct, $dk . "\0"));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem decapsulate: ciphertext must be exactly 1568 bytes', static fn() => OpensslMlKem::decapsulate(1024, $ct, $dk));
    }

    /** The public gates that run before libcrypto: level, seed, message and encapsulation-key lengths (no library needed). */
    public function testArgumentGates(): void
    {
        $lvl = static fn(int $l): string => "ML-KEM level must be 768 or 1024, got $l";
        $this->refuses(\InvalidArgumentException::class, $lvl(512), static fn() => OpensslMlKem::keygen(512, str_repeat("\1", 64)));
        $this->refuses(\InvalidArgumentException::class, $lvl(769), static fn() => OpensslMlKem::encapsulate(769, str_repeat("\0", 1184), str_repeat("\2", 32)));
        $this->refuses(\InvalidArgumentException::class, $lvl(0), static fn() => OpensslMlKem::decapsulate(0, str_repeat("\0", 1088), str_repeat("\0", 2400)));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem keygen: seed must be exactly 64 bytes', static fn() => OpensslMlKem::keygen(768, str_repeat("\1", 63)));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem keygen: seed must be exactly 64 bytes', static fn() => OpensslMlKem::keygen(1024, str_repeat("\1", 65)));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem encapsulate: message must be exactly 32 bytes', static fn() => OpensslMlKem::encapsulate(768, str_repeat("\0", 1184), str_repeat("\2", 31)));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem encapsulate: encapsulation key must be exactly 1184 bytes', static fn() => OpensslMlKem::encapsulate(768, str_repeat("\0", 1183), str_repeat("\2", 32)));
        $this->refuses(\InvalidArgumentException::class, 'ml-kem encapsulate: encapsulation key must be exactly 1568 bytes', static fn() => OpensslMlKem::encapsulate(1024, str_repeat("\0", 1184), str_repeat("\2", 32)));
    }

    /** Without a backend every operation fails closed with the install hint (as on a host without ext-ffi / OpenSSL 3.5). */
    public function testNoBackendFailsClosed(): void
    {
        $tried = new \ReflectionProperty(OpensslMlKem::class, 'tried');
        $ffi = new \ReflectionProperty(OpensslMlKem::class, 'ffi');
        $saved = [$tried->getValue(), $ffi->getValue()];
        $tried->setValue(null, true);
        $ffi->setValue(null, null);
        try {
            $this->assertFalse(OpensslMlKem::available());
            $this->refuses(\RuntimeException::class, 'ML-KEM needs ext-ffi and OpenSSL >= 3.5 (set ATLAS_PCA_LIBCRYPTO)', static fn() => OpensslMlKem::keygen(768, str_repeat("\1", 64)));
        } finally {
            $tried->setValue(null, $saved[0]);
            $ffi->setValue(null, $saved[1]);
        }
    }

    /** The probe reports false for a handle that lacks the ML-KEM calls (the throw is caught), true for the real library. */
    public function testProbeIsARealRoundTrip(): void
    {
        $f = $this->need();
        $this->assertTrue(self::call('probe', $f));
        $this->assertFalse(self::call('probe', \FFI::cdef('')));
    }

    /** libcrypto's own refusals surface with their reasons: a short seed at keygen, a short ikme at encapsulation. */
    public function testLibcryptoRefusalsKeepTheirReason(): void
    {
        $f = $this->need();
        [$ek] = self::kat(768);
        $this->refuses(\RuntimeException::class, 'ML-KEM-768 keygen refused the seed', static fn() => self::call('keygenWith', $f, 768, "\x01"));
        $this->refuses(\RuntimeException::class, 'ml-kem encapsulate: init refused', static fn() => self::call('encapsulateWith', $f, 768, $ek, "\x02"));
    }
}
