<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\CertError;
use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\PubKey;
use PHPUnit\Framework\TestCase;

/**
 * H1: the RSA public-key rule (modulus 512..16384 bits, odd e >= 3 of at most 32 bits) runs before any modular exponentiation, and
 * H8: an RSASSA-PSS issuer key that carries parameters only verifies signatures made with them.
 */
final class K05HardRsaTest extends TestCase
{
    private const SHA256 = "\x60\x86\x48\x01\x65\x03\x04\x02\x01";
    private const SHA384 = "\x60\x86\x48\x01\x65\x03\x04\x02\x02";
    private const MGF1 = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x08";
    private const PSS = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x0A";

    private static function tlv(int $tag, string $v): string
    {
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    /** A big-endian integer of exactly `$bits` bits (top bit set, every other bit set). */
    private static function bits(int $bits): string
    {
        $bytes = intdiv($bits + 7, 8);
        $top = $bits - ($bytes - 1) * 8;
        return chr((1 << $top) - 1) . str_repeat("\xFF", $bytes - 1);
    }

    private static function cnf(): string
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        return $cnf;
    }

    /** @return array{key: \OpenSSLAsymmetricKey, n: string, e: string, d: string} a real 2048-bit key */
    private static function key(): array
    {
        static $k = null;
        if ($k === null) {
            $cnf = self::cnf();
            $key = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            unlink($cnf);
            self::assertNotFalse($key);
            $d = openssl_pkey_get_details($key);
            $k = ['key' => $key, 'pub' => openssl_pkey_get_public($d['key']), 'n' => $d['rsa']['n'], 'e' => $d['rsa']['e'], 'd' => $d['rsa']['d']];
        }
        return $k;
    }

    /** A PubKey that carries `$n` and `$e` over a real key object: the rule must refuse it before any key operation. */
    private static function claiming(string $n, string $e, string $spki = ''): PubKey
    {
        return new PubKey(self::key()['key'], $spki, 'rsa', null, [], $n, $e);
    }

    public function testTheRuleAtItsBoundaries(): void
    {
        $e = "\x01\x00\x01";
        $this->assertTrue(Common::rsaKeyOk(self::bits(2048), $e));
        $this->assertTrue(Common::rsaKeyOk(self::bits(512), $e));
        $this->assertFalse(Common::rsaKeyOk(self::bits(511), $e));
        $this->assertTrue(Common::rsaKeyOk(self::bits(16384), $e));
        $this->assertFalse(Common::rsaKeyOk(self::bits(16385), $e));
        $this->assertFalse(Common::rsaKeyOk(self::bits(256), $e));
        $this->assertFalse(Common::rsaKeyOk(self::bits(17000), $e));
        $this->assertTrue(Common::rsaKeyOk("\0\0" . self::bits(2048), "\0" . $e), 'leading zero bytes do not count');
        $this->assertFalse(Common::rsaKeyOk("\0" . self::bits(511), $e), 'a padded 511-bit modulus is still 511 bits');
    }

    public function testTheExponentRule(): void
    {
        $n = self::bits(2048);
        $this->assertFalse(Common::rsaKeyOk($n, "\x01"), 'e = 1');
        $this->assertFalse(Common::rsaKeyOk($n, "\x02"), 'even');
        $this->assertFalse(Common::rsaKeyOk($n, "\x04"), 'even');
        $this->assertFalse(Common::rsaKeyOk($n, "\x01\x00\x00"), 'even 65536');
        $this->assertFalse(Common::rsaKeyOk($n, "\x00"), 'zero');
        $this->assertFalse(Common::rsaKeyOk($n, ''), 'empty');
        $this->assertTrue(Common::rsaKeyOk($n, "\x03"), 'e = 3');
        $this->assertTrue(Common::rsaKeyOk($n, "\xFF\xFF\xFF\xFF"), '32-bit odd');
        $this->assertFalse(Common::rsaKeyOk($n, "\x01\x00\x00\x00\x01"), '2^32 + 1 is 33 bits');
        $this->assertFalse(Common::rsaKeyOk($n, "\x02\x00\x00\x00\x01"), '2^33 + 1');
        $this->assertFalse(Common::rsaKeyOk(null, "\x03"));
        $this->assertFalse(Common::rsaKeyOk($n, null));
    }

    public function testAWeakKeyNeverVerifiesPkcs1(): void
    {
        $k = self::key();
        $good = new PubKey($k['pub'], '', 'rsa', null, [], $k['n'], $k['e']);
        openssl_sign('msg', $sig, $k['key'], 'sha256');
        $this->assertTrue(Common::rsaPkcs1Verify($good, $sig, 'msg', 'sha256'), 'a genuine 2048-bit e=65537 key: ' . Common::opensslError());
        foreach ([[$k['n'], "\x01"], [$k['n'], "\x04"], [$k['n'], "\x02\x00\x00\x00\x01"], [self::bits(17000), "\x01\x00\x01"], [self::bits(256), "\x01\x00\x01"]] as $i => [$n, $e]) {
            $this->assertFalse(Common::rsaPkcs1Verify(self::claiming($n, $e), $sig, 'msg', 'sha256'), "weak key $i");
        }
    }

    public function testAWeakKeyNeverRunsTheModularExponentiationOfPss(): void
    {
        $sig = str_repeat("\x01", 2125); // the right length for a 17000-bit modulus
        $start = hrtime(true);
        $this->assertFalse(Common::rsaPssVerify(self::claiming(self::bits(17000), "\x01\x00\x01"), $sig, 'msg', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPssVerify(self::claiming(self::bits(2048), "\x01"), str_repeat("\x01", 256), 'msg', 'sha256', 'sha256', 32));
        $this->assertFalse(Common::rsaPssVerify(self::claiming(self::bits(256), "\x01\x00\x01"), str_repeat("\x01", 32), 'msg', 'sha256', 'sha256', 32));
        $this->assertLessThan(100, (hrtime(true) - $start) / 1e6, 'refused without a modexp');
    }

    public function testAJwkImportOfAnUnusableKeyThrows(): void
    {
        $k = self::key();
        $this->assertNotSame('', Common::rsaSpki($k['n'], $k['e']), 'a usable key builds');
        foreach ([[$k['n'], "\x01"], [$k['n'], "\x04"], [self::bits(256), "\x01\x00\x01"], [self::bits(17000), "\x01\x00\x01"]] as [$n, $e]) {
            try {
                Common::rsaSpki($n, $e);
                $this->fail('an unusable key was imported');
            } catch (CertError $x) {
                $this->assertSame('error:1E08010C:DECODER routines::unsupported', $x->getMessage());
            }
        }
    }

    // ------------------------------------------------------------------------------------------------ H8: PSS key restrictions

    private static function algId(string $oid): string
    {
        return self::tlv(0x30, self::tlv(0x06, $oid) . "\x05\x00");
    }

    /** RSASSA-PSS-params: hash, MGF1 hash, salt length (each as an explicit [n] member). */
    private static function pssParams(string $hash, string $mgfHash, int $salt): string
    {
        return self::tlv(0x30, self::tlv(0xA0, self::algId($hash))
            . self::tlv(0xA1, self::tlv(0x30, self::tlv(0x06, self::MGF1) . self::algId($mgfHash)))
            . self::tlv(0xA2, self::tlv(0x02, chr($salt))));
    }

    /** The id-RSASSA-PSS SubjectPublicKeyInfo of the test key, with `$params` (or none: an unrestricted key). */
    private static function pssKey(?string $params): PubKey
    {
        $k = self::key();
        $alg = self::tlv(0x30, self::tlv(0x06, self::PSS) . ($params ?? ''));
        $rsaKey = self::tlv(0x30, self::tlv(0x02, "\0" . $k['n']) . self::tlv(0x02, $k['e']));
        return Common::loadPublicKey(self::tlv(0x30, $alg . self::tlv(0x03, "\0" . $rsaKey)));
    }

    /** The signature AlgorithmIdentifier of an RSASSA-PSS signature made with the given parameters. */
    private static function sigAlg(string $hash, string $mgfHash, int $salt): string
    {
        return self::tlv(0x30, self::tlv(0x06, self::PSS) . self::pssParams($hash, $mgfHash, $salt));
    }

    private static function pssSign(string $msg, string $hash, string $mgfHash, int $salt): string
    {
        $algo = [self::SHA256 => 'sha256', self::SHA384 => 'sha384'];
        [$hn, $mn] = [$algo[$hash], $algo[$mgfHash]];
        $k = self::key();
        $n = gmp_import($k['n']);
        $modBits = strlen(gmp_strval($n, 2));
        $emBits = $modBits - 1;
        $emLen = intdiv($emBits + 7, 8);
        $hLen = strlen(hash($hn, '', true));
        $saltB = random_bytes($salt);
        $h = hash($hn, str_repeat("\0", 8) . hash($hn, $msg, true) . $saltB, true);
        $db = str_repeat("\0", $emLen - $salt - $hLen - 2) . "\x01" . $saltB;
        $mask = '';
        for ($c = 0; strlen($mask) < strlen($db); $c++) {
            $mask .= hash($mn, $h . pack('N', $c), true);
        }
        $masked = $db ^ substr($mask, 0, strlen($db));
        $zero = 8 * $emLen - $emBits;
        if ($zero > 0) {
            $masked[0] = chr(ord($masked[0]) & (0xFF >> $zero));
        }
        $s = gmp_powm(gmp_import($masked . $h . "\xBC"), gmp_import($k['d']), $n);
        return str_pad(gmp_export($s), intdiv($modBits + 7, 8), "\0", STR_PAD_LEFT);
    }

    private static function verify(PubKey $key, string $hash, string $mgfHash, int $salt): bool
    {
        return Cert::verifyWithAlg(self::sigAlg($hash, $mgfHash, $salt), 'msg', self::pssSign('msg', $hash, $mgfHash, $salt), $key);
    }

    public function testAnUnrestrictedPssKeyAcceptsAnyParameters(): void
    {
        $key = self::pssKey(null);
        $this->assertTrue(self::verify($key, self::SHA256, self::SHA256, 32));
        $this->assertTrue(self::verify($key, self::SHA384, self::SHA384, 48));
    }

    public function testARestrictedPssKeyOnlyVerifiesItsParameters(): void
    {
        $key = self::pssKey(self::pssParams(self::SHA384, self::SHA384, 48));
        $this->assertTrue(self::verify($key, self::SHA384, self::SHA384, 48), 'the key\'s own parameters');
        $this->assertTrue(self::verify($key, self::SHA384, self::SHA384, 64), 'a longer salt is allowed');
        $this->assertFalse(self::verify($key, self::SHA256, self::SHA256, 32), 'sha256');
        $this->assertFalse(self::verify($key, self::SHA384, self::SHA384, 20), 'a shorter salt');
        $this->assertFalse(self::verify($key, self::SHA384, self::SHA384, 47), 'one byte short of the salt');
        $this->assertFalse(self::verify($key, self::SHA384, self::SHA256, 48), 'another MGF1 hash');
        $this->assertFalse(self::verify($key, self::SHA256, self::SHA384, 48), 'another hash');
    }
}
