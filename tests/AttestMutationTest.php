<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\Nvidia;
use Atlas\Pca\Attest\Ocsp;
use Atlas\Pca\Attest\PubKey;
use Atlas\Pca\Attest\Tlv;
use Atlas\Pca\Json;
use PHPUnit\Framework\TestCase;

/** Hardware-attestation helpers: CRL coverage edges, option parsing, OCSP walk limits, RSA-PSS key limits and OID decimal arithmetic. */
final class AttestMutationTest extends TestCase
{
    private const CA = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign";
    private const CDP = "\ncrlDistributionPoints=URI:http://crl.example/x.crl";

    private static function tlv(int $tag, string $v): string
    {
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    /** @return array{pem:string,x509:\OpenSSLCertificate,key:\OpenSSLAsymmetricKey} */
    private static function issue(string $cn, string $ext, ?array $parent, int $serial): array
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n[x]\n$ext\n");
        try {
            $opt = ['config' => $cnf, 'digest_alg' => 'sha384', 'x509_extensions' => 'x'];
            $key = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
            self::assertNotFalse($key);
            $csr = openssl_csr_new(['commonName' => $cn], $key, $opt);
            $x = openssl_csr_sign($csr, $parent['x509'] ?? null, $parent['key'] ?? $key, 2, $opt, $serial);
            self::assertNotFalse($x);
            openssl_x509_export($x, $pem);
            return ['pem' => $pem, 'x509' => $x, 'key' => $key];
        } finally {
            unlink($cnf);
        }
    }

    /** A fresh CRL signed by `$key` listing nothing. */
    private static function crl(\OpenSSLAsymmetricKey $key): string
    {
        $alg = self::tlv(0x30, self::tlv(0x06, "\x2a\x86\x48\xce\x3d\x04\x03\x02"));
        $t = time();
        $tbs = self::tlv(0x30, $alg . self::tlv(0x30, '') . self::tlv(0x17, gmdate('ymdHis', $t - 3600) . 'Z') . self::tlv(0x17, gmdate('ymdHis', $t + 3600) . 'Z'));
        openssl_sign($tbs, $sig, $key, OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs . $alg . self::tlv(0x03, "\0" . $sig));
    }

    private static function now(): float
    {
        return time() * 1000.0;
    }

    /** @return array{0: list<Cert>, 1: array<string,mixed>} chain (leaf, ica, root) */
    private static function chain(string $rootExt = self::CA): array
    {
        $root = self::issue('Mut Root', $rootExt, null, 0x5001);
        $ica = self::issue('Mut Ica', self::CA, $root, 0x5002);
        $leaf = self::issue('Mut Leaf', 'basicConstraints=critical,CA:FALSE', $ica, 0x5003);
        return [[Cert::fromPem($leaf['pem']), Cert::fromPem($ica['pem']), Cert::fromPem($root['pem'])], ['root' => $root, 'ica' => $ica]];
    }

    public function testARootThatNamesACdpNeedsNoCrlOfItsOwnIssuer(): void
    {
        [$c, $m] = self::chain(self::CA . self::CDP);
        self::assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($c, [self::crl($m['root']['key'])], self::now()));
    }

    public function testAllOnASingleCertificateChainDemandsNothingMore(): void
    {
        [$c, $m] = self::chain();
        self::assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation([$c[2]], [self::crl($m['root']['key'])], self::now(), null, 'all'));
    }

    public function testAllDemandsACrlFromEveryNonRootIssuer(): void
    {
        [$c, $m] = self::chain();
        self::assertSame(['ok' => false, 'reason' => "no verified CRL from the issuer of chain certificate 'CN=Mut Ica'"],
            Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key'])], self::now(), null, 'all'));
        self::assertSame(['ok' => true, 'verifiedCrls' => 2],
            Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key']), self::crl($m['root']['key'])], self::now(), null, 'all'));
    }

    private function jsTruthy(mixed $v): bool
    {
        return (new \ReflectionMethod(Nvidia::class, 'jsTruthy'))->invoke(null, $v);
    }

    public function testJsTruthiness(): void
    {
        foreach (['0', '0.0', '-0'] as $zero) {
            self::assertFalse($this->jsTruthy(Json::parseLax($zero)), $zero);
        }
        foreach (['1', '2', '0.5', '-1'] as $one) {
            self::assertTrue($this->jsTruthy(Json::parseLax($one)), $one);
        }
        foreach ([null, false, '', 0, 0.0] as $falsy) {
            self::assertFalse($this->jsTruthy($falsy), var_export($falsy, true));
        }
        foreach ([true, 'a', 1, 1.0, 2.5, '0'] as $truthy) {
            self::assertTrue($this->jsTruthy($truthy), var_export($truthy, true));
        }
    }

    private static function hookWith(mixed $requireFor): \Closure
    {
        return Nvidia::collateralHook(['rimRootSpkiSha256' => [str_repeat('a', 64)], 'requireCrlFor' => $requireFor],
            static fn(array $ids, mixed $evidence): ?array => null);
    }

    public function testRequireCrlForIndexListsAreNormalised(): void
    {
        foreach ([[1.0], [0.0], [0], [0, 1], Json::parseLax('[0, 2]'), Json::parseLax('[1.0]')] as $ok) {
            self::assertInstanceOf(\Closure::class, self::hookWith($ok), json_encode($ok));
        }
        foreach ([[1.5, 0], [0, 1.5], [-1], [0, -2], [0, '1'], [null, 0], Json::parseLax('[0.5, 1]')] as $bad) {
            try {
                self::hookWith($bad);
                self::fail('accepted ' . json_encode($bad));
            } catch (AttestConstructError $e) {
                self::assertStringStartsWith('nvidiaCollateralHook: malformed requireCrlFor', $e->getMessage());
            }
        }
    }

    // ---- OCSP: the time walk's start depth and node count ------------------------------------------------------------

    private static function ocspResponse(string $tbsContent): string
    {
        $basic = self::tlv(0x30, self::tlv(0x30, $tbsContent) . self::tlv(0x30, '') . self::tlv(0x03, "\x00"));
        $rb = self::tlv(0x30, self::tlv(0x06, "\x2b\x06\x01\x05\x05\x07\x30\x01\x01") . self::tlv(0x04, $basic));
        return self::tlv(0x30, self::tlv(0x0A, "\x00") . self::tlv(0xA0, $rb));
    }

    private static function nested(int $levels): string
    {
        $der = "\x30\x00";
        for ($i = 1; $i < $levels; $i++) {
            $der = self::tlv(0x30, $der);
        }
        return $der;
    }

    private static function ocspReason(string $tbsContent): string
    {
        $c = Cert::fromPem(self::issue('Mut Ocsp', self::CA, null, 0x5101)['pem']);
        $r = Ocsp::verifyResponse(self::ocspResponse($tbsContent), $c, $c, [], self::now());
        self::assertFalse($r['ok']);
        return $r['reason'];
    }

    public function testTheBasicResponseWalkAllowsNinetyNineLevelsAndRefusesAHundred(): void
    {
        $deep = 'BasicOCSPResponse is not valid DER';
        self::assertNotSame($deep, self::ocspReason(self::nested(99)));
        self::assertSame($deep, self::ocspReason(self::nested(100)));
    }

    public function testTheBasicResponseWalkCountsTenThousandNodes(): void
    {
        $deep = 'BasicOCSPResponse is not valid DER';
        // the walk meets the tbs element, its children, the empty algorithm sequence and the signature: n + 3 nodes
        self::assertNotSame($deep, self::ocspReason(str_repeat("\x05\x00", 9997)));
        self::assertSame($deep, self::ocspReason(str_repeat("\x05\x00", 9998)));
    }

    public function testTheTimeWalkDefaultsStartAtDepthZeroAndNodeZero(): void
    {
        $walk = static fn(string $der): bool => (new \ReflectionMethod(Ocsp::class, 'allTimesWellFormed'))->invoke(null, $der, 0, strlen($der));
        self::assertTrue($walk(self::nested(101)));
        self::assertFalse($walk(self::nested(102)));
        $flat = static fn(int $n): string => self::tlv(0x30, str_repeat("\x05\x00", $n));
        self::assertTrue($walk($flat(9999)));
        self::assertFalse($walk($flat(10000)));
    }

    // ---- Cert ------------------------------------------------------------------------------------------------------------

    public function testExtensionsMalformedParsesOnFirstAsk(): void
    {
        $der = Common::pemToDer(self::issue('Mut Ext', 'basicConstraints=critical,CA:TRUE', null, 0x5201)['pem']);
        $needle = "\x06\x03\x55\x1d\x13\x01\x01\xff"; // basicConstraints, critical TRUE
        $pos = strpos($der, $needle);
        self::assertNotFalse($pos);
        self::assertFalse((new Cert($der))->extensionsMalformed());
        $bad = substr_replace($der, "\x01", $pos + 7, 1); // a non-DER critical flag
        self::assertTrue((new Cert($bad))->extensionsMalformed());
    }

    private static function rsa(string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(K05HardRsaTest::class, $method))->invoke(null, ...$args);
    }

    private static function rsaConst(string $name): string
    {
        return (new \ReflectionClass(K05HardRsaTest::class))->getConstant($name);
    }

    public function testARestrictedPssKeyComparesHashAndMgfHashSeparately(): void
    {
        [$s256, $s384] = [self::rsaConst('SHA256'), self::rsaConst('SHA384')];
        $key = self::rsa('pssKey', self::rsa('pssParams', $s384, $s256, 48));
        self::assertTrue(self::rsa('verify', $key, $s384, $s256, 48));
        self::assertFalse(self::rsa('verify', $key, $s384, $s384, 48), 'the MGF1 hash must be the key\'s');
        self::assertFalse(self::rsa('verify', $key, $s256, $s256, 48), 'the hash must be the key\'s');
    }

    public function testAKeyWhoseParametersOverrunItsAlgorithmIsNotUnrestricted(): void
    {
        [$s256] = [self::rsaConst('SHA256')];
        $k = self::rsa('key');
        $alg = self::tlv(0x30, self::tlv(0x06, self::rsaConst('PSS')) . "\x04\x40" . 'ab'); // an OCTET STRING longer than the algorithm
        $rsaKey = self::tlv(0x30, self::tlv(0x02, "\0" . $k['n']) . self::tlv(0x02, $k['e']));
        $spki = self::tlv(0x30, $alg . self::tlv(0x03, "\0" . $rsaKey));
        $base = self::rsa('pssKey', null);
        self::assertTrue(self::rsa('verify', $base, $s256, $s256, 32));
        $bad = new PubKey($base->key, $spki, $base->type, $base->curve, $base->details, $base->rsaN, $base->rsaE);
        self::assertFalse(self::rsa('verify', $bad, $s256, $s256, 32));
    }

    // ---- Common ----------------------------------------------------------------------------------------------------------

    public function testBitLengthAndAZeroPaddedExponent(): void
    {
        $bl = new \ReflectionMethod(Common::class, 'bitLength');
        self::assertSame(0, $bl->invoke(null, ''));
        self::assertSame(1, $bl->invoke(null, "\x01"));
        self::assertSame(8, $bl->invoke(null, "\x80"));
        self::assertSame(9, $bl->invoke(null, "\x01\x00"));
        self::assertTrue(Common::rsaKeyOk(str_repeat("\xFF", 256), "\0\0\0\0\x01\x00\x01"));
    }

    // ---- Der: OID arcs beyond 56 bits ---------------------------------------------------------------------------------

    private static function oid(string $hex): string
    {
        $c = (string)hex2bin($hex);
        return Der::oidToDotted($c, new Tlv(0x06, 0, strlen($c)));
    }

    public function testLongArcsKeepTheirExactDecimalValue(): void
    {
        // first arc 2^56 + 80, then 1 and 2
        self::assertSame('2.72057594037927936.1.2', self::oid('818080808080808050' . '01' . '02'));
        // first arc 10^17: the borrow of 80 runs through every digit
        self::assertSame('2.99999999999999920', self::oid('81b1d1af85eca88000'));
        // later arcs 76800001000000000 and 76800001999999999 (limb carries of exactly 10^9 and 2*10^9 - 1)
        self::assertSame('1.3.76800001000000000.76800001999999999', self::oid('2b' . '8188b6a69ad2eb9400' . '8188b6a69eafd6a77f'));
    }

    public function testDecimalSubtraction(): void
    {
        $sub = new \ReflectionMethod(Der::class, 'decSub');
        self::assertSame('99999999999999920', $sub->invoke(null, '100000000000000000', 80));
        self::assertSame('99999999999999901', $sub->invoke(null, '100000000000000000', 99));
        self::assertSame('72057594037927856', $sub->invoke(null, '72057594037927936', 80));
        self::assertSame('99999999999999999', $sub->invoke(null, '100000000000000000', 1));
    }
}
