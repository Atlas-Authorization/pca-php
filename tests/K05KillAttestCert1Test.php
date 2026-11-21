<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\CertError;
use Atlas\Pca\Attest\CertExtension;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\DerError;
use Atlas\Pca\Attest\PubKey;
use PHPUnit\Framework\TestCase;

/** Kills the survivors of src/Attest/Cert.php on really signed P-384 certificates (and hand-built DER) generated at load. */
final class K05KillAttestCert1Test extends TestCase
{
    private const NESTED = 'error:0688010A:asn1 encoding routines::nested asn1 error (%s)';
    private const EOC = 'error:0680009F:asn1 encoding routines::unexpected eoc';

    private static function key(string $name): \OpenSSLAsymmetricKey
    {
        static $keys = [];
        if (!isset($keys[$name])) {
            $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
            file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
            $keys[$name] = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
            unlink($cnf);
        }
        return $keys[$name];
    }

    private static function spkiOf(\OpenSSLAsymmetricKey $k): string
    {
        return (string)base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details($k)['key']));
    }

    private static function pub(string $name): PubKey
    {
        return Common::loadPublicKey(self::spkiOf(self::key($name)));
    }

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : ($n < 0x10000 ? "\x82" . pack('n', $n) : "\x83" . substr(pack('N', $n), 1)))) . $v;
    }

    private static function oid(string $b): string
    {
        return self::tlv(0x06, $b);
    }

    private static function ext(string $id, string $v): string
    {
        return self::tlv(0x30, self::oid($id), self::tlv(0x04, $v));
    }

    private static function cnOid(): string
    {
        return self::oid("\x55\x04\x03");
    }

    /** Name with one RDN: CN = tlv($tag, $val). */
    private static function dn(int $tag, string $val): string
    {
        return self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::cnOid(), self::tlv($tag, $val))));
    }

    private static function algStd(): string
    {
        return self::tlv(0x30, self::oid("\x2a\x86\x48\xce\x3d\x04\x03\x03"));
    }

    /**
     * A certificate DER, with overridable pieces. Keys: outerTag tbsTag alg inner serial serialTag innerTag issTag valTag subTag spki
     * tail exts signer sig sigLen unused sigTlv extra trailing.
     * @param array<string,mixed> $o
     */
    private static function mk(array $o = []): string
    {
        $alg = $o['alg'] ?? self::algStd();
        $inner = $o['inner'] ?? self::algStd();
        $exts = $o['exts'] ?? [];
        $tail = $o['tail'] ?? ($exts === [] ? '' : self::tlv(0xA3, self::tlv(0x30, ...$exts)));
        $val = self::tlv($o['valTag'] ?? 0x30, self::tlv(0x17, '250101000000Z'), self::tlv(0x17, '350101000000Z'));
        $tbs = self::tlv(
            $o['tbsTag'] ?? 0x30,
            self::tlv(0xA0, self::tlv(0x02, "\x02")),
            self::tlv($o['serialTag'] ?? 0x02, $o['serial'] ?? "\x11"),
            $inner,
            self::tlv($o['issTag'] ?? 0x30, self::tlv(0x31, self::tlv(0x30, self::cnOid(), self::tlv(0x0c, 'root')))),
            $val,
            self::tlv($o['subTag'] ?? 0x30, self::tlv(0x31, self::tlv(0x30, self::cnOid(), self::tlv(0x0c, 'up')))),
            $o['spki'] ?? self::spkiOf(self::key($o['subjectKey'] ?? 'up')),
            $tail
        );
        if (isset($o['signer'])) {
            openssl_sign($tbs, $sig, $o['signer'], OPENSSL_ALGO_SHA384);
        } else {
            $sig = $o['sig'] ?? str_repeat("\x07", $o['sigLen'] ?? 40);
        }
        $sigTlv = $o['sigTlv'] ?? self::tlv(0x03, chr($o['unused'] ?? 0) . $sig);
        return self::tlv($o['outerTag'] ?? 0x30, $tbs, $alg, $sigTlv, $o['extra'] ?? '') . ($o['trailing'] ?? '');
    }

    /** @param array<string,mixed> $o */
    private function assertNested(string $what, array $o): void
    {
        try {
            new Cert(self::mk($o));
        } catch (CertError $e) {
            $this->assertSame(sprintf(self::NESTED, $what), $e->getMessage());
            return;
        }
        $this->fail("no CertError for $what");
    }

    /** @param array<string,mixed> $o */
    private function assertEoc(array $o): void
    {
        try {
            new Cert(self::mk($o));
        } catch (CertError $e) {
            $this->assertSame(self::EOC, $e->getMessage());
            return;
        }
        $this->fail('no unexpected-eoc CertError');
    }

    /** @param callable():void $f */
    private function assertNoWarnings(callable $f): void
    {
        $w = [];
        set_error_handler(static function (int $n, string $s) use (&$w): bool {
            $w[] = $s;
            return true;
        });
        try {
            $f();
        } finally {
            restore_error_handler();
        }
        $this->assertSame([], $w);
    }

    private static function priv(string $m, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Cert::class, $m))->invoke(null, ...$args);
    }

    // ---- constructor -----------------------------------------------------------------------------------------------------------

    public function testStructuralRefusalsCarryTheirExactReason(): void
    {
        $this->assertNested('not a SEQUENCE', ['outerTag' => 0x31]);
        $this->assertNested('no tbsCertificate', ['tbsTag' => 0x31]);
        $this->assertNested('serial', ['serialTag' => 0x04]);
        $this->assertNested('serial', ['serial' => "\x00\x11"]);
        $this->assertNested('signature algorithm', ['inner' => self::tlv(0x31, self::oid("\x2a\x03"))]);
        $this->assertNested('issuer', ['issTag' => 0x31]);
        $this->assertNested('validity', ['valTag' => 0x31]);
        $this->assertNested('subject', ['subTag' => 0x31]);
        $this->assertNested('subjectPublicKeyInfo', ['spki' => self::tlv(0x31, self::tlv(0x30, self::oid("\x2a\x03")), self::tlv(0x03, "\0\1"))]);
    }

    public function testSignatureWrapperChecksEachHaveTheirOwnRefusal(): void
    {
        $this->assertNested('bad signature wrapper', ['alg' => self::tlv(0x31, self::oid("\x2a\x03"))]); // only the algorithm tag is wrong
        $this->assertNested('bad signature wrapper', ['sigTlv' => self::tlv(0x04, "\0abc")]); // only the signature tag is wrong
        $this->assertNested('bad signature wrapper', ['extra' => "\x05\x00"]); // bytes after the signature inside the certificate
        $this->assertNested('bad signature wrapper', ['sigTlv' => "\x03\x00"]); // empty BIT STRING
    }

    public function testRawSignatureAndPartsOfAWellFormedCertificate(): void
    {
        $sig = '0123456789abcdefghij';
        $der = self::mk(['sig' => $sig]);
        $c = new Cert($der . "\x00\x00trailing");
        $this->assertSame($der, $c->raw);
        $this->assertSame($sig, $c->signature);
        $this->assertSame(0, $c->sigUnused);
        $this->assertSame(self::algStd(), $c->sigAlgDer);
        $this->assertSame("\x11", $c->serial);
        $this->assertSame('11', $c->serialHex());
        $this->assertSame('CN=root', $c->issuer());
        $this->assertSame('CN=up', $c->subject());
        $c2 = new Cert(self::mk(['serial' => "\x00\x80"]));
        $this->assertSame('80', $c2->serialHex());
        $this->assertSame('1', (new Cert(self::mk(['serial' => "\x01"])))->serialHex());
        $this->assertSame('', (new Cert(self::mk(['serial' => "\x00"])))->serialHex());
    }

    public function testSpkiMustBeExactlyAlgorithmAndBitString(): void
    {
        $a = self::tlv(0x30, self::oid("\x2a\x03"));
        $b = self::tlv(0x03, "\0\1\2");
        $this->assertSame(true, (new Cert(self::mk(['spki' => self::tlv(0x30, $a, $b)])))->spkiDer === self::tlv(0x30, $a, $b));
        $this->assertEoc(['spki' => self::tlv(0x30, self::tlv(0x31, self::oid("\x2a\x03")), $b)]); // algorithm tag only
        $this->assertEoc(['spki' => self::tlv(0x30, $a, self::tlv(0x04, "\0\1\2"))]); // key tag only
        $this->assertEoc(['spki' => self::tlv(0x30, $a, $b, "\x05\x00")]); // bytes after the key
    }

    public function testOnlyOrderedOptionalFieldsMayFollowTheSpki(): void
    {
        $u = self::tlv(0xA1, "\x03\x02\x00\x01"); // [1] issuerUID
        $s = self::tlv(0xA2, "\x03\x02\x00\x01"); // [2] subjectUID
        $e = self::tlv(0xA3, self::tlv(0x30));
        foreach ([$u, $s, $e, $u . $s, $u . $e, $s . $e, $u . $s . $e] as $i => $tail) {
            $this->assertInstanceOf(Cert::class, new Cert(self::mk(['tail' => $tail])), "ok $i");
        }
        $this->assertEoc(['tail' => self::tlv(0xA0, '')]); // [0] again
        $this->assertEoc(['tail' => $u . $u]); // repeated
        $this->assertEoc(['tail' => $e . $e]);
        $this->assertEoc(['tail' => $s . $u]); // out of order
        $this->assertEoc(['tail' => self::tlv(0xA4, '')]); // beyond [3]
        $this->assertEoc(['tail' => "\xA3\x20"]); // claims more than the TBS holds (and the signature follows)
    }

    public function testATruncatedTailIsRefusedWithoutReadingAnUndefinedElement(): void
    {
        $this->assertNoWarnings(function (): void {
            try {
                new Cert(self::mk(['tail' => "\xA3", 'sigLen' => 10]));
                $this->fail('parsed');
            } catch (CertError $e) {
                $this->assertSame(self::EOC, $e->getMessage());
            }
        });
    }

    // ---- fromPem ----------------------------------------------------------------------------------------------------------------

    private static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    public function testFromPemReasons(): void
    {
        $der = self::mk();
        $this->assertSame($der, Cert::fromPem(self::pem($der))->raw);
        foreach ([
            ['garbage', 'error:0480006C:PEM routines::no start line'],
            [self::pem($der . "\x00"), 'error:0680007B:asn1 encoding routines::header too long'],
            [self::pem('0'), sprintf(self::NESTED, 'truncated')],
            [self::pem(self::mk(['outerTag' => 0x31])), sprintf(self::NESTED, 'not a SEQUENCE')],
        ] as $i => [$pem, $want]) {
            try {
                Cert::fromPem($pem);
                $this->fail("row $i parsed");
            } catch (CertError $e) {
                $this->assertSame($want, $e->getMessage(), "row $i");
            }
        }
    }

    // ---- names ---------------------------------------------------------------------------------------------------------------------

    private static function cn(int $tag, string $val): string
    {
        return Cert::renderName(self::dn($tag, $val));
    }

    public function testRenderNameRefusals(): void
    {
        foreach ([
            [self::tlv(0x31, self::tlv(0x31, self::tlv(0x30, self::cnOid(), self::tlv(0x0c, 'a')))), 'name is not a SEQUENCE'],
            [self::tlv(0x30, self::tlv(0x30, self::tlv(0x30, self::cnOid(), self::tlv(0x0c, 'a')))), 'RDN is not a SET'],
        ] as $i => [$der, $want]) {
            try {
                Cert::renderName($der);
                $this->fail("row $i rendered");
            } catch (CertError $e) {
                $this->assertSame($want, $e->getMessage());
            }
        }
        $this->assertSame('CN=a', self::cn(0x0c, 'a'));
    }

    public function testEscapingFollowsOpenSslTwoThousandTwoFiftyThree(): void
    {
        foreach (str_split(',+"\\<>;') as $c) {
            $this->assertSame('CN=x\\' . $c . 'y', self::cn(0x0c, 'x' . $c . 'y'), "char $c");
            $this->assertSame('CN=\\' . $c, self::cn(0x0c, $c));
        }
        $this->assertSame('CN=a\\01b', self::cn(0x0c, "a\x01b"));
        $this->assertSame('CN=a\\1Fb', self::cn(0x0c, "a\x1fb"));
        $this->assertSame('CN=a\\00b', self::cn(0x0c, "a\x00b"));
        $this->assertSame('CN=a\\7Fb', self::cn(0x0c, "a\x7fb"));
        $this->assertSame('CN=a~b', self::cn(0x0c, 'a~b'));
        $this->assertSame("CN=a\xC2\x80b", self::cn(0x0c, "a\xC2\x80b"));
        $this->assertSame('CN=\\#a', self::cn(0x0c, '#a'));
        $this->assertSame('CN=a#b', self::cn(0x0c, 'a#b'));
        $this->assertSame('CN=a#', self::cn(0x0c, 'a#'));
        $this->assertSame('CN=\\ a', self::cn(0x0c, ' a'));
        $this->assertSame('CN=a b', self::cn(0x0c, 'a b'));
        $this->assertSame('CN=ab\\ ', self::cn(0x0c, 'ab '));
        $this->assertSame('CN=\\ ', self::cn(0x0c, ' '));
        $this->assertSame('CN=\\ \\ ', self::cn(0x0c, '  '));
    }

    public function testStringTypesDecodeAndTheRestRenderAsHex(): void
    {
        foreach ([0x12, 0x13, 0x14, 0x16, 0x1A] as $tag) {
            $this->assertSame("CN=A\xC3\xA9", self::cn($tag, "A\xE9"), "tag $tag");
        }
        $this->assertSame('CN=AB', self::cn(0x1E, "\x00A\x00B"));
        $this->assertSame('CN=A', self::cn(0x1C, "\x00\x00\x00A"));
        foreach ([0x02, 0x04, 0x11, 0x15, 0x17, 0x19, 0x1B, 0x1D, 0x1F] as $tag) {
            $this->assertSame('CN=#' . sprintf('%02X', $tag) . '02ABCD', self::cn($tag, "\xAB\xCD"), "tag $tag");
        }
        // the hex form is the value's own TLV only, whatever follows it in the name
        $c = self::oid("\x55\x04\x06");
        $o = self::oid("\x55\x04\x0a");
        $name = self::tlv(
            0x30,
            self::tlv(0x31, self::tlv(0x30, $c, self::tlv(0x13, 'US'))),
            self::tlv(0x31, self::tlv(0x30, self::cnOid(), self::tlv(0x04, "\xAB\xCD"))),
            self::tlv(0x31, self::tlv(0x30, $o, self::tlv(0x0c, 'x')))
        );
        $this->assertSame("C=US\nCN=#0402ABCD\nO=x", Cert::renderName($name));
        $multi = self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, $c, self::tlv(0x13, 'US')), self::tlv(0x30, $o, self::tlv(0x0c, 'x'))));
        $this->assertSame('C=US + O=x', Cert::renderName($multi));
    }

    public function testInvalidUtf8IsScrubbed(): void
    {
        $bad = "a\xC3\x28b";
        $got = self::cn(0x0c, $bad);
        $this->assertSame('CN=' . mb_convert_encoding($bad, 'UTF-8', 'UTF-8'), $got);
        $this->assertNotSame('CN=' . $bad, $got);
        $this->assertSame(1, preg_match('//u', $got));
        $this->assertSame("CN=\xC3\xA9", self::cn(0x0c, "\xC3\xA9")); // valid stays
    }

    public function testNameCachesAreHonoured(): void
    {
        $c = new Cert(self::mk());
        foreach (['subject' => 'subjectText', 'issuer' => 'issuerText'] as $m => $prop) {
            $p = new \ReflectionProperty(Cert::class, $prop);
            $p->setValue($c, 'cached');
            $this->assertSame('cached', $c->$m());
        }
    }

    // ---- key ---------------------------------------------------------------------------------------------------------------------

    public function testAnUndecodableKeyIsWrappedInTheDecoderError(): void
    {
        $spki = self::tlv(0x30, self::tlv(0x30, self::oid("\x2a\x86\x48\xce\x3d\x02\x01"), self::oid("\x2b\x81\x04\x00\x22")), self::tlv(0x03, "\0\x04\x01\x02"));
        $c = new Cert(self::mk(['spki' => $spki]));
        try {
            Common::loadPublicKey($c->spkiDer);
            $this->fail('key decoded');
        } catch (CertError $e) {
            $inner = $e->getMessage();
        }
        try {
            $c->publicKey();
            $this->fail('publicKey decoded');
        } catch (CertError $e) {
            $this->assertSame('error:1E08010C:DECODER routines::unsupported (' . $inner . ')', $e->getMessage());
        }
    }

    // ---- extensions / ca ---------------------------------------------------------------------------------------------------------

    public function testExtensionCacheFlagsAreHonoured(): void
    {
        $ex = new CertExtension(false, 'v');
        $c = new Cert(self::mk(['exts' => [self::ext("\x55\x1d\x13", "\x30\x03\x01\x01\xff")]]));
        $e = new \ReflectionProperty(Cert::class, 'exts');
        $e->setValue($c, ['9.9' => $ex]);
        $this->assertSame(['9.9' => $ex], $c->extensions());
        $c2 = new Cert(self::mk(['exts' => [self::ext("\x55\x1d\x13", "\x30\x03\x01\x01\xff")]]));
        $this->assertCount(1, $c2->extensions());
        $c3 = new Cert(self::mk(['exts' => [self::ext("\x55\x1d\x13", "\x30\x03\x01\x01\xff")]]));
        (new \ReflectionProperty(Cert::class, 'extsFailed'))->setValue($c3, true);
        $this->assertSame([], $c3->extensions());
    }

    private static function caOf(?string $bc, ?string $ku): bool
    {
        $exts = [];
        if ($bc !== null) {
            $exts[] = self::ext("\x55\x1d\x13", $bc);
        }
        if ($ku !== null) {
            $exts[] = self::ext("\x55\x1d\x0f", $ku);
        }
        return (new Cert(self::mk(['exts' => $exts])))->ca();
    }

    public function testKeyUsageGatesCa(): void
    {
        $bc = "\x30\x03\x01\x01\xff";
        $this->assertTrue(self::caOf($bc, null));
        $this->assertTrue(self::caOf($bc, "\x03\x02\x02\x04"));
        $this->assertTrue(self::caOf($bc, "\x03\x02\x00\x05"));
        $this->assertFalse(self::caOf($bc, "\x03\x02\x00\x01")); // encipherOnly, not keyCertSign
        $this->assertFalse(self::caOf($bc, "\x03\x02\x00\x00"));
        $this->assertFalse(self::caOf($bc, "\x03\x01\x00\x04")); // one-byte BIT STRING, a byte follows it
        $this->assertFalse(self::caOf($bc, "\x04\x02\x00\x04")); // not a BIT STRING
        $this->assertFalse(self::caOf(null, "\x03\x02\x02\x04"));
    }

    public function testBasicConstraintsShapes(): void
    {
        $this->assertFalse(self::caOf("\x04\x03\x01\x01\xff", null)); // not a SEQUENCE
        $this->assertFalse(self::caOf("\x30\x00", null));
        $this->assertFalse(self::caOf("\x30\x03\x01\x01\x00", null)); // cA FALSE
        $this->assertFalse(self::caOf("\x30\x03\x02\x01\x05", null)); // pathLen only
        $this->assertFalse(self::caOf("\x30\x02\x01\x00\xff", null)); // empty BOOLEAN, a byte follows
        $this->assertFalse(self::caOf("\x30\x02\x01\x05", null)); // element overruns the SEQUENCE
        $this->assertFalse(self::caOf('', null));
        $this->assertTrue(self::caOf("\x30\x03\x01\x01\x01", null));
    }

    // ---- AKID --------------------------------------------------------------------------------------------------------------------

    public function testAkidReasons(): void
    {
        $akid = static fn(string $v): Cert => new Cert(self::mk(['exts' => [self::ext("\x55\x1d\x23", $v)]]));
        $m = new \ReflectionMethod(Cert::class, 'authorityKeyId');
        $kid = self::tlv(0x80, "\x07\x07\x07\x07");
        $this->assertSame(["\x07\x07\x07\x07", null, null], $m->invoke($akid(self::tlv(0x30, $kid))));
        foreach ([
            [self::tlv(0x31, $kid), 'AKID is not a SEQUENCE'],
            [self::tlv(0x30, self::tlv(0x82, "\x00\x11")), 'AKID serial is not a DER INTEGER'],
        ] as $i => [$v, $want]) {
            try {
                $m->invoke($akid($v));
                $this->fail("row $i");
            } catch (DerError $e) {
                $this->assertSame($want, $e->getMessage());
            }
        }
    }

    // ---- verify ------------------------------------------------------------------------------------------------------------------

    public function testVerifyRequiresIdenticalAlgorithmsAndNoUnusedBits(): void
    {
        $root = self::key('root');
        $pk = self::pub('root');
        $this->assertTrue((new Cert(self::mk(['signer' => $root])))->verify($pk));
        $this->assertFalse((new Cert(self::mk(['signer' => self::key('up')])))->verify($pk));
        $this->assertTrue((new Cert(self::mk(['signer' => $root, 'subjectKey' => 'root'])))->verifySelf());
        // outer algorithm differs from the signed inner one in bytes only
        $withNull = self::tlv(0x30, self::oid("\x2a\x86\x48\xce\x3d\x04\x03\x03"), "\x05\x00");
        $this->assertFalse((new Cert(self::mk(['signer' => $root, 'alg' => $withNull])))->verify($pk));
        // an unused-bits count other than 0 on the otherwise valid signature
        $this->assertFalse((new Cert(self::mk(['signer' => $root, 'unused' => 1])))->verify($pk));
    }

    public function testVerifyFailsClosedOnAnUnreadableAlgorithm(): void
    {
        $empty = self::tlv(0x30);
        $c = new Cert(self::mk(['alg' => $empty, 'inner' => $empty]));
        $this->assertFalse($c->verify(self::pub('root')));
        $this->assertFalse(Cert::verifyWithAlg($empty, 'm', 's', self::pub('root')));
    }

    public function testVerifyWithAlg(): void
    {
        $pk = self::pub('root');
        openssl_sign('msg', $sig, self::key('root'), OPENSSL_ALGO_SHA384);
        $this->assertTrue(Cert::verifyWithAlg(self::algStd(), 'msg', $sig, $pk));
        $this->assertFalse(Cert::verifyWithAlg(self::algStd(), 'msh', $sig, $pk));
        // RSASSA-PSS needs an RSA key
        $pss = self::tlv(0x30, self::oid("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a"));
        $this->assertFalse(Cert::verifyWithAlg($pss, 'msg', $sig, $pk));
        // unknown algorithm
        $this->assertFalse(Cert::verifyWithAlg(self::tlv(0x30, self::oid("\x2a\x03")), 'msg', $sig, $pk));
    }

    // ---- PSS parameters ----------------------------------------------------------------------------------------------------------

    private static function hashAlg(string $oid): string
    {
        return self::tlv(0x30, self::oid($oid));
    }

    private const SHA1 = "\x2b\x0e\x03\x02\x1a";
    private const SHA256 = "\x60\x86\x48\x01\x65\x03\x04\x02\x01";
    private const SHA384 = "\x60\x86\x48\x01\x65\x03\x04\x02\x02";
    private const SHA512 = "\x60\x86\x48\x01\x65\x03\x04\x02\x03";
    private const MGF1 = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08";
    private const MD5 = "\x2a\x86\x48\x86\xf7\x0d\x02\x05";

    /** @return array{0:string,1:string,2:int} */
    private static function pss(?string $paramsDer): array
    {
        $alg = self::tlv(0x30, self::oid("\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a"), $paramsDer ?? '');
        $seq = Der::tlvLenient($alg, 0);
        $oid = Der::tlvLenient($alg, $seq->start);
        $params = $paramsDer === null ? null : Der::tlvLenient($alg, $oid->end);
        return self::priv('pssParams', $alg, $params);
    }

    private function assertPssRefused(string $paramsDer, string $want): void
    {
        try {
            self::pss($paramsDer);
        } catch (CertError $e) {
            $this->assertSame($want, $e->getMessage());
            return;
        }
        $this->fail("accepted: $want");
    }

    public function testPssDefaults(): void
    {
        $this->assertNoWarnings(function (): void {
            $this->assertSame(['sha1', 'sha1', 20], self::pss(null));
        });
        $this->assertSame(['sha1', 'sha1', 20], self::pss(self::tlv(0x30)));
        // a parameters element that is not a SEQUENCE is ignored, whatever it holds
        $this->assertSame(['sha1', 'sha1', 20], self::pss(self::tlv(0x31, self::tlv(0xA2, self::tlv(0x02, "\x05")))));
        $this->assertSame(['sha512', 'sha1', 20], self::pss(self::tlv(0x30, self::tlv(0xA0, self::hashAlg(self::SHA512)))));
    }

    public function testPssParametersParse(): void
    {
        $full = self::tlv(
            0x30,
            self::tlv(0xA0, self::hashAlg(self::SHA256)),
            self::tlv(0xA1, self::tlv(0x30, self::oid(self::MGF1), self::hashAlg(self::SHA384))),
            self::tlv(0xA2, self::tlv(0x02, "\x20")),
            self::tlv(0xA3, self::tlv(0x02, "\x01"))
        );
        $this->assertSame(['sha256', 'sha384', 32], self::pss($full));
        $this->assertSame(['sha1', 'sha1', 0], self::pss(self::tlv(0x30, self::tlv(0xA2, self::tlv(0x02, "\x00")))));
        // the trailer may come first with more parameters after it
        $this->assertSame(['sha1', 'sha1', 5], self::pss(self::tlv(0x30, self::tlv(0xA3, self::tlv(0x02, "\x01")), self::tlv(0xA2, self::tlv(0x02, "\x05")))));
        // a salt wider than an int is still an int
        $big = self::pss(self::tlv(0x30, self::tlv(0xA2, self::tlv(0x02, "\x01" . str_repeat("\x00", 8)))));
        $this->assertIsInt($big[2]);
    }

    public function testPssRefusals(): void
    {
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA0, '')), 'empty PSS parameter');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA0, self::tlv(0x31, self::oid(self::SHA256)))), 'hash algorithm is not a SEQUENCE');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA0, self::hashAlg(self::MD5))), 'unsupported hash algorithm');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA1, self::tlv(0x31, self::oid(self::MGF1), self::hashAlg(self::SHA256)))), 'mask generation function is not a SEQUENCE');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA1, self::tlv(0x30, self::oid(self::SHA256), self::hashAlg(self::SHA256)))), 'unsupported mask generation function');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA1, self::tlv(0x30, self::oid(self::MGF1), self::hashAlg(self::MD5)))), 'unsupported hash algorithm');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA2, self::tlv(0x04, "\x05"))), 'salt length is not an INTEGER');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA3, self::tlv(0x02, "\x02"))), 'trailer field is not 1');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA3, self::tlv(0x04, "\x01"))), 'trailer field is not 1');
        $this->assertPssRefused(self::tlv(0x30, self::tlv(0xA4, self::tlv(0x02, "\x00"))), 'unknown PSS parameter');
    }
}
