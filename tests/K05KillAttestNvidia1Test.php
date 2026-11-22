<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attest/Factory.php';

use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Nvidia;
use Atlas\Pca\Attest\Xml;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * 0.5 mutation-kill tests of the NVIDIA GPU SPDM verifier (src/Attest/Nvidia.php): the SPDM transcript parser edges, the device
 * chain, the RIM (XMLDSig) document checks on really signed documents, the RIM ids, the golden comparison, the CRL gate, the firmware
 * policy, the collateral hook and the verifier messages. Expected strings and limits are those of the TypeScript reference
 * (packages/pca/src/attest-nvidia-spdm.ts, attest-nvidia-rim.ts). Certificates and keys are generated at load; nothing private is
 * committed.
 */
final class K05KillAttestNvidia1Test extends TestCase
{
    private const LEAF = 'basicConstraints=critical,CA:FALSE';
    private const CA = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign";
    private const NS = 'http://www.w3.org/2000/09/xmldsig#';
    private const C14N = 'http://www.w3.org/2006/12/xml-c14n11';
    private const ENV = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
    private const ECDSA = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
    private const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
    private const PAYLOAD0 = '<Payload><Resource type="Measurement" index="0" active="true" alternatives="1" size="1" Hash1="aa"/></Payload>';
    private const TRANSFORMS_BAD = 'RIM: transforms must be exactly [enveloped-signature, C14N 1.1]';

    // ------------------------------------------------------------------------------------------------------------- helpers

    private static function now(): float
    {
        return time() * 1000.0;
    }

    /** Runs `$f` with every PHP warning / notice turned into an exception (a mutant that reads past a string end dies on it). */
    private static function strict(callable $f): mixed
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    private static function priv(string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Nvidia::class, $method))->invoke(null, ...$args);
    }

    private static function tlv(int $tag, string $v): string
    {
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    /** A P-384 key and certificate issued by `$parent` (self-signed when null); the certificate is valid now. @return array{pem:string,x509:\OpenSSLCertificate,key:\OpenSSLAsymmetricKey} */
    private static function issue(string $cn, string $ext, ?array $parent, int $serial): array
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n[x]\n$ext\n");
        try {
            $opt = ['config' => $cnf, 'digest_alg' => 'sha384', 'x509_extensions' => 'x'];
            $key = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
            self::assertNotFalse($key, 'EC keygen: ' . openssl_error_string());
            $csr = openssl_csr_new(['commonName' => $cn], $key, $opt);
            $x = openssl_csr_sign($csr, $parent['x509'] ?? null, $parent['key'] ?? $key, 2, $opt, $serial);
            self::assertNotFalse($x, (string)openssl_error_string());
            openssl_x509_export($x, $pem);
            return ['pem' => $pem, 'x509' => $x, 'key' => $key];
        } finally {
            unlink($cnf);
        }
    }

    /** The GPU device chain (leaf, intermediate, root), its concatenated PEM and the root pin. @return array<string,mixed> */
    private static function dev(): array
    {
        static $d = null;
        if ($d === null) {
            $root = self::issue('NVIDIA Test Root', self::CA, null, 0x1001);
            $inter = self::issue('NVIDIA Test Inter', self::CA, $root, 0x1002);
            $leaf = self::issue('NVIDIA GH100 Device', self::LEAF, $inter, 0x1003);
            $d = ['root' => $root, 'inter' => $inter, 'leaf' => $leaf, 'pem' => $leaf['pem'] . $inter['pem'] . $root['pem'], 'pin' => Cert::fromPem($root['pem'])->spkiSha256()];
        }
        return $d;
    }

    /** The RIM signer chain (leaf, root). @return array<string,mixed> */
    private static function rimPki(): array
    {
        static $p = null;
        if ($p === null) {
            $root = self::issue('NVIDIA RIM Root', self::CA, null, 0x2001);
            $leaf = self::issue('NVIDIA RIM Signer', self::LEAF, $root, 0x2002);
            $p = ['root' => $root, 'leaf' => $leaf, 'pin' => Cert::fromPem($root['pem'])->spkiSha256(),
                'b64leaf' => base64_encode(Common::pemToDer($leaf['pem'])), 'b64root' => base64_encode(Common::pemToDer($root['pem']))];
        }
        return $p;
    }

    /** An ECDSA-Sig-Value (DER) as the 96-byte P1363 signature. */
    private static function rawSig(string $der): string
    {
        $p = 2;
        if ((ord($der[1]) & 0x80) !== 0) {
            $p = 2 + (ord($der[1]) & 0x7F);
        }
        $rl = ord($der[$p + 1]);
        $r = substr($der, $p + 2, $rl);
        $p += 2 + $rl;
        $sl = ord($der[$p + 1]);
        $s = substr($der, $p + 2, $sl);
        return str_pad(ltrim($r, "\0"), 48, "\0", STR_PAD_LEFT) . str_pad(ltrim($s, "\0"), 48, "\0", STR_PAD_LEFT);
    }

    // ---- SPDM transcripts

    private static function req(int $ver = 0x11, string $nonce = ''): string
    {
        return chr($ver) . "\xE0\0\0" . ($nonce === '' ? str_repeat("\x07", 32) : $nonce) . "\0";
    }

    private static function resp(string $records, int $n, string $opaque = '', int $ver = 0x11, string $sig = ''): string
    {
        return chr($ver) . "\x60\0\0" . chr($n) . substr(pack('V', strlen($records)), 0, 3)
            . $records . str_repeat("\x09", 32) . pack('v', strlen($opaque)) . $opaque . ($sig === '' ? str_repeat("\xEE", 96) : $sig);
    }

    private static function block(int $index, string $digest): string
    {
        return chr($index) . "\0" . pack('v', 3 + strlen($digest)) . "\0" . pack('v', strlen($digest)) . $digest;
    }

    private static function tx(string $records, int $n, string $opaque = ''): string
    {
        return self::req() . self::resp($records, $n, $opaque);
    }

    private static function opTlv(int $tag, string $val): string
    {
        return pack('v', $tag) . pack('v', strlen($val)) . $val;
    }

    private static function parseErr(string $t): string
    {
        try {
            Nvidia::parseEvidence($t);
        } catch (\ValueError $e) {
            return $e->getMessage();
        }
        return '(no error)';
    }

    private static function vb(): string
    {
        return strrev((string)hex2bin('aabbcc0496009f00')); // renders as 96.00.9f.00.04
    }

    /** @param array<int,string> $extra @param list<int> $drop @return array<int,string> */
    private static function opq(array $extra = [], array $drop = []): array
    {
        $d = [3 => "535.104.05\0", 6 => self::vb(), 14 => 'x14', 15 => "cs15\0", 16 => 'x16', 17 => 'pr17', 18 => 'ps18', 19 => 'x19'];
        foreach ($extra as $k => $v) {
            $d[$k] = $v;
        }
        foreach ($drop as $k) {
            unset($d[$k]);
        }
        return $d;
    }

    // ---- RIM documents

    private static function rimText(array $o, string $dv, string $sv): string
    {
        $pki = self::rimPki();
        $certs = '<ds:X509Certificate>' . $pki['b64leaf'] . '</ds:X509Certificate><ds:X509Certificate>' . $pki['b64root'] . '</ds:X509Certificate>';
        $tr = $o['transforms'] ?? '<ds:Transforms><ds:Transform Algorithm="' . self::ENV . '"/><ds:Transform Algorithm="' . self::C14N . '"/></ds:Transforms>';
        $body = $o['body'] ?? ('<Meta product="GH100" colloquialVersion="535.104.05"/>' . self::PAYLOAD0);
        $dvEl = $o['dvEl'] ?? ('<ds:DigestValue>' . $dv . '</ds:DigestValue>');
        $svEl = $o['svEl'] ?? ('<ds:SignatureValue>' . $sv . '</ds:SignatureValue>');
        return '<SoftwareIdentity tagId="T1">' . $body
            . '<ds:Signature xmlns:ds="' . self::NS . '"><ds:SignedInfo>'
            . '<ds:CanonicalizationMethod Algorithm="' . self::C14N . '"/><ds:SignatureMethod Algorithm="' . self::ECDSA . '"/>'
            . '<ds:Reference URI="">' . $tr . '<ds:DigestMethod Algorithm="' . self::SHA384 . '"/>' . $dvEl . '</ds:Reference></ds:SignedInfo>'
            . $svEl . '<ds:KeyInfo><ds:X509Data>' . $certs . '</ds:X509Data></ds:KeyInfo></ds:Signature></SoftwareIdentity>';
    }

    /** A RIM whose digest and SignedInfo signature are real (signed by the RIM signer certificate). */
    private static function signedRim(array $o = []): string
    {
        $pki = self::rimPki();
        $d0 = Xml::parse(self::rimText($o, 'x', 'x'));
        $sig0 = $d0->root->elementChildren(self::NS, 'Signature')[0];
        $digest = base64_encode(hash('sha384', Xml::canonicalize($d0->root, $sig0), true));
        $d1 = Xml::parse(self::rimText($o, $digest, 'x'));
        $si = $d1->root->elementChildren(self::NS, 'Signature')[0]->elementChildren(self::NS, 'SignedInfo')[0];
        openssl_sign(Xml::canonicalize($si), $der, $pki['leaf']['key'], OPENSSL_ALGO_SHA384);
        return self::rimText($o, $digest, base64_encode(self::rawSig($der)));
    }

    private static function rimFor(string $body): string
    {
        return self::signedRim(['body' => $body]);
    }

    private static function verifyRim(string $xml): array
    {
        return Nvidia::verifyRim($xml, [self::rimPki()['pin']], self::now());
    }

    private static function resource(string $attrs): string
    {
        return '<Resource type="Measurement" ' . $attrs . '/>';
    }

    // ---- golden comparison

    private static function gold(int $index, array $hashes, bool $active = true, ?int $size = null): array
    {
        return ['index' => $index, 'active' => $active, 'alternatives' => count($hashes), 'size' => $size ?? intdiv(strlen($hashes[0]), 2), 'hashes' => $hashes];
    }

    private static function rimg(array ...$gs): array
    {
        $o = [];
        foreach ($gs as $g) {
            $o[$g['index']] = $g;
        }
        return ['golden' => $o];
    }

    /** @param list<array{0:int,1:string}> $meas */
    private static function rep(array $meas, array $op = []): array
    {
        return ['measurements' => array_map(static fn(array $m): array => ['index' => $m[0], 'digest' => $m[1]], $meas), 'opaque' => $op];
    }

    private static function cmp(array $report, array $drv, ?array $vb = null): array
    {
        return self::strict(static fn(): array => Nvidia::compareReportToRims($report, $drv, $vb ?? self::rimg()));
    }

    private static function differ(int $n): array
    {
        return ['ok' => false, 'reason' => "runtime measurements differ from the golden RIM values at $n index(es)"];
    }

    // ---- revocation

    /** A CRL (DER, ECDSA-SHA256) from an empty-named issuer, valid now, listing the given serials (raw INTEGER content). @param list<string> $serials */
    private static function crl(\OpenSSLAsymmetricKey $key, array $serials): string
    {
        $alg = self::tlv(0x30, self::tlv(0x06, "\x2a\x86\x48\xce\x3d\x04\x03\x02"));
        $t = time();
        $entries = '';
        foreach ($serials as $s) {
            $entries .= self::tlv(0x30, self::tlv(0x02, $s) . self::tlv(0x17, gmdate('ymdHis', $t - 60) . 'Z'));
        }
        $tbs = self::tlv(0x30, $alg . self::tlv(0x30, '') . self::tlv(0x17, gmdate('ymdHis', $t - 3600) . 'Z') . self::tlv(0x17, gmdate('ymdHis', $t + 3600) . 'Z')
            . ($entries === '' ? '' : self::tlv(0x30, $entries)));
        openssl_sign($tbs, $sig, $key, OPENSSL_ALGO_SHA256);
        return self::tlv(0x30, $tbs . $alg . self::tlv(0x03, "\0" . $sig));
    }

    /** @return list<Cert> */
    private static function devChain(): array
    {
        $r = Nvidia::verifyDeviceChain(self::dev()['pem'], [self::dev()['pin']], self::now());
        self::assertTrue($r['ok']);
        return $r['chain'];
    }

    // ---- collateral hook

    private static function hctx(array $report, string $subject = 'CN=NVIDIA GH100 Device'): array
    {
        $leaf = new class($subject) {
            public function __construct(private string $s)
            {
            }

            public function subject(): string
            {
                return $this->s;
            }
        };
        return ['report' => $report, 'leaf' => $leaf, 'chain' => [], 'nowMs' => self::now(), 'evidence' => ['e' => 1]];
    }

    private static function hookReport(): array
    {
        return ['opaque' => self::opq(), 'measurements' => [['index' => 1, 'digest' => "\xbb"]]];
    }

    private static function driverRim(string $product = 'GH100', string $version = '535.104.05'): string
    {
        return self::rimFor('<Meta product="' . $product . '" colloquialVersion="' . $version . '"/>'
            . '<Payload>' . self::resource('index="0" active="true" alternatives="1" size="1" Hash1="aa"') . '</Payload>');
    }

    private static function vbiosRim(string $product = 'GH100', string $version = '96.00.9f.00.04'): string
    {
        return self::rimFor('<Meta product="' . $product . '" colloquialVersion="' . $version . '"/>'
            . '<Payload>' . self::resource('index="1" active="false" alternatives="1" size="1" Hash1="cc"') . '</Payload>');
    }

    private static function hookWith(?string $driver, ?string $vbios): string
    {
        $hook = Nvidia::collateralHook(['rimRootSpkiSha256' => [self::rimPki()['pin']]], static fn(array $ids, mixed $ev): array => ['driverRimXml' => $driver, 'vbiosRimXml' => $vbios]);
        return (string)$hook(self::hctx(self::hookReport()));
    }

    private static function ctorError(callable $f): string
    {
        try {
            $f();
        } catch (AttestConstructError $e) {
            return $e->getMessage();
        }
        return '(no error)';
    }

    // ------------------------------------------------------------------------------------------------------ byte readers

    public function testByteReadersStayInsideTheBuffer(): void
    {
        $this->assertSame(0, self::strict(fn() => self::priv('b', '', 0)));
        $this->assertSame(0, self::strict(fn() => self::priv('b', 'ab', 2)));
        $this->assertSame(0, self::strict(fn() => self::priv('b', 'ab', 5)));
        $this->assertSame(0, self::strict(fn() => self::priv('b', 'ab', -1)));
        $this->assertSame(97, self::priv('b', 'ab', 0));
        $this->assertSame(98, self::priv('b', 'ab', 1));
        $this->assertSame(0x0201, self::priv('u16', "\x01\x02", 0));
        $this->assertSame(0x030201, self::priv('u24', "\x01\x02\x03", 0));
        $this->assertSame(0x050403, self::priv('u24', "\x01\x02\x03\x04\x05", 2));
    }

    // ------------------------------------------------------------------------------------------------ SPDM transcript

    public function testTranscriptLengthFloorIs175Bytes(): void
    {
        $this->assertSame('parseNvidiaSpdmEvidence: transcript too short (174)', self::parseErr(str_repeat("\0", 174)));
        $this->assertSame('parseNvidiaSpdmEvidence: request code 0x0 is not GET_MEASUREMENTS', self::parseErr(str_repeat("\0", 175)));
        $p = Nvidia::parseEvidence(self::tx('', 0));
        $this->assertSame([], $p['measurements']);
        $this->assertSame([], $p['opaque']);
    }

    public function testMeasurementRecordLengthMustFitTheTranscript(): void
    {
        $t = self::tx(self::block(1, "\xaa"), 1);
        $this->assertSame([['index' => 1, 'valueType' => 0, 'digest' => "\xaa"]], Nvidia::parseEvidence($t)['measurements']);
        $this->assertSame('parseNvidiaSpdmEvidence: measurement record length overruns transcript', self::parseErr(substr($t, 0, -1)));
    }

    public function testTruncatedMeasurementBlockHeader(): void
    {
        $this->assertSame('parseNvidiaSpdmEvidence: truncated measurement block header', self::parseErr(self::tx('abc', 1)));
    }

    public function testAMeasurementBlockMayCarryAnEmptyDigest(): void
    {
        $p = Nvidia::parseEvidence(self::tx(self::block(1, ''), 1));
        $this->assertSame([['index' => 1, 'valueType' => 0, 'digest' => '']], $p['measurements']);
    }

    public function testDmtfValueMustFitItsMeasurementBlock(): void
    {
        $over = chr(1) . "\0" . pack('v', 5) . "\0" . pack('v', 3) . 'ab';
        $this->assertSame('parseNvidiaSpdmEvidence: DMTF value overruns measurement block', self::parseErr(self::tx($over, 1)));
        $fits = chr(1) . "\0" . pack('v', 5) . "\0" . pack('v', 2) . 'ab';
        $this->assertSame([['index' => 1, 'valueType' => 0, 'digest' => 'ab']], Nvidia::parseEvidence(self::tx($fits, 1))['measurements']);
    }

    public function testOpaqueEntryEdges(): void
    {
        $rec = self::block(1, "\xaa");
        $this->assertSame('parseNvidiaSpdmEvidence: truncated opaque TLV header', self::parseErr(self::tx($rec, 1, "\x03\0\0")));
        $this->assertSame([3 => ''], Nvidia::parseEvidence(self::tx($rec, 1, self::opTlv(3, '')))['opaque']);
        $this->assertSame('parseNvidiaSpdmEvidence: opaque TLV overruns opaque data', self::parseErr(self::tx($rec, 1, "\x03\0\x0a\0")));
        $this->assertSame([3 => 'ab', 6 => 'c'], Nvidia::parseEvidence(self::tx($rec, 1, self::opTlv(3, 'ab') . self::opTlv(6, 'c')))['opaque']);
    }

    public function testVbiosVersionRendering(): void
    {
        $this->assertSame('96.00.9f.00.04', Nvidia::formatVbiosVersion(self::vb()));
    }

    // ------------------------------------------------------------------------------------------------------- device chain

    public function testPemChainLimits(): void
    {
        $blk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        try {
            Nvidia::parsePemChain(str_repeat($blk, 6));
            $this->fail('no error');
        } catch (\ValueError $e) {
            $this->assertSame('parsePemChain: chain longer than 5', $e->getMessage());
        }
        try {
            Nvidia::parsePemChain('nothing');
            $this->fail('no error');
        } catch (\ValueError $e) {
            $this->assertSame('parsePemChain: no certificates found', $e->getMessage());
        }
    }

    public function testDeviceChainRootMustBeASelfSignedCa(): void
    {
        $other = self::issue('NVIDIA Other CA', self::CA, null, 0x3001);
        $notSelfSigned = self::issue('NVIDIA Lone CA', self::CA, $other, 0x3002);
        $notCa = self::issue('NVIDIA Lone Leaf', self::LEAF, null, 0x3003);
        $why = 'device chain root is not a self-signed CA';
        $this->assertSame(['ok' => false, 'reason' => $why], Nvidia::verifyDeviceChain($notSelfSigned['pem'], [Cert::fromPem($notSelfSigned['pem'])->spkiSha256()], self::now()));
        $this->assertSame(['ok' => false, 'reason' => $why], Nvidia::verifyDeviceChain($notCa['pem'], [Cert::fromPem($notCa['pem'])->spkiSha256()], self::now()));
        $self = self::issue('NVIDIA Lone Root', self::CA, null, 0x3004);
        $this->assertTrue(Nvidia::verifyDeviceChain($self['pem'], [Cert::fromPem($self['pem'])->spkiSha256()], self::now())['ok']);
    }

    public function testPinsMayBeNonStringsAndAnyCase(): void
    {
        $d = self::dev();
        $r = Nvidia::verifyDeviceChain($d['pem'], [12345, strtoupper($d['pin'])], self::now());
        $this->assertTrue($r['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'chain root is not a pinned NVIDIA root'], Nvidia::verifyDeviceChain($d['pem'], [12345], self::now()));
    }

    public function testBase64CertificatesAreRewrappedAt64Characters(): void
    {
        $in = str_repeat('A', 64) . "\n" . str_repeat('B', 64) . ' CC';
        $this->assertSame("-----BEGIN CERTIFICATE-----\n" . str_repeat('A', 64) . "\n" . str_repeat('B', 64) . "\nCC\n-----END CERTIFICATE-----", self::priv('pemOfDerB64', $in));
    }

    public function testIntegralFloatTest(): void
    {
        foreach ([0.0, 2.0, -3.0, 1e15] as $v) {
            $this->assertTrue(self::priv('isInt', $v), (string)$v);
        }
        foreach ([1.5, -0.5, NAN, INF, -INF] as $v) {
            $this->assertFalse(self::priv('isInt', $v), (string)$v);
        }
    }

    // ----------------------------------------------------------------------------------------------------------------- RIM

    public function testRimSizeLimit(): void
    {
        $at = '<a/>' . str_repeat(' ', 4_000_000 - 4);
        $this->assertSame(4_000_000, strlen($at));
        $this->assertSame(['ok' => false, 'reason' => 'RIM: root element is not SoftwareIdentity'], Nvidia::verifyRim($at, ['aa'], self::now()));
        $this->assertSame(['ok' => false, 'reason' => 'RIM: empty or oversized document'], Nvidia::verifyRim($at . ' ', ['aa'], self::now()));
        $this->assertSame(['ok' => false, 'reason' => 'RIM: empty or oversized document'], Nvidia::verifyRim('', ['aa'], self::now()));
    }

    public function testRimProfileViolationAndParseErrorTexts(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'RIM: DTD / DOCTYPE is not permitted'], Nvidia::verifyRim('<!DOCTYPE a><a/>', ['aa'], self::now()));
        $this->assertSame(['ok' => false, 'reason' => 'RIM: verification error (fail closed): text outside the root element'], Nvidia::verifyRim("\x0c<a/>", ['aa'], self::now()));
    }

    public function testRimTransformsMustBeExactlyEnvelopedThenC14n(): void
    {
        $pin = [self::rimPki()['pin']];
        $t = static fn(string ...$algs): string => '<ds:Transforms>' . implode('', array_map(static fn(string $a): string => '<ds:Transform Algorithm="' . $a . '"/>', $algs)) . '</ds:Transforms>';
        foreach ([[self::ENV, self::ENV], [self::C14N, self::C14N], [self::ENV, self::C14N, self::C14N], [self::C14N, self::ENV], [self::ENV]] as $i => $algs) {
            $this->assertSame(['ok' => false, 'reason' => self::TRANSFORMS_BAD], Nvidia::verifyRim(self::rimText(['transforms' => $t(...$algs)], 'x', 'x'), $pin, self::now()), "case $i");
        }
    }

    public function testRimNeedsBothDigestAndSignatureValue(): void
    {
        $pin = [self::rimPki()['pin']];
        $why = ['ok' => false, 'reason' => 'RIM: missing DigestValue / SignatureValue'];
        $cases = [
            ['dvEl' => ''], ['svEl' => ''], ['dvEl' => '<ds:DigestValue></ds:DigestValue>'], ['svEl' => '<ds:SignatureValue></ds:SignatureValue>'],
            ['dvEl' => '', 'svEl' => ''],
        ];
        foreach ($cases as $i => $o) {
            $this->assertSame($why, Nvidia::verifyRim(self::rimText($o, 'x', 'x'), $pin, self::now()), "case $i");
        }
    }

    public function testASignedRimIsReadWithGoldenValuesFromTheVerifiedTree(): void
    {
        $payload = '<Payload><Resource type="Other"/><Thing type="Measurement" index="9"/>'
            . self::resource('index="0" active="true" alternatives="2" size="1" Hash2="BB" Hash1="aa"')
            . self::resource('index="3" active="false" alternatives="2" size="1" Hash1="cc" Hash2="dd"')
            . self::resource('index="5" active="TRUE" alternatives="3" size="2" Hash10="c3c3" Hash9="b2b2" Hash2="a1a1"')
            . '</Payload>';
        $r = self::verifyRim(self::rimFor('<Meta product="GH100" colloquialVersion="535.104.05"/>' . $payload));
        $this->assertSame(['ok' => true, 'rim' => [
            'tagId' => 'T1', 'product' => 'GH100', 'version' => '535.104.05',
            'golden' => [
                0 => ['index' => 0, 'active' => true, 'alternatives' => 2, 'size' => 1, 'hashes' => ['aa', 'bb']],
                3 => ['index' => 3, 'active' => false, 'alternatives' => 2, 'size' => 1, 'hashes' => ['cc', 'dd']],
                5 => ['index' => 5, 'active' => true, 'alternatives' => 3, 'size' => 2, 'hashes' => ['a1a1', 'b2b2', 'c3c3']],
            ],
        ]], $r);
    }

    public function testRimHashAttributesAreOrderedByTheirNumber(): void
    {
        $asc = self::verifyRim(self::rimFor('<Meta product="P" colloquialVersion="V"/><Payload>' . self::resource('index="0" active="true" alternatives="2" size="1" Hash1="aa" Hash2="bb"') . '</Payload>'));
        $this->assertSame(['aa', 'bb'], $asc['rim']['golden'][0]['hashes']);
        $desc = self::verifyRim(self::rimFor('<Meta product="P" colloquialVersion="V"/><Payload>' . self::resource('index="0" active="true" alternatives="2" size="1" Hash2="bb" Hash1="aa"') . '</Payload>'));
        $this->assertSame(['aa', 'bb'], $desc['rim']['golden'][0]['hashes']);
    }

    public function testRimFirstMetaAndFirstPayloadAreTheOnesRead(): void
    {
        $meta = '<Meta product="GH100" colloquialVersion="1"/>';
        $none = ['ok' => false, 'reason' => 'RIM: missing Meta / Payload'];
        $this->assertSame($none, self::verifyRim(self::rimFor($meta)));
        $this->assertSame($none, self::verifyRim(self::rimFor(self::PAYLOAD0)));
        $two = self::verifyRim(self::rimFor($meta . '<Meta product="GB100" colloquialVersion="2"/>' . self::PAYLOAD0));
        $this->assertSame(['GH100', '1'], [$two['rim']['product'], $two['rim']['version']]);
        $p2 = '<Payload>' . self::resource('index="1" active="true" alternatives="1" size="1" Hash1="bb"') . '</Payload>';
        $pay = self::verifyRim(self::rimFor($meta . self::PAYLOAD0 . $p2));
        $this->assertSame([0], array_keys($pay['rim']['golden']));
    }

    public function testRimSkipsEverythingThatIsNotAMeasurementResourceAndKeepsScanning(): void
    {
        $r = self::verifyRim(self::rimFor('<Meta product="P" colloquialVersion="V"/><Payload><Resource type="Other"/><Thing/><Thing type="Measurement"/>'
            . self::resource('index="2" active="true" alternatives="1" size="1" Hash1="aa"') . '</Payload>'));
        $this->assertSame([2], array_keys($r['rim']['golden']));
    }

    public function testRimMeasurementAttributesMustBeNonNegativeIntegers(): void
    {
        $bad = ['ok' => false, 'reason' => 'RIM: malformed Measurement resource'];
        foreach (['index="1.5" active="true" alternatives="1" size="1" Hash1="aa"', 'index="-1" active="true" alternatives="1" size="1" Hash1="aa"',
                  'index="0" active="true" alternatives="0" size="1" Hash1="aa"', 'index="0" active="true" alternatives="1.5" size="1" Hash1="aa"',
                  'index="0" active="true" alternatives="1" size="0" Hash1="aa"', 'index="0" active="true" alternatives="1" size="1.5" Hash1="aa"',
                  'index="x" active="true" alternatives="1" size="1" Hash1="aa"'] as $i => $attrs) {
            $this->assertSame($bad, self::verifyRim(self::rimFor('<Meta product="P" colloquialVersion="V"/><Payload>' . self::resource($attrs) . '</Payload>')), "case $i");
        }
    }

    public function testRimHashListMustMatchAlternativesAndSize(): void
    {
        $bad = ['ok' => false, 'reason' => 'RIM: Measurement 0 hash list is inconsistent with alternatives/size'];
        foreach (['alternatives="2" size="1" Hash1="aa"', 'alternatives="1" size="1" Hash1="zz"', 'alternatives="1" size="1" Hash1="aabb"',
                  'alternatives="1" size="2" Hash1="aa"', 'alternatives="1" size="1" Hash1=""'] as $i => $attrs) {
            $this->assertSame($bad, self::verifyRim(self::rimFor('<Meta product="P" colloquialVersion="V"/><Payload>' . self::resource('index="0" active="true" ' . $attrs) . '</Payload>')), "case $i");
        }
    }

    // ------------------------------------------------------------------------------------------------------------ RIM ids

    public function testRimIdsHopperAndBlackwellForms(): void
    {
        $ids = ['chip' => 'GH100', 'driver' => 'NV_GPU_DRIVER_GH100_535.104.05', 'vbios' => 'NV_GPU_VBIOS_PR17_PS18_CS15_96009F0004',
            'driverVersion' => '535.104.05', 'vbiosVersion' => '96.00.9f.00.04'];
        $this->assertSame($ids, Nvidia::rimIdsForReport(['opaque' => self::opq()]));
        $this->assertSame($ids, Nvidia::rimIdsForReport(['opaque' => self::opq([35 => 'GH100'])]));
        $this->assertSame(array_merge($ids, ['chip' => 'GB100', 'driver' => 'NV_GPU_CC_DRIVER_GB100_535.104.05']), Nvidia::rimIdsForReport(['opaque' => self::opq([35 => "GB100\0"])]));
        foreach (['AB1', 'A' . str_repeat('B', 11)] as $chip) {
            $this->assertSame($chip, Nvidia::rimIdsForReport(['opaque' => self::opq([35 => $chip])])['chip']);
        }
    }

    public function testRimIdsChipShape(): void
    {
        foreach (['', 'AB', 'gb100', '1AB', 'AB-1', 'A' . str_repeat('B', 12), 'G H100'] as $chip) {
            $this->assertNull(Nvidia::rimIdsForReport(['opaque' => self::opq([35 => $chip])]), $chip);
        }
    }

    public function testRimIdsNeedEveryFieldAndReadTheRightOnes(): void
    {
        foreach ([3, 6, 15, 17, 18] as $tag) {
            $this->assertNull(Nvidia::rimIdsForReport(['opaque' => self::opq([], [$tag])]), "drop $tag");
        }
        foreach ([3, 15, 17, 18] as $tag) {
            $this->assertNull(Nvidia::rimIdsForReport(['opaque' => self::opq([$tag => "\0"])]), "empty $tag");
        }
        $this->assertNull(Nvidia::rimIdsForReport(['opaque' => []]));
        $this->assertSame('NV_GPU_VBIOS_PR17_PS18_CS15_96009F0004', Nvidia::rimIdsForReport(['opaque' => self::opq()])['vbios']);
    }

    public function testRimIdsUpperCaseNonAsciiLetters(): void
    {
        $ids = Nvidia::rimIdsForReport(['opaque' => self::opq([15 => "c\xe9", 17 => "p\xe9r", 18 => "s\xe9"])]);
        $this->assertSame("NV_GPU_VBIOS_P\u{C9}R_S\u{C9}_C\u{C9}_96009F0004", $ids['vbios']);
    }

    // ------------------------------------------------------------------------------------------------- golden comparison

    public function testCompareConflictAndInactiveEntries(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'driver and VBIOS RIMs both have an active measurement at index 3'],
            self::cmp(self::rep([[4, "\xaa"]]), self::rimg(self::gold(3, ['aa'])), self::rimg(self::gold(3, ['bb']))));
        $this->assertSame(self::differ(1), self::cmp(self::rep([[1, "\xaa"], [2, "\x00"]]), self::rimg(self::gold(0, ['aa'])),
            self::rimg(self::gold(5, ['bb'], false), self::gold(1, ['cc']))));
        $this->assertSame(['ok' => true], self::cmp(self::rep([[4, "\xaa"]]), self::rimg(self::gold(3, ['aa'])), self::rimg(self::gold(3, ['bb'], false))));
    }

    public function testCompareCountsOfActiveMeasurements(): void
    {
        $none = ['ok' => false, 'reason' => 'RIMs carry no active golden measurements'];
        $this->assertSame($none, self::cmp(self::rep([[1, "\xaa"]]), self::rimg(self::gold(0, ['aa'], false))));
        $this->assertSame($none, self::cmp(self::rep([[1, "\xaa"]]), self::rimg()));
        $this->assertSame(['ok' => true], self::cmp(self::rep([[1, "\xaa"]]), self::rimg(self::gold(0, ['aa']))));
        $this->assertSame(['ok' => false, 'reason' => 'RIMs list more active measurements than the report carries'],
            self::cmp(self::rep([[1, "\xaa"]]), self::rimg(self::gold(0, ['aa']), self::gold(1, ['bb']))));
    }

    public function testCompareDigestRules(): void
    {
        $this->assertSame(['ok' => true], self::cmp(self::rep([[1, "\xbb"]]), self::rimg(self::gold(0, ['aa', 'bb']))));
        $this->assertSame(self::differ(1), self::cmp(self::rep([[1, "\xbb"]]), self::rimg(self::gold(0, ['aa']))));
        $this->assertSame(self::differ(1), self::cmp(self::rep([[1, "\xaa"]]), self::rimg(self::gold(5, ['aa']))));
        $this->assertSame(self::differ(1), self::cmp(self::rep([[1, "\xab\xcd"]]), self::rimg(self::gold(0, ['abcd'], true, 1))));
        $this->assertSame(self::differ(2), self::cmp(self::rep([[1, "\x00"], [2, "\x00"]]), self::rimg(self::gold(0, ['aa']), self::gold(1, ['bb']))));
    }

    public function testCompareNvdecBlockSkip(): void
    {
        $one = self::rimg(self::gold(34, ['aa']));
        $at = static fn(array $op): array => self::cmp(self::rep([[35, "\x00"]], $op), $one);
        $this->assertSame(['ok' => true], $at([11 => "\x55"]));
        $this->assertSame(['ok' => true], $at([11 => "\x55\x01"]));
        foreach ([[11 => "\x54"], [11 => "\x56"], [11 => ''], [], [12 => "\x55"], [10 => "\x55"]] as $i => $op) {
            $this->assertSame(self::differ(1), $at($op), "case $i");
        }
        $disabled = [11 => "\x55"];
        $this->assertSame(self::differ(1), self::cmp(self::rep([[34, "\x00"]], $disabled), self::rimg(self::gold(33, ['aa']))));
        $this->assertSame(self::differ(1), self::cmp(self::rep([[36, "\x00"]], $disabled), self::rimg(self::gold(35, ['aa']))));
        $this->assertSame(self::differ(1), self::cmp(self::rep([[37, "\x00"]], $disabled), self::rimg(self::gold(36, ['aa']))));
        // the skip does not end the scan
        $this->assertSame(self::differ(1), self::cmp(self::rep([[35, "\x00"], [41, "\x00"]], $disabled), self::rimg(self::gold(34, ['aa']), self::gold(40, ['bb']))));
    }

    // ---------------------------------------------------------------------------------------------------------- CRL gate

    public function testRevocationAcceptsACrlSignedByTheLeafItself(): void
    {
        $chain = self::devChain();
        $this->assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($chain, [self::crl(self::dev()['leaf']['key'], [])], self::now()));
    }

    public function testRevocationSeesAnIntermediateListedByTheRoot(): void
    {
        $chain = self::devChain();
        $crl = self::crl(self::dev()['root']['key'], [$chain[1]->serial]);
        $this->assertSame(['ok' => false, 'reason' => "chain certificate 'CN=NVIDIA Test Inter' is revoked"], Nvidia::checkChainRevocation($chain, [$crl], self::now()));
        $clean = self::crl(self::dev()['root']['key'], [$chain[0]->serial]);
        $this->assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($chain, [$clean], self::now()));
    }

    // -------------------------------------------------------------------------------------------------- firmware policy

    public function testVersionParsing(): void
    {
        $this->assertSame([535, 104, 5], self::priv('parseVersion', '535.104.05', 10));
        $this->assertSame([12345, 6], self::priv('parseVersion', '12345.6', 10));
        $this->assertNull(self::priv('parseVersion', '1a.2', 10));
        $this->assertSame([26, 255], self::priv('parseVersion', '1a.ff', 16));
        $this->assertSame([150, 0, 159, 0, 4], self::priv('parseVersion', '96.00.9f.00.04', 16));
        $this->assertNull(self::priv('parseVersion', '12345.6', 16));
        $this->assertNull(self::priv('parseVersion', 7, 10));
    }

    public function testVersionComparison(): void
    {
        $this->assertSame(0, self::priv('cmpVersion', [1], [1, 0]));
        $this->assertSame(0, self::priv('cmpVersion', [1, 0], [1]));
        $this->assertSame(-1, self::priv('cmpVersion', [1], [2]));
        $this->assertSame(1, self::priv('cmpVersion', [2], [1]));
        $this->assertSame(1, self::priv('cmpVersion', [1, 5], [1, 4]));
        $this->assertSame(-1, self::priv('cmpVersion', [1, 4, 0], [1, 4, 3]));
        $this->assertSame(0, self::priv('cmpVersion', [], []));
    }

    public function testFirmwareMinimumVbiosIsHexAndEqualIsNotBelow(): void
    {
        $f = self::priv('compileFirmwarePolicy', ['minVbiosVersion' => '10.0']);
        $this->assertNull($f(['driverVersion' => '1.0', 'vbiosVersion' => '10.0']));
        $this->assertSame('VBIOS 0f.0 is below the minimum 10.0', $f(['driverVersion' => '1.0', 'vbiosVersion' => '0f.0']));
        $this->assertSame("VBIOS version 'zz' in the GPU report is not parseable", $f(['driverVersion' => '1.0', 'vbiosVersion' => 'zz']));
        $this->assertSame("driver version 'q' in the GPU report is not parseable", $f(['driverVersion' => 'q', 'vbiosVersion' => '10.0']));
    }

    // --------------------------------------------------------------------------------------------------- collateral hook

    public function testHookNeedsAPinnedRoot(): void
    {
        $resolve = static fn(array $ids, mixed $ev): ?array => null;
        $msg = 'nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root';
        $this->assertSame($msg, self::ctorError(static fn() => Nvidia::collateralHook(['rimRootSpkiSha256' => []], $resolve)));
        $this->assertSame($msg, self::ctorError(static fn() => Nvidia::collateralHook(['rimRootSpkiSha256' => 'aa'], $resolve)));
        $this->assertSame($msg, self::ctorError(static fn() => Nvidia::collateralHook(null, $resolve)));
        $this->assertInstanceOf(\Closure::class, Nvidia::collateralHook(['rimRootSpkiSha256' => ['aa']], $resolve));
    }

    public function testHookNamingAndFamilyMessages(): void
    {
        $hook = Nvidia::collateralHook(['rimRootSpkiSha256' => ['aa']], static fn(array $ids, mixed $ev): ?array => null);
        $this->assertSame('GPU report does not carry the opaque fields needed to name its RIMs', $hook(self::hctx(['opaque' => []])));
        $this->assertSame("device leaf subject 'O=Acme, CN=Other' is not a GH100 device certificate (chip family mismatch)",
            $hook(self::hctx(['opaque' => self::opq()], "O=Acme\nCN=Other")));
        $this->assertSame("device leaf subject 'CN=XGH100' is not a GH100 device certificate (chip family mismatch)", $hook(self::hctx(['opaque' => self::opq()], 'CN=XGH100')));
        $this->assertSame('no RIM collateral supplied for this report', $hook(self::hctx(['opaque' => self::opq()])));
    }

    public function testHookRimFailuresAreAttributed(): void
    {
        $this->assertSame('VBIOS RIM: RIM: empty or oversized document', self::hookWith(self::driverRim(), ''));
        $this->assertSame('driver RIM: RIM: empty or oversized document', self::hookWith('', self::vbiosRim()));
    }

    public function testHookWrongFamilyManifests(): void
    {
        $this->assertSame("driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)", self::hookWith(self::driverRim('GB100'), self::vbiosRim()));
        $this->assertSame("VBIOS RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)", self::hookWith(self::driverRim(), self::vbiosRim('GB100')));
    }

    public function testHookVbiosVersionIsComparedWithoutCaseOrDots(): void
    {
        $why = 'runtime measurements differ from the golden RIM values at 1 index(es)';
        $this->assertSame($why, self::hookWith(self::driverRim(), self::vbiosRim('GH100', '96.00.9f.00.04')));
        $this->assertSame($why, self::hookWith(self::driverRim(), self::vbiosRim('GH100', '96009F0004')));
        $this->assertSame("VBIOS RIM version '9.9' does not match the report's VBIOS '96.00.9f.00.04'", self::hookWith(self::driverRim(), self::vbiosRim('GH100', '9.9')));
        $this->assertSame("driver RIM version '1' does not match the report's driver '535.104.05'", self::hookWith(self::driverRim('GH100', '1'), self::vbiosRim()));
    }

    // ------------------------------------------------------------------------------------------------------- the verifier

    public function testFromConfigWithoutACollateralHookStillNeedsPinnedMeasurements(): void
    {
        $this->assertSame('createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)',
            self::ctorError(static fn() => Nvidia::fromConfig(['rootSpkiSha256' => ['aa'], 'collateral' => null], static fn($d) => null)));
    }

    public function testMeasurementIndexRange(): void
    {
        $mk = static fn(string $k): Nvidia => new Nvidia(['rootSpkiSha256' => ['aa'], 'measurements' => Obj::of([$k => 'AB'])], static fn($d) => null);
        $want = new \ReflectionProperty(Nvidia::class, 'want');
        $this->assertSame([[0, 'ab']], $want->getValue($mk('0')));
        $this->assertSame([[255, 'ab']], $want->getValue($mk('255')));
        foreach (['-1', '256', '1.5', 'x'] as $k) {
            $this->assertSame('createNvidiaSpdmVerifier: measurement index out of range', self::ctorError(static fn() => $mk($k)), $k);
        }
    }

    public function testPinsAreKeptAsStrings(): void
    {
        $v = new Nvidia(['rootSpkiSha256' => [123, 'ab'], 'measurements' => Obj::of(['1' => 'aa'])], static fn($d) => null);
        $this->assertSame(['123', 'ab'], (new \ReflectionProperty(Nvidia::class, 'pins'))->getValue($v));
    }

    public function testVerifierMessagesBeforeAnyCryptography(): void
    {
        $mk = static fn(callable $r): Nvidia => new Nvidia(['rootSpkiSha256' => ['aa'], 'measurements' => Obj::of(['1' => 'aa'])], $r);
        $none = ['ok' => false, 'reason' => 'no NVIDIA GPU evidence for this action'];
        $this->assertSame($none, $mk(static fn($d) => ['evidence' => 123, 'certChainPem' => 'x'])->verify('doc', null, 1.0));
        $this->assertSame($none, $mk(static fn($d) => ['evidence' => 'e'])->verify('doc', null, 1.0));
        $this->assertSame($none, $mk(static fn($d) => ['certChainPem' => 'x'])->verify('doc', null, 1.0));
        $this->assertSame($none, $mk(static fn($d) => 'nope')->verify('doc', null, 1.0));
        $this->assertSame(['ok' => false, 'reason' => 'nvidia-spdm verification error (fail closed): boom'],
            $mk(static function ($d) {
                throw new \RuntimeException('boom');
            })->verify('doc', null, 1.0));
    }

    public function testANonNumericClockIsTimeZero(): void
    {
        $d = self::dev();
        $v = new Nvidia(['rootSpkiSha256' => [$d['pin']], 'measurements' => Obj::of(['1' => 'aa'])], static fn($doc) => ['evidence' => 'e', 'certChainPem' => $d['pem']]);
        $this->assertSame(['ok' => false, 'reason' => 'device chain cert #0 is outside its validity window'], $v->verify('doc', null, 'not a number'));
    }

    public function testASignedTranscriptVerifiesAndItsMeasurementsAreHashedInIndexOrder(): void
    {
        $d = self::dev();
        $d1 = str_repeat("\x11", 48);
        $d3 = str_repeat("\x33", 48);
        $exp = ['holderPub' => 'hp', 'grantRef' => 'gr', 'epoch' => 5, 'nonce' => 'n1'];
        $opaque = self::opTlv(3, "535.104.05\0\0") . self::opTlv(6, self::vb());
        $t = self::req(0x11, Common::challengeSha256($exp)) . self::resp(self::block(3, $d3) . self::block(1, $d1), 2, $opaque, 0x11, str_repeat("\0", 96));
        $signed = substr($t, 0, -96);
        openssl_sign($signed, $der, $d['leaf']['key'], OPENSSL_ALGO_SHA384);
        $evidence = $signed . self::rawSig($der);
        $v = new Nvidia(['rootSpkiSha256' => [$d['pin']], 'measurements' => Obj::of(['1' => bin2hex($d1)])], static fn($doc) => ['evidence' => $evidence, 'certChainPem' => $d['pem']]);
        $this->assertSame([
            'ok' => true, 'bound' => true,
            'measured' => ['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => '', 'operator' => ''],
            'hostAsserted' => ['attestation_type' => 'nvidia-gpu-cc', 'gpu_measurements_sha384' => hash('sha384', $d1 . $d3), 'leaf_subject' => 'CN=NVIDIA GH100 Device',
                'driver_version' => '535.104.05', 'vbios_version' => '96.00.9f.00.04'],
        ], $v->verify('doc', $exp, self::now()));
    }
}
