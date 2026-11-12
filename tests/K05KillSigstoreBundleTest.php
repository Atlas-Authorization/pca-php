<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\PubKey;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use Atlas\Pca\SigstoreBundle;
use Atlas\Pca\SigstoreFail;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for SigstoreBundle. Bundles and the trusted root are the oracle's synthetic PKI (test-data/k05-sigstore.json.gz);
 * the private DER / SCT / RFC 3161 / checkpoint helpers are driven through reflection with inputs derived from those fixtures.
 */
final class K05KillSigstoreBundleTest extends TestCase
{
    private const FILE = __DIR__ . '/../test-data/k05-sigstore.json.gz';
    private const ROOT = 'parseTrustedRoot/synthetic';
    private const DSSE = 'verifySigstoreBundleCore/dsse/valid';
    private const SET_ONLY = 'verifySigstoreBundleCore/dsse/valid set-only';
    private const V2 = 'verifySigstoreBundleCore/hashedrekord/valid';
    private const GEN_TIME = 1780315230000; // the synthetic TSA's genTime, 2026-06-01T12:00:30Z
    private const SCT_OID = '1.3.6.1.4.1.11129.2.4.2';

    // openssl-generated test material: a 1024-bit RSA key (PKCS#1 and SPKI forms) with a PKCS#1 v1.5 SHA-256 signature over
    // "atlas-k05-rsa", and a self-signed P-256 certificate whose basicConstraints is CA:FALSE (valid 2026-11-03 .. 2126-10-10)
    private const RSA_PKCS1 = 'MIGJAoGBAL0E1qMWblqw2PPCGPzPHLC6qMJkYz+omrML8J8T4ZfT8HElwlD+Oj5lEpEKEQhfRH3OEFbG8SXyByhxRh9WQPZ1RmBq4R7bX3N5yR3HycjBuErIsAE5sYXaWb9uVkb+BldCe/keCOOxl+buEek7gzhatigD0zbjfqGeEFNssDRvAgMBAAE=';
    private const RSA_SPKI = 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9BNajFm5asNjzwhj8zxywuqjCZGM/qJqzC/CfE+GX0/BxJcJQ/jo+ZRKRChEIX0R9zhBWxvEl8gcocUYfVkD2dUZgauEe219zeckdx8nIwbhKyLABObGF2lm/blZG/gZXQnv5HgjjsZfm7hHpO4M4WrYoA9M2436hnhBTbLA0bwIDAQAB';
    private const RSA_SIG = 'uZsBDLDCg/FNNmz/D2AfhdD4pzLgmr8I52rvJtkVr6YQeqJC/7S/6CI4fK49uYbbtm0jn+t7DcxV6FkjCtlrfyXZ7yVr930PzJkbfUEY/vCZ52hRgSBhk2vMYIen68NuDsRQhyHJijxTO0GVi9DhYfXjJws0sSVJKYcKBQsmU48=';
    private const NOCA = 'MIIBJjCBzaADAgECAgEHMAoGCCqGSM49BAMCMBMxETAPBgNVBAMMCGswNS1ub2NhMCAXDTI2MTEwMzA1MDA0M1oYDzIxMjYxMDEwMDUwMDQzWjATMREwDwYDVQQDDAhrMDUtbm9jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPuneSoxS9rS55sPIQf/js4Ng+JjSVYWr1BgvTXFrSK8429ZvYJa5Hy5j+zSjlYzF2wVCCfs3S6noGdbUzEPutqjEDAOMAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSAAwRQIgHEgHGpQPDgU6L4D0pI7f+E+oArHG7hRnNVXLExUEcjcCIQDUdHzCi1AaHzqz/MyQ5x713o/OWO0aT6VdR9KDJj6V7w==';

    // openssl-generated: a self-signed P-256 CA (CA:TRUE, keyCertSign, 2020-01-01 .. 2099-12-31) and two leaves it issued over one P-256
    // key (CA:FALSE, no EKU): R5_LEAF plain, R5_ODD with an extra extension 1.2.3.4.5 whose value is the bytes 06 03 55 1d 11 (the
    // subjectAltName OID) while the certificate has no subjectAltName
    private const R5_CA = 'MIIBezCCASKgAwIBAgIBATAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlrMDUtcjUtY2EwIBcNMjAwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAwMDBaMBQxEjAQBgNVBAMMCWswNS1yNS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLUjrwEHlHoQ1hNx0HH3RLn/EZpGQUqqZ2DI3A262PzGMuYR3s/B0ryyobVlwv6oU1jrLoGqaikMPctF0+mL78+jYzBhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBQ9igKa3MFJTn8t5pKzyAQqCkLLXzAfBgNVHSMEGDAWgBQ9igKa3MFJTn8t5pKzyAQqCkLLXzAKBggqhkjOPQQDAgNHADBEAiBSkVxALfRMaAkVIpHiPbr8O36JSvyd4Q0VBkbMBAMSDAIgBXP76t/TSYfStnKfgnkPpwcEKevm7nHLY3GdoZCI5q8=';
    private const R5_LEAF = 'MIIBSzCB8qADAgECAgECMAoGCCqGSM49BAMCMBQxEjAQBgNVBAMMCWswNS1yNS1jYTAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MTIzMTAwMDAwMFowFjEUMBIGA1UEAwwLazA1LXI1LWxlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARzCakdWMmq79xLyI/VVNBcx+2f31rTEx4k8iHKs9Z1QnE+t7UQl8pmwGL8lnmoSZwzKKyShE4QNC4h2M36r/V+ozEwLzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFD2KAprcwUlOfy3mkrPIBCoKQstfMAoGCCqGSM49BAMCA0gAMEUCIQDGDEhxawranamm7vR8Yxz5qNH7GTMNFh8AWPQTNMMrEAIgHEpu4RWOVWs8Uge+4kFN/ESWZ7qqMtbcDqMkPtsAYSM=';
    private const R5_ODD = 'MIIBWzCCAQGgAwIBAgIBAjAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlrMDUtcjUtY2EwIBcNMjAwMTAxMDAwMDAwWhgPMjA5OTEyMzEwMDAwMDBaMBYxFDASBgNVBAMMC2swNS1yNS1sZWFmMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcwmpHVjJqu/cS8iP1VTQXMftn99a0xMeJPIhyrPWdUJxPre1EJfKZsBi/JZ5qEmcMyiskoROEDQuIdjN+q/1fqNAMD4wDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ9igKa3MFJTn8t5pKzyAQqCkLLXzANBgQqAwQFBAUGA1UdETAKBggqhkjOPQQDAgNIADBFAiArfUMxk7WlkCs+HgH9evauGti48xk6G75Q/jKHIQ7nmwIhAPa7NhInvWBTrLQvNeKbp9dF2MjpKXCDdMvLDteEmq2o';

    // ---------------------------------------------------------------------------------------------- fixtures and helpers

    /** The first arg of each named oracle case. @return array<string,Obj> */
    private static function fx(string $name): Obj
    {
        static $fx = [];
        if ($fx === []) {
            $want = [self::ROOT, self::DSSE, self::SET_ONLY, self::V2];
            $h = gzopen(self::FILE, 'rb');
            if ($h === false) {
                throw new \RuntimeException('cannot open the sigstore oracle');
            }
            try {
                while (count($fx) < count($want) && ($l = gzgets($h)) !== false) {
                    foreach ($want as $n) {
                        if (!isset($fx[$n]) && str_contains($l, '"name":' . json_encode($n, JSON_UNESCAPED_SLASHES) . ',')) {
                            $l = rtrim($l, "\r\n");
                            $fx[$n] = Json::parseLax(str_ends_with($l, ',') ? substr($l, 0, -1) : $l)->get('args')[0];
                        }
                    }
                }
            } finally {
                gzclose($h);
            }
        }
        return $fx[$name] ?? throw new \RuntimeException("missing fixture $name");
    }

    /** A deep copy of the synthetic trusted root document (strings only, so the strict canonical form round-trips). */
    private static function rootDoc(): Obj
    {
        return Json::parseLax(Json::canonicalizeStrict(self::fx(self::ROOT)));
    }

    private static function roots(): array
    {
        return SigstoreBundle::parseTrustedRoot(self::rootDoc());
    }

    private static function call(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(SigstoreBundle::class, $m))->invoke(null, ...$a);
    }

    private function fails(string $msg, callable $f): void
    {
        try {
            $f();
            $this->fail("no refusal, wanted: $msg");
        } catch (SigstoreFail $e) {
            $this->assertSame($msg, $e->getMessage());
        }
    }

    private static function der(int $tag, string $c): string
    {
        $n = strlen($c);
        if ($n < 0x80) {
            return chr($tag) . chr($n) . $c;
        }
        $b = ltrim(pack('N', $n), "\0");
        return chr($tag) . chr(0x80 | strlen($b)) . $b . $c;
    }

    /** @return list<array{0:int,1:string}> the top-level [tag, content] elements of a DER content string */
    private static function kidsOf(string $c): array
    {
        $out = [];
        for ($o = 0; $o < strlen($c);) {
            $tag = ord($c[$o]);
            $l = ord($c[$o + 1]);
            $h = 2;
            if ($l & 0x80) {
                $n = $l & 0x7f;
                $l = 0;
                for ($i = 0; $i < $n; $i++) {
                    $l = $l * 256 + ord($c[$o + 2 + $i]);
                }
                $h += $n;
            }
            $out[] = [$tag, substr($c, $o + $h, $l)];
            $o += $h + $l;
        }
        return $out;
    }

    private static function enc(array $kids): string
    {
        return implode('', array_map(static fn(array $k): string => self::der($k[0], $k[1]), $kids));
    }

    private static function dsse(): array
    {
        $b = self::fx(self::DSSE);
        $vm = $b->get('verificationMaterial');
        $env = $b->get('dsseEnvelope');
        return [
            'leaf' => base64_decode($vm->get('certificate')->get('rawBytes')),
            'pae' => SigstoreBundle::dssePae(SigstoreBundle::INTOTO_PAYLOAD_TYPE, base64_decode($env->get('payload'))),
            'sig' => base64_decode($env->get('signatures')[0]->get('sig')),
            'tsa' => base64_decode($vm->get('timestampVerificationData')->get('rfc3161Timestamps')[0]->get('signedTimestamp')),
            'checkpoint' => $vm->get('tlogEntries')[0]->get('inclusionProof'),
        ];
    }

    // ---------------------------------------------------------------------------------------------- verifyCore

    public function testFailClosedDetailKeepsTheEngineMessage(): void
    {
        $b = Json::parseLax('{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{"certificate":{"rawBytes":"AA=="}},'
            . '"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"!!!!","signatures":[{"sig":"AA=="}]}}');
        $this->assertSame(['ok' => false, 'code' => 'malformed', 'detail' => 'fail closed: not base64'], SigstoreBundle::verifyCore($b, self::roots()));
    }

    public function testTheFirstPinnedLogWithTheKeyIdIsUsed(): void
    {
        $b = self::fx(self::DSSE);
        $r = self::roots();
        $this->assertTrue(SigstoreBundle::verifyCore($b, $r)['ok']);
        $v1 = $r['tlogs'][0];
        $r['tlogs'] = [$v1, ['valid' => [0, 1]] + $v1, $r['tlogs'][1]];
        $this->assertTrue(SigstoreBundle::verifyCore($b, $r)['ok']);
    }

    public function testCaValidityStartsAtTheSigningTime(): void
    {
        $b = self::fx(self::SET_ONLY);
        $r = self::roots();
        $at = $b->get('verificationMaterial')->get('tlogEntries')[0]->get('integratedTime');
        $this->assertSame('1780315260', $at);
        $r['cas'][0]['valid'] = [1780315260000, INF];
        $this->assertTrue(SigstoreBundle::verifyCore($b, $r)['ok']);
        $r['cas'][0]['valid'] = [1780315260001, INF];
        $this->assertSame('cert_chain', SigstoreBundle::verifyCore($b, $r)['code']);
    }

    // ---------------------------------------------------------------------------------------------- parseTrustedRoot

    private function rootRefused(Obj $doc, string $msg): void
    {
        try {
            SigstoreBundle::parseTrustedRoot($doc);
            $this->fail("accepted, wanted: $msg");
        } catch (\InvalidArgumentException $e) {
            $this->assertSame($msg, $e->getMessage());
            $this->assertSame(0, $e->getCode());
            $this->assertInstanceOf(SigstoreFail::class, $e->getPrevious());
        }
    }

    public function testTrustedRootRefusals(): void
    {
        $d = self::rootDoc();
        $t = $d->get('tlogs');
        $t[0] = $t[0]->without('publicKey');
        $d->set('tlogs', $t);
        $this->rootRefused($d, 'log entry malformed');

        $d = self::rootDoc();
        $d->set('ctlogs', [Json::parseLax('{"publicKey":{"rawBytes":"' . self::RSA_PKCS1 . '","keyDetails":"PKCS1_RSA_PKCS1V5",'
            . '"validFor":{"start":"2025-01-01T00:00:00.000Z"}},"logId":{"keyId":"' . base64_encode(str_repeat("\0", 32)) . '"}}')]);
        $this->rootRefused($d, 'log id is not the SHA-256 of its key');

        $d = self::rootDoc();
        $d->get('tlogs')[1]->get('publicKey')->set('rawBytes', base64_encode(str_repeat("\0", 44)));
        $this->rootRefused($d, 'not an Ed25519 key');

        $d = self::rootDoc();
        $d->get('certificateAuthorities')[0]->get('certChain')->set('certificates', Json::parseLax('{"0":{"rawBytes":"AA=="}}'));
        $this->rootRefused($d, 'certificate authority entry malformed');
    }

    public function testRsaCtLogKeyIdIsTheSpkiHash(): void
    {
        $d = self::rootDoc();
        $d->set('ctlogs', [Json::parseLax('{"publicKey":{"rawBytes":"' . self::RSA_PKCS1 . '","keyDetails":"PKCS1_RSA_PKCS1V5",'
            . '"validFor":{"start":"2025-01-01T00:00:00.000Z"}},"logId":{"keyId":"' . base64_encode(hash('sha256', base64_decode(self::RSA_SPKI), true)) . '"}}')]);
        $r = SigstoreBundle::parseTrustedRoot($d);
        $this->assertCount(1, $r['ctlogs']);
        $this->assertNull($r['ctlogs'][0]['v2']);
    }

    public function testV2BaseUrlDropsTabsAndCtLogsAreAList(): void
    {
        $d = self::rootDoc();
        $d->get('tlogs')[1]->set('baseUrl', "https://log2.synthetic.exa\tmple");
        $this->assertSame('log2.synthetic.example', SigstoreBundle::parseTrustedRoot($d)['tlogs'][1]['v2']);

        $d = self::rootDoc();
        $ct = $d->get('ctlogs')[0];
        $d->set('ctlogs', [$d->get('tlogs')[1], $ct]); // an Ed25519 key is no CT log: skipped
        $r = SigstoreBundle::parseTrustedRoot($d);
        $this->assertSame([0], array_keys($r['ctlogs']));
        $this->assertSame(base64_decode($ct->get('logId')->get('keyId')), $r['ctlogs'][0]['keyId']);
    }

    // ---------------------------------------------------------------------------------------------- dates, DER, OIDs

    public function testDateMs(): void
    {
        $ms = static fn(string $iso): int => (new \DateTimeImmutable($iso))->getTimestamp() * 1000;
        $this->assertSame($ms('2025-03-04T05:06:07Z'), self::call('dateMs', '2025-03-04T05:06:07Z'));
        $this->assertSame($ms('2025-03-04T05:06:07+11:30'), self::call('dateMs', '2025-03-04T05:06:07+11:30'));
        $this->assertSame($ms('2025-03-04T05:06:07-11:30'), self::call('dateMs', '2025-03-04T05:06:07-11:30'));
        $this->assertSame($ms('2025-03-04T05:06:07Z') + 500, self::call('dateMs', '2025-03-04T05:06:07.5Z'));
        $this->assertSame($ms('2025-03-04T05:06:07Z') + 123, self::call('dateMs', '2025-03-04T05:06:07.1239Z'));
        $this->assertNull(self::call('dateMs', '2025-03-00T05:06:07Z'));
        $this->assertNull(self::call('dateMs', '2025-13-01T05:06:07Z'));
    }

    public function testTlvLengths(): void
    {
        $this->assertSame([4, 0, 3, 3], self::call('tlv', "\x04\x81\x00", 0));
        $this->assertSame([4, 0, 6, 6], self::call('tlv', "\x04\x84\x00\x00\x00\x00", 0));
        $this->fails('DER length', static fn() => self::call('tlv', "\x30\x80", 0));
        $this->fails('DER length', static fn() => self::call('tlv', "\x30\x80\x00", 0));
        $this->fails('DER length', static fn() => self::call('tlv', "\x04\x82\x00", 0));
        $this->fails('DER length', static fn() => self::call('tlv', "\x04\x85\x00\x00\x00\x00\x00", 0));
    }

    private static function oidOf(string $content): string
    {
        $b = self::der(0x06, $content);
        return self::call('oid', $b, self::call('tlv', $b, 0));
    }

    public function testOidDecoding(): void
    {
        $this->assertSame('0.39', self::oidOf("\x27"));
        $this->assertSame('1.0', self::oidOf("\x28"));
        $this->assertSame('2.40', self::oidOf("\x78"));
        $this->assertSame('1.2.16385', self::oidOf("\x2a\x81\x80\x01")); // 0x80 inside an arc is fine
        $this->fails('OID arc is not minimally encoded', static fn() => self::oidOf("\x2a\x01\x80\x01"));
        $this->fails('OID arc is not minimally encoded', static fn() => self::oidOf("\x80\x01"));
        // a leading 0x80 behind a long-form length whose last byte is 0x80
        $this->fails('OID arc is not minimally encoded', static fn() => self::oidOf("\x80" . str_repeat("\x01", 127)));
    }

    public function testUtf8Lossy(): void
    {
        $this->assertSame("ok\u{e9}", self::call('utf8Lossy', "ok\u{e9}"));
        $out = self::call('utf8Lossy', "a\xffb");
        $this->assertNotSame("a\xffb", $out);
        $this->assertSame(1, preg_match('//u', $out));
        $this->assertStringStartsWith('a', $out);
    }

    // ---------------------------------------------------------------------------------------------- certificates

    private static function ext(string $oid, string $value): string
    {
        return self::der(0x30, self::der(0x06, $oid) . self::der(0x04, $value));
    }

    private static function cert(string $tbs): string
    {
        return self::der(0x30, self::der(0x30, $tbs));
    }

    private static function exts(string ...$e): string
    {
        return self::der(0xa3, self::der(0x30, implode('', $e)));
    }

    public function testParseCertStructure(): void
    {
        $serial = self::der(0x02, "\x01");
        $ok = self::cert($serial . self::exts(self::ext("\x2a\x03", "\x05\x00")));
        $pc = self::call('parseCert', $ok);
        $this->assertCount(1, $pc['exts']);
        $this->assertSame('1.2.3', $pc['exts'][0]['oid']);
        $this->assertSame("\x05\x00", $pc['exts'][0]['value']);
        // the first [3] wrapper is the extensions
        $two = self::call('parseCert', self::cert($serial . self::exts(self::ext("\x2a\x03", 'A')) . self::exts(self::ext("\x2a\x04", 'B'))));
        $this->assertSame(['1.2.3'], array_column($two['exts'], 'oid'));

        $this->fails('certificate is not one SEQUENCE', static fn() => self::call('parseCert', $ok . "\x00"));
        $this->fails('no TBSCertificate', static fn() => self::call('parseCert', "\x30\x00"));
        $this->fails('no TBSCertificate', static fn() => self::call('parseCert', "\x30\x03\x02\x01\x00"));
        $this->fails('no extensions', static fn() => self::call('parseCert', self::cert($serial)));
        $this->fails('extensions malformed', static fn() => self::call('parseCert', self::cert($serial . self::der(0xa3, ''))));
        $this->fails('extensions malformed', static fn() => self::call('parseCert', self::cert($serial . self::der(0xa3, self::der(0x02, "\x01")))));
        $this->fails('extension value is not an OCTET STRING', static fn() => self::call('parseCert',
            self::cert($serial . self::exts(self::der(0x30, self::der(0x06, "\x2a\x03") . self::der(0x01, "\xff"))))));
        $this->fails('extension value is not an OCTET STRING', static fn() => self::call('parseCert', self::cert($serial . self::exts(self::der(0x30, '')))));
    }

    public function testBasicConstraintsCa(): void
    {
        $bc = static fn(string $v): bool => self::call('basicConstraintsCa', ['exts' => [['oid' => '2.5.29.19', 'value' => $v, 'tlv' => [0, 0, 0, 0]]]]);
        $this->assertTrue($bc("\x30\x03\x01\x01\xff"));
        $this->assertFalse($bc("\x30\x03\x01\x01\x00"));
        $this->assertFalse($bc("\x30\x03\x02\x01\x01")); // the first member is an INTEGER, not the cA BOOLEAN
        $this->assertFalse($bc("\x30\x00"));
        $this->assertFalse(self::call('basicConstraintsCa', ['exts' => []]));
    }

    /** A structurally valid certificate with the given UTCTime validity texts. */
    private static function timedCert(string $nb, string $na): Cert
    {
        $alg = self::der(0x30, self::der(0x06, "\x2a\x86\x48\xce\x3d\x04\x03\x02"));
        $tbs = self::der(0x02, "\x01") . $alg . self::der(0x30, '') . self::der(0x30, self::der(0x17, $nb) . self::der(0x17, $na))
            . self::der(0x30, '') . self::der(0x30, self::der(0x30, self::der(0x06, "\x2a\x03")) . self::der(0x03, "\x00"));
        return new Cert(self::der(0x30, self::der(0x30, $tbs) . $alg . self::der(0x03, "\x00")));
    }

    public function testInsideNeedsBothBounds(): void
    {
        $at2010 = 1262304000000;
        $this->assertTrue(self::call('inside', self::timedCert('000101000000Z', '300101000000Z'), $at2010));
        $this->assertFalse(self::call('inside', self::timedCert('AA0101000000Z', '300101000000Z'), $at2010));
    }

    public function testChainOkNeedsCaIssuers(): void
    {
        $x = new Cert(base64_decode(self::NOCA)); // self-signed, CA:FALSE
        $at2030 = 1893456000000;
        $this->assertTrue(self::call('chainOk', [$x], $at2030));
        $this->assertFalse(self::call('chainOk', [$x, $x], $at2030));
    }

    public function testVerifySigDispatch(): void
    {
        $d = self::dsse();
        $ec = (new Cert($d['leaf']))->publicKey();
        $this->assertTrue(self::call('verifySig', 'sha256', $d['pae'], $ec, $d['sig']));
        $this->assertFalse(self::call('verifySig', 'sha256', $d['pae'] . 'x', $ec, $d['sig']));
        $rsa = Common::loadPublicKey(base64_decode(self::RSA_SPKI));
        $this->assertTrue(self::call('verifySig', 'sha256', 'atlas-k05-rsa', $rsa, base64_decode(self::RSA_SIG)));
        $this->assertFalse(self::call('verifySig', 'sha256', $d['pae'], new PubKey($ec->key, $ec->spki, 'dsa', null, []), $d['sig']));
        $this->assertFalse(self::call('verifySig', 'sha256', 'x', str_repeat('k', 32), str_repeat('s', 64))); // a raw key needs no hash
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x05", 32));
        $sig = sodium_crypto_sign_detached('m', sodium_crypto_sign_secretkey($kp));
        $this->assertTrue(self::call('verifySig', null, 'm', sodium_crypto_sign_publickey($kp), $sig));
    }

    // ---------------------------------------------------------------------------------------------- SCT

    public function testSctListWalk(): void
    {
        $roots = self::roots();
        $pc = self::call('parseCert', self::dsse()['leaf']);
        $issuer = $roots['cas'][0]['chain'][0];
        $this->assertNull(self::call('verifySct', $pc, $issuer, $roots));

        $idx = array_search(self::SCT_OID, array_column($pc['exts'], 'oid'), true);
        $this->assertIsInt($idx);
        [[$tag, $list]] = self::kidsOf($pc['exts'][$idx]['value']);
        $this->assertSame(0x04, $tag);
        $entries = [];
        for ($o = 2; $o < strlen($list);) {
            $n = unpack('n', $list, $o)[1];
            $entries[] = substr($list, $o + 2, $n);
            $o += 2 + $n;
        }
        $this->assertCount(1, $entries);
        $r = $entries[0];
        $this->assertSame(0, unpack('n', $r, 41)[1]); // no SCT extensions: hashAlg sits at byte 43

        $with = static function (array $scts) use ($pc, $idx): array {
            $body = implode('', array_map(static fn(string $s): string => pack('n', strlen($s)) . $s, $scts));
            $pc['exts'][$idx]['value'] = self::der(0x04, pack('n', strlen($body)) . $body);
            return $pc;
        };
        $sct = static fn(array $scts, ?array $rt = null): ?string => self::call('verifySct', $with($scts), $issuer, $rt ?? $roots);

        $this->assertNull($sct([$r]));
        $v1 = $r;
        $v1[0] = "\x01";
        $this->assertNull($sct([$v1, $r]));
        $this->assertNull($sct([substr_replace($r, str_repeat("\xee", 32), 1, 32), $r]));
        $h5 = $r;
        $h5[43] = "\x05";
        $this->assertNull($sct([$h5, $r]));
        $this->assertNull($sct([substr_replace($r, pack('J', PHP_INT_MIN), 33, 8), $r]));
        $zero = substr_replace($r, pack('J', 0), 33, 8);
        $this->assertNull($sct([$zero, $r]));
        $this->assertSame('SCT log key not valid at its timestamp', $sct([$zero]));
        // 47 bytes whose signature header is one byte short
        $short = "\x00" . substr($r, 1, 40) . "\x00\x01E\x04\x03\x00";
        $this->assertSame(47, strlen($short));
        $this->assertSame('SCT truncated', $sct([$short, $r]));
        // two pinned CT logs with the same id: the first one is used
        $rt = $roots;
        $rt['ctlogs'] = [$roots['ctlogs'][0], ['valid' => [0, 1]] + $roots['ctlogs'][0]];
        $this->assertNull($sct([$r], $rt));
    }

    // ---------------------------------------------------------------------------------------------- RFC 3161

    /** Rebuild a TimeStampResp after mapping the SignedData members. */
    private static function remapSignedData(string $token, callable $map): string
    {
        [[, $resp]] = self::kidsOf($token);
        $top = self::kidsOf($resp);              // [status, ContentInfo]
        $ci = self::kidsOf($top[1][1]);          // [OID, [0]]
        $sd = self::kidsOf(self::kidsOf($ci[1][1])[0][1]);
        $sdDer = self::der(0x30, self::enc($map($sd)));
        return self::der(0x30, self::enc([$top[0]]) . self::der(0x30, self::enc([$ci[0]]) . self::der(0xa0, $sdDer)));
    }

    public function testGeneralizedTime(): void
    {
        $g = static function (int $tag, string $text): int {
            $b = self::der($tag, $text);
            return self::call('generalizedTime', $b, self::call('tlv', $b, 0));
        };
        $this->assertSame(1735689600000, $g(0x18, '20250101000000Z'));
        $this->assertSame(1735689600500, $g(0x18, '20250101000000.5Z'));
        $this->fails('genTime is not a GeneralizedTime', static fn() => $g(0x17, '20250101000000Z'));
    }

    public function testRfc3161Structure(): void
    {
        $d = self::dsse();
        $tsas = self::roots()['tsas'];
        $this->assertSame(self::GEN_TIME, SigstoreBundle::verifyRfc3161($d['tsa'], $d['sig'], $tsas));
        $this->assertSame($d['tsa'], self::remapSignedData($d['tsa'], static fn(array $sd): array => $sd));

        // the encapsulated content is the first SEQUENCE after the digest algorithms
        $extra = self::remapSignedData($d['tsa'], static fn(array $sd): array => [...array_slice($sd, 0, 3), [0x30, ''], ...array_slice($sd, 3)]);
        $this->assertSame(self::GEN_TIME, SigstoreBundle::verifyRfc3161($extra, $d['sig'], $tsas));

        // a messageImprint without the hashed message
        $noHash = self::remapSignedData($d['tsa'], static function (array $sd): array {
            $encap = self::kidsOf($sd[2][1]);                     // [OID, [0]]
            $tst = self::kidsOf(self::kidsOf(self::kidsOf($encap[1][1])[0][1])[0][1]);
            $tst[2] = [0x30, self::enc([self::kidsOf($tst[2][1])[0]])];
            $sd[2] = [0x30, self::enc([$encap[0]]) . self::der(0xa0, self::der(0x04, self::der(0x30, self::enc($tst))))];
            return $sd;
        });
        $this->fails('messageImprint is not the hash of the signature', static fn() => SigstoreBundle::verifyRfc3161($noHash, $d['sig'], $tsas));

        // a one-byte first member is no PKIStatusInfo: the token is read as a bare ContentInfo
        $this->fails('not an OID', static fn() => SigstoreBundle::verifyRfc3161("\x30\x03\x30\x01\x00", $d['sig'], $tsas));
    }

    public function testRfc3161AuthoritySelection(): void
    {
        $d = self::dsse();
        $roots = self::roots();
        $real = $roots['tsas'][0];
        $v = static fn(array $tsas): int => SigstoreBundle::verifyRfc3161($d['tsa'], $d['sig'], $tsas);
        $this->assertSame(self::GEN_TIME, $v([['chain' => $real['chain'], 'valid' => [0, 1]], $real]));
        $this->assertSame(self::GEN_TIME, $v([$roots['cas'][0], $real]));
        $this->assertSame(self::GEN_TIME, $v([['chain' => [$real['chain'][0]], 'valid' => $real['valid']], $real]));
        $this->fails('no pinned timestamp authority signed it (valid at its time)', static fn() => $v([]));
    }

    // ---------------------------------------------------------------------------------------------- checkpoint

    public function testCheckpointSkipsForeignLines(): void
    {
        $roots = self::roots();
        $d = self::dsse();
        $ip = $d['checkpoint'];
        $this->assertNull(self::call('verifyCheckpoint', $ip->get('checkpoint')->get('envelope'), $roots['tlogs'][0],
            (int)$ip->get('treeSize'), base64_decode($ip->get('rootHash'))));

        $ip = self::fx(self::V2)->get('verificationMaterial')->get('tlogEntries')[0]->get('inclusionProof');
        $env = $ip->get('checkpoint')->get('envelope');
        $root = base64_decode($ip->get('rootHash'));
        $size = (int)$ip->get('treeSize');
        $log = $roots['tlogs'][1];
        $this->assertSame('log2.synthetic.example', $log['v2']);
        $this->assertNull(self::call('verifyCheckpoint', $env, $log, $size, $root));
        $this->assertSame(1, preg_match('/^\x{2014} \S+ (\S+)$/mu', $env, $m));
        $cut = strpos($env, "\n\n");
        $text = substr($env, 0, $cut + 2) . "junk\n\u{2014} log2.synthetic.example AAAAAAAA\n\u{2014} other.example {$m[1]}\n" . substr($env, $cut + 2);
        $this->assertNull(self::call('verifyCheckpoint', $text, $log, $size, $root));
    }

    // ---------------------------------------------------------------------------------------------- R5 review kills

    /** The DSSE fixture bundle (a deep copy) carrying `$der` as its leaf certificate. */
    private static function withLeaf(string $der): Obj
    {
        $b = Json::parseLax(Json::canonicalizeLenient(self::fx(self::DSSE)));
        $b->get('verificationMaterial')->get('certificate')->set('rawBytes', base64_encode($der));
        return $b;
    }

    public function testSanOidBytesInAnotherExtensionAreNoSan(): void
    {
        $r = self::roots();
        $r['cas'] = [['chain' => [new Cert(base64_decode(self::R5_CA))], 'valid' => [0, INF]]];
        // control: the pinned CA issues the plain leaf, so the chain passes and the leaf fails later on its missing EKU
        $this->assertSame(['ok' => false, 'code' => 'cert_eku', 'detail' => 'the certificate lacks the code-signing EKU'],
            SigstoreBundle::verifyCore(self::withLeaf(base64_decode(self::R5_LEAF)), $r));
        // the SAN OID bytes inside another extension's value are no SAN: Node's checkIssued links it, so the chain passes the same way
        $this->assertSame(['ok' => false, 'code' => 'cert_eku', 'detail' => 'the certificate lacks the code-signing EKU'],
            SigstoreBundle::verifyCore(self::withLeaf(base64_decode(self::R5_ODD)), $r));
    }

    public function testTheFirstIssuingCaEndsTheSearch(): void
    {
        $r = self::roots();
        $r['cas'][] = ['chain' => ['not a certificate'], 'valid' => [0, INF]]; // never looked at once a CA issued the leaf
        $this->assertTrue(SigstoreBundle::verifyCore(self::fx(self::DSSE), $r)['ok']);
    }

    public function testOidWithAnEmptyBody(): void
    {
        $this->fails('not an OID', static fn() => self::call('oid', "\x06\x80", [0x06, 0, 2, 2]));
    }

    public function testFulcioExtensionSixIsRawUtf8(): void
    {
        $c = ['exts' => [['oid' => '1.3.6.1.4.1.57264.1.6', 'value' => 'gh']]];
        $this->assertSame('gh', self::call('fulcioExt', $c, 6));
    }

    public function testVerifySigFailsClosedWhenTheBackendThrows(): void
    {
        $ec = (new Cert(self::dsse()['leaf']))->publicKey();
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
        try {
            $this->assertFalse(self::call('verifySig', 'k05-no-such-digest', 'm', $ec, 'sig'));
        } finally {
            restore_error_handler();
        }
    }

    public function testCheckpointBodyLinesAreNotSignatureLines(): void
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x0b", 32));
        $root = str_repeat("\x33", 32);
        // the origin line has the signature-line shape with a non-base64 signature: only the signature block is scanned
        $body = "\u{2014} x abc\n1\n" . base64_encode($root) . "\n";
        $sig = sodium_crypto_sign_detached($body, sodium_crypto_sign_secretkey($kp));
        $text = $body . "\n\u{2014} k05.example " . base64_encode("\x01\x02\x03\x04" . $sig) . "\n";
        $log = ['keyId' => "\x01\x02\x03\x04" . str_repeat("\0", 28), 'key' => sodium_crypto_sign_publickey($kp), 'valid' => [0, INF], 'v2' => 'k05.example'];
        $this->assertNull(self::call('verifyCheckpoint', $text, $log, 1, $root));
    }
}
