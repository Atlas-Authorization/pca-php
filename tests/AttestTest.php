<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\CanonicalJwsError;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\DerError;
use Atlas\Pca\Attest\Factory;
use Atlas\Pca\Attest\JsError;
use Atlas\Pca\Attest\JsJson;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * Hardware attestation: the strict DER readers, the binding, the JavaScript-faithful helpers and the fail-closed tables of the
 * vendor verifiers, each with its exact reason. (The evidence rows of the reference are replayed by VectorsTest.)
 */
final class AttestTest extends TestCase
{
    private static function j(string $t): mixed
    {
        return Json::parseLax($t);
    }

    private function derError(string $der): string
    {
        try {
            Der::readTlv($der, 0);
        } catch (DerError $e) {
            return $e->getMessage();
        }
        return 'no error';
    }

    public function testStrictDerLengthRules(): void
    {
        $this->assertSame('DER: truncated header', $this->derError("\x30"));
        $this->assertSame('DER: multi-byte tags are not supported', $this->derError("\x1F\x01\x00"));
        $this->assertSame('DER: unsupported length form', $this->derError("\x30\x80"));
        $this->assertSame('DER: unsupported length form', $this->derError("\x30\x84\x00\x00\x00\x00"));
        $this->assertSame('DER: truncated length', $this->derError("\x30\x82\x01"));
        $this->assertSame('DER: non-minimal length (leading zero)', $this->derError("\x30\x82\x00\x80" . str_repeat('a', 128)));
        $this->assertSame('DER: non-minimal length (long form below 128)', $this->derError("\x30\x81\x05abcde"));
        $this->assertSame('DER: element overruns its parent', $this->derError("\x30\x05abc"));
        $this->assertSame('no error', $this->derError("\x30\x81\x80" . str_repeat('a', 128)));
        $t = Der::readTlv("\x04\x03abc", 0);
        $this->assertSame([4, 2, 5], [$t->tag, $t->start, $t->end]);
    }

    public function testDerTimeIsStrictRfc5280(): void
    {
        $this->assertSame(1800000000000, Der::parseDerTime(0x17, '270115080000Z'));
        $this->assertSame(0, Der::parseDerTime(0x18, '19700101000000Z'));
        $this->assertSame(1000, Der::parseDerTime(0x17, '700101000001Z'));
        $this->assertSame(Der::parseDerTime(0x18, '19500101000000Z'), Der::parseDerTime(0x17, '500101000000Z')); // 50 -> 1950
        $this->assertNull(Der::parseDerTime(0x18, '20240230000000Z'));  // February 30
        $this->assertNull(Der::parseDerTime(0x18, '20230229000000Z'));  // not a leap year
        $this->assertNotNull(Der::parseDerTime(0x18, '20240229000000Z'));
        $this->assertNull(Der::parseDerTime(0x17, '270115080000+0100')); // an offset
        $this->assertNull(Der::parseDerTime(0x17, '2701150800Z'));      // no seconds
        $this->assertNull(Der::parseDerTime(0x18, '20240101240000Z'));  // hour 24
        $this->assertNull(Der::parseDerTime(0x18, '20241301000000Z'));  // month 13
        $this->assertNull(Der::parseDerTime(0x04, '20240101000000Z'));  // the wrong tag
    }

    public function testTheBindingIsExactAndRefusesAnythingMalformed(): void
    {
        $ok = ['holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 1, 'nonce' => 'n'];
        $this->assertSame(64, strlen(Common::attestationBinding($ok)));
        $this->assertSame(hash('sha512', "atlas-pca/attest-bind/v1\0" . "\0\0\0\1h" . "\0\0\0\1g" . "\0\0\0\0\0\0\0\1" . "\0\0\0\1n", true), Common::attestationBinding($ok));
        $this->assertSame(hash('sha256', Common::attestationBinding($ok), true), Common::challengeSha256($ok));
        foreach ([['holderPub', 'binding: holderPub required'], ['grantRef', 'binding: grantRef required'], ['nonce', 'binding: nonce required']] as [$k, $why]) {
            foreach ([null, ''] as $bad) {
                try {
                    Common::attestationBinding([$k => $bad] + $ok);
                    $this->fail("accepted $k=" . var_export($bad, true));
                } catch (\TypeError $e) {
                    $this->assertSame($why, $e->getMessage());
                }
            }
        }
        foreach ([-1, 1.5, 9007199254740992, '1', null] as $epoch) {
            try {
                Common::attestationBinding(['epoch' => $epoch] + $ok);
                $this->fail('accepted epoch ' . var_export($epoch, true));
            } catch (\TypeError $e) {
                $this->assertSame('binding: epoch must be a non-negative safe integer', $e->getMessage());
            }
        }
    }

    public function testNodeBase64IsLenientAndTheJwsSegmentsAreNot(): void
    {
        $this->assertSame('foobar', Common::nodeB64Decode("Zm9v\nYmFy"));
        $this->assertSame('foo', Common::nodeB64Decode('Zm9v=garbage'));
        $this->assertSame("\xfb\xff", Common::nodeB64Decode('-_8')); // both alphabets
        $this->assertSame('f', Common::decodeCanonicalB64url('Zg'));
        foreach (['Zg==' => 'bad-character', 'Z' => 'non-canonical-base64url (impossible length)', 'Zh' => 'non-canonical-base64url'] as $seg => $why) {
            try {
                Common::decodeCanonicalB64url((string)$seg);
                $this->fail("accepted $seg");
            } catch (CanonicalJwsError $e) {
                $this->assertSame("non-canonical compact JWS: $why", $e->getMessage());
            }
        }
    }

    public function testJsonParseWordingIsV8s(): void
    {
        $cases = [
            '' => 'Unexpected end of JSON input',
            'not json' => "Unexpected token 'o', \"not json\" is not valid JSON",
            'nope' => "Unexpected token 'o', \"nope\" is not valid JSON",
            '{"a":1} x' => 'Unexpected non-whitespace character after JSON at position 8',
            'NaN' => '"NaN" is not valid JSON',
            '{"a":' => 'Unexpected end of JSON input',
        ];
        foreach ($cases as $text => $want) {
            try {
                JsJson::parse((string)$text);
                $this->fail("parsed '$text'");
            } catch (JsError $e) {
                $this->assertSame($want, $e->getMessage(), (string)$text);
            }
        }
        $v = JsJson::parse('{"a":[1,2.5,"x"],"b":{"c":null},"a":3}');
        $this->assertSame('{"a":3,"b":{"c":null}}', Json::canonicalizeLenient($v)); // the last duplicate wins
    }

    public function testConfigurationsThatCouldAcceptEverythingAreRefused(): void
    {
        $bad = [
            ['amd-sev-snp', '{"binding":"report-data","policy":{"measurements":["aa"]}}', "createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'"],
            ['amd-sev-snp', '{"family":"genoa","binding":"x","policy":{"measurements":["aa"]}}', "createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'"],
            ['amd-sev-snp', '{"family":"genoa","binding":"report-data","policy":{"measurements":[]}}', 'createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)'],
            ['amd-sev-snp', '{"family":"genoa","binding":"report-data"}', 'createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)'],
            ['intel-tdx-dcap', '{"binding":"report-data","policy":{}}', 'createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)'],
            ['intel-tdx-dcap', '{"binding":"report-data","policy":{"mrtds":["abcd"]}}', 'createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)'],
            ['azure-maa', '{"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}', 'createAzureMaaVerifier: trustedIssuers must be a NON-EMPTY list of trusted MAA instance URLs'],
            ['azure-maa', '{"trustedIssuers":["https://x"],"policy":{"tdxMrtds":["aa"]}}', 'createAzureMaaVerifier: trustAnchors must configure at least one MAA root (rootCertsPem and/or rootSpkiSha256) — accept-all is not permitted'],
            ['azure-maa', '{"trustedIssuers":["https://x"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{}}', 'createAzureMaaVerifier: policy must set a NON-EMPTY sevSnpMeasurements and/or tdxMrtds allowlist (accept-all is not permitted)'],
            ['gcp-confidential-space', '{"trustedIssuers":["https://x"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":[]}}', 'createGcpConfidentialSpaceVerifier: policy.imageDigests must be a NON-EMPTY allowlist (accept-all is not permitted)'],
            ['nvidia-gpu-spdm', '{"rootSpkiSha256":[],"policy":{"measurements":{"1":"aa"}}}', 'createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)'],
            ['nvidia-gpu-spdm', '{"rootSpkiSha256":["aa"]}', 'createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)'],
            ['no-such-vendor', '{}', 'unknown attestation vendor no-such-vendor'],
        ];
        foreach ($bad as [$vendor, $config, $why]) {
            try {
                Factory::verifierFromConfig($vendor, self::j($config));
                $this->fail("built $vendor from $config");
            } catch (AttestConstructError $e) {
                $this->assertSame($why, $e->getMessage());
            }
        }
    }

    public function testEveryVerifierFailsClosedWithoutEvidenceOrBinding(): void
    {
        $hex96 = str_repeat('ab', 48);
        $configs = [
            'amd-sev-snp' => ['{"family":"genoa","binding":"report-data","policy":{"measurements":["' . $hex96 . '"]}}', 'no AMD SEV-SNP evidence for this action'],
            'intel-tdx-dcap' => ['{"binding":"report-data","policy":{"mrtds":["' . $hex96 . '"]}}', 'no Intel DCAP quote for this action'],
            'azure-maa' => ['{"trustedIssuers":["https://x"],"trustAnchors":{"rootSpkiSha256":["aa"]},"policy":{"tdxMrtds":["aa"]}}', 'no Azure MAA token for this action'],
            'gcp-confidential-space' => ['{"trustedIssuers":["https://x"],"trustAnchors":{"trustedKeySpki":["aa"]},"policy":{"imageDigests":["aa"]}}', 'no GCP Confidential Space token for this action'],
            'nvidia-gpu-spdm' => ['{"rootSpkiSha256":["aa"],"policy":{"measurements":{"1":"aa"}}}', 'no NVIDIA GPU evidence for this action'],
        ];
        foreach ($configs as $vendor => [$config, $why]) {
            $v = Factory::verifierFromConfig($vendor, self::j($config));
            $this->assertSame(['ok' => false, 'reason' => $why], $v->verify(new Obj(), ['holderPub' => 'h', 'grantRef' => 'g', 'epoch' => 0, 'nonce' => 'n'], 1), $vendor);
            $this->assertSame(['ok' => false, 'reason' => $why], $v->verify(null, null, 1), "$vendor with no document");
        }
    }

    public function testTheX509RowsOfTheReaderAreTotal(): void
    {
        $this->assertSame(['ok' => false, 'error' => 'DER: truncated header'], Factory::runX509Vector('read_cert_role_info', self::j('{"cert":""}')));
        $this->assertSame(['ok' => false, 'error' => 'unknown x509 function nope'], Factory::runX509Vector('nope', self::j('{}')));
        $this->assertSame(['ok' => true, 'value' => null], Factory::runX509Vector('parse_der_time', self::j('{"tag":24,"text":"20240230000000Z"}')));
    }

    public function testNvidiaSpdmVersionRule(): void
    {
        $why = static function (int $rq, int $rs): ?string {
            $t = chr($rq) . "\xE0\0\0" . str_repeat("\x07", 32) . "\0" . chr($rs) . "\x60\0\0\0\0\0\0" . str_repeat("\x09", 32) . "\0\0" . str_repeat("\xEE", 96);
            return \Atlas\Pca\Attest\Nvidia::versionReason(\Atlas\Pca\Attest\Nvidia::parseEvidence($t));
        };
        $this->assertNull($why(0x11, 0x11));
        $this->assertNull($why(0x12, 0x12));
        foreach ([[0x10, 0x10, '0x10/0x10'], [0x12, 0x11, '0x12/0x11'], [0x11, 0x12, '0x11/0x12']] as [$rq, $rs, $txt]) {
            $this->assertSame("SPDM version $txt is not an accepted GET_MEASUREMENTS version", $why($rq, $rs));
        }
    }
}
