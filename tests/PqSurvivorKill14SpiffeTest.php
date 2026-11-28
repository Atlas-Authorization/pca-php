<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Bytes;
use Atlas\Pca\Jose;
use Atlas\Pca\JoseError;
use Atlas\Pca\Obj;
use Atlas\Pca\OidcCodedError;
use Atlas\Pca\Pca;
use Atlas\Pca\Spiffe;
use Atlas\Pca\SpiffeError;
use PHPUnit\Framework\TestCase;

/**
 * SPIFFE gates beyond the reference corpora: exact refusal reasons for the corpus refusals, hand-built DER for the certificate
 * facts reader, an Ed25519 chain (root, intermediate, leaf, plus look-alike / expired / path-limited / critical-extension
 * variants) for the chain walk, JWT-SVID option gates, holder binding, joseCode, admission evidence and both caches.
 * Fixtures were made once with the openssl CLI (no AKID/SKID, so issuer matching is by name); validity is 2026-01-01..2036-01-01
 * except REXP (to 2026-02-01) and LSHORT (to 2027-01-01). The default clocks are driven through Spiffe::$clockHook.
 */
final class PqSurvivorKill14SpiffeTest extends TestCase
{
    private const TD = 'example.org';
    private const ID = 'spiffe://example.org/workload/db';
    private const NOW = 1_795_000_000_000;

    private const R = 'MIHvMIGioAMCAQICAQEwBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDARyb290MCowBQYDK2VwAyEALjsAlI2GnUspvAopMGXl/uILDCHnmHeLDg0N1SbwGcWjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBADqDoN6c4TmEO92/3K2ExTBrs0yhI8f24jNBMY3bKP1M5BVQGajytSUqJOcQN60Q0o7qscuEXEv97bver2HgAwM=';
    private const REXP = 'MIHvMIGioAMCAQICAQIwBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMjYwMjAxMDAwMDAwWjAPMQ0wCwYDVQQDDARyb290MCowBQYDK2VwAyEALjsAlI2GnUspvAopMGXl/uILDCHnmHeLDg0N1SbwGcWjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBAJ0GtpeLKgAuQ2sCgi/kpA8MQ7VfMn3risPNIP8ElRS52lluisTlt9c6T7oxlBSfcsqDL9ZnDLssD4esJWIdcQQ=';
    private const R0 = 'MIHyMIGloAMCAQICAQMwBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDARyb290MCowBQYDK2VwAyEALjsAlI2GnUspvAopMGXl/uILDCHnmHeLDg0N1SbwGcWjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBAO4M9q3P6cjLQuN2UJXX3mSRny+tUZcnUDTxCpkfvBZVCrXxxYEQ+0X1JpbE/qp3LJnDr66mRp/VRThvBkQbSwA=';
    private const R1 = 'MIHyMIGloAMCAQICAQQwBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDARyb290MCowBQYDK2VwAyEALjsAlI2GnUspvAopMGXl/uILDCHnmHeLDg0N1SbwGcWjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBAKeTSQllfcQ/Be5TVW6TAzI26U2NC1wBCaAIbhFp7dAsOsFf+H6lDb/udXuHDX5vrPnDad2IAILw+x6bw3rPngw=';
    private const RFAKE = 'MIHvMIGioAMCAQICAQYwBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAPMQ0wCwYDVQQDDARyb290MCowBQYDK2VwAyEAHuvP4Mht89DI016FUJ+YnTAUcSGcAj5p9X70cnP9q1GjIzAhMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMAUGAytlcANBAJY13MLsvek+OnoB+o3DcrdpqjRnG1CgHXwffLIeK7l/mUK8CN73KVLY28ocRbNQctATqaachlOpc9ze7lXeLQI=';
    private const I = 'MIHwMIGjoAMCAQICAQowBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDDAVpbnRlcjAqMAUGAytlcAMhAKETHsNOIwHUqORK8R1toE6Bc4z220jP1VFf4xMA5rSYoyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQC1NEoIQDPYGYKIYPwWGCDjpqSEiTWTyhexrNZI6uBflxlN6hyj9SIKrJfPIsinSHSD6zEWHm/qTN4LioO/SPAA';
    private const IFAKE = 'MIHwMIGjoAMCAQICAQswBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDDAVpbnRlcjAqMAUGAytlcAMhAB7rz+DIbfPQyNNehVCfmJ0wFHEhnAI+afV+9HJz/atRoyMwITAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAFBgMrZXADQQDj8aJO2ZuwYrkH+eE7dDaxPVWZ0GAEEYArDFAZs9/E8Nu85IhISqA1gwHWRs4Lomk7hC9JZp5MU73Cr6FtuY8P';
    private const ICRIT = 'MIH+MIGxoAMCAQICAQwwBQYDK2VwMA8xDTALBgNVBAMMBHJvb3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAQMQ4wDAYDVQQDDAVpbnRlcjAqMAUGAytlcAMhAKETHsNOIwHUqORK8R1toE6Bc4z220jP1VFf4xMA5rSYozEwLzAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAMBgMqAwQBAf8EAgUAMAUGAytlcANBAPb+/fpDf8C/ieHwPjCc+mkdzxfZdGVlBgEMcZackj/XZU+9Ekk/JufiX987NDk+Mo7vXqwmqgQg6yzAP8NSmgU=';
    private const L = 'MIIBGjCBzaADAgECAgEFMAUGAytlcDAQMQ4wDAYDVQQDDAVpbnRlcjAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMA8xDTALBgNVBAMMBGxlYWYwKjAFBgMrZXADIQAsJlHJg6onYsrTxZvjnA0tTufeDoDfWz8GJak3Po0gVaNNMEswDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0RBCQwIoYgc3BpZmZlOi8vZXhhbXBsZS5vcmcvd29ya2xvYWQvZGIwBQYDK2VwA0EAv4RGKTsRJoFi27kPGsb8x+0HasjvtXcuijya57Uk0BjcSfegDUbuj/kv0sS5xdPHGis0dgzFIZkks8/x5PL1Aw==';
    private const LSHORT = 'MIIBGjCBzaADAgECAgEUMAUGAytlcDAQMQ4wDAYDVQQDDAVpbnRlcjAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAwMDBaMA8xDTALBgNVBAMMBGxlYWYwKjAFBgMrZXADIQAsJlHJg6onYsrTxZvjnA0tTufeDoDfWz8GJak3Po0gVaNNMEswDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0RBCQwIoYgc3BpZmZlOi8vZXhhbXBsZS5vcmcvd29ya2xvYWQvZGIwBQYDK2VwA0EAYmgOyn72MJobR2TtLu7wEUZaIDmlLmMWrZxOuTpaXyrq4QDin+M8mmmzmkj0aMgx8vsTsMWiIpYDicjAlXN2Ag==';
    private const L448 = 'MIIBMzCB5qADAgECAgEVMAUGAytlcDAQMQ4wDAYDVQQDDAVpbnRlcjAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMA8xDTALBgNVBAMMBGxlYWYwQzAFBgMrZXEDOgC+wBMim9CJBaOzHf50UoTbyhZKnHJ9Eb9uRWRA+m6/fbv+/wdkYa2R0+V86/udV2eibc9pg3XgaoCjTTBLMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMCsGA1UdEQQkMCKGIHNwaWZmZTovL2V4YW1wbGUub3JnL3dvcmtsb2FkL2RiMAUGAytlcANBAIIX6SAtZiz/z+WNbnRfRt/h/fZYUZb6QsiDKyN2BbqA4H8YNkASHjoik1VKAq79LZlhTtQQpIastz6Ql3YKxwU=';
    private const LX = 'MIIBGjCBzaADAgECAgEWMAUGAytlcDAQMQ4wDAYDVQQDDAVpbnRlcjAeFw0yNjAxMDEwMDAwMDBaFw0zNjAxMDEwMDAwMDBaMA8xDTALBgNVBAMMBGxlYWYwKjAFBgMrZW4DIQByAIXbwFuzfsxTV1pKCC46X1nb0bvg7VcyR5I4ohL+W6NNMEswDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwKwYDVR0RBCQwIoYgc3BpZmZlOi8vZXhhbXBsZS5vcmcvd29ya2xvYWQvZGIwBQYDK2VwA0EAY6NqROu4ZNW2VV7Tnd/sYSIn5W7V/8ZVPuUZL0Kg6O+S3TULJAFvmzRmTzvqvBwODmaRX7D5w1BcjDu+prmXCg==';

    protected function tearDown(): void
    {
        Spiffe::$clockHook = null;
    }

    private static function pem(string $b64): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($b64, 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    private static function der(string $b64): string
    {
        return (string)base64_decode($b64);
    }

    /** verifyX509Svid over a list of PEM fixtures with the trust bundle `$roots` at NOW (plus `$extra` options). */
    private static function x509(array $chain, array $roots = [self::R], array $extra = []): object
    {
        return Spiffe::verifyX509Svid(array_map(self::pem(...), $chain), $extra + ['trustDomain' => self::TD, 'roots' => array_map(self::pem(...), $roots), 'nowMs' => self::NOW]);
    }

    private function refuses(string $class, string $code, string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame([$class, $code, $msg], [get_class($e), $e instanceof SpiffeError ? $e->codeName : '', $e->getMessage()]);
            return;
        }
        self::fail("no refusal, want $msg");
    }

    private static function leafRaw(): string
    {
        return substr((new Cert(self::der(self::L)))->spkiDer, 12);
    }

    // ---- the reference corpora, reasons compared exactly ---------------------------------------------------------------

    private static function ref(string $m, mixed ...$a): mixed
    {
        $f = \Closure::bind(static fn(string $m, array $a): mixed => RefSpiffeDifferentialTest::$m(...$a), null, RefSpiffeDifferentialTest::class);
        return $f($m, $a);
    }

    private static function maps(): array
    {
        $ids = fn(array $a) => Spiffe::parseSpiffeId($a[0]);
        $x509 = fn(array $a) => Spiffe::parseX509Svid(self::ref('rev', $a[0]));
        return [
            'ref-spiffe-svid.json.gz' => [
                'parseSpiffeId' => $ids,
                'parseX509Svid' => $x509,
                'verifyX509Svid' => fn(array $a) => self::ref('verifyX509', $a[0], $a[1]),
                'verifyJwtSvid' => fn(array $a) => self::ref('verifyJwt', $a[0], $a[1]),
                'svidToHolderX509' => fn(array $a) => Spiffe::svidToHolder(self::ref('x509Verified', $a[0], $a[1]), self::ref('rev', $a[2]), $a[3] ?? []),
                'svidToHolderJwt' => fn(array $a) => Spiffe::svidToHolder(self::ref('jwtVerified', $a[0], $a[1]), self::ref('rev', $a[2]), $a[3] ?? []),
                'svidToHolderUnverified' => fn(array $a) => self::ref('unverified', $a[0], $a[1]),
                'spiffeIdForHolder' => fn(array $a) => Spiffe::spiffeIdForHolder(self::ref('x509Verified', $a[0], $a[1]), $a[2], $a[3] ?? []),
                'workloadDischargePin' => fn(array $a) => Spiffe::workloadDischargePin($a[0], self::ref('x509Verified', $a[1], $a[2])),
                'holderToSpiffeId' => fn(array $a) => Spiffe::holderToSpiffeId($a[0]),
            ],
            'ref-spiffe.json.gz' => [
                'parseSpiffeId' => $ids,
                'holderToSpiffeId' => fn(array $a) => Spiffe::holderToSpiffeId($a[0]),
                'readCertFacts' => fn(array $a) => Spiffe::readCertFacts((string)base64_decode(strtr((string)$a[0], '-_', '+/'))),
                'parseX509Svid' => $x509,
                'verifyX509Svid' => fn(array $a) => self::ref('tsErr', fn() => self::ref('sessX509', $a[0], $a[1])),
                'jwtSession' => fn(array $a) => self::ref('tsErr', fn() => self::ref('sessJwt', $a[0])),
                'holderSession' => fn(array $a) => self::ref('tsErr', fn() => self::ref('holderSession', $a[0])),
                'revocationSession' => fn(array $a) => self::ref('tsErr', fn() => self::ref('cacheSession', 'revocation', $a[0])),
                'bundleSession' => fn(array $a) => self::ref('tsErr', fn() => self::ref('cacheSession', 'bundle', $a[0])),
            ],
        ];
    }

    /** Every corpus refusal this package words itself (SPIFFE codes and the DER reader) carries the reference's exact reason. */
    public function testCorpusRefusalsCarryTheExactReason(): void
    {
        $bad = [];
        $n = 0;
        foreach (self::maps() as $file => $map) {
            foreach (Base::datasets($file) as [$f, $fn, $k]) {
                if (!isset($map[$fn])) {
                    continue;
                }
                foreach (Base::cases($f, $fn, $k) as $c) {
                    $want = $c->get('out');
                    $w = $want instanceof Obj ? $want->get('$throws') : null;
                    $code = $want instanceof Obj ? $want->get('code') : null;
                    if (!is_string($w) || Base::isEngineCrash($w) || preg_match('/[^\x20-\x7e]|\'undefined\'|non-canonical compact JWS/', $w) === 1) {
                        continue;
                    }
                    $prefix = in_array($fn, ['parseX509Svid'], true) && str_starts_with($w, 'cannot parse certificate: ');
                    if ($fn !== 'readCertFacts' && !$prefix && (!is_string($code) || $code === 'jose' || str_starts_with($code, 'ERR_') || str_starts_with($w, 'cannot parse certificate: '))) {
                        continue;
                    }
                    try {
                        ($map[$fn])($c->get('args') ?? []);
                        continue; // a missing refusal is the differential test's finding
                    } catch (\Throwable $e) {
                        $m = $e->getMessage();
                    }
                    $n++;
                    $ok = $prefix ? str_starts_with($m, 'cannot parse certificate: ') && strlen($m) > 26 : $m === $w;
                    if (!$ok) {
                        $bad[] = $c->get('name') . ": want '$w' have '$m'";
                    }
                }
            }
        }
        self::assertSame([], array_slice($bad, 0, 20), count($bad) . ' reason mismatches');
        self::assertGreaterThan(1000, $n);
    }

    // ---- DER facts --------------------------------------------------------------------------------------------------------

    /** Each malformed DER shape is refused with its own RangeError reason. */
    public function testDerReaderRefusesEachMalformedShape(): void
    {
        foreach ([
            '30' => 'der: truncated header',
            '1f00' => 'der: high-tag-number form is not supported',
            '3080' => 'der: unsupported length form',
            '30850000000000' => 'der: unsupported length form',
            '308400000000' => 'der: missing tbsCertificate',
            '3081' => 'der: truncated length',
            '308100' => 'der: missing tbsCertificate',
            '3005' => 'der: content exceeds container',
            '3100' => 'der: certificate is not a single SEQUENCE',
            '300000' => 'der: certificate is not a single SEQUENCE',
            '3000' => 'der: missing tbsCertificate',
            '30020200' => 'der: missing tbsCertificate',
            '30043002a300' => 'der: malformed extensions',
            '300b3009020101a30430023000' => 'der: malformed extension',
            '30233021020101a31c301a300b0603551d0f040403020080300b0603551d0f040403020080' => 'der: duplicate extension',
            '30123010020101a30b300930070603551d0f0500' => 'der: malformed extension value',
            '30153013020101a30e300c300a0603551d0f0403030100' => 'der: malformed keyUsage',
        ] as $hex => $msg) {
            try {
                Spiffe::readCertFacts((string)hex2bin((string)$hex));
                self::fail("$hex: accepted");
            } catch (\RangeException $e) {
                self::assertSame($msg, $e->getMessage(), (string)$hex);
            }
        }
    }

    /** A multi-byte pathLen is read big-endian (258), and keyUsage bit 0x01 alone sets none of the three flags. */
    public function testDerReaderDecodesPathLenAndKeyUsageBits(): void
    {
        $bc = Spiffe::readCertFacts((string)hex2bin('301b3019020101a314301230100603551d13040930070101ff02020102'));
        self::assertSame([true, true, 258], [$bc->get('basicConstraintsPresent'), $bc->get('isCa'), $bc->get('pathLen')]);
        $ku = Spiffe::readCertFacts((string)hex2bin('30163014020101a30f300d300b0603551d0f040403020001'));
        self::assertSame([true, false, false, false], [$ku->get('keyUsagePresent'), $ku->get('digitalSignature'), $ku->get('keyCertSign'), $ku->get('crlSign')]);
    }

    /** An empty cA BOOLEAN at the very end of the DER is read as not-a-CA without reading past the buffer. */
    public function testDerReaderEmptyBooleanAtTheEndIsNotCa(): void
    {
        $f = Spiffe::readCertFacts((string)hex2bin('30163014020101a30f300d300b0603551d13040430020100'));
        self::assertSame([true, false], [$f->get('basicConstraintsPresent'), $f->get('isCa')]);
    }

    /** Only the first [3] field of the tbsCertificate holds the extensions; a later malformed one is never read. */
    public function testDerReaderUsesTheFirstExtensionsField(): void
    {
        $f = Spiffe::readCertFacts((string)hex2bin('30083006a3023000a300'));
        self::assertSame([false, [], []], [$f->get('keyUsagePresent'), $f->get('uriSans'), $f->get('unknownCritical')]);
    }

    /** The fixtures' facts: a leaf with one URI SAN, a CA intermediate, and one with an unknown critical extension. */
    public function testFixtureFacts(): void
    {
        $l = Spiffe::readCertFacts(self::der(self::L));
        self::assertSame([[self::ID], false, true], [$l->get('uriSans'), $l->get('isCa'), $l->get('digitalSignature')]);
        self::assertSame(['2a0304'], Spiffe::readCertFacts(self::der(self::ICRIT))->get('unknownCritical'));
        self::assertSame(0, Spiffe::readCertFacts(self::der(self::R0))->get('pathLen'));
    }

    // ---- serial and fingerprint ---------------------------------------------------------------------------------------------

    private static function withSerial(string $byte): Cert
    {
        $der = self::der(self::L);
        self::assertSame(1, substr_count($der, "\xa0\x03\x02\x01\x02\x02\x01\x05"));
        return new Cert(str_replace("\xa0\x03\x02\x01\x02\x02\x01\x05", "\xa0\x03\x02\x01\x02\x02\x01" . $byte, $der));
    }

    /** serialNumber is Node's form: whole-byte uppercase hex, "0" for zero, a "-" and the magnitude when negative. */
    public function testSerialNumberNodeForm(): void
    {
        self::assertSame('05', Spiffe::serialNumber(new Cert(self::der(self::L))));
        self::assertSame('0', Spiffe::serialNumber(self::withSerial("\x00")));
        self::assertSame('-7B', Spiffe::serialNumber(self::withSerial("\x85")));
        self::assertSame('-01', Spiffe::serialNumber(self::withSerial("\xff")));
    }

    /** fingerprint256 is colon-separated uppercase sha-256 of the DER. */
    public function testFingerprint256(): void
    {
        $der = self::der(self::L);
        self::assertSame(implode(':', str_split(strtoupper(hash('sha256', $der)), 2)), Spiffe::fingerprint256(new Cert($der)));
    }

    // ---- the X.509 chain walk -----------------------------------------------------------------------------------------------

    /** The fixture chain verifies; the leaf in the bundle beside the real root does not make a two-certificate chain self-anchored. */
    public function testChainVerifies(): void
    {
        self::assertSame(self::ID, self::x509([self::L, self::I])->spiffeId->get('id'));
        self::assertSame(self::ID, self::x509([self::L, self::I], [self::L, self::R])->spiffeId->get('id'));
        self::assertSame(self::ID, self::x509([self::L, self::I], [self::R1])->spiffeId->get('id'));
    }

    /** The bundle authority must be in its validity window, and the first matching authority is the one used. */
    public function testBundleAuthorityValidity(): void
    {
        $this->refuses(SpiffeError::class, 'chain_expired', 'the trust bundle authority is not within its validity period', fn() => self::x509([self::L, self::I], [self::REXP]));
        self::assertSame(self::ID, self::x509([self::L, self::I], [self::R, self::REXP])->spiffeId->get('id'));
    }

    /** A bundle authority with the right name but another key is not a signer. */
    public function testLookAlikeAuthorityIsNotASigner(): void
    {
        $this->refuses(SpiffeError::class, 'chain_untrusted_root', 'the chain does not lead to an authority in the trust bundle', fn() => self::x509([self::L, self::I], [self::RFAKE]));
    }

    /** A look-alike intermediate (right name, other key, itself issued by the root) breaks the chain signature. */
    public function testLookAlikeIntermediateBreaksTheChain(): void
    {
        $this->refuses(SpiffeError::class, 'chain_signature', 'certificate #0 is not signed by certificate #1', fn() => self::x509([self::L, self::IFAKE]));
    }

    /** A bundle authority with pathLen 0 cannot sit above an intermediate. */
    public function testBundleAuthorityPathLen(): void
    {
        $this->refuses(SpiffeError::class, 'chain_path_len', 'trust bundle authority pathLenConstraint exceeded', fn() => self::x509([self::L, self::I], [self::R0]));
    }

    /** An intermediate with an unknown critical extension is refused with its label and the OID. */
    public function testSignerUnknownCriticalExtension(): void
    {
        $this->refuses(SpiffeError::class, 'unsupported_critical_extension', 'signing certificate #1 has an unsupported critical extension (2a0304)', fn() => self::x509([self::L, self::ICRIT]));
    }

    /** A chain given as a non-list array is refused. */
    public function testChainMustBeAList(): void
    {
        $this->refuses(\TypeError::class, '', 'chain.flatMap is not a function', fn() => Spiffe::verifyX509Svid(['a' => self::pem(self::L), 'b' => self::pem(self::I)], ['trustDomain' => self::TD, 'roots' => [self::pem(self::R)], 'nowMs' => self::NOW]));
    }

    /** The default chain limit is 8: eight certificates pass the length check, nine do not. */
    public function testDefaultMaxChainLength(): void
    {
        $this->refuses(SpiffeError::class, 'chain_not_ca', 'signing certificate #1 must have the CA flag set to true', fn() => self::x509(array_fill(0, 8, self::L)));
        $this->refuses(SpiffeError::class, 'chain_too_long', 'certificate chain is too long', fn() => self::x509(array_fill(0, 9, self::L)));
    }

    /** maxChainLength given as true counts as 1 and as the string "1" counts as 1. */
    public function testMaxChainLengthCoercions(): void
    {
        $this->refuses(SpiffeError::class, 'chain_too_long', 'certificate chain is too long', fn() => self::x509([self::L, self::I], [self::R], ['maxChainLength' => true]));
        $this->refuses(SpiffeError::class, 'chain_too_long', 'certificate chain is too long', fn() => self::x509([self::L, self::I], [self::R], ['maxChainLength' => '1']));
    }

    /** A numeric-string nowMs is used as the clock, not the wall clock (in 2020 the chain is not yet valid; at NOW it is). */
    public function testStringNowMs(): void
    {
        Spiffe::$clockHook = static fn(): float => self::NOW / 1000;
        $this->refuses(SpiffeError::class, 'chain_expired', 'a certificate in the chain is not within its validity period', fn() => self::x509([self::L, self::I], [self::R], ['nowMs' => '1590969600000']));
        self::assertSame(self::ID, self::x509([self::L, self::I], [self::R], ['nowMs' => (string)self::NOW])->spiffeId->get('id'));
    }

    private static function x509At(float $sec, string $leaf): object
    {
        Spiffe::$clockHook = static fn(): float => $sec;
        return Spiffe::verifyX509Svid([self::pem($leaf), self::pem(self::I)], ['trustDomain' => self::TD, 'roots' => [self::pem(self::R)]]);
    }

    /** Without nowMs the clock is floor(seconds * 1000): 0.4 ms and 0.6 ms past the leaf's notAfter second are still inside it. */
    public function testDefaultClockFloorsMilliseconds(): void
    {
        self::assertSame(self::ID, self::x509At(1798761600.0004, self::LSHORT)->spiffeId->get('id'));
        self::assertSame(self::ID, self::x509At(1798761600.0006, self::LSHORT)->spiffeId->get('id'));
        $this->refuses(SpiffeError::class, 'chain_expired', 'a certificate in the chain is not within its validity period', fn() => self::x509At(1798761601.0, self::LSHORT));
    }

    /** Without nowMs the clock is seconds * 1000 exactly: at the chain's notBefore second it is valid. */
    public function testDefaultClockScale(): void
    {
        self::assertSame(self::ID, self::x509At(1767225600.0, self::L)->spiffeId->get('id'));
    }

    /** The cache-backed revocation check refuses the listed leaf serial end to end. */
    public function testRevocationSourceX509CheckRefusesTheLeaf(): void
    {
        $src = Spiffe::createRevocationSource(['fetch' => fn() => ['serials' => ['5']], 'refreshMs' => 1000, 'maxStaleMs' => 1000, 'now' => fn() => 5.0]);
        $src->refresh();
        $this->refuses(SpiffeError::class, 'svid_revoked', 'X.509-SVID for ' . self::ID . ' is revoked', fn() => self::x509([self::L, self::I], [self::R], ['revocation' => $src->x509Check()]));
        self::assertTrue(($src->jwtCheck())(['spiffeId' => 'z', 'tokenHash' => 't', 'jti' => 'j']) === false);
    }

    // ---- JWT-SVID option gates ------------------------------------------------------------------------------------------

    private static function jwt(mixed $token, array $o): object
    {
        return Spiffe::verifyJwtSvid($token, $o + ['trustDomain' => self::TD, 'audience' => 'api', 'nowMs' => self::NOW]);
    }

    /** A missing audience is the reference's TypeError text. */
    public function testJwtAudienceMustBeAList(): void
    {
        $this->refuses(\TypeError::class, '', "Cannot read properties of null (reading 'length')", fn() => Spiffe::verifyJwtSvid('a.b.c', ['trustDomain' => self::TD]));
    }

    /** The algorithm list gates: not a list, a non-string, none / HS* (also through Unicode upper-casing) and the empty list. */
    public function testJwtAlgorithmGates(): void
    {
        $this->refuses(\TypeError::class, '', 'algorithms.find is not a function', fn() => self::jwt('a.b.c', ['algorithms' => 'RS256']));
        $this->refuses(\TypeError::class, '', 'a.toUpperCase is not a function', fn() => self::jwt('a.b.c', ['algorithms' => [5]]));
        $this->refuses(SpiffeError::class, 'forbidden_algorithm', 'JWT-SVIDs must not use none', fn() => self::jwt('a.b.c', ['algorithms' => ['none', 5]]));
        $this->refuses(SpiffeError::class, 'forbidden_algorithm', 'JWT-SVIDs must not use HS256', fn() => self::jwt('a.b.c', ['algorithms' => ['HS256', 5]]));
        $this->refuses(SpiffeError::class, 'forbidden_algorithm', "JWT-SVIDs must not use h\u{17F}256", fn() => self::jwt('a.b.c', ['algorithms' => ["h\u{17F}256"]]));
        $this->refuses(SpiffeError::class, 'forbidden_algorithm', 'JWT-SVIDs must not use an empty algorithm list', fn() => self::jwt('a.b.c', ['algorithms' => []]));
    }

    /** nowMs is checked only when given: absent, the token's shape is the refusal; non-numeric, the clock is. */
    public function testJwtNowMsGate(): void
    {
        $this->refuses(SpiffeError::class, 'malformed_token', 'non-canonical compact JWS: bad-segment-count (2 != 3)', fn() => Spiffe::verifyJwtSvid('a.b', ['trustDomain' => self::TD, 'audience' => 'api']));
        $this->refuses(SpiffeError::class, 'malformed_token', 'verifyJwtSvid: currentDate must be a valid Date', fn() => self::jwt('a.b', ['nowMs' => 'x']));
    }

    private static function edToken(): array
    {
        $seed = hash('sha256', 'atlas-pca-conformance/spiffe14/jwt', true);
        $pub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $tok = Jose::signJwt(Obj::of(['sub' => self::ID, 'aud' => 'api', 'exp' => 4102444800]), Obj::of(['alg' => 'EdDSA']), $seed);
        return [$tok, $pub];
    }

    /** A raw Ed25519 key may be passed as Bytes or as an OKP JWK array. */
    public function testJwtKeyForms(): void
    {
        [$tok, $pub] = self::edToken();
        self::assertSame(self::ID, self::jwt($tok, ['key' => new Bytes($pub), 'algorithms' => ['EdDSA']])->spiffeId->get('id'));
        self::assertSame(self::ID, self::jwt($tok, ['key' => ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u($pub)], 'algorithms' => ['EdDSA']])->spiffeId->get('id'));
    }

    // ---- holder binding -------------------------------------------------------------------------------------------------

    /** An X25519 SVID key (44-byte SPKI, other OID) is not an Ed25519 holder. */
    public function testX25519KeyIsNotAHolder(): void
    {
        $svid = self::x509([self::LX, self::I]);
        $this->refuses(SpiffeError::class, 'invalid_holder_key', 'the X.509-SVID key is not Ed25519, so the holder cannot be derived from it: pass holderKey and opts.proof', fn() => Spiffe::svidToHolder($svid));
    }

    /** An SVID key with no supported proof scheme (Ed448) never accepts a proof. */
    public function testUnsupportedKeyProofFails(): void
    {
        $svid = self::x509([self::L448, self::I]);
        $this->refuses(SpiffeError::class, 'holder_binding_failed', 'opts.proof does not verify under the X.509-SVID key', fn() => Spiffe::svidToHolder($svid, Pca::b64u(str_repeat("\x01", 32)), ['proof' => Pca::b64u(str_repeat("\x02", 114))]));
    }

    /** spiffeIdForHolder compares the normalized holder with the leaf holder as given. */
    public function testSpiffeIdForHolderComparesTheGivenHolder(): void
    {
        $svid = self::x509([self::L, self::I]);
        self::assertSame(self::ID, Spiffe::spiffeIdForHolder($svid, Pca::b64u(self::leafRaw())));
        $this->refuses(SpiffeError::class, 'holder_binding_failed', 'the SVID is not bound to the PCActn leaf holder', fn() => Spiffe::spiffeIdForHolder($svid, new Bytes(self::leafRaw())));
    }

    // ---- joseCode ---------------------------------------------------------------------------------------------------------

    /** joseCode maps each failure text to the JOSE library's code, and non-JOSE errors to their kind. */
    public function testJoseCode(): void
    {
        self::assertSame('X_CODE', Spiffe::joseCode(new OidcCodedError('X_CODE', 'm')));
        self::assertSame('Error', Spiffe::joseCode(new \RuntimeException('signature verification failed')));
        self::assertSame('TypeError', Spiffe::joseCode(new \TypeError('m')));
        foreach ([
            'signature verification failed' => 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
            '"exp" claim timestamp check failed' => 'ERR_JWT_EXPIRED',
            'unexpected "aud" claim value' => 'ERR_JWT_CLAIM_VALIDATION_FAILED',
            'JWT Claims Set must be a top-level JSON object' => 'ERR_JWT_INVALID',
            'JWTs MUST NOT use unencoded payload' => 'ERR_JWT_INVALID',
            '"alg" (Algorithm) Header Parameter value not allowed' => 'ERR_JOSE_ALG_NOT_ALLOWED',
            'Unsupported "alg" value for a JSON Web Signature Algorithm' => 'ERR_JOSE_NOT_SUPPORTED',
            'Extension Header Parameter "x" is not recognized' => 'ERR_JOSE_NOT_SUPPORTED',
            'unsupported key type' => 'ERR_JOSE_NOT_SUPPORTED',
            'no applicable key found in the JSON Web Key Set' => 'ERR_JWKS_NO_MATCHING_KEY',
            'multiple matching keys found in the JSON Web Key Set' => 'ERR_JWKS_MULTIPLE_MATCHING_KEYS',
            'Invalid key for this operation' => 'TypeError',
            'invalid Ed25519 public key' => 'TypeError',
            'not a JSON Web Key' => 'TypeError',
            'Invalid Compact JWS' => 'ERR_JWS_INVALID',
            'JWS Protected Header is invalid' => 'ERR_JWS_INVALID',
        ] as $m => $code) {
            self::assertSame($code, Spiffe::joseCode(new JoseError((string)$m)), (string)$m);
        }
    }

    // ---- admission evidence -----------------------------------------------------------------------------------------------

    private static function evidence(mixed $verify, mixed $key): Obj
    {
        $e = ['kind' => 'x509', 'chain' => self::pem(self::L) . self::pem(self::I)];
        if ($verify !== null) {
            $e['verify'] = $verify;
        }
        return Spiffe::spiffeAdmissionEvidence($e, $key);
    }

    /** Admission takes verify options as an Obj, binds the SVID key, and reports refusals by code. */
    public function testAdmissionEvidence(): void
    {
        $verify = Obj::of(['trustDomain' => self::TD, 'roots' => [self::pem(self::R)], 'nowMs' => self::NOW]);
        $ok = self::evidence($verify, Pca::b64u(self::leafRaw()));
        self::assertSame([true, true, self::ID], [$ok->get('ok'), $ok->get('bound'), $ok->get('identity')->get('spiffe_id')]);
        $other = self::evidence($verify, new Bytes(self::leafRaw()));
        self::assertSame(['ok', 'bound', 'reason'], $other->keys());
        self::assertSame([false, false, 'SVID is bound to a different key'], [$other->get('ok'), $other->get('bound'), $other->get('reason')]);
        $none = self::evidence(null, Pca::b64u(self::leafRaw()));
        self::assertSame([false, false, 'chain_trust_domain_mismatch'], [$none->get('ok'), $none->get('bound'), $none->get('reason')]);
        $jwt = Spiffe::spiffeAdmissionEvidence(['kind' => 'jwt', 'token' => 'a.b.c', 'verify' => ['trustDomain' => self::TD]], 'k');
        self::assertSame([false, false, 'TypeError'], [$jwt->get('ok'), $jwt->get('bound'), $jwt->get('reason')]);
    }

    // ---- caches -------------------------------------------------------------------------------------------------------------

    /** The cache constructors refuse a missing fetch and a non-finite maxStaleMs. */
    public function testCacheOptionGates(): void
    {
        $this->refuses(SpiffeError::class, 'trust_bundle_unavailable', 'createTrustBundleSource requires `fetch`', fn() => Spiffe::createTrustBundleSource(['refreshMs' => 1000, 'maxStaleMs' => 1000]));
        $this->refuses(SpiffeError::class, 'revocation_unavailable', 'refreshMs must be > 0 and maxStaleMs >= refreshMs (both finite)', fn() => Spiffe::createRevocationSource(['fetch' => fn() => [], 'refreshMs' => 1000, 'maxStaleMs' => INF]));
    }

    /** The trust-bundle cache's default clock is floor(seconds * 1000): 999.6 ms later is not due, 1000.4 ms later is. */
    public function testTrustBundleDefaultClock(): void
    {
        $fetches = 0;
        $src = Spiffe::createTrustBundleSource(['fetch' => function () use (&$fetches) {
            $fetches++;
            return ['x509Authorities' => [self::pem(self::R)]];
        }, 'refreshMs' => 1000, 'maxStaleMs' => 1e9]);
        foreach ([[1000.0, 1], [1000.9996, 1], [1001.0004, 2]] as [$t, $want]) {
            Spiffe::$clockHook = static fn(): float => $t;
            $src->x509Roots();
            self::assertSame($want, $fetches, "at $t");
        }
    }

    private static function bundle(mixed $b, mixed $now = null): \Atlas\Pca\TrustBundleSource
    {
        return Spiffe::createTrustBundleSource(['fetch' => fn() => $b, 'refreshMs' => 1000, 'maxStaleMs' => 1000, 'now' => $now ?? fn() => 7.0]);
    }

    /** Usable bundles: an Obj, an object-shaped array, a numeric-string clock; x509 roots come back as a list. */
    public function testTrustBundleUsableShapes(): void
    {
        $pem = self::pem(self::R);
        self::assertSame([$pem], self::bundle(Obj::of(['x509Authorities' => [$pem]]))->x509Roots());
        self::assertSame([$pem], self::bundle(['x509Authorities' => [$pem]], fn() => '1000')->x509Roots());
        self::assertSame([$pem], self::bundle(['jwks' => ['keys' => [['kty' => 'OKP']]], 'x509Authorities' => ['a' => $pem]])->x509Roots());
    }

    /** Unusable bundles are refused with the fetch-time reason. */
    public function testTrustBundleUnusableShapes(): void
    {
        foreach ([5, ['jwks' => ['keys' => 'x']], ['jwks' => ['keys' => ['a' => 1]]]] as $b) {
            $this->refuses(SpiffeError::class, 'trust_bundle_invalid', 'fetched trust bundle has no authorities', fn() => self::bundle($b)->x509Roots());
        }
        $this->refuses(SpiffeError::class, 'trust_bundle_unavailable', "trust bundle fetch failed: Cannot read properties of null (reading 'keys')", fn() => self::bundle(['jwks' => null, 'x509Authorities' => [self::pem(self::R)]])->x509Roots());
    }

    private static function revocation(mixed $fetch, mixed $now = null): \Atlas\Pca\RevocationSource
    {
        return Spiffe::createRevocationSource(['fetch' => $fetch, 'refreshMs' => 1000, 'maxStaleMs' => 1000, 'now' => $now ?? fn() => 7.0]);
    }

    /** Revocation snapshots: an Obj or object-shaped array is a list; a list, [] or a scalar is not; a fetch failure sticks. */
    public function testRevocationSnapshotShapes(): void
    {
        $o = self::revocation(fn() => Obj::of(['serials' => ['05']]));
        $o->refresh();
        self::assertTrue($o->x509(['fingerprint256' => '00', 'serialNumber' => '5', 'spiffeId' => 'z']));
        $a = self::revocation(fn() => ['spiffeIds' => ['spiffe://x/y']], fn() => '7');
        $a->refresh();
        self::assertTrue($a->x509(['fingerprint256' => '00', 'serialNumber' => '1', 'spiffeId' => 'spiffe://x/y']));
        foreach ([[], ['x'], 5] as $raw) {
            $this->refuses(SpiffeError::class, 'revocation_unavailable', 'revocation list must be an object', fn() => self::revocation(fn() => $raw)->refresh());
        }
        $down = self::revocation(fn() => throw new \RuntimeException('down'));
        $this->refuses(SpiffeError::class, 'revocation_unavailable', 'revocation fetch failed: down', fn() => $down->refresh());
        $this->refuses(SpiffeError::class, 'revocation_unavailable', 'revocation fetch failed: down', fn() => $down->x509(['fingerprint256' => '00', 'serialNumber' => '1', 'spiffeId' => 'z']));
    }

    /** Fingerprints are compared after Unicode upper-casing; a non-string fingerprint is the reference's TypeError. */
    public function testRevocationFingerprintNormalization(): void
    {
        $s = self::revocation(fn() => ['fingerprints' => ["ab:\u{E9}"]]);
        $s->refresh();
        self::assertTrue($s->x509(['fingerprint256' => "AB:\u{C9}", 'serialNumber' => '1', 'spiffeId' => 'z']));
        $this->refuses(\TypeError::class, '', 's.replace is not a function', fn() => $s->x509(['fingerprint256' => 5, 'serialNumber' => '1', 'spiffeId' => 'z']));
    }
}
