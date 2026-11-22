<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attest/Factory.php';

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Attest\Maa;
use Atlas\Pca\Attest\Nvidia;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The strict chain profile (x509-strict.ts strictChainError) at every MAA, GCP and NVIDIA chain site, on chains built here. */
final class K05StrictChainProfileTest extends TestCase
{
    private const LEAF = 'basicConstraints=critical,CA:FALSE';
    private const CA = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign";
    private const CRIT = '1.2.3.4=critical,DER:05:00';

    /**
     * Each string is the v3 extension section of one certificate, leaf first; the last is self-signed. All keys are P-384.
     * @return list<string> PEM, leaf first
     */
    private static function chain(string ...$exts): array
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        $body = "[req]\ndistinguished_name=dn\n[dn]\n";
        foreach ($exts as $i => $e) {
            $body .= "[x$i]\n$e\n";
        }
        file_put_contents($cnf, $body);
        try {
            $pems = [];
            $parent = null;
            $parentKey = null;
            for ($i = count($exts) - 1; $i >= 0; $i--) {
                $opt = ['config' => $cnf, 'digest_alg' => 'sha384', 'x509_extensions' => "x$i"];
                $key = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'secp384r1']);
                self::assertNotFalse($key, 'EC keygen: ' . openssl_error_string());
                $csr = openssl_csr_new(['commonName' => "k05 cert $i"], $key, $opt);
                $x = openssl_csr_sign($csr, $parent, $parentKey ?? $key, 2, $opt, 1000 + $i);
                self::assertNotFalse($x, (string)openssl_error_string());
                openssl_x509_export($x, $pem);
                array_unshift($pems, $pem);
                [$parent, $parentKey] = [$x, $key];
            }
            return $pems;
        } finally {
            unlink($cnf);
        }
    }

    private static function b64(string $pem): string
    {
        return preg_replace('/-----[A-Z ]+-----|\s+/', '', $pem);
    }

    private static function spki(string $pem): string
    {
        return Common::spkiSha(Cert::fromPem($pem)->publicKey(), 'sha256');
    }

    private static function now(): float
    {
        return time() * 1000.0;
    }

    /** [the extension sections, the expected profile reason or null]. */
    private static function cases(): array
    {
        return [
            'control' => [[self::LEAF, self::CA, self::CA], null],
            'EKU critical is fine' => [[self::LEAF . "\nextendedKeyUsage=critical,serverAuth", self::CA, self::CA], null],
            'leaf CA:TRUE' => [[self::CA, self::CA, self::CA], 'leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)'],
            'issuer CA:FALSE' => [[self::LEAF, self::LEAF, self::CA], 'issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)'],
            'keyUsage without keyCertSign' => [[self::LEAF, "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,digitalSignature", self::CA], 'issuer certificate at depth 1 keyUsage lacks keyCertSign'],
            'pathLen exceeded' => [[self::LEAF, self::CA, "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign"], 'issuer certificate at depth 2 pathLenConstraint 0 is exceeded (1 intermediate(s) below)'],
            'unknown critical on the leaf' => [[self::LEAF . "\n" . self::CRIT, self::CA, self::CA], 'certificate at depth 0 has an unrecognised critical extension 1.2.3.4'],
            'unknown critical on the intermediate' => [[self::LEAF, self::CA . "\n" . self::CRIT, self::CA], 'certificate at depth 1 has an unrecognised critical extension 1.2.3.4'],
        ];
    }

    public function testMaaInChainAnchor(): void
    {
        foreach (self::cases() as $name => [$exts, $why]) {
            $c = self::chain(...$exts);
            $r = Maa::verifyX5cChain(array_map([self::class, 'b64'], $c), Obj::of(['rootSpkiSha256' => [self::spki($c[2])]]), self::now());
            $this->assertSame($why === null ? null : "x5c chain profile: $why", $r['ok'] ? null : $r['reason'], $name);
        }
    }

    public function testMaaProfilesOnlyUpToTheAnchor(): void
    {
        // a pin on the intermediate: a bad certificate above the anchor is not read
        $c = self::chain(self::LEAF, self::CA, "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign");
        $r = Maa::verifyX5cChain(array_map([self::class, 'b64'], $c), Obj::of(['rootSpkiSha256' => [self::spki($c[1])]]), self::now());
        $this->assertTrue($r['ok']);
    }

    public function testMaaExternalRoot(): void
    {
        $c = self::chain(self::LEAF, self::CA, self::CA);
        $this->assertTrue(Maa::verifyX5cChain([self::b64($c[0]), self::b64($c[1])], Obj::of(['rootCertsPem' => [$c[2]]]), self::now())['ok']);
        $bad = self::chain(self::LEAF, self::LEAF, self::CA);
        $this->assertSame('x5c chain profile: issuer certificate at depth 1 is not a CA (BasicConstraints CA:FALSE)',
            Maa::verifyX5cChain([self::b64($bad[0]), self::b64($bad[1])], Obj::of(['rootCertsPem' => [$bad[2]]]), self::now())['reason']);
        $other = self::chain(self::CA);
        $this->assertSame('x5c chain does not anchor in a configured MAA trust root',
            Maa::verifyX5cChain([self::b64($bad[0]), self::b64($bad[1])], Obj::of(['rootCertsPem' => [$other[0]]]), self::now())['reason']);
    }

    public function testGcpProfileRunsBeforeThePins(): void
    {
        foreach (self::cases() as $name => [$exts, $why]) {
            $c = self::chain(...$exts);
            $this->assertSame($why === null ? null : "x5c chain profile: $why", Gcp::verifyJwkX5cChain(array_map([self::class, 'b64'], $c),
                Obj::of(['trustedKeySpki' => [self::spki($c[0])]]), self::now(), 0.0), $name);
        }
    }

    public function testNvidiaDeviceChain(): void
    {
        foreach (self::cases() as $name => [$exts, $why]) {
            $c = self::chain(...$exts);
            $r = Nvidia::verifyDeviceChain(implode('', $c), [Cert::fromPem($c[2])->spkiSha256()], self::now());
            // an issuer X509_check_ca refuses (CA:FALSE, or keyUsage without keyCertSign) is refused earlier, by the link walk (as attest-nvidia-spdm.ts `issuer.ca`)
            $notCa = in_array($name, ['issuer CA:FALSE', 'keyUsage without keyCertSign'], true);
            $want = $why === null ? null : ($notCa ? 'device chain cert #1 issues a certificate but is not a CA' : "device chain profile: $why");
            $this->assertSame($want, $r['ok'] ? null : $r['reason'], $name);
        }
    }

    public function testAnEmptyFirmwarePolicyIsAPolicy(): void
    {
        $compile = new \ReflectionMethod(Nvidia::class, 'compileFirmwarePolicy');
        $ids = ['driverVersion' => 'not a version', 'vbiosVersion' => '96.00'];
        $this->assertNull($compile->invoke(null, null)($ids));
        $this->assertSame("driver version 'not a version' in the GPU report is not parseable", $compile->invoke(null, new Obj())($ids));
        // an empty JSON ARRAY is truthy and not an object: refused at construction, like the reference
        try {
            $compile->invoke(null, []);
            $this->fail('accepted an array policy');
        } catch (\Atlas\Pca\Attest\AttestConstructError $e) {
            $this->assertSame('nvidiaCollateralHook: firmware must be an object', $e->getMessage());
        }
    }
}
