<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\AttestConstructError;
use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Nvidia;
use PHPUnit\Framework\TestCase;

/**
 * NVIDIA CRL coverage (PCA 0.5): by default every non-root chain certificate that names a CRL distribution point needs a
 * verified CRL from its issuer; before, any one fresh CRL (for example the root's alone) satisfied the check.
 * Chain: leaf (index 0) <- ica (1) <- root (2); the leaf and the ica carry a cRLDistributionPoints extension unless a test says not.
 */
final class K05NvidiaCrlCoverageTest extends TestCase
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

    /** @return array{0: list<Cert>, 1: array<string,mixed>} the chain (leaf, ica, root) and the raw issued material */
    private static function chain(bool $leafCdp = true, bool $icaCdp = true): array
    {
        $root = self::issue('NVIDIA Cov Root', self::CA, null, 0x4001);
        $ica = self::issue('NVIDIA Cov Ica', self::CA . ($icaCdp ? self::CDP : ''), $root, 0x4002);
        $leaf = self::issue('NVIDIA Cov Device', 'basicConstraints=critical,CA:FALSE' . ($leafCdp ? self::CDP : ''), $ica, 0x4003);
        return [[Cert::fromPem($leaf['pem']), Cert::fromPem($ica['pem']), Cert::fromPem($root['pem'])], ['root' => $root, 'ica' => $ica, 'leaf' => $leaf]];
    }

    /** A fresh CRL signed by `$key` listing `$serials` (DER INTEGER content bytes). */
    private static function crl(\OpenSSLAsymmetricKey $key, array $serials = []): string
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

    private static function now(): float
    {
        return time() * 1000.0;
    }

    private const LEAF_MISSING = "no verified CRL from the issuer of chain certificate 'CN=NVIDIA Cov Device'";
    private const ICA_MISSING = "no verified CRL from the issuer of chain certificate 'CN=NVIDIA Cov Ica'";

    public function testARootCrlAloneNoLongerCoversALeafThatNamesACdp(): void
    {
        [$c, $m] = self::chain();
        $r = Nvidia::checkChainRevocation($c, [self::crl($m['root']['key'])], self::now());
        $this->assertSame(['ok' => false, 'reason' => self::LEAF_MISSING], $r);
    }

    public function testTheIcaCrlAndTheRootCrlTogetherCoverTheChain(): void
    {
        [$c, $m] = self::chain();
        $this->assertSame(['ok' => true, 'verifiedCrls' => 2],
            Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key']), self::crl($m['root']['key'])], self::now()));
    }

    public function testAnIcaCrlAloneLeavesTheIcaUncovered(): void
    {
        [$c, $m] = self::chain();
        $this->assertSame(['ok' => false, 'reason' => self::ICA_MISSING],
            Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key'])], self::now()));
    }

    public function testARevokedLeafOnTheIcaCrlStillFailsAsRevoked(): void
    {
        [$c, $m] = self::chain();
        $r = Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key'], ["\x40\x03"]), self::crl($m['root']['key'])], self::now());
        $this->assertSame(['ok' => false, 'reason' => "chain certificate 'CN=NVIDIA Cov Device' is revoked"], $r);
    }

    public function testAllDemandsACrlForACertificateWithoutACdpWhereCdpDoesNot(): void
    {
        [$c, $m] = self::chain(false, true); // the leaf names no CDP, the ica does
        $root = [self::crl($m['root']['key'])];
        $this->assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($c, $root, self::now(), null, 'cdp'), 'only the ica names a CDP and the root CRL covers it');
        $this->assertSame(['ok' => false, 'reason' => self::LEAF_MISSING], Nvidia::checkChainRevocation($c, $root, self::now(), null, 'all'));
        $this->assertSame(['ok' => true, 'verifiedCrls' => 2],
            Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key']), self::crl($m['root']['key'])], self::now(), null, 'all'));
    }

    public function testTheDefaultIsCdp(): void
    {
        [$c, $m] = self::chain(false, false);
        $this->assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($c, [self::crl($m['root']['key'])], self::now()));
        [$c2, $m2] = self::chain();
        $this->assertFalse(Nvidia::checkChainRevocation($c2, [self::crl($m2['root']['key'])], self::now())['ok']);
    }

    public function testAnIndexListDemandsExactlyThoseCertificates(): void
    {
        [$c, $m] = self::chain(false, false);
        $root = [self::crl($m['root']['key'])];
        $this->assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($c, $root, self::now(), null, [1]));
        $this->assertSame(['ok' => false, 'reason' => self::LEAF_MISSING], Nvidia::checkChainRevocation($c, $root, self::now(), null, [0]));
        $this->assertSame(['ok' => true, 'verifiedCrls' => 2],
            Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key']), self::crl($m['root']['key'])], self::now(), null, [0, 1]));
    }

    public function testAnOutOfRangeOrNonIntegerIndexFails(): void
    {
        [$c, $m] = self::chain();
        $crls = [self::crl($m['ica']['key']), self::crl($m['root']['key'])];
        foreach ([2, -1, 7, '1', 1.0, null] as $bad) {
            $r = Nvidia::checkChainRevocation($c, $crls, self::now(), null, [$bad]);
            $this->assertFalse($r['ok']);
            $this->assertSame('requireCrlFor index ' . \Atlas\Pca\Attest\Common::jsStr($bad) . ' is not a non-root chain certificate', $r['reason']);
        }
    }

    public function testNoneEnforcesSuppliedCrlsButDemandsNoCoverage(): void
    {
        [$c, $m] = self::chain();
        $this->assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($c, [self::crl($m['root']['key'])], self::now(), null, 'none'));
        $r = Nvidia::checkChainRevocation($c, [self::crl($m['root']['key'], ["\x40\x02"])], self::now(), null, 'none');
        $this->assertSame(['ok' => false, 'reason' => "chain certificate 'CN=NVIDIA Cov Ica' is revoked"], $r);
    }

    public function testAnUnknownPolicyValueFails(): void
    {
        [$c, $m] = self::chain();
        $r = Nvidia::checkChainRevocation($c, [self::crl($m['root']['key'])], self::now(), null, 'most');
        $this->assertSame(['ok' => false, 'reason' => 'requireCrlFor must be cdp, all, none or a list of chain indices'], $r);
    }

    public function testTheCollateralHookValidatesTheOptionAtConstruction(): void
    {
        $base = ['rimRootSpkiSha256' => [str_repeat('a', 64)]];
        $resolve = static fn(array $ids, mixed $evidence): ?array => null;
        foreach ([null, 'cdp', 'all', [], [0, 1]] as $ok) {
            $this->assertInstanceOf(\Closure::class, Nvidia::collateralHook($base + ($ok === null ? [] : ['requireCrlFor' => $ok]), $resolve));
        }
        foreach (['none', 'x', 5, true, ['0'], [1.5], ['a' => 1], [null]] as $bad) {
            try {
                Nvidia::collateralHook($base + ['requireCrlFor' => $bad], $resolve);
                $this->fail('accepted ' . json_encode($bad));
            } catch (AttestConstructError $e) {
                $this->assertSame("nvidiaCollateralHook: malformed requireCrlFor '" . \Atlas\Pca\Attest\Common::jsStr($bad) . "'", $e->getMessage());
            }
        }
    }

    public function testACertificateWhoseExtensionsCannotBeParsedRequiresACrl(): void
    {
        [$c, $m] = self::chain(false, false);
        $this->assertFalse($c[0]->extensionsMalformed());
        $p = new \ReflectionProperty(Cert::class, 'extsFailed');
        $p->setValue($c[0], true); // what a Cert holds after Der::parseTbsExtensions threw
        $this->assertTrue($c[0]->extensionsMalformed());
        $root = [self::crl($m['root']['key'])];
        $this->assertSame(['ok' => false, 'reason' => self::LEAF_MISSING], Nvidia::checkChainRevocation($c, $root, self::now(), null, 'cdp'));
        $this->assertSame(['ok' => true, 'verifiedCrls' => 2],
            Nvidia::checkChainRevocation($c, [self::crl($m['ica']['key']), self::crl($m['root']['key'])], self::now(), null, 'cdp'));
        $this->assertSame(['ok' => true, 'verifiedCrls' => 1], Nvidia::checkChainRevocation($c, $root, self::now(), null, 'none'));
    }

    // ---- through the full collateral hook

    private static function nv(string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(K05KillAttestNvidia1Test::class, $method))->invoke(null, ...$args);
    }

    /** Runs the whole hook (RIM signature, comparison, revocation) over the chain and the CRLs; null = accepted. */
    private static function hook(array $opts, array $chain, array $crls): ?string
    {
        $driver = self::nv('driverRim');
        $vbios = self::nv('vbiosRim');
        $hook = Nvidia::collateralHook(['rimRootSpkiSha256' => [self::nv('rimPki')['pin']]] + $opts,
            static fn(array $ids, mixed $ev): array => ['driverRimXml' => $driver, 'vbiosRimXml' => $vbios, 'crls' => $crls]);
        $ctx = self::nv('hctx', ['opaque' => self::nv('opq'), 'measurements' => [['index' => 1, 'digest' => "\xaa"]]]);
        $ctx['chain'] = $chain;
        return $hook($ctx);
    }

    public function testTheHookDemandsCoverageByDefaultAndNotWhenCrlsAreNotRequired(): void
    {
        [$c, $m] = self::chain();
        $root = [self::crl($m['root']['key'])];
        $full = [self::crl($m['ica']['key']), self::crl($m['root']['key'])];
        $this->assertNull(self::hook([], $c, $full), 'a fully covered chain is accepted');
        $why = 'revocation: ' . self::LEAF_MISSING;
        $this->assertSame($why, self::hook([], $c, $root), 'default (revocation crl)');
        $this->assertSame($why, self::hook(['revocation' => 'both'], $c, $root));
        $this->assertSame($why, self::hook(['requireCrlFor' => 'cdp'], $c, $root));
        // CRLs supplied but not required: enforced, no coverage demand
        $this->assertNull(self::hook(['requireCrls' => false], $c, $root), 'legacy requireCrls:false with a partial CRL set');
        $r = self::hook(['revocation' => 'ocsp'], $c, $root);
        $this->assertStringStartsNotWith('revocation:', (string)$r, 'ocsp-only mode: the partial CRL set passes the CRL stage (only the OCSP stage may speak)');
        $revoked = [self::crl($m['root']['key'], ["\x40\x02"])];
        $this->assertSame("revocation: chain certificate 'CN=NVIDIA Cov Ica' is revoked", self::hook(['requireCrls' => false], $c, $revoked), 'a supplied CRL is still enforced');
    }
}
