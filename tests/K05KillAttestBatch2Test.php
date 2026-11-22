<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Gcp;
use Atlas\Pca\Attest\Nvidia;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for three Attest survivors: Nvidia::checkChainRevocation (`break` after the first verifying CRL issuer), Ocsp delegated
 * responder loop (`continue` after a signature that does not verify) and Gcp::verifyJwkX5cChain (the `(string)` cast on a non-string root).
 * Fixtures are generated at load; the Ocsp world is borrowed from K05KillAttestOcsp1Test through reflection.
 */
final class K05KillAttestBatch2Test extends TestCase
{
    // ---- Nvidia CRL gate

    private static function bTlv(int $tag, string $v): string
    {
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    /** @return array{pem:string,x509:\OpenSSLCertificate,key:\OpenSSLAsymmetricKey} */
    private static function bIssue(string $cn, string $ext, ?array $parent, int $serial): array
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

    /** A CRL (DER, ECDSA-SHA256, empty issuer name) valid now, listing the given serials (raw INTEGER content). @param list<string> $serials */
    private static function bCrl(\OpenSSLAsymmetricKey $key, array $serials): string
    {
        $alg = self::bTlv(0x30, self::bTlv(0x06, "\x2a\x86\x48\xce\x3d\x04\x03\x02"));
        $t = time();
        $entries = '';
        foreach ($serials as $s) {
            $entries .= self::bTlv(0x30, self::bTlv(0x02, $s) . self::bTlv(0x17, gmdate('ymdHis', $t - 60) . 'Z'));
        }
        $tbs = self::bTlv(0x30, $alg . self::bTlv(0x30, '') . self::bTlv(0x17, gmdate('ymdHis', $t - 3600) . 'Z') . self::bTlv(0x17, gmdate('ymdHis', $t + 3600) . 'Z')
            . ($entries === '' ? '' : self::bTlv(0x30, $entries)));
        openssl_sign($tbs, $sig, $key, OPENSSL_ALGO_SHA256);
        return self::bTlv(0x30, $tbs . $alg . self::bTlv(0x03, "\0" . $sig));
    }

    public function testTheFirstVerifyingCrlIssuerDecidesWhichLinkIsChecked(): void
    {
        $root = self::bIssue('NVIDIA B2 Root', "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign", null, 0x3001);
        $inter = self::bIssue('NVIDIA B2 Inter', "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign", $root, 0x3002);
        $leaf = self::bIssue('NVIDIA B2 Device', 'basicConstraints=critical,CA:FALSE', $inter, 0x3003);
        $leafC = Cert::fromPem($leaf['pem']);
        $interC = Cert::fromPem($inter['pem']);
        // chain[1] and chain[2] share one key: both verify the CRL, the first (index 1) is the issuer of chain[0]
        $chain = [$leafC, $interC, $interC];
        $crl = self::bCrl($inter['key'], ["\x30\x03"])   // the leaf's serial 0x3003
        ;
        $this->assertSame(
            ['ok' => false, 'reason' => "chain certificate 'CN=NVIDIA B2 Device' is revoked"],
            Nvidia::checkChainRevocation($chain, [$crl], time() * 1000.0)
        );
    }

    // ---- Ocsp delegated responder

    private static function ocsp(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(K05KillAttestOcsp1Test::class, $name))->invoke(null, ...$args);
    }

    public function testADelegatedCandidateWhoseKeyDoesNotSignIsSkippedForTheNext(): void
    {
        $w = self::ocsp('world');
        $real = self::ocsp('dcert', ['serial' => "\x09"]);
        $wrongKey = self::ocsp('dcert', ['key' => $w['k']['resp2'], 'serial' => "\x0A"]);
        $der = self::ocsp('resp', ['ridCert' => $real, 'signer' => $w['k']['resp'], 'certs' => [$wrongKey->raw, $real->raw]]);
        $this->assertSame(['ok' => true, 'status' => 'good', 'responder' => 'delegated'], self::ocsp('runCase', $der));
    }

    // ---- Gcp roots

    public function testANonStringRootEntryIsSkippedLikeAnyOtherUnusableEntry(): void
    {
        $T = K05KillAttestGcp1Test::key('top');
        $R = K05KillAttestGcp1Test::key('root');
        $chain = [base64_encode(K05KillAttestGcp1Test::cert('root', 'top', $T, $R))];
        $now = (float)K05KillAttestGcp1Test::NOW;
        $rootPem = K05KillAttestGcp1Test::pem(K05KillAttestGcp1Test::cert('root', 'root', $R, $R));
        foreach ([$rootPem, K05KillAttestGcp1Test::spkiPem($R)] as $valid) {
            $this->assertNull(Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [$valid]], $now, 0.0));
            $this->assertNull(Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [5, $valid]], $now, 0.0));
        }
    }

    public function testACandidateNotSignedByTheChainIsSkippedForTheNext(): void
    {
        $w = self::ocsp('world');
        $real = self::ocsp('dcert', ['serial' => "\x09"]);
        // same subject and key as the real responder, but issued under a rogue key: matches the responderID, has the EKU and a valid
        // window, and is refused only by the "signed by the supplied NVIDIA chain" check -- the next candidate must still be tried
        $rogueIssued = self::ocsp('dcert', ['signer' => $w['k']['rogue'], 'serial' => "\x0B"]);
        $der = self::ocsp('resp', ['ridCert' => $real, 'signer' => $w['k']['resp'], 'certs' => [$rogueIssued->raw, $real->raw]]);
        $this->assertSame(['ok' => true, 'status' => 'good', 'responder' => 'delegated'], self::ocsp('runCase', $der));
        $only = self::ocsp('resp', ['ridCert' => $real, 'signer' => $w['k']['resp'], 'certs' => [$rogueIssued->raw]]);
        $this->assertSame(['ok' => false, 'reason' => 'delegated responder certificate is not signed by the supplied NVIDIA chain'], self::ocsp('runCase', $only));
    }

    public function testEveryKindOfNonStringRootEntryIsSkipped(): void
    {
        $T = K05KillAttestGcp1Test::key('top');
        $R = K05KillAttestGcp1Test::key('root');
        $chain = [base64_encode(K05KillAttestGcp1Test::cert('root', 'top', $T, $R))];
        $now = (float)K05KillAttestGcp1Test::NOW;
        $valid = K05KillAttestGcp1Test::pem(K05KillAttestGcp1Test::cert('root', 'root', $R, $R));
        foreach ([null, 5, 1.5, true, false] as $junk) {
            $this->assertNull(Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [$junk, $valid]], $now, 0.0), var_export($junk, true));
            $this->assertSame('x5c chain does not anchor in a configured GCP trust root',
                Gcp::verifyJwkX5cChain($chain, ['rootCertsPem' => [$junk]], $now, 0.0), var_export($junk, true));
        }
    }
}
