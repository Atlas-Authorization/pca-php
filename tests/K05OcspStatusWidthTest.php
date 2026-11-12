<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Cert;
use Atlas\Pca\Attest\Ocsp;
use PHPUnit\Framework\TestCase;

/** An ENUMERATED responseStatus wider than 8 bytes must not wrap to 0 (SUCCESSFUL): TS compares the value, which is nonzero. */
final class K05OcspStatusWidthTest extends TestCase
{
    private static function cert(): Cert
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        $cfg = ['config' => $cnf];
        $key = openssl_pkey_new($cfg + ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $csr = openssl_csr_new(['commonName' => 'k05'], $key, $cfg);
        $x = openssl_csr_sign($csr, null, $key, 1, $cfg);
        openssl_x509_export($x, $pem);
        unlink($cnf);
        return Cert::fromPem($pem);
    }

    public function testResponseStatusIsReadAsAWholeNumber(): void
    {
        $c = self::cert();
        $resp = static fn(string $enum): string => "\x30" . chr(strlen($enum) + 2) . "\x0A" . chr(strlen($enum)) . $enum;
        $now = 1.0e12;
        $r = Ocsp::verifyResponse($resp("\x02"), $c, $c, [$c], $now);
        $this->assertSame(['ok' => false, 'reason' => 'OCSP responseStatus is 2 (not successful)'], $r);
        $r = Ocsp::verifyResponse($resp("\x01" . str_repeat("\x00", 8)), $c, $c, [$c], $now);
        $this->assertFalse($r['ok']);
        $this->assertStringStartsWith('OCSP responseStatus is ', $r['reason']);
        $this->assertStringEndsWith(' (not successful)', $r['reason']);
        $r = Ocsp::verifyResponse($resp("\x00"), $c, $c, [$c], $now);
        $this->assertSame('successful response carries no responseBytes', $r['reason']);
    }
}
