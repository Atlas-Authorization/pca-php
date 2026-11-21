<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Intel;
use Atlas\Pca\Attest\Ocsp;
use PHPUnit\Framework\TestCase;

/** The guarded verify calls of the Intel and OCSP verifiers: whatever they throw is a failed verification, never an exception or a pass. */
final class K05AttestFaultSeamsTest extends TestCase
{
    protected function tearDown(): void
    {
        Intel::$faultHook = null;
        Ocsp::$faultHook = null;
    }

    private static function key(): \OpenSSLAsymmetricKey
    {
        $cnf = tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        $k = openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        unlink($cnf);
        return $k;
    }

    private static function pub(\OpenSSLAsymmetricKey $k): \Atlas\Pca\Attest\PubKey
    {
        $pem = openssl_pkey_get_details($k)['key'];
        return Common::loadPublicKey(base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s/', '', $pem)));
    }

    private static function priv(string $class, string $method, mixed ...$args): mixed
    {
        return (new \ReflectionMethod($class, $method))->invoke(null, ...$args);
    }

    public function testOcspSignatureCheckFailsClosedOnAThrow(): void
    {
        $k = self::key();
        $pub = self::pub($k);
        openssl_sign('msg', $sig, $k, OPENSSL_ALGO_SHA256);
        $this->assertTrue(self::priv(Ocsp::class, 'verifySig', '1.2.840.10045.4.3.2', 'msg', $sig, $pub));
        $stages = [];
        Ocsp::$faultHook = static function (string $stage) use (&$stages): void {
            $stages[] = $stage;
            throw new \RuntimeException('boom');
        };
        $this->assertFalse(self::priv(Ocsp::class, 'verifySig', '1.2.840.10045.4.3.2', 'msg', $sig, $pub));
        $this->assertSame(['verify_sig'], $stages);
    }

    public function testIntelP256CheckFailsClosedOnAThrow(): void
    {
        $k = self::key();
        $pub = self::pub($k);
        openssl_sign('msg', $sig, $k, OPENSSL_ALGO_SHA256);
        $o = (ord($sig[1]) & 0x80) !== 0 ? 2 + (ord($sig[1]) & 0x7F) : 2;
        $lr = ord($sig[$o + 1]);
        $r = substr($sig, $o + 2, $lr);
        $o2 = $o + 2 + $lr;
        $s = substr($sig, $o2 + 2, ord($sig[$o2 + 1]));
        $raw = str_pad(ltrim($r, "\0"), 32, "\0", STR_PAD_LEFT) . str_pad(ltrim($s, "\0"), 32, "\0", STR_PAD_LEFT);
        $this->assertTrue(self::priv(Intel::class, 'verifyP256', 'msg', $raw, $pub));
        $stages = [];
        Intel::$faultHook = static function (string $stage) use (&$stages): void {
            $stages[] = $stage;
            throw new \RuntimeException('boom');
        };
        $this->assertFalse(self::priv(Intel::class, 'verifyP256', 'msg', $raw, $pub));
        $this->assertSame(['verify_p256'], $stages);
    }

    public function testIntelTdReportParseFailureIsARefusalWithItsReason(): void
    {
        $this->assertSame(
            ['ok' => false, 'reason' => 'TD report parse failed: parseDcapTdReport: body too short (3 < 584)'],
            self::priv(Intel::class, 'tdReportOrRefusal', 'abc'),
        );
        $r = self::priv(Intel::class, 'tdReportOrRefusal', str_repeat("\x07", 584));
        $this->assertArrayNotHasKey('ok', $r);
        $this->assertSame(str_repeat("\x07", 16), $r['teeTcbSvn']);
    }
}
