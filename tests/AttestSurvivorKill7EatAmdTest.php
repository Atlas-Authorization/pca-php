<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AttestEat;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for AttestEat.php (group 7) that need a genuine SEV-SNP chain: the allowDebug switch of verifyAmdAttestation and the
 * expected-measurement defaulting of verifyFreshAttestedEat. The VCEK -> ASK -> ARK chain and the signed report are built here with
 * P-384 keys generated at load (the same construction as BaseKillAttestAmd1Test).
 */
final class AttestSurvivorKill7EatAmdTest extends TestCase
{
    private const NOW_S = 1893456000; // 2030-01-01T00:00:00Z
    private const TCB = "\x04\x02\x00\x00\x00\x00\x03\xC8"; // bootloader 4, tee 2, snp 3, microcode 200
    private const BC = "\x30\x03\x01\x01\xFF";

    // ---------------------------------------------------------------------------------------------------------------- builders

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

    private static function spki(string $name): string
    {
        return (string)base64_decode((string)preg_replace('/-----[A-Z ]+-----|\s+/', '', openssl_pkey_get_details(self::key($name))['key']));
    }

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    private static function oidBytes(string $dotted): string
    {
        $a = array_map('intval', explode('.', $dotted));
        $out = chr($a[0] * 40 + $a[1]);
        foreach (array_slice($a, 2) as $v) {
            $b = chr($v & 0x7F);
            for ($v >>= 7; $v > 0; $v >>= 7) {
                $b = chr(0x80 | ($v & 0x7F)) . $b;
            }
            $out .= $b;
        }
        return $out;
    }

    private static function ext(string $oid, string $value, bool $critical = false): string
    {
        return self::tlv(0x30, self::tlv(0x06, self::oidBytes($oid)), $critical ? "\x01\x01\xFF" : '', self::tlv(0x04, $value));
    }

    private static function dn(string $cn): string
    {
        return self::tlv(0x30, self::tlv(0x31, self::tlv(0x30, self::tlv(0x06, "\x55\x04\x03"), self::tlv(0x0C, $cn))));
    }

    private static function utc(string $text): string
    {
        return self::tlv(0x17, $text);
    }

    private static function splInt(int $n): string
    {
        return $n < 128 ? "\x02\x01" . chr($n) : "\x02\x02\x00" . chr($n);
    }

    /** @return list<string> */
    private static function vcekExts(): array
    {
        return [
            self::ext('1.3.6.1.4.1.3704.1.4', str_repeat("\x11", 64)),
            self::ext('1.3.6.1.4.1.3704.1.3.1', self::splInt(4)),
            self::ext('1.3.6.1.4.1.3704.1.3.2', self::splInt(2)),
            self::ext('1.3.6.1.4.1.3704.1.3.3', self::splInt(3)),
            self::ext('1.3.6.1.4.1.3704.1.3.8', self::splInt(200)),
        ];
    }

    /** @param list<string> $exts */
    private static function cert(string $iss, string $sub, string $subjectKey, string $signer, array $exts): string
    {
        $alg = self::tlv(0x30, self::tlv(0x06, "\x2A\x86\x48\xCE\x3D\x04\x03\x03"));
        $val = self::tlv(0x30, self::utc('200101000000Z'), self::utc('400101000000Z'));
        $e = $exts === [] ? [] : [self::tlv(0xA3, self::tlv(0x30, ...$exts))];
        $tbs = self::tlv(0x30, self::tlv(0xA0, self::tlv(0x02, "\x02")), self::tlv(0x02, "\x01"), $alg, $iss, $val, $sub, self::spki($subjectKey), ...$e);
        openssl_sign($tbs, $sig, self::key($signer), OPENSSL_ALGO_SHA384);
        return self::tlv(0x30, $tbs, $alg, self::tlv(0x03, "\0" . $sig));
    }

    /** @return array{0:string,1:string,2:string,3:string} [vcekDer, askDer, arkDer, arkSpkiSha384] */
    private static function world(): array
    {
        $bc = [self::ext('2.5.29.19', self::BC, true)];
        $ark = self::cert(self::dn('ARK'), self::dn('ARK'), 'ark', 'ark', $bc);
        $ask = self::cert(self::dn('ARK'), self::dn('ASK'), 'ask', 'ark', $bc);
        $vcek = self::cert(self::dn('ASK'), self::dn('VCEK'), 'vcek', 'ask', self::vcekExts());
        return [$vcek, $ask, $ark, hash('sha384', self::spki('ark'))];
    }

    private static function report(int $policy = 0x30000): string
    {
        $put = static function (string $r, int $off, string $v): string {
            return substr_replace($r, $v, $off, strlen($v));
        };
        $r = str_repeat("\0", 0x4A0);
        $r = $put($r, 0, pack('V', 2));
        $r = $put($r, 4, pack('V', 7));
        $r = $put($r, 8, pack('P', $policy));
        $r = $put($r, 0x34, pack('V', 1));
        $r = $put($r, 0x50, str_repeat("\x07", 64));
        $r = $put($r, 0x90, str_repeat("\xAB", 48));
        $r = $put($r, 0xC0, str_repeat("\xCD", 32));
        $r = $put($r, 0x180, self::TCB);
        $r = $put($r, 0x1A0, str_repeat("\x11", 64));
        $r = $put($r, 0x1E0, pack('P', 5));
        $r = $put($r, 0x1F0, pack('P', 6));
        openssl_sign(substr($r, 0, 0x2A0), $der, self::key('vcek'), OPENSSL_ALGO_SHA384);
        $p = 2;
        $lr = ord($der[$p + 1]);
        $rr = substr($der, $p + 2, $lr);
        $p += 2 + $lr;
        $ls = ord($der[$p + 1]);
        $ss = substr($der, $p + 2, $ls);
        $r = $put($r, 0x2A0, str_pad(strrev(ltrim($rr, "\0")), 72, "\0"));
        return $put($r, 0x2E8, str_pad(strrev(ltrim($ss, "\0")), 72, "\0"));
    }

    private static function amdOpts(array $extra = []): Obj
    {
        [$vcek, $ask, $ark, $pin] = self::world();
        return Obj::of($extra + ['trustAnchorArkSpkiSha384' => $pin, 'vcek' => $vcek, 'ask' => $ask, 'ark' => $ark, 'nowMs' => self::NOW_S * 1000]);
    }

    // ---------------------------------------------------------------------------------------------------------------- verifyAmdAttestation

    /** A genuine report verifies end to end (control), with its evidence and measured identity. */
    public function testGenuineReportVerifies(): void
    {
        $r = AttestEat::verifyAmdAttestation(self::report(), self::amdOpts());
        $this->assertTrue($r->get('ok'), (string)$r->get('reason'));
        $this->assertSame(AttestEat::AMD_SEV_SNP_HARDWARE_ROOT_LABEL, $r->get('hardwareRoot'));
        $this->assertSame(str_repeat('ab', 48), $r->get('evidence')->get('measurement'));
        $this->assertFalse($r->get('evidence')->get('debug'));
        $this->assertSame(str_repeat('ab', 48), $r->get('measured')->get('runtime_measurement'));
    }

    /** A guest with the DEBUG policy bit is refused unless allowDebug is exactly true. */
    public function testDebugGuestIsRefusedUnlessAllowDebugIsTrue(): void
    {
        $debug = self::report(0x30000 | 0x80000);
        $why = 'guest policy has the DEBUG bit set (host can inspect the guest)';
        $r = AttestEat::verifyAmdAttestation($debug, self::amdOpts());
        $this->assertFalse($r->get('ok'));
        $this->assertSame($why, $r->get('reason'));
        $r = AttestEat::verifyAmdAttestation($debug, self::amdOpts(['allowDebug' => false]));
        $this->assertFalse($r->get('ok'));
        $this->assertSame($why, $r->get('reason'));
        $r = AttestEat::verifyAmdAttestation($debug, self::amdOpts(['allowDebug' => 'yes']));
        $this->assertFalse($r->get('ok'));
        $this->assertSame($why, $r->get('reason'));
        $r = AttestEat::verifyAmdAttestation($debug, self::amdOpts(['allowDebug' => true]));
        $this->assertTrue($r->get('ok'), (string)$r->get('reason'));
        $this->assertTrue($r->get('evidence')->get('debug'));
        $r = AttestEat::verifyAmdAttestation(self::report(), self::amdOpts(['allowDebug' => true]));
        $this->assertTrue($r->get('ok'));
    }

    // ---------------------------------------------------------------------------------------------------------------- verifyFreshAttestedEat + amd

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/kill7-eat-amd', true);
    }

    private static function eat(string $runtimeMeasurement): string
    {
        return AttestEat::buildEat(Obj::of(['issuer' => 'iss-amd', 'nonce' => 'nonce-amd', 'key' => self::seed(), 'now' => self::NOW_S * 1000, 'channelId' => 'chan-1',
            'measured' => Obj::of(['model_id' => 'm', 'weights_digest' => 'w', 'runtime_measurement' => $runtimeMeasurement, 'operator' => 'o'])]));
    }

    private static function fresh(string $runtimeMeasurement, Obj $amdExtra): Obj
    {
        [$vcek, $ask, $ark, $pin] = self::world();
        $amd = Obj::of(['vcek' => $vcek, 'ask' => $ask, 'ark' => $ark, 'rawReport' => self::report(), 'trustAnchorArkSpkiSha384' => $pin]);
        foreach ($amdExtra->keys() as $k) {
            $amd->set($k, $amdExtra->get($k));
        }
        return AttestEat::verifyFreshAttestedEat(self::eat($runtimeMeasurement), Obj::of([
            'verifyKey' => sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed())), 'nonce' => 'nonce-amd', 'now' => self::NOW_S * 1000,
            'channelId' => 'chan-1', 'policy' => Obj::of(['endorsements' => Obj::of(['issuers' => ['iss-amd']])]), 'amd' => $amd]));
    }

    /** With no expectedMeasurement (absent or null) the EAT's own launch measurement is the one the report must carry. */
    public function testTheEatLaunchMeasurementDefaultsTheExpectedMeasurement(): void
    {
        $match = str_repeat('ab', 48);
        $mismatch = str_repeat('ff', 48);
        $r = self::fresh($match, new Obj());
        $this->assertTrue($r->get('ok'), implode(' | ', (array)$r->get('reasons')));
        $this->assertSame('affirming-hw-rooted', $r->get('tier'));
        $r = self::fresh($match, Obj::of(['expectedMeasurement' => null]));
        $this->assertTrue($r->get('ok'));
        $this->assertSame('affirming-hw-rooted', $r->get('tier'));

        foreach ([new Obj(), Obj::of(['expectedMeasurement' => null])] as $amd) {
            $r = self::fresh($mismatch, $amd);
            $this->assertFalse($r->get('ok'));
            $this->assertSame('contraindicated', $r->get('tier'));
            $reasons = $r->get('reasons');
            $this->assertSame('AMD hardware root verification failed: measurement not in policy allowlist', $reasons[count($reasons) - 1]);
        }
        // an explicit expectation wins over the token's own claim
        $r = self::fresh($mismatch, Obj::of(['expectedMeasurement' => $match]));
        $this->assertTrue($r->get('ok'));
        $this->assertSame('affirming-hw-rooted', $r->get('tier'));
        $r = self::fresh($match, Obj::of(['expectedMeasurement' => $mismatch]));
        $this->assertFalse($r->get('ok'));
        $this->assertSame('contraindicated', $r->get('tier'));
    }
}
