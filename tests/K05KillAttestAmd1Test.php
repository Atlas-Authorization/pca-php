<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Amd;
use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\PubKey;
use PHPUnit\Framework\TestCase;

/**
 * Kill tests for Attest/Amd.php (SEV-SNP). Expectations follow packages/pca/src/hardware-sevsnp.ts and attest-amd-snp.ts. The VCEK -> ASK -> ARK
 * chain and the signed report are built here with P-384 keys generated at load.
 */
final class K05KillAttestAmd1Test extends TestCase
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
            $keys[$name] = $name === 'rsa'
                ? openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA])
                : openssl_pkey_new(['config' => $cnf, 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $name === 'p256' ? 'prime256v1' : 'secp384r1']);
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
    private static function vcekExts(string $chip = ''): array
    {
        return [
            self::ext('1.3.6.1.4.1.3704.1.4', $chip === '' ? str_repeat("\x11", 64) : $chip),
            self::ext('1.3.6.1.4.1.3704.1.3.1', self::splInt(4)),
            self::ext('1.3.6.1.4.1.3704.1.3.2', self::splInt(2)),
            self::ext('1.3.6.1.4.1.3704.1.3.3', self::splInt(3)),
            self::ext('1.3.6.1.4.1.3704.1.3.8', self::splInt(200)),
        ];
    }

    /** @param list<string> $exts */
    private static function cert(string $iss, string $sub, string $subjectKey, string $signer, array $exts, ?string $nb = null, ?string $na = null): string
    {
        $alg = self::tlv(0x30, self::tlv(0x06, "\x2A\x86\x48\xCE\x3D\x04\x03\x03"));
        $val = self::tlv(0x30, $nb ?? self::utc('200101000000Z'), $na ?? self::utc('400101000000Z'));
        $e = $exts === [] ? [] : [self::tlv(0xA3, self::tlv(0x30, ...$exts))];
        $tbs = self::tlv(0x30, self::tlv(0xA0, self::tlv(0x02, "\x02")), self::tlv(0x02, "\x01"), $alg, $iss, $val, $sub, self::spki($subjectKey), ...$e);
        openssl_sign($tbs, $sig, self::key($signer), OPENSSL_ALGO_SHA384);
        return self::tlv(0x30, $tbs, $alg, self::tlv(0x03, "\0" . $sig));
    }

    private static function pem(string $der): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----\n";
    }

    /** @param array<string,mixed> $o @return array{0:string,1:string,2:string} [vcekDer, askArkPem, pin] */
    private static function world(array $o = []): array
    {
        $ark = self::cert(self::dn('ARK'), self::dn('ARK'), 'ark', 'ark', $o['arkExts'] ?? [self::ext('2.5.29.19', self::BC, true)]);
        $ask = self::cert(self::dn($o['askIssuer'] ?? 'ARK'), self::dn('ASK'), 'ask', $o['askSigner'] ?? 'ark', $o['askExts'] ?? [self::ext('2.5.29.19', self::BC, true)]);
        $vcek = self::cert(self::dn($o['vcekIssuer'] ?? 'ASK'), self::dn('VCEK'), $o['vcekKey'] ?? 'vcek', $o['vcekSigner'] ?? 'ask', $o['vcekExts'] ?? self::vcekExts(), $o['vcekNb'] ?? null, $o['vcekNa'] ?? null);
        return [$vcek, self::pem($ask) . self::pem($ark), hash('sha384', self::spki('ark'))];
    }

    private static function now(): int
    {
        return self::NOW_S * 1000;
    }

    /** @param array<string,mixed> $o */
    private static function report(array $o = []): string
    {
        $put = static function (string $r, int $off, string $v): string {
            return substr_replace($r, $v, $off, strlen($v));
        };
        $r = str_repeat("\0", 0x4A0);
        $r = $put($r, 0, pack('V', 2));
        $r = $put($r, 4, pack('V', 7));
        $r = $put($r, 8, pack('P', 0x30000));
        $r = $put($r, 0x34, pack('V', 1));
        $r = $put($r, 0x50, $o['report_data'] ?? str_repeat("\x07", 64));
        $r = $put($r, 0x90, str_repeat("\xAB", 48));
        $r = $put($r, 0xC0, str_repeat("\xCD", 32));
        $r = $put($r, 0x180, self::TCB);
        $r = $put($r, 0x1A0, $o['chip'] ?? str_repeat("\x11", 64));
        $r = $put($r, 0x1E0, pack('P', 5));
        $r = $put($r, 0x1F0, pack('P', 6));
        if (!($o['unsigned'] ?? false)) {
            openssl_sign(substr($r, 0, 0x2A0), $der, self::key('vcek'), OPENSSL_ALGO_SHA384);
            $p = 2;
            $lr = ord($der[$p + 1]);
            $rr = substr($der, $p + 2, $lr);
            $p += 2 + $lr;
            $ls = ord($der[$p + 1]);
            $ss = substr($der, $p + 2, $ls);
            $r = $put($r, 0x2A0, str_pad(strrev(ltrim($rr, "\0")), 72, "\0"));
            $r = $put($r, 0x2E8, str_pad(strrev(ltrim($ss, "\0")), 72, "\0"));
        }
        return $r;
    }

    private static function tbs(string ...$exts): string
    {
        return self::tlv(0x30, self::tlv(0xA3, self::tlv(0x30, ...$exts)));
    }

    private static function tcb(): \GMP
    {
        return gmp_init(bin2hex(strrev(self::TCB)), 16);
    }

    private static function le(string $s): \GMP
    {
        $n = gmp_init(0);
        for ($i = strlen($s) - 1; $i >= 0; $i--) {
            $n = $n * 256 + ord($s[$i]);
        }
        return $n;
    }

    // ---------------------------------------------------------------------------------------------------------------- parse

    public function testParseReportIsPublicAndExactOnPatternedBytes(): void
    {
        $b = '';
        for ($i = 0; $i < 0x4A0; $i++) {
            $b .= chr(($i * 7 + 3) % 256);
        }
        $p = Amd::parseReport($b);
        $this->assertSame(['version', 'guest_svn', 'policy', 'vmpl', 'signature_algo', 'current_tcb', 'report_data', 'measurement', 'host_data', 'reported_tcb',
            'chip_id', 'committed_tcb', 'launch_tcb', 'sig_r', 'sig_s', 'signed'], array_keys($p));
        $u32 = static fn(int $o): int => ord($b[$o]) | (ord($b[$o + 1]) << 8) | (ord($b[$o + 2]) << 16) | (ord($b[$o + 3]) << 24);
        $this->assertSame($u32(0), $p['version']);
        $this->assertSame($u32(4), $p['guest_svn']);
        $this->assertSame($u32(0x30), $p['vmpl']);
        $this->assertSame($u32(0x34), $p['signature_algo']);
        foreach (['policy' => 8, 'current_tcb' => 0x38, 'reported_tcb' => 0x180, 'committed_tcb' => 0x1E0, 'launch_tcb' => 0x1F0] as $k => $o) {
            $this->assertSame(gmp_strval(self::le(substr($b, $o, 8))), gmp_strval($p[$k]), $k);
        }
        $this->assertSame(substr($b, 0x50, 64), $p['report_data']);
        $this->assertSame(substr($b, 0x90, 48), $p['measurement']);
        $this->assertSame(substr($b, 0xC0, 32), $p['host_data']);
        $this->assertSame(substr($b, 0x1A0, 64), $p['chip_id']);
        $this->assertSame(substr($b, 0x2A0, 72), $p['sig_r']);
        $this->assertSame(substr($b, 0x2E8, 72), $p['sig_s']);
        $this->assertSame(substr($b, 0, 0x2A0), $p['signed']);
        $this->assertSame(0x2A0, strlen($p['signed']));
    }

    public function testParseReportTooShortBoundary(): void
    {
        $this->assertSame(72, strlen(Amd::parseReport(str_repeat("\1", 816))['sig_s']));
        $this->expectException(\ValueError::class);
        $this->expectExceptionMessage('parseSevSnpReport: report too short (815 < 816)');
        Amd::parseReport(str_repeat("\1", 815));
    }

    // ---------------------------------------------------------------------------------------------------------------- signature

    public function testSignatureWithSEqualToOneIsAccepted(): void
    {
        // Q = dG with d = (k - e) / r, so that (r, s = 1) verifies over sha384(0x5A * 0x2A0): key recovery, no private key needed.
        $qx = 'e470304cfb4ac062830e3846b426391d8acee44349204a465a9d16f4d16eef3e8a8209b9305a3bc885a5f899c402c095';
        $qy = '775474f7b5b7979eabece86c54ba828f99f935d22a54581998cc0cc263fd6d20249a30748197c461f0c478033a65e1d4';
        $r = '2ca8c560f92280756d4d4e5903043a370532b246669e6110b033f9ab150d51863208e24bd70ce3738d027638bbd54cd2';
        $key = Common::ecKeyFromPoint('P-384', "\x04" . hex2bin(str_pad($qx, 96, '0', STR_PAD_LEFT)) . hex2bin(str_pad($qy, 96, '0', STR_PAD_LEFT)));
        $le = static fn(string $h): string => str_pad(strrev(hex2bin(str_pad($h, 96, '0', STR_PAD_LEFT))), 72, "\0");
        $rep = ['sig_r' => $le($r), 'sig_s' => $le('1'), 'signed' => str_repeat("\x5A", 0x2A0)];
        $this->assertTrue(Amd::verifyReportSignature($rep, $key));
        $this->assertFalse(Amd::verifyReportSignature(['sig_s' => $le('2')] + $rep, $key));
    }

    public function testSignatureVerifierNeverThrows(): void
    {
        $key = Common::loadPublicKey(self::spki('vcek'));
        $this->assertFalse(Amd::verifyReportSignature(['sig_r' => "\x01", 'sig_s' => "\x01", 'signed' => null], $key));
        $this->assertFalse(Amd::verifyReportSignature(['sig_r' => str_repeat("\0", 72), 'sig_s' => "\x01", 'signed' => ''], $key));
    }

    // ---------------------------------------------------------------------------------------------------------------- decodeSpl

    public function testDecodeSplEveryOutcome(): void
    {
        $d = static fn(string $v): int|string => (new \ReflectionMethod(Amd::class, 'decodeSpl'))->invoke(null, $v);
        $this->assertSame(5, $d("\x02\x01\x05"));
        $this->assertSame(0, $d("\x02\x01\x00"));
        $this->assertSame(128, $d("\x02\x02\x00\x80"));
        $this->assertSame(255, $d("\x02\x02\x00\xFF"));
        $this->assertSame('is not a DER INTEGER', $d("\x04\x01\x05"));
        $this->assertSame('is not a DER INTEGER', $d("\x02\x01"));
        $this->assertSame('has a wrong-length INTEGER', $d("\x02\x01\x05\x06"));
        $this->assertSame('has a wrong-length INTEGER', $d("\x02\x03\x00\x00\x80"));
        $this->assertSame('has a wrong-length INTEGER', $d("\x02\x00\x05"));
        $this->assertSame('is negative', $d("\x02\x01\x80"));
        $this->assertSame('is out of range (> 255)', $d("\x02\x02\x01\x80"));
        $this->assertSame('is a non-minimal INTEGER', $d("\x02\x02\x00\x05"));
        $this->assertSame('is a non-minimal INTEGER', $d("\x02\x02\x00\x7F"));
    }

    // ---------------------------------------------------------------------------------------------------------------- VCEK binding

    public function testBindingReasonsAndByteIndexes(): void
    {
        $rep = ['chip_id' => str_repeat("\x11", 64), 'reported_tcb' => self::tcb()];
        $this->assertSame('VCEK extensions malformed: tbsCertificate is not a SEQUENCE', Amd::checkVcekReportBinding("\x04\x00", $rep));
        // byte 2 of the reported TCB differs from byte 1: the tee SPL is byte 1
        $rep['reported_tcb'] = gmp_init(bin2hex(strrev("\x04\x02\x09\x00\x00\x00\x03\xC8")), 16);
        $this->assertNull(Amd::checkVcekReportBinding(self::tbs(...self::vcekExts()), $rep));
        $rep['reported_tcb'] = gmp_init(bin2hex(strrev("\x04\x01\x02\x00\x00\x00\x03\xC8")), 16);
        $this->assertSame('VCEK tee SPL 2 does not match report reported_tcb (1) — TCB downgrade?', Amd::checkVcekReportBinding(self::tbs(...self::vcekExts()), $rep));
    }

    // ---------------------------------------------------------------------------------------------------------------- chain

    public function testChainPreconditionsReturnExactArrays(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'nowMs (verifier clock) is required for the AMD chain validity check'], Amd::verifyCertChain('', '', null, null));
        $this->assertSame(['ok' => false, 'reason' => 'nowMs (verifier clock) is required for the AMD chain validity check'], Amd::verifyCertChain('', '', null, 'x'));
        $this->assertSame(['ok' => false, 'reason' => 'clockSkewMs must be a non-negative number'], Amd::verifyCertChain('', '', null, self::now(), -1));
        $this->assertSame(['ok' => false, 'reason' => 'clockSkewMs must be a non-negative number'], Amd::verifyCertChain('', '', null, self::now(), 'x'));
    }

    public function testChainStructureReasons(): void
    {
        [$vcek, $pem, $pin] = self::world();
        $blocks = Common::pemBlocks($pem);
        $ask = $blocks[0];
        $ark = $blocks[1];
        $now = self::now();
        $this->assertSame(['ok' => false, 'reason' => 'ASK+ARK chain must contain exactly two certificates (ASK then ARK)'], Amd::verifyCertChain($vcek, $ask, $pin, $now));
        $this->assertSame(['ok' => false, 'reason' => 'ASK+ARK chain must contain exactly two certificates (ASK then ARK)'], Amd::verifyCertChain($vcek, "$ask\n$ark\n$ark", $pin, $now));
        $this->assertSame(['ok' => false, 'reason' => 'second certificate of the chain is not a self-signed ARK (chain out of order?)'], Amd::verifyCertChain($vcek, "$ark\n$ask", $pin, $now));
        $forged = self::pem(self::cert(self::dn('ARK'), self::dn('ARK'), 'ark', 'rogue', [self::ext('2.5.29.19', self::BC, true)]));
        $this->assertSame(['ok' => false, 'reason' => 'second certificate of the chain is not a self-signed ARK (chain out of order?)'], Amd::verifyCertChain($vcek, $ask . $forged, $pin, $now));
        $this->assertSame(['ok' => false, 'reason' => 'first certificate of the chain is self-signed, not an ASK (chain out of order?)'], Amd::verifyCertChain($vcek, "$ark\n$ark", $pin, $now));
        [$vo, $po] = self::world(['vcekIssuer' => 'OTHER']);
        $this->assertSame(['ok' => false, 'reason' => 'ASK subject does not match the VCEK issuer'], Amd::verifyCertChain($vo, $po, $pin, $now));
    }

    public function testChainPinSignaturesAndRoles(): void
    {
        [$vcek, $pem, $pin] = self::world();
        $now = self::now();
        $this->assertSame(['ok' => false, 'reason' => 'ARK does not match the pinned AMD trust anchor'], Amd::verifyCertChain($vcek, $pem, null, $now));
        $this->assertSame(['ok' => false, 'reason' => 'ARK does not match the pinned AMD trust anchor'], Amd::verifyCertChain($vcek, $pem, str_repeat('0', 96), $now));
        $this->assertTrue(Amd::verifyCertChain($vcek, $pem, strtoupper($pin), $now)['ok']);
        [$v1, $p1] = self::world(['askSigner' => 'rogue']);
        $this->assertSame(['ok' => false, 'reason' => 'ASK is not signed by ARK'], Amd::verifyCertChain($v1, $p1, $pin, $now));
        [$v2, $p2] = self::world(['vcekSigner' => 'rogue']);
        $this->assertSame(['ok' => false, 'reason' => 'VCEK is not signed by ASK'], Amd::verifyCertChain($v2, $p2, $pin, $now));
        [$v3, $p3] = self::world(['vcekExts' => [...self::vcekExts(), self::ext('2.5.29.19', self::BC)]]);
        $this->assertSame(['ok' => false, 'reason' => 'AMD chain role check failed: leaf certificate asserts BasicConstraints CA:TRUE (an end-entity must not be a CA)'],
            Amd::verifyCertChain($v3, $p3, $pin, $now));
        [$v4, $p4] = self::world(['vcekExts' => [...self::vcekExts(), self::ext('1.2.3.4', "\x05\x00", true)]]);
        $this->assertSame(['ok' => false, 'reason' => 'VCEK certificate has an unrecognised critical extension 1.2.3.4'], Amd::verifyCertChain($v4, $p4, $pin, $now));
        [$v5, $p5] = self::world(['askExts' => [self::ext('2.5.29.19', self::BC)]]);
        $this->assertSame(['ok' => false, 'reason' => 'ASK certificate BasicConstraints is not marked critical'], Amd::verifyCertChain($v5, $p5, $pin, $now));
        [$v6, $p6] = self::world(['arkExts' => [self::ext('2.5.29.19', self::BC)]]);
        $this->assertSame(['ok' => false, 'reason' => 'ARK certificate BasicConstraints is not marked critical'], Amd::verifyCertChain($v6, $p6, $pin, $now));
    }

    public function testChainValidityWindow(): void
    {
        $now = self::now();
        [$v1, $p1, $pin] = self::world(['vcekNb' => self::utc('garbage')]);
        $this->assertSame(['ok' => false, 'reason' => 'VCEK certificate validity is unparseable'], Amd::verifyCertChain($v1, $p1, $pin, $now));
        [$v2, $p2] = self::world(['vcekNa' => self::utc('garbage')]);
        $this->assertSame(['ok' => false, 'reason' => 'VCEK certificate validity is unparseable'], Amd::verifyCertChain($v2, $p2, $pin, $now));
        [$v3, $p3] = self::world(['vcekNb' => self::utc('310101000000Z')]);
        $this->assertSame(['ok' => false, 'reason' => 'VCEK certificate is not yet valid'], Amd::verifyCertChain($v3, $p3, $pin, $now));
        [$v4, $p4] = self::world(['vcekNa' => self::utc('250101000000Z')]);
        $this->assertSame(['ok' => false, 'reason' => 'VCEK certificate has expired'], Amd::verifyCertChain($v4, $p4, $pin, $now));
        // notAfter = now exactly; now is 1 s past it, and a 5 s skew tolerates that: now - skew <= notAfter
        [$v5, $p5] = self::world(['vcekNa' => self::utc('300101000000Z')]);
        $this->assertTrue(Amd::verifyCertChain($v5, $p5, $pin, $now + 1000, 5000)['ok']);
        $this->assertSame(['ok' => false, 'reason' => 'VCEK certificate has expired'], Amd::verifyCertChain($v5, $p5, $pin, $now + 6000, 5000));
    }

    public function testChainVcekKeyMustBeP384(): void
    {
        $now = self::now();
        [$v1, $p1, $pin] = self::world(['vcekKey' => 'p256']);
        $this->assertSame(['ok' => false, 'reason' => 'AMD chain verification error: VCEK is not EC secp384r1 (got ec/prime256v1)'], Amd::verifyCertChain($v1, $p1, $pin, $now));
        [$v2, $p2] = self::world(['vcekKey' => 'rsa']);
        $this->assertSame(['ok' => false, 'reason' => 'AMD chain verification error: VCEK is not EC secp384r1 (got rsa/undefined)'], Amd::verifyCertChain($v2, $p2, $pin, $now));
    }

    public function testChainSuccessShape(): void
    {
        [$vcek, $pem, $pin] = self::world();
        $r = Amd::verifyCertChain($vcek, $pem, $pin, self::now());
        $this->assertSame(['ok', 'vcek', 'vcekTbs'], array_keys($r));
        $this->assertTrue($r['ok']);
        $this->assertInstanceOf(PubKey::class, $r['vcek']);
        $this->assertSame(Der::tbsOfCertificate($vcek), $r['vcekTbs']);
    }

    // ---------------------------------------------------------------------------------------------------------------- policy

    /** @return array<string,mixed> */
    private static function polReport(): array
    {
        return ['signature_algo' => 1, 'policy' => gmp_init(0), 'guest_svn' => 0, 'reported_tcb' => gmp_init(0), 'committed_tcb' => gmp_init(5),
            'launch_tcb' => gmp_init(0), 'vmpl' => 0, 'measurement' => "\xAB", 'host_data' => "\xCD", 'chip_id' => "\x11"];
    }

    public function testPolicyCommittedTcbEqualAndEmptyAllowlists(): void
    {
        $r = self::polReport();
        $this->assertNull(Amd::checkPolicy($r, ['minCommittedTcb' => gmp_init(5)]));
        $this->assertSame('committed_tcb below minimum (rollback?)', Amd::checkPolicy($r, ['minCommittedTcb' => gmp_init(6)]));
        $this->assertNull(Amd::checkPolicy($r, ['measurements' => []]));
        $this->assertNull(Amd::checkPolicy($r, ['hostData' => []]));
        $this->assertNull(Amd::checkPolicy($r, ['chipIds' => []]));
        $this->assertNull(Amd::checkPolicy($r, ['measurements' => ['AB'], 'hostData' => ['CD'], 'chipIds' => ['11']]));
        $this->assertSame('measurement not in policy allowlist', Amd::checkPolicy($r, ['measurements' => ['00']]));
        $this->assertSame('host_data not in policy allowlist', Amd::checkPolicy($r, ['hostData' => ['00']]));
        $this->assertSame('chip_id not in policy allowlist', Amd::checkPolicy($r, ['chipIds' => ['00']]));
    }

    public function testPolicyNumberFormatting(): void
    {
        $r = self::polReport();
        $this->assertSame('vmpl 0 is not the required abc', Amd::checkPolicy($r, ['requireVmpl' => 'abc']));
        $this->assertSame('vmpl 0 is not the required 2.5', Amd::checkPolicy($r, ['requireVmpl' => 2.5]));
        $this->assertSame('vmpl 0 is not the required 3', Amd::checkPolicy($r, ['requireVmpl' => 3]));
        $this->assertSame('guest_svn 0 below minimum 1', Amd::checkPolicy($r, ['minGuestSvn' => 1]));
    }

    public function testDefaultIdentityIsPublicAndExact(): void
    {
        $this->assertSame(['model_id' => '', 'weights_digest' => '', 'weights_measured' => false, 'runtime_measurement' => 'abcd', 'operator' => '0102'],
            Amd::defaultIdentity(['measurement' => "\xAB\xCD", 'chip_id' => "\x01\x02"]));
    }

    public function testAzureBindingRefusesNonZeroByte32(): void
    {
        $rd = str_repeat("\0", 32) . "\x01" . str_repeat("\0", 31);
        $this->assertSame('report_data[32:64] is not zero (not an Azure runtime-data hash)', Amd::checkAzureRuntimeDataBinding($rd, '{}', null));
        $rd0 = str_repeat("\0", 64);
        $this->assertSame('sha256(runtime data) does not equal the quote report_data', Amd::checkAzureRuntimeDataBinding($rd0, '{}', null));
    }

    // ---------------------------------------------------------------------------------------------------------------- genuine report

    public function testGenuineReportEarlyRefusals(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'report parse failed: parseSevSnpReport: report too short (10 < 816)'], Amd::verifyGenuineReport(str_repeat("\0", 10), '', '', null, null));
        $this->assertSame(['ok' => false, 'reason' => 'report length 1000 is not the canonical 1184'], Amd::verifyGenuineReport(str_repeat("\0", 1000), '', '', null, null));
        foreach ([0x4A0 - 1, 0x2E8 + 72, 0x2A0 + 48, 0x2A0 + 71, 0x2E8 + 48, 0x2E8 + 71] as $off) {
            $rep = str_repeat("\0", 0x4A0);
            $rep[$off] = "\x01";
            $this->assertSame(['ok' => false, 'reason' => 'report signature block has non-zero reserved bytes'], Amd::verifyGenuineReport($rep, '', '', null, null), (string)$off);
        }
        $this->assertSame(['ok' => false, 'reason' => 'cert chain invalid: nowMs (verifier clock) is required for the AMD chain validity check'],
            Amd::verifyGenuineReport(str_repeat("\0", 0x4A0), '', '', null, null));
    }

    public function testGenuineReportPipelineReasons(): void
    {
        [$vcek, $pem, $pin] = self::world();
        $now = self::now();
        $exp = ['holderPub' => 'hp', 'grantRef' => 'gr', 'epoch' => 3, 'nonce' => 'nn'];
        $bound = self::report(['report_data' => Common::attestationBinding($exp)]);

        $this->assertSame(['ok' => false, 'reason' => 'report signature does not verify under VCEK'],
            Amd::verifyGenuineReport(self::report(['unsigned' => true]), $vcek, $pem, $pin, $now));
        $this->assertSame(['ok' => false, 'reason' => 'VCEK CHIP_ID does not match report chip_id'],
            Amd::verifyGenuineReport(self::report(['chip' => str_repeat("\x22", 64)]), $vcek, $pem, $pin, $now));
        $this->assertSame(['ok' => false, 'reason' => 'report_data does not bind holder/grant/epoch/nonce'],
            Amd::verifyGenuineReport($bound, $vcek, $pem, $pin, $now, null, ['nonce' => 'other'] + $exp));
        $this->assertSame(['ok' => false, 'reason' => 'vmpl 0 is not the required 5'],
            Amd::verifyGenuineReport($bound, $vcek, $pem, $pin, $now, null, $exp, ['requireVmpl' => 5]));
        $this->assertSame(['ok' => false, 'reason' => 'genuine verification error (fail closed): binding: holderPub required'],
            Amd::verifyGenuineReport($bound, $vcek, $pem, $pin, $now, null, 'x'));

        $ok = Amd::verifyGenuineReport($bound, $vcek, $pem, $pin, $now, null, $exp, ['measurements' => [bin2hex(str_repeat("\xAB", 48))]]);
        $this->assertTrue($ok['ok']);
        $this->assertSame(['ok', 'report', 'measured'], array_keys($ok));
        $this->assertSame(Amd::defaultIdentity($ok['report']), $ok['measured']);
        $this->assertSame(str_repeat("\xAB", 48), $ok['report']['measurement']);
    }

    // ---------------------------------------------------------------------------------------------------------------- verifier

    public function testVerifierFailsClosedWhenTheResolverThrows(): void
    {
        $v = new Amd(['family' => 'genoa', 'binding' => 'report-data', 'policy' => ['measurements' => ['00']]], static function (): never {
            throw new \RuntimeException('boom');
        });
        $this->assertSame(['ok' => false, 'reason' => 'amd-snp verification error (fail closed): boom'], $v->verify('doc', ['x' => 1], self::now()));
    }
}
