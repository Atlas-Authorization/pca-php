<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\DerError;
use PHPUnit\Framework\TestCase;

/** Survivor kills of src/Attest/Der.php: every input is hand-built DER; expectations are derived from the reader rules. */
final class K05KillAttestDer1Test extends TestCase
{
    private const OID_BC = "\x55\x1D\x13";
    private const OID_KU = "\x55\x1D\x0F";

    private static function len(int $n): string
    {
        if ($n < 128) {
            return chr($n);
        }
        return $n < 256 ? "\x81" . chr($n) : "\x82" . chr($n >> 8) . chr($n & 255);
    }

    private static function tlv(int $tag, string $c): string
    {
        return chr($tag) . self::len(strlen($c)) . $c;
    }

    private static function ext(string $oidRaw, string $value): string
    {
        return self::tlv(0x30, self::tlv(6, $oidRaw) . self::tlv(4, $value));
    }

    private static function cert(string ...$exts): string
    {
        return self::tlv(0x30, self::tlv(0x30, self::tlv(0xA3, self::tlv(0x30, implode('', $exts)))));
    }

    private function assertDer(string $msg, callable $f): void
    {
        try {
            $f();
        } catch (DerError $e) {
            $this->assertSame($msg, $e->getMessage());
            return;
        }
        $this->fail("no DerError '$msg'");
    }

    /** Runs $f with every PHP warning turned into an exception (a mutant that reads past the string must not pass silently). */
    private static function strict(callable $f): mixed
    {
        set_error_handler(static function (int $no, string $str, string $file, int $line): bool {
            throw new \ErrorException($str, 0, $no, $file, $line);
        });
        try {
            return $f();
        } finally {
            restore_error_handler();
        }
    }

    // ---- readTlv ------------------------------------------------------------------------------------------------------------------

    public function testReadTlvHonoursAnExplicitLimit(): void
    {
        $this->assertDer('DER: element overruns its parent', fn() => Der::readTlv("\x04\x05abcde", 0, 3));
    }

    public function testReadTlvLengthBytesExactlyAtTheLimit(): void
    {
        $this->assertDer('DER: element overruns its parent', fn() => Der::readTlv("\x04\x81\x80", 0));
    }

    public function testReadTlvOneLengthByteMayBeZero(): void
    {
        $this->assertDer('DER: non-minimal length (long form below 128)', fn() => Der::readTlv("\x04\x81\x00", 0));
    }

    // ---- readCertRoleInfo ---------------------------------------------------------------------------------------------------------

    public function testRoleInfoNeedsATbsSequence(): void
    {
        $this->assertDer('certificate has no tbsCertificate', fn() => Der::readCertRoleInfo("\x30\x02\x31\x00"));
    }

    public function testRoleInfoCaFalseAndTrue(): void
    {
        $f = Der::readCertRoleInfo(self::cert(self::ext(self::OID_BC, self::tlv(0x30, self::tlv(1, "\x00")))));
        $this->assertSame(['hasBasicConstraints' => true, 'ca' => false, 'hasKeyUsage' => false, 'keyCertSign' => false], $f);
        $t = Der::readCertRoleInfo(self::cert(self::ext(self::OID_BC, self::tlv(0x30, self::tlv(1, "\xFF") . self::tlv(2, "\x05")))));
        $this->assertSame(['hasBasicConstraints' => true, 'ca' => true, 'hasKeyUsage' => false, 'keyCertSign' => false, 'pathLen' => 5], $t);
    }

    public function testRoleInfoTwoBytePathLen(): void
    {
        $i = Der::readCertRoleInfo(self::cert(self::ext(self::OID_BC, self::tlv(0x30, self::tlv(2, "\x01\x00")))));
        $this->assertSame(['hasBasicConstraints' => true, 'ca' => false, 'hasKeyUsage' => false, 'keyCertSign' => false, 'pathLen' => 256], $i);
    }

    public function testRoleInfoPathLenMustBeAnInteger(): void
    {
        $this->assertDer('BasicConstraints pathLenConstraint malformed', fn() => Der::readCertRoleInfo(
            self::cert(self::ext(self::OID_BC, self::tlv(0x30, self::tlv(4, "\x01"))))));
    }

    public function testRoleInfoEmptyPathLenIsMalformed(): void
    {
        $ku = self::ext(self::OID_KU, self::tlv(3, "\x00\x80"));
        $this->assertDer('BasicConstraints pathLenConstraint malformed', fn() => Der::readCertRoleInfo(
            self::cert(self::ext(self::OID_BC, self::tlv(0x30, self::tlv(2, ''))), $ku)));
    }

    public function testRoleInfoKeyCertSignIsBitTwoOnly(): void
    {
        $no = Der::readCertRoleInfo(self::cert(self::ext(self::OID_KU, self::tlv(3, "\x00\x01"))));
        $this->assertSame(['hasBasicConstraints' => false, 'ca' => false, 'hasKeyUsage' => true, 'keyCertSign' => false], $no);
        $yes = Der::readCertRoleInfo(self::cert(self::ext(self::OID_KU, self::tlv(3, "\x00\x04"))));
        $this->assertTrue($yes['keyCertSign']);
    }

    // ---- oidToDotted --------------------------------------------------------------------------------------------------------------

    public function testOidFirstArcBoundaries(): void
    {
        foreach (["\x06\x01\x28" => '1.0', "\x06\x01\x50" => '2.0', "\x06\x01\x27" => '0.39', "\x06\x01\x4F" => '1.39'] as $b => $want) {
            $b = (string)$b;
            $this->assertSame($want, Der::oidToDotted($b, Der::readTlv($b, 0)));
        }
    }

    // ---- generalName --------------------------------------------------------------------------------------------------------------

    public function testGeneralNameUnsupportedTag(): void
    {
        $b = "\x83\x00";
        $this->assertDer('not a supported GeneralName', fn() => Der::generalName($b, Der::readTlv($b, 0)));
    }

    public function testDirectoryNameMustBeOneNameSequence(): void
    {
        $notSeq = self::tlv(0xA4, "\x31\x00");
        $this->assertDer('directoryName is not one Name', fn() => Der::generalName($notSeq, Der::readTlv($notSeq, 0)));
        $trailing = self::tlv(0xA4, "\x30\x00\x05\x00");
        $this->assertDer('directoryName is not one Name', fn() => Der::generalName($trailing, Der::readTlv($trailing, 0)));
        $ok = self::tlv(0xA4, "\x30\x00");
        Der::generalName($ok, Der::readTlv($ok, 0));
        $this->addToAssertionCount(1);
    }

    // ---- cachedExtension ----------------------------------------------------------------------------------------------------------

    public function testNameConstraintsIntegerEndsAtItsOwnContent(): void
    {
        $base = self::tlv(0x81, 'a');
        $sub1 = self::tlv(0x30, $base . self::tlv(0x80, "\x00"));
        $sub2 = self::tlv(0x30, $base);
        Der::cachedExtension('2.5.29.30', self::tlv(0x30, self::tlv(0xA0, $sub1 . $sub2)));
        $this->addToAssertionCount(1);
    }

    public function testNameConstraintsBaseIsChecked(): void
    {
        $sub = self::tlv(0x30, self::tlv(0x83, 'a'));
        $this->assertDer('not a supported GeneralName', fn() => Der::cachedExtension('2.5.29.30', self::tlv(0x30, self::tlv(0xA0, $sub))));
    }

    public function testPathLen7FIsPositive(): void
    {
        Der::cachedExtension('2.5.29.19', self::tlv(0x30, self::tlv(2, "\x7F")));
        $this->addToAssertionCount(1);
        $this->assertDer('not a positive DER INTEGER', fn() => Der::cachedExtension('2.5.29.19', self::tlv(0x30, self::tlv(2, "\x80"))));
    }

    public function testKeyUsageWithNoBits(): void
    {
        $this->assertDer('keyUsage has no bits', fn() => Der::cachedExtension('2.5.29.15', "\x03\x01\x00"));
    }

    public function testDistributionPointMustBeASequence(): void
    {
        $this->assertDer('DistributionPoint is not a SEQUENCE', fn() => Der::cachedExtension('2.5.29.31', self::tlv(0x30, "\x31\x00")));
    }

    // ---- parseTbsExtensions / tbsOfCertificate ------------------------------------------------------------------------------------

    public function testTbsMustBeASequence(): void
    {
        $this->assertDer('tbsCertificate is not a SEQUENCE', fn() => Der::parseTbsExtensions("\x31\x00"));
    }

    public function testExtensionMustBeASequence(): void
    {
        $tbs = self::tlv(0x30, self::tlv(0xA3, self::tlv(0x30, self::tlv(0x31, ''))));
        $this->assertDer('extension is not a SEQUENCE', fn() => Der::parseTbsExtensions($tbs));
    }

    public function testTbsOfCertificateRefusals(): void
    {
        $this->assertDer('certificate is not a DER SEQUENCE', fn() => Der::tbsOfCertificate("\x31\x00"));
        $this->assertDer('certificate has no tbsCertificate', fn() => Der::tbsOfCertificate("\x30\x02\x31\x00"));
    }

    // ---- strictChainError ---------------------------------------------------------------------------------------------------------

    public function testStrictChainErrorPrefixesAnExtensionParseFailure(): void
    {
        $bad = self::tlv(0x30, self::tlv(4, "\x00") . self::tlv(4, "\x00"));
        $this->assertNull(Der::checkChainRoles([self::cert($bad)]));
        $this->assertSame('certificate extension parse failed: extension OID is malformed', Der::strictChainError([self::cert($bad)]));
    }

    // ---- tlvLenient ---------------------------------------------------------------------------------------------------------------

    public function testLenientTruncatedHeader(): void
    {
        $this->assertDer('truncated', fn() => self::strict(fn() => Der::tlvLenient("\x30", 0)));
    }

    public function testLenientEmptyElementAtTheEnd(): void
    {
        $t = self::strict(fn() => Der::tlvLenient("\x30\x00", 0));
        $this->assertSame([0x30, 2, 2], [$t->tag, $t->start, $t->end]);
    }

    public function testLenientLengthFormBoundaries(): void
    {
        $t = self::strict(fn() => Der::tlvLenient("\x30\x81\x00", 0));
        $this->assertSame([0x30, 3, 3], [$t->tag, $t->start, $t->end]);
        $t = self::strict(fn() => Der::tlvLenient("\x30\x84\x00\x00\x00\x00", 0));
        $this->assertSame([0x30, 6, 6], [$t->tag, $t->start, $t->end]);
        $this->assertDer('bad length', fn() => self::strict(fn() => Der::tlvLenient("\x30\x80", 0)));
        $this->assertDer('bad length', fn() => self::strict(fn() => Der::tlvLenient("\x30\x85\x00\x00\x00\x00\x00", 0)));
        $this->assertDer('bad length', fn() => self::strict(fn() => Der::tlvLenient("\x30\x81", 0)));
    }

    // ---- calendar -----------------------------------------------------------------------------------------------------------------

    public function testDaysFromCivil(): void
    {
        $this->assertSame(0, Der::daysFromCivil(1970, 1, 1));
        $this->assertSame(-719528, Der::daysFromCivil(0, 1, 1));
        $this->assertSame(11017, Der::daysFromCivil(2000, 3, 1));
        $this->assertSame(-865259, Der::daysFromCivil(-399, 1, 1));
        $this->assertSame(-25508, Der::daysFromCivil(1900, 3, 1));
    }

    public function testDaysInMonth(): void
    {
        $this->assertSame(28, Der::daysInMonth(1900, 2));
        $this->assertSame(28, Der::daysInMonth(399, 2));
        $this->assertSame(29, Der::daysInMonth(2000, 2));
        $this->assertSame(29, Der::daysInMonth(396, 2));
        $this->assertSame(28, Der::daysInMonth(401, 2));
        $this->assertSame(29, Der::daysInMonth(404, 2));
        $this->assertSame(28, Der::daysInMonth(2023, 2));
        $this->assertSame(29, Der::daysInMonth(2024, 2));
        $this->assertSame(30, Der::daysInMonth(2023, 9));
        $this->assertSame(31, Der::daysInMonth(2023, 8));
        $this->assertSame(31, Der::daysInMonth(2023, 1));
        $this->assertSame(30, Der::daysInMonth(2023, 11));
    }

    // ---- validity -----------------------------------------------------------------------------------------------------------------

    private const LO = 1735689600000; // 2025-01-01T00:00:00Z
    private const HI = 1767225600000; // 2026-01-01T00:00:00Z

    /** @param array<string,mixed> $o */
    private static function validityCert(array $o = []): string
    {
        $nb = self::tlv(0x17, $o['nb'] ?? '250101000000Z');
        $na = self::tlv(0x17, '260101000000Z');
        $validity = self::tlv($o['validityTag'] ?? 0x30, $nb . $na . ($o['extra'] ?? ''));
        $pre = self::tlv($o['serialTag'] ?? 0x02, "\x01") . self::tlv($o['sigTag'] ?? 0x30, '') . self::tlv($o['issuerTag'] ?? 0x30, '');
        $tbs = self::tlv($o['tbsTag'] ?? 0x30, $pre . $validity);
        return self::tlv($o['outerTag'] ?? 0x30, $tbs);
    }

    public function testValidityReadsAWellFormedCertificate(): void
    {
        $this->assertSame([self::LO, self::HI], Der::derValidityMs(self::validityCert()));
    }

    public function testValidityStructureRefusals(): void
    {
        foreach (['outerTag', 'tbsTag', 'serialTag', 'sigTag', 'issuerTag', 'validityTag'] as $k) {
            $v = in_array($k, ['serialTag'], true) ? 0x04 : 0x31;
            $this->assertSame([null, null], Der::derValidityMs(self::validityCert([$k => $v])), $k);
        }
        $this->assertSame([null, null], Der::derValidityMs(self::validityCert(['extra' => "\x05\x00"])));
    }

    public function testValidityMayNotRunPastTheTbs(): void
    {
        $nb = self::tlv(0x17, '250101000000Z');
        $na = self::tlv(0x17, '260101000000Z');
        $pre = self::tlv(2, "\x01") . self::tlv(0x30, '') . self::tlv(0x30, '');
        $hdr = "\x30\x1e";
        $cert = self::tlv(0x30, self::tlv(0x30, $pre . $hdr) . $nb . $na);
        $this->assertSame([null, null], Der::derValidityMs($cert));
        // the same bytes with the tbs covering the validity are read
        $this->assertSame([self::LO, self::HI], Der::derValidityMs(self::validityCert()));
    }

    public function testValidAtDefaultSkewIsZero(): void
    {
        $c = self::validityCert();
        $this->assertFalse(Der::x509ValidAt($c, (float)(self::LO - 1)));
        $this->assertTrue(Der::x509ValidAt($c, (float)self::LO));
        $this->assertTrue(Der::x509ValidAt($c, (float)self::HI));
        $this->assertFalse(Der::x509ValidAt($c, (float)(self::HI + 1)));
    }

    public function testValidAtNeedsBothBounds(): void
    {
        $c = self::validityCert(['nb' => '251301000000Z']);
        $this->assertSame([null, self::HI], Der::derValidityMs($c));
        $this->assertFalse(Der::x509ValidAt($c, (float)(self::LO + 5)));
    }

    public function testValidAtSkewWidensBothEnds(): void
    {
        $c = self::validityCert();
        $this->assertTrue(Der::x509ValidAt($c, (float)(self::HI + 1000), 1000.0));
        $this->assertFalse(Der::x509ValidAt($c, (float)(self::HI + 1001), 1000.0));
        $this->assertTrue(Der::x509ValidAt($c, (float)(self::LO - 1000), 1000.0));
        $this->assertFalse(Der::x509ValidAt($c, (float)(self::LO - 1001), 1000.0));
    }
}
