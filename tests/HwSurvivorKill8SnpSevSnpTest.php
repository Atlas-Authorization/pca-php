<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attest/SevSnp.php';

use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\SevSnp;
use PHPUnit\Framework\TestCase;

/**
 * Survivor kills for Attest/SevSnp.php: the compressed-point expansion of the VCEK key, the VCEK certificate key-type refusal, the
 * KDS VCEK fetch (URL, refusals, body) and the little-endian u32 reader. Constants are P-384 / P-256 curve points checked offline.
 */
final class HwSurvivorKill8SnpSevSnpTest extends TestCase
{
    private const GX = 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7';
    private const GY = '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'; // odd
    private const P_MINUS_GY = 'c9e821b569d9d390a26167406d6d23d6070be242d765eb831625ceec4a0f473ef59f4e30e2817e6285bce2846f15f1a0'; // even
    private const P = 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff';
    // x = 10 lies on the curve; its root of the requested (odd) parity is below 2^380, so its 96-digit hex form starts with a zero nibble
    private const X10_Y = '0ce40acccbc0aacf8bdafbd8fa2da274ecccb65d11cb70e1be930453c1996d3cfb8c6b7cb6a356423c0ee80090b4397d';
    private const P256_GX = '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296';
    private const P256_GY = '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';

    /** The refusal message of ecdsaP384PublicKey for an input, or 'accepted'. */
    private static function refusal(string $in): string
    {
        try {
            SevSnp::ecdsaP384PublicKey($in);
        } catch (\ValueError $e) {
            return $e->getMessage();
        }
        return 'accepted';
    }

    public function testU32ReadsFourLittleEndianBytesAtTheOffset(): void
    {
        $m = new \ReflectionMethod(SevSnp::class, 'u32');
        $this->assertSame(0x12345678, $m->invoke(null, "\x00\x00\x00\x00\x78\x56\x34\x12\xFF", 4));
        $this->assertSame(1, $m->invoke(null, "\x01\x00\x00\x00", 0));
    }

    public function testCompressedKeysExpandToTheRequestedParity(): void
    {
        $x = hex2bin(self::GX);
        $this->assertSame("\x04" . $x . hex2bin(self::GY), SevSnp::ecdsaP384PublicKey("\x03" . $x));
        $this->assertSame("\x04" . $x . hex2bin(self::P_MINUS_GY), SevSnp::ecdsaP384PublicKey("\x02" . $x));
        // the uncompressed form passes through unchanged
        $full = "\x04" . $x . hex2bin(self::GY);
        $this->assertSame($full, SevSnp::ecdsaP384PublicKey($full));
    }

    public function testACompressedKeyWhoseYStartsWithAZeroNibbleKeepsFortyEightBytes(): void
    {
        $x = str_repeat("\0", 47) . "\x0a";
        $out = SevSnp::ecdsaP384PublicKey("\x03" . $x);
        $this->assertSame(97, strlen($out));
        $this->assertSame("\x04" . $x . hex2bin(self::X10_Y), $out);
    }

    public function testCompressedKeyRefusals(): void
    {
        $x = hex2bin(self::GX);
        $this->assertSame('ecdsaP384PublicKey: not a SEC1 point', self::refusal("\x05" . $x));
        $this->assertSame('ecdsaP384PublicKey: not a SEC1 point', self::refusal("\x04" . $x));
        // x equal to the field prime, and above it, is out of range
        $this->assertSame('ecdsaP384PublicKey: x is out of range', self::refusal("\x02" . hex2bin(self::P)));
        $this->assertSame('ecdsaP384PublicKey: x is out of range', self::refusal("\x03" . str_repeat("\xFF", 48)));
        // x = 1: x^3 - 3x + b is not a square mod p
        $this->assertSame('ecdsaP384PublicKey: the point is not on the curve', self::refusal("\x02" . str_repeat("\0", 47) . "\x01"));
    }

    // ---------------------------------------------------------------------------------------------------------------- VCEK certificate

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        $n = strlen($v);
        return chr($tag) . ($n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : "\x82" . pack('n', $n))) . $v;
    }

    /** A structurally minimal certificate (empty names, validity and algorithm; one-byte signature) around the given SubjectPublicKeyInfo. @return array{0:string,1:string} [cert, tbs] */
    private static function tinyCert(string $spki): array
    {
        $tbs = self::tlv(0x30, "\x02\x01\x01", "\x30\x00", "\x30\x00", "\x30\x00", "\x30\x00", $spki);
        return [self::tlv(0x30, $tbs, "\x30\x00", "\x03\x01\x00"), $tbs];
    }

    public function testATinyP384CertificateWithAOneByteLengthFormYieldsItsPointAndTbs(): void
    {
        $point = "\x04" . hex2bin(self::GX) . hex2bin(self::GY);
        [$cert, $tbs] = self::tinyCert(Common::ecKeyFromPoint('P-384', $point)->spki);
        $this->assertSame("\x30\x81", substr($cert, 0, 2)); // long form below 256: the offset-1 header is a length byte, not a tag
        $r = SevSnp::extractVcekPublicKey($cert);
        $this->assertSame(['point', 'tbs'], array_keys($r));
        $this->assertSame($point, $r['point']);
        $this->assertSame($tbs, $r['tbs']);
    }

    public function testAnEcKeyOnAnotherCurveIsRefusedWithItsCurveName(): void
    {
        $point = "\x04" . hex2bin(self::P256_GX) . hex2bin(self::P256_GY);
        [$cert] = self::tinyCert(Common::ecKeyFromPoint('P-256', $point)->spki);
        try {
            SevSnp::extractVcekPublicKey($cert);
            $this->fail('a P-256 VCEK must be refused');
        } catch (\TypeError $e) {
            $this->assertSame('VCEK is not EC secp384r1 (got ec/prime256v1)', $e->getMessage());
        }
    }

    // ---------------------------------------------------------------------------------------------------------------- KDS fetch

    public function testFetchVcekBuildsTheKdsUrlFromTheReportedTcbBytes(): void
    {
        $seen = [];
        $fetch = static function (string $u) use (&$seen): array {
            $seen[] = $u;
            return ['ok' => true, 'status' => 200, 'body' => "\x01cert"];
        };
        // little-endian bytes 04 02 00 00 00 00 03 7F: bootloader 4, tee 2, snp 3, microcode 127
        $tcb = 0x7F03000000000204;
        $this->assertSame("\x01cert", SevSnp::fetchVcek("\x01\x02", $tcb, ['fetch' => $fetch]));
        $this->assertSame("\x01cert", SevSnp::fetchVcek("\x01\x02", gmp_init('7f03000000000204', 16), ['fetch' => $fetch, 'product' => 'Genoa', 'baseUrl' => 'https://kds.test/v1']));
        $this->assertSame(['https://kdsintf.amd.com/vcek/v1/Milan/0102?blSPL=4&teeSPL=2&snpSPL=3&ucodeSPL=127',
            'https://kds.test/v1/Genoa/0102?blSPL=4&teeSPL=2&snpSPL=3&ucodeSPL=127'], $seen);
    }

    public function testFetchVcekReturnsTheBodyAsAString(): void
    {
        $this->assertSame('12345', SevSnp::fetchVcek("\x01", 5, ['fetch' => static fn(string $u): array => ['ok' => true, 'status' => 200, 'body' => 12345]]));
    }

    public function testFetchVcekWithoutATransportIsRefused(): void
    {
        try {
            SevSnp::fetchVcek("\x01", 5);
            $this->fail('no transport');
        } catch (\RuntimeException $e) {
            $this->assertSame('fetchVcekFromKds: no fetch implementation available', $e->getMessage());
        }
    }

    public function testFetchVcekRefusesAnythingNotMarkedOkWithTheStatus(): void
    {
        $url = 'https://kdsintf.amd.com/vcek/v1/Milan/01?blSPL=5&teeSPL=0&snpSPL=0&ucodeSPL=0';
        $cases = [
            [['ok' => false, 'status' => 503, 'body' => ''], 503],
            [['status' => 404, 'body' => 'x'], 404],          // no ok flag is not success
            [[], 0],                                           // neither ok nor status
        ];
        foreach ($cases as [$res, $want]) {
            try {
                SevSnp::fetchVcek("\x01", 5, ['fetch' => static fn(string $u): array => $res]);
                $this->fail('refused');
            } catch (\RuntimeException $e) {
                $this->assertSame("KDS VCEK fetch failed: HTTP $want for $url", $e->getMessage());
            }
        }
    }
}
