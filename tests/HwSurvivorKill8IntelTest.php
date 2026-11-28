<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Common;
use Atlas\Pca\Attest\Intel;
use PHPUnit\Framework\TestCase;

/** Group 8 survivor kills for Attest/Intel.php: SEC1 point decompression and the PCK TCB extension component dispatch. */
final class HwSurvivorKill8IntelTest extends TestCase
{
    private const P = "\x2A\x86\x48\x86\xF8\x4D\x01\x0D\x01";
    private const FM = "\x00\x60\x6A\x00\x00\x00";

    private static function tlv(int $tag, string ...$parts): string
    {
        $v = implode('', $parts);
        return chr($tag) . chr(strlen($v)) . $v;
    }

    private static function comp(int $n, string $val): string
    {
        return self::tlv(0x30, self::tlv(0x06, self::P . "\x02" . chr($n)), $val);
    }

    private static function point(string $sec1): string
    {
        return Common::ecPoint(Intel::ecdsaP256PublicKey($sec1), 'P-256');
    }

    /** A malformed SEC1 length is refused with the curve library's text including the actual length. */
    public function testWrongLengthReportsTheLength(): void
    {
        foreach ([[str_repeat("\x02", 10), 10], [str_repeat("\x05", 65), 65], ["\x05" . str_repeat("\x01", 32), 33]] as [$in, $len]) {
            try {
                Intel::ecdsaP256PublicKey($in);
                self::fail('expected InvalidArgumentException');
            } catch (\InvalidArgumentException $e) {
                self::assertSame('invalid Point, expected length of 33, or uncompressed 65, got ' . $len, $e->getMessage());
            }
        }
    }

    /** A compressed x with no square root (x = 2 is off the curve) is refused with its own exception. */
    public function testCompressedXOffTheCurveIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ecdsaP256PublicKey: the x coordinate is not on the curve');
        Intel::ecdsaP256PublicKey("\x02" . str_repeat("\0", 31) . "\x02");
    }

    /** Decompression picks the y whose parity the prefix names, for a root whose parity is odd. */
    public function testDecompressionHonoursThePrefixParity(): void
    {
        $x = str_repeat("\0", 30) . "\x03\xeb";
        $even = "\x04" . $x . hex2bin('4987e47f655a16c9bdfff41f16de1966149a1fdedfe8a3d08c0e2a467d4b0d96');
        $odd = "\x04" . $x . hex2bin('b6781b7f9aa5e93742000be0e921e699eb65e02220175c2f73f1d5b982b4f269');
        self::assertSame($even, self::point("\x02" . $x));
        self::assertSame($odd, self::point("\x03" . $x));
    }

    /** A y with a leading zero byte is left-padded to the full 32 bytes. */
    public function testDecompressedYIsPaddedTo32Bytes(): void
    {
        $x = str_repeat("\0", 31) . "\x3c";
        $short = "\x04" . $x . hex2bin('00732d1e92b60907d7efab40def9181cd32f7348a1840c161a286911b17c3edb');
        $long = "\x04" . $x . hex2bin('ff8cd2e06d49f6f9281054bf2106e7e32cd08cb85e7bf3e9e5d796ee4e83c124');
        self::assertSame($short, self::point("\x03" . $x));
        self::assertSame($long, self::point("\x02" . $x));
    }

    /** Only an INTEGER (SVN) or an OCTET STRING under component 18 (CPUSVN) is read; other shapes never touch cpusvn. */
    public function testCpusvnOnlyFromAnOctetStringUnderComponent18(): void
    {
        $ext = self::tlv(0x06, self::P . "\x04") . self::tlv(0x04, self::FM) . self::tlv(0x06, self::P . "\x02") . self::tlv(0x30,
            self::comp(17, self::tlv(0x02, "\x07")),
            self::comp(18, self::tlv(0x04, str_repeat("\x07", 16))),
            self::comp(5, self::tlv(0x04, 'zz')),
            self::comp(18, self::tlv(0x0C, 'yy')));
        self::assertSame(['fmspc' => self::FM, 'sgxTcbComponents' => str_repeat("\0", 16), 'pcesvn' => 7, 'cpusvn' => str_repeat("\x07", 16)],
            Intel::extractPckFmspcAndTcb($ext));
    }
}
