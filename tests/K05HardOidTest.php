<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Der;
use Atlas\Pca\Attest\DerError;
use Atlas\Pca\Attest\Tlv;
use PHPUnit\Framework\TestCase;

/**
 * H2: OID content and arc caps, and an exact decode of arcs wider than 63 bits. PHP ints wrap silently at 2^63, so an arc of 2^64 + 15
 * used to read as 15 and could alias a trusted OID. Expected strings were produced by an independent big-integer encoder.
 */
final class K05HardOidTest extends TestCase
{
    private static function decode(string $content): string
    {
        return Der::oidToDotted($content, new Tlv(0x06, 0, strlen($content)));
    }

    private static function refusal(string $content): string
    {
        try {
            self::decode($content);
        } catch (DerError $e) {
            return $e->getMessage();
        }
        return '(decoded)';
    }

    public function testOrdinaryOidsDecode(): void
    {
        $this->assertSame('2.5.29.19', self::decode("\x55\x1D\x13"));
        $this->assertSame('1.2.840.113549.1.1.11', self::decode(hex2bin('2a864886f70d01010b')));
        $this->assertSame('2.0', self::decode("\x50"));
        $this->assertSame('0.39', self::decode("\x27"));
        $this->assertSame('1.0', self::decode("\x28"));
        $this->assertSame('2.999', self::decode(hex2bin('8837')));
    }

    public function testAnArcAbove2To64IsNotWrapped(): void
    {
        $this->assertSame('1.3.6.1.4.1.18446744073709551631', self::decode(hex2bin('2b060104018280808080808080800f')));
        $this->assertNotSame('1.3.6.1.4.1.15', self::decode(hex2bin('2b060104018280808080808080800f')));
    }

    public function testTheIntAndStringPathsMeetAt2To56(): void
    {
        $this->assertSame('1.3.72057594037927935', self::decode(hex2bin('2bffffffffffffff7f')), '2^56 - 1: eight groups');
        $this->assertSame('1.3.72057594037927936', self::decode(hex2bin('2b818080808080808000')), '2^56: nine groups');
    }

    public function testAUuidArcUnderTwo25Decodes(): void
    {
        $this->assertSame('2.25.170141183460469231731687303719620034287', self::decode(hex2bin('6982808080808080808080808080808df5b6fd6f')));
    }

    public function testAFirstArcAbove2To56IsReducedByEighty(): void
    {
        $this->assertSame('2.72057594037927859', self::decode(hex2bin('818080808080808003')));
        $this->assertSame('2.5723139561382731421648218959748067199634971343994630395917245662839679433963763175796779926880028075281594658317056519161689776603185',
            self::decode(str_repeat("\x81", 63) . "\x01"), 'an arc of exactly 64 groups');
    }

    public function testTheGroupCapIs64PerArc(): void
    {
        $this->assertSame('extension OID has an oversized arc', self::refusal(str_repeat("\x81", 64) . "\x01"), '65 groups');
        $this->assertSame('extension OID has an oversized arc', self::refusal("\x2b" . str_repeat("\x81", 64) . "\x01"), '65 groups after the first byte');
        $this->assertNotSame('extension OID has an oversized arc', self::refusal("\x2b" . str_repeat("\x81", 63) . "\x01"));
    }

    public function testTheContentCapIs256Bytes(): void
    {
        $at = "\x2b" . str_repeat("\x01", 255); // 256 bytes of small arcs
        $this->assertSame(256, strlen($at));
        $this->assertSame('1.3' . str_repeat('.1', 255), self::decode($at));
        $this->assertSame('extension OID is too long', self::refusal($at . "\x01"));
        $this->assertSame('extension OID is too long', self::refusal(str_repeat("\x81", 300) . "\x01"));
    }

    public function testAHugeSingleArcIsRefusedFast(): void
    {
        $start = hrtime(true);
        $this->assertSame('extension OID is too long', self::refusal("\x2b" . str_repeat("\xff", 100000) . "\x7f"));
        $this->assertLessThan(500, (hrtime(true) - $start) / 1e6, 'refused before any arithmetic');
    }

    public function testMalformedShapesKeepTheirReasons(): void
    {
        $this->assertSame('extension OID is malformed', self::refusal(''));
        $this->assertSame('extension OID has a non-minimal arc', self::refusal("\x2b\x80\x01"));
        $this->assertSame('extension OID is truncated', self::refusal("\x2b\x81"));
        try {
            Der::oidToDotted("\x04\x01\x2b", new Tlv(0x04, 2, 3));
            $this->fail('a non-OID tag was decoded');
        } catch (DerError $e) {
            $this->assertSame('extension OID is malformed', $e->getMessage());
        }
    }
}
