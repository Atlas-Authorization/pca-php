<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Ocsp;
use PHPUnit\Framework\TestCase;

/** H3: the OCSP time walk stops at depth 100 / 10000 nodes (asn1js's bounds) instead of recursing as deep as the input. */
final class K05HardOcspDepthTest extends TestCase
{
    private static function len(int $n): string
    {
        return $n < 0x80 ? chr($n) : ($n < 0x100 ? "\x81" . chr($n) : ($n < 0x10000 ? "\x82" . pack('n', $n) : ($n < 0x1000000 ? "\x83" . substr(pack('N', $n), 1) : pack('CN', 0x84, $n))));
    }

    /** `$levels` nested SEQUENCEs around an empty one, built in one pass (no quadratic copying). */
    private static function nested(int $levels): string
    {
        $sizes = [2]; // the innermost: 30 00
        for ($i = 1; $i < $levels; $i++) {
            $inner = $sizes[$i - 1];
            $sizes[$i] = 1 + strlen(self::len($inner)) + $inner;
        }
        $out = [];
        for ($i = $levels - 1; $i >= 1; $i--) {
            $out[] = "\x30" . self::len($sizes[$i - 1]);
        }
        $out[] = "\x30\x00";
        return implode('', $out);
    }

    /** @return array{0: bool, 1: bool, 2: int} [walk result, tooDeep, nodes] */
    private static function walk(string $der): array
    {
        $nodes = 0;
        $tooDeep = false;
        $args = [$der, 0, strlen($der), 1, &$nodes, &$tooDeep];
        $ok = (new \ReflectionMethod(Ocsp::class, 'allTimesWellFormed'))->invokeArgs(null, $args);
        return [$ok, $tooDeep, $nodes];
    }

    public function testTheBuilderMakesTheNestingItClaims(): void
    {
        $this->assertSame("\x30\x02\x30\x00", self::nested(2));
        $this->assertSame("\x30\x04\x30\x02\x30\x00", self::nested(3));
    }

    public function testNestingUpToOneHundredIsWalked(): void
    {
        [$ok, $deep, $nodes] = self::walk(self::nested(100));
        $this->assertTrue($ok);
        $this->assertFalse($deep);
        $this->assertSame(100, $nodes);
    }

    public function testNestingPastOneHundredIsRefused(): void
    {
        foreach ([101, 150] as $n) {
            [$ok, $deep] = self::walk(self::nested($n));
            $this->assertFalse($ok, "depth $n");
            $this->assertTrue($deep, "depth $n");
        }
    }

    public function testAVeryDeepInputStopsAtTheCapWithoutDeepRecursion(): void
    {
        $der = self::nested(200000);
        [$ok, $deep, $nodes] = self::walk($der);
        $this->assertFalse($ok);
        $this->assertTrue($deep);
        $this->assertLessThanOrEqual(102, $nodes);
    }

    public function testTheNodeCapIsTenThousand(): void
    {
        $flat = static fn(int $n): string => "\x30" . self::len($n * 2) . str_repeat("\x05\x00", $n);
        [$ok, $deep, $nodes] = self::walk($flat(9999));
        $this->assertTrue($ok);
        $this->assertFalse($deep);
        $this->assertSame(10000, $nodes);
        [$ok, $deep] = self::walk($flat(10000));
        $this->assertFalse($ok);
        $this->assertTrue($deep);
    }
}
