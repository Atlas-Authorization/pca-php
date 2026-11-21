<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ed25519Core;
use Atlas\Pca\Frost;
use PHPUnit\Framework\TestCase;

/** Point validation is fail-closed whatever libsodium build answers its validity query: B + T (T of order 2) is mixed-order and must be refused. */
final class Ed25519MixedOrderTest extends TestCase
{
    private static function base(): string
    {
        return "\x58" . str_repeat("\x66", 31);
    }

    public function testMixedOrderAndDegeneratePointsAreRefused(): void
    {
        $t2 = "\xec" . str_repeat("\xff", 30) . "\x7f"; // (0, -1), order 2
        $mixed = Ed25519Core::add(self::base(), $t2);
        $id = "\x01" . str_repeat("\0", 31);
        $nonCanonical = "\xee" . str_repeat("\xff", 30) . "\x7f"; // y = p + 1
        $neg = substr(self::base(), 0, 31) . "\xe6";
        $this->assertTrue(Ed25519Core::isSafePoint(self::base()));
        $this->assertTrue(Ed25519Core::isSafePoint($neg));
        $this->assertSame($neg, Frost::decodeSafePoint($neg));
        foreach ([$mixed, $t2, $id, str_repeat("\0", 32), $nonCanonical] as $bad) {
            $this->assertFalse(Ed25519Core::isSafePoint($bad));
            $this->assertFalse(Ed25519Core::isValidPoint($bad));
            try {
                Frost::decodeSafePoint($bad);
                $this->fail('a bad point was accepted');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
