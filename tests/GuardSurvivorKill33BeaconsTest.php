<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Beacons.php';

use Atlas\Pca\Beacons;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Beacons.php: issue's validity text and secret coercion, message's read of v, string issuers, and a string clock. */
final class GuardSurvivorKill33BeaconsTest extends TestCase
{
    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/g33-beacon', true);
    }

    private static function beacon(int $iat, mixed $secret = null): Obj
    {
        return Beacons::issue(Obj::of(['issuerSecret' => $secret ?? self::seed(), 'instance' => 'i', 'seq' => new Num('0'), 'issuedAt' => new Num((string)$iat)]));
    }

    /** A validity of 0 ms is refused with the bound in the text. */
    public function testValidityText(): void
    {
        try {
            Beacons::issue(Obj::of(['issuerSecret' => self::seed(), 'instance' => 'i', 'seq' => new Num('0'), 'issuedAt' => new Num('0'), 'validityMs' => new Num('0')]));
            $this->fail('a zero validity was issued');
        } catch (\RangeException $e) {
            $this->assertSame('issueLivenessBeacon: validity must be in (0, 3600000] ms', $e->getMessage());
        }
    }

    /** A Stringable issuer secret is read as its seed string. */
    public function testStringableSecret(): void
    {
        $s = new class(self::seed()) implements \Stringable {
            public function __construct(private string $seed)
            {
            }

            public function __toString(): string
            {
                return $this->seed;
            }
        };
        $this->assertSame((new KeyPair(self::seed()))->public, self::beacon(0, $s)->get('issuer'));
    }

    /** The signed bytes of a null beacon are the reference's TypeError on reading v. */
    public function testMessageOfNull(): void
    {
        try {
            Beacons::message(null);
            $this->fail('a null beacon had a message');
        } catch (\TypeError $e) {
            $this->assertSame("Cannot read properties of null (reading 'v')", $e->getMessage());
        }
    }

    /** A string issuer pin is a substring test: a string that does not contain the issuer does not pin it. */
    public function testStringIssuersAreASubstringTest(): void
    {
        $b = self::beacon(0);
        $pk = $b->get('issuer');
        $this->assertSame(['ok' => true], Beacons::verify($b, "pins:$pk;", 1000, 'i'), 'control');
        $this->assertSame(['ok' => false, 'reason' => 'issuer not pinned'], Beacons::verify($b, 'zzz', 1000, 'i'));
    }

    /** A string clock concatenates with the skew, as in the reference: '1000' becomes 100030000. */
    public function testStringClockConcatenatesTheSkew(): void
    {
        $b1 = self::beacon(100000000);
        $this->assertSame(['ok' => true], Beacons::verify($b1, [$b1->get('issuer')], '1000', 'i'));
        $b2 = self::beacon(200000000);
        $this->assertSame(['ok' => false, 'reason' => 'not yet valid'], Beacons::verify($b2, [$b2->get('issuer')], '1000', 'i'));
    }
}
