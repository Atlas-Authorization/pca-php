<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentAttest.php';

use Atlas\Pca\IntentAttest;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/**
 * group 33b: the map digest covers the JSON round trip of every number (JSON.parse(JSON.stringify(m)) in the reference), so a native
 * float reads as its Number::toString form: 1e15 is the safe integer 1000000000000000, 1e16 is an unsafe integer and is refused.
 */
final class GuardSurvivorKill33bIntentAttestTest extends TestCase
{
    private static function map(mixed $x): Obj
    {
        return Obj::of(['v' => new Num('1'), 'kind' => 'pca-intent-map', 'intent_ref' => null,
            'metrics' => Obj::of(['fidelity_est_ppm' => new Num('5'), 'residual_risk_ppm' => new Num('0')]), 'x' => $x]);
    }

    private static function digest(mixed $x): string
    {
        return IntentAttest::signIntentMapAttestation(self::map($x), new KeyPair(hash('sha256', 'atlas-pca-conformance/g33b-intent', true)), 10)->get('map_digest');
    }

    public function testNativeNumbersDigestAsTheirJsonRoundTrip(): void
    {
        $this->assertSame(self::digest(new Num('1000000000000000')), self::digest(1e15));
        $this->assertSame(self::digest([new Num('1000000000000000')]), self::digest([1e15]));
        $this->assertSame(self::digest(new Num('9007199254740991')), self::digest(9007199254740991.0));
        $this->assertSame(self::digest(new Num('1.5')), self::digest(1.5));
        $this->assertSame(self::digest(new Num('5')), self::digest(5.0));
        // a Num parsed in a non-shortest form digests as JSON.parse reads it
        $this->assertSame(self::digest(new Num('1.5')), self::digest(new Num('1.50')));
    }

    public function testAnUnsafeIntegerIsRefused(): void
    {
        try {
            self::digest(1e16);
            $this->fail('an unsafe integer was digested');
        } catch (\Atlas\Pca\JsonError $e) {
            $this->assertSame('integer outside the safe range', $e->getMessage());
        }
    }
}
