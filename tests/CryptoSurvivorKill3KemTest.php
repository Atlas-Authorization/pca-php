<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Kem;
use PHPUnit\Framework\TestCase;

/** The KEM input checks: every malformed length and every non-reduced ML-KEM key is refused with its exact reason, before any primitive runs. */
final class CryptoSurvivorKill3KemTest extends TestCase
{
    private function refuses(string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\InvalidArgumentException $e) {
            $this->assertSame($msg, $e->getMessage());
            return;
        }
        $this->fail("no InvalidArgumentException: $msg");
    }

    /** A real X25519 public key (never low order). */
    private static function xPub(): string
    {
        return sodium_crypto_scalarmult_base(hash('sha256', 'atlas-pca-conformance/kem-kill-3', true));
    }

    /** Hybrid public key / randomness / ciphertext / secret key lengths, at both levels. */
    public function testHybridLengthRefusals(): void
    {
        $this->refuses('hybrid keygen: randomness must be 96 bytes (x25519 secret 32, ML-KEM seed d||z 64)', fn() => Kem::hybridKemKeygenDerand(str_repeat("\1", 95)));
        $this->refuses('hybridEncapsulate: public key must be 1216 bytes (got 5)', fn() => Kem::hybridEncapsulateDerand('short', str_repeat("\1", 64)));
        $this->refuses('hybridEncapsulate1024: public key must be 1600 bytes (got 1216)', fn() => Kem::hybridEncapsulate1024Derand(str_repeat("\0", 1216), str_repeat("\1", 64)));
        $pk = self::xPub() . str_repeat("\0", 1184);
        $this->refuses('hybridEncapsulate: randomness must be 64 bytes (ephemeral x25519 secret 32, ML-KEM message 32)', fn() => Kem::hybridEncapsulateDerand($pk, str_repeat("\1", 63)));
        $this->refuses('hybridDecapsulate: ciphertext must be 1120 bytes (got 1)', fn() => Kem::hybridDecapsulate('x', str_repeat("\1", 2432)));
        $this->refuses('hybridDecapsulate1024: ciphertext must be 1600 bytes (got 1120)', fn() => Kem::hybridDecapsulate1024(str_repeat("\1", 1120), str_repeat("\1", 3200)));
        $this->refuses('hybridDecapsulate: malformed secret key', fn() => Kem::hybridDecapsulate(self::xPub() . str_repeat("\1", 1088), 'short'));
    }

    /** A hybrid recipient key whose ML-KEM part fails the FIPS 203 modulus check is refused before encapsulation. */
    public function testHybridEncapsulationKeyModulusCheck(): void
    {
        $pk = self::xPub() . str_repeat("\xff", 1152) . str_repeat("\0", 32);
        $this->refuses('hybridEncapsulate: ML-KEM encapsulation key fails the FIPS 203 modulus check', fn() => Kem::hybridEncapsulateDerand($pk, str_repeat("\1", 64)));
    }

    /** X-Wing seed / public key / eseed / ciphertext lengths. */
    public function testXWingLengthRefusals(): void
    {
        $this->refuses('expandXWingKey: seed must be 32 bytes (got 5)', fn() => Kem::xwingKeygen('short'));
        $this->refuses('xwingEncapsulateDerand: public key must be 1216 bytes (got 1)', fn() => Kem::xwingEncapsulateDerand('x', str_repeat("\1", 64)));
        $this->refuses('xwingEncapsulateDerand: eseed must be 64 bytes (got 1)', fn() => Kem::xwingEncapsulateDerand(str_repeat("\0", 1216), 'x'));
        $this->refuses('xwingDecapsulate: ciphertext must be 1120 bytes (got 1)', fn() => Kem::xwingDecapsulate('x', str_repeat("\1", 32)));
    }

    /** The X-Wing modulus check covers all three ML-KEM-768 polynomials (a bad coefficient in the last one is refused). */
    public function testXWingModulusCheckCoversEveryPolynomial(): void
    {
        $pk = str_repeat("\0", 768) . str_repeat("\xff", 384) . str_repeat("\0", 32) . self::xPub();
        $this->refuses('xwingEncapsulateDerand: ML-KEM encapsulation key fails the FIPS 203 modulus check', fn() => Kem::xwingEncapsulateDerand($pk, str_repeat("\1", 64)));
    }

    /** The base64url decoders refuse non-canonical text. */
    public function testDecodersRefuseBadBase64url(): void
    {
        $this->refuses('invalid base64url', fn() => Kem::decodeHybridPublicKey('!!'));
        $this->refuses('invalid base64url', fn() => Kem::decodeXWingCiphertext('A'));
        $this->assertSame('ab', Kem::decodeHybridCiphertext('YWI'));
    }
}
