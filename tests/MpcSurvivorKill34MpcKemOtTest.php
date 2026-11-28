<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcKemOt;
use Atlas\Pca\MpcMlKem768;
use Atlas\Pca\MpcOtRandom;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcKemOt: the pad length bound at exactly 1 MiB, the private XOR and opening-count refusals, the length checks
 * before any KEM work (everywhere) and the message checks after key generation (ML-KEM-768 via OpenSSL >= 3.5 over ext-ffi).
 */
final class MpcSurvivorKill34MpcKemOtTest extends TestCase
{
    private function needKem(): void
    {
        if (!MpcMlKem768::available()) {
            $this->markTestSkipped('ML-KEM-768 needs OpenSSL >= 3.5 via ext-ffi');
        }
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame($class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected $class: $msg");
    }

    private static function rng(): MpcOtRandom
    {
        return MpcOtRandom::fromSeed(gmp_init(34));
    }

    /** A pad of exactly 1 MiB is produced; one byte more is refused. */
    public function testPadLengthUpToOneMiB(): void
    {
        $this->assertSame(1 << 20, strlen(MpcKemOt::kemOtPad(0, 1, 'ss', 1 << 20)));
        self::refuses(\InvalidArgumentException::class, 'kemOtPad: length must be an integer in [0, 1 MiB]', static fn() => MpcKemOt::kemOtPad(0, 1, 'ss', (1 << 20) + 1));
    }

    /** The internal XOR refuses operands of different lengths instead of truncating. */
    public function testXorRefusesUnequalLengths(): void
    {
        $xor = new \ReflectionMethod(MpcKemOt::class, 'xor');
        self::refuses(\InvalidArgumentException::class, 'kem-ot: XOR length mismatch', static fn() => $xor->invoke(null, 'a', 'bc'));
        $this->assertSame("\x03", $xor->invoke(null, "\x01", "\x02"));
    }

    /** The sender refuses an opening with another number of key pairs than commitments. */
    public function testCheckOpeningRefusesACountMismatch(): void
    {
        $check = new \ReflectionMethod(MpcKemOt::class, 'checkOpening');
        self::refuses(\InvalidArgumentException::class, 'kemBaseOtMalSend: commitments/publicKeys length mismatch', static fn() => $check->invoke(null, 'rn', [str_repeat('0', 32)], []));
    }

    /** Every entry point and its pluggable closure refuse a messages/choices length mismatch before any key is generated. */
    public function testLengthMismatchBeforeAnyKemWork(): void
    {
        self::refuses(\InvalidArgumentException::class, 'kemBaseOT: messages/choices length mismatch', static fn() => MpcKemOt::kemBaseOT([['a', 'b']], [], self::rng()));
        self::refuses(\InvalidArgumentException::class, 'kemBaseOT: messages/choices length mismatch', static fn() => (MpcKemOt::withKemBaseOt())([], [0], self::rng()));
        self::refuses(\InvalidArgumentException::class, 'kemBaseOtMal: messages/choices length mismatch', static fn() => MpcKemOt::kemBaseOtMal([['a', 'b']], [], self::rng()));
        self::refuses(\InvalidArgumentException::class, 'kemBaseOtMal: messages/choices length mismatch', static fn() => (MpcKemOt::withKemBaseOtMal())([], [0], self::rng()));
    }

    /** With keys generated, unequal message pairs are refused by both transfers, and an opening that drops a key pair is refused. */
    public function testMessageChecksAfterKeyGeneration(): void
    {
        $this->needKem();
        self::refuses(\InvalidArgumentException::class, 'kemBaseOtSend (index 0): the two messages must be equal length', static fn() => MpcKemOt::kemBaseOT([['a', 'bb']], [0], self::rng()));
        self::refuses(\InvalidArgumentException::class, 'kemBaseOtMalSend (index 0): the two messages must be equal length', static fn() => MpcKemOt::kemBaseOtMal([['a', 'bb']], [1], self::rng()));
        self::refuses(\InvalidArgumentException::class, 'kemBaseOtMalSend: messages/commitments/publicKeys length mismatch',
            static fn() => MpcKemOt::kemBaseOtMal([['a', 'b']], [0], self::rng(), ['tamperOpenedKeys' => static fn(array $pk): array => []]));
        // control: the honest transfers deliver the chosen messages
        $this->assertSame(['b'], MpcKemOt::kemBaseOT([['a', 'b']], [1], self::rng())['received']);
        $this->assertSame(['a'], MpcKemOt::kemBaseOtMal([['a', 'b']], [0], self::rng())['received']);
    }
}
