<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcBaseOtAbort;
use Atlas\Pca\MpcOt;
use Atlas\Pca\MpcOtRandom;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcOt: the XOR operand check and the base-OT shape refusals on both sides (pure, no curve library needed). */
final class MpcSurvivorKill34MpcOtTest extends TestCase
{
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

    /** The pad may be longer than the message (it is cut), never shorter. */
    public function testXorBytesNeedsALongEnoughPad(): void
    {
        self::refuses(\InvalidArgumentException::class, 'xorBytes: second operand shorter than the first', static fn() => MpcOt::xorBytes('ab', 'a'));
        $this->assertSame("\x03", MpcOt::xorBytes("\x01", "\x02\xff"));
    }

    /** The sender refuses a pad list of another length and a message pair longer than the 16-byte pad or of unequal lengths. */
    public function testSenderEncryptRefusals(): void
    {
        $pads = [[str_repeat("\1", 16), str_repeat("\2", 16)]];
        self::refuses(\InvalidArgumentException::class, 'baseOT: messages/pads length mismatch', static fn() => MpcOt::baseOtSenderEncrypt([['a', 'b']], []));
        $msg = 'baseOT: message pair 0 must be equal length and at most 16 bytes (pad width)';
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcOt::baseOtSenderEncrypt([[str_repeat('a', 17), str_repeat('b', 17)]], $pads));
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcOt::baseOtSenderEncrypt([['a', 'bb']], $pads));
        [$ct, $com] = MpcOt::baseOtSenderEncrypt([[str_repeat('a', 16), str_repeat('b', 16)]], $pads);
        $this->assertSame([str_repeat('b', 16)], MpcOt::baseOtReceiverDecrypt([1], [$pads[0][1]], $ct, $com));
    }

    /** The receiver aborts on a ciphertext/commitment/pad count that is not the choice count, and on a ciphertext pair of unequal length. */
    public function testReceiverDecryptShapeAborts(): void
    {
        $pad = str_repeat("\1", 16);
        self::refuses(MpcBaseOtAbort::class, 'base OT: ciphertext/commitment count does not match the number of choices; aborting',
            static fn() => MpcOt::baseOtReceiverDecrypt([0], [$pad], [], [['', '']]));
        self::refuses(MpcBaseOtAbort::class, 'base OT (index 0): malformed ciphertext shape; aborting',
            static fn() => MpcOt::baseOtReceiverDecrypt([0], [$pad], [['a', 'bb']], [['', '']]));
        self::refuses(MpcBaseOtAbort::class, 'base OT (index 0): malformed ciphertext shape; aborting',
            static fn() => MpcOt::baseOtReceiverDecrypt([0], [$pad], [[str_repeat('a', 17), str_repeat('b', 17)]], [['', '']]));
    }

    /** baseOT refuses a messages/choices length mismatch before any OT runs. */
    public function testBaseOtLengthMismatch(): void
    {
        self::refuses(\InvalidArgumentException::class, 'baseOT: messages/choices length mismatch', static fn() => MpcOt::baseOT([], [1], MpcOtRandom::fromSeed(gmp_init(34))));
    }
}
