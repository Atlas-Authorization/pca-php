<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcEc;
use Atlas\Pca\MpcHybridOt;
use Atlas\Pca\MpcHybridOtAbort;
use Atlas\Pca\MpcOtRandom;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcHybridOt: the transfer-key length bounds at exactly 0 and 1 MiB, the sender / receiver length refusals, the
 * commitment check, and the public entry points (the hash parts need no curve or KEM library).
 */
final class MpcSurvivorKill34MpcHybridOtTest extends TestCase
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

    /** The key length is accepted on [0, 1 MiB] inclusive and refused just outside on both sides. */
    public function testTransferKeyLengthBounds(): void
    {
        $msg = 'hybridTransferKey: length must be an integer in [0, 1 MiB]';
        $this->assertSame('', MpcHybridOt::hybridTransferKey('sid', 0, 0, 'e', 'k', 0));
        $this->assertSame(1 << 20, strlen(MpcHybridOt::hybridTransferKey('sid', 0, 0, 'e', 'k', 1 << 20)));
        $k40 = MpcHybridOt::hybridTransferKey('sid', 0, 0, 'e', 'k', 40);
        $this->assertSame(40, strlen($k40));
        $this->assertSame(substr($k40, 0, 7), MpcHybridOt::hybridTransferKey('sid', 0, 0, 'e', 'k', 7), 'one counter-mode stream, cut to length');
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcHybridOt::hybridTransferKey('sid', 0, 0, 'e', 'k', -1));
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcHybridOt::hybridTransferKey('sid', 0, 0, 'e', 'k', (1 << 20) + 1));
    }

    /** The session id is 32 bytes and binds the KEM session id. */
    public function testSessionIdBindsTheKemSid(): void
    {
        $a = MpcHybridOt::hybridSessionId('kem-a', MpcEc::base());
        $this->assertSame(32, strlen($a));
        $this->assertSame($a, MpcHybridOt::hybridSessionId('kem-a', MpcEc::base()));
        $this->assertNotSame($a, MpcHybridOt::hybridSessionId('kem-b', MpcEc::base()));
    }

    /** Encrypt then recover round-trips the chosen message; a commitment that does not match aborts with the exact reason. */
    public function testRoundTripAndCommitmentAbort(): void
    {
        $ec = [['e0', 'e1'], ['f0', 'f1']];
        $kem = [['k0', 'k1'], ['l0', 'l1']];
        $sender = MpcHybridOt::hybridSenderEncrypt('sid', [['aaaa', 'bbbb'], ['cc', 'dd']], $ec, $kem);
        $this->assertSame(['bbbb', 'cc'], MpcHybridOt::hybridReceiverRecover('sid', [1, 0], $sender, ['e1', 'f0'], ['k1', 'l0']));
        $bad = $sender;
        $bad['commitments'][1][0] = str_repeat("\0", 32);
        self::refuses(MpcHybridOtAbort::class, 'hybrid base OT (index 1): sender ciphertext inconsistent with its commitment; aborting',
            static fn() => MpcHybridOt::hybridReceiverRecover('sid', [1, 0], $bad, ['e1', 'f0'], ['k1', 'l0']));
    }

    /** The sender refuses a KEM-secret list of another length (even when the EC list matches) and unequal message pairs. */
    public function testSenderRefusals(): void
    {
        self::refuses(\InvalidArgumentException::class, 'hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch',
            static fn() => MpcHybridOt::hybridSenderEncrypt('sid', [['a', 'b']], [['e0', 'e1']], []));
        self::refuses(\InvalidArgumentException::class, 'hybridSenderEncrypt: messages/ecSecrets/kemSecrets length mismatch',
            static fn() => MpcHybridOt::hybridSenderEncrypt('sid', [['a', 'b']], [], [['k0', 'k1']]));
        self::refuses(\InvalidArgumentException::class, 'hybridSenderEncrypt (index 0): the two messages must be equal length',
            static fn() => MpcHybridOt::hybridSenderEncrypt('sid', [['a', 'bb']], [['e0', 'e1']], [['k0', 'k1']]));
    }

    /** The receiver refuses when any ONE of the four lists has another length than the choices. */
    public function testReceiverRefusesAnySingleLengthMismatch(): void
    {
        $sender = MpcHybridOt::hybridSenderEncrypt('sid', [['aa', 'bb']], [['e0', 'e1']], [['k0', 'k1']]);
        $msg = 'hybridReceiverRecover: length mismatch';
        $noEnc = ['encrypted' => [], 'commitments' => $sender['commitments']];
        $noCom = ['encrypted' => $sender['encrypted'], 'commitments' => []];
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcHybridOt::hybridReceiverRecover('sid', [0], $noEnc, ['e0'], ['k0']));
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcHybridOt::hybridReceiverRecover('sid', [0], $noCom, ['e0'], ['k0']));
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcHybridOt::hybridReceiverRecover('sid', [0], $sender, [], ['k0']));
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcHybridOt::hybridReceiverRecover('sid', [0], $sender, ['e0'], []));
    }

    /** hybridBaseOT and its pluggable closure refuse a messages/choices length mismatch before any OT runs. */
    public function testBaseOtLengthMismatch(): void
    {
        $msg = 'hybridBaseOT: messages/choices length mismatch';
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => MpcHybridOt::hybridBaseOT([['a', 'b']], [], MpcOtRandom::fromSeed(gmp_init(1))));
        $fn = MpcHybridOt::withHybridBaseOt();
        self::refuses(\InvalidArgumentException::class, $msg, static fn() => $fn([], [1], MpcOtRandom::fromSeed(gmp_init(1))));
    }
}
