<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AccumulatorError;
use Atlas\Pca\MemorySpentLeafStore;
use Atlas\Pca\Pca;
use Atlas\Pca\Ratchet;
use Atlas\Pca\RatchetBigint;
use Atlas\Pca\RatchetError;
use Atlas\Pca\RiskQuantizer;
use Atlas\Pca\SpentLeafStore;
use PHPUnit\Framework\TestCase;

/** Ratchet: index encoding, refusal messages, store records, strict Ed25519 keys, attested-budget shapes and risk rounding. */
final class CredSurvivorKill23RatchetTest extends TestCase
{
    private const ROOT = 'root-commitment';

    private function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail("expected $class: $msg");
    }

    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/ratchet-kill23', true);
    }

    private static function nullifier(int $i): string
    {
        $r = self::ROOT;
        return Pca::b64u(hash('sha256', "atlas-pca-ratchet/nullifier/v1\0" . pack('N', strlen($r)) . $r . pack('J', $i), true));
    }

    /** The index is the 64-bit big-endian two's complement of BigInt(x), for numbers, signed / padded strings and bigints. */
    public function testIndexEncoding(): void
    {
        foreach ([3, -3, -256] as $i) {
            $this->assertSame(self::nullifier($i), Ratchet::leafNullifier(self::ROOT, $i), (string)$i);
        }
        $this->assertSame(self::nullifier(-3), Ratchet::leafNullifier(self::ROOT, '-3'));
        $this->assertSame(self::nullifier(3), Ratchet::leafNullifier(self::ROOT, ' 3 '));
        $this->assertSame(self::nullifier(3), Ratchet::leafNullifier(self::ROOT, '003'));
        $this->assertSame(self::nullifier(0), Ratchet::leafNullifier(self::ROOT, '0'));
        $this->assertSame(self::nullifier(3), Ratchet::leafNullifier(self::ROOT, RatchetBigint::of(3)));
        $this->throws(fn() => Ratchet::leafNullifier(self::ROOT, 'x'), \InvalidArgumentException::class, 'Cannot convert the string to a BigInt');
        $this->throws(fn() => Ratchet::leafNullifier(self::ROOT, null), \TypeError::class, 'Cannot convert the value to a BigInt');
        foreach ([1.5, INF] as $x) {
            $this->throws(fn() => Ratchet::leafNullifier(self::ROOT, $x), \RangeException::class, 'The number cannot be converted to a BigInt because it is not an integer');
        }
    }

    /** Refusals carry their messages; a bad seed is reported only after the depth (20) is accepted. */
    public function testRefusalMessages(): void
    {
        $re = RatchetError::class;
        $this->throws(fn() => Ratchet::deriveRatchetRoot(self::seed(), 21), $re, 'depth must be an integer in [1, 20]');
        $this->throws(fn() => Ratchet::deriveRatchetRoot('short', 20), $re, 'seed must be at least 32 bytes');
        $state = Ratchet::deriveRatchetRoot(self::seed(), 1)['state'];
        $this->throws(fn() => Ratchet::signAtLeaf($state, 2, 'm'), $re, 'the leaf is out of range [0, 2)');
        $this->throws(fn() => Ratchet::counterToLeafIndex(0, 0), $re, 'depth must be an integer in [1, 20]');
        $this->throws(fn() => Ratchet::counterToLeafIndex(8, 3), $re, 'counter exceeds the ratchet capacity 2^3');
        $this->throws(fn() => Ratchet::leafIndexForAction(5, 3), \TypeError::class, 'leafIndexForAction: the action must be an object');
    }

    /** The covering is keyed "level:index"; debug output shows depth and root only. */
    public function testStateShape(): void
    {
        $r = Ratchet::deriveRatchetRoot(self::seed(), 1);
        $state = $r['state'];
        $this->assertSame(['0:0'], array_keys($state->covering));
        $this->assertSame(['1:1'], array_keys(Ratchet::signAtLeaf($state, 0, 'm')['newState']->covering));
        $this->assertSame(['depth' => 1, 'rootCommitment' => $r['rootCommitment']], $state->__debugInfo());
    }

    /** The memory store returns the first record on a repeat claim; a store reply without a record is a store error. */
    public function testStores(): void
    {
        $s = new MemorySpentLeafStore();
        $this->assertSame(['first' => true], $s->claim('n', 'r1'));
        $this->assertSame(['first' => false, 'record' => 'r1'], $s->claim('n', 'r2'));
        $r = Ratchet::deriveRatchetRoot(self::seed(), 1);
        $sig = Ratchet::signAtLeaf($r['state'], 0, 'm')['signature'];
        $this->assertFalse(Ratchet::verifyLeafSignature(5, 0, 'm', $sig));
        $this->assertTrue(Ratchet::verifyLeafSignature($r['rootCommitment'], 0, 'm', $sig));
        $bad = new class implements SpentLeafStore {
            public function claim(string $nullifier, string $record): array
            {
                return ['first' => false];
            }
        };
        $this->assertSame(['ok' => false, 'reason' => 'store-error'], Ratchet::verifyLeafSignatureOnce($r['rootCommitment'], 0, 'm', $sig, $bad));
    }

    /** A mixed-order key (prime-order key plus the order-2 point) is refused even when the signature equation holds. */
    public function testMixedOrderKeyRefused(): void
    {
        $seed = self::seed();
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $pk = sodium_crypto_sign_publickey($kp);
        $p = gmp_sub(gmp_pow(2, 255), 19);
        $yb = $pk;
        $yb[31] = chr(ord($yb[31]) & 127);
        $mixed = strrev(str_pad(gmp_export(gmp_sub($p, gmp_import(strrev($yb)))), 32, "\0", STR_PAD_LEFT)); // (x, y) + (0, -1) = (-x, -y)
        $mixed[31] = chr(ord($mixed[31]) | ((ord($pk[31]) >> 7 ^ 1) << 7));
        $msgOf = new \ReflectionMethod(Ratchet::class, 'attestMessage');
        $found = null;
        for ($i = 0; $i < 64 && $found === null; $i++) {
            $msg = $msgOf->invoke(null, "d$i", 'c');
            $sig = sodium_crypto_sign_detached($msg, $seed . $mixed); // signs with the embedded (mixed) key in the challenge
            if (sodium_crypto_sign_verify_detached($sig, $msg, $mixed)) {
                $found = ["d$i", $sig, sodium_crypto_sign_detached($msg, sodium_crypto_sign_secretkey($kp))];
            }
        }
        if ($found === null) {
            $this->markTestSkipped('this libsodium does not sign under an embedded public key');
        }
        $this->assertFalse(Ratchet::verifyRiskAttestation('c', ['actionDigest' => $found[0], 'sig' => Pca::b64u($found[1])], Pca::b64u($mixed)));
        $this->assertTrue(Ratchet::verifyRiskAttestation('c', ['actionDigest' => $found[0], 'sig' => Pca::b64u($found[2])], Pca::b64u($pk)));
    }

    /** Items keyed by anything but 0..n-1 are refused before any lookup. */
    public function testAttestedBudgetNeedsLists(): void
    {
        $item = ['attestation' => ['actionDigest' => 'd', 'sig' => 'x'], 'commitment' => 'c'];
        $this->assertFalse(Ratchet::verifyAttestedBudget(['x' => $item], ['d'], 'pk', 1, null));
        $this->assertFalse(Ratchet::verifyAttestedBudget([$item], ['x' => 'd'], 'pk', 1, null));
    }

    /** The quantizer refuses a boolean with its own error and rounds one millionth of a unit up to one unit. */
    public function testQuantizer(): void
    {
        $this->throws(fn() => (new RiskQuantizer())->next(true), AccumulatorError::class, 'risk must be a finite number >= 0');
        $this->assertSame('1', (new RiskQuantizer())->next(1e-9)->decimal);
    }

    /** Above 5e8 units the float tolerance exceeds half a unit: the nearest unit (half rounds up) is kept. */
    public function testRiskToUnitsLarge(): void
    {
        $this->assertSame('2000000001', Ratchet::riskToUnits(2000000.0005)->decimal);
        $this->assertSame('2000000001', Ratchet::riskToUnits(2000000.0007)->decimal);
        $this->assertSame('2000000000', Ratchet::riskToUnits(2000000.0004999998)->decimal);
    }
}
