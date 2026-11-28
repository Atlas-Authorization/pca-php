<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bbs;
use Atlas\Pca\Bls12;
use PHPUnit\Framework\TestCase;

/** BBS key, signature and proof refusal paths: scalar ranges, size limits, index validation, blinding randomness. Needs ext-ffi and PCA_BLST_LIB. */
final class CredSurvivorKill23BbsTest extends TestCase
{
    private const Z32 = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    protected function setUp(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst)');
        }
    }

    protected function tearDown(): void
    {
        Bbs::$randomHook = null;
    }

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

    /** @return array{0:\GMP,1:string,2:string} sk, pk, signature over ['a', 'b'] */
    private static function keys(): array
    {
        $sk = Bbs::keyGen(str_repeat("\1", 32));
        $pk = Bbs::skToPk($sk);
        return [$sk, $pk, Bbs::sign($sk, $pk, '', ['a', 'b'])];
    }

    /** Fixed blinding scalars (5 + undisclosed count). @return list<\GMP> */
    private static function fixed(int $n): array
    {
        return array_map(static fn(int $i) => gmp_init($i + 2), range(0, $n - 1));
    }

    /** A non-string message, too many generators and over-long key info are refused with their exact messages. */
    public function testArgumentLimits(): void
    {
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Bbs::hashToScalar(5, 'd'), $ia, 'bbs: message must be bytes');
        $this->throws(fn() => Bbs::createGenerators(1026), $ia, 'bbs: at most 1024 messages are supported');
        $this->assertInstanceOf(\GMP::class, Bbs::keyGen(str_repeat("\1", 32), str_repeat('i', 65535)));
        $this->throws(fn() => Bbs::keyGen(str_repeat("\1", 32), str_repeat('i', 65536)), $ia, 'bbs: key info must be at most 65535 octets');
    }

    /** generateKeyPair is public, draws exactly 32 bytes, derives the key from them and refuses an all-zero draw. */
    public function testGenerateKeyPair(): void
    {
        $asked = [];
        Bbs::$randomHook = static function (int $n) use (&$asked): string {
            $asked[] = $n;
            return str_repeat("\1", $n);
        };
        $kp = Bbs::generateKeyPair();
        $this->assertSame([32], $asked);
        $this->assertSame(['sk', 'pk'], array_keys($kp));
        $this->assertSame(0, gmp_cmp(Bbs::keyGen(str_repeat("\1", 32)), $kp['sk']));
        $this->assertSame(Bbs::skToPk($kp['sk']), $kp['pk']);
        Bbs::$randomHook = static fn(int $n): string => str_repeat("\0", $n);
        $this->throws(fn() => Bbs::generateKeyPair(), \RuntimeException::class, 'bbs: entropy source returned all zeros (RNG failure); refusing to generate a key');
    }

    /** skFromBytes / skToBytes are public: 32 octets in [1, r) round-trip; anything else is refused. */
    public function testSecretKeyBytes(): void
    {
        [$sk] = self::keys();
        $this->assertSame(0, gmp_cmp($sk, Bbs::skFromBytes(Bbs::skToBytes($sk))));
        $this->assertSame(1, gmp_intval(Bbs::skFromBytes(Bls12::i2osp(1, 32))));
        $rm1 = gmp_sub(Bls12::r(), 1);
        $this->assertSame(0, gmp_cmp($rm1, Bbs::skFromBytes(Bls12::i2osp($rm1, 32))));
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Bbs::skFromBytes(5), $ia, 'bbs: SK must be 32 octets');
        $this->throws(fn() => Bbs::skFromBytes('abc'), $ia, 'bbs: SK must be 32 octets');
        $this->throws(fn() => Bbs::skFromBytes(self::Z32), $ia, 'bbs: SK out of range');
        $this->throws(fn() => Bbs::skFromBytes(Bls12::i2osp(Bls12::r(), 32)), $ia, 'bbs: SK out of range');
    }

    /** An unknown element kind is refused by the serializer. */
    public function testSerializeUnknownKind(): void
    {
        $f = new \ReflectionMethod(Bbs::class, 'serialize');
        $this->throws(fn() => $f->invoke(null, [['x', 1]]), \InvalidArgumentException::class, 'bbs: cannot serialize');
    }

    /** Sign refuses SK 0 and SK = r; messages are taken in order whatever their keys. */
    public function testSign(): void
    {
        [$sk, $pk, $sig] = self::keys();
        $this->throws(fn() => Bbs::sign(gmp_init(0), $pk, '', ['a']), \InvalidArgumentException::class, 'bbs: SK out of range');
        $this->throws(fn() => Bbs::sign(Bls12::r(), $pk, '', ['a']), \InvalidArgumentException::class, 'bbs: SK out of range');
        $this->assertSame($sig, Bbs::sign($sk, $pk, '', ['x' => 'a', 'y' => 'b']));
        $this->assertTrue(Bbs::verify($pk, $sig, '', ['a', 'b']));
    }

    /** A signature scalar e = r is malformed; 1024 messages are verified (not refused), 1025 are refused. */
    public function testVerifyBounds(): void
    {
        [, $pk, $sig] = self::keys();
        $a = substr($sig, 0, 48);
        $this->assertSame(['ok' => false, 'reason' => 'malformed-signature'], Bbs::verifyDetailed($pk, $a . Bls12::i2osp(Bls12::r(), 32), '', ['a', 'b']));
        $this->assertSame(['ok' => false, 'reason' => 'pairing-mismatch'], Bbs::verifyDetailed($pk, $a . Bls12::i2osp(1, 32), '', ['a', 'b']));
        $this->assertSame(['ok' => false, 'reason' => 'pairing-mismatch'], Bbs::verifyDetailed($pk, $sig, '', array_fill(0, 1024, 'm')));
        $this->assertSame(['ok' => false, 'reason' => 'disclosed-length-mismatch'], Bbs::verifyDetailed($pk, $sig, '', array_fill(0, 1025, 'm')));
    }

    /** ProofGen validates the disclosed indexes with exact messages. */
    public function testProofGenIndexes(): void
    {
        [, $pk, $sig] = self::keys();
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], [2]), $ia, 'bbs: disclosed index 2 out of range [0, 2)');
        $this->throws(fn() => Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], ['a']), $ia, 'bbs: disclosed index string out of range [0, 2)');
        $this->throws(fn() => Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], [0, 0]), $ia, 'bbs: duplicate disclosed index 0');
    }

    /** Fixed blinding scalars: the count is checked, r1 and r2 must be non-zero, and their keys are ignored. */
    public function testProofGenFixedScalars(): void
    {
        [, $pk, $sig] = self::keys();
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], [0], self::fixed(3)), $ia, 'bbs: expected 6 random scalars, got 3');
        $rs = self::fixed(6);
        $rs[1] = gmp_init(0);
        $this->throws(fn() => Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], [0], $rs), $ia, 'bbs: random blinding scalars r1, r2 must be non-zero (RNG failure?)');
        $p = Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], [0], self::fixed(6));
        $this->assertSame($p, Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], [0], array_combine(range(10, 15), self::fixed(6))));
        $this->assertTrue(Bbs::proofVerify($pk, $p, '', '', ['a'], [0]));
        $this->assertTrue(Bbs::proofVerify($pk, $p, '', '', ['a'], [7 => 0])); // index keys are ignored
    }

    /** Without fixed scalars ProofGen draws exactly 5 + undisclosed 48-byte values, and the proof verifies. */
    public function testProofGenDraws(): void
    {
        [, $pk, $sig] = self::keys();
        $asked = [];
        Bbs::$randomHook = static function (int $n) use (&$asked): string {
            if (count($asked) >= 50) {
                throw new \LogicException('proofGen kept drawing');
            }
            $asked[] = $n;
            return hash('sha384', 'r' . count($asked), true);
        };
        $p = Bbs::proofGen($pk, $sig, '', '', ['a', 'b'], [0]);
        $this->assertSame([48, 48, 48, 48, 48, 48], $asked);
        $this->assertTrue(Bbs::proofVerify($pk, $p, '', '', ['a'], [0]));
    }

    /** ProofVerify: a non-string proof and a scalar equal to r are malformed; 1024 messages are checked, not refused. */
    public function testProofVerifyBounds(): void
    {
        [, $pk, $sig] = self::keys();
        $pt = substr($sig, 0, 48);
        $proof = static fn(string $eHat, int $u): string => $pt . $pt . $pt . $eHat . self::Z32 . self::Z32 . str_repeat(self::Z32, $u) . self::Z32;
        $this->assertSame(['ok' => false, 'reason' => 'malformed-proof'], Bbs::proofVerifyDetailed($pk, 5, '', '', [], []));
        $this->assertSame(['ok' => false, 'reason' => 'malformed-proof'], Bbs::proofVerifyDetailed($pk, $proof(Bls12::i2osp(Bls12::r(), 32), 0), '', '', [], []));
        $this->assertSame(['ok' => false, 'reason' => 'challenge-mismatch'], Bbs::proofVerifyDetailed($pk, $proof(self::Z32, 0), '', '', [], []));
        $this->assertSame(['ok' => false, 'reason' => 'challenge-mismatch'], Bbs::proofVerifyDetailed($pk, $proof(self::Z32, 1024), '', '', [], []));
        $this->assertSame(['ok' => false, 'reason' => 'malformed-proof'], Bbs::proofVerifyDetailed($pk, $proof(self::Z32, 1025), '', '', [], []));
    }
}
