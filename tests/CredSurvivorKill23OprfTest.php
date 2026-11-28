<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Oprf;
use Atlas\Pca\OprfRateWindowCounter;
use PHPUnit\Framework\TestCase;

/** RFC 9497 OPRF refusals (zero scalars, modes, framing), RFC 9496 decoding, and the PCA revocation / rate layer refusals. */
final class CredSurvivorKill23OprfTest extends TestCase
{
    private const Z = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    protected function tearDown(): void
    {
        Oprf::$randomHook = null;
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

    private static function g(): string
    {
        return Oprf::publicKeyFor(Oprf::serializeScalar(1));
    }

    private static function sk(): string
    {
        return Oprf::serializeScalar(7);
    }

    /** Non-bytes, over-long input, unknown modes and short seeds / scalars refuse with their exact messages. */
    public function testArgumentRefusals(): void
    {
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Oprf::toHex(5), \TypeError::class, 'toHex: expected bytes');
        $this->throws(fn() => Oprf::blind(str_repeat('a', 65536)), $ia, 'Blind(input): 65536 bytes exceeds the 65535-byte limit (RFC 9497 2-byte length framing)');
        $this->throws(fn() => Oprf::hashToGroup('x', 'zz'), $ia, 'unknown OPRF mode zz');
        $this->throws(fn() => Oprf::deriveKeyPair(str_repeat("\1", 32), '', 5), $ia, 'unknown OPRF mode integer');
        $this->throws(fn() => Oprf::deriveKeyPair('abc', '', 'oprf'), $ia, 'DeriveKeyPair: seed must be exactly 32 bytes');
        $this->throws(fn() => Oprf::publicKeyFor('abc'), $ia, 'DeserializeScalar: expected 32 bytes, got 3');
    }

    /** The server entry points accept only 'oprf' / 'voprf'. */
    public function testServerModes(): void
    {
        $m = "mode must be 'oprf' or 'voprf'";
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Oprf::evaluate(self::sk(), 'x', 'poprf'), $ia, $m);
        $this->throws(fn() => Oprf::blindEvaluate(self::sk(), self::g(), 'poprf'), $ia, $m);
        $this->throws(fn() => Oprf::finalize('x', self::sk(), self::g(), 'poprf'), $ia, $m);
        $this->throws(fn() => Oprf::buildRevocationSet(self::sk(), [], 'poprf'), $ia, $m);
        $this->throws(fn() => Oprf::makeRevocationEvaluator(self::sk(), 'poprf'), $ia, $m);
    }

    /** Zero scalars: the multiply, the base multiply and the inversion refuse 0; a zero proof is a failed proof, not a crash. */
    public function testZeroScalars(): void
    {
        $ia = \InvalidArgumentException::class;
        $zm = 'expected valid scalar: 1 <= n < the group order, got 0';
        $this->throws(fn() => Oprf::blindEvaluate(self::Z, self::g()), $ia, $zm);
        $this->throws(fn() => Oprf::publicKeyFor(self::Z), $ia, $zm);
        $this->throws(fn() => Oprf::finalize('x', self::Z, self::g()), $ia, 'scalarInvert: inverse of zero');
        $g = self::g();
        $this->throws(fn() => Oprf::finalize('x', Oprf::serializeScalar(3), $g, 'voprf', str_repeat("\0", 64), $g, $g), $ia, 'Finalize(voprf): DLEQ proof verification failed');
        $this->throws(fn() => Oprf::finalize('x', Oprf::serializeScalar(3), $g, 'voprf', str_repeat("\0", 64), null, $g), $ia,
            'Finalize(voprf): proof, publicKey and blindedElement are required');
    }

    /** RFC 9496 decoding: the generator and the identity decode; a negative s, s = -1 (y = 0), a negative xy and a non-square do not. */
    public function testRistrettoCanonical(): void
    {
        $this->assertTrue(Oprf::ristrettoCanonical(self::g()));
        $this->assertTrue(Oprf::ristrettoCanonical(self::Z));
        foreach (['0b0d51f59543b18e577b569e3affaea0a71cf4955a7d22724959a6ba1f72d209', // p - s(generator): odd s
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f', // s = -1
            '122c597083bd438b7f6d72af75d025948899647711b806bdd2cd82fa69713d33', // negative t
            '0012a3fa000c5dc26ee658c3c58e12cecd58d6455cec3d5621f0c787675b382a', // non-square
            'd0bf3e6ee1d668de18c9ca200a4f152062f345283ee68cadfe41204f215d7569'] as $hex) {
            $this->assertFalse(Oprf::ristrettoCanonical((string)hex2bin($hex)), $hex);
        }
    }

    /** serializeScalar reads a GMP as is and a string in base 10. */
    public function testSerializeScalar(): void
    {
        $this->assertSame("\x05" . str_repeat("\0", 31), Oprf::serializeScalar(gmp_init(5)));
        $this->assertSame("\x0a" . str_repeat("\0", 31), Oprf::serializeScalar('010'));
        $this->assertSame(self::g(), Oprf::serializeElement(self::g()));
    }

    /** i2osp of an 8-byte length is the big-endian word. */
    public function testI2ospEightBytes(): void
    {
        $f = new \ReflectionMethod(Oprf::class, 'i2osp');
        $this->assertSame("\0\0\0\0\0\0\0\x05", $f->invoke(null, 5, 8));
    }

    /** RFC 9380: a DST over 255 bytes is replaced by H("H2C-OVERSIZE-DST-" || DST); one of exactly 255 bytes is used as is. */
    public function testOversizeDst(): void
    {
        $f = new \ReflectionMethod(Oprf::class, 'expandMessageXmd');
        $d256 = str_repeat('D', 256);
        $d255 = str_repeat('D', 255);
        $this->assertSame($f->invoke(null, 'm', hash('sha512', 'H2C-OVERSIZE-DST-' . $d256, true)), $f->invoke(null, 'm', $d256));
        $this->assertNotSame($f->invoke(null, 'm', hash('sha512', 'H2C-OVERSIZE-DST-' . $d255, true)), $f->invoke(null, 'm', $d255));
    }

    /** randomScalar is public, retries a zero scalar and gives up after exactly 8 zero draws. */
    public function testRandomScalarRetries(): void
    {
        $this->assertSame(32, strlen(Oprf::randomScalar()));
        $calls = 0;
        Oprf::$randomHook = static function () use (&$calls): string {
            if (++$calls > 20) {
                throw new \LogicException('randomScalar kept drawing');
            }
            return self::Z;
        };
        $this->throws(fn() => Oprf::randomScalar(), \RuntimeException::class, 'randomScalar: entropy source returned zero repeatedly (RNG failure); refusing to continue');
        $this->assertSame(8, $calls);
        $calls = 0;
        $seven = self::sk();
        Oprf::$randomHook = static function () use (&$calls, $seven): string {
            return ++$calls === 1 ? self::Z : $seven;
        };
        $this->assertSame($seven, Oprf::randomScalar());
        $this->assertSame(2, $calls);
    }

    /** randomKeyPair is public and returns the secret key with its public key. */
    public function testRandomKeyPair(): void
    {
        $kp = Oprf::randomKeyPair();
        $this->assertSame(['secret_key', 'public_key'], array_keys($kp));
        $this->assertSame(Oprf::publicKeyFor($kp['secret_key']), $kp['public_key']);
    }

    /** POPRF: a key that cancels the info tweak (tweaked key = identity, sk + m = 0) is refused at each step with its own reason. */
    public function testPoprfZeroTweak(): void
    {
        $m = (new \ReflectionMethod(Oprf::class, 'poprfInfoScalar'))->invoke(null, 'win');
        $neg = sodium_crypto_core_ristretto255_scalar_negate($m);
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Oprf::blindPoprf('x', 'win', sodium_crypto_scalarmult_ristretto255_base($neg)), $ia, 'Blind(poprf): tweaked key is identity');
        $this->throws(fn() => Oprf::blindEvaluatePoprf($neg, self::g(), 'win'), $ia, 'BlindEvaluate(poprf): inverse of zero (bad info/key)');
        $this->throws(fn() => Oprf::evaluatePoprf($neg, 'x', 'win'), $ia, 'Evaluate(poprf): inverse of zero (bad info/key)');
    }

    /** Revocation set: ids must be strings, outputs map to true; the oprf evaluator does not touch the key until it is used. */
    public function testRevocationLayer(): void
    {
        $this->throws(fn() => Oprf::buildRevocationSet(self::sk(), [5]), \TypeError::class, 'capability id must be a string');
        $set = Oprf::buildRevocationSet(self::sk(), ['a']);
        $this->assertSame([true], array_values($set['outputs']));
        $this->assertInstanceOf(\Closure::class, Oprf::makeRevocationEvaluator('short', 'oprf'));
    }

    /** privateRateToken refuses an evaluation without a DLEQ proof. */
    public function testRateTokenNeedsProof(): void
    {
        $g = self::g();
        $this->throws(fn() => Oprf::privateRateToken('id', 'w', static fn(string $b, string $w): array => ['evaluated_element' => $g], $g),
            \InvalidArgumentException::class, 'privateRateToken: POPRF blind-evaluation did not return a DLEQ proof');
    }

    /** The window limit is a positive integer: an int or an integral finite float; infinity and strings are refused. */
    public function testRateWindowLimit(): void
    {
        $c = new OprfRateWindowCounter(2.0);
        $this->assertSame([['count' => 1, 'allowed' => true], ['count' => 2, 'allowed' => true], ['count' => 3, 'allowed' => false]],
            [$c->hit('t'), $c->hit('t'), $c->hit('t')]);
        $this->assertSame(['count' => 1, 'allowed' => true], (new OprfRateWindowCounter(1))->hit('t'));
        $m = 'RateWindowCounter: limit must be a positive integer';
        $this->throws(fn() => new OprfRateWindowCounter(INF), \TypeError::class, $m);
        $this->throws(fn() => new OprfRateWindowCounter('3'), \TypeError::class, $m);
    }
}
