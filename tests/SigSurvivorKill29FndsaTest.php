<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FalconBackend;
use Atlas\Pca\Fndsa;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Fndsa: the suite registry, sign/signSeeded refusals, signPca material checks and the mock backend's refusals. */
final class SigSurvivorKill29FndsaTest extends TestCase
{
    private const MOCK_SK_TAG = "atlas-pca/fn-dsa/mock-sk/v1\x00";

    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    private function threw(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class);
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected $class: $message");
    }

    /** The registry holds exactly the four suites with their framing lengths (hybrids carry a 64-byte Ed25519 sig and the FN-DSA one as pq_sig). */
    public function testTheSuiteRegistry(): void
    {
        $s = Fndsa::suites();
        $this->assertSame(['fn-dsa-512', 'fn-dsa-1024', 'hybrid-ed25519-fn-dsa-512', 'hybrid-ed25519-fn-dsa-1024'], array_keys($s));
        $row = static fn (string $a): array => [$s[$a]->alg, $s[$a]->variant, $s[$a]->hasEd25519, $s[$a]->sigBytes, $s[$a]->needsPqPk,
            $s[$a]->pqPkBytes, $s[$a]->needsPqSig, $s[$a]->pqSigBytes, $s[$a]->fnSigBytes];
        $this->assertSame(['fn-dsa-512', 'fn-dsa-512', false, 666, true, 897, false, 0, 666], $row('fn-dsa-512'));
        $this->assertSame(['fn-dsa-1024', 'fn-dsa-1024', false, 1280, true, 1793, false, 0, 1280], $row('fn-dsa-1024'));
        $this->assertSame(['hybrid-ed25519-fn-dsa-512', 'fn-dsa-512', true, Pca::ED25519_SIGNATURE_BYTES, true, 897, true, 666, 666], $row('hybrid-ed25519-fn-dsa-512'));
        $this->assertSame(['hybrid-ed25519-fn-dsa-1024', 'fn-dsa-1024', true, Pca::ED25519_SIGNATURE_BYTES, true, 1793, true, 1280, 1280], $row('hybrid-ed25519-fn-dsa-1024'));
    }

    /** sign refuses an empty or non-string key, a non-string message and a verify-only backend, each with its own error. */
    public function testSignRefusals(): void
    {
        Fndsa::registerTestBackend();
        $this->threw(\TypeError::class, 'fndsaSign: secret key must be a non-empty byte string', fn () => Fndsa::sign('fn-dsa-512', '', 'm'));
        $this->threw(\TypeError::class, 'fndsaSign: secret key must be a non-empty byte string', fn () => Fndsa::sign('fn-dsa-512', 5, 'm'));
        $this->threw(\TypeError::class, 'fndsaSign: message must be bytes', fn () => Fndsa::sign('fn-dsa-512', 'sk', 5));
        Fndsa::setFalconBackend(new FalconBackend(static fn (string $p, string $m, string $s): bool => false));
        $this->threw(\RuntimeException::class, 'fndsaSign: FN-DSA backend is verify-only (no sign())', fn () => Fndsa::sign('fn-dsa-512', 'sk', 'm'));
    }

    /** signSeeded refuses a bad variant, bad key/message, a short seed, a backend with no seeded signer and a wrong-length signature. */
    public function testSignSeededRefusals(): void
    {
        $seed = str_repeat("\1", 32);
        Fndsa::registerTestBackend();
        $kp = Fndsa::mockKeypair('fn-dsa-512');
        $this->threw(\InvalidArgumentException::class, 'fndsaSign: unknown FN-DSA variant', fn () => Fndsa::signSeeded('fn-dsa-9', $kp['sk'], 'm', $seed));
        $this->threw(\TypeError::class, 'fndsaSign: secret key and message must be non-empty / bytes', fn () => Fndsa::signSeeded('fn-dsa-512', '', 'm', $seed));
        $this->threw(\TypeError::class, 'fndsaSign: secret key and message must be non-empty / bytes', fn () => Fndsa::signSeeded('fn-dsa-512', 5, 'm', $seed));
        $this->threw(\TypeError::class, 'fndsaSign: secret key and message must be non-empty / bytes', fn () => Fndsa::signSeeded('fn-dsa-512', 'sk', 5, $seed));
        $this->threw(\InvalidArgumentException::class, 'fndsaSign: sign seed must be 32 bytes', fn () => Fndsa::signSeeded('fn-dsa-512', 'sk', 'm', 'short'));
        $this->threw(\RuntimeException::class, 'fndsaSign: FN-DSA backend has no seeded signer', fn () => Fndsa::signSeeded('fn-dsa-512', $kp['sk'], 'm', $seed));
        $verify = static fn (string $p, string $m, string $s): bool => false;
        Fndsa::setFalconBackend(new FalconBackend($verify, null, null, static fn (string $sk, string $m, string $s): string => str_repeat("\0", 665)));
        $this->threw(\RuntimeException::class, "fndsaSign: FN-DSA backend returned a bad signature; expected padded 666 bytes for 'fn-dsa-512'",
            fn () => Fndsa::signSeeded('fn-dsa-512', 'sk', 'm', $seed));
        Fndsa::setFalconBackend(new FalconBackend($verify, null, null, static fn (string $sk, string $m, string $s): string => str_repeat("\0", 666)));
        $this->assertSame(str_repeat("\0", 666), Fndsa::signSeeded('fn-dsa-512', 'sk', 'm', $seed), 'control');
    }

    /** leafMessage binds alg and pq_pk only as strings. */
    public function testLeafMessageNeedsStrings(): void
    {
        $leaf = Obj::of(['a' => 'b']);
        $this->threw(\TypeError::class, 'fndsaLeafMessage: alg and pq_pk must be strings', fn () => Fndsa::leafMessage($leaf, 5, 'pk'));
        $this->threw(\TypeError::class, 'fndsaLeafMessage: alg and pq_pk must be strings', fn () => Fndsa::leafMessage($leaf, 'fn-dsa-512', 5));
        $this->assertSame(Pca::thresholdMessage($leaf) . Fndsa::LEAF_DOMAIN . "fn-dsa-512\x00pk", Fndsa::leafMessage($leaf, 'fn-dsa-512', 'pk'));
    }

    /** signPca refuses missing FN-DSA secret material, and a hybrid refuses an Ed25519 seed that is not 32 bytes. */
    public function testSignPcaMaterialRefusals(): void
    {
        Fndsa::registerTestBackend();
        $leaf = Obj::of(['a' => 'b']);
        $kp = Fndsa::mockKeypair('fn-dsa-512');
        $this->threw(\TypeError::class, "signPcaWithFndsa: 'fn-dsa-512' requires FN-DSA secret-key material",
            fn () => Fndsa::signPca('fn-dsa-512', $leaf, ['pk' => $kp['pk'], 'sk' => '']));
        $this->threw(\TypeError::class, "signPcaWithFndsa: 'fn-dsa-512' requires FN-DSA secret-key material",
            fn () => Fndsa::signPca('fn-dsa-512', $leaf, ['pk' => $kp['pk']]));
        $this->threw(\TypeError::class, "signPcaWithFndsa: 'hybrid-ed25519-fn-dsa-512' requires edSecret (a 32-byte Ed25519 seed)",
            fn () => Fndsa::signPca('hybrid-ed25519-fn-dsa-512', $leaf, $kp, 'short'));
        $this->threw(\TypeError::class, "signPcaWithFndsa: 'hybrid-ed25519-fn-dsa-512' requires edSecret (a 32-byte Ed25519 seed)",
            fn () => Fndsa::signPca('hybrid-ed25519-fn-dsa-512', $leaf, $kp));
        $ok = Fndsa::signPca('hybrid-ed25519-fn-dsa-512', $leaf, $kp, str_repeat("\2", 32));
        $this->assertSame(['sig', 'alg', 'pq_pk', 'pq_sig'], array_keys($ok), 'control');
    }

    /** The mock backend signs and verifies both variants, and its verifier answers false (never throws) for a key of no variant. */
    public function testTheMockBackendCoversBothVariants(): void
    {
        $b = Fndsa::registerTestBackend();
        foreach (['fn-dsa-512' => 666, 'fn-dsa-1024' => 1280] as $v => $len) {
            $kp = Fndsa::mockKeypair($v);
            $sig = Fndsa::sign($v, $kp['sk'], 'msg');
            $this->assertSame($len, strlen($sig), $v);
            $this->assertTrue(Fndsa::verify($v, $kp['pk'], 'msg', $sig), $v);
            $this->assertFalse(Fndsa::verify($v, $kp['pk'], 'msG', $sig), $v);
        }
        $this->assertFalse(($b->verify)('short-pk', 'msg', str_repeat("\0", 666)));
    }

    /** The mock signer refuses a key that is only the tag, a key without the tag, and a key whose embedded pk is no variant's length. */
    public function testTheMockSignerRefusals(): void
    {
        Fndsa::registerTestBackend();
        $notMinted = 'mock FN-DSA backend: secret key was not minted by mockKeypair()';
        $this->threw(\InvalidArgumentException::class, $notMinted, fn () => Fndsa::sign('fn-dsa-512', self::MOCK_SK_TAG, 'm'));
        $this->threw(\InvalidArgumentException::class, $notMinted, fn () => Fndsa::sign('fn-dsa-512', str_repeat('x', 40), 'm'));
        $this->threw(\InvalidArgumentException::class, 'mock FN-DSA backend: public key length matches no FN-DSA variant',
            fn () => Fndsa::sign('fn-dsa-512', self::MOCK_SK_TAG . 'abc', 'm'));
    }
}
