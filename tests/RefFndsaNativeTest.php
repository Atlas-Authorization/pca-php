<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Fndsa;
use Atlas\Pca\FndsaNative;
use Atlas\Pca\MpcShake256;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Real-primitive FN-DSA through libfndsa (Atlas\Pca\FndsaNative): byte-for-byte replay of the cross-implementation known-answer file
 * (test-data/ref-fndsa-kat.json), refusals, and the hybrid framing. Needs ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA);
 * ATLAS_PCA_LIBFNDSA_REQUIRED=1 (the fndsa workflow) fails instead of skipping.
 */
final class RefFndsaNativeTest extends TestCase
{
    private const VARIANTS = ['fn-dsa-512', 'fn-dsa-1024'];

    protected function setUp(): void
    {
        if (!FndsaNative::available()) {
            if (getenv('ATLAS_PCA_LIBFNDSA_REQUIRED') === '1') {
                $this->fail('libfndsa must load (ATLAS_PCA_LIBFNDSA, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA)');
        }
        Fndsa::setFalconBackend(FndsaNative::backend());
    }

    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    private static function kat(): array
    {
        $j = json_decode((string) file_get_contents(__DIR__ . '/../test-data/ref-fndsa-kat.json'), true, 512, JSON_THROW_ON_ERROR);
        return $j;
    }

    public static function wasmSigned(): array
    {
        $o = [];
        foreach (self::kat()['wasm_signed'] as $i => $c) {
            $o["wasm_signed #$i " . $c['variant']] = [$c];
        }
        return $o;
    }

    public static function cSigned(): array
    {
        $o = [];
        foreach (self::kat()['c_signed'] as $i => $c) {
            $o["c_signed #$i " . $c['variant']] = [$c];
        }
        return $o;
    }

    private static function flip(string $b, int $i = 0): string
    {
        $b[$i] = chr(ord($b[$i]) ^ 1);
        return $b;
    }

    public function testKatHasCases(): void
    {
        $this->assertNotEmpty(self::kat()['wasm_signed']);
        $this->assertNotEmpty(self::kat()['c_signed']);
    }

    #[DataProvider('wasmSigned')]
    public function testWasmSignedByteExact(array $c): void
    {
        $v = $c['variant'];
        $vk = hex2bin($c['vk']);
        $msg = hex2bin($c['msg']);
        $sig = hex2bin($c['sig']);
        [$sk, $gotVk] = FndsaNative::keygen($v, MpcShake256::hash($c['keygen_seed_label'], 32));
        $this->assertSame($vk, $gotVk);
        $this->assertSame($sig, FndsaNative::sign($v, $sk, $msg, MpcShake256::hash($c['sign_seed_label'], 32)));
        $this->assertTrue(FndsaNative::verify($v, $vk, $msg, $sig));
        $this->assertTrue(Fndsa::verify($v, $vk, $msg, $sig));
    }

    #[DataProvider('cSigned')]
    public function testCSignedVerifies(array $c): void
    {
        $this->assertTrue(FndsaNative::verify($c['variant'], hex2bin($c['vk']), hex2bin($c['msg']), hex2bin($c['sig'])));
    }

    public function testTamperingIsRefused(): void
    {
        $c = self::kat()['c_signed'][2]; // a non-empty message, so the empty-message check below is a different message
        $v = $c['variant'];
        $vk = hex2bin($c['vk']);
        $msg = hex2bin($c['msg']);
        $sig = hex2bin($c['sig']);
        $this->assertTrue(FndsaNative::verify($v, $vk, $msg, $sig));
        $this->assertFalse(FndsaNative::verify($v, $vk, $msg, self::flip($sig, 10)));
        $this->assertFalse(FndsaNative::verify($v, $vk, $msg . 'x', $sig));
        $this->assertFalse(FndsaNative::verify($v, self::flip($vk, 5), $msg, $sig));
        $this->assertFalse(FndsaNative::verify($v, $vk, $msg, substr($sig, 0, -1)));
        $this->assertFalse(FndsaNative::verify($v, substr($vk, 0, -1), $msg, $sig));
        $this->assertFalse(FndsaNative::verify($v, $vk, str_repeat("\0", FndsaNative::MESSAGE_CAP + 1), $sig));
        $this->assertFalse(FndsaNative::verify($v, $vk, '', $sig));
        $this->assertFalse(FndsaNative::verify($v, '', $msg, $sig));
        $this->assertFalse(FndsaNative::verify($v, $vk, $msg, ''));
    }

    public function testRefusalsBeforeTheLibrary(): void
    {
        $bad = static function (callable $f, string $class): void {
            try {
                $f();
            } catch (\Throwable $e) {
                self::assertInstanceOf($class, $e);
                return;
            }
            self::fail('expected ' . $class);
        };
        $bad(static fn() => FndsaNative::keygen('fn-dsa-768', str_repeat("\0", 32)), \InvalidArgumentException::class);
        $bad(static fn() => FndsaNative::keygen('fn-dsa-512', str_repeat("\0", 31)), \InvalidArgumentException::class);
        $bad(static fn() => FndsaNative::keygen('fn-dsa-512', null), \TypeError::class);
        [$sk, $vk] = FndsaNative::keygen('fn-dsa-512', str_repeat("\0", 32));
        $bad(static fn() => FndsaNative::sign('fn-dsa-512', substr($sk, 0, -1), 'm'), \InvalidArgumentException::class);
        $bad(static fn() => FndsaNative::sign('fn-dsa-512', $sk, str_repeat("\0", FndsaNative::MESSAGE_CAP + 1)), \InvalidArgumentException::class);
        $bad(static fn() => FndsaNative::sign('fn-dsa-768', $sk, 'm'), \InvalidArgumentException::class);
        $bad(static fn() => FndsaNative::sign('fn-dsa-512', $sk, null), \TypeError::class);
        $bad(static fn() => FndsaNative::sign('fn-dsa-512', $sk, 'm', str_repeat("\0", 5)), \InvalidArgumentException::class);
        $bad(static fn() => FndsaNative::verify('fn-dsa-768', $vk, 'm', str_repeat("\0", 666)), \InvalidArgumentException::class);
        $bad(static fn() => FndsaNative::verify('fn-dsa-512', null, 'm', str_repeat("\0", 666)), \TypeError::class);
        $this->assertFalse(FndsaNative::verify('fn-dsa-512', $vk, 'm', str_repeat("\0", 666)));
        // through the registry seam: an unknown variant or a wrong length is false, never a pass
        $this->assertFalse(Fndsa::verify('fn-dsa-768', $vk, 'm', str_repeat("\0", 666)));
        $this->assertFalse(Fndsa::verify('fn-dsa-512', null, 'm', str_repeat("\0", 666)));
        $this->assertFalse(Fndsa::verify('fn-dsa-512', $vk, null, str_repeat("\0", 666)));
    }

    public function testRandomSignRoundTrip(): void
    {
        foreach (self::VARIANTS as $v) {
            [$sk, $vk] = FndsaNative::keygen($v, implode('', array_map('chr', range(0, 31))));
            $s1 = FndsaNative::sign($v, $sk, 'hello');
            $s2 = FndsaNative::sign($v, $sk, 'hello');
            $this->assertNotSame($s1, $s2); // fresh randomness per signature
            $this->assertTrue(FndsaNative::verify($v, $vk, 'hello', $s1));
            $this->assertTrue(FndsaNative::verify($v, $vk, 'hello', $s2));
            $this->assertTrue(FndsaNative::verify($v, $vk, '', FndsaNative::sign($v, $sk, ''))); // a zero-length message is valid
            $this->assertFalse(FndsaNative::verify($v, $vk, 'hellp', $s1));
            $big = str_repeat('m', FndsaNative::MESSAGE_CAP);
            $this->assertTrue(FndsaNative::verify($v, $vk, $big, FndsaNative::sign($v, $sk, $big)));
        }
    }

    public function testBackendSeam(): void
    {
        $be = Fndsa::getFalconBackend();
        $kp = ($be->keygen)();
        $sig = ($be->sign)($kp['sk'], 'x');
        $this->assertTrue(($be->verify)($kp['pk'], 'x', $sig));
        $this->assertFalse(($be->verify)(substr($kp['pk'], 0, -1), 'x', $sig));
        $this->expectException(\InvalidArgumentException::class);
        ($be->sign)(str_repeat("\0", 10), 'x');
    }

    public static function algs(): array
    {
        $o = [];
        foreach (array_keys(Fndsa::suites()) as $a) {
            $o[$a] = [$a];
        }
        return $o;
    }

    #[DataProvider('algs')]
    public function testFramingRoundTrip(string $alg): void
    {
        $suite = Fndsa::suites()[$alg];
        [$sk, $vk] = FndsaNative::keygen($suite->variant, str_repeat("\x07", 32));
        $leaf = Obj::of(['agent' => 'a', 'n' => new \Atlas\Pca\Num('1')]);
        $other = Obj::of(['agent' => 'b', 'n' => new \Atlas\Pca\Num('1')]);
        $edSeed = str_repeat("\x09", 32);
        $signed = Fndsa::signPca($alg, $leaf, ['pk' => $vk, 'sk' => $sk], $suite->hasEd25519 ? $edSeed : null);
        $holder = $suite->hasEd25519 ? Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($edSeed))) : null;
        $this->assertTrue(Fndsa::verifyPca($alg, $leaf, $holder, $signed['pq_pk'], $signed['sig'], $signed['pq_sig'] ?? null));
        $this->assertFalse(Fndsa::verifyPca($alg, $other, $holder, $signed['pq_pk'], $signed['sig'], $signed['pq_sig'] ?? null));
    }
}
