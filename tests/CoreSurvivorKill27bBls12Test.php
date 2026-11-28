<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bls12;
use Atlas\Pca\NativeDir;
use PHPUnit\Framework\TestCase;

/**
 * Bls12: scalar helpers (I2OSP/OS2IP, inverse, expand_message_xmd bounds), the blst loader's candidate list and fallthrough through the
 * path seam, the GT shim load error, buffer sizes, strict point decoding and the GT / pairing refusals. The point tests need ext-ffi
 * and PCA_BLST_LIB (the pairing shard); the scalar tests need only GMP.
 */
final class CoreSurvivorKill27bBls12Test extends TestCase
{
    private const NO_LIB = 'BLS12-381 needs a built libblst (supranational/blst shared library; abe also needs the GT shim, set PCA_BLST_LIB)';
    private const GT_PREFIX = 'abe needs the GT shim (native/pca_gt.c) built into the library: ';

    private function needBlst(): void
    {
        if (!extension_loaded('FFI') || getenv('PCA_BLST_LIB') === false) {
            if (getenv('PCA_PAIRING_REQUIRED') === '1') {
                $this->fail('PCA_PAIRING_REQUIRED is set but ext-ffi or PCA_BLST_LIB is missing');
            }
            $this->markTestSkipped('needs ext-ffi and PCA_BLST_LIB (a shared libblst)');
        }
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

    /**
     * Runs `$f` with the loader state cleared (or set to `$state`), PCA_BLST_LIB set to `$env` and the path seam set to `$hook`;
     * the loaded library, the shim, the path and the env are restored after.
     *
     * @param array{ffi?:mixed,gt?:mixed,libPath?:mixed} $state
     */
    private static function fresh(string $env, ?\Closure $hook, \Closure $f, array $state = []): mixed
    {
        $props = [];
        $saved = [];
        foreach (['ffi', 'gt', 'libPath'] as $n) {
            $props[$n] = new \ReflectionProperty(Bls12::class, $n);
            $saved[$n] = $props[$n]->getValue();
        }
        $old = (string)getenv('PCA_BLST_LIB');
        try {
            putenv('PCA_BLST_LIB=' . $env);
            foreach ($props as $n => $p) {
                $p->setValue(null, array_key_exists($n, $state) ? $state[$n] : null);
            }
            Bls12::$pathsHook = $hook;
            return $f();
        } finally {
            Bls12::$pathsHook = null;
            putenv('PCA_BLST_LIB=' . $old);
            foreach ($props as $n => $p) {
                $p->setValue(null, $saved[$n]);
            }
        }
    }

    /** @return list<string> */
    private static function tail(): array
    {
        $packaged = NativeDir::lib('blst');
        return [...($packaged === null ? [] : [$packaged]), 'libblst.so', 'libblst.dylib', 'blst.dll'];
    }

    private static function missing(): string
    {
        return sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-g27b-no-libblst.so';
    }

    // ---- scalars (GMP only) ----

    /** I2OSP pads to the length and refuses a value one octet too long or negative; OS2IP of no octets is zero. */
    public function testI2ospOs2ip(): void
    {
        $this->assertSame("\xff", Bls12::i2osp(255, 1));
        $this->assertSame("\x00\x01", Bls12::i2osp(gmp_init(1), 2));
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Bls12::i2osp(256, 1), $ia, 'integer does not fit 1 octets');
        $this->throws(fn() => Bls12::i2osp(-1, 1), $ia, 'integer does not fit 1 octets');
        $this->assertSame(0, gmp_cmp(Bls12::os2ip(''), 0));
        $this->assertSame(0, gmp_cmp(Bls12::os2ip("\x01\x00"), 256));
    }

    /** The inverse of zero (and of r) is refused; any other value inverts. */
    public function testInverseOfZero(): void
    {
        $this->throws(fn() => Bls12::inv(gmp_init(0)), \DivisionByZeroError::class, 'inverse of zero');
        $this->throws(fn() => Bls12::inv(Bls12::r()), \DivisionByZeroError::class, 'inverse of zero');
        $this->assertSame(0, gmp_cmp(Bls12::mul(Bls12::inv(gmp_init(2)), gmp_init(2)), 1));
    }

    /** expand_message_xmd: the RFC 9380 vector, exact output lengths up to 255 blocks, and refusals just past each limit. */
    public function testExpandMessageXmdBounds(): void
    {
        $this->assertSame('68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235', bin2hex(Bls12::expandMessageXmd('', 'QUUX-V01-CS02-with-expander-SHA256-128', 32)));
        $this->assertSame('', Bls12::expandMessageXmd('m', 'D', 0));
        $this->assertSame(33, strlen(Bls12::expandMessageXmd('m', 'D', 33)));
        $this->assertSame(8160, strlen(Bls12::expandMessageXmd('m', 'D', 8160)));
        $this->assertSame(32, strlen(Bls12::expandMessageXmd('m', str_repeat('d', 255), 32)));
        $ia = \InvalidArgumentException::class;
        $msg = 'expand_message_xmd: invalid length or DST';
        $this->throws(fn() => Bls12::expandMessageXmd('m', 'D', 8161), $ia, $msg);
        $this->throws(fn() => Bls12::expandMessageXmd('m', 'D', -1), $ia, $msg);
        $this->throws(fn() => Bls12::expandMessageXmd('m', str_repeat('d', 256), 32), $ia, $msg);
    }

    // ---- the loader ----

    /** Candidates: the env override (when non-empty), the packaged library, then the system names; a path that fails to load is skipped for the next. */
    public function testLoaderCandidatesAndFallthrough(): void
    {
        $this->needBlst();
        $real = (string)getenv('PCA_BLST_LIB');
        $want = Bls12::compress(1, Bls12::generator(1));
        $op = static fn() => Bls12::compress(1, Bls12::generator(1));
        $seen = [];
        $missing = self::missing();
        $got = self::fresh($real, static function (array $paths) use (&$seen, $missing, $real): array {
            $seen[] = $paths;
            return [$missing, $real];
        }, $op);
        $this->assertSame($want, $got, 'the missing first path is skipped and the second one loads');
        $got = self::fresh('', static function (array $paths) use (&$seen, $real): array {
            $seen[] = $paths;
            return [$real];
        }, $op);
        $this->assertSame($want, $got);
        $this->assertSame([[$real, ...self::tail()], self::tail()], $seen);
    }

    /** When no candidate loads, the loader throws its library error (fail closed). */
    public function testNoLoadableLibraryThrows(): void
    {
        $this->needBlst();
        $missing = self::missing();
        $this->throws(
            fn() => self::fresh((string)getenv('PCA_BLST_LIB'), static fn(array $p): array => [$missing], static fn() => Bls12::buf(1)),
            \RuntimeException::class,
            self::NO_LIB,
        );
    }

    /** The GT shim is bound from the library lib() loaded, even when nothing loaded it before. */
    public function testShimLoadsTheLibraryFirst(): void
    {
        $this->needBlst();
        $e = Bls12::gtPairing(Bls12::generator(1), Bls12::generator(2));
        $path = (new \ReflectionProperty(Bls12::class, 'libPath'))->getValue();
        $this->assertIsString($path);
        [$ok, $after] = self::fresh((string)getenv('PCA_BLST_LIB'), null, static function () use ($e): array {
            try {
                $ok = Bls12::gtIsElement($e);
            } catch (\Throwable) {
                $ok = null;
            }
            return [$ok, (new \ReflectionProperty(Bls12::class, 'libPath'))->getValue()];
        });
        $this->assertTrue($ok);
        $this->assertSame($path, $after);
    }

    /** A library without the GT shim is refused with the shim error, carrying the loader's own message. */
    public function testMissingShimError(): void
    {
        $this->needBlst();
        $ffi = (new \ReflectionProperty(Bls12::class, 'ffi'))->getValue();
        $this->assertNotNull($ffi);
        $missing = self::missing();
        $cdef = (new \ReflectionClassConstant(Bls12::class, 'GT_CDEF'))->getValue();
        $ffiMsg = null;
        try {
            \FFI::cdef($cdef, $missing);
        } catch (\Throwable $t) {
            $ffiMsg = $t->getMessage();
        }
        $this->assertIsString($ffiMsg);
        $this->assertNotSame('', $ffiMsg);
        $z = str_repeat("\0", Bls12::GT_BYTES);
        $this->throws(
            fn() => self::fresh((string)getenv('PCA_BLST_LIB'), null, static fn() => Bls12::gtMul($z, $z), ['ffi' => $ffi, 'libPath' => $missing]),
            \RuntimeException::class,
            self::GT_PREFIX . $ffiMsg,
        );
    }

    // ---- buffers and points ----

    /** buf, scalar, affine, pDup and pEq are public; every buffer has its group's exact size. */
    public function testBufferSizes(): void
    {
        $this->needBlst();
        $this->assertSame(7, \FFI::sizeof(Bls12::buf(7)));
        $this->assertSame(32, \FFI::sizeof(Bls12::scalar(gmp_init(5))));
        $g1 = Bls12::generator(1);
        $g2 = Bls12::generator(2);
        $this->assertSame(96, \FFI::sizeof(Bls12::affine(1, $g1)));
        $this->assertSame(192, \FFI::sizeof(Bls12::affine(2, $g2)));
        $this->assertSame(144, \FFI::sizeof(Bls12::pDup(1, $g1)));
        $h = Bls12::hashToG1('m', 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_');
        $this->assertSame(144, \FFI::sizeof($h));
        $this->assertFalse(Bls12::isInf(1, $h));
        $this->assertTrue(Bls12::pEq(1, $h, Bls12::hashToG1('m', 'QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_')));
        $this->assertTrue(Bls12::pEq(1, Bls12::pDup(1, $g1), $g1));
        $this->assertFalse(Bls12::pEq(1, $g1, Bls12::pAdd(1, $g1, $g1)));
        $this->throws(fn() => Bls12::identity(3), \InvalidArgumentException::class, 'group must be 1 or 2');
    }

    /** k = 0 mod r gives the zeroed identity buffer; k = r - 1 gives the negation. */
    public function testMulByZero(): void
    {
        $this->needBlst();
        $g = Bls12::generator(1);
        $this->assertSame(str_repeat("\0", 144), \FFI::string(Bls12::pMul(1, $g, Bls12::r()), 144));
        $this->assertTrue(Bls12::pEq(1, Bls12::pMul(1, $g, gmp_sub(Bls12::r(), 1)), Bls12::pNeg(1, $g)));
    }

    /** decode refuses a missing compression flag, a non-string, a wrong length and an out-of-range coordinate, each with its message. */
    public function testDecodeRefusals(): void
    {
        $this->needBlst();
        $g = Bls12::compress(1, Bls12::generator(1));
        $this->assertTrue(Bls12::pEq(1, Bls12::decode(1, $g), Bls12::generator(1)));
        $ia = \InvalidArgumentException::class;
        $flag = 'not a 48-byte compressed G1 point';
        $this->throws(fn() => Bls12::decode(1, chr(ord($g[0]) & 0x7f) . substr($g, 1)), $ia, $flag);
        $this->throws(fn() => Bls12::decode(1, 5), $ia, $flag);
        $this->throws(fn() => Bls12::decode(1, $g . "\0"), $ia, $flag);
        $this->throws(fn() => Bls12::decode(1, "\x9f" . str_repeat("\xff", 47)), $ia, 'invalid G1 encoding');
    }

    /** GT multiply and power refuse a non-canonical coordinate. */
    public function testGtRefusals(): void
    {
        $this->needBlst();
        $bad = str_repeat("\xff", Bls12::GT_BYTES);
        $z = str_repeat("\0", Bls12::GT_BYTES);
        $ia = \InvalidArgumentException::class;
        $this->throws(fn() => Bls12::gtMul($bad, $z), $ia, 'not a canonical GT encoding');
        $this->throws(fn() => Bls12::gtPow($bad, gmp_init(1)), $ia, 'not a canonical GT encoding');
        $this->assertSame(Bls12::GT_BYTES, strlen(Bls12::gtMul($z, $z)));
    }

    /** The pairing product refuses empty or unequal lists, an identity in either group (however it is represented) and an off-curve point. */
    public function testPairingRefusals(): void
    {
        $this->needBlst();
        $g1 = Bls12::generator(1);
        $g2 = Bls12::generator(2);
        $ia = \InvalidArgumentException::class;
        $lists = 'pairing product needs equal, non-empty point lists';
        $this->throws(fn() => Bls12::gtPairingProduct([], []), $ia, $lists);
        $this->throws(fn() => Bls12::gtPairingProduct([$g1], []), $ia, $lists);
        $id = 'pairing is not defined for the identity';
        $inf2 = Bls12::pSub(2, $g2, $g2); // P - P: Z is zero, X and Y need not be
        $this->assertTrue(Bls12::isInf(2, $inf2));
        $this->throws(fn() => Bls12::gtPairingProduct([$g1], [$inf2]), $ia, $id);
        $this->throws(fn() => Bls12::gtPairingProduct([Bls12::identity(1)], [$g2]), $ia, $id);
        $off = Bls12::generator(1);
        $off[0] = $off[0] ^ 1;
        $this->assertFalse(Bls12::isInf(1, $off));
        $this->throws(fn() => Bls12::gtPairingProduct([$off], [$g2]), $ia, 'invalid pairing input');
        $this->assertTrue(Bls12::gtIsElement(Bls12::gtPairingProduct([$g1], [$g2])));
    }
}
