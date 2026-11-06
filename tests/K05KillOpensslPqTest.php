<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\OpensslPq;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for OpensslPq signing: the empty message, an unknown key type, and free() without a library. */
final class K05KillOpensslPqTest extends TestCase
{
    public function testSignsAnEmptyMessageAndRefusesAnUnknownTypeQuietly(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('no ML-DSA-65 in this libcrypto');
        }
        $g = OpensslPq::generate('ML-DSA-65');
        $this->assertNotNull($g);
        [$pkey, $pk] = $g;
        try {
            $sig = OpensslPq::sign('ML-DSA-65', $pkey, '');
            $this->assertNotNull($sig, 'an empty message is signed');
            $this->assertSame(OpensslPq::KEY_TYPES['ML-DSA-65'][1], strlen($sig));
            $this->assertTrue(OpensslPq::verify('ML-DSA-65', $pk, '', $sig));
            // an unknown type is refused up front: no key-table lookup (no warning), no signature
            $warnings = [];
            set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
                $warnings[] = $msg;
                return true;
            });
            try {
                $this->assertNull(OpensslPq::sign('ML-DSA-44', $pkey, 'm'));
            } finally {
                restore_error_handler();
            }
            $this->assertSame([], $warnings);
        } finally {
            OpensslPq::free($pkey);
        }
    }

    public function testFreeWithoutALibraryIsANoOp(): void
    {
        if (!extension_loaded('FFI')) {
            $this->markTestSkipped('no FFI');
        }
        $names = ['ffi', 'tried', 'probed'];
        $saved = [];
        foreach ($names as $n) {
            $saved[$n] = (new \ReflectionProperty(OpensslPq::class, $n))->getValue();
        }
        try {
            (new \ReflectionProperty(OpensslPq::class, 'ffi'))->setValue(null, null);
            (new \ReflectionProperty(OpensslPq::class, 'tried'))->setValue(null, true);
            $c = \FFI::cdef();
            OpensslPq::free($c->new('void*'));
            $this->assertNull(OpensslPq::sign('ML-DSA-65', $c->new('void*'), 'm'));
        } finally {
            foreach ($saved as $n => $v) {
                (new \ReflectionProperty(OpensslPq::class, $n))->setValue(null, $v);
            }
        }
    }

    // ------------------------------------------------------------------ k05 R3: fault seam, native frees, candidates

    private function needMldsa(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('no ML-DSA-65 in this libcrypto');
        }
    }

    /** glibc heap bytes in use (mallinfo2: uordblks + hblkhd; libcrypto allocates through malloc), or null off glibc. */
    private static function heapInUse(): ?int
    {
        static $libc = false;
        if ($libc === false) {
            try {
                $libc = \FFI::cdef('struct mallinfo2 { size_t arena; size_t ordblks; size_t smblks; size_t hblks; size_t hblkhd;
                    size_t usmblks; size_t fsmblks; size_t uordblks; size_t fordblks; size_t keepcost; };
                    struct mallinfo2 mallinfo2(void);', 'libc.so.6');
                $libc->mallinfo2();
            } catch (\Throwable) {
                $libc = null;
            }
        }
        if ($libc === null) {
            return null;
        }
        $m = $libc->mallinfo2();
        return $m->uordblks + $m->hblkhd;
    }

    /** Heap growth over `$n` runs of `$f` after 4 warm-up runs (skipped without glibc's mallinfo2). */
    private function heapGrowth(int $n, \Closure $f): int
    {
        if (self::heapInUse() === null) {
            $this->markTestSkipped('no glibc mallinfo2');
        }
        for ($i = 0; $i < 4; $i++) {
            $f();
        }
        $before = self::heapInUse();
        for ($i = 0; $i < $n; $i++) {
            $f();
        }
        return self::heapInUse() - $before;
    }

    /** The seam makes each libcrypto step fail in turn: verify and generate refuse (fail closed). */
    public function testFaultedNativeStepsRefuse(): void
    {
        $this->needMldsa();
        $g = OpensslPq::generate('ML-DSA-65');
        $this->assertNotNull($g);
        [$pkey, $pk] = $g;
        try {
            $sig = OpensslPq::sign('ML-DSA-65', $pkey, 'k05-r3');
            $this->assertNotNull($sig);
            $this->assertTrue(OpensslPq::verify('ML-DSA-65', $pk, 'k05-r3', $sig), 'control');
            foreach (['md_ctx_new', 'verify_init'] as $step) {
                OpensslPq::$faultHook = static fn(string $at): bool => $at === $step;
                $this->assertFalse(OpensslPq::verify('ML-DSA-65', $pk, 'k05-r3', $sig), $step);
            }
            OpensslPq::$faultHook = static fn(string $at): bool => $at === 'raw_public_key';
            $this->assertNull(OpensslPq::generate('ML-DSA-65'));
        } finally {
            OpensslPq::$faultHook = null;
            OpensslPq::free($pkey);
        }
    }

    /**
     * Every native handle is released: 256 generate + sign + free rounds leave the heap where it was. A missing
     * EVP_PKEY_CTX_free (keygen context) leaks >= ~300 bytes a round, a missing EVP_MD_CTX_free (sign) also pins the private
     * key (tens of KB): both are far above the 16 KiB bound.
     */
    public function testGenerateAndSignReleaseEveryHandle(): void
    {
        $this->needMldsa();
        $grow = $this->heapGrowth(256, static function (): void {
            [$pkey] = OpensslPq::generate('ML-DSA-65');
            try {
                OpensslPq::sign('ML-DSA-65', $pkey, 'm');
            } finally {
                OpensslPq::free($pkey);
            }
        });
        $this->assertLessThan(16384, $grow);
    }

    /** The capability probe frees its probe key (an ML-DSA-65 public key is > 8 KB in libcrypto). */
    public function testProbeReleasesItsKey(): void
    {
        $this->needMldsa();
        $f = (new \ReflectionMethod(OpensslPq::class, 'ffi'))->invoke(null);
        $probe = new \ReflectionMethod(OpensslPq::class, 'builds');
        $ok = true;
        $grow = $this->heapGrowth(64, static function () use ($probe, $f, &$ok): void {
            $ok = $ok && $probe->invoke(null, $f, 'ML-DSA-65');
        });
        $this->assertTrue($ok);
        $this->assertLessThan(16384, $grow);
    }

    /** A failed public-key export frees the freshly generated key pair. */
    public function testFailedPublicKeyExportFreesTheKey(): void
    {
        $this->needMldsa();
        OpensslPq::$faultHook = static fn(string $at): bool => $at === 'raw_public_key';
        try {
            $nulls = 0;
            $grow = $this->heapGrowth(32, static function () use (&$nulls): void {
                $nulls += OpensslPq::generate('ML-DSA-65') === null ? 1 : 0;
            });
        } finally {
            OpensslPq::$faultHook = null;
        }
        $this->assertSame(36, $nulls);
        $this->assertLessThan(16384, $grow);
    }

    /** A failed key generation refuses and still frees the keygen context: 256 faulted rounds leave the heap where it was. */
    public function testFailedKeyGenerationFreesTheContext(): void
    {
        $this->needMldsa();
        OpensslPq::$faultHook = static fn(string $at): bool => $at === 'keygen';
        try {
            $nulls = 0;
            $grow = $this->heapGrowth(256, static function () use (&$nulls): void {
                $nulls += OpensslPq::generate('ML-DSA-65') === null ? 1 : 0;
            });
        } finally {
            OpensslPq::$faultHook = null;
        }
        $this->assertSame(260, $nulls);
        $this->assertLessThan(16384, $grow);
    }

    /** The fallback locations are globbed in this exact order, and every match is appended. */
    #[RunInSeparateProcess]
    public function testCandidatesGlobTheKnownLocationsInOrder(): void
    {
        $GLOBALS['__k05_globs'] = [];
        eval('namespace Atlas\Pca; function glob(string $p, int $f = 0): array|false { $GLOBALS["__k05_globs"][] = $p; return ["m:" . $p]; }');
        $want = [
            '/opt/homebrew/opt/openssl@3/lib/libcrypto*.dylib',
            '/opt/homebrew/lib/libcrypto*.dylib',
            '/usr/local/opt/openssl@3/lib/libcrypto*.dylib',
            '/usr/lib/libcrypto.so.3',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
            '/usr/lib/aarch64-linux-gnu/libcrypto.so.3',
            '/lib/x86_64-linux-gnu/libcrypto.so.3',
        ];
        $c = OpensslPq::candidates();
        $this->assertSame($want, $GLOBALS['__k05_globs']);
        $this->assertSame(array_map(fn($p) => 'm:' . $p, $want), array_slice($c, -7));
    }
}
