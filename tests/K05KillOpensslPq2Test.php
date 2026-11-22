<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\OpensslPq;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for OpensslPq::verify (round 2): the up-front length gate and the native handle releases. */
final class K05KillOpensslPq2Test extends TestCase
{
    protected function tearDown(): void
    {
        OpensslPq::$faultHook = null;
    }

    /** @return array{0:\FFI\CData,1:string,2:string} [pkey, public key, signature over 'm'] */
    private function keyAndSig(): array
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('no ML-DSA-65 in this libcrypto');
        }
        $g = OpensslPq::generate('ML-DSA-65');
        $this->assertNotNull($g);
        [$pkey, $pk] = $g;
        $sig = OpensslPq::sign('ML-DSA-65', $pkey, 'm');
        $this->assertNotNull($sig);
        return [$pkey, $pk, $sig];
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

    /** A wrong-length signature (with a right-length key) is refused before libcrypto is touched: no native step runs. */
    public function testWrongSignatureLengthNeverReachesLibcrypto(): void
    {
        [$pkey, $pk, $sig] = $this->keyAndSig();
        try {
            $steps = [];
            OpensslPq::$faultHook = static function (string $at) use (&$steps): bool {
                $steps[] = $at;
                return false;
            };
            $this->assertTrue(OpensslPq::verify('ML-DSA-65', $pk, 'm', $sig), 'control');
            $this->assertSame(['md_ctx_new', 'verify_init'], $steps, 'control');
            foreach ([$sig . "\0", substr($sig, 0, -1)] as $bad) {
                $steps = [];
                $this->assertFalse(OpensslPq::verify('ML-DSA-65', $pk, 'm', $bad));
                $this->assertSame([], $steps);
            }
        } finally {
            OpensslPq::$faultHook = null;
            OpensslPq::free($pkey);
        }
    }

    /**
     * verify releases the public key and the digest context on every call: 256 verifications leave the heap where it was. A
     * missing EVP_PKEY_free leaks the imported key (> 8 KB a round), a missing EVP_MD_CTX_free also pins it through the
     * context's key reference: both far above the 16 KiB bound.
     */
    public function testVerifyReleasesEveryHandle(): void
    {
        [$pkey, $pk, $sig] = $this->keyAndSig();
        try {
            if (self::heapInUse() === null) {
                $this->markTestSkipped('no glibc mallinfo2');
            }
            $ok = 0;
            $round = static function () use ($pk, $sig, &$ok): void {
                $ok += OpensslPq::verify('ML-DSA-65', $pk, 'm', $sig) ? 1 : 0;
            };
            for ($i = 0; $i < 4; $i++) {
                $round();
            }
            $before = self::heapInUse();
            for ($i = 0; $i < 256; $i++) {
                $round();
            }
            $grow = self::heapInUse() - $before;
            $this->assertSame(260, $ok);
            $this->assertLessThan(16384, $grow);
        } finally {
            OpensslPq::free($pkey);
        }
    }
}
