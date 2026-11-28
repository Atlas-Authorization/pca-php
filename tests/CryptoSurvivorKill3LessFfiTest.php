<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\LessFfi;
use PHPUnit\Framework\TestCase;

/** LESS keygen / sign through libatlas_less: seed lengths, the sign half loads only beside a usable verify half, a refused key throws. */
final class CryptoSurvivorKill3LessFfiTest extends TestCase
{
    private const PROPS = ['tried', 'ffi', 'signTried', 'signFfi'];

    /** @return array<string,mixed> */
    private static function save(): array
    {
        $s = [];
        foreach (self::PROPS as $p) {
            $s[$p] = (new \ReflectionProperty(LessFfi::class, $p))->getValue();
        }
        return $s;
    }

    /** @param array<string,mixed> $values */
    private static function set(array $values): void
    {
        foreach ($values as $p => $v) {
            (new \ReflectionProperty(LessFfi::class, $p))->setValue(null, $v);
        }
    }

    /** Independent of LessFfi's own loader: some candidate exports the keygen / sign half with 32-byte secret keys. */
    private static function signHalfLoads(): bool
    {
        if (!extension_loaded('FFI')) {
            return false;
        }
        foreach (LessFfi::candidates() as $p) {
            if (!is_file($p)) {
                continue;
            }
            try {
                $f = \FFI::cdef('size_t atlas_less_cat1_secret_key_bytes(void);', $p);
                if ($f->atlas_less_cat1_secret_key_bytes() === 32) {
                    return true;
                }
            } catch (\Throwable) {
                // next
            }
        }
        return false;
    }

    private function needSignHalf(): void
    {
        if (!LessFfi::available() || !self::signHalfLoads()) {
            $this->markTestSkipped('no libatlas_less with keygen / sign');
        }
    }

    private static function seed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/less-kill-3/' . $label, true);
    }

    /** A seed that is not 32 bytes is refused before the library is looked up. */
    public function testSeedLengthIsChecked(): void
    {
        foreach ([fn() => LessFfi::keygen(str_repeat("\1", 31)), fn() => LessFfi::sign(str_repeat("\1", 32), 'm', str_repeat("\1", 33))] as $i => $f) {
            try {
                $f();
                $this->fail('a wrong-length seed was accepted');
            } catch (\InvalidArgumentException $e) {
                $this->assertSame($i === 0 ? 'lessCat1Keygen: seed must be 32 bytes' : 'lessCat1Sign: seed must be 32 bytes', $e->getMessage());
            }
        }
    }

    /** Without a usable verify half the sign half is never loaded: keygen and sign refuse with the status reason. */
    public function testSignHalfNeedsTheVerifyHalf(): void
    {
        $saved = self::save();
        self::set(['tried' => true, 'ffi' => null, 'signTried' => false, 'signFfi' => null]);
        try {
            $this->assertSame(['available' => false, 'reason' => extension_loaded('FFI') ? 'libatlas_less was not found (set ATLAS_PCA_LIBLESS)' : 'the FFI extension is not loaded'], LessFfi::status());
            $why = extension_loaded('FFI') ? 'libatlas_less was not found (set ATLAS_PCA_LIBLESS)' : 'the FFI extension is not loaded';
            foreach (['lessCat1Keygen' => fn() => LessFfi::keygen(self::seed('k')), 'lessCat1Sign' => fn() => LessFfi::sign(self::seed('k'), 'm', self::seed('r'))] as $name => $f) {
                try {
                    $f();
                    $this->fail("$name worked without a verify half");
                } catch (\RuntimeException $e) {
                    $this->assertSame("$name: LESS suites are unsupported ($why)", $e->getMessage());
                }
            }
        } finally {
            self::set($saved);
        }
    }

    /** Deterministic keygen, a signature that verifies and a wrong-length secret key refused by the library. */
    public function testKeygenSignVerifyRoundTrip(): void
    {
        $this->needSignHalf();
        $saved = self::save();
        self::set(['signTried' => false, 'signFfi' => null]); // a fresh load of the sign half
        try {
            $kp = LessFfi::keygen(self::seed('k'));
            $this->assertSame(['publicKey', 'secretKey'], array_keys($kp));
            $this->assertSame(LessFfi::PUBLIC_KEY_BYTES, strlen($kp['publicKey']));
            $this->assertSame(LessFfi::SECRET_KEY_BYTES, strlen($kp['secretKey']));
            $this->assertSame($kp, LessFfi::keygen(self::seed('k')));
            $sig = LessFfi::sign($kp['secretKey'], 'atlas less', self::seed('r'));
            $this->assertTrue(LessFfi::sigLenOk(strlen($sig)));
            $this->assertTrue(LessFfi::verify($kp['publicKey'], 'atlas less', $sig));
            $this->assertFalse(LessFfi::verify($kp['publicKey'], 'atlas lesS', $sig));
            try {
                LessFfi::sign(substr($kp['secretKey'], 1), 'atlas less', self::seed('r'));
                $this->fail('a 31-byte secret key signed');
            } catch (\RuntimeException $e) {
                $this->assertSame('lessCat1Sign: the library refused the key', $e->getMessage());
            }
        } finally {
            self::set($saved);
        }
    }

    /** A missing first candidate is skipped, not the end of the search. */
    public function testMissingCandidateIsSkipped(): void
    {
        $env = (string)getenv('ATLAS_PCA_LIBLESS');
        $first = explode(PATH_SEPARATOR, $env)[0];
        if ($first === '' || !is_file($first)) {
            $this->markTestSkipped('ATLAS_PCA_LIBLESS does not name a library');
        }
        $this->needSignHalf();
        $saved = self::save();
        self::set(['signTried' => false, 'signFfi' => null]);
        putenv('ATLAS_PCA_LIBLESS=' . '/nonexistent/libatlas_less.so' . PATH_SEPARATOR . $env);
        try {
            $this->assertSame(LessFfi::PUBLIC_KEY_BYTES, strlen(LessFfi::keygen(self::seed('k'))['publicKey']));
        } finally {
            putenv("ATLAS_PCA_LIBLESS=$env");
            self::set($saved);
        }
    }
}
