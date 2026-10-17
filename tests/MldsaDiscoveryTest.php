<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Mldsa;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * ML-DSA-65 library discovery (OpensslPq::ffi caches its handle per process, so every case runs in a fresh process) and the
 * verify() edges, against a REAL ML-DSA-65 signature from the TS reference (primitives.pq_artifact, alg ml-dsa-65).
 * The box layout this pins: an OpenSSL >= 3.5 libcrypto named by ATLAS_PCA_LIBCRYPTO, and the distro OpenSSL 3.0
 * libcrypto (no ML-DSA) under /usr/lib/x86_64-linux-gnu. Cases whose library is absent are skipped unless
 * PCA_REQUIRE_MLDSA=1 (the mutation run), where they fail.
 */
final class MldsaDiscoveryTest extends TestCase
{
    private const DISTRO_30 = '/usr/lib/x86_64-linux-gnu/libcrypto.so.3';

    /** @return array{0:string,1:string,2:string} [pk, msg, sig] raw bytes of a valid ML-DSA-65 artifact signature */
    private static function vector(): array
    {
        foreach (Corpus::core()->get('primitives')->get('pq_artifact') as $a) {
            if ($a->get('alg') === 'ml-dsa-65' && $a->get('valid') === true) {
                return [Pca::unb64u($a->get('pq_pk')), Pca::unb64u($a->get('message')), Pca::unb64u($a->get('sig'))];
            }
        }
        throw new \LogicException('no valid ml-dsa-65 pq_artifact vector');
    }

    private function good35(): string
    {
        $p = getenv('PCA_GOOD_LIBCRYPTO') ?: getenv('ATLAS_PCA_LIBCRYPTO');
        if (!is_string($p) || $p === '' || !is_file($p)) {
            if (getenv('PCA_REQUIRE_MLDSA') === '1') {
                $this->fail('PCA_REQUIRE_MLDSA=1 but no OpenSSL >= 3.5 libcrypto (ATLAS_PCA_LIBCRYPTO)');
            }
            $this->markTestSkipped('no OpenSSL >= 3.5 libcrypto configured');
        }
        return $p;
    }

    /**
     * True iff `$lib` loads and reports an OpenSSL version below 3.5 (no ML-DSA). A distro libcrypto.so.3 is NOT always 3.0:
     * ubuntu-26.04 ships OpenSSL 3.5+, whose ML-DSA makes every "no ML-DSA on the box" premise below false.
     */
    public static function isPre35(string $lib): bool
    {
        try {
            $v = \FFI::cdef('unsigned long OpenSSL_version_num(void);', $lib)->OpenSSL_version_num();
        } catch (\Throwable) {
            return false;
        }
        return is_int($v) && $v < 0x30500000;
    }

    /** The box layout these cases pin: the distro OpenSSL 3.0 libcrypto exists AND no default candidate has ML-DSA. */
    private function need30(): void
    {
        $why = null;
        if (!is_file(self::DISTRO_30)) {
            $why = 'no distro OpenSSL 3.0 libcrypto';
        } else {
            $env = getenv('ATLAS_PCA_LIBCRYPTO');
            putenv('ATLAS_PCA_LIBCRYPTO');
            $defaults = Mldsa::candidates();
            if (is_string($env)) {
                putenv('ATLAS_PCA_LIBCRYPTO=' . $env);
            }
            foreach ($defaults as $lib) {
                if (!self::isPre35($lib)) {
                    $why = "default libcrypto candidate $lib is OpenSSL >= 3.5 (or unloadable), not a no-ML-DSA box";
                    break;
                }
            }
        }
        if ($why !== null) {
            if (getenv('PCA_REQUIRE_MLDSA') === '1') {
                $this->fail("PCA_REQUIRE_MLDSA=1 but $why");
            }
            $this->markTestSkipped($why);
        }
    }

    #[RunInSeparateProcess]
    public function testExplicitGoodLibraryVerifies(): void
    {
        putenv('ATLAS_PCA_LIBCRYPTO=' . $this->good35());
        [$pk, $msg, $sig] = self::vector();
        $this->assertTrue(Mldsa::available());
        $this->assertTrue(Mldsa::verify($pk, $msg, $sig));
        $this->assertTrue(Mldsa::available(), 'the handle is cached, not lost after use');
        $bad = $sig;
        $bad[100] = chr(ord($bad[100]) ^ 1);
        $this->assertFalse(Mldsa::verify($pk, $msg, $bad));
        $this->assertFalse(Mldsa::verify($pk, $msg . 'x', $sig));
        $this->assertFalse(Mldsa::verify($pk, '', $sig), 'empty message is a real (failing) verify, not a crash');
        $this->assertFalse(Mldsa::verify(substr($pk, 1), $msg, $sig));
        $this->assertFalse(Mldsa::verify($pk . 'x', $msg, $sig));
        $this->assertFalse(Mldsa::verify($pk, $msg, substr($sig, 1)));
        $this->assertFalse(Mldsa::verify($pk, $msg, $sig . 'x'));
        // a message whose first bytes match but which is shorter/longer: the whole message is bound
        $this->assertFalse(Mldsa::verify($pk, substr($msg, 0, -1), $sig));
    }

    #[RunInSeparateProcess]
    public function testOnlyAPre35LibraryMeansUnavailable(): void
    {
        $this->need30();
        // The explicit override is tried FIRST; the distro candidates (all OpenSSL 3.0 on the box) must all be refused too.
        putenv('ATLAS_PCA_LIBCRYPTO=' . self::DISTRO_30);
        [$pk, $msg, $sig] = self::vector();
        $this->assertFalse(Mldsa::available());
        $this->assertFalse(Mldsa::verify($pk, $msg, $sig), 'no ML-DSA library: fail closed');
        $this->assertFalse(Pca::suiteAvailable('ml-dsa-65'));
        $this->assertTrue(Pca::suiteAvailable('ed25519'));
    }

    #[RunInSeparateProcess]
    public function testUnloadableOverrideFallsBackToCandidates(): void
    {
        $this->need30();
        putenv('ATLAS_PCA_LIBCRYPTO=/nonexistent/libcrypto.so.3');
        $this->assertFalse(Mldsa::available(), 'a bad override is skipped; the distro 3.0 candidates have no ML-DSA');
    }

    #[RunInSeparateProcess]
    public function testEmptyOverrideIsIgnored(): void
    {
        $this->need30();
        putenv('ATLAS_PCA_LIBCRYPTO=');
        $this->assertFalse(Mldsa::available());
    }

    /** The candidate list: override entries first (PATH_SEPARATOR list, empties dropped), then every existing default path. */
    #[RunInSeparateProcess]
    public function testCandidateList(): void
    {
        $defaults = [];
        foreach ([
            '/opt/homebrew/opt/openssl@3/lib/libcrypto*.dylib', '/opt/homebrew/lib/libcrypto*.dylib',
            '/usr/local/opt/openssl@3/lib/libcrypto*.dylib', '/usr/lib/libcrypto.so.3', '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
            '/usr/lib/aarch64-linux-gnu/libcrypto.so.3', '/lib/x86_64-linux-gnu/libcrypto.so.3',
        ] as $pat) {
            foreach (glob($pat) ?: [] as $m) {
                $defaults[] = $m;
            }
        }
        putenv('ATLAS_PCA_LIBCRYPTO');
        $this->assertSame($defaults, Mldsa::candidates());
        putenv('ATLAS_PCA_LIBCRYPTO=');
        $this->assertSame($defaults, Mldsa::candidates());
        putenv('ATLAS_PCA_LIBCRYPTO=/a/x.so');
        $this->assertSame(['/a/x.so', ...$defaults], Mldsa::candidates());
        putenv('ATLAS_PCA_LIBCRYPTO=/a/x.so' . PATH_SEPARATOR . PATH_SEPARATOR . '/b/y.so');
        $this->assertSame(['/a/x.so', '/b/y.so', ...$defaults], Mldsa::candidates());
        if (getenv('PCA_REQUIRE_MLDSA') === '1') {
            $this->assertGreaterThanOrEqual(2, count($defaults), 'the box has the distro libcrypto under /usr/lib and /lib');
        }
    }

    /** A library that loads but has no ML-DSA (or does not load) is skipped and the NEXT candidate is tried. */
    #[RunInSeparateProcess]
    public function testDiscoveryContinuesPastUnusableLibraries(): void
    {
        $good = $this->good35();
        $this->need30();
        putenv('ATLAS_PCA_LIBCRYPTO=/nonexistent/libcrypto.so.3' . PATH_SEPARATOR . self::DISTRO_30 . PATH_SEPARATOR . $good);
        [$pk, $msg, $sig] = self::vector();
        $this->assertTrue(Mldsa::available());
        $this->assertTrue(Mldsa::verify($pk, $msg, $sig));
    }

    /** The probe runs once per process: the handle found first is kept even if the environment changes later. */
    #[RunInSeparateProcess]
    public function testHandleIsCachedForTheProcess(): void
    {
        putenv('ATLAS_PCA_LIBCRYPTO=' . $this->good35());
        $this->assertTrue(Mldsa::available());
        putenv('ATLAS_PCA_LIBCRYPTO=/nonexistent/libcrypto.so.3');
        $this->assertTrue(Mldsa::available());
        [$pk, $msg, $sig] = self::vector();
        $this->assertTrue(Mldsa::verify($pk, $msg, $sig));
    }
}
