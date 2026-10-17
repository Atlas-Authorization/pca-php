<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\LessFfi;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\HttpFactory;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for the 0.4.2 native seams (pca-php mutation run 38330645854): libatlas_less discovery and length rules
 * (LessFfi), the OpenSSL >= 3.5 PQ backend's fail-closed branches (OpensslPq), the capability manifest, the PQ suite
 * dispatch's no-key refusal, and the middleware's intentV2 normalisation.
 *
 * Everything runs IN PROCESS: Infection runs a mutant's tests with the mutated file swapped in by a stream wrapper that a
 * #[RunInSeparateProcess] child does not inherit, so the separate-process seam tests of R041MutationKillTest never see a
 * mutant (their branches all survived). A case that rewires a backend's process-wide state (the loaded FFI handle, the
 * probe cache, the thread's default OpenSSL library context) restores it in `finally`.
 */
final class R042NativeSeamKillTest extends TestCase
{
    private const CDEF_FULL = 'void* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const unsigned char* key, size_t keylen);
        void* EVP_MD_CTX_new(void);
        int EVP_DigestVerifyInit_ex(void* ctx, void** pctx, const char* mdname, void* libctx, const char* props, void* pkey, void* params);
        int EVP_DigestVerify(void* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen);
        void EVP_PKEY_free(void* pkey);
        void EVP_MD_CTX_free(void* ctx);';
    private const CDEF_CTX = 'void* OSSL_LIB_CTX_new(void);
        void* OSSL_LIB_CTX_set0_default(void* libctx);
        void* OSSL_PROVIDER_load(void* libctx, const char* name);';

    /** @return array<string,mixed> the private static state of `$class` */
    private static function saveStatics(string $class, array $props): array
    {
        $s = [];
        foreach ($props as $p) {
            $s[$p] = (new \ReflectionProperty($class, $p))->getValue();
        }
        return $s;
    }

    private static function setStatics(string $class, array $values): void
    {
        foreach ($values as $p => $v) {
            (new \ReflectionProperty($class, $p))->setValue(null, $v);
        }
    }

    /** Run `$f` with the environment variable `$name` set to `$value` (null = unset), restoring it afterwards. */
    private static function withEnv(string $name, ?string $value, callable $f): mixed
    {
        $old = getenv($name);
        $value === null ? putenv($name) : putenv("$name=$value");
        try {
            return $f();
        } finally {
            $old === false ? putenv($name) : putenv("$name=$old");
        }
    }

    // ================================================================== LessFfi

    /** The source directory LessFfi::candidates() builds its fallbacks from (LessFfi.php's own __DIR__). */
    private static function lessDir(): string
    {
        return dirname((string)(new \ReflectionClass(LessFfi::class))->getFileName());
    }

    /** candidates(): the override's non-empty entries in order (re-indexed), then the three repository build paths. */
    public function testLessCandidatesExact(): void
    {
        $tail = array_map(fn($n) => self::lessDir() . '/../../pca-less-c/build/' . $n, ['libatlas_less.so', 'libatlas_less.dylib', 'atlas_less.dll']);
        $this->assertSame(array_merge(['/a/x.so', '/b/y.so'], $tail),
            self::withEnv('ATLAS_PCA_LIBLESS', '/a/x.so' . PATH_SEPARATOR . PATH_SEPARATOR . '/b/y.so' . PATH_SEPARATOR, fn() => LessFfi::candidates()));
        $this->assertSame($tail, self::withEnv('ATLAS_PCA_LIBLESS', null, fn() => LessFfi::candidates()));
        $this->assertSame($tail, self::withEnv('ATLAS_PCA_LIBLESS', '', fn() => LessFfi::candidates()));
    }

    /** The less-252-45 detached signature: 1,153..1,329 bytes in steps of 16 (counted down from the maximum). */
    public function testLessSignatureLengths(): void
    {
        foreach ([1153 => true, 1169 => true, 1313 => true, 1329 => true, 1152 => false, 1154 => false, 1168 => false,
                  1328 => false, 1330 => false, 1345 => false, 1137 => false, 0 => false, 2482 => false] as $n => $ok) {
            $this->assertSame($ok, LessFfi::sigLenOk($n), "length $n");
        }
    }

    /** A library counts only when all three reported sizes are the parameter set's. */
    public function testLessSizesMatch(): void
    {
        $this->assertTrue(LessFfi::sizesMatch(97484, 1153, 1329));
        foreach ([[97483, 1153, 1329], [97484, 1152, 1329], [97484, 1153, 1328], [0, 0, 0], [97484, 1329, 1153],
                  [97483, 1152, 1328], [97484, 1152, 1328], [97483, 1153, 1328], [97483, 1152, 1329]] as $s) {
            $this->assertFalse(LessFfi::sizesMatch(...$s), implode(',', $s));
        }
    }

    /** Wrong lengths are refused before any library is touched, whether or not one is loaded. */
    public function testLessWrongLengthsRefused(): void
    {
        $pk = str_repeat("\0", LessFfi::PUBLIC_KEY_BYTES);
        $this->assertFalse(LessFfi::verify(substr($pk, 1), 'm', str_repeat("\0", 1153)));
        $this->assertFalse(LessFfi::verify($pk . "\0", 'm', str_repeat("\0", 1329)));
        $this->assertFalse(LessFfi::verify($pk, 'm', str_repeat("\0", 1154)));
        $this->assertFalse(LessFfi::verify($pk, 'm', str_repeat("\0", 1345)));
        $this->assertFalse(LessFfi::verify('', '', ''));
    }

    /** The path of a loadable libatlas_less, or the test is skipped (the CI mutation shards build one: LESS=1). */
    private function lessLib(): string
    {
        foreach (LessFfi::candidates() as $p) {
            if (is_file($p)) {
                try {
                    $f = \FFI::cdef('size_t atlas_less_cat1_public_key_bytes(void);', $p);
                    if ($f->atlas_less_cat1_public_key_bytes() === LessFfi::PUBLIC_KEY_BYTES) {
                        return $p;
                    }
                } catch (\Throwable) {
                }
            }
        }
        $this->markTestSkipped('libatlas_less not built (sdks/pca-less-c/build.sh) or not at ATLAS_PCA_LIBLESS');
    }

    /**
     * Discovery from scratch: it skips a candidate that is not a file and loads the next one; once tried, the cached result
     * is used (no second discovery).
     */
    public function testLessDiscovery(): void
    {
        $lib = $this->lessLib();
        $saved = self::saveStatics(LessFfi::class, ['ffi', 'tried']);
        try {
            self::withEnv('ATLAS_PCA_LIBLESS', sys_get_temp_dir() . '/no-such-libatlas_less-' . getmypid() . '.so' . PATH_SEPARATOR . $lib,
                function () {
                    self::setStatics(LessFfi::class, ['ffi' => null, 'tried' => false]);
                    $this->assertTrue(LessFfi::available(), 'discovered past the missing first candidate');
                    $this->assertTrue((new \ReflectionProperty(LessFfi::class, 'tried'))->getValue());
                    self::setStatics(LessFfi::class, ['ffi' => null]); // keep `tried`
                    $this->assertFalse(LessFfi::available(), 'a tried discovery is not repeated');
                });
        } finally {
            self::setStatics(LessFfi::class, $saved);
        }
    }

    /** A loaded handle whose verify call throws (the symbol is not declared): verify is false, never an exception. */
    public function testLessThrowingCallIsARefusal(): void
    {
        $lib = $this->lessLib();
        $saved = self::saveStatics(LessFfi::class, ['ffi', 'tried']);
        try {
            self::setStatics(LessFfi::class, ['ffi' => \FFI::cdef('size_t atlas_less_cat1_public_key_bytes(void);', $lib), 'tried' => true]);
            $this->assertFalse(LessFfi::verify(str_repeat("\0", LessFfi::PUBLIC_KEY_BYTES), 'm', str_repeat("\0", LessFfi::SIGNATURE_MIN_BYTES)));
        } finally {
            self::setStatics(LessFfi::class, $saved);
        }
    }

    // ================================================================== OpensslPq

    /** An unknown key type is never available and never verifies. */
    public function testOpensslUnknownKeyType(): void
    {
        foreach (['', 'ML-DSA-44', 'ml-dsa-65', 'LESS-cat1', 'Ed25519'] as $t) {
            $this->assertFalse(OpensslPq::available($t), $t);
            $this->assertFalse(OpensslPq::verify($t, str_repeat("\0", 1952), 'a', str_repeat("\0", 3309)), $t);
        }
    }

    /** @return array{0:string,1:string,2:string} a valid ML-DSA-65 (pk, msg, sig) */
    private static function mldsaVector(): array
    {
        $e = json_decode((string)file_get_contents(__DIR__ . '/../test-data/mldsa65-edge.json'), true);
        return [(string)Pca::unb64u($e['pq_pk']), 'a', (string)Pca::unb64u($e['one_byte_sig'])];
    }

    /** A libcrypto handle (with the library-context functions) whose provider builds ML-DSA-65 keys, else skipped. */
    private function goodLibcrypto(): \FFI
    {
        foreach (OpensslPq::candidates() as $p) {
            try {
                $f = \FFI::cdef(self::CDEF_FULL . self::CDEF_CTX, $p);
                if ((new \ReflectionMethod(OpensslPq::class, 'builds'))->invoke(null, $f, 'ML-DSA-65')) {
                    return $f;
                }
            } catch (\Throwable) {
            }
        }
        $this->markTestSkipped('no ML-DSA capable libcrypto among the candidates');
    }

    /** A key type cached as available but no library handle: verify refuses. */
    public function testOpensslNoHandleRefuses(): void
    {
        [$pk, $msg, $sig] = self::mldsaVector();
        $saved = self::saveStatics(OpensslPq::class, ['ffi', 'tried', 'probed']);
        try {
            self::setStatics(OpensslPq::class, ['ffi' => null, 'tried' => true, 'probed' => ['ML-DSA-65' => true]]);
            $this->assertFalse(OpensslPq::verify('ML-DSA-65', $pk, $msg, $sig));
        } finally {
            self::setStatics(OpensslPq::class, $saved);
        }
    }

    /**
     * The key import fails (this thread's default library context has only the `null` provider) while the key type is
     * cached as available: verify refuses at the import. Control: the same handle verifies once the context is restored.
     */
    public function testOpensslKeyImportFailureRefuses(): void
    {
        $f = $this->goodLibcrypto();
        [$pk, $msg, $sig] = self::mldsaVector();
        $saved = self::saveStatics(OpensslPq::class, ['ffi', 'tried', 'probed']);
        try {
            self::setStatics(OpensslPq::class, ['ffi' => $f, 'tried' => true, 'probed' => ['ML-DSA-65' => true]]);
            $ctx = $f->OSSL_LIB_CTX_new();
            $prov = $f->OSSL_PROVIDER_load($ctx, 'null');
            $this->assertFalse($prov === null || \FFI::isNull($prov), 'the null provider loads');
            $prev = $f->OSSL_LIB_CTX_set0_default($ctx);
            try {
                $this->assertFalse(OpensslPq::verify('ML-DSA-65', $pk, $msg, $sig));
            } finally {
                $f->OSSL_LIB_CTX_set0_default($prev);
            }
            $this->assertTrue(OpensslPq::verify('ML-DSA-65', $pk, $msg, $sig), 'control: the default context verifies');
        } finally {
            self::setStatics(OpensslPq::class, $saved);
        }
    }

    // ================================================================== Pca

    /** The capability manifest is a list (re-indexed after the unavailable suites are filtered out), in registry order. */
    public function testSupportedSuitesIsAList(): void
    {
        $s = Pca::supportedSuites();
        $this->assertTrue(array_is_list($s));
        $this->assertSame('ed25519', $s[0]);
        $this->assertNotContains('fn-dsa-512', $s);
        $this->assertSame(in_array('less-cat1', $s, true), LessFfi::available());
    }

    /** The suite dispatch refuses a PQ suite outright when no verifier-side key was resolved (no PinnedPq). */
    public function testPqSuiteWithoutResolvedKeyRefused(): void
    {
        $pq = array_values(array_filter(Pca::supportedSuites(), fn($s) => $s !== 'ed25519'));
        if ($pq === []) {
            $this->markTestSkipped('no PQ suite in this runtime');
        }
        $m = new \ReflectionMethod(Pca::class, 'verifySuite');
        foreach ($pq as $suite) {
            $p = Obj::of(['alg' => $suite, 'sig' => Pca::b64u(str_repeat("\1", 64)), 'pq_sig' => 'AAAA']);
            $this->assertFalse($m->invoke(null, $p, Pca::b64u(str_repeat("\2", 32)), 'msg', null), $suite);
        }
    }

    // ================================================================== PcaMiddleware

    /** Any PHP callable resolver (an invokable object, a [object, method] pair) is accepted and wrapped as a Closure. */
    public function testMiddlewareAcceptsAnyCallableResolver(): void
    {
        $f = new HttpFactory();
        $inv = new class {
            public function __invoke(Obj $p): ?Obj
            {
                return null;
            }

            public function resolve(Obj $p): ?Obj
            {
                return null;
            }
        };
        foreach ([$inv, [$inv, 'resolve'], null, new Obj()] as $i => $v2) {
            $mw = new PcaMiddleware('aud', fn() => null, null, $f, $f, 'pca', null, $v2);
            $held = (new \ReflectionProperty(PcaMiddleware::class, 'intentV2'))->getValue($mw);
            if ($v2 === null || $v2 instanceof Obj) {
                $this->assertSame($v2, $held, "case $i");
            } else {
                $this->assertInstanceOf(\Closure::class, $held, "case $i");
            }
        }
    }
}
