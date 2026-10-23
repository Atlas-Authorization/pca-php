<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Mldsa;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for the 0.4.1 surfaces (pca-php mutation.yml on ci/0.4.1-mut): the policy-layer caveat helpers
 * (policyCaveats / evaluateCaveats, semantics of envelopeCaveatEvaluator + max_spend in packages/pca/src) and the ML-DSA
 * library seam (discovery, the capability probe, fail-closed verify, Pca::suiteAvailable).
 *
 * The ML-DSA cases are HOST-AGNOSTIC: they need only some ML-DSA capable libcrypto among Mldsa::candidates() (macOS
 * runners: Homebrew openssl@3), never a pre-3.5 distro library. "A library without ML-DSA" is made from the good one by
 * switching the calling thread's default OSSL_LIB_CTX to a fresh context that loads only the `null` provider
 * (OSSL_LIB_CTX_set0_default), and a second, distinct library image is a temporary copy of the good file. The handle
 * lives in Mldsa (0.4.1) or OpensslPq (later), reached by reflection either way; every case runs in its own process.
 */
final class R041MutationKillTest extends TestCase
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

    // ================================================================== caveat helpers

    private static function ctx(array $extra = [], array $action = []): Obj
    {
        return Obj::of(['now' => new Num('1800000000000'), 'action' => Obj::of($action)] + $extra);
    }

    private static function cv(array $m): Obj
    {
        return Obj::of($m);
    }

    /** An object that answers has() / get() like Obj but is not a parsed JSON object. */
    private static function lookAlike(array $m): object
    {
        return new class ($m) {
            public function __construct(private array $m)
            {
            }

            public function has(string $k): bool
            {
                return array_key_exists($k, $this->m);
            }

            public function get(string $k): mixed
            {
                return $this->m[$k] ?? null;
            }
        };
    }

    private static function ok(array $caveats, mixed $ctx): bool
    {
        return Pca::evaluateCaveats($caveats, $ctx)['ok'];
    }

    /** policyCaveats skips only a parsed-object envelope caveat; any other element (scalar, look-alike) is kept as is. */
    public function testPolicyCaveatsKeepsNonObjectElements(): void
    {
        $env = self::cv(['type' => 'envelope']);
        $a = self::cv(['type' => 'max_spend', 'usd' => new Num('1')]);
        $fake = self::lookAlike(['type' => 'envelope']);
        $n = new Num('1');
        $this->assertSame(['x', $n, $a], Pca::policyCaveats(Obj::of(['caveats' => ['x', $n, $env, $a]]), null));
        // a look-alike "envelope" is not the envelope caveat: it is kept, and the real one after it is skipped
        $this->assertSame([$fake, $a], Pca::policyCaveats(Obj::of(['caveats' => [$fake, $env, $a]]), null));
    }

    /** Only parsed JSON objects are caveats / contexts / actions / params: look-alike objects fail closed. */
    public function testEvaluateCaveatsRefusesLookAlikeObjects(): void
    {
        $budget = ['type' => 'budget_alloc', 'limit' => new Num('1')];
        $this->assertSame(['ok' => true, 'failed' => []], Pca::evaluateCaveats([self::cv($budget)], self::ctx()), 'control');
        // a look-alike caveat (its type is not read: '<malformed>')
        $this->assertSame(['ok' => false, 'failed' => ['<malformed>']], Pca::evaluateCaveats([self::lookAlike($budget)], self::ctx()));
        // a look-alike context
        $this->assertSame(['ok' => false, 'failed' => ['budget_alloc']], Pca::evaluateCaveats([self::cv($budget)], self::lookAlike(['now' => new Num('1')])));
        // both look-alike
        $this->assertFalse(self::ok([self::lookAlike($budget)], self::lookAlike(['now' => new Num('1')])));

        $ms = self::cv(['type' => 'max_spend', 'usd' => new Num('5')]);
        $params = ['amount' => new Num('1')];
        $this->assertTrue(self::ok([$ms], Obj::of(['action' => Obj::of(['params' => Obj::of($params)])])), 'control');
        // a look-alike action
        $this->assertSame(['ok' => false, 'failed' => ['max_spend']], Pca::evaluateCaveats([$ms], Obj::of(['action' => self::lookAlike(['params' => Obj::of($params)])])));
        // look-alike params (with an own amount)
        $this->assertSame(['ok' => false, 'failed' => ['max_spend']], Pca::evaluateCaveats([$ms], Obj::of(['action' => Obj::of(['params' => self::lookAlike($params)])])));
    }

    /** evaluateCaveats is total: a caveat whose evaluation throws is unsatisfied, never satisfied. */
    public function testThrowingCaveatIsUnsatisfied(): void
    {
        $bomb = new class {
            public function __toString(): string
            {
                throw new \LogicException('boom');
            }
        };
        $c = self::cv(['type' => $bomb, 'at' => new Num('1900000000000')]);
        $this->assertSame(['ok' => false, 'failed' => ['<malformed>']], Pca::evaluateCaveats([$c], self::ctx()));
        $this->assertSame(['ok' => false, 'failed' => ['<malformed>', 'note']], Pca::evaluateCaveats([$c, self::cv(['type' => 'note'])], self::ctx()));
    }

    /** rate counts only the finite numbers of recent_action_times; any other entry is skipped, not an error. */
    public function testRateSkipsNonNumericTimes(): void
    {
        $now = 1800000000000;
        $rate = self::cv(['type' => 'rate', 'max' => new Num('2'), 'per_secs' => new Num('60')]);
        $times = ['x', true, null, [], Obj::of([]), new Num((string)($now - 1000))];
        $this->assertSame(['ok' => true, 'failed' => []], Pca::evaluateCaveats([$rate], self::ctx(['recent_action_times' => $times])));
        $times[] = $now - 2000; // a native int counts too: 2 in the window, not < 2
        $this->assertSame(['ok' => false, 'failed' => ['rate']], Pca::evaluateCaveats([$rate], self::ctx(['recent_action_times' => $times])));
    }

    /** max_spend {usd: 0} is a valid ceiling (finite >= 0): a zero amount passes, any positive amount fails. */
    public function testMaxSpendZeroCeiling(): void
    {
        $ms = self::cv(['type' => 'max_spend', 'usd' => new Num('0')]);
        $this->assertTrue(self::ok([$ms], self::ctx([], ['params' => Obj::of(['amount' => new Num('0')])])));
        $this->assertFalse(self::ok([$ms], self::ctx([], ['params' => Obj::of(['amount' => new Num('0.01')])])));
        $neg = self::cv(['type' => 'max_spend', 'usd' => new Num('-0.01')]);
        $this->assertFalse(self::ok([$neg], self::ctx([], ['params' => Obj::of(['amount' => new Num('0')])])));
    }

    /** rate needs finite max AND per_secs > 0 AND a list of times; otherwise unsatisfied even with no recent actions. */
    public function testRateParameterGuards(): void
    {
        $ctx = self::ctx(['recent_action_times' => []]);
        $rate = fn(array $m) => self::cv(['type' => 'rate'] + $m);
        $this->assertTrue(self::ok([$rate(['max' => new Num('1'), 'per_secs' => new Num('1')])], $ctx), 'control');
        $this->assertFalse(self::ok([$rate(['max' => new Num('1'), 'per_secs' => new Num('0')])], $ctx), 'per_secs 0');
        $this->assertFalse(self::ok([$rate(['max' => new Num('1'), 'per_secs' => new Num('-1')])], $ctx), 'per_secs < 0');
        $this->assertFalse(self::ok([$rate(['max' => new Num('1')])], $ctx), 'per_secs absent');
        $this->assertFalse(self::ok([$rate(['per_secs' => new Num('1')])], $ctx), 'max absent');
        $this->assertFalse(self::ok([$rate(['max' => new Num('1'), 'per_secs' => new Num('1')])], self::ctx()), 'times absent');
        $this->assertFalse(self::ok([$rate(['max' => new Num('1'), 'per_secs' => new Num('1')])], self::ctx(['recent_action_times' => Obj::of([])])), 'times not a list');
    }

    /** The rate window is (now - per_secs*1000, now]: an action at exactly `now` counts, a future one does not. */
    public function testRateWindowIncludesNow(): void
    {
        $now = 1800000000000;
        $rate = self::cv(['type' => 'rate', 'max' => new Num('1'), 'per_secs' => new Num('60')]);
        $this->assertFalse(self::ok([$rate], self::ctx(['recent_action_times' => [new Num((string)$now)]])));
        $this->assertTrue(self::ok([$rate], self::ctx(['recent_action_times' => [new Num((string)($now + 1))]])));
        $this->assertTrue(self::ok([$rate], self::ctx(['recent_action_times' => [new Num((string)($now - 60000))]])), 'lower bound open');
        $this->assertFalse(self::ok([$rate], self::ctx(['recent_action_times' => [new Num((string)($now - 59999))]])));
    }

    /** reversibility_max: an unknown limit class satisfies nothing; an equal class is allowed. */
    public function testReversibilityMaxBoundaries(): void
    {
        $rv = fn(string $c) => [self::cv(['type' => 'reversibility_max', 'class' => $c])];
        $this->assertFalse(self::ok($rv('bogus'), self::ctx(['reversibility_class' => 'reversible'])));
        $this->assertFalse(self::ok($rv('bogus'), self::ctx(['reversibility_class' => 'irreversible'])));
        $this->assertTrue(self::ok($rv('rate_limited'), self::ctx(['reversibility_class' => 'rate_limited'])));
        $this->assertTrue(self::ok($rv('reversible'), self::ctx(['reversibility_class' => 'reversible'])));
        $this->assertFalse(self::ok($rv('rate_limited'), self::ctx(['reversibility_class' => 'irreversible'])));
    }

    /** delegation_depth needs a finite ctx.delegation_depth: an absent depth is unsatisfied (not "depth 0"). */
    public function testDelegationDepthNeedsADepth(): void
    {
        $dd = [self::cv(['type' => 'delegation_depth', 'max' => new Num('1')])];
        $this->assertFalse(self::ok($dd, self::ctx()));
        $this->assertTrue(self::ok($dd, self::ctx(['delegation_depth' => new Num('1')])));
        $this->assertFalse(self::ok($dd, self::ctx(['delegation_depth' => new Num('2')])));
        $this->assertFalse(self::ok([self::cv(['type' => 'delegation_depth'])], self::ctx(['delegation_depth' => new Num('0')])));
    }

    /** budget_alloc {limit}: satisfied iff limit is finite and >= 0 (0 included). */
    public function testBudgetAllocBoundaries(): void
    {
        $ba = fn(array $m) => [self::cv(['type' => 'budget_alloc'] + $m)];
        $this->assertTrue(self::ok($ba(['limit' => new Num('0')]), self::ctx()));
        $this->assertTrue(self::ok($ba(['limit' => 0]), self::ctx()));
        $this->assertTrue(self::ok($ba(['limit' => 0.5]), self::ctx()));
        $this->assertFalse(self::ok($ba([]), self::ctx()), 'limit absent');
        $this->assertFalse(self::ok($ba(['limit' => new Num('-1')]), self::ctx()));
        $this->assertFalse(self::ok($ba(['limit' => 'x']), self::ctx()));
    }

    // ================================================================== ML-DSA library seam

    /** The class holding the libcrypto handle: Mldsa (0.4.1) or OpensslPq (later releases). */
    private static function pqClass(): string
    {
        return property_exists(Mldsa::class, 'ffi') ? Mldsa::class : 'Atlas\\Pca\\OpensslPq';
    }

    private static function setStatic(string $prop, mixed $v): void
    {
        $c = self::pqClass();
        if (property_exists($c, $prop)) {
            (new \ReflectionProperty($c, $prop))->setValue(null, $v);
        }
    }

    /** Make `$f` the process handle (no further discovery). */
    private static function inject(?\FFI $f): void
    {
        self::setStatic('ffi', $f);
        self::setStatic('tried', true);
        self::setStatic('probed', []);
    }

    /** The private capability probe: can `$f` build an ML-DSA-65 public key? */
    private static function probe(\FFI $f): bool
    {
        $c = self::pqClass();
        return $c === Mldsa::class
            ? (new \ReflectionMethod($c, 'worksMlDsa'))->invoke(null, $f)
            : (new \ReflectionMethod($c, 'builds'))->invoke(null, $f, 'ML-DSA-65');
    }

    /** The first default candidate whose provider builds an ML-DSA-65 key (the test is skipped on a host without one). */
    private function goodLib(): string
    {
        putenv('ATLAS_PCA_LIBCRYPTO');
        foreach (Mldsa::candidates() as $p) {
            try {
                if (self::probe(\FFI::cdef(self::CDEF_FULL . self::CDEF_CTX, $p))) {
                    return $p;
                }
            } catch (\Throwable) {
            }
        }
        $this->markTestSkipped('no ML-DSA capable libcrypto among the candidates');
    }

    /** @return array{0:string,1:string,2:string} a valid ML-DSA-65 (pk, msg, sig) */
    private static function vec(): array
    {
        $e = json_decode(file_get_contents(__DIR__ . '/../test-data/mldsa65-edge.json'), true);
        return [Pca::unb64u($e['pq_pk']), 'a', Pca::unb64u($e['one_byte_sig'])];
    }

    /** Switch this thread's default library context of `$f`'s libcrypto to one with only the `null` provider. */
    private static function nullProviders(\FFI $f): mixed
    {
        $ctx = $f->OSSL_LIB_CTX_new();
        $p = $f->OSSL_PROVIDER_load($ctx, 'null');
        if ($p === null || \FFI::isNull($p)) {
            throw new \LogicException('the null provider did not load');
        }
        return $f->OSSL_LIB_CTX_set0_default($ctx);
    }

    /** Exact key / signature lengths are checked before any library is touched. */
    public function testWrongLengthsAreRefused(): void
    {
        $pk = str_repeat("\0", Mldsa::PUBLIC_KEY_BYTES);
        $sig = str_repeat("\0", Mldsa::SIGNATURE_BYTES);
        $this->assertFalse(Mldsa::verify(substr($pk, 1), 'a', $sig));
        $this->assertFalse(Mldsa::verify($pk . "\0", 'a', $sig));
        $this->assertFalse(Mldsa::verify($pk, 'a', substr($sig, 1)));
        $this->assertFalse(Mldsa::verify($pk, 'a', $sig . "\0"));
        $this->assertFalse(Mldsa::verify('', 'a', ''));
    }

    /** No usable library: ML-DSA is unavailable and fails closed; Ed25519 stays available. */
    #[RunInSeparateProcess]
    public function testNoLibraryFailsClosed(): void
    {
        self::inject(null);
        [$pk, $msg, $sig] = self::vec();
        $this->assertFalse(Mldsa::available());
        $this->assertFalse(Mldsa::verify($pk, $msg, $sig));
        $this->assertTrue(Pca::suiteAvailable('ed25519'));
        $this->assertFalse(Pca::suiteAvailable('ml-dsa-65'));
        $this->assertFalse(Pca::suiteAvailable('hybrid-ed25519-ml-dsa-65'));
        $this->assertFalse(Pca::suiteAvailable('nope'));
    }

    /** A provider that cannot build an ML-DSA-65 key: the probe says no and verify refuses at the key import. */
    #[RunInSeparateProcess]
    public function testKeyImportFailureIsARefusal(): void
    {
        $f = \FFI::cdef(self::CDEF_FULL . self::CDEF_CTX, $this->goodLib());
        [$pk, $msg, $sig] = self::vec();
        $prev = self::nullProviders($f);
        try {
            $this->assertFalse(self::probe($f));
            self::inject($f);
            $this->assertFalse(Mldsa::verify($pk, $msg, $sig));
        } finally {
            $f->OSSL_LIB_CTX_set0_default($prev);
        }
        $this->assertTrue(self::probe($f), 'control: the default context builds the key');
        self::inject($f);
        $this->assertTrue(Mldsa::verify($pk, $msg, $sig), 'control: and verifies');
    }

    /** An FFI call that throws (an undeclared function) is caught by the probe and by verify: false, no exception. */
    #[RunInSeparateProcess]
    public function testThrowingFfiCallsAreRefusals(): void
    {
        $good = $this->goodLib();
        $this->assertFalse(self::probe(\FFI::cdef('void EVP_PKEY_free(void* pkey);', $good)));
        $partial = 'void* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const unsigned char* key, size_t keylen);
            void EVP_PKEY_free(void* pkey);';
        [$pk, $msg, $sig] = self::vec();
        self::inject(\FFI::cdef($partial, $good));
        $this->assertFalse(Mldsa::verify($pk, $msg, $sig));
        self::inject(\FFI::cdef(self::CDEF_FULL, $good));
        $this->assertTrue(Mldsa::verify($pk, $msg, $sig), 'control');
    }

    /** Discovery skips a library that loads but has no ML-DSA and goes on to the next candidate. */
    #[RunInSeparateProcess]
    public function testDiscoveryContinuesPastALibraryWithoutMlDsa(): void
    {
        $good = $this->goodLib();
        $copy = sys_get_temp_dir() . '/pca-r041-' . getmypid() . '-' . basename($good);
        $this->assertTrue(copy($good, $copy));
        try {
            $fa = \FFI::cdef(self::CDEF_FULL . self::CDEF_CTX, $copy);
            self::nullProviders($fa); // this thread, the copy's image only
            $this->assertFalse(self::probe($fa), 'precondition: the copy has no ML-DSA here');
            $this->assertTrue(self::probe(\FFI::cdef(self::CDEF_FULL, $good)), 'precondition: the original is a distinct image');
            putenv('ATLAS_PCA_LIBCRYPTO=' . $copy);
            $this->assertSame($copy, Mldsa::candidates()[0]);
            [$pk, $msg, $sig] = self::vec();
            $this->assertTrue(Mldsa::available());
            $this->assertTrue(Mldsa::verify($pk, $msg, $sig));
        } finally {
            putenv('ATLAS_PCA_LIBCRYPTO');
            @unlink($copy);
        }
    }

    /** Discovery runs once per process: once tried, the cached result is used and the library is never re-probed. */
    #[RunInSeparateProcess]
    public function testDiscoveryRunsOncePerProcess(): void
    {
        $this->goodLib();
        $this->assertTrue(Mldsa::available());
        self::setStatic('ffi', null); // keep `tried`
        self::setStatic('probed', []);
        $this->assertFalse(Mldsa::available(), 'a tried discovery is not repeated');
    }
}
