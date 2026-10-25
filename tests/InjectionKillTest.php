<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Mldsa;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaMiddleware;
use GuzzleHttp\Psr7\ServerRequest;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;

/**
 * Fault injection for the R6-05 backstops and fallbacks that ordinary inputs never reach: a grant / root carrying a value the
 * strict profile cannot hash, ML-DSA FFI handles that fail mid-call, and PSR-17 discovery without guzzlehttp/psr7.
 */
final class InjectionKillTest extends TestCase
{
    private const DISTRO_30 = '/usr/lib/x86_64-linux-gnu/libcrypto.so.3';
    private const CDEF_FULL = 'void* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const unsigned char* key, size_t keylen);
        void* EVP_MD_CTX_new(void);
        int EVP_DigestVerifyInit_ex(void* ctx, void** pctx, const char* mdname, void* libctx, const char* props, void* pkey, void* params);
        int EVP_DigestVerify(void* ctx, const unsigned char* sig, size_t siglen, const unsigned char* tbs, size_t tbslen);
        void EVP_PKEY_free(void* pkey);
        void EVP_MD_CTX_free(void* ctx);';

    private static function deepCopy(mixed $v): mixed
    {
        return Json::parseLax(Json::canonicalizeStrict($v));
    }

    private static function coreVector(string $name): Obj
    {
        foreach (Corpus::core()->get('vectors') as $v) {
            if ($v->get('name') === $name) {
                return $v;
            }
        }
        throw new \LogicException("vector $name not found");
    }

    // ------------------------------------------------------------------ Pca backstops
    /** A stored grant the strict profile cannot hash (here an extra field 1e300) is a chain-check failure, not an exception. */
    public function testGrantThatCannotBeHashedFailsTheChainCheck(): void
    {
        $v = self::coreVector('valid-raw-json-format-insensitive');
        $ctx = $v->get('context');
        $grant = self::deepCopy($v->get('grant'));
        $grant->set('x', new Num('1e300'));
        $r = Pca::verifyJson($v->get('pcactn_json'), $grant, $ctx->get('now')->int(), $ctx->get('aud'));
        $this->assertFalse($r['allow']);
        $this->assertFalse($r['checks']['chain']);
        $this->assertSame('chain: malformed: exponent form is not allowed', $r['reason']);
        $this->assertTrue(Pca::verifyJson($v->get('pcactn_json'), $v->get('grant'), $ctx->get('now')->int(), $ctx->get('aud'))['allow']);
    }

    /**
     * A correctly signed root whose UNSIGNED extra field cannot be hashed passes its own body check (the signed body is a
     * fixed field subset) but breaks the next hop's parent hash: the chain backstop refuses it, as in the reference
     * ("malformed capability chain: ...").
     */
    public function testUnhashableParentHitsTheChainBackstop(): void
    {
        foreach (Corpus::core()->get('primitives')->get('chain_pin') as $v) {
            if ($v->get('name') !== 'chainpin-mixed-ed25519-root-bound-pq-hop') {
                continue;
            }
            $chain = self::deepCopy($v->get('chain'));
            $chain[0]->set('x', new Num('1e300'));
            $this->assertSame(['malformed capability chain: Atlas\Pca\JsonError', false], Pca::verifyChain($chain, $v->get('expected_root_issuer'), true));
            $this->assertTrue(Pca::verifyChain([$chain[0]], $v->get('expected_root_issuer'), true)[1], 'the root alone still verifies');
            return;
        }
        $this->fail('chain_pin vector missing');
    }

    // ------------------------------------------------------------------ ML-DSA FFI failures
    private function needLibs(bool $good = true): ?string
    {
        $g = getenv('ATLAS_PCA_LIBCRYPTO');
        // without the good library, the distro one must lack ML-DSA (ubuntu-26.04's libcrypto.so.3 is OpenSSL >= 3.5)
        $ok = is_file(self::DISTRO_30) && ($good ? is_string($g) && is_file($g) : MldsaDiscoveryTest::isPre35(self::DISTRO_30));
        if (!$ok) {
            if (getenv('PCA_REQUIRE_MLDSA') === '1') {
                $this->fail('libcrypto 3.0 / 3.5 not available');
            }
            $this->markTestSkipped('libcrypto 3.0 / 3.5 not available');
        }
        return $good ? $g : null;
    }

    private static function inject(\FFI $f): void
    {
        (new \ReflectionProperty(OpensslPq::class, 'ffi'))->setValue(null, $f);
        (new \ReflectionProperty(OpensslPq::class, 'tried'))->setValue(null, true);
        (new \ReflectionProperty(OpensslPq::class, 'probed'))->setValue(null, []);
    }

    /** @return array{0:string,1:string,2:string} a valid ML-DSA-65 (pk, msg, sig) */
    private static function vec(): array
    {
        $e = json_decode(file_get_contents(__DIR__ . '/../test-data/mldsa65-edge.json'), true);
        return [Pca::unb64u($e['pq_pk']), 'a', Pca::unb64u($e['one_byte_sig'])];
    }

    /** A library whose provider cannot build an ML-DSA-65 key (OpenSSL 3.0): verify() refuses at the key import. */
    #[RunInSeparateProcess]
    public function testVerifyRefusesWhenTheKeyCannotBeImported(): void
    {
        $this->needLibs(false);
        self::inject(\FFI::cdef(self::CDEF_FULL, self::DISTRO_30));
        [$pk, $msg, $sig] = self::vec();
        $this->assertFalse(Mldsa::verify($pk, $msg, $sig));
    }

    /** An FFI call that throws mid-verification (here: an undeclared function) is caught: false, no exception. */
    #[RunInSeparateProcess]
    public function testVerifyIsTotalWhenTheFfiCallThrows(): void
    {
        $good = $this->needLibs();
        $partial = 'void* EVP_PKEY_new_raw_public_key_ex(void* libctx, const char* keytype, const char* propq, const unsigned char* key, size_t keylen);
            void EVP_PKEY_free(void* pkey);';
        self::inject(\FFI::cdef($partial, $good));
        [$pk, $msg, $sig] = self::vec();
        $this->assertFalse(Mldsa::verify($pk, $msg, $sig));
        self::inject(\FFI::cdef(self::CDEF_FULL, $good));
        $this->assertTrue(Mldsa::verify($pk, $msg, $sig), 'control: the same signature verifies with the full binding');
    }

    /** The capability probe is total too: a handle without the key constructor is "no ML-DSA", not an exception. */
    #[RunInSeparateProcess]
    public function testProbeIsTotalWhenTheFfiCallThrows(): void
    {
        $good = $this->needLibs();
        // Mldsa delegates to OpensslPq; its probe is OpensslPq::builds(handle, type)
        $probe = new \ReflectionMethod(OpensslPq::class, 'builds');
        $this->assertFalse($probe->invoke(null, \FFI::cdef('void EVP_PKEY_free(void* pkey);', $good), 'ML-DSA-65'));
        $this->assertTrue($probe->invoke(null, \FFI::cdef(self::CDEF_FULL, $good), 'ML-DSA-65'));
    }

    // ------------------------------------------------------------------ PSR-17 discovery without guzzle
    /** Hide classes from PcaMiddleware's unqualified class_exists() (namespace function shadowing, this process only). */
    private static function shadowClassExists(array $hidden): void
    {
        $GLOBALS['__pca_hidden_classes'] = $hidden;
        if (!function_exists('Atlas\Pca\class_exists')) {
            eval('namespace Atlas\Pca; function class_exists(string $c, bool $autoload = true): bool {'
                . ' return !in_array(ltrim($c, "\\\\"), $GLOBALS["__pca_hidden_classes"], true) && \class_exists($c, $autoload); }');
        }
    }

    #[RunInSeparateProcess]
    public function testNyholmIsUsedWhenGuzzleIsAbsent(): void
    {
        eval('namespace Nyholm\\Psr7\\Factory;
            use Psr\\Http\\Message\\{ResponseFactoryInterface, ResponseInterface, StreamFactoryInterface, StreamInterface};
            final class Psr17Factory implements ResponseFactoryInterface, StreamFactoryInterface {
                private \\GuzzleHttp\\Psr7\\HttpFactory $g;
                public function __construct() { $this->g = new \\GuzzleHttp\\Psr7\\HttpFactory(); }
                public function createResponse(int $code = 200, string $reasonPhrase = ""): ResponseInterface
                { return $this->g->createResponse($code, $reasonPhrase)->withHeader("X-Factory", "nyholm"); }
                public function createStream(string $content = ""): StreamInterface { return $this->g->createStream($content); }
                public function createStreamFromFile(string $filename, string $mode = "r"): StreamInterface { return $this->g->createStreamFromFile($filename, $mode); }
                public function createStreamFromResource($resource): StreamInterface { return $this->g->createStreamFromResource($resource); }
            }');
        self::shadowClassExists(['GuzzleHttp\Psr7\HttpFactory']);
        $r = (new PcaMiddleware('aud', fn() => null))->process(new ServerRequest('GET', '/'), new class implements \Psr\Http\Server\RequestHandlerInterface {
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                throw new \LogicException('must not run');
            }
        });
        $this->assertSame(401, $r->getStatusCode());
        $this->assertSame('nyholm', $r->getHeaderLine('X-Factory'));
    }

    #[RunInSeparateProcess]
    public function testNoFactoryAvailableIsAClearError(): void
    {
        self::shadowClassExists(['GuzzleHttp\Psr7\HttpFactory', 'Nyholm\Psr7\Factory\Psr17Factory']);
        try {
            new PcaMiddleware('aud', fn() => null);
            $this->fail('constructed without any PSR-17 factory');
        } catch (\RuntimeException $e) {
            $this->assertSame('No PSR-17 factories were provided to PcaMiddleware and none of guzzlehttp/psr7 or nyholm/psr7 '
                . 'is installed. Install one or pass your own response/stream factories to the constructor.', $e->getMessage());
        }
    }
}
