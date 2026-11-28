<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Pq.php';

use Atlas\Pca\Fndsa;
use Atlas\Pca\FndsaNative;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LessFfi;
use Atlas\Pca\Pca;
use Atlas\Pca\Pq;
use PHPUnit\Framework\TestCase;

/** The public PQ surface: type and length gates before any backend, FN-DSA / LESS verify needs a real check, suite dispatch and the LAMPS composite. */
final class CryptoSurvivorKill3PqTest extends TestCase
{
    protected function setUp(): void
    {
        Fndsa::resetFalconBackend();
    }

    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    private function threw(string $class, string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            $this->assertInstanceOf($class, $e, $e->getMessage());
            $this->assertSame($msg, $e->getMessage());
            return;
        }
        $this->fail("nothing thrown: $msg");
    }

    /** The public-key encoders are plain base64url. */
    public function testEncoders(): void
    {
        foreach ([Pq::encodeMlDsa87PublicKey(...), Pq::encodeSlhDsaPublicKey(...), Pq::encodeSlhDsa256sPublicKey(...), Pq::encodeFnDsaPublicKey(...),
            Pq::encodeLessPublicKey(...)] as $enc) {
            $this->assertSame('YWI', $enc('ab'));
        }
    }

    /** Non-string keys or signatures are false before any backend is asked. */
    public function testNonStringInputsAreFalse(): void
    {
        $this->assertFalse(Pq::mlDsa65Verify(5, 'm', 'sig'));
        $this->assertFalse(Pq::slhDsa128fVerify(5, 'm', 'sig'));
        $this->assertFalse(Pq::slhDsa256sVerify(5, 'm', 'sig'));
        $this->assertFalse(Pq::slhDsa256sVerifyB64u(5, 'm', 5));
        $this->assertFalse(Pq::lessCat1Verify(5, 'm', 'sig'));
    }

    /** SLH-DSA-256s keygen / sign refuse a wrong seed or a non-key-pair. */
    public function testSlhDsa256sRefusals(): void
    {
        $this->threw(\RangeException::class, 'slhDsa256sKeygen: seed must be 96 bytes', fn() => Pq::slhDsa256sKeygen('short'));
        $this->threw(\InvalidArgumentException::class, 'slhDsa256sSign needs a SLH-DSA-SHA2-256s key pair', fn() => Pq::slhDsa256sSign('x', 'm'));
    }

    /** Only a real PqKeyPair signs: an object that merely looks like one (a `family` and a `sign()`) is refused. */
    public function testLookAlikeKeyPairIsRefused(): void
    {
        $fake = new class {
            public string $family = 'ML-DSA-65';

            public function sign(string $m): string
            {
                return 'forged';
            }
        };
        $this->threw(\InvalidArgumentException::class, 'mlDsa65Sign needs a ML-DSA-65 key pair', fn() => Pq::mlDsa65Sign($fake, 'm'));
    }

    /** Without a FN-DSA backend keygen and sign refuse with the backend reason, and verify is false (never true on a backend error). */
    public function testFnDsaWithoutBackend(): void
    {
        $this->assertFalse(Pq::isFnDsaBackendActive());
        $seed = str_repeat("\1", 32);
        $this->threw(\RuntimeException::class, 'fnDsa512Keygen: FN-DSA backend unavailable', fn() => Pq::fnDsa512Keygen($seed));
        $this->threw(\RuntimeException::class, 'fnDsa1024Keygen: FN-DSA backend unavailable', fn() => Pq::fnDsa1024Keygen($seed));
        $this->threw(\RuntimeException::class, 'fnDsa512Sign: FN-DSA backend unavailable', fn() => Pq::fnDsa512Sign('sk', 'm', $seed));
        $this->threw(\RuntimeException::class, 'fnDsa1024Sign: FN-DSA backend unavailable', fn() => Pq::fnDsa1024Sign('sk', 'm', $seed));
        $this->assertFalse(Pq::fnDsa512Verify(str_repeat("\1", 897), 'm', str_repeat("\1", 666)));
    }

    /** With a backend, a wrong-length keygen seed is the RangeException of this surface. */
    public function testFnDsaKeygenSeedLength(): void
    {
        Fndsa::registerTestBackend();
        $this->assertTrue(Pq::isFnDsaBackendActive());
        $this->threw(\RangeException::class, 'fnDsa512Keygen: seed must be 32 bytes', fn() => Pq::fnDsa512Keygen(str_repeat("\1", 31)));
    }

    /** FN-DSA verify (raw and base64url, both variants) accepts the backend's signature and nothing else. */
    public function testFnDsaVerifyNeedsTheRealSignature(): void
    {
        Fndsa::registerTestBackend();
        foreach (['fn-dsa-512' => [Pq::fnDsa512Verify(...), Pq::fnDsa512VerifyB64u(...)], 'fn-dsa-1024' => [Pq::fnDsa1024Verify(...), Pq::fnDsa1024VerifyB64u(...)]] as $v => [$raw, $b64]) {
            $kp = Fndsa::mockKeypair($v);
            $sig = Fndsa::sign($v, $kp['sk'], 'atlas fn-dsa');
            $bad = $sig;
            $bad[3] = chr(ord($bad[3]) ^ 1);
            $this->assertTrue($raw($kp['pk'], 'atlas fn-dsa', $sig), $v);
            $this->assertTrue($b64(Pca::b64u($kp['pk']), 'atlas fn-dsa', Pca::b64u($sig)), $v);
            $this->assertFalse($raw($kp['pk'], 'atlas fn-dsa', $bad), $v);
            $this->assertFalse($b64(Pca::b64u($kp['pk']), 'atlas fn-dsa', Pca::b64u($bad)), $v);
            $this->assertFalse($raw($kp['pk'], 'atlas fn-dsA', $sig), $v);
        }
    }

    /** With libfndsa, keygen returns both keys at the FIPS 206 sizes. */
    public function testFnDsaKeygenReturnsBothKeys(): void
    {
        if (!FndsaNative::available()) {
            $this->markTestSkipped('needs ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA)');
        }
        Fndsa::registerTestBackend();
        $k = Pq::fnDsa512Keygen(str_repeat("\1", 32));
        $this->assertSame(['verifyingKey', 'signingKey'], array_keys($k));
        $this->assertSame(897, strlen($k['verifyingKey']));
        $this->assertSame(1345, strlen($k['signingKey']));
    }

    /** LESS keygen / sign refuse a wrong seed through this surface. */
    public function testLessSeedRefusals(): void
    {
        $this->threw(\InvalidArgumentException::class, 'lessCat1Keygen: seed must be 32 bytes', fn() => Pq::lessCat1Keygen('short'));
        $this->threw(\InvalidArgumentException::class, 'lessCat1Sign: seed must be 32 bytes', fn() => Pq::lessCat1Sign('sk', 'm', 'short'));
    }

    /** LESS verify: the known-answer signature verifies (raw and base64url); an undecodable key or signature is false, never an error. */
    public function testLessVerify(): void
    {
        $doc = json_decode((string)file_get_contents(__DIR__ . '/../conformance/less-vectors.json'), true);
        $v = $doc['vectors'][0];
        $this->assertSame('less-cat1-valid', $v['name']);
        $pkB64 = $doc['keys'][$v['key']]['pq_pk'];
        $msg = (string)Pca::unb64u($v['message']);
        $this->assertFalse(Pq::lessCat1VerifyB64u('!!', $msg, $v['sig']));
        $this->assertFalse(Pq::lessCat1VerifyB64u($pkB64, $msg, '!!'));
        if (!LessFfi::available()) {
            $this->markTestSkipped('libatlas_less not built or not at ATLAS_PCA_LIBLESS');
        }
        $this->assertTrue(Pq::lessCat1Verify((string)Pca::unb64u($pkB64), $msg, (string)Pca::unb64u($v['sig'])));
        $this->assertTrue(Pq::lessCat1VerifyB64u($pkB64, $msg, $v['sig']));
        $this->assertFalse(Pq::lessCat1VerifyB64u($pkB64, $msg . 'x', $v['sig']));
    }

    /** Suite dispatch names the unknown alg; a non-string alg is the string the signer refuses. */
    public function testSuiteDispatchRefusals(): void
    {
        $this->threw(\RangeException::class, "signSuiteArtifact: unknown signature alg 'nope'", fn() => Pq::signSuiteArtifact('nope', null, null, 'm'));
        $this->threw(\InvalidArgumentException::class, "unknown signature alg '5'", fn() => Pq::signWithSuite(5, null, null, 'm'));
    }

    /** The composite representative takes a ctx of exactly 255 bytes, not 256. */
    public function testCompositeCtxLimit(): void
    {
        $ctx = str_repeat('c', 255);
        $this->assertSame(Pq::COMPOSITE_PREFIX . Pq::COMPOSITE_LABEL . chr(255) . $ctx . hash('sha512', 'm', true), Pq::compositeRepresentative('m', $ctx));
        $this->threw(\RangeException::class, 'compositeRepresentative: ctx exceeds 255 bytes', fn() => Pq::compositeRepresentative('m', $ctx . 'c'));
    }

    /** A composite whose Ed25519 half is valid but whose ML-DSA half is not is refused: both halves must verify. */
    public function testCompositeNeedsBothHalves(): void
    {
        $kp = new KeyPair(hash('sha256', 'atlas-pca-conformance/pq-kill-3', true));
        $m = Pq::compositeRepresentative('msg');
        $ed = $kp->sign($m);
        $this->assertTrue(Pca::verifyEd25519B64u($kp->public, $m, Pca::b64u($ed)));
        $sig = str_repeat("\0", Pq::ML_DSA_65_SIGNATURE_BYTES) . $ed;
        $this->assertSame(Pq::COMPOSITE_SIGNATURE_BYTES, strlen($sig));
        $this->assertFalse(Pq::compositeVerify((string)Pca::unb64u($kp->public), str_repeat("\0", Pq::ML_DSA_65_PUBLIC_KEY_BYTES), 'msg', $sig));
    }
}
