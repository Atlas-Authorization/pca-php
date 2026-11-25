<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Pq.php';

use Atlas\Pca\KeyPair;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\Pq;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\TestCase;

/** The pq.ts public surface (src/Pq.php): constants, registry, per-primitive keygen/sign/verify, suite artifacts, composite. */
final class PqSurfaceTest extends TestCase
{
    public function testRegistryMatchesTheCoreDispatchTable(): void
    {
        self::assertEqualsCanonicalizing(Pca::REGISTERED_SUITES, array_keys(Pq::SIG_SUITES));
        self::assertTrue(Pq::isKnownSigAlg('ml-dsa-87'));
        self::assertFalse(Pq::isKnownSigAlg('ML-DSA-87'));
        self::assertFalse(Pq::isKnownSigAlg(7));
        self::assertSame('ed25519', Pq::resolveSigAlg(null)['alg']);
        self::assertNull(Pq::resolveSigAlg('nope'));
        self::assertNull(Pq::resolveSigAlg(false));
        self::assertSame(3373, Pq::COMPOSITE_SIGNATURE_BYTES);
        self::assertSame(Pq::ML_DSA_65_SIGNATURE_BYTES + Pq::ED25519_SIGNATURE_BYTES, Pq::COMPOSITE_SIGNATURE_BYTES);
        foreach (OpensslPq::KEY_TYPES as $type => [$pk, $sig]) {
            $row = array_values(array_filter(Pq::SIG_SUITES, fn(array $s) => $s['family'] === $type && !$s['needsPqSig'] && !isset($s['nested'])));
            self::assertSame($pk, $row[0]['pqPkBytes']);
            self::assertSame($sig, $row[0]['sigBytes']);
        }
    }

    public function testWellFormedPqPublicKeyAndPinnedKeyChecks(): void
    {
        self::assertTrue(Pq::isWellFormedPqPublicKey(Pca::b64u(str_repeat("\1", 32))));
        self::assertTrue(Pq::isWellFormedPqPublicKey(Pca::b64u(str_repeat("\1", 1952))));
        self::assertFalse(Pq::isWellFormedPqPublicKey(Pca::b64u(str_repeat("\1", 33))));
        self::assertFalse(Pq::isWellFormedPqPublicKey(str_repeat('A', 43) . '=='));
        self::assertFalse(Pq::isWellFormedPqPublicKey(5));
        self::assertFalse(Pq::isPinnedPqKey('abc'));
        $pk = Pca::b64u(str_repeat("\2", 32));
        self::assertNull(Pca::resolvePqVerifyKey('id', $pk, null));
        self::assertNull(Pca::resolvePqVerifyKey('id', $pk, ['allowUnboundPq' => true]));
        self::assertTrue(Pq::isPinnedPqKey(Pca::resolvePqVerifyKey('id', $pk, ['trustedPk' => $pk])));
        self::assertTrue(Pq::isPinnedPqKey(Pca::resolvePqVerifyKey('id', $pk, ['pqPins' => ['id' => $pk]])));
        self::assertNull(Pca::resolvePqVerifyKey('id', $pk, ['pqPins' => ['id' => Pca::b64u(str_repeat("\3", 32))]]));
        self::assertTrue(Pq::isPinnedPqKey(Pca::resolvePqVerifyKey('id', $pk, ['holderPq' => Pca::holderPqCommitment($pk)])));
    }

    public function testCompositeRepresentativeAndLimits(): void
    {
        $m = Pq::compositeRepresentative('msg', 'ctx');
        self::assertSame(Pq::COMPOSITE_PREFIX . Pq::COMPOSITE_LABEL . "\x03ctx" . hash('sha512', 'msg', true), $m);
        $this->expectException(\RangeException::class);
        Pq::compositeRepresentative('msg', str_repeat('c', 256));
    }

    public function testCompositeVerifyFailsClosedOnBadShapes(): void
    {
        self::assertFalse(Pq::compositeVerify(str_repeat("\1", 32), str_repeat("\1", 1952), 'm', 'short'));
        self::assertFalse(Pq::compositeVerify(5, str_repeat("\1", 1952), 'm', str_repeat("\0", 3373)));
        self::assertFalse(Pq::compositeVerify(str_repeat("\1", 32), str_repeat("\1", 1952), 'm', str_repeat("\0", 3373), str_repeat('c', 256)));
    }

    public function testMlDsaSurfaceRoundTrips(): void
    {
        if (!OpensslPq::available('ML-DSA-65') || !OpensslPq::available('ML-DSA-87')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $kp = Pq::mlDsa65Keygen(str_repeat("\7", Pq::ML_DSA_65_SEED_BYTES));
        $sig = Pq::mlDsa65Sign($kp, 'hello');
        self::assertSame(Pq::ML_DSA_65_SIGNATURE_BYTES, strlen($sig));
        self::assertSame(Pq::mlDsa65Sign($kp, 'hello'), $sig, 'deterministic');
        $pk = Pca::unb64u($kp->public, Pq::ML_DSA_65_PUBLIC_KEY_BYTES);
        self::assertTrue(Pq::mlDsa65Verify($pk, 'hello', $sig));
        self::assertFalse(Pq::mlDsa65Verify($pk, 'hellp', $sig));
        self::assertTrue(Pq::mlDsa65VerifyB64u(Pq::encodeMlDsaPublicKey($pk), 'hello', Pca::b64u($sig)));
        self::assertFalse(Pq::mlDsa65VerifyB64u($kp->public, 'hello', 7));
        self::assertFalse(Pq::mlDsa87Verify($pk, 'hello', $sig));
        $kp87 = Pq::mlDsa87Keygen(str_repeat("\7", Pq::ML_DSA_87_SEED_BYTES));
        self::assertTrue(Pq::mlDsa87VerifyB64u($kp87->public, 'x', Pca::b64u(Pq::mlDsa87Sign($kp87, 'x'))));
        try {
            Pq::mlDsa65Sign($kp87, 'x');
            self::fail('a pair of another family must be refused');
        } catch (\InvalidArgumentException) {
            self::assertTrue(true);
        }
        $this->expectException(\RangeException::class);
        Pq::mlDsa65Keygen('short');
    }

    public function testSlhDsaSurfaceRoundTrips(): void
    {
        if (!OpensslPq::available('SLH-DSA-SHA2-128f')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $kp = Pq::slhDsa128fKeygen(str_repeat("\5", Pq::SLH_DSA_SHA2_128F_SEED_BYTES));
        $sig = Pq::slhDsa128fSign($kp, 'hello');
        self::assertSame(Pq::SLH_DSA_SHA2_128F_SIGNATURE_BYTES, strlen($sig));
        self::assertTrue(Pq::slhDsa128fVerifyB64u($kp->public, 'hello', Pca::b64u($sig)));
        self::assertFalse(Pq::slhDsa128fVerifyB64u($kp->public, 'other', Pca::b64u($sig)));
    }

    public function testSuiteArtifactAndVerifyWithSuite(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $ed = new KeyPair(str_repeat("\1", 32));
        $pq = new PqKeyPair('ML-DSA-65', str_repeat("\2", 32));
        self::assertSame(['sig'], array_keys(Pq::signSuiteArtifact(null, $ed, null, 'm')));
        $a = Pq::signSuiteArtifact('hybrid-ed25519-ml-dsa-65', $ed, $pq, 'm');
        self::assertSame(['sig', 'alg', 'pq_pk', 'pq_sig'], array_keys($a));
        self::assertSame($pq->public, $a['pq_pk']);
        self::assertSame($pq->public, Pq::suitePqPublicKey('hybrid-ed25519-ml-dsa-65', $pq));
        self::assertNull(Pq::suitePqPublicKey('ed25519', $pq));
        $pin = Pca::resolvePqVerifyKey($ed->public, $a['pq_pk'], ['trustedPk' => $pq->public]);
        self::assertTrue(Pq::verifyWithSuite('hybrid-ed25519-ml-dsa-65', ['edPub' => $ed->public, 'pq' => $pin], 'm', $a));
        self::assertFalse(Pq::verifyWithSuite('hybrid-ed25519-ml-dsa-65', ['edPub' => $ed->public, 'pq' => $pin], 'n', $a));
        self::assertFalse(Pq::verifyWithSuite('hybrid-ed25519-ml-dsa-65', ['edPub' => $ed->public, 'pq' => $pq->public], 'm', $a), 'a raw key is refused');
        self::assertFalse(Pq::verifyWithSuite('hybrid-ed25519-ml-dsa-65', ['pq' => $pin], 'm', $a), 'no ed key');
        self::assertFalse(Pq::verifyWithSuite('bogus', ['edPub' => $ed->public], 'm', $a));
        $ok = Pq::compositeSign($ed, $pq, 'msg', 'c');
        self::assertSame(Pq::COMPOSITE_SIGNATURE_BYTES, strlen($ok));
        $edRaw = Pca::unb64u($ed->public, 32);
        $pqRaw = Pca::unb64u($pq->public, Pq::ML_DSA_65_PUBLIC_KEY_BYTES);
        self::assertTrue(Pq::compositeVerify($edRaw, $pqRaw, 'msg', $ok, 'c'));
        self::assertFalse(Pq::compositeVerify($edRaw, $pqRaw, 'msg', $ok, 'd'));
        self::assertFalse(Pq::compositeVerify($edRaw, $pqRaw, 'msg2', $ok, 'c'));
    }

    public function testLessAndFnDsaFailClosedWithoutALibrary(): void
    {
        self::assertSame(Pq::LESS_CAT1_SIGNATURE_STEP_BYTES, 16);
        self::assertFalse(Pq::lessCat1Verify('x', 'm', 'y'));
        self::assertFalse(Pq::lessCat1VerifyB64u('x', 'm', 'y'));
        self::assertFalse(Pq::fnDsa512VerifyB64u('x', 'm', 'y'));
        self::assertFalse(Pq::fnDsa1024Verify(1, 'm', 2));
        $st = Pq::lessBackendStatus();
        self::assertSame(Pq::isLessBackendActive(), $st['available']);
        if (!$st['available']) {
            self::assertArrayHasKey('reason', $st);
            $this->expectException(\RuntimeException::class);
            Pq::lessCat1Keygen(str_repeat("\0", 32));
        }
    }
}
