<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PqSoftware.php';

use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\PqSoftware;
use PHPUnit\Framework\TestCase;

/** The PQ software attestation root: attestor and verifier construction refuse with exact reasons; a verifier error fails closed with its text. */
final class CryptoSurvivorKill3PqSoftwareTest extends TestCase
{
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

    /** createAttestor: unknown, classical and key-less suites are refused, each with its reason. */
    public function testAttestorRefusals(): void
    {
        $this->threw(\RangeException::class, "createPqSoftwareAttestor: unknown signature alg 'nope'", fn() => PqSoftware::createAttestor('nope', null, null));
        $this->threw(\RangeException::class, "createPqSoftwareAttestor: 'ed25519' is classical; the PQ root requires a post-quantum suite",
            fn() => PqSoftware::createAttestor('ed25519', null, null));
        $this->threw(\TypeError::class, "createPqSoftwareAttestor: 'ml-dsa-65' requires the matching PQ key material", fn() => PqSoftware::createAttestor('ml-dsa-65', null, null));
    }

    /** A hybrid attestor needs the Ed25519 key too. */
    public function testHybridAttestorNeedsEd25519(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->assertNotSame('1', getenv('PCA_REQUIRE_MLDSA'), 'ML-DSA-65 must be available where CI promises OpenSSL >= 3.5');
            $this->markTestSkipped('no ML-DSA-65 in this libcrypto');
        }
        $pq = new PqKeyPair('ML-DSA-65', str_repeat("\x0b", 32));
        $this->threw(\TypeError::class, "createPqSoftwareAttestor: hybrid suite 'hybrid-ed25519-ml-dsa-65' requires edSecret",
            fn() => PqSoftware::createAttestor('hybrid-ed25519-ml-dsa-65', null, $pq));
    }

    /** createVerifier: a non-list measurement allowlist and a non-list trusted-key option are refused with the configuration reasons. */
    public function testVerifierConfigRefusals(): void
    {
        $this->threw(\TypeError::class, 'createPqSoftwareVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)',
            fn() => PqSoftware::createVerifier(Obj::of(['policy' => Obj::of(['measurements' => 'x']), 'trustedPqPublicKeys' => ['k']])));
        $this->threw(\TypeError::class, 'createPqSoftwareVerifier: at least one trusted PQ public key is required (fail closed)',
            fn() => PqSoftware::createVerifier(Obj::of(['policy' => Obj::of(['measurements' => ['m']]), 'trustedPqPublicKeys' => 'k'])));
    }

    /** A resolver that throws fails closed with its message (or "unknown" for an empty one). */
    public function testVerifierErrorFailsClosedWithItsText(): void
    {
        foreach (['boom' => 'boom', '' => 'unknown'] as $thrown => $shown) {
            $verify = PqSoftware::createVerifier(Obj::of(['policy' => Obj::of(['measurements' => ['m']]), 'trustedPqPublicKeys' => ['k'],
                'resolveEvidence' => static function () use ($thrown): never {
                    throw new \RuntimeException((string)$thrown);
                }]));
            $this->assertSame(['ok' => false, 'reason' => "pq-software verification error (fail closed): $shown"], $verify(new Obj()));
        }
    }
}
