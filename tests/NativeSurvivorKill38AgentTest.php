<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Fndsa;
use Atlas\Pca\FndsaNative;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\TestCase;

/** Survivor kills for FN-DSA key pairs in Agent.php (needs libfndsa; ATLAS_PCA_LIBFNDSA_REQUIRED=1 fails instead of skipping). */
final class NativeSurvivorKill38AgentTest extends TestCase
{
    protected function setUp(): void
    {
        if (!FndsaNative::available()) {
            if (getenv('ATLAS_PCA_LIBFNDSA_REQUIRED') === '1') {
                $this->fail('libfndsa must load (ATLAS_PCA_LIBFNDSA, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and libfndsa (ATLAS_PCA_LIBFNDSA)');
        }
        Fndsa::setFalconBackend(FndsaNative::backend());
    }

    protected function tearDown(): void
    {
        Fndsa::resetFalconBackend();
    }

    /** A caller-supplied FN-DSA keygen seed is used: the same seed gives the same key, a different seed a different one. */
    public function testKeygenSeedIsHonoured(): void
    {
        $seed = hash('sha256', 'atlas-pca-conformance/agent-38n/fndsa-keygen', true);
        $a = new PqKeyPair('FN-DSA-512', $seed);
        $this->assertSame($a->public, (new PqKeyPair('FN-DSA-512', $seed))->public);
        $this->assertNotSame($a->public, (new PqKeyPair('FN-DSA-512', hash('sha256', 'atlas-pca-conformance/agent-38n/other', true)))->public);
    }
}
