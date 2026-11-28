<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FnDsaBackendMissing;
use Atlas\Pca\Fndsa;
use Atlas\Pca\FndsaNative;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\TestCase;

/** Group 28b: an FN-DSA key pair made from a seed uses that seed (a random one only when none is given). */
final class MixSurvivorKill28bAgentTest extends TestCase
{
    protected function tearDown(): void
    {
        FndsaNative::$extensionHook = null;
        Fndsa::resetFalconBackend();
    }

    /**
     * With libfndsa: the same seed gives the same key and another seed another key, and no seed a fresh one each time. Without it the
     * native keygen is the only place a seed is used, and it refuses with the exact backend-missing error (forced through the
     * extension seam, so the message does not depend on how the library is missing).
     */
    public function testSeededKeygenIsDeterministic(): void
    {
        Fndsa::registerTestBackend();
        $s1 = str_repeat("\1", 32);
        if (FndsaNative::available()) {
            $a = new PqKeyPair('FN-DSA-512', $s1);
            self::assertSame($a->public, (new PqKeyPair('FN-DSA-512', $s1))->public);
            self::assertNotSame($a->public, (new PqKeyPair('FN-DSA-512', str_repeat("\2", 32)))->public);
            self::assertNotSame((new PqKeyPair('FN-DSA-512'))->public, (new PqKeyPair('FN-DSA-512'))->public);
            return;
        }
        FndsaNative::$extensionHook = static fn(string $name): bool => false;
        foreach ([$s1, null] as $seed) {
            try {
                new PqKeyPair('FN-DSA-512', $seed);
                self::fail('expected FnDsaBackendMissing');
            } catch (FnDsaBackendMissing $e) {
                self::assertSame('FN-DSA needs ext-ffi (ffi.enable=true)', $e->getMessage());
            }
        }
    }
}
