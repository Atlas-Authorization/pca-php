<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcOtx;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcOtx: the fixed-key AES-ECB of the correlation-robust hash refuses (never returns garbage) when OpenSSL fails. */
final class MpcSurvivorKill34MpcOtxTest extends TestCase
{
    /** Input that is not whole AES blocks (no padding is applied) makes OpenSSL fail: that is a RuntimeException, not a result. */
    public function testAesEcbFailureIsRaised(): void
    {
        $ecb = new \ReflectionMethod(MpcOtx::class, 'aesEcb');
        $this->assertSame(16, strlen($ecb->invoke(null, str_repeat("\0", 16))));
        $this->assertSame('', $ecb->invoke(null, ''));
        // OpenSSL may queue a notice for the failed call; it is not what this test is about
        set_error_handler(static fn(): bool => true);
        try {
            $ecb->invoke(null, 'abc');
            $this->fail('a partial block must fail');
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertSame('AES-ECB failed', $e->getMessage());
        } finally {
            restore_error_handler();
        }
    }
}
