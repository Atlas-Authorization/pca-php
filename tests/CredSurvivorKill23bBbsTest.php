<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bbs;
use PHPUnit\Framework\TestCase;

/** The point groups Bbs decodes and identity-checks public keys and proof points in. */
final class CredSurvivorKill23bBbsTest extends TestCase
{
    /** Public keys are G2 and Abar, Bbar, D are G1. */
    public function testPointGroups(): void
    {
        $this->assertSame(2, Bbs::PUBLIC_KEY_GROUP);
        $this->assertSame(1, Bbs::PROOF_POINT_GROUP);
    }
}
