<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcEnc;
use Atlas\Pca\MpcFieldRng;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcEnc::makeGadget: a statistical security below the minimum is refused unless the caller opts in explicitly. */
final class MpcSurvivorKill34MpcEncTest extends TestCase
{
    /** Without the unsafe flag (the default) statSec 39 is refused with the exact reason naming the minimum; with it the gadget is built. */
    public function testLowStatSecNeedsTheExplicitUnsafeFlag(): void
    {
        try {
            MpcEnc::makeGadget(39, new MpcFieldRng(gmp_init(1)));
            $this->fail('statSec 39 must be refused by default');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame(\InvalidArgumentException::class, $e::class);
            $this->assertSame('statSec 39 is below 40: refused (tests may pass the explicit unsafe flag)', $e->getMessage());
        }
        $this->assertCount(MpcEnc::encBits(39), MpcEnc::makeGadget(39, new MpcFieldRng(gmp_init(1)), true));
    }
}
