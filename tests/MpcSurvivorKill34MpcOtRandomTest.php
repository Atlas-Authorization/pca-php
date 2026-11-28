<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcFieldRng;
use Atlas\Pca\MpcOtRandom;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcOtRandom::scalar: a stream stuck at zero is an RNG failure, never a zero scalar. */
final class MpcSurvivorKill34MpcOtRandomTest extends TestCase
{
    /** A broken stream (SplitMix64 with a zero increment from state 0, so every draw is 0) fails after the retries with the exact reason. */
    public function testAStuckZeroStreamIsRefused(): void
    {
        $r = MpcOtRandom::fromSeed(gmp_init(0));
        $stream = (new \ReflectionProperty(MpcOtRandom::class, 'stream'))->getValue($r);
        (new \ReflectionProperty(MpcFieldRng::class, 'c0'))->setValue($stream, gmp_init(0));
        $this->assertSame('0', gmp_strval($stream->nextU64()), 'the stream is stuck at zero');
        try {
            $r->scalar();
            $this->fail('a zero stream must not yield a scalar');
        } catch (\RuntimeException $e) {
            $this->assertSame(\RuntimeException::class, $e::class);
            $this->assertSame('otRandom: entropy stream returned zero scalars repeatedly (RNG failure)', $e->getMessage());
        }
        $this->assertSame(1, gmp_sign(MpcOtRandom::fromSeed(gmp_init(0))->scalar()), 'control: a working stream yields a non-zero scalar');
    }
}
