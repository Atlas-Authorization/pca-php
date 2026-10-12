<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

/** primitives.depth[]: nesting depth at limit-1 / limit / limit+1 / ~100000 on every untrusted entry point (no exception). */
final class DepthCorpusTest extends TestCase
{
    public function testDepthVectors(): void
    {
        $cases = Corpus::core()->get('primitives')->get('depth');
        $this->assertGreaterThanOrEqual(29, count($cases));
        foreach ($cases as $d) {
            [$got, $why] = DepthCases::run($d);
            $this->assertSame($d->get('valid'), $got, $d->get('name') . " ($why)");
        }
    }
}
