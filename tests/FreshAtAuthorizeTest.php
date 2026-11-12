<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/fresh-at-authorize.php';

/** `fresh_at` forwarded by Authorize::authorize and read from the `pca-fresh-at` header by PcaMiddleware. */
final class FreshAtAuthorizeTest extends TestCase
{
    public function testFreshAtThroughAuthorizeAndMiddleware(): void
    {
        $this->assertSame([], \freshAtAuthorizeRun());
    }
}
