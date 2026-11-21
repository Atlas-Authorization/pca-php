<?php
declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\NativeDir;
use PHPUnit\Framework\TestCase;

final class NativeDirTest extends TestCase
{
    public function testDirNamesThePlatformFolder(): void
    {
        $this->assertMatchesRegularExpression('#/native/(linux|darwin|windows)-[^/]+$#', NativeDir::dir());
    }

    public function testNoPackagedLibraryInASourceCheckout(): void
    {
        if (is_dir(NativeDir::dir())) {
            $this->markTestSkipped('this tree carries packaged libraries');
        }
        $this->assertNull(NativeDir::lib('blst'));
    }
}
