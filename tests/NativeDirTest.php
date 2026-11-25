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

    public function testLibNamesThePlatformFile(): void
    {
        $dir = NativeDir::dir();
        $ext = PHP_OS_FAMILY === 'Windows' ? 'dll' : (PHP_OS_FAMILY === 'Darwin' ? 'dylib' : 'so');
        $name = (PHP_OS_FAMILY === 'Windows' ? '' : 'lib') . 'pcatmp.' . $ext;
        @mkdir($dir, 0777, true);
        $f = $dir . '/' . $name;
        file_put_contents($f, 'x');
        try {
            $this->assertSame($dir . '/' . $name, NativeDir::lib('pcatmp'));
        } finally {
            unlink($f);
            @rmdir($dir);
        }
    }

    public function testDirNamesTheOsForThisHost(): void
    {
        $os = PHP_OS_FAMILY === 'Windows' ? 'windows' : (PHP_OS_FAMILY === 'Darwin' ? 'darwin' : 'linux');
        $this->assertStringContainsString('/native/' . $os . '-', NativeDir::dir());
    }
}
