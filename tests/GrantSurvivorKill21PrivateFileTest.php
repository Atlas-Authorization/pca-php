<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetCerts;
use Atlas\Pca\PrivateFile;
use Atlas\Pca\PrivateFileError;
use PHPUnit\Framework\TestCase;

/**
 * Private files and directories: every creation that cannot happen reports false (never true), the Windows-only helpers refuse
 * off Windows, and on Windows the current user's SID and a missing object's descriptor read back as documented. Runs on Linux and Windows.
 */
final class GrantSurvivorKill21PrivateFileTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-g21-private-' . bin2hex(random_bytes(6));
        mkdir($this->root);
    }

    protected function tearDown(): void
    {
        MpcNetCerts::rmTree($this->root);
        @rmdir($this->root);
    }

    private static function noFfiOnWindows(): bool
    {
        return PrivateFile::isWindows() && !extension_loaded('ffi');
    }

    private function p(string ...$parts): string
    {
        return $this->root . DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
    }

    /** A directory under a regular file, or under a missing parent without `$recursive`, is not created: false, never true. */
    public function testMkdirFailures(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
        }
        $file = $this->p('plain');
        file_put_contents($file, 'x');
        // the parent (the file itself) cannot be made a directory, so the recursive call stops there with false
        $this->assertFalse(PrivateFile::mkdir($file . DIRECTORY_SEPARATOR . 'a', true));
        $this->assertFalse(PrivateFile::mkdir($file . DIRECTORY_SEPARATOR . 'a' . DIRECTORY_SEPARATOR . 'b', true));
        $this->assertFalse(PrivateFile::mkdir($file . DIRECTORY_SEPARATOR . 'a'));
        $this->assertFalse(PrivateFile::mkdir($this->p('missing', 'x')));
        $this->assertDirectoryDoesNotExist($this->p('missing'));
        $this->assertTrue(PrivateFile::mkdir($this->p('made')));
        $this->assertTrue(PrivateFile::mkdir($this->p('made')), 'an existing directory is fine');
    }

    /** A file that cannot be created (missing directory, or the path is a directory) is a failure for create, write, open and tempnam. */
    public function testCreateFailures(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
        }
        $missing = $this->p('missing', 'f');
        $this->assertFalse(PrivateFile::create($missing));
        $this->assertFalse(PrivateFile::create($missing, true));
        $this->assertFalse(PrivateFile::write($missing, 'abc'));
        $this->assertFalse(PrivateFile::open($missing, 'wb'));
        $this->assertFalse(PrivateFile::tempnam($this->p('missing'), 'pt'));
        $this->assertFileDoesNotExist($missing);
        mkdir($this->p('dir'));
        $this->assertFalse(PrivateFile::create($this->p('dir')));
        $f = $this->p('f');
        $this->assertTrue(PrivateFile::create($f, true));
        $this->assertTrue(PrivateFile::create($f), 'a non-exclusive create of an existing file is fine');
        $this->assertSame(3, PrivateFile::write($f, 'abc'));
        $this->assertSame('abc', file_get_contents($f));
    }

    /** killSelf is callable from other classes (the store conformance harness ends a child with it) and exits 137 by default. */
    public function testKillSelfContract(): void
    {
        $this->assertTrue(is_callable([PrivateFile::class, 'killSelf']));
        $this->assertSame(137, (new \ReflectionParameter([PrivateFile::class, 'killSelf'], 'code'))->getDefaultValue());
    }

    /** Off Windows the SID and DACL helpers are public and refuse: ext-ffi cannot load the Windows libraries (or, without ext-ffi, the guard refuses). */
    public function testWindowsHelpersOffWindows(): void
    {
        if (PrivateFile::isWindows()) {
            if (self::noFfiOnWindows()) {
                $this->expectException(PrivateFileError::class);
            }
            $sid = PrivateFile::currentSid();
            $this->assertMatchesRegularExpression('/^S-1-\d+(-\d+)+$/', $sid);
            $this->assertSame($sid, PrivateFile::currentSid());
            try {
                PrivateFile::aclSddl($this->p('nope'));
                $this->fail('a missing object has no descriptor');
            } catch (PrivateFileError $e) {
                $this->assertSame('owner-only files: cannot read the security descriptor', $e->getMessage());
            }
            return;
        }
        foreach ([static fn() => PrivateFile::currentSid(), fn() => PrivateFile::aclSddl($this->root)] as $call) {
            try {
                $call();
                $this->fail('a Windows helper succeeded off Windows');
            } catch (\Throwable $e) {
                if (extension_loaded('ffi')) {
                    $this->assertInstanceOf(\FFI\Exception::class, $e);
                } else {
                    $this->assertSame([PrivateFileError::class, 'owner-only private state on Windows needs the FFI extension (it is not loaded): '
                        . 'refusing to write a file other local users could read'], [get_class($e), $e->getMessage()]);
                }
            }
        }
    }
}
