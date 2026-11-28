<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PrivateFile;
use Atlas\Pca\PrivateFileError;
use PHPUnit\Framework\TestCase;

/** killSelf's steps, observed in-process through the exit seam, and the no-ext-ffi refusal through the extension seam. Runs on Linux and Windows. */
final class GrantSurvivorKill21bPrivateFileTest extends TestCase
{
    protected function tearDown(): void
    {
        PrivateFile::$exitHook = null;
        PrivateFile::$extensionHook = null;
    }

    /** @return list<array{0:string,1:int}> */
    private static function kill(?int $code): array
    {
        $seen = [];
        PrivateFile::$exitHook = static function (string $how, int $arg) use (&$seen): void {
            $seen[] = [$how, $arg];
            if ($how === 'exit') {
                throw new \LogicException('exit');
            }
        };
        try {
            $code === null ? PrivateFile::killSelf() : PrivateFile::killSelf($code);
        } catch (\LogicException) {
        }
        return $seen;
    }

    /** POSIX: SIGKILL (9) itself when posix is there, then exit with the code (137 by default); Windows: TerminateProcess, then exit. */
    public function testKillSelfSteps(): void
    {
        if (PrivateFile::isWindows()) {
            if (!extension_loaded('ffi')) {
                $this->expectException(PrivateFileError::class);
            }
            $this->assertSame([['terminate', 137], ['exit', 137]], self::kill(null));
            $this->assertSame([['terminate', 5], ['exit', 5]], self::kill(5));
            return;
        }
        $kill = function_exists('posix_kill') ? [['kill', 9]] : [];
        $this->assertSame([...$kill, ['exit', 137]], self::kill(null));
        $this->assertSame([...$kill, ['exit', 5]], self::kill(5));
    }

    /** Without ext-ffi the Windows helpers refuse with the owner-only error, never a file others could read. */
    public function testNoFfiRefuses(): void
    {
        $asked = [];
        PrivateFile::$extensionHook = static function (string $name) use (&$asked): bool {
            $asked[] = $name;
            return false;
        };
        try {
            PrivateFile::aclSddl(sys_get_temp_dir());
            $this->fail('refused');
        } catch (PrivateFileError $e) {
            $this->assertSame('owner-only private state on Windows needs the FFI extension (it is not loaded): refusing to write a file other local users could read',
                $e->getMessage());
        }
        $this->assertSame(['ffi'], $asked);
    }
}
