<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\DirectoryKv;
use Atlas\Pca\FileApprovalStore;
use Atlas\Pca\FileMeshWitnessStore;
use Atlas\Pca\FileRevocationStore;
use Atlas\Pca\MpcNetCerts;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\PrivateFile;
use Atlas\Pca\PrivateFileError;
use Atlas\Pca\FileScittLogStore;
use PHPUnit\Framework\TestCase;

/**
 * Every writer of private state creates its file or directory owner-only, and the restriction reads back: on POSIX mode 0600 (files)
 * or 0700 (directories); on Windows a protected DACL with exactly one entry, full access for the current user (a directory's entry
 * is inherited by what is created inside it). Windows needs ext-ffi: without it private state is refused, and that is asserted too.
 */
final class PrivateFileTest extends TestCase
{
    private string $root;

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-private-' . bin2hex(random_bytes(6));
        if (PrivateFile::isWindows() && !extension_loaded('ffi')) {
            // the library's own parent directory is made by the test; only the private objects below are under test
            mkdir($this->root);
        } else {
            self::assertTrue(PrivateFile::mkdir($this->root, true));
        }
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

    /** The restriction of `$path`, read back from the file system. */
    private function assertPrivate(string $path, bool $dir = false): void
    {
        self::assertFileExists($path);
        if (!PrivateFile::isWindows()) {
            self::assertSame($dir ? 0700 : 0600, fileperms($path) & 0777, $path);
            return;
        }
        $sid = PrivateFile::currentSid();
        $want = 'D:P(A;' . ($dir ? 'OICI' : '') . ';FA;;;' . $sid . ')';
        $got = PrivateFile::aclSddl($path);
        if (str_ends_with($sid, '-500')) {
            $got = str_replace(';;;LA)', ';;;' . $sid . ')', $got); // the built-in administrator account's SID reads back as its alias LA
        }
        self::assertSame($want, $got, "$path: wanted $want, read $got"); // protected, exactly one entry, the current user
    }

    public function testDirectoryFileAndExclusiveCreate(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
            PrivateFile::create($this->root . DIRECTORY_SEPARATOR . 'x');
        }
        $d = $this->root . DIRECTORY_SEPARATOR . 'a' . DIRECTORY_SEPARATOR . 'b';
        self::assertTrue(PrivateFile::mkdir($d, true));
        $this->assertPrivate(dirname($d), true);
        $this->assertPrivate($d, true);
        $f = $d . DIRECTORY_SEPARATOR . 'f';
        self::assertTrue(PrivateFile::create($f, true));
        $this->assertPrivate($f);
        self::assertFalse(PrivateFile::create($f, true), 'an exclusive create of an existing file fails');
        self::assertSame(3, PrivateFile::write($f, 'abc'));
        $this->assertPrivate($f);
        $h = PrivateFile::open($f, 'wb');
        self::assertIsResource($h);
        fclose($h);
        self::assertFalse(PrivateFile::open($f, 'xb'), 'x stays exclusive');
        $t = PrivateFile::tempnam($d, 'pt');
        self::assertIsString($t);
        $this->assertPrivate($t);
    }

    public function testRevocationFileStore(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
        }
        $p = $this->root . DIRECTORY_SEPARATOR . 'revocations.json';
        (new FileRevocationStore($p))->add(['kind' => 'grant', 'value' => 'g1', 'revokedAt' => 1]);
        $this->assertPrivate($p);
    }

    public function testMeshWitnessFileStore(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
        }
        $p = $this->root . DIRECTORY_SEPARATOR . 'witness.json';
        (new FileMeshWitnessStore($p))->save(Obj::of(['n' => new Num('1')]));
        $this->assertPrivate($p);
    }

    public function testApprovalFileStoreAndDirectoryKv(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
        }
        $p = $this->root . DIRECTORY_SEPARATOR . 'approvals.json';
        self::assertTrue((new FileApprovalStore($p))->cas('k', 0, 'v'));
        $this->assertPrivate($p);

        $dir = $this->root . DIRECTORY_SEPARATOR . 'kv';
        $kv = new DirectoryKv($dir);
        $this->assertPrivate($dir, true);
        self::assertTrue($kv->putIfEquals('key', null, '{"version":1,"value":1}'));
        $this->assertPrivate($dir . DIRECTORY_SEPARATOR . hash('sha256', 'key'));
    }

    public function testScittLogFile(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
        }
        $p = $this->root . DIRECTORY_SEPARATOR . 'scitt.log';
        FileScittLogStore::open($p)->close();
        $this->assertPrivate($p);
    }

    public function testKeyMaterialHelpers(): void
    {
        if (self::noFfiOnWindows()) {
            $this->expectException(PrivateFileError::class);
        }
        $tmp = MpcNetCerts::tempDir();
        try {
            $this->assertPrivate($tmp, true);
            $key = $tmp . DIRECTORY_SEPARATOR . 'key.pem';
            MpcNetCerts::writeSecret($key, 'secret');
            $this->assertPrivate($key);
        } finally {
            MpcNetCerts::rmTree($tmp);
            @rmdir($tmp);
        }
    }

    public function testNullDeviceIsUsableAsAChildStream(): void
    {
        self::assertSame(PrivateFile::isWindows() ? 'NUL' : '/dev/null', PrivateFile::nullDevice());
        $null = PrivateFile::nullDevice();
        $p = proc_open([PHP_BINARY, '-r', 'echo fgets(STDIN) === false ? "eof" : "data";'], [0 => ['file', $null, 'r'], 1 => ['pipe', 'w'], 2 => ['file', $null, 'w']], $pipes);
        self::assertIsResource($p);
        self::assertSame('eof', stream_get_contents($pipes[1]));
        fclose($pipes[1]);
        proc_close($p);
    }
}
