<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetCerts;
use Atlas\Pca\PrivateFile;
use Atlas\Pca\PrivateFileError;
use PHPUnit\Framework\TestCase;

/**
 * Windows: an owner-only descriptor that cannot be built refuses the create (file and directory) with its exact reason and creates
 * nothing, never an object with the default, inherited ACL. The class name matches the Windows mutation shard's PrivateFileTest filter.
 */
final class WinSurvivorKill38PrivateFileTest extends TestCase
{
    private string $root;
    private ?string $savedSid = null;
    /** @var array<string,mixed> */
    private array $savedSa = [];

    protected function setUp(): void
    {
        if (PHP_OS_FAMILY !== 'Windows') {
            self::markTestSkipped('the DACL builder (ConvertStringSecurityDescriptorToSecurityDescriptorW) exists only on Windows');
        }
        if (!extension_loaded('ffi')) {
            self::markTestSkipped('ext-ffi is not loaded: the no-ffi refusal is held by GrantSurvivorKill21bPrivateFileTest');
        }
        $this->root = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'pca-w38-private-' . bin2hex(random_bytes(6));
        mkdir($this->root);
        PrivateFile::currentSid(); // cache the real SID first, so it is the value restored
        $this->savedSid = self::prop('sid')->getValue();
        $this->savedSa = self::prop('sa')->getValue();
    }

    protected function tearDown(): void
    {
        if (PHP_OS_FAMILY !== 'Windows' || !extension_loaded('ffi')) {
            return;
        }
        self::prop('sid')->setValue(null, $this->savedSid);
        self::prop('sa')->setValue(null, $this->savedSa);
        MpcNetCerts::rmTree($this->root);
        @rmdir($this->root);
    }

    private static function prop(string $name): \ReflectionProperty
    {
        return new \ReflectionProperty(PrivateFile::class, $name);
    }

    /** An SDDL the system rejects (the SID is not a SID) is a PrivateFileError for create and mkdir, and nothing is created. */
    public function testUnbuildableDescriptorRefusesCreate(): void
    {
        self::prop('sid')->setValue(null, 'XX-NOT-A-SID');
        self::prop('sa')->setValue(null, []);
        $f = $this->root . DIRECTORY_SEPARATOR . 'f';
        try {
            PrivateFile::create($f, true);
            $this->fail('a file was created without its owner-only descriptor');
        } catch (PrivateFileError $e) {
            $this->assertSame('owner-only files: cannot build the security descriptor', $e->getMessage());
        }
        $this->assertFileDoesNotExist($f);
        $d = $this->root . DIRECTORY_SEPARATOR . 'd';
        try {
            PrivateFile::mkdir($d);
            $this->fail('a directory was created without its owner-only descriptor');
        } catch (PrivateFileError $e) {
            $this->assertSame('owner-only files: cannot build the security descriptor', $e->getMessage());
        }
        $this->assertDirectoryDoesNotExist($d);

        // control: with the real SID the same create succeeds and reads back owner-only
        self::prop('sid')->setValue(null, $this->savedSid);
        self::prop('sa')->setValue(null, []);
        $this->assertTrue(PrivateFile::create($f, true));
        $sid = (string)$this->savedSid;
        $got = PrivateFile::aclSddl($f);
        if (str_ends_with($sid, '-500')) {
            $got = str_replace(';;;LA)', ';;;' . $sid . ')', $got); // the built-in administrator's SID reads back as its alias LA
        }
        $this->assertSame('D:P(A;;FA;;;' . $sid . ')', $got);
    }
}
