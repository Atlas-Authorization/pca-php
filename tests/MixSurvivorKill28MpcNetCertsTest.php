<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PrivateFile.php';
require_once __DIR__ . '/../src/MpcNetCerts.php';

use Atlas\Pca\MpcNetCerts;
use PHPUnit\Framework\TestCase;

/**
 * Group 28 survivors in MpcNetCerts. Identity generation runs against a stand-in `openssl` (a /bin/sh wrapper around `php -n` and a
 * script that checks the exact command lines and writes fixed files), so every verdict is exact and no real openssl is needed.
 */
final class MixSurvivorKill28MpcNetCertsTest extends TestCase
{
    private string $dir = '';
    private string $fake = '';
    /** @var list<string> */
    private array $warnings = [];

    private const FAKE = <<<'PHP'
<?php
$mode = trim((string) file_get_contents(__DIR__ . '/mode'));
$a = array_slice($argv, 1);
$out = (string) end($a);
if ($mode === 'fail') {
    fwrite(STDERR, 'A' . str_repeat('B', 198) . 'C' . str_repeat('D', 100));
    exit(3);
}
if ($a[0] === 'genpkey') {
    if ($a !== ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', $out] || basename($out) !== 'key.pem' || !is_dir(dirname($out))) {
        fwrite(STDERR, 'bad genpkey');
        exit(2);
    }
    if ($mode !== 'silent') {
        file_put_contents($out, 'KEY');
    }
    exit(0);
}
$i = array_search('-key', $a, true);
$k = $i === false ? '' : (string) $a[$i + 1];
$want = ['req', '-new', '-x509', '-key', $k, '-subj', '/CN=node0', '-days', '2', '-sha256', '-addext', 'basicConstraints=critical,CA:FALSE',
    '-addext', 'keyUsage=critical,digitalSignature', '-addext', 'extendedKeyUsage=serverAuth,clientAuth', '-out', $out];
if ($a !== $want || ($mode !== 'silent' && @file_get_contents($k) !== 'KEY') || basename($out) !== 'cert.pem' || dirname($out) !== dirname($k)) {
    fwrite(STDERR, 'bad req');
    exit(2);
}
if ($mode === 'ok') {
    file_put_contents($out, 'CERT');
}
exit(0);
PHP;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/mix28-certs-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0700);
        file_put_contents($this->dir . '/fake.php', self::FAKE);
        $this->fake = $this->dir . '/fake-openssl';
        file_put_contents($this->fake, "#!/bin/sh\nexec " . escapeshellarg(PHP_BINARY) . ' -n ' . escapeshellarg($this->dir . '/fake.php') . " \"\$@\"\n");
        chmod($this->fake, 0755);
        $this->mode('ok');
    }

    protected function tearDown(): void
    {
        MpcNetCerts::$mkdirHook = null;
        MpcNetCerts::$procOpenHook = null;
        MpcNetCerts::rmTree($this->dir);
    }

    private function mode(string $m): void
    {
        file_put_contents($this->dir . '/mode', $m);
    }

    private static function posix(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            self::markTestSkipped('the stand-in openssl is a /bin/sh script');
        }
    }

    /** Run `$f`, collecting PHP warnings instead of letting them through, and return the exception it threw (null when none). */
    private function thrown(callable $f): ?\Throwable
    {
        set_error_handler(function (int $no, string $msg): bool {
            $this->warnings[] = $msg;
            return true;
        });
        try {
            $f();
            return null;
        } catch (\Throwable $e) {
            return $e;
        } finally {
            restore_error_handler();
        }
    }

    private function refuses(string $class, string $msg, callable $f): void
    {
        $e = $this->thrown($f);
        self::assertNotNull($e, "expected $class");
        self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
    }

    /** generate runs genpkey then req with the exact arguments and returns the two files it wrote. */
    public function testGenerateRunsTheTwoCommands(): void
    {
        self::posix();
        self::assertSame(['keyPem' => 'KEY', 'certPem' => 'CERT'], MpcNetCerts::generate('node0', $this->fake));
    }

    /** A common name outside [A-Za-z0-9._-]{1,64} is refused before anything runs. */
    public function testBadCommonNameRefused(): void
    {
        $this->refuses(\InvalidArgumentException::class, 'certs: bad common name', fn() => MpcNetCerts::generate('bad name', $this->fake));
        $this->refuses(\InvalidArgumentException::class, 'certs: bad common name', fn() => MpcNetCerts::generate(str_repeat('a', 65), $this->fake));
    }

    /** Commands that succeed without writing the identity files fail closed. */
    public function testMissingIdentityFilesFailClosed(): void
    {
        self::posix();
        foreach (['nocert', 'silent'] as $m) {
            $this->mode($m);
            $this->refuses(\RuntimeException::class, 'certs: identity files unreadable', fn() => MpcNetCerts::generate('node0', $this->fake));
        }
    }

    /** A failing command throws with its name and the first 200 bytes of its stderr. */
    public function testFailingCommandReportsItsStderr(): void
    {
        self::posix();
        $this->mode('fail');
        $this->refuses(\RuntimeException::class, 'certs: ' . $this->fake . ' failed: A' . str_repeat('B', 198) . 'C',
            fn() => MpcNetCerts::generate('node0', $this->fake));
    }

    /** A command that cannot be started is refused with its name. */
    public function testUnstartableCommand(): void
    {
        MpcNetCerts::$procOpenHook = static fn(array $cmd): bool => false;
        $this->refuses(\RuntimeException::class, 'certs: cannot start my-openssl', static fn() => MpcNetCerts::generate('node0', 'my-openssl'));
    }

    /** A temporary directory that cannot be created is refused. */
    public function testTempDirFailure(): void
    {
        MpcNetCerts::$mkdirHook = static fn(string $d): bool => false;
        $this->refuses(\RuntimeException::class, 'certs: cannot create a temporary directory', static fn() => MpcNetCerts::tempDir());
    }

    /** generateFiles writes key.pem and cert.pem under the directory, and refuses a directory it cannot create. */
    public function testGenerateFiles(): void
    {
        self::posix();
        $out = $this->dir . '/out';
        self::assertSame(['keyPath' => "$out/key.pem", 'certPath' => "$out/cert.pem"], MpcNetCerts::generateFiles($out, 'node0', $this->fake));
        self::assertSame(['KEY', 'CERT'], [file_get_contents("$out/key.pem"), file_get_contents("$out/cert.pem")]);
        $bad = $this->dir . '/mode/sub';
        $this->refuses(\RuntimeException::class, "certs: cannot create $bad", fn() => MpcNetCerts::generateFiles($bad, 'node0', $this->fake));
    }

    /** fingerprintOf refuses what is not a certificate; readPem reads a file or refuses a missing one; writeSecret refuses an unwritable path. */
    public function testFileHelpers(): void
    {
        $this->refuses(\InvalidArgumentException::class, 'certs: not a certificate', static fn() => MpcNetCerts::fingerprintOf('not a pem'));
        file_put_contents($this->dir . '/a.pem', 'PEM');
        self::assertSame('PEM', MpcNetCerts::readPem($this->dir . '/a.pem'));
        $missing = $this->dir . '/missing.pem';
        $this->refuses(\RuntimeException::class, "certs: cannot read $missing", static fn() => MpcNetCerts::readPem($missing));
        $nowhere = $this->dir . '/no/such/key.pem';
        $this->refuses(\RuntimeException::class, "certs: cannot write $nowhere", static fn() => MpcNetCerts::writeSecret($nowhere, 'k'));
    }
}
