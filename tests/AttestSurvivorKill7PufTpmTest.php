<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/AttestPuf.php';

use Atlas\Pca\AttestPuf;
use Atlas\Pca\Obj;
use Atlas\Pca\TpmEkPufProvider;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the TPM-EK PUF provider (response stream, bounds) and its default process runner. */
final class AttestSurvivorKill7PufTpmTest extends TestCase
{
    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e::class . ': ' . $e->getMessage();
        }
        return 'no error';
    }

    private static function provider(int $len, string $ek, array $extra = []): TpmEkPufProvider
    {
        return new TpmEkPufProvider(Obj::of(['id' => 'tpm', 'length' => $len,
            'run' => static fn(string $c, array $a): Obj => Obj::of(['status' => 0, 'stdout' => $ek])] + $extra));
    }

    private static function expectedBits(string $ek, string $challenge, int $len): string
    {
        $secret = hash_hkdf('sha256', $ek, 32, $challenge, AttestPuf::TPM_EK_PUF_DOMAIN);
        $stream = '';
        for ($b = 0; $b < intdiv($len + 255, 256); $b++) {
            $stream .= hash('sha256', $secret . pack('N', $b), true);
        }
        $out = '';
        for ($i = 0; $i < $len; $i++) {
            $out .= ((ord($stream[$i >> 3]) >> ($i & 7)) & 1) === 1 ? "\1" : "\0";
        }
        return $out;
    }

    private static function needUnix(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            self::markTestSkipped('needs a POSIX sh');
        }
    }

    private static function sh(string $script): Obj
    {
        return TpmEkPufProvider::defaultRunner('sh', ['-c', $script]);
    }

    /** The response covers exactly ceil(length/256) hash blocks, at every block boundary. */
    public function testResponseStreamLengthAtBlockBoundaries(): void
    {
        $ek = str_repeat("\7", 64);
        foreach ([1, 8, 9, 256, 257, 513] as $len) {
            $got = self::provider($len, $ek)->response('chal');
            $this->assertSame($len, strlen($got), "length $len");
            $this->assertSame(self::expectedBits($ek, 'chal', $len), $got, "bits $len");
        }
    }

    /** A length of exactly 1 and a minEkBytes of exactly 1 are valid; zero is refused for both. */
    public function testMinimalBoundsAccepted(): void
    {
        $this->assertSame(1, strlen(self::provider(1, str_repeat("\7", 64))->response('c')));
        $this->assertSame('A', self::provider(8, 'A', ['minEkBytes' => 1])->readEkPublic());
        $this->assertSame(
            'RangeException: TpmEkPufProvider: length must be a positive integer (= enrolled rep*messageBits)',
            self::thrown(static fn() => self::provider(0, 'A'))
        );
        $this->assertSame(
            'RangeException: TpmEkPufProvider: minEkBytes must be a positive integer',
            self::thrown(static fn() => self::provider(8, 'A', ['minEkBytes' => 0]))
        );
    }

    /** Without an injected runner the provider spawns the tool itself and returns its stdout. */
    public function testDefaultRunnerIsWiredWhenNoRunnerIsInjected(): void
    {
        self::needUnix();
        $p = new TpmEkPufProvider(Obj::of(['id' => 't', 'length' => 8, 'tool' => 'sh', 'args' => ['-c', 'printf abc'], 'minEkBytes' => 1]));
        $this->assertSame('abc', $p->readEkPublic());
    }

    /** The runner returns status, stdout and (only when non-empty) stderr, for a tool that takes a moment and exits non-zero. */
    public function testRunnerReportsStatusStdoutAndStderr(): void
    {
        self::needUnix();
        $r = self::sh('sleep 0.2; printf ABC; printf ERR >&2; exit 3');
        $this->assertSame(['status', 'stdout', 'stderr'], $r->keys());
        $this->assertSame(3, $r->get('status'));
        $this->assertSame('ABC', $r->get('stdout'));
        $this->assertSame('ERR', $r->get('stderr'));

        $ok = self::sh('printf ABC');
        $this->assertSame(['status', 'stdout'], $ok->keys());
        $this->assertSame(0, $ok->get('status'));
        $this->assertSame('ABC', $ok->get('stdout'));
    }

    /** A tool that cannot be started is reported as an error with a null status (or, if the OS starts a shell stub, a failing status). */
    public function testRunnerReportsASpawnFailure(): void
    {
        self::needUnix();
        $cmd = '/nonexistent/atlas-no-such-tool';
        $r = TpmEkPufProvider::defaultRunner($cmd, []);
        if ($r->has('error')) {
            $this->assertSame(['status', 'stdout', 'error'], $r->keys());
            $this->assertNull($r->get('status'));
            $this->assertSame('', $r->get('stdout'));
            $this->assertSame("$cmd: spawn failed", $r->get('error'));
        } else {
            $this->assertNotSame(0, $r->get('status'));
        }
    }

    /** Output of exactly 1 MiB is returned whole; the cap is only exceeded by one more byte. */
    public function testRunnerAcceptsExactlyOneMiB(): void
    {
        self::needUnix();
        $r = self::sh('head -c 1048576 /dev/zero');
        $this->assertSame(['status', 'stdout'], $r->keys());
        $this->assertSame(0, $r->get('status'));
        $this->assertSame(1048576, strlen($r->get('stdout')));
    }

    /** One byte past the 1 MiB cap kills the tool at once (SIGKILL, even a tool ignoring other signals) and reports a timeout. */
    public function testRunnerKillsATooChattyTool(): void
    {
        self::needUnix();
        $t = hrtime(true);
        $r = self::sh('trap "" 8 10; head -c 1048577 /dev/zero; sleep 5');
        $secs = (hrtime(true) - $t) / 1e9;
        $this->assertSame(['status', 'stdout', 'error'], $r->keys());
        $this->assertNull($r->get('status'));
        $this->assertSame('', $r->get('stdout'));
        $this->assertSame('sh: ETIMEDOUT', $r->get('error'));
        $this->assertLessThan(3.0, $secs);
    }

    /**
     * All of stderr is read even after the tool has exited with stdout closed: the tool exits at once, leaving a background writer that
     * holds stderr and writes only a second later, so the exit status and stdout's end are always seen before any stderr byte arrives.
     */
    public function testRunnerDrainsStderrAfterStdoutClosed(): void
    {
        self::needUnix();
        $r = self::sh('exec 1>&-; (sleep 1; head -c 150000 /dev/zero >&2) & exit 0');
        $this->assertSame(['status', 'stdout', 'stderr'], $r->keys());
        $this->assertSame(0, $r->get('status'));
        $this->assertSame('', $r->get('stdout'));
        $this->assertSame(150000, strlen($r->get('stderr')));
    }

    /** All of stdout is read even after the tool has exited with stderr closed (a background writer holds stdout and writes a second later). */
    public function testRunnerDrainsStdoutAfterStderrClosed(): void
    {
        self::needUnix();
        $r = self::sh('exec 2>&-; (sleep 1; head -c 150000 /dev/zero) & exit 0');
        $this->assertSame(['status', 'stdout'], $r->keys());
        $this->assertSame(0, $r->get('status'));
        $this->assertSame(150000, strlen($r->get('stdout')));
    }

    /** The runner waits for the tool to exit even when a stream is already closed, and when both are. */
    public function testRunnerWaitsForExitAfterStreamsClose(): void
    {
        self::needUnix();
        $a = self::sh('exec 2>&-; sleep 0.2; printf late');
        $this->assertSame(0, $a->get('status'));
        $this->assertSame('late', $a->get('stdout'));
        $b = self::sh('exec 1>&- 2>&-; sleep 0.2; exit 5');
        $this->assertSame(5, $b->get('status'));
        $this->assertSame('', $b->get('stdout'));
    }

    /** The tool's standard input is the null device. */
    public function testRunnerStdinIsTheNullDevice(): void
    {
        if (PHP_OS_FAMILY !== 'Linux') {
            self::markTestSkipped('needs /proc');
        }
        $r = self::sh('readlink /proc/self/fd/0');
        $this->assertSame("/dev/null\n", $r->get('stdout'));
    }
}
