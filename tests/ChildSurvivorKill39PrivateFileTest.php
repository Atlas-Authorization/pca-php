<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PrivateFile;
use PHPUnit\Framework\TestCase;

/**
 * killSelf with no test hook really ends the process, in a child PHP process: SIGKILL where posix_kill exists, else exit with the code;
 * on Windows TerminateProcess with the code. The class name matches the Windows mutation shard's PrivateFileTest filter.
 */
final class ChildSurvivorKill39PrivateFileTest extends TestCase
{
    protected function tearDown(): void
    {
        PrivateFile::$exitHook = null;
    }

    /**
     * Under a mutation run the child must load the same mutated source as this process: replay the parent's include interception (when
     * one is active) in the child before the autoloader, so the child runs exactly the code under test.
     */
    private static function interception(): string
    {
        $c = 'Infection\\StreamWrapper\\IncludeInterceptor';
        if (!class_exists($c, false)) {
            return '';
        }
        $r = new \ReflectionClass($c);
        $from = $r->hasProperty('intercept') ? $r->getProperty('intercept')->getValue() : null;
        $to = $r->hasProperty('replacement') ? $r->getProperty('replacement')->getValue() : null;
        if (!is_string($from) || !is_string($to)) {
            return ''; // an unknown interceptor shape: the child runs the plain source, so it can only miss a kill, never invent one
        }
        return 'require_once ' . var_export((string)$r->getFileName(), true) . ';'
            . '\\' . $c . '::intercept(' . var_export($from, true) . ', ' . var_export($to, true) . ');'
            . '\\' . $c . '::enable();';
    }

    /**
     * Run killSelf(5) in a fresh PHP process with the given ini settings.
     *
     * @param list<string> $ini
     * @return array{0: array<string,mixed>, 1: string} the final proc_get_status and everything the child printed
     */
    private static function child(array $ini): array
    {
        $code = self::interception() . 'require ' . var_export(dirname(__DIR__) . '/vendor/autoload.php', true) . ';'
            . '\\Atlas\\Pca\\PrivateFile::killSelf(5); echo "survived";';
        $args = [PHP_BINARY];
        foreach ($ini as $i) {
            $args[] = '-d';
            $args[] = $i;
        }
        $args[] = '-r';
        $args[] = $code;
        $p = proc_open($args, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        self::assertIsResource($p);
        fclose($pipes[0]);
        $out = (string)stream_get_contents($pipes[1]) . (string)stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        do {
            $s = proc_get_status($p);
            if ($s['running']) {
                usleep(10000);
            }
        } while ($s['running']);
        proc_close($p);
        return [$s, $out];
    }

    /** Covers the hook path in this process (so a coverage-selected run picks this test), then checks the real path in a child. */
    private static function coverInProcess(): void
    {
        PrivateFile::$exitHook = static function (string $step, int $code): void {
            if ($step === 'exit') {
                throw new \LogicException("exit $code");
            }
        };
        try {
            PrivateFile::killSelf(5);
        } catch (\LogicException $e) {
            self::assertSame('exit 5', $e->getMessage());
        } catch (\Throwable) {
            // Windows without ext-ffi refuses before any step; the child test below is skipped there
        }
        PrivateFile::$exitHook = null;
    }

    /** POSIX with posix_kill: the process dies of SIGKILL (signal 9), before any exit code and before printing anything more. */
    public function testPosixKillSelfSendsSigkill(): void
    {
        if (PHP_OS_FAMILY === 'Windows' || !function_exists('posix_kill')) {
            self::markTestSkipped('needs POSIX signals and posix_kill');
        }
        self::coverInProcess();
        [$s, $out] = self::child([]);
        self::assertTrue($s['signaled'], "child: $out");
        self::assertSame(9, $s['termsig']);
        self::assertSame('', $out);
    }

    /** POSIX without posix_kill: the process exits with exactly the requested code and prints nothing. */
    public function testPosixKillSelfWithoutPosixExitsWithTheCode(): void
    {
        if (PHP_OS_FAMILY === 'Windows') {
            self::markTestSkipped('the exit-code fallback is the POSIX branch');
        }
        self::coverInProcess();
        [$s, $out] = self::child(['disable_functions=posix_kill']);
        self::assertFalse($s['signaled'], "child: $out");
        self::assertSame(5, $s['exitcode']);
        self::assertSame('', $out);
    }

    /** Windows: TerminateProcess ends the process with exactly the requested code and nothing more is printed. */
    public function testWindowsKillSelfTerminatesWithTheCode(): void
    {
        if (PHP_OS_FAMILY !== 'Windows') {
            self::markTestSkipped('TerminateProcess is the Windows branch');
        }
        if (!extension_loaded('ffi')) {
            self::markTestSkipped('the Windows branch needs ext-ffi; its no-ffi refusal is held by GrantSurvivorKill21bPrivateFileTest');
        }
        self::coverInProcess();
        [$s, $out] = self::child(['ffi.enable=1']);
        self::assertSame(5, $s['exitcode'], "child: $out");
        self::assertSame('', $out);
    }
}
