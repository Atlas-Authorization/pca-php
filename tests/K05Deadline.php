<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\Assert;

/**
 * Deadline helper for kill tests of loops whose mutants stop advancing. The call runs in a forked copy of this process (so it sees
 * the same, possibly mutated, code); the child reports back over a socket pair and is then killed without running shutdown code.
 * A child that has not answered within $seconds is killed and counts as a hang.
 */
final class K05Deadline
{
    /** @return 'ok'|'hang'|string 'ok' when the call returned, 'hang' when it did not return in time, else 'error: ...' */
    public static function run(callable $fn, float $seconds = 3.0): string
    {
        if (PHP_OS_FAMILY === 'Windows') {
            throw new \PHPUnit\Framework\SkippedWithMessageException('no fork on Windows (the mutation job runs on Linux)');
        }
        Assert::assertTrue(function_exists('pcntl_fork') && function_exists('posix_kill'), 'pcntl and posix are required by the deadline tests');
        $pair = stream_socket_pair(STREAM_PF_UNIX, STREAM_SOCK_STREAM, STREAM_IPPROTO_IP);
        Assert::assertNotFalse($pair);
        $pid = pcntl_fork();
        Assert::assertNotSame(-1, $pid, 'fork failed');
        if ($pid === 0) {
            fclose($pair[0]);
            try {
                $fn();
                $msg = 'ok';
            } catch (\Throwable $e) {
                $msg = 'error: ' . get_class($e) . ': ' . $e->getMessage();
            }
            fwrite($pair[1], $msg);
            posix_kill(posix_getpid(), SIGKILL);
            exit(0);
        }
        fclose($pair[1]);
        $r = [$pair[0]];
        $w = $e = [];
        $sec = (int)floor($seconds);
        $ready = stream_select($r, $w, $e, $sec, (int)(($seconds - $sec) * 1e6));
        $answer = $ready ? (string)stream_get_contents($pair[0]) : '';
        fclose($pair[0]);
        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status);
        return $answer === '' ? 'hang' : $answer;
    }
}
