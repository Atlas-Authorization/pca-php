<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

/**
 * A forked test copy that ends WITHOUT running PHP shutdown. A copy that calls exit() destroys every object its parent held open at the fork, which
 * closes inherited SQLite connections inside the copy; POSIX fcntl locks belong to the process, so closing any descriptor on the database drops the
 * copy's OWN locks on it and the mutual exclusion under test breaks. The copy writes its result code to a file and kills itself (SIGKILL), so no
 * destructor runs; the parent reads the code back with {@see wait}. Whatever the copy did has completed (a statement committed) before it ends.
 */
final class ForkedCopy
{
    private function __construct(public readonly int $pid, private readonly string $result)
    {
    }

    /** Fork a copy that runs `$body` (returning its result code 0..255; a throw is 255) and ends as above. Returns the parent's handle. */
    public static function start(callable $body): self
    {
        $result = tempnam(sys_get_temp_dir(), 'pcafork');
        $pid = pcntl_fork();
        if ($pid < 0) {
            throw new \RuntimeException('fork failed');
        }
        if ($pid === 0) {
            try {
                $code = (int)$body();
            } catch (\Throwable) {
                $code = 255;
            }
            self::end($result, $code);
        }
        return new self($pid, $result);
    }

    /** Wait for the copy and return its result code (255 when it left none). */
    public function wait(): int
    {
        pcntl_waitpid($this->pid, $status);
        $raw = (string)@file_get_contents($this->result);
        @unlink($this->result);
        return preg_match('/\A[0-9]{1,3}\z/', $raw) === 1 ? (int)$raw : 255;
    }

    /** End the calling copy now: record `$code` in `$resultFile`, then SIGKILL itself so no shutdown or destructor runs. */
    public static function end(string $resultFile, int $code): never
    {
        file_put_contents($resultFile, (string)$code);
        if (function_exists('posix_kill')) {
            posix_kill(getmypid(), SIGKILL);
        }
        exit($code);
    }
}
