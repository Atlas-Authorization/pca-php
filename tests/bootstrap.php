<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

/*
 * Per-test guard for the mutation job (env PCA_TEST_DEADLINE = seconds; unset or 0 = off). A mutant that makes a loop stop advancing
 * would otherwise hang PHPUnit until Infection's timeout, or grow memory (every PHP warning adds a PHPUnit Issue) until the
 * memory_limit fatal ends the process: both are reported as run errors that no test decided.
 *  - Deadline: one SIGALRM per test, re-armed every second while the test still runs; the running test throws when it fires and so
 *    FAILS (the mutant is killed by it), even if a catch swallows the first throw.
 *  - Memory (Linux): a watchdog child process reads this process's resident set from /proc ten times a second and, only while it is above
 *    PCA_TEST_MEMORY_MB (default 2400), sends SIGUSR1 at every poll; the handler throws, so the running test fails the same way even
 *    if a catch swallows the first throw. Nothing is signalled in a normal run (a periodic tick would cut short the sleeps of the
 *    timing tests). The clean suite peaks at about 970 MB (about 1.2 GB resident in Infection's coverage run) under a 3072 MB memory_limit.
 */
(static function (): void {
    $seconds = (int)getenv('PCA_TEST_DEADLINE');
    if ($seconds <= 0 || !function_exists('pcntl_alarm') || !function_exists('pcntl_async_signals')) {
        return;
    }
    pcntl_async_signals(true);
    pcntl_signal(SIGALRM, static function () use ($seconds): void {
        pcntl_alarm(1);   // a catch that swallows this throw must meet the next one a second later, not wait for the process timeout
        throw new \RuntimeException("test deadline of $seconds s exceeded (a loop that does not end)");
    });
    $memoryMb = (int)(getenv('PCA_TEST_MEMORY_MB') ?: 2400);
    if (function_exists('pcntl_fork') && function_exists('posix_kill') && is_readable('/proc/self/statm')) {
        pcntl_signal(SIGUSR1, static function () use ($memoryMb): void {
            throw new \RuntimeException("test memory above $memoryMb MB (a loop that grows without end)");
        });
        $parent = getmypid();
        $pid = pcntl_fork();
        if ($pid === 0) {
            // watchdog: never runs PHPUnit or shutdown code; ends with the parent. It lets go of the inherited stdio first, so a
            // reader waiting for the end of the parent's output (Infection) is not held up by it.
            foreach (['STDIN', 'STDOUT', 'STDERR'] as $h) {
                if (defined($h)) { // not defined when this file is loaded by `php` reading code from stdin
                    @fclose(constant($h));
                }
            }
            while (posix_getppid() === $parent) {
                usleep(100000);
                $statm = @file_get_contents("/proc/$parent/statm");
                if ($statm === false) {
                    break;
                }
                $pages = (int)(explode(' ', $statm)[1] ?? 0);
                if ($pages * 4 / 1024 > $memoryMb) {
                    posix_kill($parent, SIGUSR1);
                }
            }
            posix_kill(posix_getpid(), SIGKILL);
            exit(0);
        }
    }
    $facade = \PHPUnit\Event\Facade::instance();
    $facade->registerSubscriber(new class ($seconds) implements \PHPUnit\Event\Test\PreparedSubscriber {
        public function __construct(private readonly int $seconds)
        {
        }

        public function notify(\PHPUnit\Event\Test\Prepared $event): void
        {
            pcntl_alarm($this->seconds);
        }
    });
    $facade->registerSubscriber(new class implements \PHPUnit\Event\Test\FinishedSubscriber {
        public function notify(\PHPUnit\Event\Test\Finished $event): void
        {
            pcntl_alarm(0);
        }
    });
})();
