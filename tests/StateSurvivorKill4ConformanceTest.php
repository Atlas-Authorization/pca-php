<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/StoreConformance.php';

use Atlas\Pca\MemoryOperationStore;
use Atlas\Pca\StoreConformance;
use PHPUnit\Framework\TestCase;

/** The conformance kit's race harness: the exit status of a copy that wrote no result, and the stuck-race diagnostic. */
final class StateSurvivorKill4ConformanceTest extends TestCase
{
    /** @var list<string> */
    private array $files = [];

    protected function tearDown(): void
    {
        StoreConformance::$forkHook = null;
        foreach ($this->files as $f) {
            @unlink($f);
        }
    }

    /** A forked copy that exits normally without a result file is counted by its exit status (here 10, an admitted create). */
    public function testACopyWithoutAResultFileIsCountedByItsExitStatus(): void
    {
        if (!function_exists('pcntl_fork') || !function_exists('pcntl_exec') || !is_executable('/bin/sh')) {
            $this->markTestSkipped('pcntl_fork / pcntl_exec and /bin/sh are needed');
        }
        StoreConformance::$forkHook = static function (): int {
            StoreConformance::$forkHook = null; // only the first race's copy; every later race forks normally
            $pid = pcntl_fork();
            if ($pid === 0) {
                pcntl_exec('/bin/sh', ['-c', 'exit 10']); // ends the copy with status 10 and no PHP shutdown, writing no result file
            }
            return $pid;
        };
        $r = StoreConformance::runOperationStore(['name' => 'exit-status', 'open' => static fn() => new MemoryOperationStore(), 'shared' => false,
            'durable' => false, 'processes' => true, 'copies' => 1]);
        self::assertSame('pass', $r->status('create-once'), (string)$r);
    }

    /** The stuck-race diagnostic names, on stderr, the last step of every copy not yet reaped, in order. */
    public function testReportStuckNamesTheLastStepOfEachUnfinishedCopy(): void
    {
        $dir = sys_get_temp_dir() . '/statekill4-' . bin2hex(random_bytes(6));
        mkdir($dir, 0700);
        $gate = $dir . '/gate';
        $step = $dir . '/pcastep-gate-1';
        file_put_contents($step, 'claim');
        $this->files = [$step];
        if (!in_array('statekill4.capture', stream_get_filters(), true)) {
            stream_filter_register('statekill4.capture', StateKill4StderrCapture::class);
        }
        StateKill4StderrCapture::$buf = '';
        $filter = stream_filter_append(STDERR, 'statekill4.capture', STREAM_FILTER_WRITE);
        try {
            (new \ReflectionMethod(StoreConformance::class, 'reportStuck'))->invoke(null, $gate, 3, 1);
        } finally {
            stream_filter_remove($filter);
            @unlink($step);
            @rmdir($dir);
        }
        self::assertSame("\n[conformance] race still running after 20 s; last step of each unfinished copy: 1=claim, 2=no step\n", StateKill4StderrCapture::$buf);
    }
}

/** A stream filter that keeps what is written through it (and passes nothing on), to read what the kit writes to STDERR. */
final class StateKill4StderrCapture extends \php_user_filter
{
    public static string $buf = '';

    public function filter($in, $out, &$consumed, bool $closing): int
    {
        while ($bucket = stream_bucket_make_writeable($in)) {
            self::$buf .= $bucket->data;
            $consumed += $bucket->datalen;
        }
        return PSFS_FEED_ME;
    }
}
