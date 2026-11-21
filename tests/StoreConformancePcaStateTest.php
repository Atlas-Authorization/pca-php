<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\StoreConformancePcaState as P;
use PHPUnit\Framework\TestCase;

/** The pca-state profile: the good reference stores pass through the real guard, the planted-bug stores are caught. */
final class StoreConformancePcaStateTest extends TestCase
{
    private static function statusOfTest(array $report, string $test): string
    {
        foreach ($report['tests'] as $t) {
            if ($t['test'] === $test) {
                return $t['status'];
            }
        }
        return 'absent';
    }

    public function testFixtureProofsAreRealSignedPcactnsAndTheGuardAdmitsEachCounterOnce(): void
    {
        $fx = P::fixture(3);
        $this->assertCount(3, $fx['proofs']);
        $g = P::guard($fx, new MemoryStateStore());
        $this->assertSame(['admitted', 'replay', 'admitted'], [$g(1), $g(1), $g(2)]);
    }

    public function testTheInMemoryStorePassesWhatItCanAndSkipsTheRest(): void
    {
        $r = P::run(P::builtin('in-memory'), ['rounds' => 3, 'copies' => 8]);
        $this->assertSame('pass', $r['status'], P::format($r));
        $this->assertSame('skip', self::statusOfTest($r, 'instances'));
        $this->assertSame('skip', self::statusOfTest($r, 'processes'));
        $this->assertSame('pass', self::statusOfTest($r, 'one-instance'));
        $this->assertSame('pass', self::statusOfTest($r, 'retry-after-timeout'));
    }

    public function testAProcessScopedStoreIsRefusedInMultiInstanceMode(): void
    {
        $a = P::builtin('in-memory');
        $a['shared'] = true; // the adapter claims to be shared; the store says otherwise
        $r = P::run($a, ['tests' => ['instances'], 'rounds' => 2, 'copies' => 4]);
        $this->assertSame('fail', $r['status'], P::format($r));
    }

    public function testPerHandleStatePassedOffAsSharedAdmitsOnePerHandle(): void
    {
        $r = P::run(P::builtin('bad-unshared'), ['tests' => ['instances'], 'rounds' => 3, 'copies' => 8]);
        $this->assertSame('fail', $r['status'], P::format($r));
    }

    public function testAStoreThatForgetsOnRestartFailsTheCrashTest(): void
    {
        $r = P::run(P::builtin('bad-volatile'), ['tests' => ['crash-after-claim']]);
        $this->assertSame('fail', $r['status'], P::format($r));
    }

    public function testTheDurableFileStorePassesAcrossRealProcesses(): void
    {
        if (!extension_loaded('pdo_sqlite') || !function_exists('proc_open')) {
            $this->markTestSkipped('needs pdo_sqlite and proc_open');
        }
        $dir = sys_get_temp_dir() . '/pcasc-test-' . bin2hex(random_bytes(4));
        mkdir($dir, 0700, true);
        $a = P::loadAdapter('builtin:durable-file', ['dir' => $dir]);
        $r = P::run($a, ['rounds' => 3, 'copies' => 4, 'processes' => 2]);
        $this->assertSame('pass', $r['status'], P::format($r));
        $this->assertSame('pass', self::statusOfTest($r, 'processes'));
        $this->assertSame('pass', self::statusOfTest($r, 'crash-after-claim'));
    }
}
