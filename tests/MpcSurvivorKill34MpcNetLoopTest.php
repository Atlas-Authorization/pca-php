<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetLoop;
use Atlas\Pca\MpcNetPumpable;
use PHPUnit\Framework\TestCase;

/** A registered loop member with no streams that counts how often it is serviced. */
final class Mpc34CountingPump implements MpcNetPumpable
{
    public int $pumps = 0;

    public function pump(): void
    {
        $this->pumps++;
    }

    public function readStreams(): array
    {
        return [];
    }

    public function writeStreams(): array
    {
        return [];
    }
}

/** Group 34 kills for MpcNetLoop: idle() outside a Fiber services the loop once after its named wait, and run()'s real-time cap. */
final class MpcSurvivorKill34MpcNetLoopTest extends TestCase
{
    /** Outside a Fiber, idle() waits IDLE_STEP_MS (20 ms) for activity and then services every live member exactly once. */
    public function testIdleOutsideAFiberStepsTheLoopOnce(): void
    {
        $this->assertSame(20, MpcNetLoop::IDLE_STEP_MS);
        $p = new Mpc34CountingPump();
        MpcNetLoop::register($p);
        try {
            MpcNetLoop::idle();
        } finally {
            MpcNetLoop::unregister($p);
        }
        $this->assertSame(1, $p->pumps);
    }

    /**
     * Past the cap every unfinished task fails with the cap error (and is not resumed again, even though it would finish on the next
     * resume); a task that already finished keeps its value.
     */
    public function testRealTimeCapFailsTheUnfinishedTasks(): void
    {
        $res = MpcNetLoop::run([
            'slow' => static function (): string {
                \Fiber::suspend();
                return 'late';
            },
            'fast' => static fn(): string => 'done',
        ], static function (): void {
            usleep(1000); // the cap is 0 ms: guarantee the clock has moved past it whatever the loop found to service
        }, 0);
        $this->assertSame(['fast', 'slow'], array_keys($res));
        $this->assertSame(['ok' => true, 'value' => 'done'], $res['fast']);
        $this->assertSame(['ok', 'error'], array_keys($res['slow']));
        $this->assertFalse($res['slow']['ok']);
        $this->assertSame(\RuntimeException::class, get_class($res['slow']['error']));
        $this->assertSame('loop: real-time cap reached', $res['slow']['error']->getMessage());
    }
}
