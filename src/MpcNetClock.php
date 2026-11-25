<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Time source for every DECISION the mesh makes by time (receive deadlines, connect deadline). The default is the wall clock; tests
 * inject a virtual clock so an outcome never depends on how loaded the machine is. A deadline is always a parameter (`timeoutMs`)
 * and is recorded on the resulting MpcNetAbort (`deadlineMs`). Polling intervals and pacing are real time, not decisions.
 */
interface MpcNetClock
{
    /** Milliseconds on this clock. */
    public function now(): int;
}

final class MpcNetWallClock implements MpcNetClock
{
    public function now(): int
    {
        return (int) floor(microtime(true) * 1000);
    }
}
