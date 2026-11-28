<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** Something the cooperative loop services: a mesh or a fault proxy. All I/O is non-blocking; pump() never waits. */
interface MpcNetPumpable
{
    public function pump(): void;

    /** @return list<resource> streams to wait on for reading */
    public function readStreams(): array;

    /** @return list<resource> streams to wait on for writing */
    public function writeStreams(): array;
}

/**
 * The single-threaded cooperative scheduler behind the networked MPC. Protocol code is written as blocking calls; inside a Fiber a
 * blocking call suspends back to run(), outside one it waits in step(). run() drives several nodes (each a Fiber) over real loopback
 * sockets in one process, so an in-process n-node run exercises the same TLS mesh as separate processes do.
 */
final class MpcNetLoop
{
    /** Real milliseconds idle() waits for socket activity when it is not inside a Fiber. */
    public const IDLE_STEP_MS = 20;

    /** @var array<int,MpcNetPumpable> */
    private static array $live = [];

    public static function register(MpcNetPumpable $p): void
    {
        self::$live[spl_object_id($p)] = $p;
    }

    public static function unregister(MpcNetPumpable $p): void
    {
        unset(self::$live[spl_object_id($p)]);
    }

    public static function mono(): int
    {
        return intdiv(hrtime(true), 1_000_000);
    }

    /** Wait up to $ms real milliseconds for socket activity, then service every live mesh / proxy once. */
    public static function step(int $ms): void
    {
        $r = [];
        $w = [];
        foreach (self::$live as $p) {
            array_push($r, ...$p->readStreams());
            array_push($w, ...$p->writeStreams());
        }
        if ($r === [] && $w === []) {
            usleep($ms * 1000);
        } else {
            $e = [];
            // a TLS stream can hold decrypted bytes select cannot see: the short timeout bounds the delay, every pump reads to the end
            @stream_select($r, $w, $e, 0, $ms * 1000);
        }
        foreach (self::$live as $p) {
            $p->pump();
        }
    }

    /** Service the sockets for $ms real milliseconds (lets abort frames and closes flush). */
    public static function drain(int $ms): void
    {
        $end = self::mono() + $ms;
        do {
            self::step(5);
        } while (self::mono() < $end);
    }

    /** Block (or, inside a Fiber, yield) until something may have changed. */
    public static function idle(): void
    {
        if (\Fiber::getCurrent() !== null) {
            \Fiber::suspend();
            return;
        }
        self::step(self::IDLE_STEP_MS);
    }

    /**
     * Run every task (a callable) as a Fiber until all finish. Each result is ['ok' => true, 'value' => mixed] or
     * ['ok' => false, 'error' => \Throwable]. $onIdle runs once per scheduling round (tests advance a virtual clock there);
     * $capMs is a real-time cap after which the unfinished tasks fail with a RuntimeException.
     *
     * @param array<int|string,callable> $tasks
     * @return array<int|string,array{ok:bool,value?:mixed,error?:\Throwable}>
     */
    public static function run(array $tasks, ?callable $onIdle = null, int $capMs = 300000): array
    {
        $fibers = [];
        foreach ($tasks as $k => $t) {
            $fibers[$k] = new \Fiber($t);
        }
        $res = [];
        $end = self::mono() + $capMs;
        while ($fibers !== []) {
            foreach ($fibers as $k => $f) {
                try {
                    if (!$f->isStarted()) {
                        $f->start();
                    } elseif ($f->isSuspended()) {
                        $f->resume();
                    }
                    if ($f->isTerminated()) {
                        $res[$k] = ['ok' => true, 'value' => $f->getReturn()];
                        unset($fibers[$k]);
                    }
                } catch (\Throwable $e) {
                    $res[$k] = ['ok' => false, 'error' => $e];
                    unset($fibers[$k]);
                }
            }
            if ($fibers === []) {
                break;
            }
            self::step(5);
            if ($onIdle !== null) {
                $onIdle();
            }
            if (self::mono() > $end) {
                foreach ($fibers as $k => $_) {
                    $res[$k] = ['ok' => false, 'error' => new \RuntimeException('loop: real-time cap reached')];
                }
                break;
            }
        }
        self::drain(150);
        ksort($res);
        return $res;
    }
}
