<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetFaultProxy;
use PHPUnit\Framework\TestCase;

/** Group 28b: the fault proxy stops writing a direction for this pump as soon as a write makes no progress. */
final class MixSurvivorKill28bMpcNetFaultsTest extends TestCase
{
    protected function tearDown(): void
    {
        MpcNetFaultProxy::$writeHook = null;
    }

    /** A write that returns 0 ends the write loop after that one call; the bytes stay pending and the direction is not shut. */
    public function testZeroWriteStopsTheLoop(): void
    {
        $calls = [];
        MpcNetFaultProxy::$writeHook = static function ($to, string $bytes) use (&$calls): int {
            $calls[] = $bytes;
            return count($calls) === 1 ? 0 : strlen($bytes);
        };
        $p = new MpcNetFaultProxy(0, ['host' => '127.0.0.1', 'port' => 9], ['kind' => 'none', 'dir' => 'c2s', 'afterBytes' => 0]);
        $st = ['seen' => 0, 'fired' => false, 'done' => false, 'held' => null, 'out' => 'abc', 'delayed' => [], 'ended' => false, 'shut' => false];
        $from = fopen('php://memory', 'w+');
        $to = fopen('php://memory', 'w+');
        (new \ReflectionMethod(MpcNetFaultProxy::class, 'pipe'))->invokeArgs($p, [$from, $to, &$st, 'c2s']);
        fclose($from);
        fclose($to);
        self::assertSame(['abc'], $calls);
        self::assertSame(['abc', true, false], [$st['out'], $st['ended'], $st['shut']]);
    }
}
