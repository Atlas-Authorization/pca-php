<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetWire;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcNetWire: stringify refuses a value shape the protocol never uses, and encodeFrame refuses a body over 4 MiB. */
final class MpcSurvivorKill34MpcNetWireTest extends TestCase
{
    private static function refuses(string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame(\InvalidArgumentException::class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected InvalidArgumentException: $msg");
    }

    /** An unsupported value is refused naming its type, also when nested. */
    public function testStringifyRefusesAnUnsupportedValue(): void
    {
        self::refuses('stringify: unsupported value stdClass', static fn() => MpcNetWire::stringify(new \stdClass()));
        self::refuses('stringify: unsupported value Closure', static fn() => MpcNetWire::stringify(['a' => static fn() => 1]));
    }

    /** A frame whose JSON body is one byte over MAX_FRAME_BYTES is refused; one exactly at the limit is encoded with its length prefix. */
    public function testFrameBodyLimit(): void
    {
        $frame = static fn(string $d): array => ['v' => 2, 'ty' => 'msg', 'sid' => 's', 'seq' => 1, 'rd' => 'r', 'd' => $d];
        $overhead = strlen(MpcNetWire::stringify(['v' => 2, 'ty' => 'msg', 'sid' => 's', 'seq' => 1, 'rd' => 'r', 'd' => '']));
        $fill = MpcNetWire::MAX_FRAME_BYTES - $overhead;
        $enc = MpcNetWire::encodeFrame($frame(str_repeat('a', $fill)));
        $this->assertSame(4 + MpcNetWire::MAX_FRAME_BYTES, strlen($enc));
        $this->assertSame(pack('N', MpcNetWire::MAX_FRAME_BYTES), substr($enc, 0, 4));
        self::refuses('frame too large', static fn() => MpcNetWire::encodeFrame($frame(str_repeat('a', $fill + 1))));
    }
}
