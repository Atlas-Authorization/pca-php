<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetCodec;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcNetCodec: the strict base64 and point decoders refuse a wrong type and a truncated quantum with their exact reason. */
final class MpcSurvivorKill34MpcNetCodecTest extends TestCase
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

    /** A non-string and a lone trailing base64 character (6 bits, no whole byte) are both 'bad base64'; canonical text decodes. */
    public function testUnb64RefusesNonStringsAndATruncatedQuantum(): void
    {
        self::refuses('bad base64', static fn() => MpcNetCodec::unb64(123));
        self::refuses('bad base64', static fn() => MpcNetCodec::unb64(null));
        self::refuses('bad base64', static fn() => MpcNetCodec::unb64('A'));
        self::refuses('bad base64', static fn() => MpcNetCodec::unb64('QUJD='));
        $this->assertSame('ABC', MpcNetCodec::unb64('QUJD'));
    }

    /** A point that is not an object is refused as 'bad point' before any coordinate is read. */
    public function testJPtRefusesANonObject(): void
    {
        self::refuses('bad point', static fn() => MpcNetCodec::jPt(['x' => '1', 'y' => '1']));
        self::refuses('bad point', static fn() => MpcNetCodec::jPt('1'));
    }
}
