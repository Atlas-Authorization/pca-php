<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Entropy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The adaptive-proportion cutoff is exact integer arithmetic over p = 2^-h taken as the dyadic rational of its own bits. */
final class EntropyCutoffTest extends TestCase
{
    public function testKnownCutoffs(): void
    {
        self::assertSame(1107, Entropy::proportionCutoff(1, 2000)); // the old float recurrence underflowed here and returned 2001: the test was off
        self::assertSame(13, Entropy::proportionCutoff(8, 512));
        self::assertSame(410, Entropy::proportionCutoff(0.5, 512));
    }

    /** @return array<string,array{float,float}> */
    public static function badDomain(): array
    {
        return ['h not a multiple of 1/8' => [1.1, 512.0], 'h zero' => [0.0, 512.0], 'h below 1/8' => [0.0625, 512.0], 'h above 64' => [64.125, 512.0],
            'h NaN' => [NAN, 512.0], 'h infinite' => [INF, 512.0], 'window 1' => [1.0, 1.0], 'window above 65536' => [1.0, 65537.0],
            'window fractional' => [1.0, 512.5], 'window NaN' => [1.0, NAN]];
    }

    #[DataProvider('badDomain')]
    public function testOutOfDomainIsRefusedNeverRounded(float $h, float $w): void
    {
        $this->expectException(\RangeException::class);
        Entropy::proportionCutoff($h, $w);
    }

    public function testHealthTestFailsClosedOnAnUnrepresentableH(): void
    {
        self::assertSame(['ok' => false, 'test' => 'repetition-count'], Entropy::healthTestBytes(str_repeat("\x01\x02", 300), 1.1));
        self::assertSame(['ok' => false, 'test' => 'repetition-count'], Entropy::healthTestBytes(str_repeat("\x01\x02", 300), NAN));
        self::assertSame(['ok' => true], Entropy::healthTestBytes("\x01\x02\x03\x04\x05\x06\x07\x08", 8, 512));
    }

    public function testWindowClampsAndAOneByteWindowSkipsTheProportionTest(): void
    {
        self::assertSame(['ok' => true], Entropy::healthTestBytes("\x07", 8, 512)); // one byte: the proportion test is skipped
        // a window above 65536 clamps to it instead of being refused
        $bytes = '';
        for ($i = 0; $i < 70000; $i++) {
            $bytes .= chr(($i * 7 + intdiv($i, 3)) & 0xff);
        }
        self::assertArrayHasKey('ok', Entropy::healthTestBytes($bytes, 8, 100000));
    }

    public function testTheProportionTestStillCatchesABiasedWindow(): void
    {
        // 512 bytes whose first byte repeats far past the cutoff (13) without a run of the repetition-count length
        $w = '';
        for ($i = 0; $i < 512; $i++) {
            $w .= $i % 2 === 0 ? "\x00" : chr(1 + ($i % 250));
        }
        self::assertSame(['ok' => false, 'test' => 'adaptive-proportion'], Entropy::healthTestBytes($w, 8, 512));
    }
}
