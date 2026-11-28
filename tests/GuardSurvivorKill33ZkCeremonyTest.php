<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ZkCeremony.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\ZkCeremony;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/ZkCeremony.php: member equality (numbers, null, absent, lists), the safe-integer bound, a NaN minimum and a falsy key. */
final class GuardSurvivorKill33ZkCeremonyTest extends TestCase
{
    private static function h(string $c): string
    {
        return str_repeat($c, 64);
    }

    /** prov / expect with the given circuit members (null = leave it out), everything else matching. */
    private static function check(array $circuit): ?string
    {
        $prov = ['sourceSha256' => self::h('1'), 'r1csSha256' => self::h('2'), 'vkId' => ZkCeremony::vkId('K')];
        $exp = ['sourceSha256' => self::h('1'), 'vkey' => 'K'];
        if ($circuit !== []) {
            $prov['circuit'] = $circuit[0];
            $exp['circuit'] = $circuit[1];
        }
        return ZkCeremony::checkCircuitProvenance(Obj::of($prov), Obj::of($exp));
    }

    /** Equal numbers, two nulls and two absent members are the same circuit; equal lists are not (an object equals nothing). */
    public function testCircuitEquality(): void
    {
        $this->assertNull(self::check(['c', 'c']), 'control');
        $this->assertNull(self::check([new Num('5'), new Num('5')]));
        $this->assertNull(self::check([null, null]));
        $this->assertNull(self::check([]));
        $this->assertSame('record is for another circuit', self::check([['x'], ['x']]));
        $this->assertSame('record is for another circuit', self::check([new Num('5'), '5']));
    }

    /** A valid two-contribution transcript (or one with `$n` contributions) naming `$vkey`. */
    private static function transcript(mixed $vkey, int $n = 2, array $over = []): Obj
    {
        $cs = [];
        $prev = self::h('3');
        for ($i = 0; $i < $n; $i++) {
            $key = self::h((string)(4 + $i));
            $cs[] = Obj::of(['index' => new Num((string)$i), 'name' => "p$i", 'prevZkeySha256' => $prev, 'zkeySha256' => $key]);
            $prev = $key;
        }
        return Obj::of($over + ['version' => new Num('1'), 'circuit' => 'c', 'curve' => 'bn128', 'r1csSha256' => self::h('1'), 'ptauSha256' => self::h('2'),
            'initZkeySha256' => self::h('3'), 'contributions' => $cs,
            'beacon' => Obj::of(['hashHex' => self::h('a'), 'iterationsExp' => new Num('10'), 'prevZkeySha256' => $prev, 'zkeySha256' => self::h('b')]),
            'finalZkeySha256' => self::h('b'), 'vkId' => ZkCeremony::vkId($vkey)]);
    }

    /** A transcript minimum of 2^53 - 1 is a safe integer and applies. */
    public function testLargestSafeMinimumApplies(): void
    {
        $this->assertNull(ZkCeremony::checkTranscript(self::transcript('K')), 'control');
        $r = ZkCeremony::checkTranscript(self::transcript('K', 2, ['minContributions' => new Num('9007199254740991')]));
        $this->assertIsString($r);
        $this->assertStringStartsWith('fewer than ', $r);
    }

    /** A NaN caller minimum makes the minimum NaN (as Math.max does), whatever the transcript asks: the count check passes. */
    public function testNanMinimumIsSticky(): void
    {
        $this->assertNull(ZkCeremony::checkTranscript(self::transcript('K', 2, ['minContributions' => new Num('3')]), ['minContributions' => NAN]));
        $this->assertSame('fewer than 3 contributions', ZkCeremony::checkTranscript(self::transcript('K', 2, ['minContributions' => new Num('3')])), 'control');
    }

    /** A falsy verifying key is single-party even when a transcript names it. */
    public function testFalsyKeyIsSingleParty(): void
    {
        $ev = static fn(Obj $t): Obj => Obj::of(['transcript' => $t, 'sha256' => ZkCeremony::transcriptSha256($t)]);
        $this->assertSame('multi-party', ZkCeremony::ceremonyOf('K', $ev(self::transcript('K'))), 'control');
        $this->assertSame('single-party', ZkCeremony::ceremonyOf('', $ev(self::transcript(''))));
    }
}
