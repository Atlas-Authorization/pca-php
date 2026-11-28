<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcMalOtAbort;
use Atlas\Pca\MpcOtExtReceiver;
use Atlas\Pca\MpcOtRandom;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcOtExtReceiver: no round before the base OT, the zero KOS values sent with a u matrix that is out of range, and the
 * ciphertext count check of finish.
 */
final class MpcSurvivorKill34MpcOtExtReceiverTest extends TestCase
{
    private static function receiver(): MpcOtExtReceiver
    {
        return new MpcOtExtReceiver(MpcOtRandom::fromSeed(gmp_init(34)), 'mpc34-kos-binding');
    }

    /** begin before the seeds exist is a logic error. */
    public function testBeginNeedsTheBaseOt(): void
    {
        try {
            self::receiver()->begin([0]);
            $this->fail('begin must need the base OT');
        } catch (\LogicException $e) {
            $this->assertSame(\LogicException::class, $e::class);
            $this->assertSame('OtExtReceiver: base OT not done', $e->getMessage());
        }
    }

    /** A u matrix pushed out of range (a cheating receiver) goes out with x = tComb = 0 and the same three keys, no KOS work. */
    public function testOutOfRangeUSendsZeroKosValues(): void
    {
        $r = self::receiver();
        $r->makeSeeds();
        $r->tamperU = static function (array $u, int $round): array {
            $u[0] = gmp_init(-1);
            return $u;
        };
        $b = $r->begin([1, 0]);
        $this->assertSame(['u', 'x', 'tComb'], array_keys($b['msg']));
        $this->assertSame('-1', gmp_strval($b['msg']['u'][0]));
        $this->assertSame('0', gmp_strval($b['msg']['x']));
        $this->assertSame('0', gmp_strval($b['msg']['tComb']));
        $this->assertSame(2, $b['pending']['m']);
    }

    /** finish aborts when the sender's ciphertext lists do not have one entry per row. */
    public function testFinishChecksTheCiphertextCount(): void
    {
        $pending = ['m' => 1, 'choiceBits' => [0], 't' => [], 'W' => 0, 'rowOffset' => 0];
        foreach ([[[], [gmp_init(1)]], [[gmp_init(1)], []]] as [$y0, $y1]) {
            try {
                self::receiver()->finish($pending, $y0, $y1);
                $this->fail('a ciphertext count mismatch must abort');
            } catch (MpcMalOtAbort $e) {
                $this->assertSame('OT extension: ciphertext count does not match the number of rows; aborting', $e->getMessage());
            }
        }
    }
}
