<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcOtChannel;
use Atlas\Pca\MpcOtRandom;
use Atlas\Pca\MpcShake256;
use PHPUnit\Framework\TestCase;

/**
 * Group 34 kills for MpcOtChannel, over an ideal pluggable base OT (each choice picks its seed) so no curve library is needed (the KOS
 * check needs SHAKE256): the caller's binding is used as given, setup on first use, the extension delivers the chosen messages, and a
 * refused extend leaves the channel usable.
 */
final class MpcSurvivorKill34MpcOtChannelTest extends TestCase
{
    private const BINDING = ['sessionId' => 'mpc34-ot-channel', 'senderIndex' => 0, 'receiverIndex' => 1];

    private function needShake(): void
    {
        if (!MpcShake256::available()) {
            $this->markTestSkipped('the KOS check needs SHAKE256 (ext-ffi + libcrypto)');
        }
    }

    private static function idealBaseOt(): \Closure
    {
        return static fn(array $m, array $c, MpcOtRandom $r): array => array_map(static fn(array $pair, int $ci): string => $pair[$ci], $m, $c);
    }

    /** @return list<\GMP> */
    private static function g(int ...$v): array
    {
        return array_map(static fn(int $x): \GMP => gmp_init($x), $v);
    }

    /**
     * A supplied binding draws no randomness for a session id: the stream after a manual 16-byte draw then matches a channel that had
     * to draw its own binding (the selector, the first secret the setup draws, comes out the same). selector() also runs the setup.
     */
    public function testASuppliedBindingDrawsNoRandomBinding(): void
    {
        $own = new MpcOtChannel(MpcOtRandom::fromSeed(gmp_init(34)), self::idealBaseOt());
        $rng = MpcOtRandom::fromSeed(gmp_init(34));
        $rng->bytes(16);
        $given = new MpcOtChannel($rng, self::idealBaseOt(), self::BINDING);
        $sel = $own->selector();
        $this->assertInstanceOf(\GMP::class, $sel);
        $this->assertSame(gmp_strval($sel), gmp_strval($given->selector()));
        $this->assertSame(gmp_strval($sel), gmp_strval($own->selector()), 'setup runs once');
    }

    /** extend delivers m_c for every row and refuses a msg1 list of another length with the exact reason. */
    public function testExtendDeliversTheChosenMessages(): void
    {
        $this->needShake();
        $ch = new MpcOtChannel(MpcOtRandom::fromSeed(gmp_init(7)), self::idealBaseOt(), self::BINDING);
        $this->assertSame(['10', '21', '30'], array_map('gmp_strval', $ch->extend([0, 1, 0], self::g(10, 20, 30), self::g(11, 21, 31))['received']));
        try {
            $ch->extend([0, 1], self::g(1, 2), self::g(3));
            $this->fail('a short msg1 must be refused');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('OtChannel.extend: length mismatch', $e->getMessage());
        }
    }

    /** A message outside [0, 2^64) is refused before either side moves, so the next extend still passes the KOS check and delivers. */
    public function testARefusedMessageLeavesTheChannelInStep(): void
    {
        $this->needShake();
        $ch = new MpcOtChannel(MpcOtRandom::fromSeed(gmp_init(9)), self::idealBaseOt(), self::BINDING);
        try {
            $ch->extend([1], self::g(-1), self::g(0));
            $this->fail('a negative message must be refused');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('OtChannel.extend: message 0 must be a bigint in [0, 2^64) (the pad is 64 bits wide)', $e->getMessage());
        }
        $this->assertSame(['6'], array_map('gmp_strval', $ch->extend([1], self::g(5), self::g(6))['received']));
    }
}
