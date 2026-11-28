<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcMalOtAbort;
use Atlas\Pca\MpcOt;
use Atlas\Pca\MpcOtExtSender;
use Atlas\Pca\MpcOtRandom;
use PHPUnit\Framework\TestCase;

/** Group 34 kills for MpcOtExtSender: the base-OT size and readiness checks, and the KOS shape refusals of a receiver message. */
final class MpcSurvivorKill34MpcOtExtSenderTest extends TestCase
{
    private static function sender(bool $ready): MpcOtExtSender
    {
        $s = new MpcOtExtSender(MpcOtRandom::fromSeed(gmp_init(34)), 'mpc34-kos-binding');
        if ($ready) {
            $s->makeSelector();
            $s->setSeeds(array_fill(0, MpcOt::KAPPA, str_repeat("\0", MpcOt::SEED_BYTES)));
        }
        return $s;
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame($class, $e::class, $e->getMessage());
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("expected $class: $msg");
    }

    /** Seeds are refused unless there are exactly kappa of them for a drawn selector; respond before that is a logic error. */
    public function testBaseOtSizeAndReadiness(): void
    {
        self::refuses(\LogicException::class, 'OtExtSender: wrong base-OT output size', static fn() => self::sender(false)->setSeeds([]));
        $s = self::sender(false);
        $s->makeSelector();
        self::refuses(\LogicException::class, 'OtExtSender: wrong base-OT output size', static fn() => $s->setSeeds(array_fill(0, MpcOt::KAPPA - 1, 'x')));
        self::refuses(\LogicException::class, 'OtExtSender: base OT not done', static fn() => self::sender(false)->respond(['u' => [], 'x' => gmp_init(0), 'tComb' => gmp_init(0)], [], []));
        $this->assertTrue(self::sender(true)->ready);
    }

    /** A msg1 list of another length, a u matrix without kappa columns, and a missing x are refused with their exact reasons (round 0). */
    public function testRespondShapeRefusals(): void
    {
        $zero = gmp_init(0);
        $u = array_fill(0, MpcOt::KAPPA, $zero);
        self::refuses(\InvalidArgumentException::class, 'OtChannel.extend: length mismatch', static fn() => self::sender(true)->respond(['u' => $u, 'x' => $zero, 'tComb' => $zero], [gmp_init(1)], []));
        $cheat = 'a cheating OT-extension receiver was detected; aborting';
        self::refuses(MpcMalOtAbort::class, "KOS check (round 0): wrong number of u columns; $cheat", static fn() => self::sender(true)->respond(['u' => [], 'x' => $zero, 'tComb' => $zero], [gmp_init(1)], [gmp_init(2)]));
        self::refuses(MpcMalOtAbort::class, "KOS check (round 0): wrong number of u columns; $cheat", static fn() => self::sender(true)->respond(['u' => null, 'x' => $zero, 'tComb' => $zero], [gmp_init(1)], [gmp_init(2)]));
        self::refuses(MpcMalOtAbort::class, "KOS check (round 0): malformed (x, t); $cheat", static fn() => self::sender(true)->respond(['u' => $u, 'x' => null, 'tComb' => $zero], [gmp_init(1)], [gmp_init(2)]));
    }
}
