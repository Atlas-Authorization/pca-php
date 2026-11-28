<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcEndemicOt;
use Atlas\Pca\MpcEndemicOtAbort;
use Atlas\Pca\MpcLweLattice;
use Atlas\Pca\MpcOtRandom;
use PHPUnit\Framework\TestCase;

/**
 * Mutation kills for MpcEndemicOt: the wire validators (decided before any lattice work, so they run everywhere), the public helpers, and with
 * liblweot the index handling of keyed (non-list) inputs, the sender's own entropy and the transcript.
 */
final class SigSurvivorKill29MpcEndemicOtTest extends TestCase
{
    private function needLattice(): void
    {
        if (!MpcLweLattice::available()) {
            if (getenv('ATLAS_PCA_LIBLWEOT_REQUIRED') === '1') {
                $this->fail('liblweot must load (ATLAS_PCA_LIBLWEOT, ffi.enable=true)');
            }
            $this->markTestSkipped('needs ext-ffi and liblweot (ATLAS_PCA_LIBLWEOT)');
        }
    }

    private static function point(): array
    {
        return [str_repeat("\1", MpcLweLattice::TVEC_BYTES), str_repeat("\2", MpcLweLattice::TVEC_BYTES)];
    }

    private static function rho(): string
    {
        return str_repeat("\3", MpcLweLattice::PK_BYTES - MpcLweLattice::TVEC_BYTES);
    }

    private function refused(string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame(MpcEndemicOtAbort::class, $e::class, $e->getMessage());
            $this->assertSame($message, $e->getMessage());
            return;
        }
        $this->fail("expected: $message");
    }

    private function send(mixed $points, mixed $rhos): void
    {
        MpcEndemicOt::sendRandom(['rn' => str_repeat("\0", MpcLweLattice::SYM_BYTES), 'points' => $points, 'rhos' => $rhos]);
    }

    public function testThePublicHelpers(): void
    {
        $p = MpcEndemicOt::pad('sid', 0, 1, 'payload', 40);
        $this->assertSame(40, strlen($p));
        $this->assertSame(substr($p, 0, 32), MpcEndemicOt::pad('sid', 0, 1, 'payload', 32));
        $this->assertInstanceOf(\Closure::class, MpcEndemicOt::withEndemicBaseOt());
    }

    public function testTheSenderValidatesTheReceiverMessage(): void
    {
        $len = 'endemic LWE OT: points/rhos length mismatch';
        $this->refused($len, fn () => $this->send('x', []));
        $this->refused($len, fn () => $this->send([], [self::rho()]));
        $pair = 'endemic LWE OT: malformed point pair at index 0';
        $short = 'short';
        [$a, $b] = self::point();
        $this->refused($pair, fn () => $this->send([[$a, $short]], [self::rho()]));
        $this->refused($pair, fn () => $this->send([[$short, $b]], [self::rho()]));
        $this->refused($pair, fn () => $this->send([[$a, $b, $a]], [self::rho()]));
        $this->refused($pair, fn () => $this->send([5 => [$a, $short]], [self::rho()]));
        $this->refused('endemic LWE OT: malformed rho at index 0', fn () => $this->send([self::point()], ['short']));
    }

    public function testTheReceiverValidatesTheCiphertexts(): void
    {
        $state = ['choices' => [0], 'secretKeys' => ['x'], 'sid' => 'sid'];
        $ct = str_repeat("\4", MpcLweLattice::CT_BYTES);
        $msg = 'endemic LWE OT: malformed ciphertext pair at index 0';
        foreach ([[[$ct, 'short']], [['short', $ct]], [[$ct, $ct, $ct]], [5 => [$ct, 'short']]] as $cts) {
            $this->refused($msg, fn () => MpcEndemicOt::recoverRandom($state, ['ciphertexts' => $cts]));
        }
    }

    public function testBaseOtNeedsAChoicePerMessage(): void
    {
        try {
            MpcEndemicOt::baseOT([], [1]);
            $this->fail('expected a refusal');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('endemicBaseOT: messages/choices length mismatch', $e->getMessage());
        }
    }

    /** Keyed (non-list) inputs are read in order: index i is the i-th entry, never its key. */
    public function testKeyedInputsAreReadInOrder(): void
    {
        $this->needLattice();
        $r = MpcEndemicOt::baseOT([7 => ['ab', 'cd']], [5 => 1]);
        $this->assertSame(['cd'], $r['received']);
        $this->assertSame(['rn', 'points', 'rhos', 'ciphertexts', 'encrypted', 'commitments'], array_keys($r['transcript']));

        $rv = MpcEndemicOt::receive([1]);
        $m = $rv['message'];
        $m['points'] = [5 => $m['points'][0]];
        $m['rhos'] = [9 => $m['rhos'][0]];
        $sm = MpcEndemicOt::sendRandom($m);
        $sm['ciphertexts'] = [3 => $sm['ciphertexts'][0]];
        $this->assertSame([$sm['senderPads'][0][1]], MpcEndemicOt::recoverRandom($rv['state'], $sm));
    }

    /** The sender draws from its own generator, and a given generator is used, not replaced. */
    public function testTheGeneratorsAreTheOnesGiven(): void
    {
        $this->needLattice();
        $seed = static fn (int $s): MpcOtRandom => MpcOtRandom::fromSeed(gmp_init($s));
        $a = MpcEndemicOt::baseOT([['ab', 'cd']], [0], $seed(1), $seed(2))['transcript']['ciphertexts'];
        $b = MpcEndemicOt::baseOT([['ab', 'cd']], [0], $seed(1), $seed(3))['transcript']['ciphertexts'];
        $this->assertNotSame($a, $b, 'the sender randomness comes from senderRng');
        $this->assertSame(MpcEndemicOt::baseOtRandom([1], $seed(4))['senderPads'], MpcEndemicOt::baseOtRandom([1], $seed(4))['senderPads']);
    }
}
