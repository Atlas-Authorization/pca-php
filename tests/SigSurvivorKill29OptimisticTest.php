<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Optimistic;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for Optimistic::verifyClaim (every refusal reason, the ok verdict, the wall-clock default) and validateWindow. */
final class SigSurvivorKill29OptimisticTest extends TestCase
{
    private const POLICY_NO_SKEW = ['minWindowMs' => 1000, 'maxWindowMs' => 86_400_000, 'defaultWindowMs' => 300_000, 'maxSkewMs' => 0];

    protected function tearDown(): void
    {
        Optimistic::$clockHook = null;
    }

    private static function pcactn(): Obj
    {
        return Obj::of(['action' => 'transfer', 'n' => new Num('1')]);
    }

    /** An unsigned claim over pcactn() issued at `$issuedAt` with a 60 s window. */
    private static function claim(string $issuedAt = '1000'): Obj
    {
        return Obj::of(['pcactn_digest' => Pca::hashCanonical(self::pcactn()), 'claimed_r' => new Num('0.5'),
            'issued_at' => new Num($issuedAt), 'challenge_window_ms' => new Num('60000')]);
    }

    /** @return array{0:Obj,1:string} the claim signed under a fixed key, and that key (base64url) */
    private static function signed(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca-conformance/g29-optimistic', true));
        $c = self::claim();
        $sig = sodium_crypto_sign_detached(Optimistic::CLAIM_DOMAIN . Json::canonicalizeLenient($c), sodium_crypto_sign_secretkey($kp));
        $c->set('sig', Pca::b64u($sig));
        return [$c, Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    /** A claim signed under the key, covering this PCActn, inside the window, verifies with exactly ['ok' => true]. */
    public function testASoundClaimVerifies(): void
    {
        [$c, $pk] = self::signed();
        $this->assertSame(['ok' => true], Optimistic::verifyClaim($c, self::pcactn(), $pk, new Num('1000')));
        $this->assertSame(['ok' => true], Optimistic::verifyClaim($c, self::pcactn(), $pk, 1000));
        $c->set('claimed_r', new Num('0.6')); // the signature no longer covers the body
        $this->assertSame(['ok' => false, 'reason' => 'claim signature does not verify'], Optimistic::verifyClaim($c, self::pcactn(), $pk, 1000));
    }

    /** Every failing check maps to its own reason, with ok false. */
    public function testEachRefusalHasItsReason(): void
    {
        [, $pk] = self::signed();
        $v = static fn (mixed $c): array => Optimistic::verifyClaim($c, self::pcactn(), $pk, 1000);
        $this->assertSame(['ok' => false, 'reason' => 'malformed claim'], $v('not a claim'));
        $irr = self::claim();
        $irr->set('reversibility_class', Optimistic::IRREVERSIBLE_CLASS);
        $this->assertSame(['ok' => false, 'reason' => 'irreversible action is ineligible for the optimistic path'], $v($irr));
        $dg = self::claim();
        $dg->set('pcactn_digest', 'another');
        $this->assertSame(['ok' => false, 'reason' => 'claim does not cover this PCActn'], $v($dg));
        $this->assertSame(['ok' => false, 'reason' => 'claimed_r is not finite'], $v(self::claim()->without('claimed_r')));
        $this->assertSame(['ok' => false, 'reason' => 'claim signature does not verify'], $v(self::claim()));
        $this->assertSame(['ok' => false, 'reason' => 'issued_at is outside the allowed skew of server time'], $v(self::claim('900000')));
        $short = self::claim();
        $short->set('challenge_window_ms', new Num('999'));
        $this->assertSame(['ok' => false, 'reason' => 'challenge window is below the minimum'], $v($short));
    }

    /** A PCActn that cannot be hashed is a refusal naming the cause, never a throw. */
    public function testAnUnhashablePcactnIsAVerificationError(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'claim verification error: non-finite number'],
            Optimistic::verifyClaim(self::claim(), INF, 'pk', 1000));
    }

    /** With no server time, the clock is read in whole milliseconds rounded down (floor of seconds x 1000). */
    public function testTheDefaultClockIsFlooredMilliseconds(): void
    {
        // 1 + 2^-10 s = 1000.9765625 ms exactly: floor 1000 sits on issued_at with zero skew; 999, 1001 or 0 ms would not
        Optimistic::$clockHook = static fn (): float => 1.0009765625;
        $this->assertSame(['ok' => false, 'reason' => 'claim signature does not verify'],
            Optimistic::verifyClaim(self::claim('1000'), self::pcactn(), 'pk', null, self::POLICY_NO_SKEW));
        $this->assertSame(['ok' => false, 'reason' => 'issued_at is outside the allowed skew of server time'],
            Optimistic::verifyClaim(self::claim('1001'), self::pcactn(), 'pk', null, self::POLICY_NO_SKEW));
        // an explicit server time wins over the clock
        $this->assertSame(['ok' => false, 'reason' => 'claim signature does not verify'],
            Optimistic::verifyClaim(self::claim('1001'), self::pcactn(), 'pk', 1001, self::POLICY_NO_SKEW));
    }

    /** Without the seam the real wall clock is read: a claim issued at epoch 1 s is far outside the skew. */
    public function testTheWallClockIsReadWithoutTheSeam(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'issued_at is outside the allowed skew of server time'],
            Optimistic::verifyClaim(self::claim('1000'), self::pcactn(), 'pk'));
    }

    /** validateWindow is public and answers the first failing window check, or null. */
    public function testValidateWindow(): void
    {
        $this->assertNull(Optimistic::validateWindow(1000, 60000, 1000));
        $this->assertSame('challenge window exceeds the maximum', Optimistic::validateWindow(1000, 86_400_001, 1000));
        $this->assertSame('server time is not finite', Optimistic::validateWindow(1000, 60000, 'now'));
    }
}
