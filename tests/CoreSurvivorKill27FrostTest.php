<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Frost.php';

use Atlas\Pca\Frost;
use Atlas\Pca\FrostNonces;
use PHPUnit\Framework\TestCase;

/** FROST refusal paths: scalar/point guards, commitment-list rules, signing input checks, one-shot nonce bookkeeping, aggregation and cosign checks. */
final class CoreSurvivorKill27FrostTest extends TestCase
{
    private static function throws(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [get_class($e), $e->getMessage()];
        }
        return ['none', ''];
    }

    private static function kg(int $t, int $n): array
    {
        static $cache = [];
        return $cache["$t/$n"] ??= Frost::trustedDealerKeygen($t, $n);
    }

    /** y = 2 has no x on the curve: not a point. */
    private static function offCurve(): string
    {
        return "\x02" . str_repeat("\0", 31);
    }

    private static function base(): string
    {
        return "\x58" . str_repeat("\x66", 31);
    }

    private static function nonces(array $c): FrostNonces
    {
        return new FrostNonces($c['hidingNonce'], $c['bindingNonce']);
    }

    /** Scalar and point helpers refuse what they cannot use with their own messages. */
    public function testScalarAndPointRefusals(): void
    {
        $this->assertSame([\TypeError::class, 'frost: expected bytes'], self::throws(static fn() => Frost::bytesToScalar(5)));
        $this->assertSame([\InvalidArgumentException::class, 'frost: scalar input longer than 64 bytes'], self::throws(static fn() => Frost::bytesToScalar(str_repeat('a', 65))));
        $this->assertSame([\RuntimeException::class, 'frost: point multiplication refused'], self::throws(static fn() => Frost::mulPoint(self::offCurve(), Frost::scalarOfId(2))));
        $this->assertSame([\RuntimeException::class, 'frost: point addition refused'], self::throws(static fn() => Frost::add(self::offCurve(), self::base())));
        $this->assertSame([\InvalidArgumentException::class, 'frost: point must be 32 bytes'], self::throws(static fn() => Frost::decodeSafePoint('x')));
        $kg = self::kg(1, 1);
        $p = $kg['participantShares'][0];
        $c = Frost::commit($p);
        $this->assertSame([\InvalidArgumentException::class, 'frost: participant identifier must be a positive safe integer'],
            self::throws(static fn() => Frost::sign(0, $p['share'], $kg['groupPublicKey'], self::nonces($c), 'm', [$c['commitment']])));
    }

    /** Aggregation refuses an empty, short or duplicated commitment list and shares that do not pair one-to-one with the signers. */
    public function testAggregateListRules(): void
    {
        $kg = self::kg(1, 1);
        $gpk = $kg['groupPublicKey'];
        $cm = Frost::commit($kg['participantShares'][0])['commitment'];
        $ia = \InvalidArgumentException::class;
        $this->assertSame([\TypeError::class, 'frost: expected bytes'], self::throws(static fn() => Frost::aggregate(5, [$cm], [], $gpk)));
        $this->assertSame([$ia, 'frost: empty commitment list'], self::throws(static fn() => Frost::aggregate('m', [], [], $gpk)));
        $this->assertSame([$ia, 'frost: need at least t=2 commitments (got 1)'], self::throws(static fn() => Frost::aggregate('m', [$cm], [], $gpk, 2)));
        $this->assertSame([$ia, 'frost: duplicate commitment identifier 1'], self::throws(static fn() => Frost::aggregate('m', [$cm, $cm], [], $gpk)));
        $this->assertSame([$ia, 'frostAggregate: need exactly one signature share per commitment'], self::throws(static fn() => Frost::aggregate('m', [$cm], [], $gpk)));
        $z = str_repeat("\0", 32);
        $this->assertSame([$ia, 'frostAggregate: share from non-signer'], self::throws(static fn() => Frost::aggregate('m', [$cm], [['identifier' => 2, 'sigShare' => $z]], $gpk)));
        $k2 = self::kg(2, 2);
        $cs = [Frost::commit($k2['participantShares'][0])['commitment'], Frost::commit($k2['participantShares'][1])['commitment']];
        $this->assertSame([$ia, 'frostAggregate: duplicate signature share'],
            self::throws(static fn() => Frost::aggregate('m', $cs, [['identifier' => 1, 'sigShare' => $z], ['identifier' => 1, 'sigShare' => $z]], $k2['groupPublicKey'])));
    }

    /** Shares that verify against their verification shares but not under the stated group key never aggregate into a signature. */
    public function testAggregateRefusesASignatureThatDoesNotVerify(): void
    {
        $a = self::kg(1, 1)['participantShares'][0];
        $gpkB = Frost::trustedDealerKeygen(1, 1)['groupPublicKey'];
        $c = Frost::commit($a);
        $share = Frost::sign(1, $a['share'], $gpkB, self::nonces($c), 'm', [$c['commitment']]);
        $this->assertSame([\InvalidArgumentException::class, 'frostAggregate: aggregate signature does not verify (a share is invalid)'],
            self::throws(static fn() => Frost::aggregate('m', [$c['commitment']], [$share], $gpkB, null, [['identifier' => 1, 'publicKey' => $a['publicKey']]])));
    }

    /** Signing refuses non-bytes inputs, a zero nonce, equal nonces and an own commitment that does not match either nonce. */
    public function testSignInputRefusals(): void
    {
        $kg = self::kg(1, 1);
        $p = $kg['participantShares'][0];
        $gpk = $kg['groupPublicKey'];
        $c = Frost::commit($p);
        $cm = $c['commitment'];
        $ia = \InvalidArgumentException::class;
        $this->assertSame([\TypeError::class, 'frost: expected bytes'], self::throws(static fn() => Frost::sign(1, 5, $gpk, self::nonces($c), 'm', [$cm])));
        $this->assertSame([\TypeError::class, 'frost: expected bytes'], self::throws(static fn() => Frost::sign(1, $p['share'], $gpk, self::nonces($c), 5, [$cm])));
        $this->assertSame([$ia, 'frostSign: zero/zeroized nonce (one-shot; reuse would leak the signing share)'],
            self::throws(static fn() => Frost::sign(1, $p['share'], $gpk, new FrostNonces(str_repeat("\0", 32), $c['bindingNonce']), 'm', [$cm])));
        $this->assertSame([$ia, 'frostSign: hiding and binding nonce must differ'],
            self::throws(static fn() => Frost::sign(1, $p['share'], $gpk, new FrostNonces($c['hidingNonce'], $c['hidingNonce']), 'm', [$cm])));
        $other = Frost::commit($p)['commitment'];
        $this->assertSame([$ia, 'frostSign: own commitment does not match nonces'],
            self::throws(static fn() => Frost::sign(1, $p['share'], $gpk, self::nonces($c), 'm', [['identifier' => 1, 'hiding' => $cm['hiding'], 'binding' => $other['hiding']]])));
    }

    /** A share wipes its nonces to 32 zero bytes, and a commitment whose hiding OR binding point was already used is refused. */
    public function testNoncesAreOneShot(): void
    {
        $kg = self::kg(1, 1);
        $p = $kg['participantShares'][0];
        $gpk = $kg['groupPublicKey'];
        $hr = random_bytes(32);
        $c1 = Frost::commit($p, $hr, random_bytes(32));
        $n = self::nonces($c1);
        Frost::sign(1, $p['share'], $gpk, $n, 'm', [$c1['commitment']]);
        $this->assertSame([str_repeat("\0", 32), str_repeat("\0", 32)], [$n->hiding, $n->binding]);
        $used = [\InvalidArgumentException::class, 'frostSign: nonces already used (one-shot; reuse would leak the signing share)'];
        $this->assertSame($used, self::throws(static fn() => Frost::sign(1, $p['share'], $gpk, self::nonces($c1), 'm', [$c1['commitment']])));
        $c2 = Frost::commit($p, $hr, random_bytes(32));
        $this->assertSame($c1['commitment']['hiding'], $c2['commitment']['hiding']);
        $this->assertSame($used, self::throws(static fn() => Frost::sign(1, $p['share'], $gpk, self::nonces($c2), 'm', [$c2['commitment']])));
    }

    /** The verification share for an identifier is the FIRST entry naming it. */
    public function testVerificationShareLookupUsesTheFirstMatch(): void
    {
        $kg = self::kg(1, 1);
        $p = $kg['participantShares'][0];
        $c = Frost::commit($p);
        $s = Frost::sign(1, $p['share'], $kg['groupPublicKey'], self::nonces($c), 'm', [$c['commitment']],
            ['verificationShares' => [['identifier' => 1, 'publicKey' => $p['publicKey']], ['identifier' => 1, 'publicKey' => self::base()]]]);
        $this->assertSame(1, $s['identifier']);
    }

    /** The spent set holds at most SPENT_COMMITMENT_CAP keys and evicts only the oldest one once that is exceeded. */
    public function testSpentSetCap(): void
    {
        $this->assertSame(262144, Frost::SPENT_COMMITMENT_CAP);
        $prop = new \ReflectionProperty(Frost::class, 'spent');
        $saved = $prop->getValue();
        $fill = [];
        for ($i = 0; $i < Frost::SPENT_COMMITMENT_CAP - 1; $i++) {
            $fill["f$i"] = true;
        }
        $prop->setValue(null, $fill);
        unset($fill);
        try {
            $kg = self::kg(1, 1);
            $p = $kg['participantShares'][0];
            $c = Frost::commit($p);
            Frost::sign(1, $p['share'], $kg['groupPublicKey'], self::nonces($c), 'm', [$c['commitment']]);
            $after = $prop->getValue();
            $this->assertSame([Frost::SPENT_COMMITMENT_CAP, false, true], [count($after), isset($after['f0']), isset($after['f1'])]);
        } finally {
            $prop->setValue(null, $saved);
        }
    }

    /** A share check over a malformed signing set is false, never an acceptance. */
    public function testVerifySigShareMalformedIsFalse(): void
    {
        $kg = self::kg(1, 1);
        $this->assertFalse(Frost::verifySigShare(1, $kg['participantShares'][0]['publicKey'], [], [], 'x', $kg['groupPublicKey'], 'm'));
    }

    /** cosign refuses an empty or short quorum and a duplicate participant; a whole-number float threshold is a threshold. */
    public function testCosignRules(): void
    {
        $k1 = self::kg(1, 1);
        $k2 = self::kg(2, 2);
        $p = $k1['participantShares'][0];
        $ia = \InvalidArgumentException::class;
        $this->assertSame([$ia, 'frostCosign: empty signing quorum'], self::throws(static fn() => Frost::cosign($k1['groupPublicKey'], [], 'm')));
        $this->assertSame([$ia, 'frostCosign: quorum of 1 is below the threshold t=2'], self::throws(static fn() => Frost::cosign($k2['groupPublicKey'], [$k2['participantShares'][0]], 'm', 2)));
        $this->assertSame([$ia, 'frostCosign: duplicate participant 1 in quorum'], self::throws(static fn() => Frost::cosign($k1['groupPublicKey'], [$p, $p], 'm')));
        $sig = Frost::cosign($k1['groupPublicKey'], [$p], 'm', 1.0);
        $this->assertTrue(sodium_crypto_sign_verify_detached($sig, 'm', $k1['groupPublicKey']));
    }
}
