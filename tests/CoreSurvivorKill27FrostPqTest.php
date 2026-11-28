<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/FrostPq.php';

use Atlas\Pca\Frost;
use Atlas\Pca\FrostPq;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\TestCase;

/** FROST post-quantum companions: signer-set refusals, hybrid co-sign refusals and verdict reasons, PQ quorum block shape and entry rules. */
final class CoreSurvivorKill27FrostPqTest extends TestCase
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

    private static function pq(string $label): PqKeyPair
    {
        return new PqKeyPair('ML-DSA-65', hash('sha256', 'atlas-pca-conformance/k27-frost-pq/' . $label, true));
    }

    /** A plain Ed25519 key stands in for the group key: its signature is what the FROST aggregate is. */
    private static function ed(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca-conformance/k27-frost-pq/ed', true));
        return [Pca::b64u(sodium_crypto_sign_publickey($kp)), Pca::b64u(sodium_crypto_sign_detached('m', sodium_crypto_sign_secretkey($kp)))];
    }

    /** A non-list signer set and an identifier that is not a number are refused as RangeErrors. */
    public function testSignerSetRefusals(): void
    {
        $this->assertSame([\RangeException::class, 'frostSignerSetDigest: empty signer set'], self::throws(static fn() => FrostPq::signerSetDigest('x')));
        $this->assertSame([\RangeException::class, 'frostSignerSetDigest: participant identifiers must be positive safe integers'], self::throws(static fn() => FrostPq::signerSetDigest(['x'])));
    }

    /** Signing refuses an unknown group algorithm, and a hybrid one without a guardian ML-DSA key pair. */
    public function testSignHybridRefusals(): void
    {
        $kg = Frost::trustedDealerKeygen(1, 1);
        $q = $kg['participantShares'];
        $this->assertSame([\RangeException::class, "signHybridFrostCosign: unknown groupAlg 'x'"],
            self::throws(static fn() => FrostPq::signHybridCosign($kg['groupPublicKey'], $q, 'm', ['groupAlg' => 'x'])));
        $this->assertSame([\TypeError::class, "signHybridFrostCosign: 'hybrid-ed25519-ml-dsa-65' requires a guardian ML-DSA-65 key pair"],
            self::throws(static fn() => FrostPq::signHybridCosign($kg['groupPublicKey'], $q, 'm', ['groupAlg' => FrostPq::HYBRID_GROUP_ALG])));
    }

    /** Each verify refusal names its reason: unknown algorithms (artifact and expected), a malformed registered key, and which half failed. */
    public function testVerifyHybridReasons(): void
    {
        [$gpk, $sig] = self::ed();
        $h = FrostPq::HYBRID_GROUP_ALG;
        $reason = static fn(array $r): mixed => [$r['ok'], $r['reason'] ?? null];
        $this->assertSame([false, "unknown groupAlg 'zz'"], $reason(FrostPq::verifyHybridCosign(Obj::of(['sig' => $sig, 'groupAlg' => 'zz']), 'm', $gpk, [1])));
        $this->assertSame([false, "unknown expected groupAlg 'zz'"],
            $reason(FrostPq::verifyHybridCosign(Obj::of(['sig' => $sig]), 'm', $gpk, [1], Obj::of(['expectGroupAlg' => 'zz']))));
        $this->assertSame([false, 'hybrid groupAlg requires a registered guardian ML-DSA-65 public key'],
            $reason(FrostPq::verifyHybridCosign(Obj::of(['sig' => $sig, 'groupAlg' => $h, 'pq_sig' => 'AAAA']), 'm', $gpk, [1], Obj::of(['guardianPqPublicKey' => 'x']))));
        $r = FrostPq::verifyHybridCosign(Obj::of(['sig' => $sig, 'groupAlg' => $h, 'pq_sig' => 'AAAA']), 'm', $gpk, [1], Obj::of(['guardianPqPublicKey' => self::pq('g')->public]));
        $this->assertSame([false, true, false, 'guardian ML-DSA-65 co-signature did not verify'], [$r['ok'], $r['edOk'], $r['pqOk'], $r['reason']]);
    }

    /** A block that is not an object, lacks a version, is version 1 or has a non-number version is refused with its own reason. */
    public function testPqBlockVersions(): void
    {
        $reason = static fn(mixed $b): mixed => FrostPq::verifyPqQuorum($b, 'm', [], 1)['reason'] ?? null;
        $this->assertSame('malformed pq block', $reason('x'));
        $this->assertSame('pq quorum version missing (pre-0.5 format is refused)', $reason(new Obj()));
        $this->assertSame('pq quorum version 1 is no longer accepted (pre-0.5 format)', $reason(Obj::of(['v' => 1])));
        $this->assertSame('unsupported pq quorum version', $reason(Obj::of(['v' => 'x'])));
    }

    /** A non-object entry never counts; a short quorum says how many of how many. */
    public function testPqQuorumShortReason(): void
    {
        $k = self::pq('q1');
        $block = FrostPq::signPqQuorum('m', [$k]);
        $entry = $block->get('signers')[0];
        $pool = [$k->public];
        $this->assertTrue(FrostPq::verifyPqQuorum($block, 'm', $pool, 1)['ok']);
        $asArray = Obj::of(['v' => 2, 'alg' => 'ml-dsa-65', 'signers' => [['pk' => $entry->get('pk'), 'sig' => $entry->get('sig')]]]);
        $this->assertSame(['ok' => false, 'count' => 0, 'need' => 1, 'reason' => 'post-quantum quorum short: 0 of 1 required ML-DSA co-signatures'],
            FrostPq::verifyPqQuorum($asArray, 'm', $pool, 1));
    }
}
