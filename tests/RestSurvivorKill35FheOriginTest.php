<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\FheOrigin;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the signed FHE risk claim and verdict attestation (no SEAL needed). */
final class RestSurvivorKill35FheOriginTest extends TestCase
{
    private const SEED = "\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07\x07";

    private static function refusal(\Closure $f): string
    {
        try {
            $f();
        } catch (\InvalidArgumentException $e) {
            return $e->getMessage();
        }
        return 'no refusal';
    }

    /** A signing key that is not a 32-byte seed and an empty context are refused with their reasons. */
    public function testSigningRefusals(): void
    {
        $claim = Obj::of(['binding' => new Obj(), 'policy' => new Obj(), 'encInputs' => 'x']);
        $this->assertSame('signing key must be a 32-byte Ed25519 secret key', self::refusal(static fn() => FheOrigin::signRiskClaim($claim, 'short', 'c', str_repeat("\x01", 16))));
        $this->assertSame('context must be a non-empty string of at most 512 characters', self::refusal(static fn() => FheOrigin::signRiskClaim($claim, self::SEED, '', str_repeat("\x01", 16))));
    }

    /** A numeric ciphertext member is digested as its string form (the reference's utf8(String(x))), on signing and attesting. */
    public function testNumericBytesAreDigestedAsStrings(): void
    {
        $s = FheOrigin::signRiskClaim(Obj::of(['binding' => new Obj(), 'policy' => new Obj(), 'encInputs' => 5]), self::SEED, 'c', str_repeat("\x01", 16));
        $this->assertSame($s->get('sig'), FheOrigin::signRiskClaim(Obj::of(['binding' => new Obj(), 'policy' => new Obj(), 'encInputs' => '5']), self::SEED, 'c', str_repeat("\x01", 16))->get('sig'));
        $a = FheOrigin::attestVerdict(self::SEED, $s, Obj::of(['encRiskRaw' => 1, 'encSlack' => 2]), true);
        $r = FheOrigin::verifyVerdictAttestation($a, [$a->get('holder')], FheOrigin::signedClaimDigest($s), Obj::of(['encRiskRaw' => '1', 'encSlack' => 2]));
        $this->assertSame(['ok' => true, 'admit' => true], $r);
        $r = FheOrigin::verifyVerdictAttestation($a, [$a->get('holder')], FheOrigin::signedClaimDigest($s), Obj::of(['encRiskRaw' => 1, 'encSlack' => '2']));
        $this->assertSame(['ok' => true, 'admit' => true], $r);
    }

    /** A verified claim whose policy the gate refuses reports that refusal, after integer coefficients and a default kappa. */
    public function testEvaluationFailureReason(): void
    {
        $p = Obj::of(['scale' => new Num('0'), 'dim' => new Num('1'), 'weightsScaled' => [new Num('1')], 'kappaWeightsScaled' => [new Num('1')], 'budgetScaled' => new Num('1')]);
        $b = Obj::of(['a' => 1]);
        $s = FheOrigin::signRiskClaim(Obj::of(['binding' => $b, 'policy' => $p, 'encInputs' => 'x']), self::SEED, 'c', str_repeat("\x02", 16));
        $r = FheOrigin::evalSignedRiskClaim('pk', 'gk', $s, [$s->get('signer')], 'c', $b, $p, FheOrigin::memoryNonceGuard());
        $this->assertSame(['ok' => false, 'reason' => 'evaluation failed: policy.scale must be a positive integer'], $r);
    }

    /** The default replay window holds 100000 nonces and then fails closed. */
    public function testDefaultNonceWindow(): void
    {
        $g = FheOrigin::memoryNonceGuard();
        $all = true;
        for ($i = 0; $i < 100000; $i++) {
            $all = $g((string)$i) && $all;
        }
        $this->assertTrue($all);
        $this->assertFalse($g('last'));
    }
}
