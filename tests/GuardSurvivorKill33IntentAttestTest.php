<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentAttest.php';

use Atlas\Pca\IntentAttest;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Ledger;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/IntentAttest.php: map shape refusals, the JSON form the digest covers, attestation times and anchor matching. */
final class GuardSurvivorKill33IntentAttestTest extends TestCase
{
    private static function map(array $extra = [], array $metrics = []): Obj
    {
        return Obj::of(['v' => new Num('1'), 'kind' => 'pca-intent-map', 'intent_ref' => null,
            'metrics' => Obj::of($metrics + ['fidelity_est_ppm' => new Num('5'), 'residual_risk_ppm' => new Num('0')])] + $extra);
    }

    private static function key(): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/g33-intent-attest', true));
    }

    public function testMapShapeRefusals(): void
    {
        $this->assertNull(IntentAttest::intentMapShapeError(self::map([], ['fidelity_est_ppm' => new Num('0')])), 'control');
        $this->assertSame('metrics.fidelity_est_ppm must be an integer in [0, 1e6]',
            IntentAttest::intentMapShapeError(self::map([], ['fidelity_est_ppm' => new Num('-0')])));
        $m = self::map();
        $m->set('metrics', 5);
        $this->assertSame('metrics must be an object', IntentAttest::intentMapShapeError($m));
    }

    /** A plain PHP associative-array map is read as the object it spells. */
    public function testArrayMapIsAccepted(): void
    {
        $arr = ['v' => 1, 'kind' => 'pca-intent-map', 'intent_ref' => null, 'metrics' => ['fidelity_est_ppm' => 5, 'residual_risk_ppm' => 0]];
        $a = IntentAttest::signIntentMapAttestation($arr, self::key(), 10);
        $this->assertSame(IntentAttest::signIntentMapAttestation(self::map(), self::key(), 10)->get('map_digest'), $a->get('map_digest'));
    }

    /** The digest covers the JSON round trip: a non-finite number inside a list is null there. */
    public function testDigestCoversTheJsonForm(): void
    {
        $k = self::key();
        $this->assertSame(IntentAttest::signIntentMapAttestation(self::map(['x' => [null]]), $k, 10)->get('map_digest'),
            IntentAttest::signIntentMapAttestation(self::map(['x' => [INF]]), $k, 10)->get('map_digest'));
    }

    public function testSignedAtZeroVerifies(): void
    {
        $k = self::key();
        $a = IntentAttest::signIntentMapAttestation(self::map(), $k, 0);
        $this->assertSame(['ok' => true], IntentAttest::verifyIntentMapAttestation($a, self::map(), Obj::of(['expectedSigner' => $k->public])));
        $a->set('alg', 'ml-dsa-65');
        $this->assertSame(['ok' => false, 'reason' => 'malformed intent map attestation: pq_pk is missing'], IntentAttest::verifyIntentMapAttestation($a));
    }

    public function testAnchorReceiptMatching(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'malformed anchor receipt: the receipt has no signed tree head'],
            IntentAttest::verifyIntentAnchor(Obj::of(['kind' => 'statement', 'digest' => Pca::b64u(str_repeat("\x05", 32))]), 'g', 'inst'));
        $seed = hash('sha256', 'atlas-pca-conformance/g33-intent-anchor', true);
        $kp = sodium_crypto_sign_seed_keypair($seed);
        $g = Pca::b64u(sodium_crypto_sign_publickey($kp));
        $f = ['instance_id' => 'inst', 'principal' => IntentAttest::INTENT_ANCHOR_LOG, 'size' => new Num('1'), 'root' => Pca::b64u(str_repeat("\x06", 32)),
            'prev_root' => '', 'timestamp' => new Num('1')];
        $h = Obj::of($f + ['guardian' => $g]);
        $h->set('sig', Pca::b64u(sodium_crypto_sign_detached(Ledger::STH_DOMAIN . Json::canonicalizeStrict(Obj::of($f)), sodium_crypto_sign_secretkey($kp))));
        $this->assertTrue(Ledger::verifyTreeHead($h, $g), 'control: the head is genuine');
        $r = static fn(array $proof, array $idx): Obj => Obj::of(['kind' => 'statement', 'digest' => Pca::b64u(str_repeat("\x05", 32)), 'signed_tree_head' => $h,
            'proof' => Obj::of($proof + ['size' => new Num('1')])] + $idx);
        $notIncluded = ['ok' => false, 'reason' => 'artifact is not included under the signed head'];
        $mismatch = ['ok' => false, 'reason' => 'proof does not match the head'];
        // both indexes absent compare equal, so the check moves on to inclusion
        $this->assertSame($notIncluded, IntentAttest::verifyIntentAnchor($r([], []), $g, 'inst'));
        // two different non-number indexes never match
        $this->assertSame($mismatch, IntentAttest::verifyIntentAnchor($r(['index' => 'a'], ['index' => 'b']), $g, 'inst'));
    }
}
