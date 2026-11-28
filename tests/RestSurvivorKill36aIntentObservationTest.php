<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentObservation.php';
require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/../src/Pq.php';
require_once __DIR__ . '/../src/OpensslPq.php';

use Atlas\Pca\IntentObservation;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\Pq;
use Atlas\Pca\PqKeyPair;
use PHPUnit\Framework\TestCase;

/** Group 36a mutation kills for src/IntentObservation.php: shape refusals with their reasons, the signing suite gate, and PQ pinning. */
final class RestSurvivorKill36aIntentObservationTest extends TestCase
{
    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/intent-obs-36a', true);
    }

    private static function signed(): Obj
    {
        return IntentObservation::sign(Obj::of(['map_digest' => Pca::b64u(str_repeat("\x01", 32)), 'verb' => 'pay', 'values' => Obj::of(['amount' => 5]),
            'y' => 1, 'source' => 'runtime', 'observed_at' => 0]), self::seed());
    }

    private static function withMember(Obj $o, string $k, mixed $v): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $x) {
            $c->set($x, $o->get($x));
        }
        $c->set($k, $v);
        return $c;
    }

    /** body() is public: it is the signed body, every body member in order and no signature. */
    public function testBodyIsTheSignedBodyWithoutTheSignature(): void
    {
        $o = self::signed();
        self::assertSame(['ok' => true], IntentObservation::verify($o));
        self::assertSame(['v', 'map_digest', 'verb', 'values', 'y', 'source', 'observed_at', 'signer'], IntentObservation::body($o)->keys());
    }

    /** values that are not an object are refused with the shape reason, not an internal error. */
    public function testValuesThatAreNotAnObjectAreRefused(): void
    {
        self::assertSame(['ok' => false, 'reason' => 'values must map paths to numbers or strings'],
            IntentObservation::verify(self::withMember(self::signed(), 'values', 'x')));
    }

    /** A signer that is a string but not a canonical 32-byte key is refused by the shape check. */
    public function testNonCanonicalSignerStringIsRefused(): void
    {
        self::assertSame(['ok' => false, 'reason' => 'signer is not canonical base64url (32 bytes)'],
            IntentObservation::verify(self::withMember(self::signed(), 'signer', 'not-a-key')));
    }

    /** A post-quantum suite without its pq_pk cannot be bound: refused as malformed with the exact cause. */
    public function testPqSuiteWithoutItsKeyIsMalformed(): void
    {
        self::assertSame(['ok' => false, 'reason' => 'malformed intent observation: pq_pk is missing'],
            IntentObservation::verify(self::withMember(self::signed(), 'alg', 'ml-dsa-65')));
    }

    /** Native signing takes only Ed25519: an explicit ed25519 suite signs, any other suite throws. */
    public function testSigningTakesOnlyEd25519(): void
    {
        $d = Obj::of(['map_digest' => Pca::b64u(str_repeat("\x02", 32)), 'verb' => 'v', 'values' => new Obj(), 'y' => 0, 'source' => 'witness', 'observed_at' => 7]);
        self::assertSame(['ok' => true], IntentObservation::verify(IntentObservation::sign($d, self::seed(), ['alg' => 'ed25519'])));
        try {
            IntentObservation::sign($d, self::seed(), ['alg' => 'ml-dsa-65']);
            self::fail('a non-Ed25519 suite was signed natively');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('signIntentObservation: only Ed25519 signing is supported natively', $e->getMessage());
        }
    }

    /** A hybrid observation verifies only under its pinned PQ key, with alg and pq_pk bound into the signed message. */
    public function testHybridObservationVerifiesUnderItsPin(): void
    {
        $alg = 'hybrid-ed25519-ml-dsa-65';
        if (!Pca::suiteAvailable($alg) || !OpensslPq::available('ML-DSA-65')) {
            self::assertNotSame('1', getenv('PCA_REQUIRE_PQ'), 'ML-DSA-65: OpenSSL >= 3.5 over FFI is required in CI');
            return;
        }
        $ed = new KeyPair(self::seed());
        $pq = new PqKeyPair('ML-DSA-65');
        $body = IntentObservation::body(self::signed());
        self::assertSame($ed->public, $body->get('signer'));
        $m = IntentObservation::body($body);
        $m->set('alg', $alg);
        $m->set('pq_pk', $pq->public);
        $o = IntentObservation::body($body);
        foreach (Pq::signSuiteArtifact($alg, $ed, $pq, IntentObservation::SIG_DOMAIN . Json::canonicalizeNative($m)) as $k => $v) {
            $o->set($k, $v);
        }
        $o->set('alg', $alg);
        $o->set('pq_pk', $pq->public);
        self::assertSame(['ok' => true], IntentObservation::verify($o, ['pqPins' => Obj::of([$ed->public => $pq->public])]));
        $bad = ['ok' => false, 'reason' => 'bad signature'];
        self::assertSame($bad, IntentObservation::verify($o), 'no pin, no PQ key');
        self::assertSame($bad, IntentObservation::verify($o, ['pqPins' => Obj::of([$ed->public => (new PqKeyPair('ML-DSA-65'))->public])]));
        self::assertSame($bad, IntentObservation::verify($o, ['pqPins' => Obj::of([$ed->public => 7])]), 'a non-string pin never matches');
    }
}
