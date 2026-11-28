<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Attestation.php';

use Atlas\Pca\Attestation;
use Atlas\Pca\DevAttestor;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryNonceStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Software attestation kills: the nonce store, the dev attestor, the binding, the entropy gate, and the agent-binding match edges. */
final class AttestSurvivorKill7AttestationCoreTest extends TestCase
{
    private const N = '0123456789abcdef0123456789abcdef';
    private const MALFORMED = 'min_measurement is malformed: it must be a non-empty string or {svn: n} with n a non-negative safe integer (fail closed)';

    private static function kp(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/att/' . $label, true));
    }

    private static function priv(string $m, mixed ...$a): mixed
    {
        return (new \ReflectionMethod(Attestation::class, $m))->invoke(null, ...$a);
    }

    private static function prop(object $o, string $p): mixed
    {
        return (new \ReflectionProperty($o, $p))->getValue($o);
    }

    private static function thrown(\Closure $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return get_class($e) . '|' . $e->getMessage();
        }
        return 'none';
    }

    // ---- MemoryNonceStore ------------------------------------------------------------------------------------------------------

    /** An explicit null max and absent retention take the documented defaults as binary64 numbers. */
    public function testStoreDefaultsAreFloats(): void
    {
        $s = new MemoryNonceStore(null);
        self::assertSame(100000.0, self::prop($s, 'max'));
        self::assertSame(3600000.0, self::prop($s, 'retention'));
    }

    /** Without an injected clock the store reads the wall clock in whole epoch milliseconds, and keys each nonce under the "k" prefix. */
    public function testDefaultClockIsWholeEpochMilliseconds(): void
    {
        $s = new MemoryNonceStore(8);
        foreach (['a', 'b', 'c'] as $n) {
            self::assertTrue($s->consume($n), $n);
        }
        $seen = self::prop($s, 'seen');
        self::assertSame(['ka', 'kb', 'kc'], array_keys($seen));
        foreach ($seen as $t) {
            self::assertEqualsWithDelta(microtime(true) * 1000, $t, 60000.0);
        }
        self::assertFalse($s->consume('a'), 'a consumed nonce is never re-accepted inside the retention window');
        $clock = self::prop($s, 'clock');
        self::assertIsInt($clock(), 'the default clock is an int (a float reading would be refused by consume)');
        self::assertEqualsWithDelta(microtime(true) * 1000, $clock(), 60000.0);
    }

    /** A full store stops at the first still-retained entry: a later-inserted entry with an older time is not evicted past it. */
    public function testEvictionStopsAtTheFirstRetainedEntry(): void
    {
        $times = [1000, 0, 1500];
        $i = 0;
        $s = new MemoryNonceStore(2, Obj::of(['retentionMs' => 1000, 'now' => static function () use (&$times, &$i) {
            return $times[$i++];
        }]));
        self::assertTrue($s->consume('a'));
        self::assertTrue($s->consume('b'));
        self::assertFalse($s->consume('c'), 'full of entries the walk cannot prove expired: refuse (fail closed)');
    }

    // ---- DevAttestor and the binding ---------------------------------------------------------------------------------------------

    /** An unknown signature alg is refused naming the alg. */
    public function testDevAttestorRefusesAnUnknownAlg(): void
    {
        self::assertSame("RuntimeException|createDevAttestor: unknown signature alg 'bogus'", self::thrown(static fn() => new DevAttestor(self::kp('x'), 'bogus')));
    }

    private static function claims(array $drop = []): Obj
    {
        $a = ['model_id' => 'm1', 'weights_digest' => 'w1', 'runtime_measurement' => 'rt1', 'operator' => 'op1', 'nonce' => self::N,
            'issued_at' => 1000, 'expires_at' => 2000, 'holder_pub' => 'H', 'grant_ref' => 'G', 'epoch' => 1];
        foreach ($drop as $k) {
            unset($a[$k]);
        }
        return Obj::of($a);
    }

    /** The document is bound only when holder_pub, grant_ref and epoch are all given; any one missing leaves it unbound. */
    public function testAttestBindsOnlyWithAllThreeFields(): void
    {
        $att = new DevAttestor(self::kp('a'));
        $full = $att->attest(self::claims());
        self::assertSame(Attestation::bindingB64u(Obj::of(['holderPub' => 'H', 'grantRef' => 'G', 'epoch' => 1, 'nonce' => self::N])), $full->get('binding'));
        foreach (['holder_pub', 'grant_ref', 'epoch'] as $drop) {
            self::assertFalse($att->attest(self::claims([$drop]))->has('binding'), $drop);
        }
    }

    /** A malformed holderPub is refused with the holderPub message (absent, null, not a string, empty). */
    public function testBindingRefusesAMalformedHolder(): void
    {
        foreach ([[], ['holderPub' => null], ['holderPub' => 123], ['holderPub' => '']] as $h) {
            $exp = Obj::of($h + ['grantRef' => 'g', 'nonce' => 'n', 'epoch' => 1]);
            self::assertSame('TypeError|binding: holderPub required', self::thrown(static fn() => Attestation::binding($exp)), json_encode($h));
        }
        self::assertSame('TypeError|binding: holderPub required', self::thrown(static fn() => Attestation::binding(null)));
        self::assertSame(64, strlen(Attestation::binding(Obj::of(['holderPub' => 'h', 'grantRef' => 'g', 'nonce' => 'n', 'epoch' => 0]))));
    }

    // ---- nonce entropy and requiresAttestation ------------------------------------------------------------------------------------

    /** Hex nonces count half a byte per character and base64url ones floor(3/4) per character: the 16-byte minimum holds at the edge. */
    public function testNonceEntropyBoundaries(): void
    {
        self::assertTrue(Attestation::nonceEntropyOk(self::N));
        self::assertFalse(Attestation::nonceEntropyOk('0123456789abcd0123456789abcd'), '28 hex characters are 14 bytes');
        self::assertFalse(Attestation::nonceEntropyOk('ghijklmnopqrstuvwxyz_'), '21 base64url characters are 15 bytes');
        self::assertTrue(Attestation::nonceEntropyOk('ghijklmnopqrstuvwxyz_-'), '22 base64url characters are 16 bytes');
    }

    /** require_measured_weights alone makes an attestation required, and false does not. */
    public function testRequireMeasuredWeightsRequiresAttestation(): void
    {
        self::assertTrue(Attestation::requiresAttestation(Obj::of(['require_measured_weights' => true])));
        self::assertFalse(Attestation::requiresAttestation(Obj::of(['require_measured_weights' => false])));
        self::assertFalse(Attestation::requiresAttestation(new Obj()));
    }

    // ---- private predicates -----------------------------------------------------------------------------------------------------

    /** SameValueZero: NaN equals NaN and nothing else, numbers by value, a number never equals its text. */
    public function testSameValueZero(): void
    {
        self::assertTrue(self::priv('szEq', NAN, NAN));
        self::assertFalse(self::priv('szEq', NAN, 1.0));
        self::assertFalse(self::priv('szEq', 1.0, NAN));
        self::assertTrue(self::priv('szEq', 1, 1.0));
        self::assertFalse(self::priv('szEq', 1, 2));
        self::assertFalse(self::priv('szEq', 1, '1'));
        self::assertTrue(self::priv('szEq', 'a', 'a'));
        self::assertTrue(self::priv('szEq', null, null));
    }

    /** The nonce-age check: equal to the clock is fresh, skew moves the issue time, and a non-finite clock or skew is refused. */
    public function testNonceAgeReasons(): void
    {
        $future = 'nonce issued in the future';
        self::assertNull(self::priv('nonceAgeReason', 1000, 1000.0, 0.0, 300000.0));
        self::assertNull(self::priv('nonceAgeReason', 1200, 1000.0, 500.0, 300000.0));
        self::assertSame($future, self::priv('nonceAgeReason', 1, INF, 0.0, 300000.0));
        self::assertSame($future, self::priv('nonceAgeReason', 1, 1000.0, INF, 300000.0));
        self::assertSame($future, self::priv('nonceAgeReason', 1200, 1000.0, 100.0, 300000.0));
        self::assertSame('attestation nonce expired (stale quote)', self::priv('nonceAgeReason', 1, 500000.0, 0.0, 300000.0));
    }

    /** The validity window: iat == exp is a valid instant, and a non-finite clock or skew is expired. */
    public function testWindowStates(): void
    {
        self::assertSame('valid', self::priv('window', 1000.0, 0.0, 1000, 1000));
        self::assertSame('malformed', self::priv('window', 1000.0, 0.0, 1001, 1000));
        self::assertSame('expired', self::priv('window', -INF, 0.0, 1, 2));
        self::assertSame('expired', self::priv('window', 1000.0, INF, 1, 2));
        self::assertSame('notyet', self::priv('window', 1000.0, 0.0, 2000, 3000));
        self::assertSame('expired', self::priv('window', 5000.0, 0.0, 1, 2));
    }

    /** verifyPinnedSuite refuses an absent-as-null or unknown alg outright. */
    public function testPinnedSuiteRefusesAnUnknownAlg(): void
    {
        self::assertFalse(self::priv('verifyPinnedSuite', null, 'x', null, 'm', 's', null, null));
        self::assertFalse(self::priv('verifyPinnedSuite', 'bogus', 'x', null, 'm', 's', null, null));
    }

    // ---- matchAgentBinding -------------------------------------------------------------------------------------------------------

    private static function bound(mixed $mm, string $rt = '5'): ?string
    {
        $id = Obj::of(['model_id' => 'm', 'weights_digest' => 'w', 'runtime_measurement' => $rt, 'operator' => 'o']);
        return Attestation::matchAgentBinding($id, Obj::of(['min_measurement' => $mm]));
    }

    /** An SVN bound accepts 0 and the largest safe integer, and a measurement above the safe range is not an integer SVN. */
    public function testSvnBoundsAndSafeRange(): void
    {
        self::assertNull(self::bound(Obj::of(['svn' => 0]), '9007199254740991'));
        self::assertNull(self::bound(Obj::of(['svn' => 0]), '0'));
        self::assertNull(self::bound(Obj::of(['svn' => 9007199254740991]), '9007199254740991'));
        self::assertStringStartsWith('runtime_measurement 9007199254740992 is not an integer SVN (required min svn ', (string)self::bound(Obj::of(['svn' => 0]), '9007199254740992'));
    }

    /** Every non-conforming SVN bound is malformed (fail closed): negative zero, fractions, negatives, extra members, non-objects. */
    public function testMalformedSvnBoundsAreRefused(): void
    {
        foreach ([Obj::of(['svn' => -0.0]), Obj::of(['svn' => 1.5]), Obj::of(['svn' => -1]), Obj::of(['svn' => 1, 'x' => 2]), new Obj(), 5, [1]] as $mm) {
            self::assertSame(self::MALFORMED, self::bound($mm), json_encode($mm instanceof Obj ? $mm->keys() : $mm));
        }
    }

    /** require_measured_weights demands weights_measured === true, exactly. */
    public function testRequireMeasuredWeights(): void
    {
        $reason = 'weights_digest is not hardware-measured (require_measured_weights: self-asserted or host-asserted weights rejected)';
        $id = static fn(array $x): Obj => Obj::of($x + ['model_id' => 'm', 'weights_digest' => 'w', 'runtime_measurement' => 'r', 'operator' => 'o']);
        $req = Obj::of(['require_measured_weights' => true]);
        self::assertNull(Attestation::matchAgentBinding($id(['weights_measured' => true]), $req));
        self::assertSame($reason, Attestation::matchAgentBinding($id(['weights_measured' => false]), $req));
        self::assertSame($reason, Attestation::matchAgentBinding($id([]), $req));
        self::assertNull(Attestation::matchAgentBinding($id(['weights_measured' => false]), Obj::of(['require_measured_weights' => false])));
    }
}
