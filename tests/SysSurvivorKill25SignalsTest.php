<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Jose;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Signals;
use Atlas\Pca\SignalsError;
use Atlas\Pca\SignalsRevocationState;
use PHPUnit\Framework\TestCase;

/** Group 25 kills for src/Signals.php: replay store clocks, entries, jti layout, SET gates, stream ordering, receive boundaries, snapshots. */
final class SysSurvivorKill25SignalsTest extends TestCase
{
    private const GRANT = 'https://atlasauth.net/caep/grant-revoked';
    private const SESSION = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

    protected function tearDown(): void
    {
        Signals::$randomHook = null;
    }

    /** @return array{0:Obj,1:Obj} private and public JWK of a fixed seed */
    private static function keys(): array
    {
        $seed = str_repeat("\x07", 32);
        $kp = new KeyPair($seed);
        return [Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public, 'd' => Pca::b64u($seed)]), Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public])];
    }

    private static function payload(string $jwt): array
    {
        return json_decode((string) Pca::unb64u(explode('.', $jwt)[1]), true, 512, JSON_THROW_ON_ERROR);
    }

    /** @param \Closure():mixed $f */
    private function throwsExactly(string $class, string $message, \Closure $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame($class, $e::class, $e->getMessage());
            $this->assertSame($message, $e->getMessage());
            return $e;
        }
        $this->fail("expected $class: $message");
    }

    private static function snapshot(array $grants = [], array $intents = []): array
    {
        return ['v' => 1, 'grants' => $grants, 'agents' => [], 'intents' => $intents];
    }

    /** A clock or expiry that is not a number admits nothing (and records nothing), as Number.isFinite in the reference. */
    public function testReplayStoreRefusesNonNumberClocks(): void
    {
        $s = Signals::createInMemorySetReplayStore();
        $this->assertFalse($s->addIfAbsent('a', 200, 'now'));
        $this->assertFalse($s->addIfAbsent('a', 200, null));
        $this->assertFalse($s->addIfAbsent('a', '200', 100));
        $this->assertTrue($s->addIfAbsent('a', 200, 100));
        $this->assertFalse($s->addIfAbsent('a', 200, 150));
    }

    /** Object.entries: list indices and object keys as strings, a string's characters, nothing for ''. */
    public function testEntries(): void
    {
        $this->assertSame([['0', 5], ['1', 6]], Signals::entries([5, 6]));
        $this->assertSame([['a', 1], ['3', 'x']], Signals::entries(['a' => 1, 3 => 'x']));
        $this->assertSame([['0', 'a'], ['1', 'b']], Signals::entries('ab'));
        $this->assertSame([], Signals::entries(''));
    }

    /** The jti is an RFC 4122 version-4 UUID laid out from the random bytes: version and variant bits forced, the rest kept in order. */
    public function testJtiLayout(): void
    {
        [$priv] = self::keys();
        $ev = Obj::of([self::SESSION => new Obj()]);
        foreach ([
            "\x00\x11\x22\x33\x44\x55\x6B\x77\xFF\x99\xAA\xBB\xCC\xDD\xEE\xF1" => '00112233-4455-4b77-bf99-aabbccddeef1',
            "\x00\x00\x00\x00\x00\x00\x60\x00\x80\x00\x00\x00\x00\x00\x00\x00" => '00000000-0000-4000-8000-000000000000',
        ] as $bytes => $uuid) {
            Signals::$randomHook = static function (int $n) use ($bytes): string {
                self::assertSame(16, $n);
                return $bytes;
            };
            $this->assertSame($uuid, self::payload(Signals::buildSET($ev, 'https://tx.example', 'rx', $priv))['jti']);
        }
    }

    /** buildSET needs an events object; a SET whose events claim is missing is refused after its signature verifies. */
    public function testEventsMustBeAnObject(): void
    {
        [$priv, $pub] = self::keys();
        $this->throwsExactly(\InvalidArgumentException::class, 'buildSET: at least one event is required in the `events` map (RFC 8417 §2.2)',
            static fn() => Signals::buildSET([self::SESSION => new Obj()], 'https://tx.example', 'rx', $priv));
        $jwt = Jose::signJwt(Obj::of(['iss' => 'https://tx.example', 'iat' => time(), 'jti' => 'j1']), Obj::of(['alg' => 'EdDSA', 'typ' => 'secevent+jwt']), $priv);
        $this->throwsExactly(\InvalidArgumentException::class, 'SET invalid: `events` claim is missing or not a JSON object (RFC 8417 §2.2)',
            static fn() => Signals::verifySET($jwt, $pub));
    }

    /** The state gates: applySET's TypeError, and SignalsError misconfigured for the standard-revocation and hook builders. */
    public function testStateGates(): void
    {
        $parsed = ['events' => Obj::of([self::GRANT => Obj::of(['grant_ref' => 'g'])]), 'payload' => new Obj()];
        $this->throwsExactly(\TypeError::class, 'applySET: state must come from createRevocationState()', static fn() => Signals::applySET(new \stdClass(), $parsed));
        $msg = 'state must come from createRevocationState()';
        foreach ([
            static fn() => Signals::applyStandardRevocations(new \stdClass(), $parsed),
            static fn() => Signals::createRevocationHook(new \stdClass()),
            static fn() => Signals::createIsRevoked(new \stdClass()),
        ] as $f) {
            $e = $this->throwsExactly(SignalsError::class, $msg, $f);
            $this->assertSame('misconfigured', $e->errorCode);
        }
    }

    /** streamProcessor: a non-list is refused; ties keep input order; a set without timestamps ranks at 0; non-number timestamps are skipped. */
    public function testStreamOrdering(): void
    {
        $this->throwsExactly(\TypeError::class, 'parsedSets is not iterable', static fn() => Signals::streamProcessor(['a' => ['events' => new Obj()]]));
        // A (no timestamp, recorded as int 0) and B (float 0.0) tie at 0: input order wins, so the int stays
        $a = ['events' => Obj::of([self::GRANT => Obj::of(['grant_ref' => 'g'])])];
        $b = ['events' => Obj::of([self::GRANT => Obj::of(['grant_ref' => 'g', 'event_timestamp' => 0.0])])];
        $this->assertSame([['g', 0]], Signals::snapshotRevocationState(Signals::streamProcessor([$a, $b]))['grants']);
        // C ranks at 5 (its 'x' timestamp is not a number), D at 4: D's float 5.0 is applied first and kept
        $c = ['events' => Obj::of([self::GRANT => Obj::of(['grant_ref' => 'h', 'event_timestamp' => 5]), 'urn:example:other' => Obj::of(['event_timestamp' => 'x'])])];
        $d = ['events' => Obj::of([self::GRANT => Obj::of(['grant_ref' => 'h', 'event_timestamp' => 5.0]), 'urn:example:other' => Obj::of(['event_timestamp' => 4])])];
        $this->assertSame([['h', 5.0]], Signals::snapshotRevocationState(Signals::streamProcessor([$c, $d]))['grants']);
    }

    /** A lone set is applied as it is, so its events before a malformed one take effect before the error. */
    public function testALoneSetIsAppliedThenFails(): void
    {
        $state = Signals::createRevocationState();
        $set = ['events' => Obj::of([self::GRANT => Obj::of(['grant_ref' => 'g', 'event_timestamp' => 1]), 'urn:example:other' => null])];
        try {
            Signals::streamProcessor([$set], $state);
            $this->fail('a null event must throw');
        } catch (\TypeError $e) {
            $this->assertSame("Cannot read properties of null (reading 'event_timestamp')", $e->getMessage());
        }
        $this->assertTrue(Signals::isRevoked($state, 'g'));
    }

    /** The conformance suite asks a store exactly these questions, in order. */
    public function testConformanceCalls(): void
    {
        $log = new \ArrayObject();
        $n = 0;
        $make = static function () use (&$n, $log): object {
            $n++;
            return new class (Signals::createInMemorySetReplayStore(), $log, $n) {
                public function __construct(private object $inner, private \ArrayObject $log, private int $i)
                {
                }

                public function addIfAbsent(string $jti, mixed $exp, mixed $now): bool
                {
                    $this->log[] = [$this->i, $jti, $exp, $now];
                    return $this->inner->addIfAbsent($jti, $exp, $now);
                }
            };
        };
        $this->assertSame([], Signals::runSetReplayStoreConformance($make));
        $want = [[1, 'a', 200, 100], [1, 'a', 200, 101], [1, 'b', 200, 101], [1, 'a', 200, 199], [2, 'c', 200, 100], [2, 'c', 400, 200]];
        for ($k = 0; $k < 16; $k++) {
            $want[] = [3, 'race', 200, 100];
        }
        $this->assertSame($want, $log->getArrayCopy());
    }

    /** @return array{0:string,1:Obj,2:Obj} a fresh SET, the public key, and complete receive options */
    private static function receivable(object $store): array
    {
        [$priv, $pub] = self::keys();
        $set = Signals::buildSET(Obj::of([self::SESSION => new Obj()]), 'https://tx.example', 'rx', $priv);
        return [$set, $pub, Obj::of(['issuer' => 'https://tx.example', 'audience' => 'rx', 'replayStore' => $store, 'state' => Signals::createRevocationState(), 'maxAgeSec' => 3600])];
    }

    /** receiveSET boundaries: maxBytes is inclusive, a clock of exactly 8.64e15 ms is representable, an infinite skew is refused. */
    public function testReceiveBoundaries(): void
    {
        [$set, $pub, $o] = self::receivable(Signals::createInMemorySetReplayStore());
        $o->set('maxBytes', strlen($set));
        $this->assertTrue(Signals::receiveSET($set, $pub, $o)['ok']);
        [$set, $pub, $o] = self::receivable(Signals::createInMemorySetReplayStore());
        $o->set('nowSec', 8.64e12);
        $this->assertSame(['ok' => false, 'code' => 'iat_stale', 'reason' => 'SET is older than 3600s'], Signals::receiveSET($set, $pub, $o));
        [$set, $pub, $o] = self::receivable(Signals::createInMemorySetReplayStore());
        $o->set('clockSkewSec', INF);
        $this->assertSame(['ok' => false, 'code' => 'iat_future', 'reason' => 'SET iat is in the future'], Signals::receiveSET($set, $pub, $o));
    }

    /** The jti is held until iat + maxAgeSec + clockSkewSec. */
    public function testReplayExpiry(): void
    {
        $store = new class () {
            public array $calls = [];

            public function addIfAbsent(string $jti, mixed $exp, mixed $now): bool
            {
                $this->calls[] = $exp;
                return true;
            }
        };
        [$set, $pub, $o] = self::receivable($store);
        $o->set('clockSkewSec', 7);
        $this->assertTrue(Signals::receiveSET($set, $pub, $o)['ok']);
        $this->assertSame([(float) self::payload($set)['iat'] + 3600.0 + 7.0], $store->calls);
    }

    /** The default subject mapper names an agent only for an opaque subject. */
    public function testDefaultSubjectMapping(): void
    {
        $parsed = ['payload' => new Obj(), 'events' => Obj::of([self::SESSION => Obj::of(['subject' => Obj::of(['format' => 'email', 'id' => 'x'])])])];
        $this->assertSame(['agents' => [], 'unmapped' => [self::SESSION]], Signals::planStandardRevocations($parsed));
        $parsed = ['payload' => new Obj(), 'events' => Obj::of([self::SESSION => Obj::of(['subject' => Obj::of(['format' => 'opaque', 'id' => 'x'])])])];
        $this->assertSame(['agents' => [['x', 0]], 'unmapped' => []], Signals::planStandardRevocations($parsed));
    }

    /** Snapshots: an assoc-array snapshot restores, a non-finite timestamp or a numeric unknown member is refused, intents accumulate. */
    public function testRestore(): void
    {
        $st = Signals::restoreRevocationState(self::snapshot([['g', 5]], [['pca-intent:a', 1], ['pca-intent:b', 2]]));
        $this->assertTrue(Signals::isIntentRevoked($st, 'pca-intent:a'));
        $this->assertTrue(Signals::isIntentRevoked($st, 'pca-intent:b'));
        Signals::restoreRevocationState(self::snapshot([['g', 5.0]], [['pca-intent:c', 3]]), $st);
        $this->assertSame(['v' => 1, 'grants' => [['g', 5]], 'agents' => [], 'intents' => [['pca-intent:a', 1], ['pca-intent:b', 2], ['pca-intent:c', 3]]],
            Signals::snapshotRevocationState($st));
        $e = $this->throwsExactly(SignalsError::class, 'grants holds an entry that is not [string, number]', static fn() => Signals::restoreRevocationState(self::snapshot([['g', INF]])));
        $this->assertSame('bad_snapshot', $e->errorCode);
        $this->throwsExactly(SignalsError::class, "snapshot has unknown member '0'", static fn() => Signals::restoreRevocationState(self::snapshot() + [0 => 1]));
        $this->assertInstanceOf(SignalsRevocationState::class, Signals::restoreRevocationState(Obj::of(self::snapshot())));
    }

    /** assurance-level-change: a non-object event is an empty event; a non-list order is refused. */
    public function testAssuranceLevelChange(): void
    {
        [$priv] = self::keys();
        $set = Signals::assuranceLevelChangeSET(['issuer' => 'https://tx.example', 'audience' => 'rx', 'key' => $priv, 'event' => ['previous_level' => 'a']]);
        $this->assertSame([], self::payload($set)['events']['https://schemas.openid.net/secevent/caep/event-type/assurance-level-change']);
        $ev = Obj::of(['previous_level' => 'a', 'current_level' => 'b']);
        $this->throwsExactly(\TypeError::class, 'order must be a list', static fn() => Signals::assuranceLevelChangeSET(['issuer' => 'i', 'audience' => 'rx', 'key' => $priv, 'event' => $ev, 'order' => ['x' => 'a', 'y' => 'b']]));
    }
}
