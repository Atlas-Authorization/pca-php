<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Grants;
use Atlas\Pca\Notary;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Notary refusal paths: request/key validation, signed-but-malformed sessions, duck-typed inputs, the attested_fact caveat clock and error reasons. */
final class CoreSurvivorKill27NotaryTest extends TestCase
{
    private const DROP = "\0drop";

    protected function tearDown(): void
    {
        Notary::$clockHook = null;
    }

    /** @return array{0:string,1:string} public key, secret key */
    private static function kp(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca-conformance/notary27', true));
        return [sodium_crypto_sign_publickey($kp), sodium_crypto_sign_secretkey($kp)];
    }

    private static function key(): array
    {
        [$pk, $sk] = self::kp();
        return ['publicKey' => $pk, 'secretKey' => $sk];
    }

    private static function pub(): string
    {
        return Pca::b64u(self::kp()[0]);
    }

    private static function throws(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [get_class($e), $e->getMessage()];
        }
        return ['none', ''];
    }

    private static function leaf(mixed $p = ['a']): Obj
    {
        return Obj::of(['p' => $p, 'v' => 'x', 's' => 'salt']);
    }

    /** A session over a single-leaf body, with fields overridden (DROP removes one). */
    private static function session(array $over = [], array $commitOver = [], mixed $leafPath = ['a']): Obj
    {
        $commit = ['alg' => Notary::BODY_COMMIT_ALG, 'root' => Pca::merkleRoot([self::leaf($leafPath)]), 'size' => 1];
        $s = ['v' => 1, 'method' => 'GET', 'url' => 'https://api.example/x', 'requestHeadersDigest' => Pca::hashCanonical(new Obj()),
            'responseStatus' => 200, 'responseBodyCommit' => null, 'observedAt' => 1000];
        foreach ($commitOver as $k => $v) {
            $commit[$k] = $v;
        }
        $s['responseBodyCommit'] = Obj::of(array_filter($commit, static fn($v) => $v !== self::DROP));
        foreach ($over as $k => $v) {
            $s[$k] = $v;
        }
        return Obj::of(array_filter($s, static fn($v) => $v !== self::DROP));
    }

    /** An attestation the trusted notary really signed over `$session`. */
    private static function att(Obj $session): Obj
    {
        [$pk, $sk] = self::kp();
        return Obj::of(['session' => $session, 'notary' => Pca::b64u($pk), 'sig' => Pca::b64u(sodium_crypto_sign_detached(Notary::notaryMessage($session), $sk))]);
    }

    private static function disclosure(mixed $path = ['a']): Obj
    {
        return Obj::of(['path' => $path, 'value' => 'x', 'salt' => 'salt', 'proof' => Grants::merkleProof([self::leaf($path)], 0)]);
    }

    private static function duck(Obj $o): object
    {
        return new class ($o) {
            public function __construct(private Obj $o)
            {
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }
        };
    }

    private static function req(string $method = 'get', mixed $headers = null): Obj
    {
        return Obj::of(['method' => $method, 'url' => 'https://api.example/x', 'headers' => $headers]);
    }

    private static function resp(): Obj
    {
        return Obj::of(['status' => 200, 'body' => Obj::of(['a' => 'x'])]);
    }

    private static function salts(): callable
    {
        return static fn(int $n): string => str_repeat("\x07", $n);
    }

    /** A notarized single-field response, its disclosure of ['a'] and the caveat that requires a = 'x'. */
    private static function evidence(int $observedAt = 1000): array
    {
        $n = Notary::notarizeResponse(self::req(), self::resp(), self::key(), $observedAt, null, self::salts());
        $att = $n->get('attestation');
        $disc = Notary::discloseField($att, $n->get('witness'), ['a']);
        return [Notary::requireAttestedFact(['publicKey' => self::kp()[0]], ['a'], 'x'), Obj::of(['attestation' => $att, 'disclosure' => $disc])];
    }

    /** toPubB64u is public and accepts a key pair as an assoc array or an Obj, and refuses anything else with its own message. */
    public function testToPubB64uForms(): void
    {
        [$pk] = self::kp();
        $this->assertSame(Pca::b64u($pk), Notary::toPubB64u(['publicKey' => $pk]));
        $this->assertSame(Pca::b64u($pk), Notary::toPubB64u(Obj::of(['publicKey' => new Bytes($pk)])));
        $this->assertSame(['TypeError', 'not a public key'], self::throws(static fn() => Notary::toPubB64u(42)));
        $this->assertSame(['TypeError', 'not a public key'], self::throws(static fn() => Notary::toPubB64u(['secretKey' => $pk])));
    }

    /** notarizeResponse refuses a missing request, a missing response and an incomplete key pair, each with its exact TypeError. */
    public function testNotarizeRefusals(): void
    {
        $rb = self::salts();
        $this->assertSame(['TypeError', 'notarizeResponse: request.method is required'], self::throws(static fn() => Notary::notarizeResponse(null, self::resp(), self::key(), 1, null, $rb)));
        $this->assertSame(['TypeError', 'notarizeResponse: request.method is required'],
            self::throws(static fn() => Notary::notarizeResponse(Obj::of(['url' => 'https://api.example/x']), self::resp(), self::key(), 1, null, $rb)));
        $this->assertSame(['TypeError', 'notarizeResponse: response.status must be an integer'], self::throws(static fn() => Notary::notarizeResponse(self::req(), null, self::key(), 1, null, $rb)));
        $msg = ['TypeError', 'notarizeResponse: a notary key pair is required'];
        $this->assertSame($msg, self::throws(static fn() => Notary::notarizeResponse(self::req(), self::resp(), ['publicKey' => self::kp()[0]], 1, null, $rb)));
        $this->assertSame($msg, self::throws(static fn() => Notary::notarizeResponse(self::req(), self::resp(), null, 1, null, $rb)));
    }

    /** The method is upper-cased and header names lower-cased with full Unicode case mapping. */
    public function testUnicodeCaseMapping(): void
    {
        $a = Notary::notarizeResponse(self::req('gét', Obj::of(['X-Ä' => 'v'])), self::resp(), self::key(), 1, null, self::salts())->get('attestation')->get('session');
        $this->assertSame('GÉT', $a->get('method'));
        $this->assertSame(Pca::hashCanonical(Obj::of(['x-ä' => 'v'])), $a->get('requestHeadersDigest'));
    }

    /** Without an observedAt the session carries the clock in whole milliseconds. */
    public function testDefaultObservedAt(): void
    {
        Notary::$clockHook = static fn(): float => 1000.0009765625;
        $s = Notary::notarizeResponse(self::req(), self::resp(), self::key(), null, null, self::salts())->get('attestation')->get('session');
        $this->assertSame(1000000, $s->get('observedAt'));
        Notary::$clockHook = null;
        $before = (int)(microtime(true) * 1000);
        $s = Notary::notarizeResponse(self::req(), self::resp(), self::key(), null, null, self::salts())->get('attestation')->get('session');
        $after = (int)(microtime(true) * 1000);
        $this->assertIsInt($s->get('observedAt'));
        $this->assertGreaterThanOrEqual($before, $s->get('observedAt'));
        $this->assertLessThanOrEqual($after, $s->get('observedAt'));
    }

    /** discloseField refuses an assoc-array path, and with two leaves at one path it reveals the first. */
    public function testDiscloseFieldPathAndFirstMatch(): void
    {
        $this->assertSame(['TypeError', 'path must be a string or an array'], self::throws(static fn() => Notary::discloseField(null, null, ['k' => 'a'])));
        $w = Obj::of(['leaves' => [Obj::of(['path' => ['a'], 'value' => 'one', 'salt' => 's1']), Obj::of(['path' => ['a'], 'value' => 'two', 'salt' => 's2'])]]);
        $d = Notary::discloseField(null, $w, 'a');
        $this->assertSame(['one', 's1'], [$d->get('value'), $d->get('salt')]);
        $this->assertSame(0, $d->get('proof')->get('index')->int());
    }

    /** A session the trusted notary did sign is still refused when any one field is malformed. */
    public function testSignedMalformedSessionsAreRefused(): void
    {
        $this->assertTrue(Notary::verifyNotaryAttestation(self::att(self::session()), self::pub()));
        $bad = [
            [['v' => 2], []], [['method' => 5], []], [['url' => 5], []], [['requestHeadersDigest' => 5], []],
            [['responseStatus' => 1.5], []], [['responseStatus' => -0.0], []], [['observedAt' => 1.5], []], [['observedAt' => -0.0], []],
            [['observedAt' => self::DROP], []], [['responseBodyCommit' => 'x'], []],
            [[], ['alg' => 'other']], [[], ['root' => 5]], [[], ['root' => 'abc']], [[], ['size' => 0]], [[], ['size' => 1.5]], [[], ['size' => self::DROP]],
        ];
        foreach ($bad as $i => [$over, $commit]) {
            $this->assertFalse(Notary::verifyNotaryAttestation(self::att(self::session($over, $commit)), self::pub()), "case $i");
        }
    }

    /** An attestation-shaped object that is not an Obj is refused even when it carries a valid signed session. */
    public function testDuckTypedAttestationRefused(): void
    {
        $real = self::att(self::session());
        $this->assertTrue(Notary::verifyNotaryAttestation($real, self::pub()));
        $this->assertFalse(Notary::verifyNotaryAttestation(self::duck($real), self::pub()));
    }

    /** verifyDisclosedField refuses a duck-typed disclosure and a non-list path even when the leaf is committed. */
    public function testDisclosureShapeRefusals(): void
    {
        $att = self::att(self::session());
        $this->assertTrue(Notary::verifyDisclosedField($att, self::disclosure(), self::pub()));
        $this->assertFalse(Notary::verifyDisclosedField($att, self::duck(self::disclosure()), self::pub()));
        $attStr = self::att(self::session([], [], 'a'));
        $this->assertFalse(Notary::verifyDisclosedField($attStr, self::disclosure('a'), self::pub()));
    }

    /** factMatchesPcActn binds only through an Obj fact_binding. */
    public function testFactBindingMustBeObj(): void
    {
        $att0 = self::att(self::session());
        $pc = Obj::of(['provenance' => Obj::of(['trusted_refs' => [Notary::factRef($att0)]])]);
        $att = Notary::bindFactToPcActn($att0, $pc);
        $this->assertTrue(Notary::factMatchesPcActn($att, $pc));
        $att->set('fact_binding', self::duck(Obj::of(['pcactn_digest' => Pca::hashCanonical($pc)])));
        $this->assertFalse(Notary::factMatchesPcActn($att, $pc));
    }

    /** requireAttestedFact refuses an assoc-array path. */
    public function testRequireAttestedFactPath(): void
    {
        $this->assertSame(['TypeError', 'requireAttestedFact: path must be an array of segments'], self::throws(static fn() => Notary::requireAttestedFact(self::pub(), ['k' => 'a'], 'x')));
    }

    /** A caveat value that cannot be canonicalized never matches; a non-object policy is ignored; errors carry their message. */
    public function testEvaluateEqualsPolicyAndErrors(): void
    {
        [$cv, $ev] = self::evidence();
        $this->assertSame(['ok' => true, 'trust' => 'notary-trusted'], Notary::evaluateAttestedFactCaveat($cv, $ev));
        $this->assertSame(['ok' => true, 'trust' => 'notary-trusted'], Notary::evaluateAttestedFactCaveat($cv, $ev, ['x']));
        $odd = Notary::requireAttestedFact(self::pub(), ['a'], new \stdClass());
        $this->assertSame(['ok' => false, 'reason' => 'disclosed field value does not satisfy the caveat'], Notary::evaluateAttestedFactCaveat($odd, $ev));
        $this->assertSame(['ok' => false, 'reason' => 'attested_fact evaluation error (fail closed): evidence is required'], Notary::evaluateAttestedFactCaveat($cv, null));
    }

    /** The age check reads policy.now first, then the caller's now, then the clock in whole milliseconds. */
    public function testEvaluateClockPrecedence(): void
    {
        [$cv, $ev] = self::evidence(1000);
        $ok = ['ok' => true, 'trust' => 'notary-trusted'];
        $stale = ['ok' => false, 'reason' => 'attestation is stale or from the future'];
        $this->assertSame($ok, Notary::evaluateAttestedFactCaveat($cv, $ev, [Obj::of(['maxAgeMs' => 10])], 1005));
        $this->assertSame($ok, Notary::evaluateAttestedFactCaveat($cv, $ev, [Obj::of(['maxAgeMs' => 10, 'now' => 1005])], 999999999));
        $this->assertSame($stale, Notary::evaluateAttestedFactCaveat($cv, $ev, [Obj::of(['maxAgeMs' => 10, 'now' => 999999999])], 1005));
        Notary::$clockHook = static fn(): float => 1.0009765625; // 1000.9765625 ms, floored to 1000
        $this->assertSame($ok, Notary::evaluateAttestedFactCaveat($cv, $ev, [Obj::of(['maxAgeMs' => 0])]));
    }
}
