<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Escalation.php';

use Atlas\Pca\Escalation;
use Atlas\Pca\IntentWb;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * k05 mutation kills for Escalation: the request builder (default ttl, aud, render digest, non-object action, reason casting
 * and the 512-unit cut incl. the lone high surrogate it keeps), reasonsWire's lone-surrogate escape, the answer shape
 * (principal, times), verifyAnswer's principal list / pin choice (first match) and its fail-closed catch (test seam).
 */
final class K05KillEscalationTest extends TestCase
{
    private const NOW = 1_000_000;

    protected function tearDown(): void
    {
        Escalation::$verifyHook = null;
    }

    /** @return array{0:string,1:string} [secret key, b64u public key] */
    private static function kp(): array
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'atlas-pca/k05-escalation', true));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private static function d(string $c): string
    {
        return Pca::b64u(str_repeat($c, 32));
    }

    private static function body(array $over = []): Obj
    {
        $b = Obj::of([
            'v' => new Num('1'), 'kind' => 'pca-escalation-answer', 'principal' => self::kp()[1],
            'policy_digest' => self::d("\x01"), 'action_digest' => self::d("\x02"), 'history_head' => self::d("\x03"),
            'decision' => 'allow', 'iat' => new Num((string)(self::NOW - 1000)), 'expires_at' => new Num((string)(self::NOW + 60000)),
            'nonce' => Pca::b64u(str_repeat("\x07", 16)), 'sig' => 'x',
        ]);
        foreach ($over as $k => $v) {
            $b->set($k, $v);
        }
        return $b;
    }

    private static function bind(): array
    {
        return ['policy_digest' => self::d("\x01"), 'action_digest' => self::d("\x02"), 'history_head' => self::d("\x03")];
    }

    private static function req(array $reasons = [], mixed $aud = 'aud', ?string $render = null, mixed $action = null): Obj
    {
        $pcactn = Obj::of(['action' => $action ?? Obj::of(['verb' => 'v', 'resource' => 'r'])]);
        return $render === null
            ? Escalation::buildRequest($aud, new Obj(), $pcactn, null, $reasons, 1000)
            : Escalation::buildRequest($aud, new Obj(), $pcactn, null, $reasons, 1000, 3_600_000, $render);
    }

    public function testBuildRequestDefaultsAudAndRenderDigest(): void
    {
        $r = self::req();
        $this->assertSame('3601000', $r->get('expires_at')->lexeme, 'the default ttl is exactly one hour');
        $this->assertSame('aud', $r->get('aud'));
        $this->assertSame('', self::req([], 5)->get('aud'));
        $this->assertFalse($r->has('render_digest'));
        $this->assertSame('rd', self::req([], 'aud', 'rd')->get('render_digest'));
    }

    public function testANonObjectActionRendersNull(): void
    {
        $r = self::req([], 'aud', null, 'x');
        $this->assertSame(['null', 'null'], [$r->get('verb'), $r->get('resource')]);
    }

    public function testReasonsAreCastAndCutAt512Units(): void
    {
        $this->assertSame(['5'], self::req([5])->get('reasons'));
        // exactly 512 units is kept as is (an invalid UTF-8 byte would not survive a needless cut)
        $s = str_repeat('a', 511) . "\xFF";
        $this->assertSame([$s], self::req([$s])->get('reasons'));
    }

    public function testACutInsideASurrogatePairKeepsTheExactHighSurrogate(): void
    {
        $a = str_repeat('a', 511);
        $cases = [
            "\u{10000}" => "\xED\xA0\x80", // hi D800 (cp 0)
            "\u{103FF}" => "\xED\xA0\x80", // hi D800 (cp 0x3FF)
            "\u{20000}" => "\xED\xA1\x80", // hi D840 (odd middle 6 bits)
        ];
        foreach ($cases as $ch => $hi) {
            $this->assertSame([$a . $hi], self::req([$a . $ch . 'tail'])->get('reasons'), bin2hex($ch));
        }
    }

    public function testReasonsWireEscapesOnlyACompleteLoneSurrogate(): void
    {
        $w = static fn(string $r): string => Escalation::reasonsWire(Obj::of(['reasons' => [$r]]));
        $this->assertSame("[\"\xED\xA0\"]", $w("\xED\xA0"), 'a truncated sequence is copied raw');
        $this->assertSame("[\"\xED\x80\x80\"]", $w("\xED\x80\x80"), 'U+D000 is a real character');
        $this->assertSame('["\ud800"]', $w("\xED\xA0\x80"));
        $this->assertSame('["\ud840"]', $w("\xED\xA1\x80"));
        $this->assertSame('["\ud800X"]', $w("\xED\xA0\x80X"));
    }

    public function testAnswerShapePrincipalAndTimes(): void
    {
        $this->assertNull(Escalation::answerShapeError(self::body()), 'control');
        $p = 'principal must be canonical base64url (32 bytes)';
        $this->assertSame($p, Escalation::answerShapeError(self::body(['principal' => new Num('5')])));
        $this->assertSame($p, Escalation::answerShapeError(self::body(['principal' => ''])));
        $this->assertSame($p, Escalation::answerShapeError(self::body(['principal' => str_repeat('A', 65)])));
        $z = new Num('0');
        $this->assertSame('expires_at must be greater than iat', Escalation::answerShapeError(self::body(['iat' => $z, 'expires_at' => $z])));
        $this->assertSame('iat and expires_at must be non-negative safe integers',
            Escalation::answerShapeError(self::body(['iat' => $z, 'expires_at' => new Num('1.5')])));
    }

    private static function signed(array $over = []): Obj
    {
        $s = Escalation::signAnswer(self::body($over), self::kp()[0]);
        self::assertNotNull($s);
        return $s;
    }

    public function testPrincipalListMustBeANonEmptyListOfKeysOrPins(): void
    {
        $a = self::signed();
        $pk = self::kp()[1];
        $this->assertSame(['ok' => true, 'principal' => $pk, 'decision' => 'allow'], Escalation::verifyAnswer($a, [$pk], self::bind(), self::NOW), 'control');
        $this->assertSame(['ok' => false, 'reason' => 'no principal is pinned for escalation answers'], Escalation::verifyAnswer($a, 'nope', self::bind(), self::NOW));
        $this->assertSame(['ok' => false, 'reason' => 'the answering principal is not pinned by this verifier'], Escalation::verifyAnswer($a, [5], self::bind(), self::NOW));
    }

    public function testTheCatchFailsClosed(): void
    {
        Escalation::$verifyHook = static function (): void {
            throw new \RuntimeException('boom');
        };
        try {
            $this->assertSame(['ok' => false, 'reason' => 'escalation answer error (fail closed): boom'],
                Escalation::verifyAnswer(self::signed(), [self::kp()[1]], self::bind(), self::NOW));
        } finally {
            Escalation::$verifyHook = null;
        }
    }

    public function testTheFirstMatchingPinIsUsed(): void
    {
        if (!Pca::suiteImplemented('ml-dsa-65')) {
            $this->markTestSkipped('no ML-DSA-65 in this libcrypto');
        }
        $g = OpensslPq::generate('ML-DSA-65');
        $this->assertNotNull($g);
        [$pkey, $pqRaw] = $g;
        try {
            $pq = Pca::b64u($pqRaw);
            $body = self::body(['alg' => 'ml-dsa-65', 'pq_pk' => $pq]);
            $sig = OpensslPq::sign('ML-DSA-65', $pkey, IntentWb::artifactMessage(Escalation::ANSWER_DOMAIN, $body));
            $this->assertNotNull($sig);
            $body->set('sig', Pca::b64u($sig));
            $pk = self::kp()[1];
            $ok = ['ok' => true, 'principal' => $pk, 'decision' => 'allow'];
            // the first pin carries the PQ key; a later bare-key pin for the same principal must not replace it
            $this->assertSame($ok, Escalation::verifyAnswer($body, [Obj::of(['pk' => $pk, 'pq_pk' => $pq]), $pk], self::bind(), self::NOW));
            $this->assertSame(['ok' => false, 'reason' => 'escalation answer signature invalid'], Escalation::verifyAnswer($body, [$pk], self::bind(), self::NOW));
        } finally {
            OpensslPq::free($pkey);
        }
    }
}
