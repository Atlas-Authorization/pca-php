<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\Der;
use Atlas\Pca\Decision;
use Atlas\Pca\Escalation;
use Atlas\Pca\Json;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Exact-outcome boundary tests (mutation kills) for the native-parity modules: every limit at limit-1, limit and limit+1. */
final class ParityBoundaryKillTest extends TestCase
{
    private string $sk;
    private string $pk;

    protected function setUp(): void
    {
        $kp = sodium_crypto_sign_seed_keypair(hash('sha256', 'parity-boundary', true));
        $this->sk = sodium_crypto_sign_secretkey($kp);
        $this->pk = Pca::b64u(sodium_crypto_sign_publickey($kp));
    }

    private function answer(int $iat, int $exp, string $nonceBytes = '1234567890123456'): Obj
    {
        $d = Pca::b64u(str_repeat('a', 32));
        $a = Obj::of(['v' => new Num('1'), 'kind' => 'pca-escalation-answer', 'principal' => $this->pk, 'policy_digest' => $d,
            'action_digest' => $d, 'history_head' => $d, 'decision' => 'allow', 'iat' => new Num((string)$iat),
            'expires_at' => new Num((string)$exp), 'nonce' => Pca::b64u($nonceBytes)]);
        $signed = Escalation::signAnswer($a, $this->sk);
        if ($signed === null) {
            $a->set('sig', 'x'); // an out-of-limit answer is not signable: only its shape is judged
            return $a;
        }
        return $signed;
    }

    public function testAnswerLifetimeAndNonceLimits(): void
    {
        $this->assertNull(Escalation::answerShapeError($this->answer(1000, 1000 + 86_400_000)));
        $this->assertSame('an answer lives at most 86400000 ms', Escalation::answerShapeError($this->answer(1000, 1001 + 86_400_000)));
        $this->assertSame('expires_at must be greater than iat', Escalation::answerShapeError($this->answer(1000, 1000)));
        $this->assertNull(Escalation::answerShapeError($this->answer(0, 1)));
        $this->assertSame('nonce must be canonical base64url of at least 16 bytes', Escalation::answerShapeError($this->answer(1, 2, '123456789012345')));
    }

    public function testVerifierWindowIsInclusiveAtBothEnds(): void
    {
        $a = $this->answer(1000, 2000);
        $bind = ['policy_digest' => Pca::b64u(str_repeat('a', 32)), 'action_digest' => Pca::b64u(str_repeat('a', 32)), 'history_head' => Pca::b64u(str_repeat('a', 32))];
        $v = fn(int $now) => Escalation::verifyAnswer($a, [$this->pk], $bind, $now);
        $this->assertTrue($v(1000)['ok']);
        $this->assertTrue($v(2000)['ok']);
        $this->assertSame('the answer is from the future', $v(999)['reason']);
        $this->assertSame('the answer has expired', $v(2001)['reason']);
        $this->assertSame('the verifier clock is not a safe integer (fail closed)', $v(9007199254740992)['reason']);
        $this->assertSame('no principal is pinned for escalation answers', Escalation::verifyAnswer($a, [], $bind, 1000)['reason']);
    }

    public function testRuleListLimits(): void
    {
        $rule = fn(int $i) => '{"id":"r' . $i . '","when":{"field":"a","op":"eq","value":1},"signal":"deny"}';
        $list = fn(int $n) => '[' . implode(',', array_map($rule, range(1, $n))) . ']';
        $this->assertNull(Decision::tightenListError(Json::parseLax($list(64))));
        $this->assertSame('tighten has more than 64 rules', Decision::tightenListError(Json::parseLax($list(65))));
        $this->assertNull(Decision::tightenListError(Json::parseLax('[]')));
        $reason = fn(int $n) => Json::parseLax('[{"id":"r","when":{"field":"a","op":"eq","value":1},"signal":"deny","reason":"' . str_repeat('x', $n) . '"}]');
        $this->assertNull(Decision::tightenListError($reason(256)));
        $this->assertSame('tighten[0].reason must be a string of at most 256 characters', Decision::tightenListError($reason(257)));
        $id = fn(string $i) => Json::parseLax('[{"id":"' . $i . '","when":{"field":"a","op":"eq","value":1},"signal":"deny"}]');
        $this->assertNull(Decision::tightenListError($id('a' . str_repeat('b', 63))));
        $this->assertNotNull(Decision::tightenListError($id('a' . str_repeat('b', 64))));
        $this->assertNotNull(Decision::tightenListError($id('1a')));
    }

    public function testUnitTagLimits(): void
    {
        $tags = fn(int $n) => Json::parseLax('{' . implode(',', array_map(fn($i) => '"action.params.p' . $i . '":{"kind":"k"}', range(1, $n))) . '}');
        $this->assertNull(Decision::unitTagsError($tags(64)));
        $this->assertSame('units has more than 64 entries', Decision::unitTagsError($tags(65)));
        $exp = fn(string $e) => Json::parseLax('{"action.params.a":{"kind":"k","exponent":' . $e . '}}');
        $this->assertNull(Decision::unitTagsError($exp('0')));
        $this->assertNull(Decision::unitTagsError($exp('18')));
        $this->assertNotNull(Decision::unitTagsError($exp('19')));
        $this->assertNotNull(Decision::unitTagsError($exp('-1')));
        $this->assertNotNull(Decision::unitTagsError($exp('1.5')));
        $kind = fn(int $n) => Json::parseLax('{"action.params.a":{"kind":"' . str_repeat('k', $n) . '"}}');
        $this->assertNull(Decision::unitTagsError($kind(64)));
        $this->assertNotNull(Decision::unitTagsError($kind(65)));
        $this->assertNotNull(Decision::unitTagsError(Json::parseLax('{"action.params.a":{"kind":""}}')));
    }

    public function testDerBoundaries(): void
    {
        $this->assertSame(127, Der::readTlv("\x04\x7f" . str_repeat('a', 127), 0)->end - 2);
        $this->assertSame(128, Der::readTlv("\x04\x81\x80" . str_repeat('a', 128), 0)->end - 3);
        $this->assertSame(0, Der::parseDerTime(0x18, '19700101000000Z'));
        $this->assertSame(86_399_000, Der::parseDerTime(0x18, '19700101235959Z'));
        $this->assertNull(Der::parseDerTime(0x18, '19700101240000Z'));
        $this->assertNull(Der::parseDerTime(0x18, '19700101006000Z'));
        $this->assertNull(Der::parseDerTime(0x18, '19700101000060Z'));
        $this->assertNull(Der::parseDerTime(0x18, '19700001000000Z'));
        $this->assertNull(Der::parseDerTime(0x18, '19700100000000Z'));
        $this->assertSame(Der::parseDerTime(0x18, '20491231235959Z') + 1000, Der::parseDerTime(0x18, '20500101000000Z'));
        $this->assertSame(Der::parseDerTime(0x18, '20491231235959Z'), Der::parseDerTime(0x17, '491231235959Z')); // 49 -> 2049
    }
}
