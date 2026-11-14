<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SignersMore.php';
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore as S;
use PHPUnit\Framework\TestCase;

/** Exact outputs and boundaries of the extra producer-side signers (limits and messages from the reference). */
final class SignersMoreKillTest extends TestCase
{
    private function refuses(string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\InvalidArgumentException $e) {
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("no exception: $msg");
    }

    private static function args(string $name): Obj
    {
        foreach (Vectors::load('producer-vectors.json')->get('cases') as $c) {
            if ($c->get('name') === $name) {
                return $c->get('args');
            }
        }
        throw new \LogicException($name);
    }

    private static function with(Obj $o, string $k, mixed $v): Obj
    {
        $c = $o->without();
        $c->set($k, Sign::n($v));
        return $c;
    }

    private static function canon(mixed $v): string
    {
        return Json::canonicalizeLenient(Sign::n($v));
    }

    public function testPqBindingTakesTheLargestSafeEpoch(): void
    {
        $k = new KeyPair(str_repeat("\x02", 32));
        $b = S::signPqBinding($k, 'PQ', 9007199254740991, 'aud');
        self::assertSame('9007199254740991', $b->get('epoch')->lexeme);
        self::assertTrue(sodium_crypto_sign_verify_detached(Pca::unb64u($b->get('sig')),
            "atlas-pca/pq-binding/v2\0{$k->public}\0PQ\0" . "9007199254740991\0aud", Pca::unb64u($k->public)));
    }

    public function testCautionBoundaries(): void
    {
        $k = new KeyPair(str_repeat("\x02", 32));
        $body = self::args('caution-reason')->get('body');
        self::assertSame('0', S::signCaution(self::with($body, 'caution', 0), $k)->get('caution')->lexeme);
        $r = str_repeat('r', 64);
        self::assertSame($r, S::signCaution(self::with($body, 'reason', $r), $k)->get('reason'));
        $this->refuses('signCaution: invalid reason', fn() => S::signCaution(self::with($body, 'reason', $r . 'r'), $k));
    }

    public function testReadReceiptSuccessorOfAWellFormedPrevOnly(): void
    {
        $a = self::args('read-receipt-chained');
        $rs = new KeyPair(str_repeat("\x05", 32));
        $sign = fn(?Obj $prev) => S::signReadReceipt($rs, $a->get('grant'), 'read', 'customers/7', 'support', $a->get('fields'), $a->get('labels'), 1800000001000, $prev);
        self::assertSame('0', $sign(null)->get('seq')->lexeme);
        self::assertNull($sign(null)->get('prev'));
        $prev = $a->get('prev');
        self::assertSame('1', $sign($prev)->get('seq')->lexeme);
        $raw = $prev->without();
        $raw->set('seq', 3); // a raw PHP int (not a parsed number)
        self::assertSame('4', $sign($raw)->get('seq')->lexeme);
        foreach ([-1, 2.5, '3', null, [1]] as $bad) {
            $p = $prev->without();
            $p->set('seq', $bad);
            $this->refuses('signReadReceipt: prev.seq must be a non-negative safe integer', fn() => $sign($p));
        }
        $this->refuses('signReadReceipt: prev.seq must be a non-negative safe integer', fn() => $sign($prev->without('seq')));
    }

    public function testMeshProofExactShape(): void
    {
        $leaf = new KeyPair(str_repeat("\x06", 32));
        $chain = [Obj::of(['id' => 'c1'])];
        $action = ['verb' => 'refund', 'resource' => 'orders/1'];
        $l1 = ['k' => 'a'];
        $l2 = ['k' => 'b'];
        $l3 = ['k' => 'c'];
        $one = ['cap' => ['size' => 1], 'issuer_key' => ['size' => 1]];
        $hops = [
            ['domain' => 'd1', 'head' => ['head' => ['n' => 1], 'sig' => 's1', 'cosigs' => [['witness' => 'w1', 'sig' => 'x1']]], 'inclusion' => 'i1',
                'revocation' => ['cap' => ['size' => 5, 'lo' => $l1, 'hi' => $l2], 'issuer_key' => ['size' => 6, 'lo' => $l1]], 'binding' => ['b' => 1]],
            // same head and sig: one table entry, w1 kept once, w2 appended; a non-object binding is dropped
            ['domain' => 'd2', 'head' => ['head' => ['n' => 1], 'sig' => 's1', 'cosigs' => [['witness' => 'w1', 'sig' => 'x1b'], ['witness' => 'w2', 'sig' => 'x2']]],
                'inclusion' => 'i2', 'revocation' => ['cap' => ['size' => 7, 'hi' => $l2], 'issuer_key' => ['size' => 8]], 'binding' => 'nope'],
            // same head, another sig: a new entry
            ['domain' => 'd3', 'head' => ['head' => ['n' => 1], 'sig' => 's2', 'cosigs' => []], 'inclusion' => 'i3',
                'revocation' => ['cap' => ['size' => 9, 'lo' => $l3], 'issuer_key' => ['size' => 1]]],
            // sig + head text collide without the separator ('a' . 12 vs 'a1' . 2): two entries
            ['domain' => 'd4', 'head' => ['head' => 12, 'sig' => 'a', 'cosigs' => []], 'inclusion' => 'i4', 'revocation' => $one],
            ['domain' => 'd5', 'head' => ['head' => 2, 'sig' => 'a1', 'cosigs' => []], 'inclusion' => 'i5', 'revocation' => $one],
            // same sig, another head: a new entry
            ['domain' => 'd6', 'head' => ['head' => ['n' => 2], 'sig' => 's1', 'cosigs' => []], 'inclusion' => 'i6', 'revocation' => $one],
        ];
        $want = [
            'chain' => $chain,
            'heads' => [
                ['head' => ['n' => 1], 'sig' => 's1', 'cosigs' => [['witness' => 'w1', 'sig' => 'x1'], ['witness' => 'w2', 'sig' => 'x2']]],
                ['head' => ['n' => 1], 'sig' => 's2', 'cosigs' => []],
                ['head' => 12, 'sig' => 'a', 'cosigs' => []],
                ['head' => 2, 'sig' => 'a1', 'cosigs' => []],
                ['head' => ['n' => 2], 'sig' => 's1', 'cosigs' => []],
            ],
            'rev_leaves' => [$l1, $l2, $l3],
            'hops' => [
                ['domain' => 'd1', 'head' => 0, 'inclusion' => 'i1', 'revocation' => ['cap' => ['size' => 5, 'lo' => 0, 'hi' => 1], 'issuer_key' => ['size' => 6, 'lo' => 0]],
                    'binding' => ['b' => 1]],
                ['domain' => 'd2', 'head' => 0, 'inclusion' => 'i2', 'revocation' => ['cap' => ['size' => 7, 'hi' => 1], 'issuer_key' => ['size' => 8]]],
                ['domain' => 'd3', 'head' => 1, 'inclusion' => 'i3', 'revocation' => ['cap' => ['size' => 9, 'lo' => 2], 'issuer_key' => ['size' => 1]]],
                ['domain' => 'd4', 'head' => 2, 'inclusion' => 'i4', 'revocation' => $one],
                ['domain' => 'd5', 'head' => 3, 'inclusion' => 'i5', 'revocation' => $one],
                ['domain' => 'd6', 'head' => 4, 'inclusion' => 'i6', 'revocation' => $one],
            ],
            'action' => $action,
            'action_sig' => S::signMeshAction($chain, $action, $leaf),
        ];
        self::assertSame(self::canon($want), Json::canonicalizeLenient(S::assembleMeshProof($chain, $hops, $action, $leaf)));
        $pins = [['domain' => 'd1', 'proof' => ['x' => 1]]];
        self::assertSame(self::canon($want + ['pin_proofs' => $pins]), Json::canonicalizeLenient(S::assembleMeshProof($chain, $hops, $action, $leaf, $pins)));
    }

    public function testSessionGrantRefusalSaltAndEnvelope(): void
    {
        $a = self::args('session-grant-g0');
        $k = new KeyPair(str_repeat("\x07", 32));
        [$session, $root, $map] = [$a->get('session'), $a->get('root'), $a->get('map_digest')];
        $this->refuses('mintSessionGrant: intent_session caveat: seq must be a safe integer in [0, 2147483647]',
            fn() => S::mintSessionGrant($k, $k->public, $session, -1, $root, $map, []));
        $rp = array_replace(Sign::defaultRiskPolicy(), ['bMax' => 2]);
        $r = S::mintSessionGrant($k, $k->public, $session, 0, $root, $map, [['verb' => 'refund', 'resource' => 'orders/*']], agentBinding: ['operator' => 'acme'],
            riskPolicy: $rp);
        self::assertSame(16, strlen(Pca::unb64u($r['goal_salt'])));
        $env = $r['grant']->get('caveats')[0];
        self::assertSame('envelope', $env->get('type'));
        self::assertSame('{"operator":"acme"}', Json::canonicalizeLenient($env->get('agent_binding')));
        self::assertSame(self::canon($rp), Json::canonicalizeLenient($env->get('risk_policy')));
    }

    public function testActionSchemaRefusalAndKeyEntryWithoutPq(): void
    {
        $k = new KeyPair(str_repeat("\x08", 32));
        $this->refuses('signActionSchema: unsupported schema version', fn() => S::signActionSchema(['v' => 3], 'k1', $k));
        $e = S::actionSchemaKeyOf('k1', $k, 'hybrid-ed25519-ml-dsa-65');
        self::assertSame(['kid', 'alg', 'pk'], $e->keys());
        self::assertSame('hybrid-ed25519-ml-dsa-65', $e->get('alg'));
    }

    public function testIntentRequiredBoundaries(): void
    {
        $ir = self::args('intent-required')->get('body');
        $cell = fn(mixed $coords) => S::intentRequiredShapeError(self::with($ir, 'cell', ['verb' => 'refund', 'coords' => $coords]));
        $dims = static function (int $n): array {
            $o = [];
            for ($i = 0; $i < $n; $i++) {
                $o["k$i"] = [0, 1];
            }
            return $o;
        };
        $vals = static fn(int $n): array => array_map(static fn(int $i): string => "v$i", range(0, $n - 1));
        self::assertNull($cell($dims(64)));
        self::assertSame('coords must be an object of 1..64 dimensions', $cell($dims(65)));
        self::assertSame('coords must be an object of 1..64 dimensions', $cell('x'));
        self::assertSame('a coordinate path must be 1..256 characters', $cell(['' => [0, 1]]));
        self::assertNull($cell([str_repeat('a', 256) => [0, 1]]));
        self::assertSame('a coordinate path must be 1..256 characters', $cell([str_repeat('a', 257) => [0, 1]]));
        foreach (['x', [0, 'x'], ['x', 1], ['x', 'y', 1], $vals(257)] as $bad) {
            self::assertSame("coords 'a': an index range [lo, hi] or a value set", $cell(['a' => $bad]));
        }
        self::assertSame("coords 'a': need 0 <= lo <= hi", $cell(['a' => [-1, 5]]));
        self::assertNull($cell(['a' => [3, 3]]));
        self::assertNull($cell(['a' => $vals(256)]));
        self::assertSame('not a pca-intent-required v1', S::intentRequiredShapeError(self::with($ir, 'v', '1')));
        self::assertSame('cell must be {verb, coords}', S::intentRequiredShapeError(self::with($ir, 'cell', 'x')));
        self::assertNull(S::intentRequiredShapeError(self::with($ir, 'expires_at', 0)));
    }

    public function testHybridShareAndKeyEntry(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            self::assertNotSame('1', getenv('PCA_REQUIRE_PQ'), 'ML-DSA-65: OpenSSL >= 3.5 over FFI is required in CI');
            $this->markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $k = new KeyPair(str_repeat("\x09", 32));
        $pq = new PqKeyPair('ML-DSA-65', str_repeat("\x0a", 32));
        $alg = 'hybrid-ed25519-ml-dsa-65';
        $set = [['publicKey' => $k->public, 'role' => 'agent']];
        $s = S::signThresholdShare('agent', $k, 'm', $set, 1, $alg, $pq);
        $msg = "atlas-pca/share/agent\0" . hash('sha256', 'm', true) . Pca::signerSetHashRaw(Sign::n($set)) . chr(1) . "\0atlas-pca/share-suite/v1\0" . $alg;
        self::assertSame(['role', 'publicKey', 'sig', 'alg', 'pq_sig'], $s->keys());
        self::assertSame($alg, $s->get('alg'));
        self::assertTrue(sodium_crypto_sign_verify_detached(Pca::unb64u($s->get('sig')), $msg, Pca::unb64u($k->public)));
        self::assertSame(Pca::b64u($pq->sign($msg)), $s->get('pq_sig'));

        $e = S::actionSchemaKeyOf('k1', $k, $alg, $pq);
        self::assertSame(['kid', 'alg', 'pk', 'pq_pk'], $e->keys());
        self::assertSame($pq->public, $e->get('pq_pk'));
        self::assertSame(['kid', 'alg', 'pk'], S::actionSchemaKeyOf('k1', $k, null, $pq)->keys());
    }
}
