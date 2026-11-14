<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SignersMore.php';
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\Agent;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Pca;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use Atlas\Pca\SignersMore as S;
use Atlas\Pca\UnsupportedSigner;
use PHPUnit\Framework\TestCase;

/** The extra producer-side signers refuse exactly what the reference refuses, with its messages; seeded PQ keys and PQ sub-agents. */
final class SignersMoreTest extends TestCase
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

    public function testPqBindingAndCaution(): void
    {
        $k = new KeyPair(str_repeat("\x02", 32));
        foreach ([0, -1, 1.5, '1', 9007199254740992] as $bad) {
            $this->refuses('signPqBinding: epoch must be a positive safe integer', fn() => S::signPqBinding($k, 'PQ', $bad, 'aud'));
        }
        $this->refuses('signPqBinding: aud (the instance/audience id) is required', fn() => S::signPqBinding($k, 'PQ', 1, ''));
        $b = S::signPqBinding($k, 'PQ', 3, 'aud');
        self::assertSame(['ed', 'pq', 'epoch', 'aud', 'sig'], $b->keys());
        self::assertTrue(sodium_crypto_sign_verify_detached(Pca::unb64u($b->get('sig')), "atlas-pca/pq-binding/v2\0{$k->public}\0PQ\0" . "3\0aud", Pca::unb64u($k->public)));

        $body = self::args('caution-reason')->get('body');
        $this->refuses('signCaution: not an object', fn() => S::signCaution('x', $k));
        $this->refuses('signCaution: action_digest required', fn() => S::signCaution($body->without('action_digest'), $k));
        $this->refuses('signCaution: holder required', fn() => S::signCaution(self::with($body, 'holder', ''), $k));
        foreach ([1.5, -0.1, '0.5'] as $bad) {
            $this->refuses('signCaution: caution must be a finite number in [0,1]', fn() => S::signCaution(self::with($body, 'caution', $bad), $k));
        }
        foreach (['', 'has space', str_repeat('r', 65), 5] as $bad) {
            $this->refuses('signCaution: invalid reason', fn() => S::signCaution(self::with($body, 'reason', $bad), $k));
        }
        self::assertSame(['action_digest', 'caution', 'holder', 'reason', 'sig'], S::signCaution(self::with($body, 'extra', 1), $k)->keys());
        self::assertSame(['action_digest', 'caution', 'holder', 'sig'], S::signCaution($body->without('reason'), $k)->keys());
    }

    public function testShareAndProgressAndEpochRefusals(): void
    {
        $k = new KeyPair(str_repeat("\x03", 32));
        $set = [['publicKey' => $k->public, 'role' => 'agent']];
        foreach ([0, 4] as $t) {
            $this->refuses('signShare: t must be 1, 2 or 3', fn() => S::signThresholdShare('agent', $k, 'm', $set, $t));
        }
        $this->refuses('signShare: malformed signer set', fn() => S::signThresholdShare('agent', $k, 'm', 'nope', 1));
        self::assertSame(['role', 'publicKey', 'sig'], S::signThresholdShare('agent', $k, 'm', $set, 1)->keys());

        $step = self::args('progress-step')->get('step');
        foreach (['goal_commitment', 'action_digest', 'before_digest', 'after_digest', 'seq', 'prev', 'digest'] as $f) {
            $this->refuses("signProgressStep: step.$f is required", fn() => S::signProgressStep($step->without($f), $k));
        }
        $this->refuses('signProgressStep: not an object', fn() => S::signProgressStep([1], $k));

        $ep = self::args('revocation-epoch')->get('body');
        $this->refuses('signRevocationEpoch: missing root', fn() => S::signRevocationEpoch($k, $ep->without('root')));
        self::assertSame($k->public, S::signRevocationEpoch($k, $ep)->get('guardian'));
        $hb = self::args('lease-heartbeat')->get('body');
        $this->refuses('signHeartbeat: seq is required', fn() => S::signHeartbeat($hb->without('seq'), $k));
        self::assertSame(['cap_id', 'seq', 'at', 'holder', 'lease_issued_at', 'sig'], S::signHeartbeat(self::with($hb, 'extra', 1), $k)->keys());
        $this->refuses('signMeshAction: empty chain', fn() => S::signMeshAction([], ['verb' => 'x'], $k));
    }

    public function testSiteDocumentRefusals(): void
    {
        $k = new KeyPair(str_repeat("\x04", 32));
        $ir = self::args('intent-required')->get('body');
        self::assertNull(S::intentRequiredShapeError($ir));
        $cases = [
            ['not an object', 'x'],
            ["unknown member 'zz'", self::with($ir, 'zz', 1)],
            ['not a pca-intent-required v1', self::with($ir, 'v', 2)],
            ['session must be canonical base64url (32 bytes)', self::with($ir, 'session', 'abc')],
            ['cell must be {verb, coords}', self::with($ir, 'cell', ['verb' => 'refund'])],
            ['coords must be an object of 1..64 dimensions', self::with($ir, 'cell', ['verb' => 'refund', 'coords' => new Obj()])],
            ["coords 'a': need 0 <= lo <= hi", self::with($ir, 'cell', ['verb' => 'refund', 'coords' => ['a' => [5, 1]]])],
            ["coords 'a': values must be distinct", self::with($ir, 'cell', ['verb' => 'refund', 'coords' => ['a' => ['x', 'x']]])],
            ["coords 'a': an index range [lo, hi] or a value set", self::with($ir, 'cell', ['verb' => 'refund', 'coords' => ['a' => []]])],
            ["reason must be 'uncertain'", self::with($ir, 'reason', 'sure')],
            ['question_id must match [A-Za-z0-9_-]{1,64}', self::with($ir, 'question_id', 'a b')],
            ['unknown friction tier', self::with($ir, 'friction', 'none')],
            ["delivered_to must be 'wallet' or 'agent'", self::with($ir, 'delivered_to', 'email')],
            ['expires_at must be a non-negative safe integer', self::with($ir, 'expires_at', -1)],
            ['an unsigned body must not carry sig', self::with($ir, 'sig', 'x')],
        ];
        foreach ($cases as [$msg, $body]) {
            self::assertSame($msg, S::intentRequiredShapeError(Sign::n($body)), $msg);
            $this->refuses("signIntentRequired: $msg", fn() => S::signIntentRequired($body, 'k1', $k));
        }
        $signed = S::signIntentRequired($ir, 'k1', $k);
        self::assertSame(['alg' => 'ed25519', 'kid' => 'k1'], ['alg' => $signed->get('sig')->get('alg'), 'kid' => $signed->get('sig')->get('kid')]);

        $this->refuses("unknown signature alg 'rot13'", fn() => S::actionSchemaKeyOf('k1', $k, 'rot13'));
        self::assertSame(['kid', 'alg', 'pk'], S::actionSchemaKeyOf('k1', $k)->keys());
        $this->refuses('signActionSchema: not an object', fn() => S::signActionSchema('x', 'k1', $k));
        $this->refuses('signSessionRoot: not an object', fn() => S::signSessionRoot(5, $k));
        $root = self::args('session-root')->get('body');
        $this->refuses('signSessionRoot: signer is not one of the session principals', fn() => S::signSessionRoot($root, $k));
        $this->refuses('mintSessionGrant: mapDigest must be canonical base64url (32 bytes)',
            fn() => S::mintSessionGrant($k, $k->public, $root->get('session'), 0, $root->get('session'), 'short', []));
        $this->refuses('signLabels: not an object', fn() => S::signLabels('x', $k));
        self::assertSame(['v', 'kind', 'name', 'sig'], S::signFact(['name' => 'n'], $k)->keys());
        $def = self::args('policy-template')->get('def');
        $this->refuses('signTemplate: template v / kind mismatch', fn() => S::signTemplate(self::with($def, 'kind', 'nope'), $k));
        self::assertSame(['def', 'signer', 'sig'], S::signTemplate($def, $k)->keys());
        $ov = self::args('policy-tighten')->get('overlay');
        $this->refuses('signTighten: overlay v / kind mismatch', fn() => S::signTighten(self::with($ov, 'kind', 'nope'), $k));
        self::assertSame(['overlay', 'signer', 'sig'], S::signTighten($ov, $k)->keys());
    }

    public function testOfferSetExactOutputsAndRefusals(): void
    {
        $cases = [];
        foreach (Vectors::load('producer-vectors.json')->get('cases') as $c) {
            $cases[$c->get('name')] = $c;
        }
        $site = new KeyPair(Pca::unb64u(Vectors::load('producer-vectors.json')->get('keys')->get('site')->get('seed'), 32));
        foreach (['offer-set-complete', 'offer-set-partial-page'] as $n) {
            $c = $cases[$n];
            self::assertSame(Json::canonicalizeLenient($c->get('expect')), Json::canonicalizeLenient(S::signOfferSet($c->get('args')->get('body'), $site)), $n);
        }
        foreach (['offer-set-refuses-unsafe-price', 'offer-set-refuses-unsafe-issued-at'] as $n) {
            self::assertSame('canonicalize: integer outside the safe range (|n| > 2^53-1)', $cases[$n]->get('expect')->get('error'));
            try {
                S::signOfferSet($cases[$n]->get('args')->get('body'), $site);
                self::fail("$n: signed an out-of-profile body");
            } catch (JsonError $e) {
                self::assertSame('integer outside the safe range', $e->getMessage(), $n);
            }
        }
        $this->refuses('signOfferSet: not an object', fn() => S::signOfferSet('x', $site));
        $this->refuses('signOfferSet: not an object', fn() => S::signOfferSet([1, 2], $site));
    }

    public function testSeededPqKeysAndPqSubAgents(): void
    {
        $this->refuses('a ML-DSA-65 seed is 32 bytes', fn() => new PqKeyPair('ML-DSA-65', str_repeat('x', 31)));
        $this->refuses('a SLH-DSA-SHA2-128f seed is 48 bytes', fn() => new PqKeyPair('SLH-DSA-SHA2-128f', str_repeat('x', 32)));
        $this->refuses('a SLH-DSA-SHA2-256s seed is 96 bytes', fn() => new PqKeyPair('SLH-DSA-SHA2-256s', str_repeat('x', 48)));
        try {
            new PqKeyPair('FN-DSA-512', str_repeat('x', 48));
            self::fail('an FN-DSA key was generated');
        } catch (UnsupportedSigner $e) {
            self::assertStringStartsWith('unsupported_suite: FN-DSA-512', $e->getMessage());
        }
        if (!OpensslPq::available('ML-DSA-65')) {
            self::assertNotSame('1', getenv('PCA_REQUIRE_PQ'), 'ML-DSA-65: OpenSSL >= 3.5 over FFI is required in CI');
            $this->markTestSkipped('no OpenSSL >= 3.5 over FFI');
        }
        $seed = str_repeat("\x07", 32);
        self::assertSame((new PqKeyPair('ML-DSA-65', $seed))->public, (new PqKeyPair('ML-DSA-65', $seed))->public);
        self::assertNotSame((new PqKeyPair('ML-DSA-65', $seed))->public, (new PqKeyPair('ML-DSA-65'))->public);
        $pq = new PqKeyPair('ML-DSA-65', $seed);
        self::assertSame($pq->sign('m'), $pq->sign('m'));

        $principal = KeyPair::generate();
        $key = KeyPair::generate();
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'g', null, $pq->public)['grant'];
        $parent = new Agent($key, $grant, 'rs-test', null, 0, null, null, Sign::DEFAULT_TTL_MS, 'hybrid-ed25519-ml-dsa-65', $pq);
        foreach ([null, new PqKeyPair('ML-DSA-65', str_repeat("\x08", 32))] as $given) {
            $child = $parent->delegate(KeyPair::generate(), [], $given);
            self::assertNotSame($pq->public, $child->pq->public);
            if ($given !== null) {
                self::assertSame($given->public, $child->pq->public);
            }
            $a = $child->act('refund', 'orders/1')->pcactn;
            self::assertSame($child->pq->public, $a->get('pq_pk'));
            self::assertSame(Pca::holderPqCommitment($child->pq->public), $a->get('cap_chain')[1]->get('holder_pq'));
            $v = Pca::verifyPcactnCore($a, $grant, $a->get('iat')->int(), 'rs-test', insecureSkipPlanRootCheck: true);
            self::assertTrue($v['allow'], (string)($v['reason'] ?? ''));
        }
        $ed = (new Agent($key, $grant, 'rs-test'))->delegate(KeyPair::generate());
        self::assertNull($ed->pq);
        self::assertNull($ed->alg);
    }
}
