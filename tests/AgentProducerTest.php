<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\Agent;
use Atlas\Pca\CaveatLang;
use Atlas\Pca\Escalation;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Passport;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\UnsupportedSigner;
use PHPUnit\Framework\TestCase;

/**
 * The agent / issuer side (src/Agent.php): replays packages/pca/conformance/producer-vectors.json byte for byte (fixed keys, nonces and
 * timestamps; Ed25519 is deterministic) and round-trips everything it produces through this package's verifiers.
 */
final class AgentProducerTest extends TestCase
{
    /** @var array<string,KeyPair> */
    private array $keys = [];

    private static function i(mixed $v): int
    {
        return $v instanceof Num ? $v->int() : (int)$v;
    }

    private function run_(string $op, Obj $a): mixed
    {
        $k = fn(string $n): KeyPair => $this->keys[$n];
        switch ($op) {
            case 'ed25519_sign':
                $kp = KeyPair::fromSeedB64u($a->get('seed'));
                return Obj::of(['public' => $kp->public, 'sig' => Pca::b64u($kp->sign($a->get('message_utf8')))]);
            case 'goal_commit':
                return Obj::of(['commit' => Sign::goalCommit($a->get('goal'), $a->get('salt'))]);
            case 'params_digest':
                return Obj::of(['digest' => Pca::paramsDigest($a->get('params'))]);
            case 'plan_commit':
                return Sign::commitPlan($a->get('nodes'));
            case 'mint_grant':
                $r = Sign::mintGrant($k($a->get('principal')), $k($a->get('holder'))->public, Sign::plain($a->get('envelope')), $a->get('goal'), $a->get('salt'));
                return Obj::of(['grant' => $r['grant'], 'goal_commit' => $r['goal_commit'], 'goal_salt' => $r['goal_salt']]);
            case 'delegate':
                $to = $a->get('to_holder');
                return Sign::delegate($a->get('parent'), $k($a->get('signer')), $to === null ? null : $k($to)->public, $a->get('added_caveats'));
            case 'act':
                $extra = [];
                foreach (['nonce', 'caution', 'rationale_commitment', 'tool_binding', 'fresh_at'] as $n) {
                    if ($a->has($n)) {
                        $extra[$n] = $a->get($n);
                    }
                }
                $p = Sign::buildPcactn($a->get('grant'), $a->get('chain'), $a->get('plan'), $a->get('node_id'), self::i($a->get('counter')), $k($a->get('signer')),
                    $a->get('aud'), $a->get('params'), self::i($a->get('iat')), self::i($a->get('exp')), Sign::DEFAULT_TTL_MS, $extra);
                return Obj::of(['pcactn' => $p, 'header' => Sign::headers($p)['PCA-Action']]);
            case 'fresh_at':
                return Sign::signFreshAt($k($a->get('signer')), $a->get('scope'), $a->get('state'), self::i($a->get('issued_at')));
            case 'escalation_digests':
                $lc = $a->get('last_counter');
                return Obj::of(['policy_digest' => Escalation::policyDigest($a->get('grant')), 'action_digest' => Escalation::actionDigest($a->get('pcactn')),
                    'history_head' => Escalation::historyHead($lc === null ? null : self::i($lc))]);
            case 'sign_escalation_answer':
                $b = $a->get('body');
                return Sign::signEscalationAnswer($k($a->get('signer')), $b, $b->get('decision'), self::i($b->get('iat')), self::i($b->get('expires_at')), $b->get('nonce'));
            case 'sign_discharge':
                $b = $a->get('body');
                return Sign::signDischarge($k($a->get('signer')), $b->get('caveat_id'), $b->get('issuer'), $b->get('cap_hash'), $b->get('claims'),
                    self::i($b->get('iat')), self::i($b->get('not_after')), $b->get('bind'), $b->get('action_digest'), $b->get('nonce'));
            case 'discharge_digest':
                return Obj::of(['digest' => CaveatLang::dischargeDigest($a->get('discharge'))]);
            case 'sign_narrow':
                $b = $a->get('body');
                return Sign::signNarrow($k($a->get('signer')), $b->get('cap_hash'), $b->get('caveats'), self::i($b->get('iat')), self::i($b->get('not_after')),
                    $b->get('action_digest'), $b->get('nonce'));
            case 'sign_passport':
                $pp = Sign::issuePassport($a->get('identity'));
                return Obj::of(['passport' => $pp, 'signed' => Sign::signPassport($pp, $k($a->get('issuer')), $k($a->get('subject'))->public, self::i($a->get('exp')))]);
            case 'sign_workflow':
                return Sign::signWorkflow($k($a->get('signer')), $a->get('body'));
            case 'sign_step_receipt':
                $prev = $a->get('prev');
                return Sign::signStepReceipt($k($a->get('signer')), $a->get('workflow'), $a->get('step'), $a->get('outcome'), $a->get('params_digest'),
                    $a->get('outputs'), self::i($a->get('issued_at')), $prev instanceof Obj ? $prev : null);
            case 'sign_read_grant':
                return Sign::signReadGrant($k($a->get('signer')), $a->get('body'));
            case 'sign_aggregate_grant':
                return Sign::signAggregateGrant($k($a->get('signer')), $a->get('body'));
        }
        $this->fail("unknown op $op");
    }

    public function testVectors(): void
    {
        $doc = Vectors::load('producer-vectors.json');
        foreach ($doc->get('keys')->keys() as $n) {
            $kp = KeyPair::fromSeedB64u($doc->get('keys')->get($n)->get('seed'));
            self::assertSame($doc->get('keys')->get($n)->get('public'), $kp->public, "key $n");
            $this->keys[$n] = $kp;
        }
        $cases = $doc->get('cases');
        self::assertGreaterThanOrEqual(34, count($cases));
        $bad = [];
        foreach ($cases as $c) {
            $want = $c->get('expect');
            if ($c->get('op') === 'act') {
                $want = $want->without('threshold_message');
            }
            // canonical form is the comparison: key order and number spelling are not part of the contract
            if (Json::canonicalizeLenient($this->run_($c->get('op'), $c->get('args'))) !== Json::canonicalizeLenient($want)) {
                $bad[] = $c->get('name');
            }
        }
        self::assertSame([], $bad);
    }

    private function grantFor(KeyPair $principal, KeyPair $agent): Obj
    {
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return Sign::mintGrant($principal, $agent->public, $env, 'refund an order')['grant'];
    }

    private function coreOk(Obj $p, Obj $grant, string $label): void
    {
        $v = Pca::verifyPcactnCore($p, $grant, self::i($p->get('iat')), 'rs-test');
        self::assertTrue($v['allow'], "$label: " . ($v['reason'] ?? ''));
    }

    public function testAgentRoundTripDelegatePlan(): void
    {
        $principal = KeyPair::generate();
        $key = KeyPair::generate();
        $grant = $this->grantFor($principal, $key);
        $agent = new Agent($key, $grant, 'rs-test');
        $a1 = $agent->act('refund', 'orders/1', ['amount_cents' => 500]);
        $a2 = $agent->act('refund', 'orders/1', ['amount_cents' => 500]);
        self::assertSame([1, 2], [self::i($a1->pcactn->get('counter')), self::i($a2->pcactn->get('counter'))]);
        self::assertNotSame($a1->pcactn->get('nonce'), $a2->pcactn->get('nonce'));
        $this->coreOk(Json::parseStrict(Pca::decodePcaHeader($a1->headers['PCA-Action'])), $grant, 'header round trip');
        $t = clone $a1->pcactn;
        $t = $t->without('counter');
        $t->set('counter', new Num('9'));
        self::assertFalse(Pca::verifyPcactnCore($t, $grant, self::i($a1->pcactn->get('iat')), 'rs-test')['allow']);

        $sub = KeyPair::generate();
        $child = $agent->delegate($sub, [Sign::sealedCaveat()]);
        $this->coreOk($child->act('refund', 'orders/2', ['amount_cents' => 1])->pcactn, $grant, 'sub-agent');

        $planned = (new Agent($key, $grant, 'rs-test'))->usePlan([['id' => 'a', 'verb' => 'read', 'resource' => 'x'], ['id' => 'b', 'verb' => 'refund', 'resource' => 'orders/1']]);
        $this->coreOk($planned->act('refund', 'orders/1')->pcactn, $grant, 'plan node');
        $this->expectException(\InvalidArgumentException::class);
        $planned->act('delete', 'everything');
    }

    public function testEscalationAnswerAndPassport(): void
    {
        $principal = KeyPair::generate();
        $key = KeyPair::generate();
        $grant = $this->grantFor($principal, $key);
        $act = (new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/1')->pcactn;
        $now = self::i($act->get('iat'));
        $req = Obj::of(['policy_digest' => Escalation::policyDigest($grant), 'action_digest' => Escalation::actionDigest($act), 'history_head' => Escalation::historyHead(0)]);
        $ans = Sign::signEscalationAnswer($principal, $req, 'allow', $now, $now + 60000);
        $bind = $req;
        self::assertTrue(Escalation::verifyAnswer($ans, [$principal->public], $bind, $now)['ok']);
        $bad = $ans->without('decision');
        $bad->set('decision', 'deny');
        self::assertFalse(Escalation::verifyAnswer($bad, [$principal->public], $bind, $now)['ok']);

        $issuer = KeyPair::generate();
        $pp = Sign::issuePassport(['model_id' => 'm', 'operator' => 'acme', 'hardware_rooted' => false, 'issued_at' => 1800000000000]);
        $sp = Sign::signPassport($pp, $issuer, $key->public, 1800003600000);
        self::assertTrue(Passport::verify($sp, ['trustedIssuers' => [$issuer->public], 'now' => 1800000000500, 'revocation' => static fn() => false])['ok']);
    }

    public function testRefusesBadInput(): void
    {
        $principal = KeyPair::generate();
        $key = KeyPair::generate();
        try {
            Sign::mintGrant($principal, $key->public, ['predicates' => [], 'caveats' => [], 'risk_policy' => []], 'g');
            self::fail('a grant with an empty risk policy was minted');
        } catch (\InvalidArgumentException) {
        }
        try {
            Sign::mintGrant($principal, $key->public, ['predicates' => [], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()], '');
            self::fail('a grant without a goal was minted');
        } catch (\InvalidArgumentException) {
        }
        $hw = Sign::issuePassport(['model_id' => 'm', 'operator' => 'a', 'hardware_rooted' => true, 'issued_at' => 1]);
        try {
            Sign::signPassport($hw, $principal, $key->public, 99);
            self::fail('a hardware-rooted passport was signed without evidence');
        } catch (\InvalidArgumentException) {
        }
        $this->expectException(UnsupportedSigner::class);
        Sign::signArtifact('d', ['v' => 1], $key, 'fn-dsa-512');
    }

    /** The PQ suites sign through OpenSSL >= 3.5 over FFI; CI installs it, so a runtime without it fails this test instead of skipping it. */
    public function testPostQuantumSuitesCrossVerify(): void
    {
        $required = getenv('PCA_REQUIRE_PQ') === '1';
        $suites = [['hybrid-ed25519-ml-dsa-65', 'ML-DSA-65'], ['hybrid-nested-ed25519-ml-dsa-65', 'ML-DSA-65'], ['ml-dsa-87', 'ML-DSA-87'],
            ['hybrid-ed25519-slh-dsa-sha2-128f', 'SLH-DSA-SHA2-128f']];
        foreach ($suites as [$alg, $family]) {
            if (!OpensslPq::available($family)) {
                self::assertFalse($required, "$family: OpenSSL >= 3.5 over FFI is required in CI");
                try {
                    new PqKeyPair($family);
                    self::fail('a PQ key was generated without a backend');
                } catch (UnsupportedSigner) {
                }
                continue;
            }
            $pq = new PqKeyPair($family);
            $principal = KeyPair::generate();
            $key = KeyPair::generate();
            $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
            $grant = Sign::mintGrant($principal, $key->public, $env, 'g', null, $pq->public)['grant'];
            $a = (new Agent($key, $grant, 'rs-test', null, 0, null, null, Sign::DEFAULT_TTL_MS, $alg, $pq))->act('refund', 'orders/1');
            self::assertSame($alg, $a->pcactn->get('alg'));
            $this->coreOk($a->pcactn, $grant, $alg);
            $other = new PqKeyPair($family);
            $f = (new Agent($key, $grant, 'rs-test', null, 0, null, null, Sign::DEFAULT_TTL_MS, $alg, $other))->act('refund', 'orders/1');
            self::assertFalse(Pca::verifyPcactnCore($f->pcactn, $grant, self::i($f->pcactn->get('iat')), 'rs-test')['allow'], "$alg: an uncommitted PQ key verified");
        }
        $this->expectException(UnsupportedSigner::class);
        Sign::signArtifact('d', ['v' => 1], $key = KeyPair::generate(), 'fn-dsa-512');
    }

    // ---- exact-outcome kill tests for the refusal paths, counters, nonces and header encoding (Infection-mutated module) ----

    private function refuses(string $class, string $msg, callable $fn, string $label = ''): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            self::assertInstanceOf($class, $e, $label);
            self::assertSame($msg, $e->getMessage(), $label);
            return;
        }
        self::fail("no exception: $msg $label");
    }

    private static function env(array $over = []): array
    {
        return $over + ['predicates' => [['verb' => 'v', 'resource' => 'r']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
    }

    private static function rp(array $over): array
    {
        return $over + Sign::defaultRiskPolicy();
    }

    public function testSeedsAndSuites(): void
    {
        $I = \InvalidArgumentException::class;
        foreach ([0, 31, 33] as $n) {
            $this->refuses($I, 'an Ed25519 seed is 32 bytes', fn() => new KeyPair(str_repeat('x', $n)), "len $n");
        }
        $seed = str_repeat("\x01", 32);
        $k = new KeyPair($seed);
        self::assertSame($k->public, KeyPair::fromSeedB64u(Pca::b64u($seed))->public);
        $this->refuses($I, 'an Ed25519 seed is 32 canonical base64url bytes', fn() => KeyPair::fromSeedB64u('AAAA'));
        self::assertSame(['public' => $k->public], $k->__debugInfo());
        self::assertSame(64, strlen($k->sign('m')));
        foreach (['fn-dsa-512', 'fn-dsa-1024', 'less-cat1', 'hybrid-ed25519-less-cat1'] as $alg) {
            $this->refuses(UnsupportedSigner::class, "unsupported_suite: $alg", fn() => Sign::signArtifact('d', ['v' => 1], $k, $alg), $alg);
        }
        $this->refuses($I, "unknown signature alg 'rot13'", fn() => Sign::signArtifact('d', ['v' => 1], $k, 'rot13'));
        $this->refuses($I, 'ml-dsa-65 needs a post-quantum key pair', fn() => Sign::signArtifact('d', ['v' => 1], $k, 'ml-dsa-65'));
        self::assertSame(['v', 'sig'], Sign::signArtifact('d', ['v' => 1], $k, 'ed25519')->keys());
        self::assertSame(['v', 'sig'], Sign::signArtifact('d', ['v' => 1], $k)->keys());
    }

    public function testMintGrantRefusals(): void
    {
        $I = \InvalidArgumentException::class;
        $p = KeyPair::generate();
        $h = KeyPair::generate()->public;
        $mg = fn(array $env, string $goal = 'g') => Sign::mintGrant($p, $h, $env, $goal);
        $this->refuses($I, 'mintGrant: goal required', fn() => $mg(self::env(), ''));
        $this->refuses($I, 'mintGrant: envelope.predicates and envelope.caveats required', fn() => $mg(['risk_policy' => Sign::defaultRiskPolicy()]));
        $this->refuses($I, 'mintGrant: risk_policy.weights missing', fn() => $mg(self::env(['risk_policy' => []])));
        $w = Sign::defaultRiskPolicy()['weights'];
        $this->refuses($I, 'mintGrant: risk_policy.weights.alpha must be finite and >= 0', fn() => $mg(self::env(['risk_policy' => self::rp(['weights' => ['alpha' => -1] + $w])])));
        $this->refuses($I, 'mintGrant: risk_policy.theta1 must be finite', fn() => $mg(self::env(['risk_policy' => array_diff_key(Sign::defaultRiskPolicy(), ['theta1' => 1])])));
        $this->refuses($I, 'mintGrant: risk_policy requires 0 <= theta1 <= theta2', fn() => $mg(self::env(['risk_policy' => self::rp(['theta1' => 0.7])])));
        $this->refuses($I, 'mintGrant: risk_policy requires 0 <= theta1 <= theta2', fn() => $mg(self::env(['risk_policy' => self::rp(['theta1' => -0.1])])));
        $this->refuses($I, 'mintGrant: risk_policy.kappa must be > 0', fn() => $mg(self::env(['risk_policy' => self::rp(['kappa' => 0])])));
        $this->refuses($I, 'mintGrant: risk_policy lambda/rho/bMax must be >= 0', fn() => $mg(self::env(['risk_policy' => self::rp(['rho' => -1])])));
        $this->refuses($I, "mintGrant: model_polarity must be 'legacy' when present", fn() => $mg(self::env(['model_polarity' => 'strict'])));
        $g = Sign::mintGrant($p, $h, self::env(), 'g', 'abc');
        self::assertSame('abc', $g['goal_salt']);
        self::assertSame(Sign::goalCommit('g', 'abc'), $g['goal_commit']);
        self::assertSame(16, strlen(Pca::unb64u(Sign::mintGrant($p, $h, self::env(), 'g')['goal_salt'])));
        $cav = $g['grant']->get('caveats')[0];
        self::assertSame('envelope', $cav->get('type'));
        self::assertSame(1, count($cav->get('agent_binding')->keys()) + 1);
        self::assertSame('legacy', Sign::mintGrant($p, $h, self::env(['model_polarity' => 'legacy']), 'g')['grant']->get('caveats')[0]->get('model_polarity'));
    }

    public function testDelegationAppendsOnlyAndPlanRefusals(): void
    {
        $I = \InvalidArgumentException::class;
        $p = KeyPair::generate();
        $k = KeyPair::generate();
        $grant = Sign::mintGrant($p, $k->public, self::env(), 'g')['grant'];
        $add = ['type' => 'budget_alloc', 'limit' => 5];
        $child = Sign::delegate($grant, $k, null, [$add]);
        self::assertCount(2, $child->get('caveats'));
        self::assertSame(Json::canonicalizeStrict($grant->get('caveats')[0]), Json::canonicalizeStrict($child->get('caveats')[0]));
        self::assertSame($k->public, $child->get('holder'));
        self::assertSame($k->public, $child->get('issuer'));
        self::assertSame(Pca::capHash($grant), $child->get('parent'));
        self::assertFalse($child->has('holder_pq'));
        $pq = Sign::mintGrant($p, $k->public, self::env(), 'g', null, 'PQKEY')['grant'];
        self::assertSame(Pca::holderPqCommitment('PQKEY'), $pq->get('holder_pq'));
        self::assertSame($pq->get('holder_pq'), Sign::delegate($pq, $k)->get('holder_pq'));
        self::assertFalse(Sign::delegate($pq, $k, KeyPair::generate()->public)->has('holder_pq'));
        self::assertSame(Pca::holderPqCommitment('OTHER'), Sign::delegate($pq, $k, KeyPair::generate()->public, [], 'OTHER')->get('holder_pq'));

        $node = ['id' => 'a', 'verb' => 'v', 'resource' => 'r'];
        $bp = fn(array $over = []) => Sign::buildPcactn($grant, [$grant], $over['plan'] ?? [$node], $over['node'] ?? 'a', 1, $k, $over['aud'] ?? 'x',
            $over['params'] ?? null, $over['iat'] ?? 1000, $over['exp'] ?? null, $over['ttl'] ?? Sign::DEFAULT_TTL_MS, $over['extra'] ?? []);
        $this->refuses($I, 'buildPcactn: aud (audience) is required', fn() => $bp(['aud' => '']));
        $this->refuses($I, 'buildPcactn: unknown plan node zz', fn() => $bp(['node' => 'zz']));
        $this->refuses($I, "buildPcactn: params do not match plan node a's params_digest", fn() => $bp(['plan' => [$node + ['params_digest' => Pca::paramsDigest(Sign::n(['x' => 1]))]], 'params' => ['x' => 2]]));
        $this->refuses($I, 'commitPlan: duplicate node id a', fn() => Sign::commitPlan([$node, $node]));
        $this->refuses($I, 'commitPlan: empty plan', fn() => Sign::commitPlan([]));
        $x = $bp();
        self::assertSame([1000, 1000 + 20 * 60000, 2, 1], [$x->get('iat')->int(), $x->get('exp')->int(), $x->get('ver')->int(), $x->get('counter')->int()]);
        self::assertSame('reversible', $x->get('action')->get('reversibility_class'));
        self::assertSame(5000, $bp(['exp' => 5000])->get('exp')->int());
        self::assertSame(1007, $bp(['ttl' => 7])->get('exp')->int());
        $e = $bp(['extra' => ['nonce' => 'n', 'caution' => null]]);
        self::assertSame('n', $e->get('nonce'));
        self::assertFalse($e->has('caution'));
    }

    public function testCounterNonceHookAndHeaders(): void
    {
        $p = KeyPair::generate();
        $k = KeyPair::generate();
        $grant = Sign::mintGrant($p, $k->public, self::env(), 'g')['grant'];
        $seen = [];
        $agent = new Agent($k, $grant, 'rs', null, 41, fn() => 5000, function (int $n) use (&$seen): void {
            $seen[] = $n;
        });
        $acts = [$agent->act('v', 'r'), $agent->act('v', 'r'), $agent->act('v', 'r')];
        self::assertSame([42, 43, 44], array_map(fn($a) => $a->pcactn->get('counter')->int(), $acts));
        self::assertSame([42, 43, 44], $seen);
        self::assertCount(3, array_unique(array_map(fn($a) => $a->pcactn->get('nonce'), $acts)));
        foreach ($acts as $a) {
            self::assertSame(16, strlen(Pca::unb64u($a->pcactn->get('nonce'))));
            self::assertSame([5000, 5000 + 20 * 60000, 'rs', 'n1'], [$a->pcactn->get('iat')->int(), $a->pcactn->get('exp')->int(), $a->pcactn->get('aud'), $a->nodeId]);
        }
        $sub = $agent->delegate(KeyPair::generate());
        self::assertSame(1, $sub->act('v', 'r')->pcactn->get('counter')->int());
        self::assertCount(2, $sub->chain());
        self::assertCount(1, $agent->chain());
        self::assertSame('fixed', (new Agent($k, $grant, 'rs'))->act('v', 'r', null, ['nonce' => 'fixed'])->pcactn->get('nonce'));
        $this->refuses(\InvalidArgumentException::class, 'act: no node of the committed plan matches v nope',
            fn() => (new Agent($k, $grant, 'rs'))->usePlan([['id' => 'a', 'verb' => 'v', 'resource' => 'r']])->act('v', 'nope'));

        $act = $acts[0];
        self::assertSame(['PCA-Action'], array_keys($act->headers));
        self::assertStringNotContainsString('=', $act->headers['PCA-Action']);
        self::assertSame(Json::canonicalizeStrict($act->pcactn), Pca::unb64u($act->headers['PCA-Action']));
        $full = Sign::headers($act->pcactn, [Obj::of(['d' => new Num('1')])], Obj::of(['n' => new Num('2')]), Obj::of(['a' => new Num('3')]));
        self::assertSame(['PCA-Action', 'PCA-Discharges', 'PCA-Narrow', 'PCA-Escalation-Answer'], array_keys($full));
        self::assertSame('[{"d":1}]', Pca::unb64u($full['PCA-Discharges']));
        self::assertSame('{"n":2}', Pca::unb64u($full['PCA-Narrow']));
        self::assertSame('{"a":3}', Pca::unb64u($full['PCA-Escalation-Answer']));
        self::assertSame(['PCA-Action'], array_keys(Sign::headers($act->pcactn, [])));
    }

    public function testSignerAnswerAndPassportRefusals(): void
    {
        $I = \InvalidArgumentException::class;
        $k = KeyPair::generate();
        $o = KeyPair::generate();
        foreach ([['signWorkflow', 'signWorkflow'], ['signReadGrant', 'signReadGrant'], ['signAggregateGrant', 'signAggregateGrant']] as [$fn, $w]) {
            $this->refuses($I, "$w: principal is not the signer", fn() => Sign::$fn($o, ['principal' => $k->public]), $fn);
        }
        $req = Obj::of(['policy_digest' => 'a', 'action_digest' => 'b', 'history_head' => 'c']);
        $this->refuses($I, "decision must be 'allow' or 'deny'", fn() => Sign::signEscalationAnswer($o, $req, 'maybe', 1, 2));
        $pp = Sign::issuePassport(['model_id' => 'm', 'operator' => 'o', 'hardware_rooted' => false, 'issued_at' => 10]);
        $hw = Sign::issuePassport(['model_id' => 'm', 'operator' => 'o', 'hardware_rooted' => true, 'issued_at' => 10]);
        $this->refuses($I, 'signPassport: exp must be after nbf', fn() => Sign::signPassport($pp, $o, $k->public, 10));
        $bad = Sign::issuePassport(['model_id' => 'other', 'operator' => 'o', 'hardware_rooted' => false, 'issued_at' => 10]);
        $bad->set('id', $pp->get('id'));
        $this->refuses($I, 'signPassport: passport.id is not the fingerprint of its identity (use issuePassport)', fn() => Sign::signPassport($bad, $o, $k->public, 99));
        $this->refuses($I, 'signPassport: hardware_rooted requires attestation evidence (fail closed)', fn() => Sign::signPassport($hw, $o, $k->public, 99));
        $sp = Sign::signPassport($pp, $o, $k->public, 99);
        self::assertSame([10, 10, 99], [$sp->get('iat')->int(), $sp->get('nbf')->int(), $sp->get('exp')->int()]);
        self::assertSame(30, Sign::signPassport($pp, $o, $k->public, 99, 20, 30)->get('nbf')->int());
    }
}
