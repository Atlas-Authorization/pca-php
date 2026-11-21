<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';
require_once __DIR__ . '/ProducerOps.php';
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\Agent;
use Atlas\Pca\CaveatLang;
use Atlas\Pca\Escalation;
use Atlas\Pca\Facade;
use Atlas\Pca\IntentV2;
use Atlas\Pca\IntentWb;
use Atlas\Pca\SignersMore;
use Atlas\Pca\Json;
use Atlas\Pca\JsonError;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Passport;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use Atlas\Pca\UnsupportedSigner;
use PHPUnit\Framework\Attributes\DataProvider;
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

    /** Every case of producer-vectors.json through the shared producer dispatch; a refusal case must refuse with the reference's text. */
    public function testVectors(): void
    {
        $doc = Vectors::load('producer-vectors.json');
        foreach ($doc->get('keys')->keys() as $n) {
            $kp = KeyPair::fromSeedB64u($doc->get('keys')->get($n)->get('seed'));
            self::assertSame($doc->get('keys')->get($n)->get('public'), $kp->public, "key $n");
            $this->keys[$n] = $kp;
        }
        $ops = new ProducerOps($doc->get('keys'));
        $cases = $doc->get('cases');
        self::assertGreaterThanOrEqual(89, count($cases));
        $bad = [];
        $refused = 0;
        foreach ($cases as $c) {
            $want = $c->get('expect');
            if ($c->get('op') === 'act') {
                $want = $want->without('threshold_message');
            }
            try {
                $got = $ops->run($c->get('op'), $c->get('args'));
            } catch (NotProduced $e) {
                $bad[] = $c->get('name') . ': op not produced';
                continue;
            } catch (JsonError $e) {
                // the canonical profile's wording is per-language: a reference `canonicalize: ...` refusal only has to refuse
                $refused++;
                if (!$want->has('error') || !str_starts_with($want->get('error'), 'canonicalize: ')) {
                    $bad[] = $c->get('name') . ': ' . $e->getMessage();
                }
                continue;
            } catch (\InvalidArgumentException $e) {
                $refused++;
                if (!$want->has('error') || $e->getMessage() !== $want->get('error')) {
                    $bad[] = $c->get('name') . ': ' . $e->getMessage();
                }
                continue;
            }
            // canonical form is the comparison: key order and number spelling are not part of the contract
            if ($want->has('error') || Json::canonicalizeLenient($got) !== Json::canonicalizeLenient($want)) {
                $bad[] = $c->get('name');
            }
        }
        self::assertSame([], $bad);
        self::assertSame(count(array_filter($cases, static fn(Obj $c) => $c->get('expect')->has('error'))), $refused);
    }

    /** The PQ family a producer-pq-vectors.json case needs ('ed25519' for none). */
    private static function familyOf(Obj $c): string
    {
        $src = $c->get('op') === 'pq_keygen' ? $c->get('args')->get('family') : $c->get('alg');
        return preg_match('/(ml-dsa-\d+|slh-dsa-sha2-\d+[fs]|fn-dsa-\d+)/', $src, $m) === 1 ? ProducerOps::FAMILIES[$m[1]] : 'ed25519';
    }

    /** @return array<string, array{string}> one data set per family (each stays well inside the per-test deadline) */
    public static function pqFamilies(): array
    {
        $out = [];
        foreach (['ed25519', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f', 'SLH-DSA-SHA2-256s', 'FN-DSA-512', 'FN-DSA-1024'] as $f) {
            $out[$f] = [$f];
        }
        return $out;
    }

    /**
     * producer-pq-vectors.json: every case that lists this SDK in `exact` is reproduced byte for byte (seeded keys, deterministic
     * ML-DSA / SLH-DSA); a suite this SDK does not sign (FN-DSA) is refused with unsupported_suite, never signed differently.
     * CI sets PCA_REQUIRE_PQ=1 where OpenSSL >= 3.5 is reachable over FFI: a missing backend then FAILS instead of skipping.
     */
    #[DataProvider('pqFamilies')]
    public function testPostQuantumVectors(string $family): void
    {
        $doc = Vectors::load('producer-pq-vectors.json');
        $ops = new ProducerOps($doc->get('ed_keys'), $doc->get('pq_keys'));
        $cases = array_values(array_filter($doc->get('cases'), static fn(Obj $c) => self::familyOf($c) === $family));
        self::assertNotSame([], $cases, $family);
        if ($family !== 'ed25519' && !str_starts_with($family, 'FN-DSA') && !OpensslPq::available($family)) {
            self::assertNotSame('1', getenv('PCA_REQUIRE_PQ'), "$family: OpenSSL >= 3.5 over FFI is required in CI");
            $this->markTestSkipped("$family: no OpenSSL >= 3.5 over FFI");
        }
        $bad = [];
        foreach ($cases as $c) {
            $name = $c->get('name');
            if (!in_array('php', $c->get('exact'), true)) {
                try {
                    $ops->run($c->get('op'), $c->get('args'));
                    $bad[] = "$name: signed a suite outside this SDK";
                } catch (UnsupportedSigner $e) {
                    self::assertStringStartsWith('unsupported_suite: ', $e->getMessage(), $name);
                }
                continue;
            }
            $got = Json::canonicalizeLenient($ops->run($c->get('op'), $c->get('args')));
            if ($got !== Json::canonicalizeLenient($c->get('expect'))) {
                $bad[] = $name;
            } elseif ($c->get('op') === 'suite_sign' && Json::canonicalizeLenient($ops->run($c->get('op'), $c->get('args'))) !== $got) {
                $bad[] = "$name: signing twice gave different bytes";
            }
        }
        self::assertSame([], $bad);
        self::assertSame(str_starts_with($family, 'FN-DSA'), array_filter($cases, static fn(Obj $c) => !in_array('php', $c->get('exact'), true)) !== []);
    }

    private function grantFor(KeyPair $principal, KeyPair $agent): Obj
    {
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return Sign::mintGrant($principal, $agent->public, $env, 'refund an order')['grant'];
    }

    private function coreOk(Obj $p, Obj $grant, string $label): void
    {
        $v = Pca::verifyPcactnCore($p, $grant, self::i($p->get('iat')), 'rs-test', insecureSkipPlanRootCheck: true);
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
        self::assertFalse(Pca::verifyPcactnCore($t, $grant, self::i($a1->pcactn->get('iat')), 'rs-test', insecureSkipPlanRootCheck: true)['allow']);

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
            self::assertFalse(Pca::verifyPcactnCore($f->pcactn, $grant, self::i($f->pcactn->get('iat')), 'rs-test', insecureSkipPlanRootCheck: true)['allow'], "$alg: an uncommitted PQ key verified");
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
        // risk.ts Number.isFinite: a numeric string, INF and NAN are not finite numbers
        foreach (['1', INF, NAN] as $bad) {
            $this->refuses($I, 'mintGrant: risk_policy.weights.alpha must be finite and >= 0', fn() => $mg(self::env(['risk_policy' => self::rp(['weights' => ['alpha' => $bad] + $w])])));
            $this->refuses($I, 'mintGrant: risk_policy.kappa must be finite', fn() => $mg(self::env(['risk_policy' => self::rp(['kappa' => $bad])])));
        }
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
        // a body that is not well-formed is refused before the principal is compared
        $this->refuses($I, 'signWorkflow: malformed workflow', fn() => Sign::signWorkflow($o, ['principal' => $k->public]));
        $this->refuses($I, 'signReadGrant: malformed grant', fn() => Sign::signReadGrant($o, ['principal' => $k->public]));
        $this->refuses($I, 'signAggregateGrant: malformed grant', fn() => Sign::signAggregateGrant($o, ['principal' => $k->public]));
        $doc = Vectors::load('producer-vectors.json');
        $args = static fn(string $name) => array_values(array_filter($doc->get('cases'), static fn(Obj $c) => $c->get('name') === $name))[0]->get('args');
        $this->refuses($I, 'signWorkflow: principal is not the signer', fn() => Sign::signWorkflow($o, $args('workflow-sign')->get('body')));
        // a read grant names its principal inside the validated body: another signer makes it malformed
        $this->refuses($I, 'signReadGrant: malformed grant', fn() => Sign::signReadGrant($o, $args('read-grant-sign')->get('body')));
        $this->refuses($I, 'signAggregateGrant: malformed grant', fn() => Sign::signAggregateGrant($o, $args('aggregate-grant-sign')->get('body')));
        $req = Obj::of(['policy_digest' => 'a', 'action_digest' => 'b', 'history_head' => 'c']);
        $this->refuses($I, "decision must be 'allow' or 'deny'", fn() => Sign::signEscalationAnswer($o, $req, 'maybe', 1, 2));
        // a signed artifact every verifier would refuse is never handed out: a short caller nonce fails the reference shape check
        $dg = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE';
        $okReq = Obj::of(['policy_digest' => $dg, 'action_digest' => $dg, 'history_head' => $dg]);
        $cav = [['type' => 'expires', 'at' => 2000]];
        $nonceMsg = ': nonce must be canonical base64url of at least 16 bytes';
        $this->assertSame(22, strlen(Sign::signEscalationAnswer($o, $okReq, 'allow', 1, 2)->get('nonce')));
        $this->refuses($I, 'signEscalationAnswer' . $nonceMsg, fn() => Sign::signEscalationAnswer($o, $okReq, 'allow', 1, 2, 'n1'));
        $this->assertSame(22, strlen(Sign::signDischarge($o, 'd1', 'idp', $dg, ['tier' => 'gold'], 1000, 2000)->get('nonce')));
        $this->refuses($I, 'signDischarge' . $nonceMsg, fn() => Sign::signDischarge($o, 'd1', 'idp', $dg, ['tier' => 'gold'], 1000, 2000, 'chain_hop', null, 'n1'));
        $this->assertSame(22, strlen(Sign::signNarrow($o, $dg, $cav, 1000, 2000)->get('nonce')));
        $this->refuses($I, 'signNarrow' . $nonceMsg, fn() => Sign::signNarrow($o, $dg, $cav, 1000, 2000, null, 'n1'));
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

    // ---- natives -> reference: this SDK's signed artifacts for the reference verifier ----------------------------------------

    private const V3_AUD = 'rs-php-producer';
    private const V3_NOW = 1800000001000;
    /** suite => PQ family (null: Ed25519 alone), every suite this SDK signs */
    private const V3_SUITES = ['ed25519' => null, 'hybrid-ed25519-ml-dsa-65' => 'ML-DSA-65', 'hybrid-ed25519-ml-dsa-87' => 'ML-DSA-87',
        'hybrid-ed25519-slh-dsa-sha2-128f' => 'SLH-DSA-SHA2-128f', 'hybrid-ed25519-slh-dsa-sha2-256s' => 'SLH-DSA-SHA2-256s',
        'hybrid-nested-ed25519-ml-dsa-65' => 'ML-DSA-65', 'ml-dsa-65' => 'ML-DSA-65', 'ml-dsa-87' => 'ML-DSA-87',
        'slh-dsa-sha2-128f' => 'SLH-DSA-SHA2-128f', 'slh-dsa-sha2-256s' => 'SLH-DSA-SHA2-256s'];

    private static function seeded(string $family, int $byte): PqKeyPair
    {
        return new PqKeyPair($family, str_repeat(chr($byte), OpensslPq::SEED_BYTES[$family]));
    }

    private static function pins(KeyPair $k, ?PqKeyPair $pq = null, array $extra = []): Obj
    {
        $p = Obj::of($extra + ['pk' => $k->public]);
        if ($pq !== null) {
            $p->set('pq_pk', $pq->public);
        }
        return $p;
    }

    /**
     * One PCActn per suite this runtime signs and one from a delegated sub-agent under each (a PQ sub-agent signs with its OWN key,
     * committed in its hop), one facade act with params, and each artifact kind under Ed25519 and, when available, a hybrid
     * ML-DSA suite.
     * @return array{lang:string, aud:string, now:int, cases:list<array<string,mixed>>}
     */
    private function buildNativeCases(ProducerOps $ops, Obj $doc): array
    {
        $required = getenv('PCA_REQUIRE_PQ') === '1';
        $args = static fn(string $name): Obj => array_values(array_filter($doc->get('cases'), static fn(Obj $c) => $c->get('name') === $name))[0]->get('args');
        $t0 = self::V3_NOW - 1000;
        $principal = $ops->key('principal');
        $agentKey = $ops->key('agent');
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'agent_binding' => new Obj(),
            'risk_policy' => Sign::defaultRiskPolicy()];
        $cases = [];
        $i = 0;
        foreach (self::V3_SUITES as $alg => $family) {
            $i++;
            if ($family !== null && !OpensslPq::available($family)) {
                self::assertFalse($required, "$family: OpenSSL >= 3.5 over FFI is required in CI");
                continue;
            }
            $pq = $family === null ? null : self::seeded($family, $i);
            $grant = Sign::mintGrant($principal, $agentKey->public, $env, 'refund an order', 's', $pq?->public)['grant'];
            $a = new Agent($agentKey, $grant, self::V3_AUD, null, 0, static fn(): int => $t0, null, Sign::DEFAULT_TTL_MS, $family === null ? null : $alg, $pq);
            $cases[] = ['kind' => 'pcactn', 'alg' => $alg, 'grant' => $grant, 'pcactn' => $a->act('refund', 'orders/1', ['amount' => 5])->pcactn];
            $sub = $a->delegate($ops->key('subagent'), [['type' => 'budget_alloc', 'limit' => 5]], $family === null ? null : self::seeded($family, 100 + $i));
            $cases[] = ['kind' => 'pcactn', 'alg' => $alg, 'grant' => $grant, 'pcactn' => $sub->act('refund', 'orders/2', ['amount' => 1])->pcactn];
        }
        $h = Facade::createAgent($principal, 'refund order 1', ['stripe' => ['refund']], ['refund' => '$500/day'], holder: $agentKey, aud: self::V3_AUD, now: $t0);
        $h->provenance->principal('refund order 1');
        $cases[] = ['kind' => 'pcactn', 'alg' => 'ed25519', 'grant' => $h->grant,
            'pcactn' => $h->act('stripe.refund', 'charge:ch_1', ['amount' => 42, 'currency' => 'usd'], now: $t0)['pcactn']];

        $variants = [['ed25519', null, null]];
        if (OpensslPq::available('ML-DSA-65')) {
            $variants[] = ['hybrid-ed25519-ml-dsa-65', self::seeded('ML-DSA-65', 42), self::seeded('ML-DSA-65', 43)];
        } else {
            self::assertFalse($required, 'ML-DSA-65: OpenSSL >= 3.5 over FFI is required in CI');
        }
        $site = $ops->key('site');
        $guardian = $ops->key('guardian');
        $oracle = $ops->key('oracle');
        foreach ($variants as [$alg, $pq, $pq2]) {
            $al = $pq === null ? null : $alg;
            $b = $args('escalation-answer-allow')->get('body');
            $cases[] = ['kind' => 'escalation_answer', 'alg' => $alg, 'pins' => self::pins($principal, $pq), 'artifact' => Sign::signEscalationAnswer($principal, $b,
                $b->get('decision'), $b->get('iat')->int(), $b->get('expires_at')->int(), $b->get('nonce'), $al, $pq)];
            $cases[] = ['kind' => 'revocation_epoch', 'alg' => $alg, 'pins' => self::pins($guardian, $pq2),
                'artifact' => SignersMore::signRevocationEpoch($guardian, $args('revocation-epoch')->get('body'), $al, $pq2)];
            $cases[] = ['kind' => 'session_root', 'alg' => $alg, 'pins' => self::pins($principal, $pq),
                'artifact' => SignersMore::signSessionRoot($args('session-root')->get('body'), $principal, $al, $pq)];
            $cases[] = ['kind' => 'action_schema', 'alg' => $alg, 'pins' => self::pins($site, $pq2, ['kid' => 'site-k1', 'alg' => $alg]),
                'artifact' => SignersMore::signActionSchema($args('action-schema')->get('doc'), 'site-k1', $site, $al, $pq2)];
            $cases[] = ['kind' => 'intent_required', 'alg' => $alg, 'pins' => self::pins($site, $pq2, ['kid' => 'site-k1', 'alg' => $alg]),
                'artifact' => SignersMore::signIntentRequired($args('intent-required')->get('body'), 'site-k1', $site, $al, $pq2)];
            $lb = $args('labels')->get('body');
            $cases[] = ['kind' => 'labels', 'alg' => $alg, 'pins' => self::pins($site, $pq2, ['kid' => $lb->get('kid'), 'site' => $lb->get('site')]),
                'artifact' => SignersMore::signLabels($lb, $site, $al, $pq2)];
            $cases[] = ['kind' => 'fact', 'alg' => $alg, 'pins' => self::pins($oracle, $pq),
                'artifact' => SignersMore::signFact($args('fact-integer')->get('body'), $oracle, $al, $pq)];
        }
        $cases[] = ['kind' => 'caution', 'alg' => 'ed25519', 'pins' => self::pins($agentKey),
            'artifact' => SignersMore::signCaution($args('caution-reason')->get('body'), $agentKey)];
        $cases[] = ['kind' => 'pq_binding', 'alg' => 'ed25519', 'pins' => self::pins($agentKey),
            'artifact' => SignersMore::signPqBinding($agentKey, $args('pq-binding')->get('pq_pk'), 1, self::V3_AUD)];
        return ['lang' => 'php', 'aud' => self::V3_AUD, 'now' => self::V3_NOW, 'cases' => $cases];
    }

    private static function edOk(string $pk, string $msg, string $sig): bool
    {
        $p = Pca::unb64u($pk, 32);
        $s = Pca::unb64u($sig, 64);
        return $p !== null && $s !== null && sodium_crypto_sign_verify_detached($s, $msg, $p);
    }

    /** This package's own verifier for each kind (the reference verifies the same file). */
    private static function selfCheck(array $c): bool
    {
        $k = $c['kind'];
        $a = $c['artifact'] ?? null;
        $p = $c['pins'] ?? new Obj();
        $now = self::V3_NOW;
        $pin = Obj::of(['pk' => $p->get('pk')]);
        if ($p->has('pq_pk')) {
            $pin->set('pq_pk', $p->get('pq_pk'));
        }
        switch ($k) {
            case 'pcactn':
                return Pca::verifyPcactnCore($c['pcactn'], $c['grant'], $now, self::V3_AUD, insecureSkipPlanRootCheck: true)['allow'] === true;
            case 'escalation_answer':
                $bind = Obj::of(['policy_digest' => $a->get('policy_digest'), 'action_digest' => $a->get('action_digest'), 'history_head' => $a->get('history_head')]);
                return Escalation::verifyAnswer($a, [$pin], $bind, $now)['ok'] === true;
            case 'revocation_epoch':
                return IntentV2::checkRevocationEpoch($a, $p->get('pk'), $now, $a->get('grant_ref'), $p->has('pq_pk') ? $p->get('pq_pk') : null)['ok'] === true;
            case 'session_root':
                return IntentV2::verifySessionRoot($a, $p->has('pq_pk') ? Obj::of([$p->get('pk') => $p->get('pq_pk')]) : new Obj())['ok'] === true;
            case 'action_schema':
                return IntentV2::verifyActionSchema($a, [$p])['ok'] === true;
            case 'intent_required': // no verifier in this package (host / wallet tooling): the classical half and the pinning are checked here
                $sig = $a->get('sig');
                return $sig->get('kid') === $p->get('kid') && $sig->get('alg') === $p->get('alg') && $now <= $a->get('expires_at')->int()
                    && self::edOk($p->get('pk'), SignersMore::INTENT_REQUIRED_DOMAIN . Json::canonicalizeStrict($a->without('sig')), $sig->get('value'))
                    && $sig->has('pq_value') === $p->has('pq_pk');
            case 'labels':
                return IntentWb::verifyLabels($a, [$p]) === null;
            case 'fact':
                return IntentWb::validateFactWire($a) === null && IntentWb::verifyArtifactSig(IntentWb::FACT_DOMAIN, $a, $pin);
            case 'caution':
                return $a->get('holder') === $p->get('pk')
                    && self::edOk($p->get('pk'), Json::canonicalizeLenient(Obj::of(['d' => SignersMore::CAUTION_DOMAIN, 'b' => $a->without('sig')])), $a->get('sig'));
            case 'pq_binding':
                return $a->get('ed') === $p->get('pk') && self::edOk($p->get('pk'),
                    SignersMore::PQ_BINDING_DOMAIN . $a->get('ed') . "\0" . $a->get('pq') . "\0" . $a->get('epoch')->int() . "\0" . $a->get('aud'), $a->get('sig'));
        }
        return false;
    }

    /** Builds this SDK's artifacts for the reference verifier, checks each here, and with PCA_PRODUCER_OUT set (CI) writes them there. */
    public function testNativeProducerFile(): void
    {
        $doc = Vectors::load('producer-vectors.json');
        $ops = new ProducerOps($doc->get('keys'));
        $file = $this->buildNativeCases($ops, $doc);
        $cases = $file['cases'];
        $kinds = array_values(array_unique(array_map(static fn(array $c) => $c['kind'], $cases)));
        sort($kinds);
        self::assertSame(['action_schema', 'caution', 'escalation_answer', 'fact', 'intent_required', 'labels', 'pcactn', 'pq_binding', 'revocation_epoch',
            'session_root'], $kinds);
        $bad = [];
        foreach ($cases as $c) {
            if (!self::selfCheck($c)) {
                $bad[] = "{$c['kind']} {$c['alg']}";
            }
        }
        self::assertSame([], $bad);
        // a PQ sub-agent signs with its own key, committed in its hop, never with the parent's
        $pcactns = array_values(array_filter($cases, static fn(array $c) => $c['kind'] === 'pcactn'));
        $subs = 0;
        foreach ($pcactns as $j => $c) {
            $chain = $c['pcactn']->get('cap_chain');
            if (count($chain) !== 2) {
                continue;
            }
            $subs++;
            if ($c['alg'] !== 'ed25519') {
                self::assertSame(Pca::holderPqCommitment($c['pcactn']->get('pq_pk')), $chain[1]->get('holder_pq'), $c['alg']);
                self::assertNotSame($pcactns[$j - 1]['pcactn']->get('pq_pk'), $c['pcactn']->get('pq_pk'), $c['alg']);
            }
        }
        self::assertSame(intdiv(count($pcactns), 2), $subs);
        $out = getenv('PCA_PRODUCER_OUT');
        if (is_string($out) && $out !== '') {
            $json = Json::canonicalizeLenient(Sign::n($file));
            self::assertNotFalse(file_put_contents($out, $json));
        }
    }
}
