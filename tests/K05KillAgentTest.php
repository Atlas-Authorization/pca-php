<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Agent.php';

use Atlas\Pca\Agent;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslPq;
use Atlas\Pca\Passport;
use Atlas\Pca\PqKeyPair;
use Atlas\Pca\Sign;
use Atlas\Pca\UnsupportedSigner;
use Atlas\Pca\Workflow;
use PHPUnit\Framework\TestCase;

/** Exact-outcome kill tests of the producer side (src/Agent.php): value model, defaults, plan proofs, suites, passports, receipts. */
final class K05KillAgentTest extends TestCase
{
    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    private static function refuses(string $class, string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\Throwable $e) {
            self::assertInstanceOf($class, $e);
            self::assertSame($msg, $e->getMessage());
            return;
        }
        self::fail("no exception: $msg");
    }

    private static function env(array $over = []): array
    {
        return $over + ['predicates' => [['verb' => 'v', 'resource' => 'r']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
    }

    private static function grant(): Obj
    {
        return Sign::mintGrant(self::kp(1), self::kp(2)->public, self::env(), 'g', 's')['grant'];
    }

    private static function nowMs(): int
    {
        return (int)(microtime(true) * 1000);
    }

    /** @return list<string> */
    private static function sides(Obj $proof): array
    {
        return array_map(static fn(Obj $s): string => $s->get('side'), $proof->get('path'));
    }

    public function testPublicSurface(): void
    {
        // KeyPair::sign and Sign::delegate share a name with a later method in the file (PqKeyPair::sign, Agent::delegate)
        foreach ([[KeyPair::class, 'sign'], [Sign::class, 'delegate'], [Sign::class, 'mintRoot'], [Sign::class, 'signPcactn'],
                     [Sign::class, 'needsDischargeCaveat'], [Sign::class, 'maxUsesCaveat'], [Sign::class, 'passportFingerprint'], [Sign::class, 'wfOutput']] as [$c, $m]) {
            $this->assertTrue((new \ReflectionMethod($c, $m))->isPublic(), "$c::$m");
        }
        $this->assertSame(64, strlen(self::kp(1)->sign('m')));
        $this->assertSame(['type' => 'needs_discharge', 'id' => 'c', 'issuer' => 'i', 'issuer_class' => 'k', 'bind' => 'chain_hop', 'ttl_ms' => 300000, 'require' => ['a' => 1]],
            Sign::needsDischargeCaveat('c', 'i', 'k', ['a' => 1]));
        $this->assertSame(['type' => 'max_uses', 'id' => 'c', 'n' => 3, 'until' => 99], Sign::maxUsesCaveat('c', 3, 99));
        $this->assertSame(['weights' => ['alpha' => 0.25, 'beta' => 0.2, 'gamma' => 0.2, 'delta' => 0.2, 'epsilon' => 0.1, 'zeta' => 0.05],
            'theta1' => 0.25, 'theta2' => 0.6, 'kappa' => 1, 'lambda' => 0.0005, 'rho' => 0.5, 'bMax' => 1], Sign::defaultRiskPolicy());
        $id = ['model_id' => 'm', 'operator' => 'op', 'hardware_rooted' => false];
        $this->assertSame(Passport::fingerprint(Sign::issuePassport($id)), Sign::passportFingerprint($id));
        self::refuses(\InvalidArgumentException::class, 'expected a JSON object', static fn() => Sign::passportFingerprint('x'));
        $p = Sign::signPcactn(['v' => 1], self::kp(3));
        $this->assertTrue(is_string($p->get('sig')));
    }

    public function testValueModel(): void
    {
        self::refuses(\InvalidArgumentException::class, 'non-finite number', static fn() => Sign::n(INF));
        $this->assertSame('2', Sign::n(2.0)->lexeme);
        $this->assertSame('-2', Sign::n(-2.0)->lexeme);
        $this->assertSame('0.5', Sign::n(0.5)->lexeme);
        // at 1e15 the float keeps its float spelling (a fraction or an exponent), never the bare integer digits
        $this->assertMatchesRegularExpression('/[.eE]/', Sign::n(1e15)->lexeme);
        $o = Sign::n(['a' => 1, 5 => 2]);
        $this->assertSame(['a', '5'], $o->keys());
        $this->assertSame([1, 2.5], Sign::plain([new Num('1'), new Num('2.5')]));
    }

    public function testRiskPolicyZeroBoundariesAndOptionalMembers(): void
    {
        $rp = ['weights' => ['alpha' => 0, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0],
            'theta1' => 0, 'theta2' => 0, 'kappa' => 1, 'lambda' => 0, 'rho' => 0, 'bMax' => 0];
        $g = Sign::mintGrant(self::kp(1), 'h', self::env(['risk_policy' => $rp, 'objective_risk' => ['x' => 1]]), 'g', 's')['grant'];
        $this->assertTrue($g->get('caveats')[0]->has('objective_risk'));
    }

    public function testChainAndNonce(): void
    {
        $cap = Sign::mintRoot(self::kp(1), 'h', [], null, 'ed25519');
        $this->assertFalse($cap->has('alg'));
        $this->assertFalse($cap->has('pq_pk'));
        $child = Sign::delegate(Obj::of(['caveats' => []]), self::kp(1), 'h2');
        $this->assertSame('', $child->get('issuer'));
        $this->assertSame('h2', $child->get('holder'));
        $d = Sign::signDischarge(self::kp(1), 'c', 'l', 'ch', [], 1, 2);
        $this->assertSame(22, strlen($d->get('nonce')));
        $n = Sign::signNarrow(self::kp(1), 'ch', [], 1, 2, 'ad', 'nn');
        $this->assertSame('ad', $n->get('action_digest'));
    }

    public function testPlanProofs(): void
    {
        $node = static fn(string $id): array => ['id' => $id, 'verb' => 'v', 'resource' => 'r'];
        $four = Sign::commitPlan([$node('a'), $node('b'), $node('c'), $node('d')])->get('proofs');
        $this->assertSame(['R', 'R'], self::sides($four->get('a')));
        $this->assertSame(['R', 'L'], self::sides($four->get('c')));
        $this->assertSame(['L', 'L'], self::sides($four->get('d')));
        $five = Sign::commitPlan([$node('a'), $node('b'), $node('c'), $node('d'), $node('e')])->get('proofs');
        $this->assertSame(['R', 'R', 'R'], self::sides($five->get('a')));
        $this->assertSame(['L'], self::sides($five->get('e')));
        // ids are compared as strings: false and a missing id are both ""
        self::refuses(\InvalidArgumentException::class, 'commitPlan: duplicate node id ',
            static fn() => Sign::commitPlan([['id' => false, 'verb' => 'v', 'resource' => 'r'], ['verb' => 'v', 'resource' => 'r']]));
        $this->assertTrue(Sign::commitPlan([['id' => false, 'verb' => 'v', 'resource' => 'r']])->get('proofs')->has(''));
    }

    public function testDefaultClockAndExtraKeys(): void
    {
        $g = self::grant();
        $before = self::nowMs();
        $p = Sign::buildPcactn($g, [$g], [['id' => 'n1', 'verb' => 'v', 'resource' => 'r']], 'n1', 1, self::kp(2), 'aud', null, null, null, 1000, [7 => 'x']);
        $after = self::nowMs();
        $iat = $p->get('iat');
        $this->assertTrue($iat->isInt());
        $this->assertGreaterThanOrEqual($before, $iat->int());
        $this->assertLessThanOrEqual($after, $iat->int());
        $this->assertSame($iat->int() + 1000, $p->get('exp')->int());
        $this->assertSame('x', $p->get('7'));

        $before = self::nowMs();
        $a = (new Agent(self::kp(2), $g, 'aud'))->act('v', 'r')->pcactn->get('iat');
        $after = self::nowMs();
        $this->assertTrue($a->isInt());
        $this->assertGreaterThanOrEqual($before, $a->int());
        $this->assertLessThanOrEqual($after, $a->int());
    }

    public function testAgentPlanPickAndDelegationChain(): void
    {
        $g = self::grant();
        $agent = (new Agent(self::kp(2), $g, 'aud', null, 0, static fn() => 5000))
            ->usePlan([['id' => 'n1', 'verb' => 'v', 'resource' => 'r'], ['id' => 'n2', 'verb' => 'v', 'resource' => 'r']]);
        $this->assertSame('n1', $agent->act('v', 'r')->nodeId);
        $odd = (new Agent(self::kp(2), $g, 'aud', null, 0, static fn() => 5000))->usePlan([['id' => false, 'verb' => 'v', 'resource' => 'r']]);
        self::refuses(\InvalidArgumentException::class, 'buildPcactn: unknown plan node ', static fn() => $odd->act('v', 'r'));
        $two = (new Agent(self::kp(2), $g, 'aud'))->delegate(self::kp(3))->delegate(self::kp(4));
        $chain = $two->chain();
        $this->assertCount(3, $chain);
        $this->assertSame(self::kp(3)->public, $chain[1]->get('holder'));
        $this->assertSame(self::kp(4)->public, $chain[2]->get('holder'));
    }

    public function testPassportTimesAndEvidence(): void
    {
        $iss = self::kp(1);
        $pp = Sign::issuePassport(['model_id' => 'm', 'operator' => 'op', 'hardware_rooted' => false, 'issued_at' => 5]);
        $this->assertSame('100', Sign::signPassport($pp, $iss, 's', 1000, 100)->get('iat')->lexeme);
        $bare = Sign::issuePassport(['model_id' => 'm', 'operator' => 'op', 'hardware_rooted' => false]);
        $sp = Sign::signPassport($bare, $iss, 's', 1000);
        $this->assertSame('0', $sp->get('iat')->lexeme);
        $this->assertSame('0', $sp->get('nbf')->lexeme);
        $noAt = Sign::signPassport($bare, $iss, 's', 1000, 100, null, ['document' => ['nonce' => 'n']]);
        $this->assertSame('100', $noAt->get('evidence')->get('at')->lexeme);
        $withAt = Sign::signPassport($bare, $iss, 's', 1000, 100, null, ['document' => ['nonce' => 'n'], 'at' => 7]);
        $this->assertSame('7', $withAt->get('evidence')->get('at')->lexeme);
    }

    public function testWorkflowOutputsAndReceiptSeq(): void
    {
        $this->assertNull(Sign::wfOutput(5)->get('num'));
        $this->assertSame('5', Sign::wfOutput(5, [], null, true)->get('num')->lexeme);
        $this->assertNull(Sign::wfOutput('5', [], null, true)->get('num'));
        $this->assertNull(Sign::wfOutput(5, [], null, false)->get('num'));
        $o = Sign::wfOutput(5, ['b', 'a']);
        $this->assertSame(['a', 'b'], $o->get('labels'));
        $this->assertSame(Workflow::valueDigest(Sign::n(5)), $o->get('digest'));
        // a non-Num seq is read as an integer
        $r = Sign::signStepReceipt(self::kp(1), ['a' => 1], 'st', 'ok', 'pd', [], 10, Obj::of(['seq' => '2.5']));
        $this->assertSame('3', $r->get('seq')->lexeme);
    }

    public function testUnknownPqFamilyRefuses(): void
    {
        self::refuses(UnsupportedSigner::class, 'unsupported_suite: NOPE (needs the FFI extension and OpenSSL >= 3.5 libcrypto)', static fn() => new PqKeyPair('NOPE'));
    }

    public function testPqSuitesOnTheCapability(): void
    {
        if (!OpensslPq::available('ML-DSA-65')) {
            $this->markTestSkipped('ML-DSA-65 needs OpenSSL >= 3.5 over FFI');
        }
        $pq = new PqKeyPair('ML-DSA-65');
        $h = Sign::mintRoot(self::kp(1), 'h', [], null, 'hybrid-ed25519-ml-dsa-65', $pq);
        $this->assertSame('hybrid-ed25519-ml-dsa-65', $h->get('alg'));
        $this->assertSame($pq->public, $h->get('pq_pk'));
        $this->assertTrue(is_string($h->get('pq_sig')));
        $s = Sign::mintRoot(self::kp(1), 'h', [], null, 'ml-dsa-65', $pq);
        $this->assertSame('ml-dsa-65', $s->get('alg'));
        $this->assertSame($pq->public, $s->get('pq_pk'));
        $this->assertFalse($s->has('pq_sig'));
        self::refuses(\InvalidArgumentException::class, 'ml-dsa-87 needs a ML-DSA-87 key pair', static fn() => Sign::mintRoot(self::kp(1), 'h', [], null, 'ml-dsa-87', $pq));
        // a PQ signature that fails is refused as unsupported, never returned
        $g = OpensslPq::generate('ML-DSA-65');
        $this->assertNotNull($g);
        $fake = (new \ReflectionClass(PqKeyPair::class))->newInstanceWithoutConstructor();
        \Closure::bind(function () use ($g): void {
            $this->family = 'BOGUS';
            $this->pkey = $g[0];
        }, $fake, PqKeyPair::class)();
        self::refuses(UnsupportedSigner::class, 'unsupported_suite: BOGUS (signing failed)', static fn() => $fake->sign('m'));
    }
}
