<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Harness;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the mediator harness (plan gate, risk rounding, trust budget, signing). */
final class RestSurvivorKill35HarnessTest extends TestCase
{
    private const T = 1800000000000;

    private static function grant(): Obj
    {
        $principal = new KeyPair(str_repeat("\x01", 32));
        $key = new KeyPair(str_repeat("\x02", 32));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        return Sign::mintGrant($principal, $key->public, $env, 'refund an order', 'c2FsdA')['grant'];
    }

    private static function plan(): array
    {
        return Sign::n([['id' => 'n1', 'verb' => 'refund', 'resource' => 'orders/1']]);
    }

    private static function policy(mixed $kappa = 1): Obj
    {
        return Sign::n(['weights' => ['alpha' => 1, 'beta' => 0, 'gamma' => 0, 'delta' => 0, 'epsilon' => 0, 'zeta' => 0],
            'theta1' => 0.5, 'theta2' => 0.9, 'kappa' => $kappa, 'lambda' => 0, 'rho' => 0.5, 'bMax' => 1]);
    }

    private static function harness(float $sd, float $b, mixed $policy, ?\Closure $now = null): Harness
    {
        return new Harness(self::grant(), str_repeat("\x02", 32), self::plan(), 'rs-test', Obj::of(['B' => $b, 'tau' => 0, 'asOf' => 0]),
            null, $policy, Obj::of(['semanticDistance' => $sd]), $now ?? static fn(): int => self::T);
    }

    private static function step(Harness $h): Obj
    {
        return $h->step(static fn(): Obj => Obj::of(['nodeId' => 'n1', 'verb' => 'refund', 'resource' => 'orders/1']));
    }

    private static function refusal(\Closure $f): string
    {
        try {
            $f();
        } catch (\InvalidArgumentException | \TypeError $e) {
            return get_class($e) . ': ' . $e->getMessage();
        }
        return 'no refusal';
    }

    /** A budget exactly equal to the cost admits the action and is debited to zero. */
    public function testBudgetEqualToCostSigns(): void
    {
        $r = self::step(self::harness(0.25, 0.25, self::policy()));
        $this->assertTrue($r->get('ok'));
        $this->assertSame(0.0, $r->get('budget')->get('B'));
    }

    /** Params that cannot be serialised are a bad_candidate refusal, as in the reference (its build is wrapped in a catch-all): nothing signed, nothing debited. */
    public function testUnserialisableParamsAreRefused(): void
    {
        $h = self::harness(0.25, 0.25, self::policy());
        $r = $h->step(static fn(): Obj => Obj::of(['nodeId' => 'n1', 'verb' => 'refund', 'resource' => 'orders/1', 'params' => Obj::of(['a' => static fn(): int => 1])]));
        $this->assertFalse($r->get('ok'));
        $this->assertSame('bad_candidate', $r->get('reason'));
        $this->assertStringStartsWith('could not build PCActn: ', $r->get('detail'));
        $this->assertSame(0, $h->counter());
        $this->assertTrue(self::step($h)->get('ok'));
    }

    /** The risk is rounded to 6 d.p. half up: 0.0078125 is 0.007813. */
    public function testRiskRoundsHalfUp(): void
    {
        $r = self::step(self::harness(0.0078125, 1.0, self::policy()));
        $this->assertSame(7813 / 1e6, $r->get('risk')->get('r'));
    }

    /** An over-budget detail prints numbers of 1e21 and above in exponent form. */
    public function testOverBudgetDetailUsesExponentForHugeNumbers(): void
    {
        $r = self::step(self::harness(0.2, 1e21, self::policy(1e22)));
        $this->assertSame('over_budget', $r->get('reason'));
        $this->assertStringStartsWith('budget 1e+21 < cost ', $r->get('detail'));
        $this->assertStringEndsWith('e+21; step up to a human co-sign', $r->get('detail'));
    }

    /** A clock that returns a whole float is used as the integer issue time. */
    public function testAFloatClockIsAccepted(): void
    {
        $r = self::step(self::harness(0.25, 1.0, self::policy(), static fn(): float => 1800000000000.0));
        $this->assertTrue($r->get('ok'));
        $this->assertSame(self::T, $r->get('pcactn')->get('iat')->int());
    }

    /** Without a clock the wall clock is read in milliseconds; the default nonce is 16 random bytes as hex. */
    public function testDefaultClockAndNonce(): void
    {
        Harness::$clockHook = static fn(): float => 1800000000.0;
        try {
            $h = new Harness(self::grant(), str_repeat("\x02", 32), self::plan(), 'rs-test', Obj::of(['B' => 1.0, 'tau' => 0, 'asOf' => 0]), null, self::policy(),
                Obj::of(['semanticDistance' => 0.25]));
            $r = self::step($h);
        } finally {
            Harness::$clockHook = null;
        }
        $this->assertTrue($r->get('ok'));
        $this->assertSame(self::T, $r->get('pcactn')->get('iat')->int());
        $this->assertSame(32, strlen($r->get('pcactn')->get('nonce')));
        $this->assertSame(1, preg_match('/\A[0-9a-f]{32}\z/', $r->get('pcactn')->get('nonce')));
    }

    /** A policy whose weights are not an object throws from step. */
    public function testPolicyWeightsMustBeAnObject(): void
    {
        $p = Obj::of(['weights' => 5, 'theta1' => 0.5, 'theta2' => 0.9, 'kappa' => 1, 'lambda' => 0, 'rho' => 0.5, 'bMax' => 1]);
        $this->assertSame('TypeError: policy.weights is not an object', self::refusal(static fn() => self::step(self::harness(0.25, 1.0, $p))));
    }

    /** The constructor refuses a short secret, an empty plan, a node without an id, duplicate ids and a non-finite budget. */
    public function testConstructorRefusals(): void
    {
        $mk = static fn(string $secret, array $plan, float $b = 1.0): \Closure => static fn() => new Harness(self::grant(), $secret, $plan, 'rs-test',
            Obj::of(['B' => $b, 'tau' => 0, 'asOf' => 0]));
        $s = str_repeat("\x02", 32);
        $this->assertSame('InvalidArgumentException: Harness: `agent_secret` must be a 32-byte Ed25519 secret key', self::refusal($mk(str_repeat("\x02", 31), self::plan())));
        $this->assertSame('InvalidArgumentException: Harness: `plan` must be a non-empty array (an empty plan authorises nothing)', self::refusal($mk($s, [])));
        $this->assertSame('TypeError: plan node without an id', self::refusal($mk($s, ['x'])));
        $this->assertSame('TypeError: plan node without an id', self::refusal($mk($s, [Obj::of(['verb' => 'refund'])])));
        $dup = Sign::n([['id' => 'n1', 'verb' => 'refund', 'resource' => 'orders/1'], ['id' => 'n1', 'verb' => 'refund', 'resource' => 'orders/2']]);
        $this->assertSame('InvalidArgumentException: Harness: plan node ids must be unique', self::refusal($mk($s, $dup)));
        $this->assertSame('InvalidArgumentException: Harness: `budget` must have finite B >= 0, tau and asOf', self::refusal($mk($s, self::plan(), INF)));
    }

    /** The measurement needs an object policy and the verifier a config. */
    public function testStaticRefusals(): void
    {
        $this->assertSame('TypeError: computeHarnessMeasurement: policy is not an object',
            self::refusal(static fn() => Harness::computeHarnessMeasurement('0.1.0', [], 'x')));
        $this->assertSame('TypeError: config is null', self::refusal(static fn() => Harness::createHarnessAttestationVerifier(null)));
    }
}
