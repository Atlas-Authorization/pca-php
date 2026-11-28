<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\ChargeBudgetStore;
use Atlas\Pca\ChargeStoreError;
use Atlas\Pca\Sign;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MandateGrantError;
use Atlas\Pca\MemoryChargeBudgetStore;
use Atlas\Pca\Obj;
use Atlas\Pca\PartnerNetworkTokenProvider;
use Atlas\Pca\Payments;
use PHPUnit\Framework\TestCase;

/** A budget store that always loses the race (bounded so a runaway loop fails fast). */
final class Money10PayLosingStore implements ChargeBudgetStore
{
    public int $cas = 0;

    public function get(string $key): mixed
    {
        return null;
    }

    public function compareAndSet(string $key, ?int $expected, mixed $budget): bool
    {
        if (++$this->cas > 20) {
            throw new \RuntimeException('runaway compare-and-set loop');
        }
        return false;
    }
}

/** A budget store that returns a fixed record. */
final class Money10PayFixedStore implements ChargeBudgetStore
{
    public function __construct(private mixed $rec)
    {
    }

    public function get(string $key): mixed
    {
        return $this->rec;
    }

    public function compareAndSet(string $key, ?int $expected, mixed $budget): bool
    {
        return true;
    }
}

/** A non-Closure callable step-up hook (must not be called: only a Closure is). */
final class Money10PayHook
{
    public int $n = 0;

    public function __invoke(mixed ...$a): void
    {
        $this->n++;
    }
}

/** Payments survivors (group 10): budget store CAS, partner token mapping, JS-semantics helpers, mandate validation. */
final class MoneySurvivorKill10PaymentsTest extends TestCase
{
    private static function seed(string $label = 'principal'): string
    {
        return hash('sha256', 'atlas-pca-conformance/money10-' . $label, true);
    }

    /** A valid mandate parameter set; `$over` replaces members, a null value in `$drop` removes one. */
    private static function params(array $over = [], array $drop = []): array
    {
        $p = ['merchants' => ['m1'], 'currency' => 'USD', 'perTransactionCap' => 1000, 'autoApproveThreshold' => 100,
            'cumulativeCap' => 5000, 'principalSecret' => self::seed(), 'principalPublic' => (new KeyPair(self::seed()))->public,
            'agentPublic' => (new KeyPair(self::seed('agent')))->public, 'now' => 1000];
        foreach ($drop as $k) {
            unset($p[$k]);
        }
        return array_merge($p, $over);
    }

    private function refused(array $p, string $class, string $message): void
    {
        try {
            Payments::buildPaymentMandate($p);
            $this->fail('mandate was built: ' . $message);
        } catch (\Throwable $e) {
            $this->assertSame([$class, $message], [get_class($e), $e->getMessage()]);
        }
    }

    /** The mandate error keeps its message and code name. */
    public function testMandateGrantErrorCarriesItsMessage(): void
    {
        $e = new MandateGrantError('mandate_grant_mismatch', 'the grant is not this mandate');
        $this->assertSame(['mandate_grant_mismatch', 'the grant is not this mandate'], [$e->codeName, $e->getMessage()]);
    }

    /** The budget store counts versions from 1 and refuses a stale expected version. */
    public function testBudgetStoreCompareAndSetVersions(): void
    {
        $s = new MemoryChargeBudgetStore();
        $this->assertNull($s->get('k'));
        $this->assertFalse($s->compareAndSet('k', 1, 'x')); // no record yet: only null matches
        $this->assertTrue($s->compareAndSet('k', null, 'a'));
        $this->assertSame(1, $s->get('k')->get('version'));
        $this->assertFalse($s->compareAndSet('k', null, 'z'));
        $this->assertTrue($s->compareAndSet('k', 1, 'b'));
        $this->assertSame([2, 'b'], [$s->get('k')->get('version'), $s->get('k')->get('budget')]);
        $this->assertFalse($s->compareAndSet('k', 1, 'c'));
        $this->assertSame([2, 'b'], [$s->get('k')->get('version'), $s->get('k')->get('budget')]);
        $this->assertTrue($s->compareAndSet('k', 2, 'd'));
        $this->assertSame(3, $s->get('k')->get('version'));
    }

    /** The partner token request carries every control under the scope key; expires_at only when given. */
    public function testPartnerTokenIssueMapsEveryControl(): void
    {
        $calls = [];
        $post = static function (string $path, Obj $body) use (&$calls) {
            $calls[] = [$path, $body];
            return Obj::of(['token_ref' => 'tok_abcdef12']);
        };
        $prov = new PartnerNetworkTokenProvider('pp', 'spend_scope', $post);
        $this->assertSame('pp', $prov->id());
        $controls = ['currency' => 'USD', 'perAuthorizationMax' => 500, 'totalMax' => 900, 'categories' => ['5411'],
            'merchants' => ['m1'], 'expiresAt' => 77, 'metadata' => ['k' => 'v']];
        $r = $prov->issue(['controls' => $controls, 'agentId' => 'agent-1']);
        $this->assertSame(['token_ref'], $r->keys());
        $this->assertSame('tok_abcdef12', $r->get('token_ref'));
        [$path, $body] = $calls[0];
        $this->assertSame('/tokens', $path);
        $this->assertSame(['agent_id', 'spend_scope', 'metadata'], $body->keys());
        $this->assertSame('agent-1', $body->get('agent_id'));
        $this->assertSame(['k' => 'v'], $body->get('metadata'));
        $scope = $body->get('spend_scope');
        $this->assertSame(['currency', 'per_authorization_max', 'total_max', 'merchant_categories', 'merchants', 'expires_at'], $scope->keys());
        $this->assertSame(['USD', 500, 900, ['5411'], ['m1'], 77], array_map(static fn($k) => $scope->get($k), $scope->keys()));

        unset($controls['expiresAt']);
        $prov->issue(['controls' => $controls, 'agentId' => 'agent-1']);
        $this->assertSame(['currency', 'per_authorization_max', 'total_max', 'merchant_categories', 'merchants'], $calls[1][1]->get('spend_scope')->keys());
    }

    /** A malformed token ref from the provider is refused with the provider id and the reason. */
    public function testPartnerTokenMalformedRefIsRefused(): void
    {
        $prov = new PartnerNetworkTokenProvider('pp', 's', static fn(string $p, Obj $b) => Obj::of(['token_ref' => 'bad']));
        try {
            $prov->issue(['controls' => ['currency' => 'USD', 'perAuthorizationMax' => 1, 'totalMax' => 1, 'categories' => [], 'merchants' => [], 'metadata' => null], 'agentId' => 'a']);
            $this->fail('a malformed token ref was accepted');
        } catch (\RuntimeException $e) {
            $this->assertSame('pp: provider returned token_ref_malformed', $e->getMessage());
        }
    }

    /** Suspend posts the reason to the escaped token path. */
    public function testPartnerTokenSuspendCarriesTheReason(): void
    {
        $calls = [];
        $prov = new PartnerNetworkTokenProvider('pp', 's', static function (string $path, Obj $body) use (&$calls) {
            $calls[] = [$path, $body->keys(), $body->get('reason')];
            return null;
        });
        $prov->suspend('tok/a', 'grant_revoked');
        $this->assertSame([['/tokens/tok%2Fa/suspend', ['reason'], 'grant_revoked']], $calls);
    }

    /** ToNumber: false is 0, a one-element list goes through its string form, a string parses. */
    public function testToNumber(): void
    {
        $this->assertSame(0.0, Payments::n(false));
        $this->assertSame(1.0, Payments::n(true));
        $this->assertSame(7.0, Payments::n([7]));
        $this->assertSame(5.0, Payments::n('5'));
        $this->assertNan(Payments::n(Obj::of(['a' => 1])));
    }

    /** num(): integral floats become ints, except negative zero and values at or past 9e15. */
    public function testNumNormalisesIntegralFloats(): void
    {
        $this->assertSame(-5, Payments::num(-5.0));
        $this->assertSame(0, Payments::num(0.0));
        $this->assertSame(1, Payments::num(1.0));
        $this->assertSame(5, Payments::num(5.0));
        $z = Payments::num(-0.0);
        $this->assertIsFloat($z);
        $this->assertTrue(fdiv(1.0, $z) < 0);
        $this->assertIsFloat(Payments::num(9.0e15));
        $this->assertSame(8999999999999999, Payments::num(8999999999999999.0));
        $this->assertSame(2.5, Payments::num(2.5));
    }

    /** Math.max is NaN when either side is NaN; Math.floor is public and floors. */
    public function testMaxAndFloor(): void
    {
        $this->assertNan(Payments::jsMax(NAN, 1.0));
        $this->assertNan(Payments::jsMax(1.0, NAN));
        $this->assertSame(3.0, Payments::jsMax(1.0, 3.0));
        $this->assertSame(2.0, Payments::jsFloor(2.7));
        $this->assertSame(-3.0, Payments::jsFloor(-2.5));
    }

    /** Math.round: halves go up, and the floor is the base (no pre-rounding of values just under a half). */
    public function testRound(): void
    {
        $this->assertSame(3.0, Payments::jsRound(2.5));
        $this->assertSame(-2.0, Payments::jsRound(-2.5));
        $this->assertSame(2.0, Payments::jsRound(2.4));
        $this->assertSame(0.0, Payments::jsRound(0.49999999999999994));
        $this->assertSame(4503599627370497.0, Payments::jsRound(4503599627370497.0));
    }

    /** Relational operators on two strings compare by code unit, not by number. */
    public function testStringRelationalOperators(): void
    {
        $this->assertFalse(Payments::gt('10', '9'));
        $this->assertTrue(Payments::gt('9', '10'));
        $this->assertFalse(Payments::gt('a', 'a'));
        $this->assertTrue(Payments::gt('b', 'a'));
        $this->assertTrue(Payments::gt(10, 9));
        $this->assertTrue(Payments::le('10', '9'));
        $this->assertFalse(Payments::le('9', '10'));
        $this->assertTrue(Payments::le('a', 'a'));
        $this->assertFalse(Payments::le('b', 'a'));
        $this->assertFalse(Payments::le('10', 9)); // mixed: numeric
        $this->assertTrue(Payments::le('9', 10));
    }

    /** Strict equality: arrays are never equal, null only equals null. */
    public function testStrictEquality(): void
    {
        $this->assertTrue(Payments::seq(5, 5.0));
        $this->assertTrue(Payments::seq('a', 'a'));
        $this->assertTrue(Payments::seq(true, true));
        $this->assertTrue(Payments::seq(null, null));
        $this->assertFalse(Payments::seq([1], [1]));
        $this->assertFalse(Payments::seq(null, [1]));
        $this->assertFalse(Payments::seq([1], null));
        $this->assertFalse(Payments::seq(5, '5'));
    }

    /** length reads an object's length member; spread of undefined is a TypeError. */
    public function testLengthAndSpread(): void
    {
        $this->assertSame(3, Payments::length(Obj::of(['length' => 3])));
        $this->assertSame(Payments::UNDEF, Payments::length(Obj::of(['a' => 1])));
        $this->assertSame(2, Payments::length([1, 2]));
        foreach ([null, Payments::UNDEF] as $v) {
            try {
                Payments::spread($v);
                $this->fail('spread of a nullish value');
            } catch (\TypeError $e) {
                $this->assertSame('value is not iterable', $e->getMessage());
            }
        }
    }

    /** Object spread and object literals take integer keys as property names. */
    public function testObjectKeysFromIntegers(): void
    {
        $o = Payments::spreadObj([5 => 'a', 'x' => 'b']);
        $this->assertSame(['a', 'b'], [$o->get('5'), $o->get('x')]);
        $this->assertSame('a', Payments::obj([0 => 'a', 'u' => Payments::UNDEF])->get('0'));
        $this->assertFalse(Payments::obj([0 => 'a', 'u' => Payments::UNDEF])->has('u'));
    }

    /** now() is the wall clock in milliseconds; isList is public; the default sort is by string form. */
    public function testNowIsListAndSort(): void
    {
        $before = microtime(true) * 1000;
        $now = Payments::now();
        $after = microtime(true) * 1000;
        $this->assertGreaterThanOrEqual((int)$before - 1, $now);
        $this->assertLessThanOrEqual($after + 1, $now);
        $this->assertTrue(Payments::isList([1]));
        $this->assertFalse(Payments::isList(['a' => 1]));
        $this->assertSame([1, 10, 9], Payments::jsSort([10, 9, 1]));
    }

    /** A Bytes seed builds the same mandate as the raw seed; a non-string seed is refused by name. */
    public function testMandateSeedForms(): void
    {
        $m = Payments::buildPaymentMandate(self::params(['principalSecret' => new Bytes(self::seed())]));
        $this->assertSame(['m1'], $m->get('terms')->get('merchants'));
        $this->refused(self::params(['principalSecret' => 5]), \TypeError::class, 'a 32-byte Ed25519 seed is required');
    }

    /** Negative zero is refused by name before any other check; positive zero and negative numbers reach their own checks. */
    public function testMandateNegativeZero(): void
    {
        $this->refused(self::params(['perTransactionCap' => -0.0]), \InvalidArgumentException::class, 'buildPaymentMandate: perTransactionCap must not be negative zero');
        $this->refused(self::params(['perTransactionCap' => 0.0, 'strictMinorUnits' => false]), \InvalidArgumentException::class,
            'buildPaymentMandate: perTransactionCap (X) must be a finite number > 0');
        $this->refused(self::params(['perTransactionCap' => -5.5, 'strictMinorUnits' => false]), \InvalidArgumentException::class,
            'buildPaymentMandate: perTransactionCap (X) must be a finite number > 0');
    }

    /** strictMinorUnits checks perTransactionCap too. */
    public function testMandateStrictMinorUnits(): void
    {
        $this->refused(self::params(['perTransactionCap' => 1.5, 'autoApproveThreshold' => 1]), \InvalidArgumentException::class,
            'buildPaymentMandate: perTransactionCap must be a safe integer in minor units (strictMinorUnits)');
    }

    /** A non-string merchant id is refused as not a non-empty string. */
    public function testMandateMerchantIds(): void
    {
        $this->refused(self::params(['merchants' => [5]]), \InvalidArgumentException::class, 'buildPaymentMandate: merchant ids must be non-empty strings');
    }

    /** X must be > 0, Y within [0, X], periodMs and maxTransactionsPerPeriod positive. */
    public function testMandateBounds(): void
    {
        $x = 'buildPaymentMandate: perTransactionCap (X) must be a finite number > 0';
        $this->refused(self::params(['perTransactionCap' => 0, 'autoApproveThreshold' => 0]), \InvalidArgumentException::class, $x);
        $this->refused(self::params(['perTransactionCap' => -5, 'autoApproveThreshold' => 0]), \InvalidArgumentException::class, $x);
        $this->refused(self::params(['autoApproveThreshold' => -1]), \InvalidArgumentException::class, 'buildPaymentMandate: autoApproveThreshold (Y) must satisfy 0 <= Y <= X');
        $pm = 'buildPaymentMandate: periodMs must be a finite number > 0 when given';
        $this->refused(self::params(['periodMs' => 0]), \InvalidArgumentException::class, $pm);
        $mx = 'buildPaymentMandate: maxTransactionsPerPeriod must be a positive integer when given';
        $this->refused(self::params(['maxTransactionsPerPeriod' => 0]), \InvalidArgumentException::class, $mx);
        $this->refused(self::params(['maxTransactionsPerPeriod' => 1.5]), \InvalidArgumentException::class, $mx);
        $m = Payments::buildPaymentMandate(self::params(['periodMs' => 10, 'maxTransactionsPerPeriod' => 1]));
        $this->assertSame([1010, 1], [$m->get('terms')->get('periodEnd'), $m->get('terms')->get('maxTransactionsPerPeriod')]);
    }

    /** goal, principalPublic, agentPublic and goalSalt are refused by name. */
    public function testMandateIdentityChecks(): void
    {
        $this->refused(self::params(['goal' => 5]), \TypeError::class, 'buildPaymentMandate: goal must be a string');
        $this->refused(self::params(['principalPublic' => (new KeyPair(self::seed('agent')))->public]), \InvalidArgumentException::class,
            'buildPaymentMandate: principalPublic is not the public key of principalSecret');
        $this->refused(self::params(['agentPublic' => 5]), \TypeError::class, 'buildPaymentMandate: agentPublic must be a string');
        $this->refused(self::params(['goalSalt' => 5]), \TypeError::class, 'buildPaymentMandate: goalSalt must be a string');
    }

    /** A period start of exactly 0 adds no not_before caveat. */
    public function testCaveatsPeriodStartZero(): void
    {
        $cv = Payments::mandateCaveats(['periodStart' => 0]);
        $this->assertCount(1, $cv);
        $this->assertSame('reversibility_max', $cv[0]->get('type'));
        $this->assertSame('not_before', Payments::mandateCaveats(['periodStart' => 1])[0]->get('type'));
    }

    private static function mandate(array $over = []): Obj
    {
        return Payments::buildPaymentMandate(self::params($over));
    }

    /** An injected engine that releases and admits, echoing the budget it was given. */
    private static function engine(): \Closure
    {
        return static fn(Obj $in) => Obj::of(['admit' => true, 'releaseGuardianShare' => true, 'reasons' => ['engine-ok'],
            'budget' => $in->get('budget'), 'r' => 0.1, 'requiredThreshold' => Obj::of(['t' => 1])]);
    }

    private static function charge(int $amount = 200): array
    {
        return ['amount' => $amount, 'merchant' => 'm1', 'now' => 2000];
    }

    /** blastRadius is amount / X, a whole ratio as an integer; a mandate whose signed X is 0 weighs a full blast of 1. */
    public function testDecideInputBlastRadius(): void
    {
        $m = self::mandate();
        $g = $m->get('grant');
        $this->assertSame(1, Payments::chargeDecideInput($m, self::charge(1000), 2000, $g)->get('risk')->get('blastRadius'));
        $this->assertSame(0.2, Payments::chargeDecideInput($m, self::charge(200), 2000, $g)->get('risk')->get('blastRadius'));

        $terms = Obj::of(['merchants' => ['m1'], 'categories' => [], 'currency' => 'USD', 'perTransactionCap' => 0, 'autoApproveThreshold' => 0,
            'cumulativeCap' => 5000, 'periodStart' => 1000]);
        $policy = $m->get('policy');
        $minted = Sign::mintGrant(new KeyPair(self::seed()), (new KeyPair(self::seed('agent')))->public, ['predicates' => Payments::mandatePredicates($terms),
            'caveats' => Payments::mandateCaveats($terms), 'agent_binding' => new Obj(), 'risk_policy' => Sign::plain($policy)], 'zero cap', 'money10-salt');
        $zero = Obj::of(['grant' => $minted['grant'], 'policy' => $policy, 'budget' => $m->get('budget'), 'terms' => $terms]);
        $this->assertSame(1, Payments::chargeDecideInput($zero, self::charge(200), 2000, $minted['grant'])->get('risk')->get('blastRadius'));
    }

    /** An exact auto charge uses the injected engine, costs the amount and debits it from B. */
    public function testAuthorizeChargeExactDebit(): void
    {
        $m = self::mandate();
        $d = Payments::authorizeCharge($m, self::charge(), $m->get('grant'), self::engine());
        $this->assertSame(['auto', 1, 0.1, 200, ['engine-ok']], [$d->get('outcome'), $d->get('t'), $d->get('r'), $d->get('cost'), $d->get('reasons')]);
        $this->assertSame([5000, 4800], [$d->get('budgetBefore')->get('B'), $d->get('budgetAfter')->get('B')]);
    }

    /** nz: only a finite positive number survives; everything else is +0. */
    public function testNz(): void
    {
        $this->assertSame(5.0, Payments::nz(5));
        $this->assertSame(0.0, Payments::nz(-1));
        $this->assertSame(0.0, Payments::nz(INF));
        $this->assertSame(0.0, Payments::nz('x'));
        $z = Payments::nz(-0.0);
        $this->assertTrue($z === 0.0 && fdiv(1.0, $z) > 0);
    }

    /** A string budget concatenates with rho (JS `+`), a number adds. */
    public function testCosignConcatenatesAStringBudget(): void
    {
        $m = fn(mixed $b) => Obj::of(['policy' => Obj::of(['bMax' => 1000000, 'rho' => 7]), 'budget' => Obj::of(['B' => $b])]);
        $this->assertSame(57, Payments::applyHumanCosign($m('5'), 3000)->get('budget')->get('B'));
        $this->assertSame(57, Payments::applyHumanCosign($m([5]), 3000)->get('budget')->get('B'));
        $this->assertSame(12, Payments::applyHumanCosign($m(5), 3000)->get('budget')->get('B'));
        $this->assertSame([3000, 3000], [Payments::applyHumanCosign($m(5), 3000)->get('budget')->get('tau'), Payments::applyHumanCosign($m(5), 3000)->get('budget')->get('asOf')]);
    }

    /** A stored budget record must have a non-negative-zero safe-integer version and finite B, tau and asOf. */
    public function testValidRecord(): void
    {
        $v = new \ReflectionMethod(Payments::class, 'validRecord');
        $rec = static fn(mixed $ver, mixed $b = 5, mixed $tau = 1, mixed $asOf = 1) => Obj::of(['version' => $ver, 'budget' => Obj::of(['B' => $b, 'tau' => $tau, 'asOf' => $asOf])]);
        $this->assertTrue($v->invoke(null, $rec(1)));
        $this->assertTrue($v->invoke(null, $rec(0)));
        $this->assertFalse($v->invoke(null, $rec(-0.0)));
        $this->assertFalse($v->invoke(null, $rec(1.5)));
        $this->assertFalse($v->invoke(null, $rec('x')));
        $this->assertFalse($v->invoke(null, $rec(1, 'x')));
        $this->assertFalse($v->invoke(null, $rec(1, 5, 'x')));
        $this->assertFalse($v->invoke(null, $rec(1, 5, 1, 'x')));
        $this->assertFalse($v->invoke(null, 'junk'));
        $this->assertFalse($v->invoke(null, Obj::of(['version' => 1, 'budget' => 'junk'])));
    }

    private function storeError(callable $f, string $message): void
    {
        try {
            $f();
            $this->fail('no ChargeStoreError: ' . $message);
        } catch (ChargeStoreError $e) {
            $this->assertSame($message, $e->getMessage());
        }
    }

    /** The atomic charge commits the auto debit under the given key with the injected engine. */
    public function testAtomicChargeCommits(): void
    {
        $m = self::mandate();
        $s = new MemoryChargeBudgetStore();
        $d = Payments::authorizeChargeAtomic($m, self::charge(), $m->get('grant'), $s, self::engine(), 'k1');
        $this->assertSame(['auto', ['engine-ok']], [$d->get('outcome'), $d->get('reasons')]);
        $this->assertSame([1, 4800], [$s->get('k1')->get('version'), $s->get('k1')->get('budget')->get('B')]);
        $d2 = Payments::authorizeChargeAtomic($m, self::charge(), $m->get('grant'), $s, self::engine(), 'k1');
        $this->assertSame([4800, 4600], [$d2->get('budgetBefore')->get('B'), $d2->get('budgetAfter')->get('B')]);
        $this->assertSame(2, $s->get('k1')->get('version'));
    }

    /** Persistent contention: exactly 8 attempts, then a deny with t 3, no cost, the budget unchanged and the conflict reason first. */
    public function testAtomicChargeConflict(): void
    {
        $m = self::mandate();
        $s = new Money10PayLosingStore();
        $d = Payments::authorizeChargeAtomic($m, self::charge(), $m->get('grant'), $s, self::engine());
        $this->assertSame(8, $s->cas);
        $this->assertSame(['deny', 3, 0, ['budget_store_conflict', 'engine-ok']], [$d->get('outcome'), $d->get('t'), $d->get('cost'), $d->get('reasons')]);
        $this->assertSame(5000, $d->get('budgetAfter')->get('B'));
    }

    /** The atomic paths refuse a non-store and a malformed record. */
    public function testAtomicStoreGuards(): void
    {
        $m = self::mandate();
        $g = $m->get('grant');
        $req = 'a ChargeBudgetStore with get and compareAndSet is required';
        $bad = 'the store returned a malformed budget record';
        $this->storeError(fn() => Payments::authorizeChargeAtomic($m, self::charge(), $g, 'nope', self::engine()), $req);
        $this->storeError(fn() => Payments::applyHumanCosignAtomic($m, $g, 'nope', 3000), $req);
        $this->storeError(fn() => Payments::authorizeChargeAtomic($m, self::charge(), $g, new Money10PayFixedStore('junk'), self::engine()), $bad);
        $this->storeError(fn() => Payments::applyHumanCosignAtomic($m, $g, new Money10PayFixedStore('junk'), 3000), $bad);
    }

    /** The atomic co-sign replenishes the stored budget by rho, or to bMax with full, under the given key. */
    public function testAtomicCosign(): void
    {
        $m = self::mandate(['replenishPerCosign' => 50]);
        $g = $m->get('grant');
        $s = new MemoryChargeBudgetStore();
        $next = Payments::applyHumanCosignAtomic($m, $g, $s, 3000, ['key' => 'k2']);
        $this->assertSame([5000, 3000, 3000], [$next->get('B'), $next->get('tau'), $next->get('asOf')]);
        $this->assertSame(1, $s->get('k2')->get('version'));
        $this->assertTrue($s->compareAndSet('k2', 1, Obj::of(['B' => 100, 'tau' => 1, 'asOf' => 1])));
        $this->assertSame(150, Payments::applyHumanCosignAtomic($m, $g, $s, 3000, ['key' => 'k2'])->get('B'));
        $this->assertSame(3, $s->get('k2')->get('version'));
        $this->assertTrue($s->compareAndSet('k2', 3, Obj::of(['B' => 100, 'tau' => 1, 'asOf' => 1])));
        $this->assertSame(5000, Payments::applyHumanCosignAtomic($m, $g, $s, 3000, ['key' => 'k2', 'full' => true])->get('B'));
        $this->assertSame(5, $s->get('k2')->get('version'));
        $key = \Atlas\Pca\Pca::hashCanonical(Sign::n($g));
        $this->assertSame(5000, Payments::applyHumanCosignAtomic($m, $g, $s, 3000)->get('B'));
        $this->assertSame(1, $s->get($key)->get('version'));
    }

    /** A co-sign that keeps losing the race throws after 8 attempts. */
    public function testAtomicCosignContention(): void
    {
        $m = self::mandate();
        $s = new Money10PayLosingStore();
        $this->storeError(fn() => Payments::applyHumanCosignAtomic($m, $m->get('grant'), $s, 3000), 'could not commit the co-sign: the budget record kept changing');
        $this->assertSame(8, $s->cas);
    }

    private static function zeroCapMandate(Obj $m): array
    {
        $terms = Obj::of(['merchants' => ['m1'], 'categories' => [], 'currency' => 'USD', 'perTransactionCap' => 0, 'autoApproveThreshold' => 0,
            'cumulativeCap' => 5000, 'periodStart' => 1000]);
        $minted = Sign::mintGrant(new KeyPair(self::seed()), (new KeyPair(self::seed('agent')))->public, ['predicates' => Payments::mandatePredicates($terms),
            'caveats' => Payments::mandateCaveats($terms), 'agent_binding' => new Obj(), 'risk_policy' => Sign::plain($m->get('policy'))], 'zero cap', 'money10-salt');
        return [Obj::of(['grant' => $minted['grant'], 'policy' => $m->get('policy'), 'budget' => $m->get('budget'), 'terms' => $terms]), $minted['grant']];
    }

    private static function pcOpts(array $over = []): array
    {
        return array_merge(['signerSecret' => self::seed('agent'), 'aud' => 'merchant-api', 'counter' => 1, 'now' => 2000], $over);
    }

    private function invalid(callable $f, string $class, string $message): void
    {
        try {
            $f();
            $this->fail('accepted: ' . $message);
        } catch (\Throwable $e) {
            $this->assertSame([$class, $message], [get_class($e), $e->getMessage()]);
        }
    }

    /** The charge risk claim is amount / X clamped to 1; a zero X claims the full 1 even for a zero amount. */
    public function testChargePcactnRiskClaim(): void
    {
        $m = self::mandate();
        $over = Payments::chargeToPCActn($m, ['amount' => 2000, 'merchant' => 'm1'], self::pcOpts())->get('pcactn');
        $this->assertSame(1.0, Payments::n($over->get('risk_claim')->get('r')));
        $half = Payments::chargeToPCActn($m, ['amount' => 500, 'merchant' => 'm1'], self::pcOpts())->get('pcactn');
        $this->assertSame(0.5, Payments::n($half->get('risk_claim')->get('r')));
        [$zero] = self::zeroCapMandate($m);
        $z = Payments::chargeToPCActn($zero, ['amount' => 0, 'merchant' => 'm1'], self::pcOpts())->get('pcactn');
        $this->assertSame(1.0, Payments::n($z->get('risk_claim')->get('r')));
    }

    /** chargeToPCActn refuses a non-integer counter, a bad chain and a non-string node id, each by name. */
    public function testChargePcactnRefusals(): void
    {
        $m = self::mandate();
        $c = ['amount' => 200, 'merchant' => 'm1'];
        $this->invalid(fn() => Payments::chargeToPCActn($m, $c, self::pcOpts(['counter' => 1.5])), \InvalidArgumentException::class, 'chargeToPCActn: counter must be an integer');
        $chain = 'chargeToPCActn: chain must be a non-empty list of capabilities';
        $this->invalid(fn() => Payments::chargeToPCActn($m, $c, self::pcOpts(['chain' => [5]])), \InvalidArgumentException::class, $chain);
        $this->invalid(fn() => Payments::chargeToPCActn($m, $c, self::pcOpts(['chain' => [1 => 'x', 0 => $m->get('grant')]])), \InvalidArgumentException::class, $chain);
        $this->invalid(fn() => Payments::chargeToPCActn($m, $c, self::pcOpts(['nodeId' => 5])), \InvalidArgumentException::class, 'chargeToPCActn: nodeId and aud must be strings');
    }

    /** SPT limits: an integer max, a lower-cased currency (multibyte too), and refusals by name. */
    public function testSharedPaymentTokenLimits(): void
    {
        $m = fn(mixed $cur) => Obj::of(['terms' => Obj::of(['autoApproveThreshold' => 100, 'currency' => $cur, 'categories' => ['5411'], 'merchants' => ['m1']]),
            'budget' => Obj::of(['B' => 500])]);
        $l = Payments::sharedPaymentTokenLimits($m('ÉUR'), 1000);
        $this->assertSame(['currency' => 'éur', 'max_amount' => 100], ['currency' => $l->get('currency'), 'max_amount' => $l->get('max_amount')]);
        $this->invalid(fn() => Payments::sharedPaymentTokenLimits($m('USD'), 'x'), \TypeError::class, 'sharedPaymentTokenLimits: now must be an epoch-ms time');
        $this->invalid(fn() => Payments::sharedPaymentTokenLimits($m(5), 1000), \TypeError::class, 't.currency.toLowerCase is not a function');
        $r = Payments::railLimits($m('éur'), 1000);
        $this->assertSame(['ÉUR', 100, 500, ['5411'], ['m1']], [$r->get('currency'), $r->get('perAuthorizationMax'), $r->get('totalMax'), $r->get('categories'), $r->get('merchants')]);
        $this->invalid(fn() => Payments::railLimits($m('USD'), 1000, ['actionTraits' => ['mcc.c5734']]), \RangeException::class,
            'railLimits: the action traits and the mandate categories do not intersect; nothing may be spent');
    }

    /** An engine with a fixed outcome that records every decide input. */
    private static function rec(array &$seen, bool $admit, bool $release, array $reasons, float $busyS = 0.0): \Closure
    {
        return static function (Obj $in) use (&$seen, $admit, $release, $reasons, $busyS) {
            $seen[] = $in;
            if ($busyS > 0) {
                $t = microtime(true);
                while (microtime(true) - $t < $busyS) {
                    // busy-wait: the decision deterministically outlasts a sub-microsecond budget
                }
            }
            return Obj::of(['admit' => $admit, 'releaseGuardianShare' => $release, 'reasons' => $reasons, 'budget' => $in->get('budget'), 'r' => 0.1,
                'requiredThreshold' => Obj::of(['t' => 1])]);
        };
    }

    private static function rail(Obj $m, \Closure $decide, array $over = [], ?MemoryChargeBudgetStore $store = null): \Closure
    {
        $g = $m->get('grant');
        return Payments::createRailAuthorizer(array_merge(['instruments' => static fn(string $id) => $id === 'i1' ? ['mandate' => $m, 'grant' => $g, 'budgetKey' => 'bk1'] : null,
            'store' => $store ?? new MemoryChargeBudgetStore(), 'decide' => $decide, 'now' => static fn(): int => 4242], $over));
    }

    private static function auth(array $over = []): array
    {
        return array_merge(['id' => 'auth1', 'instrumentId' => 'i1', 'amount' => 200, 'currency' => 'usdé', 'merchantId' => 'm1', 'mcc' => '5411'], $over);
    }

    /** An auto approval carries the upper-cased currency, the mcc, the injected clock and commits under the instrument's budget key. */
    public function testRailApproves(): void
    {
        $seen = [];
        $store = new MemoryChargeBudgetStore();
        $v = self::rail(self::mandate(), self::rec($seen, true, true, ['engine-ok']), [], $store)(self::auth());
        $this->assertSame([true, []], [$v->get('approved'), $v->get('reasons')]);
        $params = $seen[0]->get('action')->get('action')->get('params');
        $this->assertSame(['USDÉ', '5411', 4242], [$params->get('currency'), $params->get('category'), $seen[0]->get('now')]);
        $this->assertSame('merchant:m1', $seen[0]->get('action')->get('action')->get('resource'));
        $this->assertSame(4800, $store->get('bk1')->get('budget')->get('B'));

        $seen = [];
        $v = self::rail(self::mandate(), self::rec($seen, true, true, []), ['now' => null])(self::auth(['mcc' => null]));
        $this->assertTrue($v->get('approved'));
        $this->assertFalse($seen[0]->get('action')->get('action')->get('params')->has('category') && $seen[0]->get('action')->get('action')->get('params')->get('category') !== null);
        $seen = [];
        $a = self::auth();
        unset($a['mcc']);
        self::rail(self::mandate(), self::rec($seen, true, true, []))($a);
        $this->assertFalse($seen[0]->get('action')->get('action')->get('params')->has('category'));
    }

    /** A step-up is a decline with step_up_required first; only a Closure hook is notified. */
    public function testRailStepUp(): void
    {
        $seen = [];
        $calls = [];
        $hook = static function (mixed $a, Obj $d) use (&$calls) {
            $calls[] = [$a['id'], $d->get('outcome')];
        };
        $v = self::rail(self::mandate(), self::rec($seen, false, true, ['s1', 's2']), ['onStepUp' => $hook])(self::auth());
        $this->assertSame([false, ['step_up_required', 's1', 's2']], [$v->get('approved'), $v->get('reasons')]);
        $this->assertSame([['auth1', 'step_up']], $calls);
        $inv = new Money10PayHook();
        $v = self::rail(self::mandate(), self::rec($seen, false, true, ['s1']), ['onStepUp' => $inv])(self::auth());
        $this->assertSame(['step_up_required', 's1'], $v->get('reasons'));
        $this->assertSame(0, $inv->n);
    }

    /** A deny passes the engine reasons through, or says denied when there are none. */
    public function testRailDeny(): void
    {
        $seen = [];
        $v = self::rail(self::mandate(), self::rec($seen, false, false, ['r1', 'r2']))(self::auth());
        $this->assertSame([false, ['r1', 'r2']], [$v->get('approved'), $v->get('reasons')]);
        $v = self::rail(self::mandate(), self::rec($seen, false, false, []))(self::auth());
        $this->assertSame([false, ['denied']], [$v->get('approved'), $v->get('reasons')]);
    }

    /** Malformed authorizations decline by name, with approved false. */
    public function testRailDeclines(): void
    {
        $seen = [];
        $r = self::rail(self::mandate(), self::rec($seen, true, true, []));
        foreach ([['malformed_authorization', ['id' => 5]], ['currency_missing', ['currency' => 5]], ['merchant_unknown', ['merchantId' => 5]],
            ['instrument_unknown', ['instrumentId' => 'i2']]] as [$why, $over]) {
            $v = $r(self::auth($over));
            $this->assertSame([['approved', 'reasons'], false, [$why]], [$v->keys(), $v->get('approved'), $v->get('reasons')], $why);
        }
        $this->assertSame([], $seen);
    }

    /** The latency budget is in milliseconds: a decision that outlasts 0.001 ms is discarded. */
    public function testRailLatencyBudget(): void
    {
        $seen = [];
        $v = self::rail(self::mandate(), self::rec($seen, true, true, [], 0.002), ['latencyBudgetMs' => 0.001])(self::auth());
        $this->assertSame([false, ['latency_budget_exceeded']], [$v->get('approved'), $v->get('reasons')]);
        foreach ([0, -5] as $bad) {
            $this->invalid(fn() => self::rail(self::mandate(), self::rec($seen, true, true, []), ['latencyBudgetMs' => $bad]), \RangeException::class,
                'createRailAuthorizer: latencyBudgetMs must be positive');
        }
    }

    /** Settlement reconciliation compares currencies case-insensitively (multibyte too) and refuses a non-string currency. */
    public function testReconcileSettlementCurrency(): void
    {
        $ap = ['id' => 'a1', 'amount' => 200, 'currency' => 'ÉUR', 'merchantId' => 'm1'];
        $st = ['authorizationId' => 'a1', 'amount' => 200, 'currency' => 'éur', 'merchantId' => 'm1', 'captures' => 1];
        $r = Payments::reconcileSettlement($ap, $st);
        $this->assertSame([['ok'], true], [$r->keys(), $r->get('ok')]);
        $this->invalid(fn() => Payments::reconcileSettlement($ap, array_merge($st, ['currency' => 5])), \TypeError::class, 'currency.toUpperCase is not a function');
    }

    /** Stripe card params: lower-cased currency, named categories, metadata by own-key order; a missing category name is refused. */
    public function testStripeCardParams(): void
    {
        $limits = ['currency' => 'ÉUR', 'perAuthorizationMax' => 100, 'totalMax' => 500, 'categories' => ['5411'], 'merchants' => ['m1']];
        $p = Payments::stripeCardParams($limits, ['cardholder' => 'ich_1', 'categoryNames' => ['5411' => 'grocery_stores'], 'metadata' => ['a' => 'y', 5 => 'x']]);
        $this->assertSame(['éur', 'grocery_stores', 'x', 'y'], [$p->get('currency'), $p->get('spending_controls[allowed_categories][0]'), $p->get('metadata[5]'), $p->get('metadata[a]')]);
        $this->assertSame(['metadata[5]', 'metadata[a]'], array_values(array_filter($p->keys(), static fn($k) => str_starts_with($k, 'metadata['))));
        $this->invalid(fn() => Payments::stripeCardParams($limits, ['categoryNames' => []]), \RangeException::class, 'stripeCardParams: no Stripe category name for MCC 5411');
        $this->invalid(fn() => Payments::stripeCardParams(array_merge($limits, ['currency' => 5]), []), \TypeError::class, 'limits.currency.toLowerCase is not a function');
    }

    /** Stripe signatures: unknown parts are skipped, a non-numeric t / stale t / wrong key is refused, a non-string body cannot be signed. */
    public function testStripeSignature(): void
    {
        $body = '{"id":"evt_1"}';
        $sec = 'whsec_money10';
        $h = Payments::signStripePayload($body, $sec, 1000);
        $this->assertTrue(Payments::verifyStripeSignature($body, $h, $sec, 1000));
        $this->assertTrue(Payments::verifyStripeSignature($body, 'junk,' . $h, $sec, 1000));
        $this->assertFalse(Payments::verifyStripeSignature($body, Payments::signStripePayload($body, $sec, 'abc'), $sec, 0));
        $this->assertFalse(Payments::verifyStripeSignature($body, $h, $sec, 2000));
        $this->assertFalse(Payments::verifyStripeSignature($body, Payments::signStripePayload($body, 'whsec_other', 1000), $sec, 1000));
        $this->invalid(fn() => Payments::signStripePayload(5, $sec, 1), \TypeError::class, 'signStripePayload: rawBody and secret must be strings');
    }

    /** The webhook answers with the configured Stripe version and tolerance, and uses the wall clock when no clock is given. */
    public function testStripeWebhookOptions(): void
    {
        $body = '{"type":"other"}';
        $sec = 'whsec_money10';
        $req = ['rawBody' => $body, 'signature' => Payments::signStripePayload($body, $sec, 1000)];
        $mk = fn(array $o) => Payments::createStripeIssuingWebhook(array_merge(['secret' => $sec, 'authorize' => static fn($a) => null], $o));
        $r = $mk(['nowSec' => static fn(): int => 1005, 'stripeVersion' => 'v-test', 'toleranceSec' => 10])($req);
        $this->assertSame([200, 'v-test'], [$r->get('status'), $r->get('headers')->get('Stripe-Version')]);
        $r = $mk(['nowSec' => static fn(): int => 1100, 'toleranceSec' => 10])($req);
        $this->assertSame([400, Payments::STRIPE_API_VERSION], [$r->get('status'), $r->get('headers')->get('Stripe-Version')]);
        $this->assertSame(200, $mk(['nowSec' => static fn(): int => 1100])($req)->get('status'));
        $this->assertSame(400, $mk([])($req)->get('status')); // the wall clock is far from t=1000
    }

    /** looksLikePan: Luhn over whole 13..19-digit runs; a non-string is a TypeError. */
    public function testLooksLikePan(): void
    {
        $this->assertTrue(Payments::looksLikePan('5555555555554444'));
        $this->assertTrue(Payments::looksLikePan('4000056655665556'));
        $this->assertTrue(Payments::looksLikePan('4222222222222'));
        $this->assertTrue(Payments::looksLikePan('4000000000000000006'));
        $this->assertFalse(Payments::looksLikePan('5555555555554445'));
        $this->invalid(fn() => Payments::looksLikePan(5), \TypeError::class, 's.replace is not a function');
        $this->assertSame('token_ref_looks_like_pan', Payments::tokenRefError('5555-5555-5555-4444'));
    }

    /** Network-token plumbing: a binding body needs every member, the Mastercard adapter's identity, the provider gate, a numeric ref on suspend. */
    public function testNetworkTokenPlumbing(): void
    {
        $this->invalid(fn() => Payments::bindingMessage(['provider' => 'p']), \TypeError::class, 'canonicalize: unsupported type undefined');
        $calls = [];
        $post = static function (string $path, Obj $body) use (&$calls) {
            $calls[] = [$path, $body->keys()];
            return Obj::of(['token_ref' => 'tok_abcdef12']);
        };
        $mc = Payments::mastercardAgentPayAdapter($post);
        $this->assertSame('mastercard_agent_pay', $mc->id());
        $mc->issue(['controls' => ['currency' => 'USD', 'perAuthorizationMax' => 1, 'totalMax' => 1, 'categories' => [], 'merchants' => [], 'metadata' => null], 'agentId' => 'a']);
        $this->assertSame(['/tokens', ['agent_id', 'session_scope', 'metadata']], $calls[0]);
        Payments::suspendOnRevoke($mc, ['token_ref' => 5]);
        $this->assertSame('/tokens/5/suspend', $calls[1][0]);
        $this->invalid(fn() => Payments::issueBoundNetworkToken(['provider' => 'nope']), \TypeError::class, 'a NetworkTokenProvider is required');
    }

    /** The charge bond: claimedR must be finite, the window must be a number, and a skew of exactly maxSkewMs is allowed. */
    public function testChargeBondWindow(): void
    {
        $pc = Obj::of(['action' => Obj::of(['reversibility_class' => 'reversible'])]);
        $o = ['claimedR' => 0.1, 'serverNow' => 100000, 'issuedAt' => 105000, 'bondRef' => 'bond-1'];
        $b = Payments::openChargeBond($pc, $o, self::seed('agent'));
        $this->assertSame([105000, 300000, 'bond-1', 'reversible'], [$b->get('issued_at'), $b->get('challenge_window_ms'), $b->get('bond_ref'), $b->get('reversibility_class')]);
        $this->invalid(fn() => Payments::openChargeBond($pc, array_merge($o, ['issuedAt' => 105001]), self::seed('agent')), \InvalidArgumentException::class,
            'openOptimistic: issued_at is outside the allowed skew of server time');
        $this->invalid(fn() => Payments::openChargeBond($pc, array_merge($o, ['challengeWindowMs' => 'x']), self::seed('agent')), \InvalidArgumentException::class,
            'openOptimistic: malformed challenge window');
        $this->invalid(fn() => Payments::openChargeBond($pc, array_merge($o, ['claimedR' => 'x']), self::seed('agent')), \InvalidArgumentException::class,
            'openOptimistic: claimedR must be finite');
    }

    /** A network-token binding takes the holder key as Bytes, verifies against the holder, and refuses non-bytes by name. */
    public function testBindNetworkTokenHolderBytes(): void
    {
        $g = self::mandate()->get('grant');
        $raw = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed('agent')));
        $o = ['provider' => 'visa_ic', 'tokenRef' => 'tok_abcdef12', 'grant' => $g, 'issuerNonce' => str_repeat('n', 16), 'holderSecret' => self::seed('agent'),
            'holderPublic' => new Bytes($raw)];
        $b = Payments::bindNetworkToken($o);
        $pk = (new KeyPair(self::seed('agent')))->public;
        $this->assertSame($pk, $b->get('holder'));
        $this->assertNull(Payments::verifyNetworkTokenBinding($b, ['grant' => $g, 'holder' => $pk, 'issuerNonce' => str_repeat('n', 16)]));
        $this->invalid(fn() => Payments::bindNetworkToken(array_merge($o, ['holderPublic' => 5])), \TypeError::class, 'bytes are required');
    }
}
