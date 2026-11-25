<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Acp;
use Atlas\Pca\Ap2;
use Atlas\Pca\AdmissionRegistry;
use Atlas\Pca\BondSettlement;
use Atlas\Pca\BondStore;
use Atlas\Pca\CaveatLang;
use Atlas\Pca\Dlp;
use Atlas\Pca\BondStoreError;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\StoreBondLedger;
use Atlas\Pca\BudgetTree;
use Atlas\Pca\ConnectReplay;
use Atlas\Pca\GatewayReplayGuard;
use Atlas\Pca\InMemoryDpopReplayStore;
use Atlas\Pca\InMemoryReplayStore;
use Atlas\Pca\InMemorySetReplayStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Optimistic;
use Atlas\Pca\Payments;
use Atlas\Pca\Risk;
use Atlas\Pca\Sdjwt;
use Atlas\Pca\SlidingWindowCounter;
use Atlas\Pca\StreamHealth;
use Atlas\Pca\UndoCoordinatorFactory;
use Atlas\Pca\UndoError;
use Atlas\Pca\WebbotauthMemoryReplayCache;
use Atlas\Pca\WindowReadAccumulator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * An infinite or NaN clock, spend, charge or remaining budget never admits: every comparison with NaN is false and an infinite value
 * lands on the admitting side of a plain one-sided comparison, so each refusal needs the explicit finite check.
 */
final class NonFiniteClockKillTest extends TestCase
{
    /** @return list<array{float}> */
    public static function nonFinite(): array
    {
        return [[NAN], [INF], [-INF]];
    }

    #[DataProvider('nonFinite')]
    public function testDpopReplayStoreAdmitsNothingOnANonFiniteClock(float $now): void
    {
        $s = new InMemoryDpopReplayStore();
        $this->assertTrue($s->addIfAbsent('k', 100, 50));
        $this->assertFalse($s->addIfAbsent('k', 100, $now)); // +Infinity read the live entry as expired
        $this->assertFalse($s->addIfAbsent('fresh', 100, $now));
    }

    #[DataProvider('nonFinite')]
    public function testSetReplayStoreAdmitsNothingOnANonFiniteClockOrExpiry(float $now): void
    {
        $s = new InMemorySetReplayStore(10);
        $this->assertTrue($s->addIfAbsent('a', 100, 50));
        $this->assertFalse($s->addIfAbsent('a', 100, $now));
        $this->assertFalse($s->addIfAbsent('b', 100, $now));
        $this->assertFalse($s->addIfAbsent('c', $now, 50));
    }

    #[DataProvider('nonFinite')]
    public function testWebBotAuthReplayCacheAdmitsNothingOnANonFiniteClockOrExpiry(float $now): void
    {
        $c = new WebbotauthMemoryReplayCache();
        $this->assertTrue($c->claim('k', 100.0, 50.0));
        $this->assertFalse($c->claim('k', 100.0, $now));
        $this->assertFalse($c->claim('fresh', 100.0, $now));
        $this->assertFalse($c->claim('other', $now, 50.0));
    }

    #[DataProvider('nonFinite')]
    public function testGatewayReplayGuardRefusesANonFiniteClockOrExpiry(float $bad): void
    {
        $g = new GatewayReplayGuard(10);
        $this->assertTrue($g->claim('a', 100, 50));
        $this->expectException(\RuntimeException::class);
        $g->claim('a', 100, $bad);
    }

    public function testGatewayReplayGuardRefusesANonFiniteExpiry(): void
    {
        $g = new GatewayReplayGuard(10);
        $this->expectException(\RuntimeException::class);
        $g->claim('a', INF, 50);
    }

    #[DataProvider('nonFinite')]
    public function testReplayStorePruneKeepsLiveKeysOnANonFiniteClock(float $now): void
    {
        $s = new InMemoryReplayStore();
        $this->assertTrue($s->consumeOnce('k', 200, 100));
        $this->assertSame(0, $s->prune($now)); // an infinite clock expired every live key
        $this->assertSame(1, $s->size());
    }

    #[DataProvider('nonFinite')]
    public function testReadAccumulatorRefusesANonFiniteChargeOrClock(float $bad): void
    {
        $a = new WindowReadAccumulator(10, 1000);
        $this->assertFalse($a->charge('k', $bad, 5)); // a non-finite charge counted as zero
        $this->assertFalse($a->charge('k', 1, $bad));
        $this->assertTrue($a->charge('k', 1, 5));
    }

    #[DataProvider('nonFinite')]
    public function testSlidingWindowCounterNeverForgetsOnANonFiniteClock(float $now): void
    {
        $w = new SlidingWindowCounter(1000);
        $this->assertTrue($w->tryAdd(1, 5));
        $this->assertFalse($w->tryAdd($now, 5)); // +Infinity pruned the window then recorded the event
        $this->assertSame(1, $w->count(1));
        $this->assertSame(1, $w->count($now));
    }

    public function testBudgetAllocationAndDebitRefuseAnInfiniteRemainingBudget(): void
    {
        $this->assertFalse(Risk::subBudget(['B' => INF, 'tau' => 0.0], 5.0)['ok']);
        $this->assertFalse(Risk::subBudget(['B' => NAN, 'tau' => 0.0], 5.0)['ok']);
        $this->assertFalse(Risk::debitConsolidated(['B' => INF, 'tau' => 0.0], ['B' => 10.0, 'tau' => 0.0], 1.0)['ok']);
        $this->assertFalse(Risk::debitConsolidated(['B' => 10.0, 'tau' => 0.0], ['B' => INF, 'tau' => 0.0], 1.0)['ok']);
        $this->assertFalse(Risk::debitConsolidatedPath([['B' => 10.0, 'tau' => 0.0], ['B' => INF, 'tau' => 0.0]], 1.0)['ok']);
        $this->assertFalse(BudgetTree::subBudget(Obj::of(['B' => INF, 'tau' => 0]), 5)['ok']);
        $this->assertFalse(BudgetTree::debitConsolidated(Obj::of(['B' => INF, 'tau' => 0]), Obj::of(['B' => 10, 'tau' => 0]), 1)['ok']);
        $this->assertTrue(Risk::subBudget(['B' => 10.0, 'tau' => 0.0], 5.0)['ok']);
    }

    public function testStreamHealthRefusesANonFiniteClock(): void
    {
        $h = new StreamHealth(new Obj());
        foreach ([NAN, INF, -INF] as $bad) {
            $this->assertNull($h->requestVerification($bad));
        }
        $state = $h->requestVerification(100.0);
        $this->assertIsString($state);
        $this->assertTrue($h->ackVerification($state, 100.0));
        $this->assertFalse($h->ackVerification('x', INF));
        $this->assertSame('degraded', $h->report(-INF)['state']); // -Infinity made the last round trip look recent
        $this->assertFalse($h->revocationFreshWithin(300, -INF));
        $this->assertFalse($h->revocationFreshWithin(300, NAN));
        $this->assertTrue($h->revocationFreshWithin(300, 150));
    }

    public function testStripeSignatureRefusesAnInfiniteTolerance(): void
    {
        $t = '1700000000';
        $body = '{}';
        $header = "t=$t,v1=" . hash_hmac('sha256', "$t.$body", 'whsec');
        $this->assertTrue(Payments::verifyStripeSignature($body, $header, 'whsec', 1700000000, 300));
        $this->assertFalse(Payments::verifyStripeSignature($body, $header, 'whsec', 1700000000, INF)); // an infinite window admitted any age
        $this->assertFalse(Payments::verifyStripeSignature($body, $header, 'whsec', INF, 300));
        $this->assertFalse(Payments::verifyStripeSignature($body, $header, 'whsec', NAN, 300));
    }

    public function testSelectiveDisclosureVerifierRefusesANonFiniteClock(): void
    {
        foreach (['now', 'clockToleranceSec', 'kbMaxAgeSec'] as $k) {
            foreach ([NAN, INF, -INF] as $bad) {
                $r = Sdjwt::verifyPcaSdJwt('x', Obj::of([$k => $bad]));
                $this->assertFalse($r->get('ok'));
                $this->assertSame('now, clockToleranceSec and kbMaxAgeSec must be finite', $r->get('reason'));
            }
        }
    }

    public function testAp2BudgetRefusesAnInfiniteSpend(): void
    {
        $open = Obj::of(['constraints' => [Obj::of(['type' => 'payment.budget', 'currency' => 'USD', 'max' => 100])]]);
        $ctx = Obj::of(['totalAmount' => 0, 'totalUses' => 0]);
        $o = Obj::of(['context' => $ctx, 'now' => 0]);
        $ok = Obj::of(['payment_amount' => Obj::of(['currency' => 'USD', 'amount' => 5])]);
        $this->assertSame([], Ap2::checkPaymentConstraints($open, $ok, $o));
        foreach ([-INF, INF, NAN] as $bad) {
            $closed = Obj::of(['payment_amount' => Obj::of(['currency' => 'USD', 'amount' => $bad])]);
            $this->assertNotSame([], Ap2::checkPaymentConstraints($open, $closed, $o)); // -Infinity spend passed `spend <= max`
        }
    }

    #[DataProvider('nonFinite')]
    public function testSharedPaymentTokenLimitsRefuseANonFinitePeriodEnd(float $end): void
    {
        $m = fn($pe) => Obj::of(['terms' => Obj::of(['autoApproveThreshold' => 50, 'currency' => 'USD', 'periodEnd' => $pe]), 'budget' => Obj::of(['B' => 100])]);
        $this->assertSame(20, Payments::sharedPaymentTokenLimits($m(20000), 10000)->get('expires_at'));
        $this->expectException(\TypeError::class); // +Infinity was emitted as an absent expiry
        Payments::sharedPaymentTokenLimits($m($end), 10000);
    }

    /** @return list<array{mixed}> */
    public static function badCaps(): array
    {
        return [[NAN], [INF], [-INF], [-1], [-0.0], [1.5], [null], ['5']];
    }

    #[DataProvider('badCaps')]
    public function testAcpSpendCapMustBeANonNegativeInteger(mixed $cap): void
    {
        $req = Obj::of(['amount' => 5, 'currency' => 'usd', 'merchant' => 'm']);
        $r = Acp::checkPaymentAuthority(Obj::of(['maxAmount' => $cap, 'merchants' => null, 'categories' => null]), $req);
        $this->assertFalse($r->get('ok'));
        $this->assertSame('authorized spend cap is not a non-negative integer (fail closed)', $r->get('reason')); // +Infinity admitted every amount
        $this->assertTrue(Acp::checkPaymentAuthority(Obj::of(['merchants' => null, 'categories' => null]), $req)->get('ok')); // absent stays unbounded
        $this->assertTrue(Acp::checkPaymentAuthority(Obj::of(['maxAmount' => 5, 'merchants' => null, 'categories' => null]), $req)->get('ok'));
    }

    public function testAp2UnknownRecurrenceFrequencyIsAlwaysAViolation(): void
    {
        $closed = Obj::of(['payment_amount' => Obj::of(['currency' => 'USD', 'amount' => 10])]);
        foreach (['HOURLY', '', 'daily'] as $f) {
            $open = Obj::of(['constraints' => [Obj::of(['type' => 'payment.agent_recurrence', 'frequency' => $f])]]);
            $this->assertContains('unknown recurrence frequency', Ap2::checkPaymentConstraints($open, $closed, Obj::of(['now' => 1]))); // the mandate also lacks its amount range and budget
            $o = Obj::of(['now' => 1, 'context' => Obj::of(['totalAmount' => 0, 'totalUses' => 0])]);
            $this->assertContains('unknown recurrence frequency', Ap2::checkPaymentConstraints($open, $closed, $o)); // no last-used date: was admitted
        }
    }

    #[DataProvider('nonFinite')]
    public function testBondChallengeStatusRefusesANonFiniteClock(float $t): void
    {
        $store = new class implements BondStore {
            public function read(string $claimId, ?string $depositor = null): array
            {
                return ['bond' => ['claimId' => $claimId, 'window' => ['registeredAt' => 0, 'windowMs' => 1000]], 'balances' => [], 'openTotals' => ['count' => 0, 'sum' => 0], 'highWater' => 0];
            }

            public function commit(mixed $plan, mixed $observedAt): array
            {
                return ['outcome' => 'conflict', 'reason' => 'x'];
            }

            public function deposit(mixed $account, mixed $amount): float|int
            {
                return 0;
            }
        };
        $good = new StoreBondLedger($store, KeyPair::generate(), fn() => 5000);
        $this->assertSame('finalized', $good->challengeStatus('c')['phase']);
        $ledger = new StoreBondLedger($store, KeyPair::generate(), fn() => $t);
        try {
            $ledger->challengeStatus('c'); // +Infinity read as finalized, which opens settlement
            $this->fail('a non-finite clock must refuse');
        } catch (BondStoreError $e) {
            $this->assertSame('clock_invalid', $e->codeName);
        }
    }

    #[DataProvider('nonFinite')]
    public function testBondMovesRefuseANonFiniteBalance(float $bal): void
    {
        $this->assertIsArray(BondSettlement::applyBondMoves(fn() => 10, [['account' => 'a', 'op' => 'debit', 'amount' => 5]]));
        $this->expectException(\RuntimeException::class); // +Infinity balance covered every debit
        BondSettlement::applyBondMoves(fn() => $bal, [['account' => 'a', 'op' => 'debit', 'amount' => 5]]);
    }

    #[DataProvider('nonFinite')]
    public function testDlpRefusesANonFiniteTaintUnderAnUnboundedCeiling(float $taint): void
    {
        $policy = Obj::of(['classes' => [], 'defaultMaxTaintForAuto' => INF]);
        $r = Dlp::evaluateDlp($policy, Obj::of(['verb' => 'v', 'resource' => 'r', 'taint' => $taint]));
        $this->assertSame('step_up', $r->get('outcome')); // INF > INF is false: the bad taint was allowed
        $this->assertSame('allow', Dlp::evaluateDlp($policy, Obj::of(['verb' => 'v', 'resource' => 'r', 'taint' => 5]))->get('outcome'));
    }

    public function testAdmissionRegistryCheckerRefusesANonFiniteClock(): void
    {
        $reg = new AdmissionRegistry();
        $bp = Obj::of(['key' => 'k', 'epoch' => 1]);
        $reg->admit('i', $bp, 1000);
        $this->assertTrue($reg->checker(5)('i', $bp));
        foreach ([-INF, INF, NAN] as $bad) {
            $this->assertFalse($reg->checker($bad)('i', $bp)); // -Infinity < until held
        }
    }

    public function testDeriveCountNeedsAReadableClock(): void
    {
        $c = Json::parseLax('{"type":"derive","id":"d","defs":[{"name":"n","kind":"count","window_ms":1000}],"check":{"op":"lte","a":{"ref":"n"},"b":{"const":5}}}');
        $mk = fn($now) => ['now' => $now, 'claims' => new Obj(), 'history' => []];
        $this->assertTrue(CaveatLang::evaluateDerive($c, $mk(new Num('100'))));
        foreach ([INF, -INF, NAN] as $bad) {
            $this->assertNull(CaveatLang::evaluateDerive($c, $mk($bad))); // an unreadable clock must not count zero uses
        }
    }

    #[DataProvider('nonFinite')]
    public function testClaimStatusRefusesANonFiniteClock(float $now): void
    {
        $c = Obj::of(['issued_at' => new Num('1000'), 'challenge_window_ms' => new Num('500')]);
        $this->expectException(\RangeException::class); // the old code answered finalized, which opens settlement
        Optimistic::claimStatus($c, $now);
    }

    public function testClaimStatusRefusesANonFiniteWindow(): void
    {
        $c = Obj::of(['issued_at' => 1.7e308, 'challenge_window_ms' => 1.7e308]); // the sum overflows to Infinity
        $this->expectException(\RangeException::class);
        Optimistic::claimStatus($c, 5.0);
    }

    /** @return list<array{mixed}> */
    public static function badEffectTimeouts(): array
    {
        return [[NAN], [-1], [-INF], ['5']];
    }

    #[DataProvider('badEffectTimeouts')]
    public function testUndoCoordinatorRefusesANonNumericOrNegativeEffectTimeout(mixed $timeout): void
    {
        try {
            UndoCoordinatorFactory::create(['effectTimeoutMs' => $timeout]);
            $this->fail('expected an UndoError');
        } catch (UndoError $e) {
            $this->assertSame('config', $e->errorCode);
            $this->assertStringContainsString('effectTimeoutMs must be a non-negative number', $e->getMessage());
        }
    }
}
