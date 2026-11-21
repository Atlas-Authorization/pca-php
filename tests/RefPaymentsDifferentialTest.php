<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\MemoryChargeBudgetStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Payments;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Payments against the TS reference: test-data/ref-payments.json.gz (mandate, charge decision, charge PCActn, Shared Payment Token
 * limits, rails, Stripe Issuing adapter, network tokens) and ref-payments-java-extra.json.gz (the bonded claim over a charge PCActn).
 * The charge decision takes the policy engine as an injected callable: the reference's recorded policy decision (the 4th argument)
 * is fed back through it. authorizeChargeCore needs the reference's built-in policy engine, which this port does not carry.
 */
final class RefPaymentsDifferentialTest extends TestCase
{
    private const FILE = 'ref-payments.json.gz';
    private const EXTRA = 'ref-payments-java-extra.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    public static function provideExtra(): array
    {
        return Base::datasets(self::EXTRA);
    }

    /** Seeds cross as {"$bytes"}; any other present non-null value is not key material and must be refused. */
    private static function keys(mixed $o, string ...$keys): mixed
    {
        if (!($o instanceof Obj)) {
            return $o;
        }
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $v = $o->get($k);
            if (in_array($k, $keys, true) && $v !== null) {
                $v = $v instanceof Obj && $v->keys() === ['$bytes'] ? Base::bytes($v) : new \stdClass();
            }
            $c->set($k, $v);
        }
        return $c;
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'buildPaymentMandate' => fn(array $a) => Payments::buildPaymentMandate(self::keys($a[0] ?? null, 'principalSecret')),
            'mandatePredicates' => fn(array $a) => Payments::mandatePredicates($a[0] ?? null),
            'mandateCaveats' => fn(array $a) => Payments::mandateCaveats($a[0] ?? null),
            'mandateRiskPolicy' => fn(array $a) => array_key_exists(1, $a) ? Payments::mandateRiskPolicy($a[0] ?? null, $a[1]) : Payments::mandateRiskPolicy($a[0] ?? null),
            'autoSpendBound' => fn(array $a) => Payments::autoSpendBound($a[0] ?? null),
            'isMinorUnits' => fn(array $a) => Payments::isMinorUnits($a[0] ?? null),
            'isPlainId' => fn(array $a) => Payments::isPlainId($a[0] ?? null),
            'chargeActionContext' => fn(array $a) => Payments::chargeActionContext($a[0] ?? null, $a[1] ?? null),
            'chargeParams' => fn(array $a) => Payments::chargeParams($a[0] ?? null, $a[1] ?? null),
            'chargePlanNode' => fn(array $a) => Payments::chargePlanNode($a[0] ?? null, $a[1] ?? null, $a[2] ?? null),
            'chargeDecideInput' => fn(array $a) => Payments::chargeDecideInput($a[0] ?? null, $a[1] ?? null, $a[2] ?? null, $a[3] ?? null),
            'authorizeCharge' => fn(array $a) => Payments::authorizeCharge($a[0] ?? null, $a[1] ?? null, $a[2] ?? null, static fn() => $a[3] ?? null),
            'chargeToPCActn' => fn(array $a) => Payments::chargeToPCActn($a[0] ?? null, $a[1] ?? null, self::keys($a[2] ?? null, 'signerSecret')),
            'settleCharge' => fn(array $a) => Payments::settleCharge($a[0] ?? null, $a[1] ?? null),
            'applyHumanCosign' => fn(array $a) => Payments::applyHumanCosign($a[0] ?? null, $a[1] ?? null, $a[2] ?? null),
            'sharedPaymentTokenLimits' => fn(array $a) => Payments::sharedPaymentTokenLimits($a[0] ?? null, $a[1] ?? null),
            'railLimits' => fn(array $a) => Payments::railLimits($a[0] ?? null, $a[1] ?? null, $a[2] ?? null),
            'categoriesFromTraits' => fn(array $a) => Payments::categoriesFromTraits($a[0] ?? null),
            'reconcileSettlement' => fn(array $a) => Payments::reconcileSettlement($a[0] ?? null, $a[1] ?? null),
            // an absent tolerance (the reference's undefined) crosses as null
            'verifyStripeSignature' => fn(array $a) => ($a[4] ?? null) === null
                ? Payments::verifyStripeSignature($a[0], $a[1], $a[2], $a[3])
                : Payments::verifyStripeSignature($a[0], $a[1], $a[2], $a[3], $a[4]),
            'signStripePayload' => fn(array $a) => Payments::signStripePayload($a[0], $a[1], $a[2]),
            'stripeCardParams' => fn(array $a) => Payments::stripeCardParams($a[0], ($a[3] ?? null) === null
                ? Obj::of(['categoryNames' => $a[1], 'cardholder' => $a[2]])
                : Obj::of(['categoryNames' => $a[1], 'cardholder' => $a[2], 'metadata' => $a[3]])),
            'stripeAuthorizationFromEvent' => fn(array $a) => Payments::stripeAuthorizationFromEvent($a[0] ?? null),
            'stripeIssuingWebhook' => fn(array $a) => Payments::createStripeIssuingWebhook([
                'secret' => $a[2], 'nowSec' => static fn() => $a[3], 'authorize' => static fn() => Obj::of(['approved' => $a[4], 'reasons' => []]),
            ])(Obj::of(['rawBody' => $a[0], 'signature' => $a[1]])),
            'stripeSettlementFromTransaction' => fn(array $a) => Payments::stripeSettlementFromTransaction($a[0] ?? null),
            'tokenRefError' => fn(array $a) => Payments::tokenRefError($a[0] ?? null),
            'looksLikePan' => fn(array $a) => Payments::looksLikePan($a[0] ?? null),
            'bindNetworkToken' => fn(array $a) => Payments::bindNetworkToken(self::keys($a[0] ?? null, 'holderSecret', 'holderPublic')),
            'verifyNetworkTokenBinding' => fn(array $a) => Payments::verifyNetworkTokenBinding($a[0] ?? null, $a[1] ?? null),
            'bindingMessage' => fn(array $a) => Base::outBytes(Payments::bindingMessage($a[0] ?? null)),
            'controlsFromLimits' => fn(array $a) => Payments::controlsFromLimits($a[0] ?? null, $a[1] ?? null),
            'settlementMetadata' => fn(array $a) => Payments::settlementMetadata($a[0] ?? null, $a[1] ?? null),
            'reconcileNetworkSettlement' => fn(array $a) => Payments::reconcileNetworkSettlement($a[0] ?? null, $a[1] ?? null),
            'chargeWithNetworkToken' => fn(array $a) => Payments::chargeWithNetworkToken($a[0] ?? null, $a[1] ?? null, $a[2] ?? null, self::keys($a[3] ?? null, 'signerSecret')),
        ]);
    }

    #[DataProvider('provideExtra')]
    public function testBondAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            // the default decision is the native policy engine (Decide::decide)
            'authorizeChargeCore' => fn(array $a) => Payments::authorizeCharge($a[0], $a[1], $a[2]),
            'openChargeBond' => fn(array $a) => Payments::openChargeBond($a[0], $a[1], \Atlas\Pca\Pca::unb64u($a[2])),
        ]);
    }

    /** A mandate for the hand-written checks below. */
    private static function mandate(): Obj
    {
        $p = new KeyPair(str_repeat("\x01", 32));
        $a = new KeyPair(str_repeat("\x02", 32));
        return Payments::buildPaymentMandate(Obj::of([
            'principalSecret' => str_repeat("\x01", 32), 'principalPublic' => $p->public, 'agentPublic' => $a->public, 'merchants' => ['m1'],
            'currency' => 'USD', 'perTransactionCap' => 500, 'autoApproveThreshold' => 200, 'cumulativeCap' => 1000, 'goal' => 'g',
            'goalSalt' => 'c2FsdC0wMDAx', 'now' => 1800000000000,
        ]));
    }

    public function testChargeDebitsTheDurableBudgetExactlyOnce(): void
    {
        $m = self::mandate();
        $grant = $m->get('grant');
        $decide = static fn() => Obj::of([
            'releaseGuardianShare' => true, 'admit' => true, 'r' => 0.1, 'reasons' => [],
            'requiredThreshold' => Obj::of(['t' => 1, 'proof' => 'claim', 'optimisticAllowed' => true]),
            'budget' => Obj::of(['B' => 1000, 'tau' => 1800000000000, 'asOf' => 1800000001000]),
        ]);
        $store = new MemoryChargeBudgetStore();
        $charge = Obj::of(['merchant' => 'm1', 'amount' => 50, 'currency' => 'USD', 'now' => 1800000001000]);
        $d1 = Payments::authorizeChargeAtomic($m, $charge, $grant, $store, $decide);
        self::assertSame('auto', $d1->get('outcome'));
        self::assertSame(950, $d1->get('budgetAfter')->get('B'));
        $d2 = Payments::authorizeChargeAtomic($m, $charge, $grant, $store, $decide);
        self::assertSame(900, $d2->get('budgetAfter')->get('B'));
    }

    public function testRailAuthorizerDeclinesWhatItCannotAnswer(): void
    {
        $authorize = Payments::createRailAuthorizer(['instruments' => static fn() => null, 'store' => new MemoryChargeBudgetStore(), 'decide' => static fn() => null]);
        self::assertSame(['instrument_unknown'], $authorize(Obj::of(['id' => 'a1', 'instrumentId' => 'c', 'amount' => 5, 'currency' => 'USD', 'merchantId' => 'm']))->get('reasons'));
        self::assertSame(['malformed_authorization'], $authorize(null)->get('reasons'));
        self::assertSame(['amount_not_positive_minor_units'], $authorize(Obj::of(['id' => 'a1', 'instrumentId' => 'c', 'amount' => 0, 'currency' => 'USD', 'merchantId' => 'm']))->get('reasons'));
    }

    public function testPartnerAdapterMapsControlsAndSuspends(): void
    {
        $calls = [];
        $provider = Payments::visaIntelligentCommerceAdapter(static function (string $path, Obj $body) use (&$calls): Obj {
            $calls[] = $path;
            return Obj::of(['token_ref' => 'tok_abcdef123456']);
        });
        $limits = Obj::of(['currency' => 'USD', 'perAuthorizationMax' => 200, 'totalMax' => 1000, 'categories' => ['5734'], 'merchants' => ['m1']]);
        $p = new KeyPair(str_repeat("\x03", 32));
        $res = Payments::issueBoundNetworkToken(Obj::of(['provider' => $provider, 'limits' => $limits, 'grant' => self::mandate()->get('grant'), 'agentId' => 'agent',
            'holderSecret' => str_repeat("\x03", 32), 'holderPublic' => \Atlas\Pca\Pca::unb64u($p->public), 'issuerNonce' => 'nonce-0123456789abcdef']));
        self::assertSame('visa_ic', $res->get('binding')->get('provider'));
        Payments::suspendOnRevoke($provider, $res->get('binding'));
        self::assertSame(['/tokens', '/tokens/tok_abcdef123456/suspend'], $calls);
    }
}
