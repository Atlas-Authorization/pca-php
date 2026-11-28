<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ap2;
use Atlas\Pca\Ap2KeyPair;
use Atlas\Pca\Bytes;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PurchaseLedger;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * AP2 mandates against the TS reference: test-data/ref-ap2.json.gz (SD-JWT parsing and disclosures, ES256, thumbprints, mandate validators,
 * minor units, open-mandate constraints, issuing / presenting / verifying delegation chains, purchases and the redeem ledger, PCA terms to
 * open mandates, settlement payloads, the PCA payment binding) and ref-ap2-java-extra.json.gz (verifyPcaBinding).
 *
 * Key arguments are labels: the key pair is derived from the label exactly as the reference does. ECDSA signatures are randomized, so a
 * fn that signs is compared with every signature segment replaced by "SIG" (the signed tokens inside arguments verify; they are not
 * reproducible). The charge decision of verifyPcaBinding takes the PCA policy engine as an injected callable, which this port does not
 * carry: the reference's own outcome (allow, deny with its reasons, step up) is fed back through it, so only the checks that run before the
 * decision are independent of the reference. A case listed in STRICTER is one where the native is deliberately stricter than the
 * reference: it must refuse, and is reported as skipped instead of compared.
 */
final class RefAp2DifferentialTest extends TestCase
{
    private const FILE = 'ref-ap2.json.gz';
    private const EXTRA = 'ref-ap2-java-extra.json.gz';
    private const T0 = 1_800_000_000;

    /** @var array<string,string> case name => why the native refuses what the reference accepts (none known before the first CI run) */
    private const STRICTER = [];

    /** @var array<string,Ap2KeyPair> */
    private static array $keys = [];

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    public static function provideExtra(): array
    {
        return Base::datasets(self::EXTRA);
    }

    // ---- fixtures derived from labels -----------------------------------------------------------------------------------

    private static function pad32(string $b): string
    {
        return str_pad(ltrim($b, "\0"), 32, "\0", STR_PAD_LEFT);
    }

    /** The private JWK of a label: d = sha256("atlas-pca-conformance/ap2/<label>"), the public point d*G. */
    private static function privOf(string $label): Obj
    {
        $d = hash('sha256', "atlas-pca-conformance/ap2/$label", true);
        $der = hex2bin('30310201010420') . $d . hex2bin('a00a06082a8648ce3d030107');
        $pem = "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n";
        $k = openssl_pkey_get_private($pem);
        self::assertNotFalse($k, 'cannot build the fixture key');
        $ec = openssl_pkey_get_details($k)['ec'];
        return Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'd' => Pca::b64u($d), 'x' => Pca::b64u(self::pad32($ec['x'])), 'y' => Pca::b64u(self::pad32($ec['y'])), 'kid' => $label]);
    }

    private static function keyFor(string $label): Ap2KeyPair
    {
        return self::$keys[$label] ??= Ap2::ap2KeyPairFromPrivateJwk(self::privOf($label));
    }

    private static function pubOf(string $label): Obj
    {
        $j = self::keyFor($label)->publicJwk;
        return Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'x' => $j->get('x'), 'y' => $j->get('y')]);
    }

    private static function seed(string $label): Bytes
    {
        return new Bytes(hash('sha256', "atlas-pca-conformance/$label", true));
    }

    /** Salts "salt-000000000001", "salt-000000000002", ... (base64url). */
    private static function counterSalt(): \Closure
    {
        $n = 0;
        return static function () use (&$n): string {
            return Pca::b64u(sprintf('salt-%012d', ++$n));
        };
    }

    private static function stripSig(string $t): string
    {
        return implode('~', array_map(
            static fn(string $s): string => preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $s) === 1 ? preg_replace('/\.[A-Za-z0-9_-]+$/', '.SIG', $s) : $s,
            explode('~', $t),
        ));
    }

    private static function merch(): Obj
    {
        return Obj::of(['id' => 'merchant_1', 'name' => 'Demo Merchant', 'website' => 'https://demo-merchant.example']);
    }

    private static function merch2(): Obj
    {
        return Obj::of(['id' => 'merchant_2', 'name' => 'Other Merchant']);
    }

    // ---- small object helpers -------------------------------------------------------------------------------------------

    private static function truthy(mixed $v): bool
    {
        return $v !== null && $v !== false && $v !== '' && $v !== 0 && $v !== 0.0;
    }

    /** A copy of $o with $set applied (members given as null are kept as null). */
    private static function with(Obj $o, array $set): Obj
    {
        $c = new Obj();
        foreach ($o->keys() as $k) {
            $c->set($k, $o->get($k));
        }
        foreach ($set as $k => $v) {
            $c->set((string)$k, $v);
        }
        return $c;
    }

    /** The members of $a named in $names that are present, in that order. */
    private static function pick(Obj $a, array $names): Obj
    {
        $c = new Obj();
        foreach ($names as $k) {
            if ($a->has($k)) {
                $c->set($k, $a->get($k));
            }
        }
        return $c;
    }

    private static function mask(mixed $s): mixed
    {
        return is_string($s) ? preg_replace('/invalid JSON \(.*\)\z/s', 'invalid JSON (*)', $s) : $s;
    }

    /** The oracle's key resolver: the entry of the {kid: jwk} map whose name equals header.kid (a string), else nothing. */
    private static function resolver(mixed $m): \Closure
    {
        return static function (mixed $h) use ($m): mixed {
            $kid = $h instanceof Obj ? $h->get('kid') : null;
            return $m instanceof Obj && is_string($kid) && $m->has($kid) ? $m->get($kid) : null;
        };
    }

    private static function baseOpts(Obj $c): Obj
    {
        $o = self::pick($c, ['expectedAudience', 'expectedNonce', 'now', 'clockSkewSeconds']);
        $o->set('resolveIssuerKey', self::resolver($c->get('issuerKeys')));
        $o->set('resolveMerchantKey', self::resolver($c->get('merchantKeys')));
        return $o;
    }

    private static function purchOpts(Obj $c): Obj
    {
        $o = self::pick($c, ['checkout', 'payment', 'context', 'now', 'clockSkewSeconds']);
        $o->set('resolveIssuerKey', self::resolver($c->get('issuerKeys')));
        $o->set('resolveMerchantKey', self::resolver($c->get('merchantKeys')));
        return $o;
    }

    private static function projChain(Obj $r): Obj
    {
        if ($r->get('ok') !== true) {
            $o = Obj::of(['ok' => false, 'reason' => self::mask($r->get('reason'))]);
            if (self::truthy($r->get('violations'))) {
                $o->set('violations', $r->get('violations'));
            }
            return $o;
        }
        $hops = array_map(static fn(Obj $h): Obj => Obj::of(['index' => $h->get('index'), 'kind' => $h->get('kind'), 'claims' => $h->get('claims'), 'mandate' => $h->get('mandate')]), $r->get('hops'));
        $o = Obj::of(['ok' => true, 'hops' => $hops]);
        if (self::truthy($r->get('open'))) {
            $o->set('open', $r->get('open'));
            $o->set('closed', $r->get('closed'));
        }
        if (self::truthy($r->get('checkoutJwt'))) {
            $o->set('checkoutJwt', $r->get('checkoutJwt'));
            $o->set('checkout', $r->get('checkout'));
        }
        if (self::truthy($r->get('openHash'))) {
            $o->set('openHash', $r->get('openHash'));
        }
        return $o;
    }

    private static function projPurchase(Obj $r): Obj
    {
        return $r->get('ok') === true
            ? Obj::of(['ok' => true, 'checkout' => self::projChain($r->get('checkout')), 'payment' => self::projChain($r->get('payment'))])
            : Obj::of(['ok' => false, 'reason' => self::mask($r->get('reason'))]);
    }

    private static function sigBytes(Obj $x): Obj
    {
        $o = new Obj();
        foreach ($x->keys() as $k) {
            $o->set($k, $k === 'signature' ? Base::outBytes($x->get($k)) : $x->get($k));
        }
        return $o;
    }

    private static function problems(string $name): \Closure
    {
        return match ($name) {
            'openPaymentMandateProblems' => static fn($v) => Ap2::openPaymentMandateProblems($v),
            'paymentMandateProblems' => static fn($v) => Ap2::paymentMandateProblems($v),
            'openCheckoutMandateProblems' => static fn($v) => Ap2::openCheckoutMandateProblems($v),
            'checkoutMandateProblems' => static fn($v) => Ap2::checkoutMandateProblems($v),
            default => throw new \InvalidArgumentException("unknown validator $name"),
        };
    }

    // ---- fns that sign, build inputs, or need a recording ledger ---------------------------------------------------------

    private static function issueIn(Obj $a): Obj
    {
        $issuer = Obj::of(['privateKey' => self::keyFor((string)($a->get('issuerKey') ?? 'issuer'))->privateKey]);
        if ($a->has('kid')) {
            $issuer->set('kid', $a->get('kid'));
        }
        if (self::truthy($a->get('x5c')) || is_array($a->get('x5c'))) {
            $issuer->set('x5c', $a->get('x5c'));
        }
        $in = self::pick($a, ['iat', 'exp', 'constraints', 'payee', 'paymentAmount', 'paymentInstrument', 'pisp', 'executionDate', 'pca', 'sdAlg', 'typ']);
        $in->set('issuer', $issuer);
        $in->set('agentJwk', $a->get('agentJwk') ?? self::pubOf((string)($a->get('agentKey') ?? 'agent')));
        $in->set('salt', self::counterSalt());
        return $in;
    }

    private static function presentIn(Obj $a, array $own): Obj
    {
        $in = self::pick($a, ['open', 'aud', 'nonce', 'iat', 'exp', 'pca', 'hashMode', ...$own]);
        $in->set('agentKey', self::keyFor((string)($a->get('agentKey') ?? 'agent')));
        $in->set('salt', self::counterSalt());
        return $in;
    }

    private static function fromIn(Obj $a): Obj
    {
        $in = self::pick($a, ['exp']);
        $in->set('issuer', Obj::of(['privateKey' => self::keyFor('issuer')->privateKey, 'kid' => 'issuer-1']));
        $in->set('agentJwk', self::pubOf('agent'));
        $in->set('merchants', $a->get('merchants') ?? [self::merch(), self::merch2()]);
        $in->set('iat', $a->get('iat') ?? self::T0);
        $in->set('salt', self::counterSalt());
        return $in;
    }

    private static function redeem(array $a): Obj
    {
        $spec = $a[3];
        $calls = [];
        $ledger = null;
        if ($spec instanceof Obj) {
            $ledger = new class($spec, $calls) implements PurchaseLedger {
                public function __construct(private Obj $spec, private array &$calls)
                {
                }

                public function reserve(string $openMandateHash, string $transactionId, mixed $amountMinor): mixed
                {
                    $this->calls[] = ['reserve', $openMandateHash, $transactionId, $amountMinor];
                    $mode = $this->spec->get('mode');
                    if ($mode === 'throw') {
                        throw new \RuntimeException('down');
                    }
                    if ($mode === 'replayed') {
                        return 'replayed';
                    }
                    if ($mode === 'undefined') {
                        return null;
                    }
                    return $this->spec->get('ctx') ?? Obj::of(['totalAmount' => 0, 'totalUses' => 0]);
                }

                public function release(string $openMandateHash, string $transactionId): void
                {
                    $this->calls[] = ['release', $openMandateHash, $transactionId];
                    if ($this->spec->get('releaseThrows') === true) {
                        throw new \RuntimeException('release failed');
                    }
                }
            };
        }
        $r = Ap2::redeemPurchase($a[0], $a[1], self::purchOpts($a[2]), $ledger);
        return Obj::of(['result' => $r->get('ok') === true ? self::projPurchase($r) : Obj::of(['ok' => false, 'reason' => self::mask($r->get('reason'))]), 'calls' => $calls]);
    }

    private static function binding(Obj $a): Obj
    {
        $in = self::pick($a, ['mandate', 'open', 'audience', 'counter', 'transactionId', 'payee', 'amount', 'instrumentId', 'category', 'now']);
        $in->set('agentJwk', self::pubOf('agent'));
        $in->set('agentSecret', self::seed((string)$a->get('agentSeed')));
        if ($a->has('cosign')) {
            $shares = $a->get('cosign');
            $in->set('cosign', static fn($built) => $shares);
        }
        return Ap2::buildPcaPaymentBinding($in);
    }

    private static function descriptors(mixed $hooks): mixed
    {
        if (!($hooks instanceof Obj)) {
            return $hooks;
        }
        $o = new Obj();
        foreach ($hooks->keys() as $k) {
            $d = $hooks->get($k);
            $o->set($k, static fn($ctx) => $d);
        }
        return $o;
    }

    /** verifyPcaBinding with the reference's own decision fed through the injected policy engine (see the class comment). */
    private static function verifyBinding(array $a, Obj $case): Obj
    {
        $want = $case->get('out');
        $reason = $want instanceof Obj && is_string($want->get('reason')) ? $want->get('reason') : '';
        $ok = $want instanceof Obj && $want->get('ok') === true;
        $in = self::with($a[0], []);
        if ($in->has('hooks')) {
            $in->set('hooks', self::descriptors($in->get('hooks')));
        }
        $budget = $in->get('mandate') instanceof Obj ? $in->get('mandate')->get('budget') : null;
        $decision = static fn(bool $admit, bool $release, array $reasons): Obj => Obj::of([
            'admit' => $admit, 'releaseGuardianShare' => $release, 'reasons' => $reasons, 'budget' => $budget, 'r' => 0, 'requiredThreshold' => Obj::of(['t' => 1]),
        ]);
        $decide = static function ($input) use ($ok, $reason, $decision) {
            if ($ok) {
                return $decision(true, true, []);
            }
            if (str_starts_with($reason, 'PCA denies this charge: ')) {
                return $decision(false, false, explode('; ', substr($reason, strlen('PCA denies this charge: '))));
            }
            if (str_starts_with($reason, 'PCA requires a human co-sign')) {
                return $decision(false, true, []);
            }
            throw new \LogicException('the policy decision was not expected to run');
        };
        return Ap2::verifyPcaBinding($in, $decide);
    }

    /** A STRICTER case must be refused (thrown, or an ok:false verdict); it is then skipped instead of compared. */
    private static function guarded(Obj $case, \Closure $run): mixed
    {
        $why = self::STRICTER[(string)$case->get('name')] ?? null;
        if ($why === null) {
            return $run();
        }
        try {
            $r = $run();
        } catch (\Throwable) {
            return [Base::SKIP, "native stricter: $why"];
        }
        self::assertTrue($r instanceof Obj && $r->get('ok') === false, "native-stricter case must be refused: $why");
        return [Base::SKIP, "native stricter: $why"];
    }

    // ---- the replay ---------------------------------------------------------------------------------------------------------

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        $chain = static fn(string $name) => static fn(array $a, Obj $c) => self::guarded($c, static fn() => self::projChain(Ap2::$name($a[0], self::baseOpts($a[1]))));
        Base::run($file, $fn, $k, [
            'b64uEncode' => fn(array $a) => Ap2::b64uEncode($a[0]),
            'b64uDecode' => fn(array $a) => Base::outBytes(Ap2::b64uDecode($a[0], $a[1])),
            'parseJson' => fn(array $a) => Ap2::parseJson($a[0], $a[1]),
            'isSdAlg' => fn(array $a) => Ap2::isSdAlg($a[0]),
            'sdDigest' => fn(array $a) => count($a) > 1 ? Ap2::sdDigest($a[0], $a[1]) : Ap2::sdDigest($a[0]),
            'assertP256Jwk' => fn(array $a) => Ap2::assertP256Jwk($a[0], $a[1]),
            'jwkThumbprint' => fn(array $a) => Ap2::jwkThumbprint($a[0]),
            'ap2KeyPairFromPrivateJwk' => fn(array $a) => Ap2::ap2KeyPairFromPrivateJwk(self::with(self::privOf($a[0]), $a[1] instanceof Obj ? array_combine($a[1]->keys(), array_map(fn($x) => $a[1]->get($x), $a[1]->keys())) : []))->publicJwk,
            'hopSdJwt' => function (array $a): string {
                $x = Ap2::parseSdJwtHop($a[0]);
                return Ap2::hopSdJwt(Obj::of(['jwt' => $x->get('jwt'), 'disclosures' => $x->get('disclosures')]));
            },
            'parseSdJwtHop' => fn(array $a) => self::sigBytes(Ap2::parseSdJwtHop($a[0])),
            'sdHashOf' => fn(array $a) => count($a) > 1 ? Ap2::sdHashOf(Ap2::parseSdJwtHop($a[0]), $a[1]) : Ap2::sdHashOf(Ap2::parseSdJwtHop($a[0])),
            'issuerJwtHashOf' => fn(array $a) => count($a) > 1 ? Ap2::issuerJwtHashOf(Ap2::parseSdJwtHop($a[0]), $a[1]) : Ap2::issuerJwtHashOf(Ap2::parseSdJwtHop($a[0])),
            // the oracle also takes a whole SD-JWT (it parses the hop, then processes that payload with the hop's own algorithm)
            'processDisclosures' => static function (array $a) {
                if (is_string($a[0])) {
                    $hop = Ap2::parseSdJwtHop($a[0]);
                    return Ap2::processDisclosures($hop->get('payload'), $hop->get('disclosures'), $hop->get('sdAlg'));
                }
                return Ap2::processDisclosures($a[0], $a[1], $a[2]);
            },
            'verifyHopSignature' => fn(array $a) => Ap2::verifyHopSignature(Ap2::parseSdJwtHop($a[0]), $a[1]),
            'parseJwt' => fn(array $a) => self::sigBytes(Ap2::parseJwt($a[0], $a[1])),
            'verifyJwtEs256' => fn(array $a) => Ap2::verifyJwtEs256(Ap2::parseJwt($a[0], 'jwt'), $a[1]),
            'disclosureBuilder' => function (array $a): Obj {
                $b = Ap2::disclosureBuilder($a[0], self::counterSalt());
                $results = [];
                foreach ($a[1] as $op) {
                    $results[] = $op->get('kind') === 'element' ? $b->element($op->get('value')) : $b->property($op->get('name'), $op->get('value'));
                }
                return Obj::of(['results' => $results, 'disclosures' => $b->disclosures]);
            },
            'signSdJwt' => fn(array $a) => self::stripSig(Ap2::signSdJwt(self::with($a[0], ['privateKey' => self::keyFor($a[0]->get('key'))->privateKey]))),
            'signJwtEs256' => fn(array $a) => self::stripSig(Ap2::signJwtEs256(self::with($a[0], ['privateKey' => self::keyFor($a[0]->get('key'))->privateKey]))),
            'currencyExponent' => fn(array $a) => Ap2::currencyExponent($a[0]),
            'toMinorUnits' => fn(array $a) => Ap2::toMinorUnits($a[0], $a[1]),
            'fromMinorUnits' => fn(array $a) => Ap2::fromMinorUnits($a[0], $a[1]),
            'openPaymentMandateProblems' => fn(array $a) => Ap2::openPaymentMandateProblems($a[0]),
            'paymentMandateProblems' => fn(array $a) => Ap2::paymentMandateProblems($a[0]),
            'openCheckoutMandateProblems' => fn(array $a) => Ap2::openCheckoutMandateProblems($a[0]),
            'checkoutMandateProblems' => fn(array $a) => Ap2::checkoutMandateProblems($a[0]),
            'assertValid' => fn(array $a) => Ap2::assertValid($a[1], self::problems($a[0]), $a[2]),
            'constants' => fn(array $a) => Obj::of([
                'VCT_CHECKOUT' => Ap2::VCT_CHECKOUT, 'VCT_CHECKOUT_OPEN' => Ap2::VCT_CHECKOUT_OPEN, 'VCT_PAYMENT' => Ap2::VCT_PAYMENT, 'VCT_PAYMENT_OPEN' => Ap2::VCT_PAYMENT_OPEN,
                'PCA_CLAIM' => Ap2::PCA_CLAIM, 'FREQUENCIES' => Ap2::FREQUENCIES, 'AP2_COMMIT' => Ap2::AP2_COMMIT, 'PCA_BINDING_VERSION' => Ap2::PCA_BINDING_VERSION,
                'TYP_TERMINAL' => Ap2::TYP_TERMINAL, 'TYP_INTERMEDIATE' => Ap2::TYP_INTERMEDIATE,
            ]),
            'merchantMatches' => fn(array $a) => Ap2::merchantMatches($a[0], $a[1]),
            'checkPaymentConstraints' => fn(array $a) => Ap2::checkPaymentConstraints($a[0], $a[1], $a[2]),
            'projectCheckout' => fn(array $a) => Ap2::projectCheckout($a[0]),
            'checkoutTotal' => fn(array $a) => Ap2::checkoutTotal($a[0]),
            'checkCheckoutConstraints' => fn(array $a) => Ap2::checkCheckoutConstraints($a[0], $a[1]),
            'splitChain' => fn(array $a) => Ap2::splitChain($a[0]),
            'verifyKbHop' => function (array $a): Obj {
                $v = Ap2::verifyKbHop(Ap2::parseSdJwtHop($a[0]), Obj::of(['hop' => Ap2::parseSdJwtHop($a[1]), 'mandate' => $a[2]]), $a[3], $a[4]);
                return Obj::of(['index' => $v->get('index'), 'kind' => $v->get('kind'), 'claims' => $v->get('claims'), 'mandate' => $v->get('mandate')]);
            },
            'verifyDelegationChain' => $chain('verifyDelegationChain'),
            'verifyCheckoutChain' => $chain('verifyCheckoutChain'),
            'verifyPaymentChain' => function (array $a): Obj {
                $o = self::baseOpts($a[1]);
                foreach (['openCheckoutHash', 'context', 'expectedTransactionId'] as $k) {
                    if ($a[1]->has($k)) {
                        $o->set($k, $a[1]->get($k));
                    }
                }
                return self::projChain(Ap2::verifyPaymentChain($a[0], $o));
            },
            'verifyPurchase' => fn(array $a) => self::projPurchase(Ap2::verifyPurchase($a[0], $a[1], self::purchOpts($a[2]))),
            'redeemPurchase' => fn(array $a) => self::redeem($a),
            'issueOpenPaymentMandate' => fn(array $a) => self::stripSig(Ap2::issueOpenPaymentMandate(self::issueIn($a[0]))),
            'issueOpenCheckoutMandate' => fn(array $a) => self::stripSig(Ap2::issueOpenCheckoutMandate(self::issueIn($a[0]))),
            'presentClosedPayment' => fn(array $a) => self::stripSig(Ap2::presentClosedPayment(self::presentIn($a[0], ['transactionId', 'payee', 'paymentAmount', 'paymentInstrument', 'pisp', 'executionDate', 'riskData']))),
            'presentClosedCheckout' => fn(array $a) => self::stripSig(Ap2::presentClosedCheckout(self::presentIn($a[0], ['checkoutJwt']))),
            'ap2BudgetMax' => fn(array $a) => Ap2::ap2BudgetMax($a[0], $a[1]),
            'ap2BudgetReads' => fn(array $a) => Ap2::ap2BudgetReads($a[0], $a[1]),
            'riskRatio' => fn(array $a) => Ap2::riskRatio($a[0], $a[1]),
            'pcaBindingNonce' => fn(array $a) => Ap2::pcaBindingNonce($a[0]),
            'paymentConstraintsFromTerms' => fn(array $a) => Ap2::paymentConstraintsFromTerms($a[0], $a[1], $a[2]),
            'pcaOpenClaim' => fn(array $a) => Ap2::pcaOpenClaim($a[0]),
            'openPaymentMandateFromPca' => function (array $a): string {
                $o = self::fromIn($a[0]);
                $o->set('checkoutReference', $a[0]->get('checkoutReference') ?? 'REF');
                return self::stripSig(Ap2::openPaymentMandateFromPca($a[0]->get('mandate'), $o));
            },
            'openCheckoutMandateFromPca' => function (array $a): string {
                $o = self::fromIn($a[0]);
                $o->set('lineItems', $a[0]->get('lineItems') ?? [Obj::of(['id' => 'line_1', 'acceptable_items' => [Obj::of(['id' => 'sku-1', 'title' => 'Widget'])], 'quantity' => 2])]);
                return self::stripSig(Ap2::openCheckoutMandateFromPca($a[0]->get('mandate'), $o));
            },
            'toAtomicUnits' => fn(array $a) => Ap2::toAtomicUnits($a[0], $a[1]),
            'x402Settlement' => fn(array $a) => count($a) > 1 ? Ap2::x402Settlement($a[0], $a[1]) : Ap2::x402Settlement($a[0]),
            'stripeSptSettlement' => fn(array $a) => count($a) > 1 ? Ap2::stripeSptSettlement($a[0], $a[1]) : Ap2::stripeSptSettlement($a[0]),
            'buildPcaPaymentBinding' => fn(array $a) => self::binding($a[0]),
        ]);
    }

    #[DataProvider('provideExtra')]
    public function testVerifyPcaBindingAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'verifyPcaBinding' => fn(array $a, Obj $c) => self::verifyBinding($a, $c),
        ]);
    }
}
