<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Acp;
use Atlas\Pca\AcpAuthorityError;
use Atlas\Pca\Jose;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** ACP / x402: payment authority, delegated token mint and settlement, single-use stores, x402 v2 codecs and matching, Stripe SPT checks. */
final class GrantSurvivorKill21AcpTest extends TestCase
{
    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/g21-acp', true);
    }

    private static function pub(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private function assertThrown(string $class, string $message, callable $f): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            $this->assertSame([$class, $message], [get_class($e), $e->getMessage()]);
            return;
        }
        $this->fail('expected a throw');
    }

    // ---- payment authority ---------------------------------------------------------------------------------------------

    /** The tightest cap wins and an equal later cap keeps the first; the first category list is de-duplicated. */
    public function testExtractPaymentAuthority(): void
    {
        $cap = static fn(mixed $m): Obj => Acp::spendCapCaveat($m);
        $this->assertSame(500, Acp::extractPaymentAuthority([$cap(500), $cap(500.0)])->get('maxAmount'));
        $this->assertSame(100, Acp::extractPaymentAuthority([$cap(100), $cap(500)])->get('maxAmount'));
        $this->assertSame(['x', 'y'], Acp::extractPaymentAuthority([Acp::merchantCategoryCaveat(['x', 'x', 'y'])])->get('categories'));
    }

    /** A non-list merchant or category allowlist is a TypeError naming the list. */
    public function testCheckPaymentAuthorityMalformedLists(): void
    {
        $req = Obj::of(['amount' => 100, 'currency' => 'usd', 'merchant' => 'm']);
        $this->assertThrown(\TypeError::class, 'authority.merchants.includes is not a function', fn() => Acp::checkPaymentAuthority(Obj::of(['merchants' => 'x']), $req));
        $this->assertThrown(\TypeError::class, 'authority.categories.includes is not a function',
            fn() => Acp::checkPaymentAuthority(Obj::of(['merchants' => null, 'categories' => 'x']), $req));
    }

    // ---- delegated token mint ------------------------------------------------------------------------------------------

    private static function fakePcActn(): Obj
    {
        return Obj::of(['cap_chain' => [Obj::of(['holder' => 'h', 'caveats' => []])], 'exp' => 10000, 'aud' => 'a', 'grant_ref' => 'g',
            'action' => Obj::of(['verb' => 'v', 'resource' => 'r', 'params_digest' => 'p'])]);
    }

    private static function mintOpts(array $over = []): array
    {
        return $over + ['amount' => 100, 'currency' => 'usd', 'merchant' => 'm', 'session' => 's', 'expiresAt' => 5000, 'now' => 1000,
            'signingKey' => self::seed(), 'paymentMethod' => ['type' => 'card']];
    }

    /** Each mint refusal keeps its exact reason. */
    public function testMintRefusals(): void
    {
        $pc = self::fakePcActn();
        $this->assertThrown(AcpAuthorityError::class, 'refused: amount must be a positive integer in minor units',
            fn() => Acp::mintDelegatedPaymentToken($pc, self::mintOpts(['amount' => 0])));
        $this->assertThrown(AcpAuthorityError::class, 'refused: expiresAt must be a finite epoch-ms timestamp',
            fn() => Acp::mintDelegatedPaymentToken($pc, ['expiresAt' => 'x'] + self::mintOpts()));
        $this->assertThrown(AcpAuthorityError::class, "refused: token expiry 20000 would outlive the proof's exp 10000",
            fn() => Acp::mintDelegatedPaymentToken($pc, self::mintOpts(['expiresAt' => 20000])));
        $this->assertThrown(\TypeError::class, '"alg" must be a string', fn() => Acp::mintDelegatedPaymentToken($pc, self::mintOpts(['alg' => 5])));
    }

    // ---- settlement ----------------------------------------------------------------------------------------------------

    /** A compact EdDSA JWS over raw payload bytes, signed with the test key. */
    private static function forge(string $payload): string
    {
        $prot = Jose::b64u(Js::utf8(Js::stringify(Obj::of(['alg' => 'EdDSA', 'typ' => Acp::ACP_DELEGATED_TOKEN_TYPE]))));
        $body = Jose::b64u($payload);
        return "$prot.$body." . Jose::b64u(Jose::jwsSign('EdDSA', self::seed(), "$prot.$body"));
    }

    private static function loose(array $over = []): array
    {
        return $over + ['strict' => false, 'verifyKey' => self::pub(), 'expectedMerchant' => 'zz', 'amount' => 100, 'now' => 2000];
    }

    /** Invalid UTF-8 in the payload is decoded lossily as U+FFFD (and the caller's substitute character is restored). */
    public function testPayloadIsDecodedLossily(): void
    {
        $payload = '{"typ":"acp-delegated-payment","ver":1,"jti":"j","session":"s","merchant":"m' . "\xff" . '","amount":100,"currency":"usd",'
            . '"iat":1000,"exp":5000,"humanPresent":false,"paymentMethod":{"type":"card"},"pca":{"digest":"d","aud":"a","grant_ref":"g",'
            . '"leaf_holder":"h","verb":"v","resource":"r","params_digest":"p"}}';
        $before = mb_substitute_character();
        $r = Acp::verifyDelegatedPaymentToken(self::forge($payload), self::loose());
        $this->assertSame($before, mb_substitute_character());
        $this->assertSame("token merchant \"m\u{FFFD}\" does not match expected \"zz\"", $r->get('reason'));
    }

    /** A payload that is JSON but not an object is not a well-formed token. */
    public function testNonObjectPayloadIsRefused(): void
    {
        $r = Acp::verifyDelegatedPaymentToken(self::forge('[1]'), self::loose());
        $this->assertSame('token payload is not a well-formed delegated payment token', $r->get('reason'));
    }

    /** A store's claim may be an object method, an Obj member or an assoc-array member Closure; it gets the jti and expiry. */
    public function testSingleUseStoreShapes(): void
    {
        $tok = Acp::mintDelegatedPaymentToken(self::fakePcActn(), self::mintOpts());
        $calls = [];
        $claim = static function (string $jti, float $exp) use (&$calls): bool {
            $calls[] = $exp;
            return true;
        };
        $opts = ['expectedCurrency' => 'usd', 'verifyKey' => self::pub(), 'expectedMerchant' => 'm', 'amount' => 100, 'now' => 2000];
        $method = new class {
            public function claim(string $jti, float $exp): bool
            {
                return true;
            }
        };
        foreach ([['claim' => $claim], Obj::of(['claim' => $claim]), $method] as $store) {
            $r = Acp::verifyDelegatedPaymentToken($tok, $opts + ['singleUse' => $store]);
            $this->assertTrue($r->get('ok'), (string)$r->get('reason'));
        }
        $this->assertSame([5000.0, 5000.0], $calls);
        // without strict mode a claim member that is not a Closure (even a callable name) is an unavailable store
        $r = Acp::verifyDelegatedPaymentToken($tok, ['strict' => false, 'singleUse' => ['claim' => 'max']] + $opts);
        $this->assertSame([false, 'single-use store unavailable (fail closed)'], [$r->get('ok'), $r->get('reason')]);
    }

    /** The x402 verifier forwards `alg`; a non-string alg is a signature failure naming the TypeError. */
    public function testX402VerifierForwardsAlg(): void
    {
        $tok = Acp::mintDelegatedPaymentToken(self::fakePcActn(), self::mintOpts());
        $v = Acp::acpX402Verifier(['expectedMerchant' => 'm', 'amount' => 100, 'verifyKey' => self::pub(), 'strict' => false, 'now' => 2000, 'alg' => 5]);
        $r = $v(Obj::of(['token' => $tok]));
        $this->assertSame([false, 'token signature did not verify: "alg" must be a string'], [$r->get('ok'), $r->get('reason')]);
        $ok = Acp::acpX402Verifier(['expectedMerchant' => 'm', 'amount' => 100, 'verifyKey' => self::pub(), 'strict' => false, 'now' => 2000]);
        $this->assertTrue($ok(Obj::of(['token' => $tok]))->get('ok'));
    }

    /** The bound proof is checked at floor(now): half a millisecond does not move the clock-skew boundary. */
    public function testBoundProofUsesFlooredNow(): void
    {
        $agent = new KeyPair(str_repeat("\x02", 32));
        $g = Sign::mintGrant(new KeyPair(str_repeat("\x01", 32)), $agent->public,
            ['predicates' => [['verb' => 'v', 'resource' => 'r']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()], 'g', 's')['grant'];
        $n = 1000000;
        $pc = Sign::buildPcactn($g, [$g], [['id' => 'n1', 'verb' => 'v', 'resource' => 'r']], 'n1', 1, $agent, 'aud', null, $n + 1 + Pca::MAX_SKEW_MS, null, 60000);
        $tok = Acp::mintDelegatedPaymentToken($pc, self::mintOpts(['expiresAt' => $n + 1000, 'now' => $n]));
        $r = Acp::verifyDelegatedPaymentToken($tok, ['strict' => false, 'verifyKey' => self::pub(), 'expectedMerchant' => 'm', 'amount' => 100,
            'now' => $n + 0.5, 'pcActn' => $pc, 'grant' => $g, 'audience' => 'aud', 'insecureSkipPlanRootCheck' => true]);
        $this->assertSame([false, 'bound proof failed to verify: validity: iat is in the future (clock skew)'], [$r->get('ok'), $r->get('reason')]);
        $checks = $r->get('pcaResult')->get('checks');
        $this->assertSame([true, false], [$checks->get('wire'), $checks->get('validity')]);
    }

    // ---- x402 ----------------------------------------------------------------------------------------------------------

    /** A non-callable verify or settle step is a TypeError naming it. */
    public function testX402SettleNeedsCallables(): void
    {
        $p = Obj::of(['token' => 't']);
        $this->assertThrown(\TypeError::class, 'opts.verify is not a function', fn() => Acp::x402Settle($p, ['verify' => 5]));
        $verify = static fn(mixed $x): Obj => Obj::of(['ok' => true, 'claims' => Obj::of(['a' => 1])]);
        $this->assertThrown(\TypeError::class, 'opts.settle is not a function', fn() => Acp::x402Settle($p, ['verify' => $verify, 'settle' => 'x']));
    }

    /** Expiry times render as Date#toISOString, including years 0 and below and the calendar edges. */
    public function testAllowanceExpiryIso(): void
    {
        $claims = static fn(mixed $exp): array => ['amount' => 100, 'currency' => 'usd', 'merchant' => 'm', 'session' => 's', 'exp' => $exp];
        foreach ([-62162121600000 => '0000-02-29T00:00:00.000Z', 4107542400000 => '2100-03-01T00:00:00.000Z', -62167219200000 => '0000-01-01T00:00:00.000Z',
            3600000 => '1970-01-01T01:00:00.000Z', -74784816000000 => '-000400-03-01T00:00:00.000Z', -949449600000 => '1939-12-01T00:00:00.000Z',
            -944179200000 => '1940-01-31T00:00:00.000Z', 59000 => '1970-01-01T00:00:59.000Z'] as $ms => $iso) {
            $this->assertSame($iso, Acp::toAcpAllowance($claims($ms))->get('expires_at'), "exp $ms");
        }
        $this->assertSame('krw', Acp::toAcpAllowance(['currency' => "\u{212A}RW"] + $claims(0))->get('currency')); // KELVIN SIGN lowercases to k
    }

    /** Resource tags allow exactly 5, an icon URL exactly 2048 characters. */
    public function testResourceInfoBounds(): void
    {
        $icon = 'https://a.example/' . str_repeat('i', 2048 - 18);
        $this->assertSame(2048, strlen($icon));
        $this->assertSame([], Acp::resourceInfoProblems(Obj::of(['url' => 'https://a.example/r', 'tags' => ['a', 'b', 'c', 'd', 'e'], 'iconUrl' => $icon])));
    }

    private static function pr(mixed $extensions): array
    {
        return ['x402Version' => 2, 'resource' => ['url' => 'https://a.example/r'], 'accepts' => [self::req()], 'extensions' => $extensions];
    }

    private static function req(mixed $extra = null): array
    {
        $r = ['scheme' => 'exact', 'network' => 'eip155:8453', 'amount' => '100', 'asset' => 'USDC', 'payTo' => '0xabc', 'maxTimeoutSeconds' => 60];
        return $extra === null ? $r : $r + ['extra' => $extra];
    }

    /** Extension keys of an assoc array (numeric ones too) are read as strings. */
    public function testExtensionsAsAssocArray(): void
    {
        $ok = ['info' => ['a' => 1], 'schema' => ['b' => 1]];
        $this->assertSame([], Acp::paymentRequiredV2Problems(self::pr(['k' => $ok, '1' => $ok])));
        $this->assertSame(['extensions.z needs info and schema objects'], Acp::paymentRequiredV2Problems(self::pr(['1' => $ok, 'z' => 5])));
    }

    /** Header codecs prefix their problems with `x402: ` / `stripe spt: `. */
    public function testCodecProblemMessages(): void
    {
        $this->assertThrown(\TypeError::class, 'x402: PaymentRequired must be an object', fn() => Acp::encodePaymentRequiredHeader(5));
        $this->assertThrown(\TypeError::class, 'x402: PaymentRequired must be an object', fn() => Acp::decodePaymentRequiredHeader('NQ=='));
        $this->assertThrown(\TypeError::class, 'x402: PaymentPayload must be an object', fn() => Acp::decodePaymentSignatureHeader('NQ=='));
        $this->assertThrown(\TypeError::class, 'x402: SettlementResponse must be an object', fn() => Acp::decodePaymentResponseHeader('NQ=='));
        $this->assertThrown(\TypeError::class, 'stripe spt: the token must be an object', fn() => Acp::parseStripeSpt(5));
    }

    /** Base64 decoding drops one dangling character (length 4k+1) and keeps every other one. */
    public function testBase64DanglingCharacter(): void
    {
        // "Ingi" is base64 of "x" as JSON; a dangling 5th character is dropped, two extra characters decode to a NUL byte
        $this->assertThrown(\TypeError::class, 'x402: PaymentRequired must be an object', fn() => Acp::decodePaymentRequiredHeader('IngiA'));
        $this->assertThrown(\TypeError::class, 'x402: PAYMENT-REQUIRED is not JSON', fn() => Acp::decodePaymentRequiredHeader('IngiAA'));
    }

    /** A zero amount is refused before the challenge is built. */
    public function testChallengeV2ZeroAmount(): void
    {
        $this->assertThrown(\TypeError::class, 'x402Challenge: amount must be a positive integer in atomic units',
            fn() => Acp::x402ChallengeV2('https://a.example/r', ['amount' => 0]));
    }

    /** Malformed negotiation inputs are TypeErrors with the reference's messages. */
    public function testNegotiateRefusals(): void
    {
        $this->assertThrown(\TypeError::class, 'supported.filter is not a function', fn() => Acp::x402Negotiate([2], 'x'));
        $this->assertThrown(\TypeError::class, "Cannot read properties of null (reading 'length')", fn() => Acp::x402Negotiate(null));
        $this->assertThrown(\TypeError::class, 'offered.includes is not a function', fn() => Acp::x402Negotiate('x'));
        $this->assertSame(2, Acp::x402Negotiate([1, 2]));
    }

    /** `accepted` matches only a structurally identical offer (lists, keys and nesting all count); assoc-array offers compare like Obj. */
    public function testAcceptedMatchesIsExact(): void
    {
        $acc = static fn(mixed $extra): Obj => Js::parse(Js::stringify(self::req($extra)));
        $this->assertThrown(\TypeError::class, 'offered.some is not a function', fn() => Acp::x402AcceptedMatches('x', $acc(['a' => 1])));
        $pairs = [
            [['l' => [[1, 1]]], ['l' => [[1], 1]]],
            [['l' => [[1, 1]]], ['l' => [1, [1]]]],
            [['l' => []], ['l' => [1]]],
            [['a' => 1], ['b' => 1]],
            [['a' => ['a' => 1, 'b' => 1]], ['a' => ['a' => 1], 'b' => 1]],
        ];
        foreach ($pairs as [$x, $y]) {
            $this->assertFalse(Acp::x402AcceptedMatches([$acc($y)], $acc($x)), Js::stringify($x));
            $this->assertTrue(Acp::x402AcceptedMatches([$acc($x)], $acc($x)));
        }
        $this->assertTrue(Acp::x402AcceptedMatches([self::req(['1' => 'x', 'n' => ['k' => [1]]])], $acc(['1' => 'x', 'n' => ['k' => [1]]])));
    }

    // ---- Stripe SPT ----------------------------------------------------------------------------------------------------

    private static function spt(string $currency, mixed $expiresAt = null): Obj
    {
        return Obj::of(['object' => 'shared_payment.granted_token', 'id' => 'spt_1', 'created' => 1, 'livemode' => true, 'deactivated_at' => null,
            'deactivated_reason' => null, 'usage_limits' => Obj::of(['currency' => $currency, 'max_amount' => 500, 'expires_at' => $expiresAt]),
            'usage_details' => null]);
    }

    /** The full max_amount is usable when nothing was captured; the use currency lowercases as Unicode; a non-string one is a TypeError. */
    public function testSptUsable(): void
    {
        $this->assertSame([], Acp::stripeSptProblems(self::spt('usd')));
        $this->assertTrue(Acp::stripeSptUsable(self::spt('usd'), ['now' => 10, 'amount' => 500, 'currency' => 'usd'])->get('ok'));
        $this->assertTrue(Acp::stripeSptUsable(self::spt('krw'), ['now' => 10, 'amount' => 500, 'currency' => "\u{212A}RW"])->get('ok'));
        $this->assertThrown(\TypeError::class, 'use.currency.toLowerCase is not a function',
            fn() => Acp::stripeSptUsable(self::spt('usd'), ['now' => 10, 'amount' => 5, 'currency' => 5]));
    }

    /** The delegated currency lowercases as Unicode; a non-string one is a TypeError. */
    public function testSptWithinClaims(): void
    {
        $this->assertTrue(Acp::stripeSptWithinClaims(self::spt('krw', 100), ['currency' => "\u{212A}RW", 'amount' => 500, 'exp' => 100000])->get('ok'));
        $this->assertThrown(\TypeError::class, 'claims.currency.toLowerCase is not a function',
            fn() => Acp::stripeSptWithinClaims(self::spt('krw', 100), ['currency' => 5, 'amount' => 500, 'exp' => 100000]));
    }
}
