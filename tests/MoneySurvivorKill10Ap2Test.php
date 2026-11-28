<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Ap2;
use Atlas\Pca\Ap2Error;
use Atlas\Pca\Bytes;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Payments;
use Atlas\Pca\Pca;
use Atlas\Pca\PcaBindingError;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Ap2 survivors (group 10): base64url, duplicate-key JSON, P-256 keys and ES256, then the mandate / constraint / chain logic. */
final class MoneySurvivorKill10Ap2Test extends TestCase
{
    /** P-256 fixtures computed offline: d = 379, whose public x starts with a zero byte, and an ES256 signature over "money10.input" whose r starts with a zero byte. */
    private const FX_D = 'AXs';
    private const FX_X = 'AFVDiUrz0A7X10Cr29dclrBod7eH219w7qeLkKjXwAo';
    private const FX_Y = 'u0yFo9jqKe-q-iRAaRLdhNWxTcMr9lbvbGvVil2UP5I';
    private const FX_SIG = 'AFVDiUrz0A7X10Cr29dclrBod7eH219w7qeLkKjXwArdIU6PuJnW9NRgBWjOSTDDkOOG5NJg5bked_4ChlqGDQ';
    /** The public point of d = 0xd76df8, the scalar a lenient base64 decode of the text "1234" gives. */
    private const FX3_X = 'P5eIkzTNVX3j38h9GuHfrN_5mbRXkt_QIfrHfep8I4A';
    private const FX3_Y = 'bVzdzVIH1qgiZAYthH-gVnWOaWBxC4Jl1aoGipW6z4c';

    private function throwsAp2(callable $f, string $message): void
    {
        try {
            $f();
            $this->fail('no Ap2Error: ' . $message);
        } catch (\Throwable $e) {
            $this->assertSame([Ap2Error::class, $message], [get_class($e), $e->getMessage()]);
        }
    }

    private function throwsType(callable $f, string $message): void
    {
        try {
            $f();
            $this->fail('no TypeError: ' . $message);
        } catch (\Throwable $e) {
            $this->assertSame([\TypeError::class, $message], [get_class($e), $e->getMessage()]);
        }
    }

    private static function jwk(string $x, string $y, array $extra = []): Obj
    {
        return Obj::of(array_merge(['kty' => 'EC', 'crv' => 'P-256', 'x' => $x, 'y' => $y], $extra));
    }

    /** The binding error keeps its message and code name. */
    public function testPcaBindingErrorMessage(): void
    {
        $e = new PcaBindingError('mandate_required', 'the open mandate is required');
        $this->assertSame(['mandate_required', 'the open mandate is required'], [$e->codeName, $e->getMessage()]);
    }

    /** now() is the floor of the wall clock in seconds (checked in the upper part of a second, where ceil and round differ from floor). */
    public function testNowIsFlooredSeconds(): void
    {
        do {
            $t = microtime(true);
            $f = $t - floor($t);
        } while (!($f >= 0.6 && $f < 0.9));
        $n = (new \ReflectionMethod(Ap2::class, 'now'))->invoke(null);
        $this->assertSame(floor($t), floor(microtime(true)), 'the call stayed inside the same second');
        $this->assertSame((int)floor($t), $n);
    }

    /** base64url: Bytes encode raw, non-bytes are a TypeError; a 4k+1 length or a non-canonical tail is refused. */
    public function testB64u(): void
    {
        $this->assertSame('__4', Ap2::b64uEncode(new Bytes("\xff\xfe")));
        $this->throwsType(fn() => Ap2::b64uEncode(5), 'b64uEncode: bytes or a string are required');
        $this->throwsAp2(fn() => Ap2::b64uDecode('A', 'x'), 'x: non-canonical base64url');
        $this->throwsAp2(fn() => Ap2::b64uDecode('AAAAA', 'x'), 'x: non-canonical base64url');
        $this->throwsAp2(fn() => Ap2::b64uDecode('AB', 'x'), 'x: non-canonical base64url');
        $this->assertSame("\x00", Ap2::b64uDecode('AA', 'x'));
    }

    /** Duplicate keys are found through escapes and nesting; values and closed objects never count as keys. */
    public function testDuplicateKeys(): void
    {
        $this->throwsAp2(fn() => Ap2::parseJson('{"a":1,"a":2}', 'x'), 'x: duplicate key "a"');
        $this->throwsAp2(fn() => Ap2::parseJson('{"\\n":1,"\\n":2}', 'x'), 'x: duplicate key "\\n"');
        $this->assertSame('x', Ap2::parseJson('{"a":"x","b":"x"}', 'x')->get('b'));
        $this->assertSame('a', Ap2::parseJson('{"a":"a"}', 'x')->get('a'));
        $this->assertSame(2, Ap2::parseJson('{"a":{"b":1},"b":2}', 'x')->get('b'));
        $this->throwsType(fn() => Ap2::parseJson(5, 'x'), 'parseJson: text must be a string');
        try {
            Ap2::parseJson('{', 'x');
            $this->fail('invalid JSON parsed');
        } catch (Ap2Error $e) {
            $this->assertStringStartsWith('x: invalid JSON (', $e->getMessage());
            $this->assertNotSame('x: invalid JSON ()', $e->getMessage()); // the parser's own reason is carried
        }
    }

    /** A JWT segment must be UTF-8 and a JSON object. */
    public function testJwtSegments(): void
    {
        $this->throwsAp2(fn() => Ap2::parseJwt('_w.e30.AA', 't'), 't header: not valid UTF-8');
        $this->throwsAp2(fn() => Ap2::parseJwt('WzFd.e30.AA', 't'), 't header: must be a JSON object');
    }

    /** assertP256Jwk: non-object and off-curve keys are refused by name; a key whose x starts with a zero byte is valid. */
    public function testAssertP256Jwk(): void
    {
        $this->throwsAp2(fn() => Ap2::assertP256Jwk('x', 'w'), 'w: JWK must be an object');
        $one = Pca::b64u(str_repeat("\x01", 32));
        $this->throwsAp2(fn() => Ap2::assertP256Jwk(self::jwk($one, $one), 'w'), 'w: JWK is not a valid P-256 point');
        $j = self::jwk(self::FX_X, self::FX_Y);
        $this->assertSame($j, Ap2::assertP256Jwk($j, 'w'));
    }

    /** A signature whose r starts with a zero byte verifies (r is re-encoded as a minimal DER integer). */
    public function testEs256VerifyLeadingZeroR(): void
    {
        $v = new \ReflectionMethod(Ap2::class, 'es256Verify');
        $sig = Ap2::b64uDecode(self::FX_SIG, 's');
        $this->assertTrue($v->invoke(null, self::jwk(self::FX_X, self::FX_Y), 'money10.input', $sig));
        $this->assertFalse($v->invoke(null, self::jwk(self::FX_X, self::FX_Y), 'money10.other', $sig));
    }

    /** generateAp2KeyPair: a valid EC P-256 public JWK (kid only when given) whose ES256 signatures verify, many times over. */
    public function testGenerateSignVerify(): void
    {
        $kp = Ap2::generateAp2KeyPair('k1');
        $this->assertSame(['kty', 'crv', 'x', 'y', 'kid'], $kp->publicJwk->keys());
        $this->assertSame(['EC', 'P-256', 'k1'], [$kp->publicJwk->get('kty'), $kp->publicJwk->get('crv'), $kp->publicJwk->get('kid')]);
        Ap2::assertP256Jwk($kp->publicJwk, 'g');
        $this->assertFalse(Ap2::generateAp2KeyPair()->publicJwk->has('kid'));
        for ($i = 0; $i < 40; $i++) {
            $jwt = Ap2::signJwtEs256(['header' => Obj::of(['kid' => 'm']), 'payload' => Obj::of(['i' => $i]), 'privateKey' => $kp->privateKey]);
            $this->assertSame(86, strlen(explode('.', $jwt)[2]));
            $this->assertTrue(Ap2::verifyJwtEs256(Ap2::parseJwt($jwt, 't'), $kp->publicJwk), "signature $i");
        }
    }

    /** Signing with a public key fails with the signing error. */
    public function testSignWithPublicKeyFails(): void
    {
        $kp = Ap2::generateAp2KeyPair();
        $pub = openssl_pkey_get_public(openssl_pkey_get_details($kp->privateKey)['key']);
        set_error_handler(static fn(): bool => true);
        try {
            $this->throwsAp2(fn() => Ap2::signJwtEs256(['header' => Obj::of(['kid' => 'm']), 'payload' => Obj::of(['a' => 1]), 'privateKey' => $pub]), 'ES256 signing failed');
        } finally {
            restore_error_handler();
        }
    }

    /** A private JWK: a short d is left-padded, a non-string d / an over-long d / an invalid scalar is refused. */
    public function testPrivateJwk(): void
    {
        $kp = Ap2::ap2KeyPairFromPrivateJwk(self::jwk(self::FX_X, self::FX_Y, ['d' => self::FX_D, 'kid' => 'k9']));
        $this->assertSame([self::FX_X, self::FX_Y, 'k9'], [$kp->publicJwk->get('x'), $kp->publicJwk->get('y'), $kp->publicJwk->get('kid')]);
        $bad = function (Obj $j): void {
            try {
                Ap2::ap2KeyPairFromPrivateJwk($j);
                $this->fail('private JWK accepted');
            } catch (\Throwable $e) {
                $this->assertSame([Ap2Error::class, 'Invalid JWK EC key', 'ERR_CRYPTO_INVALID_JWK'], [get_class($e), $e->getMessage(), $e instanceof Ap2Error ? $e->codeName : null]);
            }
        };
        $bad(self::jwk(self::FX3_X, self::FX3_Y, ['d' => 1234]));
        $bad(self::jwk(self::FX_X, self::FX_Y, ['d' => Pca::b64u(str_repeat("\x01", 33))]));
        $bad(self::jwk(self::FX_X, self::FX_Y, ['d' => Pca::b64u(str_repeat("\xff", 32))]));
    }

    /** verifyJwtEs256 / verifyHopSignature read the signing input and signature as strings: a non-string never verifies. */
    public function testVerifyCastsToString(): void
    {
        $kp = Ap2::generateAp2KeyPair();
        $odd = Obj::of(['header' => Obj::of(['alg' => 'ES256']), 'signingInput' => 5, 'signature' => 5]);
        $this->assertFalse(Ap2::verifyJwtEs256($odd, $kp->publicJwk));
        $this->assertFalse(Ap2::verifyHopSignature($odd, $kp->publicJwk));
        $this->throwsType(fn() => Ap2::parseJwt(5, 'x'), 'jwt.split is not a function');
        $this->throwsType(fn() => Ap2::signJwtEs256(['header' => Obj::of(['kid' => 'm']), 'payload' => [], 'privateKey' => 'nope']), 'privateKey must be an ES256 key');
        $this->assertSame(22, strlen(Ap2::newSalt()));
    }

    /** Disclosures must be 2- or 3-element arrays with a salt and a string claim name. */
    public function testDecodeDisclosure(): void
    {
        $d = fn(string $json) => Ap2::processDisclosures(new Obj(), [Pca::b64u($json)], 'sha-256');
        $this->throwsAp2(fn() => $d('{"a":1}'), 'disclosure: must be a JSON array');
        $this->throwsAp2(fn() => $d('["s"]'), 'disclosure: array must have 2 or 3 elements');
        $this->throwsAp2(fn() => $d('["s",5,1]'), 'disclosure: claim name must be a string');
        $this->throwsAp2(fn() => $d('["s",1,2,3]'), 'disclosure: array must have 2 or 3 elements');
        $this->throwsAp2(fn() => Ap2::processDisclosures(Obj::of(['_sd' => 'x']), [], 'sha-256'), 'SD-JWT: _sd must be an array of strings');
        $this->throwsAp2(fn() => Ap2::processDisclosures(Obj::of(['_sd' => [5]]), [], 'sha-256'), 'SD-JWT: _sd must be an array of strings');
    }

    private static function wrap(mixed $v, int $n): mixed
    {
        for ($i = 0; $i < $n; $i++) {
            $v = [$v];
        }
        return $v;
    }

    /** Nesting is capped at depth 32 exactly, counted the same through element and property disclosures. */
    public function testNestingDepth(): void
    {
        $deep = 'SD-JWT: nesting too deep';
        $this->assertSame(\Atlas\Pca\Js::stringify(self::wrap(1, 32)), \Atlas\Pca\Js::stringify(Ap2::processDisclosures(self::wrap(1, 32), [], 'sha-256')));
        $this->throwsAp2(fn() => Ap2::processDisclosures(self::wrap(1, 33), [], 'sha-256'), $deep);
        foreach ([31 => true, 32 => false] as $n => $ok) {
            $b = Ap2::disclosureBuilder();
            $ph = $b->element(self::wrap(1, $n));
            $run = fn() => Ap2::processDisclosures([$ph], $b->disclosures, 'sha-256');
            if ($ok) {
                $this->assertSame(\Atlas\Pca\Js::stringify([self::wrap(1, $n)]), \Atlas\Pca\Js::stringify($run()));
            } else {
                $this->throwsAp2($run, $deep);
            }
            $b = Ap2::disclosureBuilder();
            $dg = $b->property('k', self::wrap(1, $n));
            $run = fn() => Ap2::processDisclosures(Obj::of(['_sd' => [$dg]]), $b->disclosures, 'sha-256');
            if ($ok) {
                $this->assertSame(\Atlas\Pca\Js::stringify(Obj::of(['k' => self::wrap(1, $n)])), \Atlas\Pca\Js::stringify($run()));
            } else {
                $this->throwsAp2($run, $deep);
            }
        }
    }

    /** Currency exponent and major/minor conversion refusals name the offending value. */
    public function testMinorUnits(): void
    {
        $this->throwsAp2(fn() => Ap2::currencyExponent(5), 'currency must be an ISO 4217 alpha-3 code, got 5');
        $this->throwsAp2(fn() => Ap2::currencyExponent(\Atlas\Pca\Payments::UNDEF), 'currency must be an ISO 4217 alpha-3 code, got undefined');
        $this->throwsAp2(fn() => Ap2::toMinorUnits(-1, 'USD'), 'amount must be a finite non-negative number, got -1');
        $this->throwsAp2(fn() => Ap2::toMinorUnits(1.5, 'JPY'), 'amount 1.5 is not exactly representable in JPY minor units');
        $this->throwsAp2(fn() => Ap2::toMinorUnits(10000000000000000, 'USD'), 'amount 10000000000000000 is outside the safe integer range in minor units');
        $this->throwsAp2(fn() => Ap2::fromMinorUnits(-1, 'USD'), 'minor-unit amount must be a non-negative safe integer, got -1');
        $this->assertSame(12050, Ap2::toMinorUnits(120.5, 'USD'));
    }

    /** A closed payment mandate reports every problem of every member. */
    public function testPaymentMandateProblemsAreComplete(): void
    {
        $p = Ap2::paymentMandateProblems(Obj::of(['vct' => Ap2::VCT_PAYMENT, 'iat' => -1, 'exp' => 'x', 'transaction_id' => 't',
            'payee' => Obj::of(['id' => '', 'name' => '']), 'payment_amount' => Obj::of(['amount' => -1, 'currency' => 'usd']),
            'payment_instrument' => Obj::of(['id' => '', 'type' => '', 'description' => 5]), 'pisp' => new Obj()]));
        $this->assertSame(['iat: must be an integer epoch-seconds', 'exp: must be an integer epoch-seconds', 'payee.id: required string', 'payee.name: required string',
            'payment_amount.amount: must be a non-negative integer (minor units)', 'payment_amount.currency: must be an ISO 4217 alpha-3 code',
            'payment_instrument.id: required string', 'payment_instrument.type: required string', 'payment_instrument.description: must be a string',
            'pisp.legal_name: required string', 'pisp.brand_name: required string', 'pisp.domain_name: required string'], $p);
        $this->assertSame(['vct: must be ' . Ap2::VCT_CHECKOUT, 'checkout_jwt: required string', 'checkout_hash: required string'],
            Ap2::checkoutMandateProblems(Obj::of(['vct' => 'x'])));
    }

    /** Open payment constraints report each problem; min may equal max; an infinite budget is refused. */
    public function testPaymentConstraintProblems(): void
    {
        $p = Ap2::openPaymentMandateProblems(Obj::of(['vct' => Ap2::VCT_PAYMENT_OPEN, 'execution_date' => 5, 'constraints' => [
            Obj::of(['type' => 'payment.agent_recurrence', 'frequency' => 'NEVER', 'max_occurrences' => 0]),
            Obj::of(['type' => 'payment.amount_range', 'currency' => 'USD', 'max' => 5, 'min' => 5]),
            Obj::of(['type' => 'payment.budget', 'currency' => 'usd', 'max' => INF]),
            Obj::of(['type' => 'payment.execution_date', 'not_before' => 5, 'not_after' => 6]),
            Obj::of(['type' => 'payment.reference', 'conditional_transaction_id' => 'c'])]]));
        $this->assertSame(['constraints[0].frequency: not a known frequency', 'constraints[0].max_occurrences: must be a positive integer',
            'constraints[2].currency: must be an ISO 4217 alpha-3 code', 'constraints[2].max: must be a non-negative number (major units)',
            'constraints[3].not_before: must be a string', 'constraints[3].not_after: must be a string'],
            array_values(array_filter($p, static fn($x) => str_starts_with($x, 'constraints['))));
        $this->assertContains('execution_date: must be a string', $p);
    }

    /** Checkout line items: every item is checked (a non-object does not stop the scan), acceptable items need id and title. */
    public function testCheckoutConstraintProblems(): void
    {
        $p = Ap2::openCheckoutMandateProblems(Obj::of(['vct' => Ap2::VCT_CHECKOUT_OPEN, 'constraints' => [Obj::of(['type' => 'checkout.line_items', 'items' => [5,
            Obj::of(['id' => '', 'quantity' => 0, 'acceptable_items' => [Obj::of(['title' => 't']), new Obj()]])]])]]));
        $this->assertSame(['constraints[0].items[0]: not an object', 'constraints[0].items[1].id: required string', 'constraints[0].items[1].quantity: must be a positive integer',
            'constraints[0].items[1].acceptable_items[0].id: required string', 'constraints[0].items[1].acceptable_items[1].id: required string',
            'constraints[0].items[1].acceptable_items[1].title: required string'], array_values(array_filter($p, static fn($x) => str_starts_with($x, 'constraints['))));
    }

    /** assertValid joins every problem after the label; sameJson sorts keys inside lists too. */
    public function testAssertValidAndSameJson(): void
    {
        $this->throwsAp2(fn() => Ap2::assertValid(new Obj(), static fn($v) => ['a', 'b'], 'w'), 'w: a; b');
        $same = new \ReflectionMethod(Ap2::class, 'sameJson');
        $this->assertTrue($same->invoke(null, [Obj::of(['b' => 1, 'a' => 2])], [Obj::of(['a' => 2, 'b' => 1])]));
        $this->assertFalse($same->invoke(null, [Obj::of(['b' => 1])], [Obj::of(['b' => 2])]));
    }

    private static function priv(string $name): \ReflectionMethod
    {
        return new \ReflectionMethod(Ap2::class, $name);
    }

    /** Calendar arithmetic (proleptic Gregorian, floor division) against values computed independently. */
    public function testCivilCalendar(): void
    {
        $fd = self::priv('floorDiv');
        $this->assertSame([3, -4, -4, 0, -1, 2, -1, -2], array_map(fn($x) => $fd->invoke(null, $x[0], $x[1]), [[7, 2], [-7, 2], [-8, 2], [0, 5], [-1, 400], [6, 3], [-400, 400], [-401, 400]]));
        $dfc = self::priv('daysFromCivil');
        $dates = [[2024, 2, 29], [2024, 3, 1], [1900, 2, 28], [1900, 3, 1], [2000, 2, 29], [1600, 3, 1], [1599, 12, 31], [2100, 1, 1], [-1, 1, 1], [-401, 3, 1], [1970, 1, 1], [9999, 12, 31], [1, 1, 1], [400, 2, 29]];
        $this->assertSame([19782, 19783, -25509, -25508, 11016, -135080, -135141, 47482, -719893, -865931, 0, 2932896, -719162, -573372],
            array_map(fn($x) => $dfc->invoke(null, ...$x), $dates));
        $cfd = self::priv('civilFromDays');
        $z = [-719468, -719469, -1, 0, 59, 60, 10957, 11016, 11017, 2932896, -146097, -146098, -36524, 146096, 146097, 1460, 36523, 36524, -100000, 4000000, 11323, 10956,
            -718008, -718009, -682944, -682945, -573372, -573373, -573371];
        $this->assertSame([[0, 3, 1], [0, 2, 29], [1969, 12, 31], [1970, 1, 1], [1970, 3, 1], [1970, 3, 2], [2000, 1, 1], [2000, 2, 29], [2000, 3, 1], [9999, 12, 31], [1570, 1, 1],
            [1569, 12, 31], [1870, 1, 1], [2369, 12, 31], [2370, 1, 1], [1973, 12, 31], [2069, 12, 30], [2069, 12, 31], [1696, 3, 17], [12921, 8, 18], [2001, 1, 1], [1999, 12, 31],
            [4, 2, 29], [4, 2, 28], [100, 3, 1], [100, 2, 28], [400, 2, 29], [400, 2, 28], [400, 3, 1]], array_map(fn($x) => $cfd->invoke(null, $x), $z));
        $dim = self::priv('daysInMonth');
        $ym = [[2024, 2], [1900, 2], [2000, 2], [2023, 2], [2100, 2], [2400, 2]];
        for ($m = 1; $m <= 12; $m++) {
            $ym[] = [2023, $m];
        }
        $this->assertSame([29, 28, 29, 28, 28, 29, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31], array_map(fn($x) => $dim->invoke(null, ...$x), $ym));
        $du = self::priv('dateUtc');
        $this->assertSame([-631152000000, -2208988800000, 915148800000, -59011459200000, -62198755200000, 1735689600000, 1701388800000, 1703980800000],
            array_map(fn($x) => $du->invoke(null, ...$x), [[50, 0, 1], [0, 0, 1], [99, 0, 1], [100, 0, 1], [-1, 0, 1], [2024, 12, 1], [2024, -1, 1], [2024, 0, 0]]));
    }

    /** RFC 3339 instants: fractions to the millisecond, offsets up to 23:59, every component range-checked. */
    public function testParseInstant(): void
    {
        $pi = self::priv('parseInstant');
        $in = ['2024-03-16', '2024-02-29T12:34:56.789Z', '2024-02-30', '2024-01-01T00:00:45.123Z', '2024-01-01T00:00:45.1Z', '2024-01-01T23:59:59+23:00',
            '2024-01-01T00:00:00-05:59', '2024-01-01T00:00:00+05:60', '2024-01-01T00:00:00+24:00', '1900-02-29', '2000-02-29', '2023-04-31',
            '2023-06-30T00:00:00.123456789+01:30', '2024-01-01T24:00:00Z'];
        $this->assertSame([1710547200000, 1709210096789, null, 1704067245123, 1704067245100, 1704070799000, 1704088740000, null, null, null, 951782400000, null,
            1688077800123, null], array_map(fn($x) => $pi->invoke(null, $x), $in));
    }

    /** Period starts for every frequency (a Saturday, a Sunday, the epoch, just before it, the TimeClip edge, the years 0..99 Date.UTC quirk). */
    public function testPeriodStart(): void
    {
        $ps = self::priv('periodStart');
        $f = ['ON_DEMAND', 'DAILY', 'WEEKLY', 'BIWEEKLY', 'MONTHLY', 'QUARTERLY', 'ANNUALLY', 'HOURLY'];
        $want = [
            [1710592496789.0, [0, 1710547200000, 1710115200000, 1710115200000, 1709251200000, 1704067200000, 1704067200000, null]],
            [1710633600000.0, [0, 1710633600000, 1710115200000, 1710115200000, 1709251200000, 1704067200000, 1704067200000, null]],
            [0.0, [0, 0, -259200000, -259200000, 0, 0, 0, null]],
            [-1.0, [0, -86400000, -259200000, -259200000, -2678400000, -7948800000, -31536000000, null]],
            [1704412800000.0, [0, 1704412800000, 1704067200000, 1704067200000, 1704067200000, 1704067200000, 1704067200000, null]],
            [1705017600000.0, [0, 1705017600000, 1704672000000, 1704067200000, 1704067200000, 1704067200000, 1704067200000, null]],
            [8.64e15, [0, 8640000000000000, 8639999568000000, 8639999568000000, 8639998963200000, 8639993606400000, 8639977881600000, null]],
            [9e15, [null, null, null, null, null, null, null, null]],
            [-62132140800000.0, [0, -2173996800000, -2174428800000, -2175120000000, -2174774400000, -2177452800000, -2177452800000, null]],
        ];
        foreach ($want as [$ms, $exp]) {
            $this->assertSame($exp, array_map(fn($x) => $ps->invoke(null, $ms, $x), $f), (string)$ms);
        }
    }

    /** lt / ge / le compare two strings by code unit and anything else numerically. */
    public function testRelational(): void
    {
        [$lt, $ge, $le] = [self::priv('lt'), self::priv('ge'), self::priv('le')];
        $c = fn(\ReflectionMethod $m, array $pairs) => array_map(fn($x) => $m->invoke(null, $x[0], $x[1]), $pairs);
        $pairs = [['10', '9'], ['9', '10'], ['a', 'a'], ['a', 'b'], ['b', 'a'], ['10', 9], [9, '10']];
        $this->assertSame([true, false, false, true, false, false, true], $c($lt, $pairs));
        $this->assertSame([false, true, true, false, true, true, false], $c($ge, $pairs));
        $this->assertSame([true, false, true, true, false, false, true], $c($le, $pairs));
        $this->throwsType(fn() => self::priv('iter')->invoke(null, 5), 'x is not iterable');
    }

    private static function cnf(\Atlas\Pca\Ap2KeyPair $k): Obj
    {
        return Obj::of(['jwk' => Obj::of(['crv' => 'P-256', 'kty' => 'EC', 'x' => $k->publicJwk->get('x'), 'y' => $k->publicJwk->get('y')])]);
    }

    /** A root SD-JWT over an arbitrary mandate, signed the way issueOpen*Mandate signs one. */
    private static function root(Obj $mandate, \Atlas\Pca\Ap2KeyPair $issuer): string
    {
        $b = Ap2::disclosureBuilder();
        $el = $b->element($mandate);
        return Ap2::signSdJwt(['header' => Obj::of(['typ' => 'dc+sd-jwt']), 'payload' => Obj::of(['delegate_payload' => [$el], '_sd_alg' => 'sha-256']),
            'disclosures' => $b->disclosures, 'privateKey' => $issuer->privateKey]);
    }

    /** A terminal key-binding hop over an arbitrary closed mandate, signed the way presentClosed* signs one. */
    private static function hop(string $open, Obj $mandate, \Atlas\Pca\Ap2KeyPair $agent, string $nonce): string
    {
        $b = Ap2::disclosureBuilder();
        $el = $b->element($mandate);
        $payload = Obj::of(['delegate_payload' => [$el], 'iat' => 1500, 'aud' => 'merchant', 'nonce' => $nonce, 'sd_hash' => Ap2::sdHashOf(Ap2::parseSdJwtHop($open)), '_sd_alg' => 'sha-256']);
        return $open . '~' . Ap2::signSdJwt(['header' => Obj::of(['typ' => 'kb+sd-jwt']), 'payload' => $payload, 'disclosures' => $b->disclosures, 'privateKey' => $agent->privateKey]);
    }

    private static function closedPay(): Obj
    {
        return Obj::of(['vct' => Ap2::VCT_PAYMENT, 'transaction_id' => 'c', 'payee' => Obj::of(['id' => 'm1', 'name' => 'M']),
            'payment_amount' => Obj::of(['amount' => 100, 'currency' => 'USD']), 'payment_instrument' => Obj::of(['id' => 'i1', 'type' => 'card'])]);
    }

    private static function openPay(\Atlas\Pca\Ap2KeyPair $issuer, \Atlas\Pca\Ap2KeyPair $agent, string $notAfter): string
    {
        return Ap2::issueOpenPaymentMandate(['issuer' => ['privateKey' => $issuer->privateKey], 'agentJwk' => $agent->publicJwk, 'iat' => 1000, 'exp' => 5000, 'salt' => 'abc',
            'constraints' => [Obj::of(['type' => 'payment.reference', 'conditional_transaction_id' => 'c']), Obj::of(['type' => 'payment.execution_date', 'not_after' => $notAfter])]]);
    }

    private static function present(string $open, mixed $agentKey): string
    {
        return Ap2::presentClosedPayment(['open' => $open, 'agentKey' => $agentKey, 'aud' => 'merchant', 'nonce' => 'n1', 'iat' => 1500, 'transactionId' => 'c', 'salt' => 'abc',
            'payee' => Obj::of(['id' => 'm1', 'name' => 'M']), 'paymentAmount' => Obj::of(['amount' => 100, 'currency' => 'USD']), 'paymentInstrument' => Obj::of(['id' => 'i1', 'type' => 'card'])]);
    }

    private static function payOpts(\Atlas\Pca\Ap2KeyPair $issuer, array $over = []): array
    {
        return array_merge(['resolveIssuerKey' => static fn($h) => $issuer->publicJwk, 'expectedAudience' => 'merchant', 'expectedNonce' => 'n1', 'now' => 2000,
            'openCheckoutHash' => 'c'], $over);
    }

    /** An issued + presented payment chain verifies (a non-Closure salt is ignored, the agent key may be a key pair or a {privateKey} bag) and uses the given now. */
    public function testPaymentChainVerifies(): void
    {
        [$issuer, $agent] = [Ap2::generateAp2KeyPair(), Ap2::generateAp2KeyPair()];
        $open = self::openPay($issuer, $agent, '1970-01-01T01:00:00Z');
        foreach ([$agent, ['privateKey' => $agent->privateKey]] as $key) {
            $r = Ap2::verifyPaymentChain(self::present($open, $key), self::payOpts($issuer));
            $this->assertSame(true, $r->get('ok'), (string)$r->get('reason'));
        }
        $late = self::openPay($issuer, $agent, '1970-01-01T00:00:01Z');
        $r = Ap2::verifyPaymentChain(self::present($late, $agent), self::payOpts($issuer));
        $this->assertSame(['ok', 'reason', 'violations'], $r->keys());
        $this->assertSame([false, 'open payment constraints violated: execution date is after the allowed window (not_after 1970-01-01T00:00:01Z)'], [$r->get('ok'), $r->get('reason')]);
        $r = Ap2::verifyPaymentChain(self::present($open, $agent), self::payOpts($issuer, ['clockSkewSeconds' => INF]));
        $this->assertSame([['ok', 'reason'], false, 'root mandate: expired at 5000'], [$r->keys(), $r->get('ok'), $r->get('reason')]);
    }

    /** Open mandates must carry exp, the closed mandate is validated, and the preceding mandate must have cnf.jwk. */
    public function testChainStructureRefusals(): void
    {
        [$issuer, $agent] = [Ap2::generateAp2KeyPair(), Ap2::generateAp2KeyPair()];
        $ref = [Obj::of(['type' => 'payment.reference', 'conditional_transaction_id' => 'c'])];
        $noExp = self::root(Obj::of(['vct' => Ap2::VCT_PAYMENT_OPEN, 'constraints' => $ref, 'cnf' => self::cnf($agent), 'iat' => 1000]), $issuer);
        $r = Ap2::verifyPaymentChain(self::hop($noExp, self::closedPay(), $agent, 'n1'), self::payOpts($issuer));
        $this->assertSame([false, 'open payment mandate: an open mandate must carry exp'], [$r->get('ok'), $r->get('reason')]);
        $r = Ap2::verifyDelegationChain(self::hop($noExp, self::closedPay(), $agent, 'n1'), self::payOpts($issuer, ['clockSkewSeconds' => INF]));
        $this->assertSame([false, 'root mandate: iat is in the future'], [$r->get('ok'), $r->get('reason')]);
        $open = self::openPay($issuer, $agent, '1970-01-01T01:00:00Z');
        $r = Ap2::verifyPaymentChain(self::hop($open, Obj::of(['vct' => Ap2::VCT_PAYMENT]), $agent, 'n1'), self::payOpts($issuer));
        $this->assertSame([false, 'closed payment mandate: transaction_id: required string; payee: not an object; payment_amount: not an object; payment_instrument: not an object'],
            [$r->get('ok'), $r->get('reason')]);
        foreach ([[], ['cnf' => Obj::of(['kid' => 'k'])]] as $cnf) {
            $noCnf = self::root(Obj::of(['vct' => Ap2::VCT_PAYMENT_OPEN, 'constraints' => $ref, 'exp' => 5000, ...$cnf]), $issuer);
            $r = Ap2::verifyDelegationChain(self::hop($noCnf, self::closedPay(), $agent, 'n1'), self::payOpts($issuer));
            $this->assertSame([false, 'preceding mandate: no cnf.jwk to delegate to'], [$r->get('ok'), $r->get('reason')]);
        }
        $this->throwsAp2(fn() => Ap2::presentClosedPayment(['open' => $open, 'agentKey' => $agent, 'aud' => 'a', 'nonce' => 'n', 'iat' => 1]),
            'closed payment mandate: transaction_id: required string; payee: not an object; payment_amount: not an object; payment_instrument: not an object');
    }

    /** The checkout chain: a cart outside the open line items is refused with the constraint reason; exp and the closed mandate are checked. */
    public function testCheckoutChain(): void
    {
        [$issuer, $agent, $merchant] = [Ap2::generateAp2KeyPair(), Ap2::generateAp2KeyPair(), Ap2::generateAp2KeyPair()];
        $cons = [Obj::of(['type' => 'checkout.line_items', 'items' => [Obj::of(['id' => 'r1', 'quantity' => 1, 'acceptable_items' => [Obj::of(['id' => 'sku1', 'title' => 'T'])]])]])];
        $open = Ap2::issueOpenCheckoutMandate(['issuer' => ['privateKey' => $issuer->privateKey], 'agentJwk' => $agent->publicJwk, 'iat' => 1000, 'exp' => 5000, 'salt' => 'abc',
            'constraints' => $cons]);
        $jwt = fn(string $sku) => Ap2::signJwtEs256(['header' => Obj::of(['kid' => 'm']), 'privateKey' => $merchant->privateKey, 'payload' => Obj::of(['id' => 'co1', 'currency' => 'USD',
            'line_items' => [Obj::of(['id' => 'l1', 'item' => Obj::of(['id' => $sku, 'title' => 'X', 'price' => 0]), 'quantity' => 1])], 'totals' => [Obj::of(['type' => 'total', 'amount' => 0])]])]);
        $o = ['resolveIssuerKey' => static fn($h) => $issuer->publicJwk, 'resolveMerchantKey' => static fn($h) => $merchant->publicJwk, 'expectedAudience' => 'merchant',
            'expectedNonce' => 'n2', 'now' => 2000];
        $present = fn(string $j) => Ap2::presentClosedCheckout(['open' => $open, 'agentKey' => $agent, 'aud' => 'merchant', 'nonce' => 'n2', 'iat' => 1500, 'checkoutJwt' => $j]);
        $ok = Ap2::verifyCheckoutChain($present($jwt('sku1')), $o);
        $this->assertSame(true, $ok->get('ok'), (string)$ok->get('reason'));
        $r = Ap2::verifyCheckoutChain($present($jwt('sku2')), $o);
        $why = 'line items do not satisfy the constraint: assigned 0 of 1 required and 1 carted units';
        $this->assertSame([['ok', 'reason', 'violations'], false, 'open checkout constraints violated: ' . $why, [$why]], [$r->keys(), $r->get('ok'), $r->get('reason'), $r->get('violations')]);
        $r = Ap2::verifyCheckoutChain(self::hop($open, Obj::of(['vct' => Ap2::VCT_CHECKOUT]), $agent, 'n2'), $o);
        $this->assertSame([false, 'closed checkout mandate: checkout_jwt: required string; checkout_hash: required string'], [$r->get('ok'), $r->get('reason')]);
        $noExp = self::root(Obj::of(['vct' => Ap2::VCT_CHECKOUT_OPEN, 'constraints' => $cons, 'cnf' => self::cnf($agent)]), $issuer);
        $j = $jwt('sku1');
        $closed = Obj::of(['vct' => Ap2::VCT_CHECKOUT, 'checkout_jwt' => $j, 'checkout_hash' => Ap2::sdDigest($j)]);
        $r = Ap2::verifyCheckoutChain(self::hop($noExp, $closed, $agent, 'n2'), $o);
        $this->assertSame([false, 'open checkout mandate: an open mandate must carry exp'], [$r->get('ok'), $r->get('reason')]);
        $this->throwsAp2(fn() => $present(''), 'closed checkout mandate: checkout_jwt: required string');
        $this->throwsAp2(fn() => Ap2::issueOpenCheckoutMandate(['issuer' => ['privateKey' => $issuer->privateKey], 'agentJwk' => $agent->publicJwk, 'iat' => 1.5, 'exp' => 5000,
            'constraints' => $cons]), 'open mandate: need integer iat < exp (epoch seconds)');
    }

    /** Line items: ids match by string form; the max flow is exact (a reverse edge starts empty and accumulates). */
    public function testLineItemFlow(): void
    {
        $chk = function (array $cart, array $reqs): array {
            $items = array_map(static fn($c) => Obj::of(['item' => Obj::of(['id' => $c[0]]), 'quantity' => $c[1]]), $cart);
            $rq = array_map(static fn($r) => Obj::of(['quantity' => $r[0], 'acceptable_items' => array_map(static fn($i) => Obj::of(['id' => $i]), $r[1])]), $reqs);
            return Ap2::checkCheckoutConstraints(Obj::of(['constraints' => [Obj::of(['type' => 'checkout.line_items', 'items' => $rq])]]), Obj::of(['line_items' => $items]));
        };
        $this->assertSame([], $chk([[5, 1]], [[1, ['5']]]));
        $this->assertSame(['line items do not satisfy the constraint: assigned 4 of 6 required and 6 carted units'],
            $chk([['A', 1], ['B', 2], ['C', 3]], [[3, ['A', 'B', 'C']], [3, ['A']]]));
        $this->assertSame(['line items do not satisfy the constraint: assigned 9 of 11 required and 9 carted units'],
            $chk([['A', 3], ['B', 3], ['C', 3]], [[1, ['B', 'C', 'D', 'E']], [2, ['A', 'B', 'C', 'D']], [1, ['A', 'B', 'C', 'D']], [3, ['A', 'B', 'D', 'E']], [4, ['B', 'D', 'E']]]));
        // an acceptable id listed twice adds one edge, not two: the flow stays capped at the edge capacity
        $this->assertSame($chk([['A', 2e16]], [[2e16, ['A']]]), $chk([['A', 2e16]], [[2e16, ['A', 'A']]]));
        $p = Ap2::projectCheckout(Obj::of(['id' => 'co', 'currency' => 'USD', 'totals' => [],
            'line_items' => [Obj::of(['id' => 'l', 'item' => Obj::of(['id' => 'i', 'title' => 't', 'price' => 0]), 'quantity' => 1])]]));
        $this->assertSame([0, 1], [$p->get('line_items')[0]->get('item')->get('price'), $p->get('line_items')[0]->get('quantity')]);
    }

    /** Budget amount_range / recurrence evaluation: every violation is reported, and now is in seconds. */
    public function testPaymentEvaluation(): void
    {
        $closed = Obj::of(['payment_amount' => Obj::of(['amount' => INF, 'currency' => 'USD'])]);
        $this->assertSame(['amount Infinity is not finite', 'amount Infinity exceeds maximum 100'],
            Ap2::checkPaymentConstraints(Obj::of(['constraints' => [Obj::of(['type' => 'payment.amount_range', 'currency' => 'USD', 'max' => 100])]]), $closed, []));
        $day = 1710547200;
        $rec = fn(array $c, int $now, int $last, int $uses) => Ap2::checkPaymentConstraints(Obj::of(['constraints' => [Obj::of(array_merge(['type' => 'payment.agent_recurrence', 'frequency' => 'DAILY'], $c))]]),
            $closed, ['now' => $now, 'context' => ['totalAmount' => 0, 'totalUses' => $uses, 'lastUsedDate' => $last]]);
        $need = ['payment.agent_recurrence requires a payment.amount_range constraint', 'payment.agent_recurrence requires a payment.budget constraint'];
        $this->assertSame([...$need, 'maximum occurrences exceeded: 1 >= 1', 'already used in the current DAILY period'], $rec(['max_occurrences' => 1], $day + 43200, $day + 1, 1));
        $this->assertSame([...$need, 'already used in the current DAILY period'], $rec([], $day + 43200, $day + 1, 0));
        $this->assertSame($need, $rec([], $day + 10, $day - 1, 0));
    }

    /** Option bags: an Obj or an associative array gives its members; a list or a scalar gives none. */
    public function testOptionBag(): void
    {
        $bag = self::priv('bag');
        $this->assertSame(['a' => 1], $bag->invoke(null, Obj::of(['a' => 1])));
        $this->assertSame(['x' => 1], $bag->invoke(null, ['x' => 1]));
        $this->assertSame([], $bag->invoke(null, [1, 2]));
        $this->assertSame([], $bag->invoke(null, null));
    }

    /**
     * A checkout token and a payment token bound to it, plus verifyPurchase options. `$over`: payload (members merged into the merchant's
     * checkout payload, null drops one), amount, payee, extra (more open payment constraints).
     * @return array{0: string, 1: string, 2: array<string,mixed>}
     */
    private static function purchase(array $over = []): array
    {
        [$issuer, $agent, $merchant] = [Ap2::generateAp2KeyPair(), Ap2::generateAp2KeyPair(), Ap2::generateAp2KeyPair()];
        $common = ['issuer' => ['privateKey' => $issuer->privateKey], 'agentJwk' => $agent->publicJwk, 'iat' => 1000, 'exp' => 5000];
        $openCheckout = Ap2::issueOpenCheckoutMandate([...$common, 'constraints' => [Obj::of(['type' => 'checkout.line_items',
            'items' => [Obj::of(['id' => 'r1', 'quantity' => 1, 'acceptable_items' => [Obj::of(['id' => 'sku1', 'title' => 'T'])]])]])]]);
        $payload = ['id' => 'co1', 'currency' => 'USD', 'line_items' => [Obj::of(['id' => 'l1', 'item' => Obj::of(['id' => 'sku1', 'title' => 'T', 'price' => 100]), 'quantity' => 1])],
            'totals' => [Obj::of(['type' => 'total', 'amount' => 100])], 'merchant' => Obj::of(['id' => 'm1', 'name' => 'M'])];
        foreach ($over['payload'] ?? [] as $k => $v) {
            if ($v === null) {
                unset($payload[$k]);
            } else {
                $payload[$k] = $v;
            }
        }
        $jwt = Ap2::signJwtEs256(['header' => Obj::of(['kid' => 'm']), 'payload' => Obj::of($payload), 'privateKey' => $merchant->privateKey]);
        $checkoutToken = Ap2::presentClosedCheckout(['open' => $openCheckout, 'agentKey' => $agent, 'aud' => 'merchant', 'nonce' => 'nc', 'iat' => 1500, 'checkoutJwt' => $jwt]);
        $openHash = Ap2::sdHashOf(Ap2::parseSdJwtHop($openCheckout));
        $openPayment = Ap2::issueOpenPaymentMandate([...$common, 'constraints' => [Obj::of(['type' => 'payment.reference', 'conditional_transaction_id' => $openHash]),
            ...($over['extra'] ?? [])]]);
        $paymentToken = Ap2::presentClosedPayment(['open' => $openPayment, 'agentKey' => $agent, 'aud' => 'merchant', 'nonce' => 'np', 'iat' => 1500,
            'transactionId' => Ap2::sdDigest($jwt), 'payee' => $over['payee'] ?? Obj::of(['id' => 'm1', 'name' => 'M']),
            'paymentAmount' => $over['amount'] ?? Obj::of(['amount' => 100, 'currency' => 'USD']), 'paymentInstrument' => Obj::of(['id' => 'i1', 'type' => 'card'])]);
        $o = ['resolveIssuerKey' => static fn($h) => $issuer->publicJwk, 'resolveMerchantKey' => static fn($h) => $merchant->publicJwk, 'now' => 2000,
            'checkout' => ['expectedAudience' => 'merchant', 'expectedNonce' => 'nc'], 'payment' => ['expectedAudience' => 'merchant', 'expectedNonce' => 'np']];
        return [$checkoutToken, $paymentToken, $o];
    }

    private function refusedWith(Obj $r, string $reason): void
    {
        $this->assertSame([['ok', 'reason'], false, $reason], [$r->keys(), $r->get('ok'), $r->get('reason')]);
    }

    /** verifyPurchase accepts a matching purchase and refuses each mismatch with its own reason (and nothing else). */
    public function testVerifyPurchase(): void
    {
        [$c, $p, $o] = self::purchase();
        $ok = Ap2::verifyPurchase($c, $p, $o);
        $this->assertSame([['ok', 'checkout', 'payment'], true], [$ok->keys(), $ok->get('ok')], (string)$ok->get('reason'));
        $this->refusedWith(Ap2::verifyPurchase($c, $p, [...$o, 'clockSkewSeconds' => INF]), 'checkout: root mandate: expired at 5000');
        $this->refusedWith(Ap2::verifyPurchase($c, $p, [...$o, 'checkout' => ['expectedAudience' => 'merchant', 'expectedNonce' => 'x']]), 'checkout: hop 1: nonce mismatch');
        $this->refusedWith(Ap2::verifyPurchase($c, $p, [...$o, 'payment' => ['expectedAudience' => 'merchant', 'expectedNonce' => 'x']]), 'payment: hop 1: nonce mismatch');
        [$c, $p, $o] = self::purchase(['payload' => ['totals' => []]]);
        $this->refusedWith(Ap2::verifyPurchase($c, $p, $o), 'checkout: needs exactly one total entry');
        [$c, $p, $o] = self::purchase(['amount' => Obj::of(['amount' => 100, 'currency' => 'EUR'])]);
        $this->refusedWith(Ap2::verifyPurchase($c, $p, $o), 'payment currency differs from the checkout currency');
        [$c, $p, $o] = self::purchase(['payload' => ['totals' => [Obj::of(['type' => 'total', 'amount' => 200])]]]);
        $this->refusedWith(Ap2::verifyPurchase($c, $p, $o), 'payment amount 100 differs from the checkout total 200');
        [$c, $p, $o] = self::purchase(['payload' => ['merchant' => null]]);
        $this->refusedWith(Ap2::verifyPurchase($c, $p, $o), 'checkout: no merchant to compare the payee with');
        [$c, $p, $o] = self::purchase(['payee' => Obj::of(['id' => 'm2', 'name' => 'M'])]);
        $this->refusedWith(Ap2::verifyPurchase($c, $p, $o), 'payee differs from the checkout merchant');
    }

    /** redeemPurchase: no ledger, a failing ledger and a replay each deny; the first check runs on a zero context (one use left still passes). */
    public function testRedeemPurchase(): void
    {
        [$c, $p, $o] = self::purchase(['extra' => [Obj::of(['type' => 'payment.amount_range', 'currency' => 'USD', 'max' => 1000]),
            Obj::of(['type' => 'payment.budget', 'currency' => 'USD', 'max' => 10]), Obj::of(['type' => 'payment.agent_recurrence', 'frequency' => 'ON_DEMAND', 'max_occurrences' => 1])]]);
        $this->refusedWith(Ap2::redeemPurchase($c, $p, $o, null), 'ledger_required');
        $ledger = new Money10Ledger(['totalAmount' => 0, 'totalUses' => 0]);
        $ok = Ap2::redeemPurchase($c, $p, $o, $ledger);
        $this->assertSame([true, 1, 0], [$ok->get('ok'), $ledger->reserves, $ledger->releases], (string)$ok->get('reason'));
        $this->refusedWith(Ap2::redeemPurchase($c, $p, $o, new Money10Ledger('replayed')), 'replayed');
        $this->refusedWith(Ap2::redeemPurchase($c, $p, $o, new Money10Ledger(null)), 'ledger_unavailable');
        $used = new Money10Ledger(['totalAmount' => 0, 'totalUses' => 1]);
        $r = Ap2::redeemPurchase($c, $p, $o, $used);
        $this->assertSame([false, 'payment: open payment constraints violated: maximum occurrences exceeded: 1 >= 1', 1, 1],
            [$r->get('ok'), $r->get('reason'), $used->reserves, $used->releases]);
    }

    /** budget.max: nudged up by exactly one ulp when cap / 10^e lands under the decimal; a cap with no exact value throws with its reason. */
    public function testBudgetMax(): void
    {
        $this->assertSame(78.74000000000001, Ap2::ap2BudgetMax(7874, 'JPY'));
        $this->assertSame(344039040087.91003, Ap2::ap2BudgetMax(34403904008791, 'USD'));
        $this->assertSame(68422740.96000001, Ap2::ap2BudgetMax(68422740960, 'KWD'));
        $this->assertSame(8.620000000000001, Ap2::ap2BudgetMax(86200, 'CLF'));
        $this->throwsAp2(fn() => Ap2::ap2BudgetMax(4344391529304477, 'USD'), 'cumulativeCap 4344391529304477 USD has no exact AP2 budget.max representation');
        $this->throwsAp2(fn() => Ap2::ap2BudgetMax(1.5, 'USD'), 'PCA term cumulativeCap must be a non-negative integer in minor units, got 1.5');
        $this->throwsAp2(fn() => Ap2::ap2BudgetReads(INF, 'USD'), 'budget.max must be a finite non-negative number, got Infinity');
    }

    /** Merchant descriptors: the first descriptor with the id wins, and a merchant with none is refused by id. A missing period end needs exp. */
    public function testConstraintsFromTerms(): void
    {
        $terms = Obj::of(['currency' => 'USD', 'perTransactionCap' => 100, 'cumulativeCap' => 1000, 'merchants' => ['m1']]);
        $first = Obj::of(['id' => 'm1', 'name' => 'First']);
        $c = Ap2::paymentConstraintsFromTerms($terms, [$first, Obj::of(['id' => 'm1', 'name' => 'Second'])], 'ref');
        $this->assertSame([$first], $c[1]->get('allowed'));
        $this->throwsAp2(fn() => Ap2::paymentConstraintsFromTerms($terms, [Obj::of(['id' => 'm9', 'name' => 'N'])], 'ref'), 'no merchant descriptor supplied for PCA merchant m1');
        $this->throwsAp2(fn() => Ap2::openPaymentMandateFromPca(['terms' => $terms], []), 'exp is required when the PCA terms have no period end');
    }

    /** An Ed25519 seed is taken from Bytes or a raw string; anything else (including the absent value) is a TypeError with the seed message. */
    public function testSeedBytes(): void
    {
        $seed = self::priv('seedBytes');
        $raw = str_repeat("\x01", 32);
        $this->assertSame($raw, $seed->invoke(null, $raw));
        $this->assertSame($raw, $seed->invoke(null, new Bytes($raw)));
        foreach ([5, \Atlas\Pca\Payments::UNDEF] as $bad) {
            try {
                $seed->invoke(null, $bad);
                $this->fail('seed accepted');
            } catch (\TypeError $e) {
                $this->assertSame('a 32-byte Ed25519 seed is required', $e->getMessage());
            }
        }
    }

    private static function pseed(string $label): string
    {
        return hash('sha256', 'atlas-pca-conformance/money10-' . $label, true);
    }

    /** A PCA payment mandate (X 1000, Y 100, cap 5000 USD, merchant m1, category food) and the open AP2 payment mandate issued from it. */
    private static function pcaOpen(): array
    {
        $mandate = Payments::buildPaymentMandate(['merchants' => ['m1'], 'currency' => 'USD', 'perTransactionCap' => 1000, 'autoApproveThreshold' => 100,
            'cumulativeCap' => 5000, 'categories' => ['food'], 'principalSecret' => self::pseed('principal'),
            'principalPublic' => (new KeyPair(self::pseed('principal')))->public, 'agentPublic' => (new KeyPair(self::pseed('agent')))->public, 'now' => 1000]);
        [$issuer, $agent] = [Ap2::generateAp2KeyPair(), Ap2::generateAp2KeyPair()];
        $open = Ap2::openPaymentMandateFromPca($mandate, ['issuer' => ['privateKey' => $issuer->privateKey], 'agentJwk' => $agent->publicJwk,
            'merchants' => [Obj::of(['id' => 'm1', 'name' => 'M'])], 'iat' => 1000, 'exp' => 5000, 'checkoutReference' => 'ref']);
        return ['mandate' => $mandate, 'open' => $open, 'agent' => $agent, 'issuer' => $issuer];
    }

    /** buildPcaPaymentBinding input: a 50 USD food charge at m1, counter 1, audience "aud", PCActn iat 2000 ms. */
    private static function bindIn(array $f, array $over = []): array
    {
        return array_merge(['mandate' => $f['mandate'], 'open' => $f['open'], 'agentJwk' => $f['agent']->publicJwk, 'agentSecret' => self::pseed('agent'),
            'audience' => 'aud', 'counter' => 1, 'transactionId' => 't1', 'payee' => Obj::of(['id' => 'm1', 'name' => 'M']),
            'amount' => Obj::of(['amount' => 50, 'currency' => 'USD']), 'instrumentId' => 'i1', 'category' => 'food', 'now' => 2000], $over);
    }

    /** The verifyPcaBinding input for the closed mandate that carries `$binding`, taken from a verified payment chain. */
    private static function pcaIn(array $f, Obj $binding, array $over = []): array
    {
        $token = Ap2::presentClosedPayment(['open' => $f['open'], 'agentKey' => $f['agent'], 'aud' => 'merchant', 'nonce' => 'np', 'iat' => 1500, 'transactionId' => 't1',
            'payee' => Obj::of(['id' => 'm1', 'name' => 'M']), 'paymentAmount' => Obj::of(['amount' => 50, 'currency' => 'USD']),
            'paymentInstrument' => Obj::of(['id' => 'i1', 'type' => 'card']), 'pca' => $binding]);
        $issuer = $f['issuer'];
        $v = Ap2::verifyPaymentChain($token, ['resolveIssuerKey' => static fn($h) => $issuer->publicJwk, 'expectedAudience' => 'merchant', 'expectedNonce' => 'np',
            'now' => 2000, 'openCheckoutHash' => 'ref', 'context' => ['totalAmount' => 0, 'totalUses' => 0]]);
        if ($v->get('ok') !== true) {
            throw new \LogicException('fixture chain refused: ' . (string)$v->get('reason'));
        }
        return array_merge(['open' => $v->get('open'), 'closed' => $v->get('closed'), 'openHash' => $v->get('openHash'),
            'expectedPrincipal' => (new KeyPair(self::pseed('principal')))->public, 'audience' => 'aud', 'mandate' => $f['mandate'], 'now' => 2000], $over);
    }

    /** An injected policy engine with a fixed verdict that records the decision input it was given. */
    private static function pcaEngine(bool $admit, bool $release, array $reasons, ?\ArrayObject $seen = null): \Closure
    {
        return static function (Obj $in) use ($admit, $release, $reasons, $seen): Obj {
            if ($seen !== null) {
                $seen['in'] = $in;
            }
            return Obj::of(['admit' => $admit, 'releaseGuardianShare' => $release, 'reasons' => $reasons, 'budget' => $in->get('budget'), 'r' => 0.05,
                'requiredThreshold' => Obj::of(['t' => 1])]);
        };
    }

    private static function withMembers(Obj $o, array $set): Obj
    {
        $c = Payments::spreadObj($o);
        foreach ($set as $k => $v) {
            $c->set($k, $v);
        }
        return $c;
    }

    /** A bound charge verifies; the decision sees the category, the caller's history and the given now; hooks see the PCActn and nowEpoch. */
    public function testPcaBindingAccepts(): void
    {
        $f = self::pcaOpen();
        $seen = new \ArrayObject();
        $ctx = new \ArrayObject();
        $in = self::pcaIn($f, Ap2::buildPcaPaymentBinding(self::bindIn($f)), ['recentChargeTimes' => [1500],
            'hooks' => ['attestation' => static function ($c) use ($ctx): array {
                $ctx['c'] = $c;
                return ['enforced' => false];
            }]]);
        $r = Ap2::verifyPcaBinding($in, self::pcaEngine(true, true, ['ok'], $seen));
        $this->assertSame([['ok', 'pcactn', 'grant', 'terms'], true], [$r->keys(), $r->get('ok')], (string)$r->get('reason'));
        $this->assertSame([2000, [1500], 'food'], [$seen['in']->get('now'), $seen['in']->get('caveatContext')->get('recentActionTimes'),
            $seen['in']->get('action')->get('action')->get('params')->get('category')]);
        $this->assertSame([true, 2000], [$ctx['c']->get('pcactn') instanceof Obj, $ctx['c']->get('nowEpoch')]);
        // with no now anywhere, both sides use the wall clock in milliseconds
        $live = self::pcaIn($f, Ap2::buildPcaPaymentBinding(self::bindIn($f, ['now' => null])));
        unset($live['now']);
        $r = Ap2::verifyPcaBinding($live, self::pcaEngine(true, true, []));
        $this->assertSame(true, $r->get('ok'), (string)$r->get('reason'));
    }

    /** The decision: a deny carries its reasons, a step-up needs a threshold hook that ENFORCED t >= 2, and an attestation hook can refuse. */
    public function testPcaBindingDecisionGates(): void
    {
        $f = self::pcaOpen();
        $in = self::pcaIn($f, Ap2::buildPcaPaymentBinding(self::bindIn($f)));
        $run = fn(array $over, \Closure $e) => Ap2::verifyPcaBinding([...$in, ...$over], $e);
        $this->refusedWith($run([], self::pcaEngine(false, false, ['no', true])), 'PCA denies this charge: no; true');
        $step = self::pcaEngine(false, true, []);
        $cosign = 'PCA requires a human co-sign for this charge and no verified threshold (t >= 2) was enforced';
        $hook = static fn(string $name, array $res): array => ['hooks' => [$name => static fn($c) => $res]];
        $this->refusedWith($run([], $step), $cosign);
        $ok = $run($hook('threshold', ['enforced' => true, 'ok' => true, 't' => 2]), $step);
        $this->assertSame(true, $ok->get('ok'), (string)$ok->get('reason'));
        $this->refusedWith($run($hook('threshold', ['enforced' => true, 'ok' => true, 't' => 1]), $step), $cosign);
        $this->refusedWith($run($hook('threshold', ['enforced' => false, 'ok' => true, 't' => 2]), $step), $cosign);
        $this->refusedWith($run($hook('attestation', ['enforced' => true, 'ok' => true, 't' => 2]), $step), $cosign);
        $this->refusedWith($run($hook('attestation', ['enforced' => true, 'ok' => false, 'reason' => 'bad']), self::pcaEngine(true, true, [])), 'PCActn: attestation: bad');
    }

    /** Structural refusals before the decision: enforce gates, undefined charge members and facts, understated risk, payee, risk policy. */
    public function testPcaBindingRefusals(): void
    {
        $f = self::pcaOpen();
        $in = self::pcaIn($f, Ap2::buildPcaPaymentBinding(self::bindIn($f)));
        $allow = self::pcaEngine(true, true, []);
        $run = fn(array $over) => Ap2::verifyPcaBinding([...$in, ...$over], $allow);
        $this->refusedWith($run(['enforce' => Obj::of(['taint' => true])]), 'PCActn: an enforce gate other than freshness is not supported by this verifier (fail closed)');
        $this->refusedWith($run(['enforce' => ['freshness' => 5]]), 'PCActn: enforce.freshness must be an object');
        $noHash = $in;
        unset($noHash['openHash']);
        $this->refusedWith(Ap2::verifyPcaBinding($noHash, $allow), 'canonical JSON cannot encode an undefined binding fact');
        $claim = self::withMembers($in['closed']->get('x_pca'), ['charge' => Obj::of(['currency' => 'USD', 'category' => 'food'])]);
        $this->refusedWith($run(['closed' => self::withMembers($in['closed'], ['x_pca' => $claim, 'payment_amount' => Obj::of(['currency' => 'USD'])])]),
            'canonical JSON cannot encode an undefined charge member');
        // a PCActn claiming less risk than amount / X is refused; exactly 1e-9 under is the tolerance
        $grant = $f['mandate']->get('grant');
        $claimed = fn(float $x) => self::withMembers($in['closed'], ['x_pca' => Ap2::buildPcaPaymentBinding(self::bindIn($f, ['mandate' => Obj::of(['grant' => $grant,
            'terms' => Obj::of(['perTransactionCap' => $x])])]))]);
        $this->refusedWith($run(['closed' => $claimed(1e6)]), 'PCActn understates the risk of this charge');
        $edge = $run(['closed' => $claimed(1000.0000200000004)]);
        $this->assertSame(true, $edge->get('ok'), (string)$edge->get('reason'));
        $m2 = Obj::of(['id' => 'm2', 'name' => 'N']);
        $this->refusedWith($run(['closed' => self::withMembers($in['closed'], ['payee' => $m2, 'x_pca' => Ap2::buildPcaPaymentBinding(self::bindIn($f, ['payee' => $m2]))])]),
            'payment currency or payee is outside the PCA terms');
        $terms = $f['mandate']->get('terms');
        $policy = Payments::mandateRiskPolicy($terms);
        $policy->set('kappa', 999);
        $g = Sign::mintGrant(new KeyPair(self::pseed('principal')), (new KeyPair(self::pseed('agent')))->public, ['predicates' => Payments::mandatePredicates($terms),
            'caveats' => Payments::mandateCaveats($terms), 'agent_binding' => new Obj(), 'risk_policy' => Sign::plain($policy)], 'goal')['grant'];
        $open = Obj::of(['x_pca' => Ap2::pcaOpenClaim(['grant' => $g, 'terms' => $terms]),
            'constraints' => Ap2::paymentConstraintsFromTerms($terms, [Obj::of(['id' => 'm1', 'name' => 'M'])], 'ref')]);
        $this->refusedWith($run(['open' => $open]), 'x_pca terms do not match the grant risk policy');
    }

    /** buildPcaPaymentBinding refuses a non-integer counter, a non-string audience and a mandate without a grant object. */
    public function testPcaBindingBuildRefusals(): void
    {
        $f = self::pcaOpen();
        $msg = 'buildPcaPaymentBinding: counter, audience and grant are required';
        $this->throwsAp2(fn() => Ap2::buildPcaPaymentBinding(self::bindIn($f, ['counter' => 1.5])), $msg);
        $this->throwsAp2(fn() => Ap2::buildPcaPaymentBinding(self::bindIn($f, ['audience' => 5])), $msg);
        $this->throwsAp2(fn() => Ap2::buildPcaPaymentBinding(self::bindIn($f, ['mandate' => Obj::of(['grant' => 'g', 'terms' => $f['mandate']->get('terms')])])), $msg);
    }

    /** A mandate that limits the charge count needs a history of finite numbers: one bad entry is enough to refuse. */
    public function testPcaBindingHistory(): void
    {
        $m = Obj::of(['terms' => Obj::of(['maxTransactionsPerPeriod' => 1])]);
        $allow = self::pcaEngine(true, true, []);
        try {
            Ap2::verifyPcaBinding(['mandate' => $m, 'recentChargeTimes' => ['x', 5]], $allow);
            $this->fail('history accepted');
        } catch (PcaBindingError $e) {
            $this->assertSame('charge_history_required', $e->codeName);
        }
        $this->assertSame(false, Ap2::verifyPcaBinding(['mandate' => $m, 'recentChargeTimes' => [5, 6]], $allow)->get('ok'));
    }

    /** Open constraints vs PCA terms: either budget read over the cap refuses, and exp is compared with the period end floored to seconds. */
    public function testConstraintsWithinTerms(): void
    {
        $cwt = self::priv('constraintsWithinTerms');
        $cons = static fn(int $budget): array => [Obj::of(['type' => 'payment.amount_range', 'currency' => 'JPY', 'max' => 100]),
            Obj::of(['type' => 'payment.allowed_payees', 'allowed' => [Obj::of(['id' => 'm1'])]]), Obj::of(['type' => 'payment.budget', 'currency' => 'JPY', 'max' => $budget])];
        $terms = ['currency' => 'JPY', 'perTransactionCap' => 100, 'cumulativeCap' => 500, 'merchants' => ['m1']];
        $this->assertNull($cwt->invoke(null, Obj::of(['constraints' => $cons(5)]), Obj::of($terms)));
        $this->assertSame('budget exceeds the PCA cumulative cap', $cwt->invoke(null, Obj::of(['constraints' => $cons(10)]), Obj::of($terms)));
        $pe = Obj::of([...$terms, 'periodEnd' => 5000500]);
        $this->assertSame('open mandate outlives the PCA period', $cwt->invoke(null, Obj::of(['constraints' => $cons(5), 'exp' => 5001]), $pe));
        $this->assertNull($cwt->invoke(null, Obj::of(['constraints' => $cons(5), 'exp' => 5000]), $pe));
        $inc = self::priv('includes');
        $this->assertSame([true, false, false, false, true, false],
            [$inc->invoke(null, 'abc', 'b'), $inc->invoke(null, 'abc', 'zz'), $inc->invoke(null, 'abc', 5), $inc->invoke(null, 5, '5'), $inc->invoke(null, ['a'], 'a'), $inc->invoke(null, ['a'], 'b')]);
    }

    /** Settlement payloads: atomic units are exact (0 stays "0"), refusals name the value, and the SPT currency is lowercased as Unicode. */
    public function testSettlement(): void
    {
        $amt = static fn($a, string $c = 'USD') => Obj::of(['amount' => $a, 'currency' => $c]);
        $this->assertSame(['0', '150', '150000000'], [Ap2::toAtomicUnits($amt(0), 6), Ap2::toAtomicUnits($amt(150), 2), Ap2::toAtomicUnits($amt(150), 8)]);
        foreach ([[fn() => Ap2::toAtomicUnits($amt(1), 19), 'x402: decimals must be an integer in 0..18, got 19'],
            [fn() => Ap2::toAtomicUnits($amt(1.5), 6), 'x402: amount 1.5 cannot be expressed in atomic units with 6 decimals'],
            [fn() => Ap2::toAtomicUnits($amt(1), 1), 'x402: amount 1 cannot be expressed in atomic units with 1 decimals']] as [$f, $m]) {
            try {
                $f();
                $this->fail('accepted');
            } catch (\RangeException $e) {
                $this->assertSame($m, $e->getMessage());
            }
        }
        $pay = static fn(string $type, mixed $cur) => Obj::of(['payment_instrument' => Obj::of(['id' => 'spt_1', 'type' => $type]),
            'payment_amount' => Obj::of(['amount' => 100, 'currency' => $cur]), 'payee' => Obj::of(['id' => 'm1'])]);
        $this->throwsAp2(fn() => Ap2::stripeSptSettlement($pay('card', 'USD')), 'stripe-spt: the payment instrument must be of type shared_payment_token, got card');
        $this->assertSame('éur', Ap2::stripeSptSettlement($pay('shared_payment_token', 'ÉUR'))->get('payload')->get('currency'));
        try {
            Ap2::stripeSptSettlement($pay('shared_payment_token', 5));
            $this->fail('accepted');
        } catch (\TypeError $e) {
            $this->assertSame('currency.toLowerCase is not a function', $e->getMessage());
        }
    }

    /** A budget whose max * 100 is within exactly 1e-6 of a whole number of minor units is accepted; a wider gap is refused. Issuing names what is malformed. */
    public function testBudgetToleranceAndIssueProblems(): void
    {
        $chk = static fn(float $max) => Ap2::checkPaymentConstraints(Obj::of(['constraints' => [Obj::of(['type' => 'payment.budget', 'currency' => 'USD', 'max' => $max])]]),
            Obj::of(['payment_amount' => Obj::of(['amount' => 0, 'currency' => 'USD'])]), ['context' => ['totalAmount' => 0, 'totalUses' => 0]]);
        $this->assertSame([], $chk(1e-8));
        $this->assertSame(['budget.max is not a whole number of minor units'], $chk(1.5e-8));
        $agent = Ap2::generateAp2KeyPair();
        $this->throwsAp2(fn() => Ap2::issueOpenPaymentMandate(['issuer' => ['privateKey' => $agent->privateKey], 'agentJwk' => $agent->publicJwk, 'iat' => 1000, 'exp' => 5000,
            'constraints' => [Obj::of(['type' => 'payment.execution_date', 'not_after' => '1970-01-01T01:00:00Z'])]]),
            'open payment mandate: constraints: must contain a payment.reference constraint');
    }
}

/** A purchase ledger that returns a fixed context (null: reserve throws) and counts its calls. */
final class Money10Ledger implements \Atlas\Pca\PurchaseLedger
{
    public int $reserves = 0;
    public int $releases = 0;

    public function __construct(private mixed $ctx)
    {
    }

    public function reserve(string $openMandateHash, string $transactionId, mixed $amountMinor): mixed
    {
        $this->reserves++;
        if ($this->ctx === null) {
            throw new \RuntimeException('ledger down');
        }
        return $this->ctx;
    }

    public function release(string $openMandateHash, string $transactionId): void
    {
        $this->releases++;
    }
}
