<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Bytes;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Webauthn;
use PHPUnit\Framework\TestCase;

/**
 * WebAuthn assertions hold their strict ES256 signature rules, COSE_Key reading, SPC payment comparison and exact refusal texts.
 * The ES256 signatures are built over P-256 arithmetic here (any r that is a curve point's x, any s, and the public key solved
 * for them), so the edge values a random signature never hits (r = 1, s = 1, s = n/2, a 64-byte DER, r's first byte 0x30) are
 * real, valid signatures.
 */
final class ProofSurvivorKill5WebauthnTest extends TestCase
{
    private const RP = 'rp.example';
    private const ORIGIN = 'https://app.example';
    private const P = 'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff';
    private const B = '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b';
    private const GX = '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296';
    private const GY = '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5';
    private const N = 'ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551';

    // ---- P-256 affine arithmetic (null is the point at infinity) ---------------------------------------------------------

    private static function g(string $hex): \GMP
    {
        return gmp_init($hex, 16);
    }

    /** @param ?array{0:\GMP,1:\GMP} $a @param ?array{0:\GMP,1:\GMP} $b @return ?array{0:\GMP,1:\GMP} */
    private static function add(?array $a, ?array $b): ?array
    {
        $p = self::g(self::P);
        if ($a === null) {
            return $b;
        }
        if ($b === null) {
            return $a;
        }
        if (gmp_cmp($a[0], $b[0]) === 0) {
            if (gmp_cmp(gmp_mod(gmp_add($a[1], $b[1]), $p), 0) === 0) {
                return null;
            }
            $l = gmp_mod(gmp_mul(gmp_sub(gmp_mul(3, gmp_mul($a[0], $a[0])), 3), gmp_invert(gmp_mul(2, $a[1]), $p)), $p);
        } else {
            $l = gmp_mod(gmp_mul(gmp_sub($b[1], $a[1]), gmp_invert(gmp_mod(gmp_sub($b[0], $a[0]), $p), $p)), $p);
        }
        $x = gmp_mod(gmp_sub(gmp_sub(gmp_mul($l, $l), $a[0]), $b[0]), $p);
        return [$x, gmp_mod(gmp_sub(gmp_mul($l, gmp_sub($a[0], $x)), $a[1]), $p)];
    }

    /** @param array{0:\GMP,1:\GMP} $pt @return ?array{0:\GMP,1:\GMP} */
    private static function mul(\GMP $k, array $pt): ?array
    {
        $r = null;
        $k = gmp_mod($k, self::g(self::N));
        for ($i = strlen(gmp_strval($k, 2)) - 1; $i >= 0; $i--) {
            $r = self::add($r, $r);
            if (gmp_testbit($k, $i)) {
                $r = self::add($r, $pt);
            }
        }
        return $r;
    }

    /** The curve point with this x (and an even-or-odd y), or null when x is not on the curve. @return ?array{0:\GMP,1:\GMP} */
    private static function lift(\GMP $x): ?array
    {
        $p = self::g(self::P);
        $rhs = gmp_mod(gmp_add(gmp_sub(gmp_powm($x, 3, $p), gmp_mul(3, $x)), self::g(self::B)), $p);
        $y = gmp_powm($rhs, gmp_div_q(gmp_add($p, 1), 4), $p);
        return gmp_cmp(gmp_powm($y, 2, $p), $rhs) === 0 ? [$x, $y] : null;
    }

    /** The first x >= $from that is on the curve. */
    private static function onCurveFrom(\GMP $from): \GMP
    {
        for ($x = $from;; $x = gmp_add($x, 1)) {
            if (self::lift($x) !== null) {
                return $x;
            }
        }
    }

    private static function be32(\GMP $v): string
    {
        return str_pad(gmp_export($v), 32, "\0", STR_PAD_LEFT);
    }

    /**
     * A valid ES256 signature (r = Rx mod n, s) over $msg and the public JWK it verifies under: Q = r^-1 (sR - zG).
     * @return array{0: \GMP, 1: \GMP, 2: array<string,string>} [r, s, jwk]
     */
    private static function forge(\GMP $rx, \GMP $s, string $msg): array
    {
        $n = self::g(self::N);
        $rp = self::lift($rx);
        self::assertNotNull($rp, 'R is on the curve');
        $r = gmp_mod($rx, $n);
        $z = gmp_import(hash('sha256', $msg, true));
        $G = [self::g(self::GX), self::g(self::GY)];
        $t = self::add(self::mul($s, $rp), self::mul(gmp_sub($n, gmp_mod($z, $n)), $G));
        $q = self::mul(gmp_invert($r, $n), $t);
        return [$r, $s, ['kty' => 'EC', 'crv' => 'P-256', 'x' => Pca::b64u(self::be32($q[0])), 'y' => Pca::b64u(self::be32($q[1]))]];
    }

    /** A DER INTEGER of the raw big-endian bytes as given (no normalization). */
    private static function int(string $v): string
    {
        return "\x02" . chr(strlen($v)) . $v;
    }

    private static function minimal(\GMP $v): string
    {
        $b = gmp_cmp($v, 0) === 0 ? "\0" : gmp_export($v);
        return (ord($b[0]) & 0x80) !== 0 ? "\0$b" : $b;
    }

    private static function der(\GMP $r, \GMP $s): string
    {
        $body = self::int(self::minimal($r)) . self::int(self::minimal($s));
        return "\x30" . chr(strlen($body)) . $body;
    }

    // ---- the assertion ----------------------------------------------------------------------------------------------------

    private static function challenge(): string
    {
        return hash('sha256', 'atlas-pca/webauthn-kill-5', true);
    }

    private static function ad(int $count = 7, int $flags = 0x05): string
    {
        return hash('sha256', self::RP, true) . chr($flags) . pack('N', $count);
    }

    private static function cd(): string
    {
        return (string) json_encode(['type' => 'webauthn.get', 'challenge' => Pca::b64u(self::challenge()), 'origin' => self::ORIGIN, 'crossOrigin' => false]);
    }

    private static function msg(): string
    {
        return self::ad() . hash('sha256', self::cd(), true);
    }

    private static function expect(array $extra = []): array
    {
        return $extra + ['expectedChallenge' => new Bytes(self::challenge()), 'rpId' => self::RP, 'origins' => [self::ORIGIN], 'storedSignCount' => 3];
    }

    /** verifyAssertion with every PHP warning / notice / deprecation turned into an exception (so a stray one shows in the reason). */
    private static function verify(string $sig, mixed $publicKey, array $expect = []): array
    {
        set_error_handler(static function (int $no, string $str): bool {
            throw new \ErrorException($str, 0, $no);
        });
        try {
            return Webauthn::verifyAssertion(['authenticatorData' => new Bytes(self::ad()), 'clientDataJSON' => new Bytes(self::cd()),
                'signature' => new Bytes($sig), 'publicKey' => $publicKey], self::expect($expect));
        } finally {
            restore_error_handler();
        }
    }

    private static function assertOk(array $v, string $m = ''): void
    {
        self::assertSame(['ok' => true, 'alg' => 'ES256', 'signCount' => 7, 'flags' => ['up' => true, 'uv' => true, 'be' => false, 'bs' => false, 'at' => false, 'ed' => false]], $v, $m);
    }

    private static function assertBadSig(array $v, string $m = ''): void
    {
        self::assertSame(['ok' => false, 'reason' => 'assertion signature did not verify'], $v, $m);
    }

    private static function typical(): array
    {
        return self::forge(self::onCurveFrom(gmp_init('4a' . str_repeat('5c', 31), 16)), gmp_init('31' . str_repeat('a7', 31), 16), self::msg());
    }

    public function testATypicalForgedSignatureVerifiesInBothEncodings(): void
    {
        [$r, $s, $jwk] = self::typical();
        self::assertOk(self::verify(self::der($r, $s), $jwk), 'DER');
        self::assertOk(self::verify(self::be32($r) . self::be32($s), $jwk), 'raw');
        self::assertBadSig(self::verify(self::der($r, gmp_add($s, 1)), $jwk), 'another s');
    }

    /** DER integers are strict: a needless leading zero, a missing sign pad or a wrong tag is refused even when the values verify. */
    public function testDerIntegersAreStrict(): void
    {
        // r's first byte odd and below 0x80, s plain
        [$r, $s, $jwk] = self::forge(self::onCurveFrom(gmp_init('15' . str_repeat('3c', 31), 16)), gmp_init('2b' . str_repeat('19', 31), 16), self::msg());
        self::assertOk(self::verify(self::der($r, $s), $jwk));
        $padded = self::int("\0" . gmp_export($r)) . self::int(gmp_export($s));
        self::assertBadSig(self::verify("\x30" . chr(strlen($padded)) . $padded, $jwk), 'needless leading zero');
        $wrongTag = "\x04" . substr(self::int(gmp_export($r)), 1) . self::int(gmp_export($s));
        self::assertBadSig(self::verify("\x30" . chr(strlen($wrongTag)) . $wrongTag, $jwk), 'r is not an INTEGER');
        $seqLong = self::int(gmp_export($r)) . self::int(gmp_export($s));
        self::assertBadSig(self::verify("\x30\x81" . chr(strlen($seqLong)) . $seqLong, $jwk), 'non-minimal long-form length');
        // r with its top bit set
        [$r, $s, $jwk] = self::forge(self::onCurveFrom(gmp_init('c1' . str_repeat('07', 31), 16)), gmp_init('2b' . str_repeat('19', 31), 16), self::msg());
        self::assertOk(self::verify(self::der($r, $s), $jwk));
        $unpadded = self::int(gmp_export($r)) . self::int(gmp_export($s));
        self::assertBadSig(self::verify("\x30" . chr(strlen($unpadded)) . $unpadded, $jwk), 'negative r');
    }

    /** Malformed DER is refused without reading past the bytes (no PHP warning on the way). */
    public function testMalformedDerIsRefusedCleanly(): void
    {
        [$r, $s, $jwk] = self::typical();
        $sigs = ["\x30", "\x30\x00", "\x30\x81", "\x30\x81\x01", "\x30\x81\x00", "\x30\x82\x00\x80", "\x30\x85\x00\x00\x00\x00\x80", "\x30\x02\x02\x00",
            "\x30\x03\x02\x01\x00", "\x30\x06\x02\x01\x00\x02\x01\x01", "\x30\x06\x02\x01\x01\x02\x01\x00", "\x30\x04\x02\x02\x00\x01",
            "\x30\x80" . substr(self::der($r, $s), 2), "\x30\x83\x00\x00\x46" . substr(self::der($r, $s), 2), self::der($r, $s) . "\x00",
            "\x30\x05\x02\x01\x01\x02\x00", "\x30\x03\x02\x81\x01"];
        foreach ($sigs as $sig) {
            self::assertBadSig(self::verify($sig, $jwk), bin2hex($sig));
        }
    }

    /** r and s must be in [1, n-1]: 0 and n are refused, s = 1 is a valid value. */
    public function testTheScalarRangeIsOneToNMinusOne(): void
    {
        $n = self::g(self::N);
        [$r, $s, $jwk] = self::forge(self::onCurveFrom(gmp_init('4a' . str_repeat('5c', 31), 16)), gmp_init(1), self::msg());
        self::assertOk(self::verify(self::der($r, $s), $jwk), 's = 1');
        // r = 1 cannot occur: no P-256 point has x = 1 or x = n + 1 (the only x < p with x mod n = 1)
        self::assertNull(self::lift(gmp_init(1)));
        self::assertNull(self::lift(gmp_add($n, 1)));
        foreach ([[gmp_init(0), $s], [$r, gmp_init(0)], [$n, $s], [$r, $n]] as [$a, $b]) {
            self::assertBadSig(self::verify(self::der($a, $b), $jwk), 'out of range');
        }
    }

    /** Low-S: s = floor(n/2) is low, one above is high. */
    public function testLowSBoundaryIsHalfTheOrder(): void
    {
        $half = gmp_div_q(self::g(self::N), 2);
        $rx = self::onCurveFrom(gmp_init('4a' . str_repeat('5c', 31), 16));
        [$r, $s, $jwk] = self::forge($rx, $half, self::msg());
        self::assertOk(self::verify(self::der($r, $s), $jwk, ['requireLowS' => true]));
        [$r, $s, $jwk] = self::forge($rx, gmp_add($half, 1), self::msg());
        self::assertOk(self::verify(self::der($r, $s), $jwk));
        self::assertBadSig(self::verify(self::der($r, $s), $jwk, ['requireLowS' => true]));
    }

    /** A 64-byte signature is always r || s, even when it starts with 0x30; any other length starting with 0x30 is DER. */
    public function testSixtyFourBytesAreRawEvenWhenTheyLookLikeDer(): void
    {
        [$r, $s, $jwk] = self::forge(self::onCurveFrom(gmp_init('30' . str_repeat('77', 31), 16)), gmp_init('2b' . str_repeat('19', 31), 16), self::msg());
        $raw = self::be32($r) . self::be32($s);
        self::assertSame("\x30", $raw[0]);
        self::assertOk(self::verify($raw, $jwk), 'raw starting 0x30');
        // a 64-byte DER (r of 25 bytes, s of 33 with its pad) is read as r || s and so refused
        [$r, $s, $jwk] = self::forge(self::onCurveFrom(gmp_init('15' . str_repeat('3c', 24), 16)), gmp_init('c1' . str_repeat('07', 31), 16), self::msg());
        $der = self::der($r, $s);
        self::assertSame(64, strlen($der));
        self::assertBadSig(self::verify($der, $jwk), '64-byte DER');
        // 63 and 65 bytes starting 0x30: DER (valid) and DER (refused)
        [$r, $s, $jwk] = self::forge(self::onCurveFrom(gmp_init('15' . str_repeat('3c', 23), 16)), gmp_init('c1' . str_repeat('07', 31), 16), self::msg());
        self::assertSame(63, strlen(self::der($r, $s)));
        self::assertOk(self::verify(self::der($r, $s), $jwk), '63-byte DER');
    }

    public function testKeyResolutionFailuresNameTheirCause(): void
    {
        [$r, $s, $jwk] = self::typical();
        $sig = self::der($r, $s);
        self::assertSame(['ok' => false, 'reason' => 'public key could not be resolved: resolveKey: invalid EC JWK coordinates'],
            self::verify($sig, ['x' => '!!'] + $jwk));
        self::assertSame(['ok' => false, 'reason' => 'public key could not be resolved: resolveKey: invalid EC JWK coordinates'],
            self::verify($sig, ['y' => '!!'] + $jwk));
        self::assertSame(['ok' => false, 'reason' => 'public key could not be resolved: resolveKey: unsupported public key'], self::verify($sig, ['kty' => 'RSA', 'n' => 'AQAB', 'e' => 'AQAB']));
        self::assertSame(['ok' => false, 'reason' => 'verification error (fail closed): Cannot read properties of null (reading \'authenticatorData\')'],
            Webauthn::verifyAssertion(null, self::expect()));
    }

    public function testTheSignCountIsTheFourBytesAfterTheFlags(): void
    {
        $h = hash('sha256', self::RP, true);
        foreach (["\x01\x02\x03\x04", "\x01\x02\x03\x04\xff", "\x01\x02\x03\x04\xff\xee\xdd\xcc"] as $tail) {
            $p = Webauthn::parseAuthenticatorData($h . "\x05" . $tail);
            self::assertSame(0x01020304, $p['signCount']);
        }
    }

    // ---- COSE_Key -----------------------------------------------------------------------------------------------------------

    private static function okpX(): string
    {
        return str_repeat("\x11", 32);
    }

    private static function okp(): array
    {
        return ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Pca::b64u(self::okpX()), 'alg' => 'EdDSA'];
    }

    public function testCoseArgumentsOfOneTwoAndFourBytes(): void
    {
        $x = self::okpX();
        self::assertSame(self::okp(), Webauthn::coseKeyToJwk(new Bytes("\xa4\x01\x01\x03\x27\x20\x06\x21\x58\x20$x")));
        self::assertSame(self::okp(), Webauthn::coseKeyToJwk(new Bytes("\xa4\x01\x01\x03\x27\x20\x06\x21\x59\x00\x20$x")));
        self::assertSame(self::okp(), Webauthn::coseKeyToJwk(new Bytes("\xa4\x01\x01\x03\x27\x20\x06\x21\x5a\x00\x00\x00\x20$x")));
        // an argument that ends exactly at the end of the bytes
        self::assertSame(self::okp(), Webauthn::coseKeyToJwk(new Bytes("\xa4\x01\x01\x20\x06\x21\x58\x20$x\x04\x18\x64")));
        self::assertSame(self::okp(), Webauthn::coseKeyToJwk(new Bytes("\xa4\x01\x01\x20\x06\x21\x58\x20$x\x04\x19\x01\x00")));
        self::assertSame(self::okp(), Webauthn::coseKeyToJwk(new Bytes("\xa4\x01\x01\x20\x06\x21\x58\x20$x\x04\x1a\x01\x00\x00\x00")));
        // a two-byte coordinate length for EC2 y
        $y = str_repeat("\x22", 32);
        self::assertSame(['kty' => 'EC', 'crv' => 'P-256', 'x' => Pca::b64u($x), 'y' => Pca::b64u($y), 'alg' => 'ES256'],
            Webauthn::coseKeyToJwk(new Bytes("\xa4\x01\x02\x20\x01\x21\x58\x20$x\x22\x59\x00\x20$y")));
    }

    /** @return array{0:string,1:string} [class, message] of what coseKeyToJwk throws */
    private static function coseThrow(mixed $b): array
    {
        try {
            Webauthn::coseKeyToJwk($b);
        } catch (\Throwable $e) {
            return [get_class($e), $e->getMessage()];
        }
        self::fail('no throw');
    }

    public function testCoseRefusalsAreExact(): void
    {
        $x = self::okpX();
        foreach (["\xa1\x01\x19\x00", "\xa1\x01\x1a\x00\x00\x00", "\xa1\x01\x18", "\xb9\x00", "\xa1\x01"] as $b) {
            self::assertSame([\RangeException::class, 'Offset is outside the bounds of the DataView'], self::coseThrow(new Bytes($b)), bin2hex($b));
        }
        self::assertSame([\RuntimeException::class, 'cose: byte string length out of range'], self::coseThrow(new Bytes("\xa1\x21\x58\x20\x01\x02\x03")));
        self::assertSame([\RuntimeException::class, 'cose: byte string length out of range'], self::coseThrow(new Bytes("\xa1\x21\x59\x00\x21$x")));
        self::assertSame([\RuntimeException::class, 'cose: non-integer map key'], self::coseThrow(new Bytes("\xa1\x41\x00\x01")));
        self::assertSame([\RuntimeException::class, 'cose: unsupported CBOR major type 4'], self::coseThrow(new Bytes("\x80")));
        self::assertSame([\RuntimeException::class, 'cose: unsupported CBOR major type 3'], self::coseThrow(new Bytes("\xa1\x01\x61\x41")));
        self::assertSame([\TypeError::class, 'coseKeyToJwk: expected a Uint8Array'], self::coseThrow(5));
        self::assertSame([\TypeError::class, 'coseKeyToJwk: expected a Uint8Array'], self::coseThrow(null));
        self::assertSame([\RuntimeException::class, 'coseKeyToJwk: COSE_Key is not a CBOR map'], self::coseThrow(new Bytes("\x01")));
        self::assertSame([\RuntimeException::class, 'coseKeyToJwk: COSE_Key is not a CBOR map'], self::coseThrow(new Bytes("\x41\x00")));
        $kty = [
            "\xa1\x01\x41\x00" => '[object Uint8Array]',
            "\xa1\x01\xa0" => '[object Map]',
            "\xa1\x01\x03" => '3',
            "\xa1\x01\x20" => '-1',
            "\xa1\x03\x27" => 'undefined',
        ];
        foreach ($kty as $b => $shown) {
            self::assertSame([\RuntimeException::class, "coseKeyToJwk: unsupported COSE key type (kty=$shown)"], self::coseThrow(new Bytes($b)), bin2hex($b));
        }
    }

    public function testAStepUpDigestStringMustBeCanonical(): void
    {
        foreach (['abc', '', Pca::b64u(str_repeat("\x01", 31))] as $d) {
            try {
                Webauthn::stepUpChallengeB64u($d);
                self::fail('no throw');
            } catch (\RangeException $e) {
                self::assertSame('buildStepUpChallenge: digest is not a canonical base64url 32-byte value', $e->getMessage());
            }
        }
    }

    // ---- SPC payment ----------------------------------------------------------------------------------------------------

    private static function expectation(array $total = ['currency' => 'USD', 'value' => '1.00'], array $extra = []): Obj
    {
        return Obj::of($extra + ['payeeName' => 'Shop', 'topOrigin' => 'https://top.example', 'total' => Obj::of($total)]);
    }

    private static function payment(array $total = ['currency' => 'USD', 'value' => '1.00'], array $extra = []): Obj
    {
        return Obj::of($extra + ['rpId' => self::RP, 'topOrigin' => 'https://top.example', 'payeeName' => 'Shop', 'total' => Obj::of($total)]);
    }

    public function testPaymentRecordsMayBeAssociativeArrays(): void
    {
        $pay = ['rpId' => self::RP, 'topOrigin' => 'https://top.example', 'payeeName' => 'Shop', 'total' => ['currency' => 'USD', 'value' => '1.00']];
        self::assertNull(Webauthn::spcPaymentError($pay, self::expectation(), self::RP));
        self::assertSame('clientData.payment is missing', Webauthn::spcPaymentError([], self::expectation(), self::RP));
        self::assertSame('clientData.payment is missing', Webauthn::spcPaymentError(['a', 'b'], self::expectation(), self::RP));
        self::assertSame('clientData.payment.total does not equal the canonical render',
            Webauthn::spcPaymentError(['total' => ['USD', '1.00']] + $pay, self::expectation(), self::RP));
    }

    public function testAnAbsentMemberDiffersFromANullOne(): void
    {
        $pay = Obj::of(['rpId' => self::RP, 'payeeName' => 'Shop', 'total' => Obj::of(['currency' => 'USD', 'value' => '1.00'])]);
        self::assertSame('clientData.payment.topOrigin is not the verifier approval origin', Webauthn::spcPaymentError($pay, self::expectation(extra: ['topOrigin' => null]), self::RP));
        $pay2 = self::payment(extra: ['topOrigin' => null]);
        $e2 = Obj::of(['payeeName' => 'Shop', 'total' => Obj::of(['currency' => 'USD', 'value' => '1.00'])]);
        self::assertSame('clientData.payment.topOrigin is not the verifier approval origin', Webauthn::spcPaymentError($pay2, $e2, self::RP));
    }

    /** Numbers compare by value (1 equals 1.0); a number never equals null or a string. */
    public function testPaymentNumbersCompareByValue(): void
    {
        $bad = 'clientData.payment.total does not equal the canonical render';
        self::assertNull(Webauthn::spcPaymentError(self::payment(['currency' => 'USD', 'value' => 5]), self::expectation(['currency' => 'USD', 'value' => 5]), self::RP));
        self::assertNull(Webauthn::spcPaymentError(self::payment(['currency' => 'USD', 'value' => 1]), self::expectation(['currency' => 'USD', 'value' => 1.0]), self::RP));
        self::assertNull(Webauthn::spcPaymentError(self::payment(['currency' => 'USD', 'value' => 1.0]), self::expectation(['currency' => 'USD', 'value' => 1]), self::RP));
        self::assertSame($bad, Webauthn::spcPaymentError(self::payment(['currency' => 'USD', 'value' => 5]), self::expectation(['currency' => 'USD', 'value' => 6]), self::RP));
        self::assertSame($bad, Webauthn::spcPaymentError(self::payment(['currency' => 'USD', 'value' => 0]), self::expectation(['currency' => 'USD', 'value' => null]), self::RP));
        self::assertSame($bad, Webauthn::spcPaymentError(self::payment(['currency' => 'USD', 'value' => null]), self::expectation(['currency' => 'USD', 'value' => 0]), self::RP));
        self::assertSame($bad, Webauthn::spcPaymentError(self::payment(['currency' => 'USD', 'value' => 1]), self::expectation(['currency' => 'USD', 'value' => '1']), self::RP));
    }

    /** null equals null; an object never equals anything, not even itself. */
    public function testNullEqualsNullAndObjectsNeverEqual(): void
    {
        self::assertNull(Webauthn::spcPaymentError(self::payment(extra: ['payeeName' => null]), self::expectation(extra: ['payeeName' => null]), self::RP));
        $o = Obj::of(['n' => 'Shop']);
        self::assertSame('clientData.payment.payeeName does not equal the canonical render',
            Webauthn::spcPaymentError(self::payment(extra: ['payeeName' => $o]), self::expectation(extra: ['payeeName' => $o]), self::RP));
    }
}
