<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Jose;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sdjwt;
use Atlas\Pca\Signals;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A clock beyond +-8.64e15 ms is not a Date (the signature library would read it as no clock), and a KB-JWT iat of +-Infinity would slip past
 * the age window: both are refused, with a positive control for each so the fixture is shown to reach the check.
 */
final class UnrepresentableTimeTest extends TestCase
{
    private const NOW_SEC = 1_800_000_000;

    private static function privJwk(KeyPair $kp, string $seed): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public, 'd' => Pca::b64u($seed)]);
    }

    private static function pubJwk(KeyPair $kp): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public]);
    }

    // ---- Shared Signals: receiveSET ------------------------------------------------------------------------------------------------

    /** @return array{0:string,1:Obj,2:Obj} a signed SET, the public key, and receive options (nowSec set by the caller) */
    private static function set(): array
    {
        $seed = str_repeat("\x07", 32);
        $kp = new KeyPair($seed);
        $events = Obj::of(['https://schemas.openid.net/secevent/caep/event-type/session-revoked' => Obj::of([])]);
        $set = Signals::buildSET($events, 'https://tx.example', 'rx', self::privJwk($kp, $seed), 'user-1');
        $opts = Obj::of(['issuer' => 'https://tx.example', 'audience' => 'rx', 'replayStore' => Signals::createInMemorySetReplayStore(),
            'state' => Signals::createRevocationState(), 'maxAgeSec' => 3600]);
        return [$set, self::pubJwk($kp), $opts];
    }

    public function testReceiveSetAcceptsARepresentableClock(): void
    {
        [$set, $key, $opts] = self::set();
        $opts->set('nowSec', time());
        self::assertTrue(Signals::receiveSET($set, $key, $opts)['ok']);
    }

    #[DataProvider('badClocks')]
    public function testReceiveSetRefusesAnUnrepresentableNowSec(float $bad): void
    {
        [$set, $key, $opts] = self::set();
        $opts->set('nowSec', $bad);
        $r = Signals::receiveSET($set, $key, $opts);
        self::assertFalse($r['ok']);
        self::assertSame('verify_failed', $r['code']);
        self::assertSame('nowSec is not a representable time', $r['reason']);
    }

    /** @return array<string,array{float}> */
    public static function badClocks(): array
    {
        return ['1e300' => [1e300], '-1e300' => [-1e300], 'NaN' => [NAN], 'Infinity' => [INF], '-Infinity' => [-INF], 'just past the Date range' => [8.64e12 + 1.0]];
    }

    /** @return array<string,array{float}> milliseconds: the SD-JWT clock is in ms, the SET clock in seconds */
    public static function badClocksMs(): array
    {
        return ['1e300' => [1e300], '-1e300' => [-1e300], 'NaN' => [NAN], 'Infinity' => [INF], '-Infinity' => [-INF], 'just past the Date range' => [8.64e15 + 1000.0]];
    }

    // ---- SD-JWT: now and the KB-JWT iat --------------------------------------------------------------------------------------------

    /** @return array{0:string,1:Obj,2:Obj} the issued SD-JWT (one disclosure), the holder private JWK and the verifier options */
    private static function sdJwt(): array
    {
        $issuerSeed = str_repeat("\x01", 32);
        $holderSeed = str_repeat("\x02", 32);
        $issuer = new KeyPair($issuerSeed);
        $holder = new KeyPair($holderSeed);
        $disclosure = Pca::b64u((string) json_encode(['sb', 'b', 2]));
        $digest = Jose::b64u(hash('sha256', $disclosure, true));
        $payload = Obj::of(['iss' => 'https://iss', 'aud' => 'rs', 'iat' => self::NOW_SEC, 'exp' => self::NOW_SEC + 3600, '_sd_alg' => 'sha-256',
            '_sd' => [$digest], 'cnf' => Obj::of(['jwk' => self::pubJwk($holder)])]);
        $jwt = Jose::signJwt($payload, Obj::of(['alg' => 'EdDSA', 'typ' => 'pca+sd-jwt']), self::privJwk($issuer, $issuerSeed));
        $opts = Obj::of(['issuerKey' => self::pubJwk($issuer), 'now' => self::NOW_SEC * 1000, 'kbMaxAgeSec' => 300, 'expectedAudience' => 'rs']);
        return [$jwt . '~' . $disclosure . '~', self::privJwk($holder, $holderSeed), $opts];
    }

    private static function presentation(mixed $iat): string
    {
        [$sd, $holderKey] = self::sdJwt();
        return Sdjwt::present($sd, ['b'], Obj::of(['keyBinding' => Obj::of(['holderKey' => $holderKey, 'audience' => 'rs', 'nonce' => 'n1', 'iat' => $iat])]));
    }

    public function testASoundPresentationVerifies(): void
    {
        [, , $opts] = self::sdJwt();
        $r = Sdjwt::verifyPcaSdJwt(self::presentation(self::NOW_SEC), $opts);
        self::assertTrue($r->get('ok'), (string) $r->get('reason'));
    }

    #[DataProvider('badClocksMs')]
    public function testSdJwtRefusesAnUnrepresentableNow(float $bad): void
    {
        [, , $opts] = self::sdJwt();
        $opts->set('now', $bad);
        $r = Sdjwt::verifyPcaSdJwt(self::presentation(self::NOW_SEC), $opts);
        self::assertFalse($r->get('ok'));
        // NaN and the infinities are refused as not finite; the finite out-of-range values are refused as not representable
        self::assertSame(is_finite($bad) ? 'now is not a representable time' : 'now, clockToleranceSec and kbMaxAgeSec must be finite', $r->get('reason'));
    }

    #[DataProvider('badIats')]
    public function testSdJwtRefusesANonFiniteKbJwtIat(string $iat): void
    {
        [, , $opts] = self::sdJwt();
        $r = Sdjwt::verifyPcaSdJwt(self::presentation(new Num($iat)), $opts);
        self::assertFalse($r->get('ok'));
        // the strict profile refuses a number that is not written as a plain decimal before the iat check can see it: the KB-JWT is refused whole
        self::assertStringStartsWith('KB-JWT', (string) $r->get('reason'));
        self::assertStringNotContainsString('is in the future', (string) $r->get('reason'));
    }

    /** @return array<string,array{string}> */
    public static function badIats(): array
    {
        return ['+Infinity' => ['1e999'], '-Infinity' => ['-1e999']];
    }
}
