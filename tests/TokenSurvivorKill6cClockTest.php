<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\Jose;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Oidc;
use Atlas\Pca\Pca;
use Atlas\Pca\Sdjwt;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * The default wall clocks through the clock seam: the JWKS cache clock is floor(epoch ms), the KB-JWT stamp is the second rounded
 * down, the KB age window and the core clock read floor(epoch ms).
 */
final class TokenSurvivorKill6cClockTest extends TestCase
{
    private const EXPIRED = 'validity: the PCActn has expired';
    private const X = '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo';

    protected function tearDown(): void
    {
        Oidc::$clockHook = null;
        Sdjwt::$clockHook = null;
    }

    // ---- Oidc: the JWKS cache clock ----

    /** Fetches made by a resolver whose two lookups happen at clock values $t1 and $t2 (epoch seconds). */
    private static function fetchesAcross(float $maxAgeSec, float $t1, float $t2): int
    {
        $t = $t1;
        Oidc::$clockHook = static function () use (&$t): float {
            return $t;
        };
        $n = 0;
        $body = (string)json_encode(['keys' => [['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::X]]]);
        $fetch = static function (string $u, array $h, mixed $to) use (&$n, $body): array {
            $n++;
            return ['status' => 200, 'body' => $body, 'headers' => []];
        };
        $r = Oidc::createOidcJwks(['jwksUri' => 'https://jwks.example', 'fetch' => $fetch, 'cacheMaxAgeSec' => $maxAgeSec]);
        $h = Obj::of(['alg' => 'EdDSA']);
        self::assertSame(self::X, Js::opt($r($h), 'x'));
        $t = $t2;
        self::assertSame(self::X, Js::opt($r($h), 'x'));
        return $n;
    }

    /** The cache ages in whole milliseconds of the clock: exactly the max age refetches, just under it does not. */
    public function testJwksCacheClockIsFlooredMilliseconds(): void
    {
        self::assertSame(2, self::fetchesAcross(1000, 1000.0, 2000.0), '1 000 000 ms is the 1000 s max age');
        self::assertSame(1, self::fetchesAcross(1000.0005, 1000.0, 2000.0), '1 000 000 ms is under 1000.0005 s');
        self::assertSame(1, self::fetchesAcross(0.0025, 1000.0, 1000.0026), 'floor(1 000 002.6) - 1 000 000 = 2 ms, under 2.5 ms');
        self::assertSame(2, self::fetchesAcross(0.0025, 1000.0, 1000.0036), '3 ms is over 2.5 ms');
    }

    // ---- Sdjwt ----

    private static function issuer(): KeyPair
    {
        return new KeyPair(str_repeat("\x01", 32));
    }

    private static function holder(): KeyPair
    {
        return new KeyPair(str_repeat("\x02", 32));
    }

    private static function priv(KeyPair $kp, string $seed): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public, 'd' => Pca::b64u($seed)]);
    }

    private static function pub(KeyPair $kp): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public]);
    }

    /** An issuer SD-JWT (iat `$base`, one hour) with one disclosed claim b, bound to the holder key. */
    private static function sdJwt(int $base): string
    {
        $d = Pca::b64u((string)json_encode(['sb', 'b', 2]));
        $p = Obj::of(['iss' => 'https://iss', 'aud' => 'rs', 'iat' => $base, 'exp' => $base + 3600, '_sd_alg' => 'sha-256',
            '_sd' => [Jose::b64u(hash('sha256', $d, true))], 'cnf' => Obj::of(['jwk' => self::pub(self::holder())])]);
        return Jose::signJwt($p, Obj::of(['alg' => 'EdDSA', 'typ' => 'pca+sd-jwt']), self::priv(self::issuer(), str_repeat("\x01", 32))) . "~$d~";
    }

    private static function present(string $sd, array $kb): string
    {
        return Sdjwt::present($sd, ['b'], Obj::of(['keyBinding' => Obj::of($kb + ['holderKey' => self::priv(self::holder(), str_repeat("\x02", 32)), 'audience' => 'rs'])]));
    }

    /** A KB-JWT stamped at 1800000000.7 s carries iat 1800000000 (rounded down, never up). */
    public function testKbStampIsTheSecondRoundedDown(): void
    {
        Sdjwt::$clockHook = static fn(): float => 1_800_000_000.7;
        $kb = explode('~', self::present(self::sdJwt(time() - 10), []));
        $payload = Js::parse(Jose::lenientB64d(explode('.', $kb[count($kb) - 1])[1]));
        self::assertSame(1_800_000_000.0, Js::num($payload->get('iat')));
    }

    /**
     * kbMaxAgeSec 0 with a KB iat of 1799999999, on a clock at 1799999999.9996 s: floor(ms) / 1000 is still 1799999999 (fresh); a
     * clock rounded up to the next millisecond reads 1800000000 (too old). At 1800000000.0004 s it is too old.
     */
    public function testKbAgeWindowClockIsFlooredMilliseconds(): void
    {
        $p = self::present(self::sdJwt(time() - 10), ['iat' => 1_799_999_999]);
        $opts = Obj::of(['issuerKey' => self::pub(self::issuer()), 'kbMaxAgeSec' => 0]);
        Sdjwt::$clockHook = static fn(): float => 1_799_999_999.9996;
        $r = Sdjwt::verifyPcaSdJwt($p, $opts);
        self::assertTrue($r->get('ok'), (string)$r->get('reason'));
        Sdjwt::$clockHook = static fn(): float => 1_800_000_000.0004;
        self::assertSame('KB-JWT is older than the accepted window', Sdjwt::verifyPcaSdJwt($p, $opts)->get('reason'));
    }

    /** @return array{0: Obj, 1: Obj} a fresh PCActn's SD-JWT verify result and its grant */
    private static function fresh(): array
    {
        $principal = new KeyPair(hash('sha256', 'atlas-pca-conformance/sdjwt-principal', true));
        $key = new KeyPair(hash('sha256', 'atlas-pca-conformance/sdjwt-agent', true));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order')['grant'];
        $act = (new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/1', ['amount_cents' => 500])->pcactn;
        $res = Sdjwt::verifyPcaSdJwt(Sdjwt::issuePcaSdJwt($act, ['issuerKey' => self::priv(self::issuer(), str_repeat("\x01", 32))]),
            Obj::of(['issuerKey' => self::pub(self::issuer())]));
        self::assertTrue($res->get('ok'), (string)$res->get('reason'));
        return [$res, $grant];
    }

    /** The verify result with the PCActn's iat / exp moved to [exp - 1 s, exp] (the signature no longer matches; validity is checked first). */
    private static function withExp(Obj $res, int $exp): Obj
    {
        $iat = $exp - 1000;
        $c = $res->get('claims')->without('iat_ms', 'exp_ms');
        $c->set('iat_ms', new Num((string)$iat));
        $c->set('exp_ms', new Num((string)$exp));
        $p = $res->get('processed')->without('iat', 'exp');
        $p->set('iat', new Num((string)intdiv($iat, 1000)));
        $p->set('exp', new Num((string)(int)max(ceil($exp / 1000), intdiv($iat, 1000) + 1)));
        return Obj::of(['claims' => $c, 'processed' => $p]);
    }

    /** The core clock is floor(epoch ms): at m + 0.6 ms a PCActn expiring at m is not expired; at m + 1.6 ms it is. */
    public function testCoreClockIsFlooredMilliseconds(): void
    {
        [$res, $grant] = self::fresh();
        $opts = ['grant' => $grant, 'audience' => 'rs-test', 'insecureSkipPlanRootCheck' => true];
        $m = (int)floor(microtime(true) * 1000);
        $r = self::withExp($res, $m);
        Sdjwt::$clockHook = static fn(): float => ($m + 1.6) / 1000;
        self::assertSame(self::EXPIRED, Sdjwt::verifyRecovered($r, $opts)['reason']);
        Sdjwt::$clockHook = static fn(): float => ($m + 0.6) / 1000;
        self::assertNotSame(self::EXPIRED, Sdjwt::verifyRecovered($r, $opts)['reason']);
    }
}
