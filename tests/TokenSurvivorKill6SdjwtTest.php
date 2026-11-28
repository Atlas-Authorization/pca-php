<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Agent;
use Atlas\Pca\Attest\PubKey;
use Atlas\Pca\Jose;
use Atlas\Pca\Js;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Sdjwt;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/**
 * SD-JWT of a PCActn: the Disclosure digest over the ASCII view, presentation (which Disclosures a selection keeps), Disclosure
 * processing, the KB-JWT clock / audience / age checks, the cnf key thumbprint, issuance refusals, and verifyRecovered.
 */
final class TokenSurvivorKill6SdjwtTest extends TestCase
{
    private const NOW_SEC = 1_800_000_000;

    private static function issuer(): KeyPair
    {
        return new KeyPair(str_repeat("\x01", 32));
    }

    private static function holder(): KeyPair
    {
        return new KeyPair(str_repeat("\x02", 32));
    }

    private static function privJwk(KeyPair $kp, string $seed): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public, 'd' => Pca::b64u($seed)]);
    }

    private static function pubJwk(KeyPair $kp): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $kp->public]);
    }

    private static function issuerPriv(): Obj
    {
        return self::privJwk(self::issuer(), str_repeat("\x01", 32));
    }

    private static function holderPriv(): Obj
    {
        return self::privJwk(self::holder(), str_repeat("\x02", 32));
    }

    private static function disc(array $parts): string
    {
        return Pca::b64u((string)json_encode($parts, JSON_UNESCAPED_SLASHES));
    }

    private static function dig(string $e): string
    {
        return Jose::b64u(hash('sha256', $e, true));
    }

    /** An issuer JWT over `$claims` (iss, aud rs, iat/exp around `$base`, sha-256, cnf = the holder) followed by `$disclosures`. */
    private static function sdJwt(array $claims, array $disclosures, int $base = self::NOW_SEC): string
    {
        $p = Obj::of(['iss' => 'https://iss', 'aud' => 'rs', 'iat' => $base, 'exp' => $base + 3600, '_sd_alg' => 'sha-256']);
        foreach ($claims as $k => $v) {
            $p->set($k, $v);
        }
        $p->set('cnf', Obj::of(['jwk' => self::pubJwk(self::holder())]));
        $jwt = Jose::signJwt($p, Obj::of(['alg' => 'EdDSA', 'typ' => 'pca+sd-jwt']), self::issuerPriv());
        return $jwt . '~' . implode('', array_map(static fn(string $d): string => $d . '~', $disclosures));
    }

    private static function opts(array $o = []): Obj
    {
        return Obj::of($o + ['issuerKey' => self::pubJwk(self::issuer()), 'now' => self::NOW_SEC * 1000]);
    }

    /** @return list<string> warnings raised while `$f` ran */
    private static function warnings(callable $f): array
    {
        $seen = [];
        set_error_handler(static function (int $no, string $msg) use (&$seen): bool {
            $seen[] = $msg;
            return true;
        });
        try {
            $f();
        } finally {
            restore_error_handler();
        }
        return $seen;
    }

    // ---- the Disclosure digest ---------------------------------------------------------------------------------------------------

    /**
     * The digest hashes the low byte of each UTF-16 code unit: a segment whose first character is U+0157 has the same ASCII view as one
     * starting with "W", so presenting both is a duplicate Disclosure.
     */
    public function testDigestIsOverTheAsciiView(): void
    {
        $e1 = self::disc(['sb', 'b', 2]);
        self::assertSame('W', $e1[0]);
        $e2 = "\u{0157}" . substr($e1, 1);
        $sd = self::sdJwt(['_sd' => [self::dig($e1)]], [$e1]);
        self::assertTrue(Sdjwt::verifyPcaSdJwt($sd, self::opts())->get('ok'));
        $r = null;
        $w = self::warnings(static function () use (&$r, $sd, $e2): void {
            $r = Sdjwt::verifyPcaSdJwt($sd . $e2 . '~', self::opts());
        });
        self::assertSame([], $w);
        self::assertFalse($r->get('ok'));
        self::assertSame('duplicate disclosure', $r->get('reason'));
    }

    // ---- presentation --------------------------------------------------------------------------------------------------------

    /**
     * Selecting a claim keeps its Disclosure and every Disclosure nested anywhere in its value (`_sd` inside an object member), skips
     * decoys and non-string `_sd` entries, never treats a plain string list as digests, and a decoy before it does not stop the scan.
     */
    public function testPresentKeepsNestedDisclosures(): void
    {
        $d2 = self::disc(['s2', 'b', 1]);
        $d5 = self::disc(['s5', 'e', 3]);
        $d1 = self::disc(['s1', 'a', ['x' => ['_sd' => [self::dig($d2), 5, 'decoy-digest']], 'list' => [self::dig($d5)]]]);
        $sd = self::sdJwt(['_sd' => ['decoy-top', self::dig($d1), self::dig($d5)]], [$d1, $d2, $d5]);
        $jwt = explode('~', $sd)[0];
        $out = null;
        $w = self::warnings(static function () use (&$out, $sd): void {
            $out = Sdjwt::present($sd, ['a']);
        });
        self::assertSame([], $w);
        self::assertSame($jwt . '~' . $d1 . '~' . $d2 . '~', $out);
    }

    /** Only a [salt, name, value] Disclosure with a string name is selectable by name; a [salt, value] pair or a numeric name is not. */
    public function testPresentSelectsOnlyNamedTriples(): void
    {
        $num = self::disc(['s6', 5, 'v']);
        $pair = self::disc(['s7', 'a']);
        $sd = self::sdJwt(['_sd' => [self::dig($num), self::dig($pair)]], [$num, $pair]);
        self::assertSame(explode('~', $sd)[0] . '~', Sdjwt::present($sd, [5, 'a']));
    }

    /** A KB-JWT without an explicit iat is stamped with the current second, rounded down. */
    public function testPresentStampsTheCurrentSecond(): void
    {
        $d = self::disc(['sb', 'b', 2]);
        $sd = self::sdJwt(['_sd' => [self::dig($d)]], [$d]);
        $m0 = microtime(true);
        $p = Sdjwt::present($sd, ['b'], Obj::of(['keyBinding' => Obj::of(['holderKey' => self::holderPriv(), 'audience' => 'rs'])]));
        $m1 = microtime(true);
        $kb = explode('~', $p);
        $payload = Js::parse(Jose::lenientB64d(explode('.', $kb[count($kb) - 1])[1]));
        $iat = Js::num($payload->get('iat'));
        self::assertContains($iat, [floor($m0), floor($m1)]);
    }

    // ---- Disclosure processing -----------------------------------------------------------------------------------------------

    /**
     * Below the top level a security-critical name (iss) may be selectively disclosed: inside an array element Disclosure, a plain array
     * element and a disclosed member's value. An undisclosed array element before a disclosed one does not end the array.
     */
    public function testNestedCriticalNamesAndArrayElements(): void
    {
        $e = self::disc(['s8', 'v']);
        $f1 = self::disc(['s9', 'iss', 'x']);
        $g = self::disc(['s10', ['_sd' => [self::dig($f1)]]]);
        $f2 = self::disc(['s11', 'iss', 'y']);
        $f3 = self::disc(['s13', 'iss', 'z']);
        $h = self::disc(['s12', 'nest', ['_sd' => [self::dig($f3)]]]);
        $sd = self::sdJwt([
            'arr' => [Obj::of(['...' => 'decoy']), Obj::of(['...' => self::dig($e)])],
            'arr2' => [Obj::of(['...' => self::dig($g)])],
            'arr3' => [Obj::of(['_sd' => [self::dig($f2)]])],
            '_sd' => [self::dig($h)],
        ], [$e, $f1, $g, $f2, $f3, $h]);
        $r = Sdjwt::verifyPcaSdJwt($sd, self::opts());
        self::assertTrue($r->get('ok'), (string)$r->get('reason'));
        $p = $r->get('processed');
        self::assertSame(['v'], $p->get('arr'));
        self::assertSame('x', $p->get('arr2')[0]->get('iss'));
        self::assertSame('y', $p->get('arr3')[0]->get('iss'));
        self::assertSame('z', $p->get('nest')->get('iss'));
        self::assertSame(['nest'], $r->get('disclosed')->keys());
    }

    // ---- options and the KB-JWT ----------------------------------------------------------------------------------------------

    /** A clock of exactly +-8.64e15 ms is still a representable time (the refusal is only beyond it). */
    public function testClockAtTheDateLimitIsAccepted(): void
    {
        foreach ([8.64e15, -8.64e15] as $now) {
            $r = Sdjwt::verifyPcaSdJwt('x', Obj::of(['now' => $now]));
            self::assertSame('pca-sdjwt: malformed SD-JWT (missing ~ separator)', $r->get('reason'));
        }
    }

    private static function presented(mixed $iat, string $aud = 'rs', int $base = self::NOW_SEC): string
    {
        $d = self::disc(['sb', 'b', 2]);
        $sd = self::sdJwt(['_sd' => [self::dig($d)]], [$d], $base);
        return Sdjwt::present($sd, ['b'], Obj::of(['keyBinding' => Obj::of(['holderKey' => self::holderPriv(), 'audience' => $aud, 'iat' => $iat])]));
    }

    /** expectedKbAudience alone checks the KB-JWT aud, and the refusal carries the JOSE reason. */
    public function testExpectedKbAudienceAloneIsEnforced(): void
    {
        self::assertTrue(Sdjwt::verifyPcaSdJwt(self::presented(self::NOW_SEC), self::opts(['expectedKbAudience' => 'rs']))->get('ok'));
        $r = Sdjwt::verifyPcaSdJwt(self::presented(self::NOW_SEC, 'other'), self::opts(['expectedKbAudience' => 'rs']));
        self::assertFalse($r->get('ok'));
        self::assertSame('KB-JWT signature/claims invalid: unexpected "aud" claim value', $r->get('reason'));
    }

    /** The KB age window is in whole seconds of `now` rounded down, and an age of exactly kbMaxAgeSec is inside it. */
    public function testKbAgeWindowBoundaries(): void
    {
        $r = Sdjwt::verifyPcaSdJwt(self::presented(self::NOW_SEC), self::opts(['now' => self::NOW_SEC * 1000 + 600, 'kbMaxAgeSec' => 0]));
        self::assertTrue($r->get('ok'), (string)$r->get('reason'));
        $r = Sdjwt::verifyPcaSdJwt(self::presented(self::NOW_SEC), self::opts(['now' => (self::NOW_SEC + 300) * 1000, 'kbMaxAgeSec' => 300]));
        self::assertTrue($r->get('ok'), (string)$r->get('reason'));
        $r = Sdjwt::verifyPcaSdJwt(self::presented(self::NOW_SEC), self::opts(['now' => (self::NOW_SEC + 301) * 1000, 'kbMaxAgeSec' => 300]));
        self::assertSame('KB-JWT is older than the accepted window', $r->get('reason'));
    }

    /** With no clockToleranceSec a KB iat one second ahead is in the future. */
    public function testKbIatAheadWithoutTolerance(): void
    {
        $r = Sdjwt::verifyPcaSdJwt(self::presented(self::NOW_SEC + 1), self::opts(['kbMaxAgeSec' => 300]));
        self::assertFalse($r->get('ok'));
        self::assertSame('KB-JWT iat is in the future', $r->get('reason'));
        $r = Sdjwt::verifyPcaSdJwt(self::presented(self::NOW_SEC + 1), self::opts(['kbMaxAgeSec' => 300, 'clockToleranceSec' => 1]));
        self::assertTrue($r->get('ok'), (string)$r->get('reason'));
    }

    /** With no `now` the age window reads the wall clock in milliseconds: a KB-JWT stamped now is fresh. */
    public function testKbAgeWindowOnTheWallClock(): void
    {
        $base = time() - 10;
        $r = Sdjwt::verifyPcaSdJwt(self::presented(time(), 'rs', $base), Obj::of(['issuerKey' => self::pubJwk(self::issuer()), 'kbMaxAgeSec' => 300]));
        self::assertTrue($r->get('ok'), (string)$r->get('reason'));
    }

    /** The KB-JWT's own time claims are checked at the verifier's `now`, not the wall clock. */
    public function testKbJwtClaimsUseTheGivenClock(): void
    {
        $base = 2_500_000_000;
        $d = self::disc(['sb', 'b', 2]);
        $head = Sdjwt::present(self::sdJwt(['_sd' => [self::dig($d)]], [$d], $base), ['b']);
        $kb = Jose::signJwt(Obj::of(['iat' => $base, 'aud' => 'rs', 'sd_hash' => self::dig($head), 'exp' => $base + 10]),
            Obj::of(['alg' => 'EdDSA', 'typ' => 'kb+jwt']), self::holderPriv());
        $o = static fn(int $at): Obj => Obj::of(['issuerKey' => self::pubJwk(self::issuer()), 'now' => $at * 1000]);
        self::assertTrue(Sdjwt::verifyPcaSdJwt($head . $kb, $o($base + 5))->get('ok'));
        $r = Sdjwt::verifyPcaSdJwt($head . $kb, $o($base + 100));
        self::assertFalse($r->get('ok'));
        self::assertSame('KB-JWT signature/claims invalid: "exp" claim timestamp check failed', $r->get('reason'));
    }

    // ---- the cnf key thumbprint ----------------------------------------------------------------------------------------------

    private static function thumbX(mixed $k): mixed
    {
        return (new \ReflectionMethod(Sdjwt::class, 'thumbX'))->invoke(null, $k);
    }

    private static function ecKey(?string $curve, array $ec): PubKey
    {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($k);
        return new PubKey($k, '', 'ec', $curve, ['ec' => $ec]);
    }

    /** A public-key x coordinate is left-padded to the curve's field size; an unknown curve or a missing x has no thumbprint. */
    public function testThumbprintOfAPublicKey(): void
    {
        foreach (['prime256v1' => 32, 'secp384r1' => 48, 'secp521r1' => 66] as $curve => $size) {
            $x = str_repeat("\x01", $size - 1);
            self::assertSame(Jose::b64u("\0" . $x), self::thumbX(self::ecKey($curve, ['x' => $x])), $curve);
            $full = str_repeat("\x02", $size);
            self::assertSame(Jose::b64u($full), self::thumbX(self::ecKey($curve, ['x' => $full])), $curve);
        }
        self::assertNull(self::thumbX(self::ecKey('secp256k1', ['x' => str_repeat("\x01", 32)])));
        self::assertNull(self::thumbX(self::ecKey('prime256v1', [])));
        self::assertSame(Jose::b64u('abc'), self::thumbX('abc'));
        self::assertSame('XX', self::thumbX(Obj::of(['kty' => 'OKP', 'x' => 'XX'])));
        try {
            self::thumbX(5);
            self::fail('a key of no known shape has a thumbprint');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('pca-sdjwt: keyBindingKey must be raw bytes, a JWK or a public key', $e->getMessage());
        }
    }

    // ---- issuance --------------------------------------------------------------------------------------------------------------

    private static function pcActn(array $over = []): Obj
    {
        return Obj::of($over + ['cap_chain' => [Obj::of(['issuer' => 'I', 'holder' => self::holder()->public])], 'aud' => 'rs',
            'iat' => 1_800_000_000_000, 'exp' => 1_800_000_600_000, 'action' => Obj::of(['verb' => 'read'])]);
    }

    private static function issueFails(mixed $pcActn, array $options, string $message): void
    {
        try {
            Sdjwt::issuePcaSdJwt($pcActn, $options + ['issuerKey' => self::issuerPriv()]);
            self::fail("issued: $message");
        } catch (\InvalidArgumentException $e) {
            self::assertSame($message, $e->getMessage());
        }
    }

    /** Disclosure salts are 128-bit. */
    public function testIssuedSaltIs16Bytes(): void
    {
        $sd = Sdjwt::issuePcaSdJwt(self::pcActn(), ['issuerKey' => self::issuerPriv()]);
        $names = [];
        foreach (array_slice(explode('~', $sd), 1, -1) as $d) {
            $parts = Js::parse(Jose::lenientB64d($d));
            $names[] = $parts[1];
            self::assertSame(16, strlen(Jose::lenientB64d($parts[0])), (string)$parts[1]);
        }
        self::assertSame(['cap_chain', 'action'], $names);
    }

    /** Issuance refusals, each with its own reason. */
    public function testIssuanceRefusals(): void
    {
        self::issueFails(['cap_chain' => []], [], 'pca-sdjwt: pcActn must be an object');
        self::issueFails(self::pcActn(['cap_chain' => 'x']), [], 'pca-sdjwt: pcActn.cap_chain must be a non-empty array');
        self::issueFails(self::pcActn(['iat' => 'x']), [], 'pca-sdjwt: PCActn.iat must be a finite number (epoch ms)');
        self::issueFails(self::pcActn(['exp' => INF]), [], 'pca-sdjwt: PCActn.exp must be a finite number (epoch ms)');
        self::issueFails(self::pcActn(['cap_chain' => [Obj::of(['issuer' => 'I', 'holder' => ''])]]), ['keyBinding' => true],
            'pca-sdjwt: cannot derive holder key — cap_chain leaf holder is missing');
        self::issueFails(self::pcActn(), ['keyBinding' => ['holderPublicKey' => Obj::of(['crv' => 'x'])]],
            'pca-sdjwt: keyBinding.holderPublicKey must be a JWK or a raw Ed25519 public key');
    }

    // ---- verifyRecovered -------------------------------------------------------------------------------------------------------

    private static function recovered(Obj $claims, Obj $processed, array $core = []): array
    {
        return Sdjwt::verifyRecovered(Obj::of(['claims' => $claims, 'processed' => $processed]), $core);
    }

    /** verifyRecovered refuses anything but a verify result with both claims and processed objects. */
    public function testRecoveredNeedsAVerifyResult(): void
    {
        foreach ([[Obj::of([]), 'x'], ['x', Obj::of([])]] as [$c, $p]) {
            try {
                Sdjwt::verifyRecovered(Obj::of(['claims' => $c, 'processed' => $p]), []);
                self::fail('accepted a malformed result');
            } catch (\InvalidArgumentException $e) {
                self::assertSame('pca-sdjwt: verifyRecovered needs a successful verifyPcaSdJwt result', $e->getMessage());
            }
        }
    }

    /** iat_ms / exp_ms agree with iat (floored) and exp (ceiled, at least iat + 1 s), also for a zero and a sub-second lifetime. */
    public function testRecoveredTimeConsistency(): void
    {
        foreach ([1_800_000_000_000, 1_800_000_000_600] as $ms) {
            $r = self::recovered(Obj::of(['iat_ms' => $ms, 'exp_ms' => $ms]), Obj::of(['iat' => self::NOW_SEC, 'exp' => self::NOW_SEC + 1]));
            self::assertFalse($r['allow']);
            self::assertSame("pca-sdjwt: required claim 'action' was not disclosed", $r['reason'], (string)$ms);
        }
    }

    private static function crafted(array $chain): array
    {
        $claims = Obj::of(['iat_ms' => 1_800_000_000_000, 'exp_ms' => 1_800_000_600_000, 'action' => Obj::of([]), 'cap_chain' => $chain, 'plan' => Obj::of([]),
            'sig' => 's', 'grant_ref' => 'g', 'counter' => 1]);
        $processed = Obj::of(['iss' => 'I', 'sub' => 'H', 'aud' => 'rs', 'iat' => self::NOW_SEC, 'exp' => self::NOW_SEC + 600]);
        return [$claims, $processed];
    }

    /** A one-hop chain is checked against its own root and leaf; a null root is a TypeError as in the reference. */
    public function testRecoveredChainMembers(): void
    {
        [$c, $p] = self::crafted([Obj::of(['issuer' => 'I', 'holder' => 'H'])]);
        $r = null;
        $w = self::warnings(static function () use (&$r, $c, $p): void {
            $r = self::recovered($c, $p);
        });
        self::assertSame([], $w);
        self::assertSame('audience: PCActn carries a signed aud but this verifier supplied no audience (pass your audience, or Audience::Any to accept any)', $r['reason']);
        self::assertSame('audience: the verifier audience must be a string or Audience::Any', self::recovered($c, $p, ['audience' => 5])['reason']);
        [$c, $p] = self::crafted([null]);
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage("Cannot read properties of null (reading 'issuer')");
        self::recovered($c, $p);
    }

    /** @return array{0: Obj, 1: Obj} a fresh PCActn's SD-JWT verify result (wall clock) and its grant */
    private static function fresh(): array
    {
        $principal = new KeyPair(hash('sha256', 'atlas-pca-conformance/sdjwt-principal', true));
        $key = new KeyPair(hash('sha256', 'atlas-pca-conformance/sdjwt-agent', true));
        $env = ['predicates' => [['verb' => 'refund', 'resource' => 'orders/*']], 'caveats' => [], 'risk_policy' => Sign::defaultRiskPolicy()];
        $grant = Sign::mintGrant($principal, $key->public, $env, 'refund an order')['grant'];
        $act = (new Agent($key, $grant, 'rs-test'))->act('refund', 'orders/1', ['amount_cents' => 500])->pcactn;
        $res = Sdjwt::verifyPcaSdJwt(Sdjwt::issuePcaSdJwt($act, ['issuerKey' => self::issuerPriv()]), Obj::of(['issuerKey' => self::pubJwk(self::issuer())]));
        self::assertTrue($res->get('ok'), (string)$res->get('reason'));
        return [$res, $grant];
    }

    /**
     * A PCActn minted now is allowed on the default (wall, millisecond) clock; allowedSuites and authorizedPlanRoots reach the core; the
     * rebuilt PCActn takes `ver` from the processed payload only.
     */
    public function testRecoveredThroughTheCore(): void
    {
        [$res, $grant] = self::fresh();
        $base = ['grant' => $grant, 'audience' => 'rs-test'];
        $r = Sdjwt::verifyRecovered($res, $base + ['insecureSkipPlanRootCheck' => true]);
        self::assertTrue($r['allow'], $r['reason'] ?? '');
        self::assertFalse(Sdjwt::verifyRecovered($res, $base + ['insecureSkipPlanRootCheck' => true, 'allowedSuites' => []])['allow']);
        $root = $res->get('claims')->get('plan')->get('root');
        $r = Sdjwt::verifyRecovered($res, $base + ['authorizedPlanRoots' => [$root]]);
        self::assertTrue($r['allow'], $r['reason'] ?? '');
        $noVer = Obj::of(['claims' => $res->get('claims'), 'processed' => $res->get('processed')->without('ver')]);
        self::assertFalse(Sdjwt::verifyRecovered($noVer, $base + ['insecureSkipPlanRootCheck' => true])['allow']);
    }
}
