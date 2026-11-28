<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Attest\CanonicalJwsError;
use Atlas\Pca\JoseError;
use Atlas\Pca\Js;
use Atlas\Pca\Obj;
use Atlas\Pca\Oidc;
use Atlas\Pca\OidcClaimFailed;
use Atlas\Pca\OidcCodedError;
use Atlas\Pca\OidcDiscoveryError;
use Atlas\Pca\OidcVerificationError;
use PHPUnit\Framework\TestCase;

/** OIDC discovery, the JWKS resolvers and ID-token verification: every refusal keeps its exact code and reason. */
final class TokenSurvivorKill6OidcTest extends TestCase
{
    private const ISS = 'https://idp.example';
    private const NOW = 1_700_000_000;
    private const SECRET = 'oidc-kill6-hmac-secret-0123456789';
    private const META = '{"issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks"}';
    private const WK = 'https://idp.example/.well-known/openid-configuration';
    private const NOFILE = 'file:///nonexistent-pca-kill6';

    private static ?array $rsa = null;
    private static ?array $ec = null;

    private static function b64(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    private static function json(array $v): string
    {
        return (string)json_encode($v, JSON_UNESCAPED_SLASHES);
    }

    /** A compact JWS: HS256 over SECRET by default; `$sig` replaces the signature bytes. */
    private static function tok(array $payload, array $header = ['alg' => 'HS256'], ?string $secret = null, ?string $sig = null): string
    {
        $h = self::b64(self::json($header));
        $p = self::b64(self::json($payload));
        $s = $sig ?? hash_hmac('sha256', "$h.$p", $secret ?? self::SECRET, true);
        return "$h.$p." . self::b64($s);
    }

    private static function claims(array $extra = [], array $drop = []): array
    {
        $c = array_merge(['iss' => self::ISS, 'sub' => 'u1', 'aud' => 'client-1', 'iat' => self::NOW - 100, 'exp' => self::NOW + 100], $extra);
        foreach ($drop as $k) {
            unset($c[$k]);
        }
        return $c;
    }

    private static function opts(array $extra = [], array $drop = []): array
    {
        $o = array_merge(['issuer' => self::ISS, 'audience' => 'client-1', 'key' => self::SECRET, 'algorithms' => ['HS256'], 'now' => self::NOW], $extra);
        foreach ($drop as $k) {
            unset($o[$k]);
        }
        return $o;
    }

    /** ['ok'] or [codeName, message]. */
    private static function verdict(mixed $tok, mixed $o): array
    {
        try {
            Oidc::verifyIdToken($tok, $o);
            return ['ok'];
        } catch (OidcVerificationError $e) {
            return [$e->codeName, $e->getMessage()];
        }
    }

    private static function edSeed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/oidc-kill6', true);
    }

    private static function edJwk(): array
    {
        $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::edSeed()));
        return ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::b64($pk)];
    }

    private static function edTok(array $payload, array $header = ['alg' => 'EdDSA']): string
    {
        $h = self::b64(self::json($header));
        $p = self::b64(self::json($payload));
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::edSeed()));
        return "$h.$p." . self::b64(sodium_crypto_sign_detached("$h.$p", $sk));
    }

    private static function newKey(array $spec): \OpenSSLAsymmetricKey
    {
        $cnf = (string)tempnam(sys_get_temp_dir(), 'pcacnf');
        file_put_contents($cnf, "[req]\ndistinguished_name=dn\n[dn]\n");
        $k = openssl_pkey_new(['config' => $cnf] + $spec);
        unlink($cnf);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $k);
        return $k;
    }

    /** A 2040-bit RSA key: [n (255 bytes), e]. */
    private static function rsa(): array
    {
        if (self::$rsa === null) {
            $d = openssl_pkey_get_details(self::newKey(['private_key_bits' => 2040, 'private_key_type' => OPENSSL_KEYTYPE_RSA]))['rsa'];
            self::$rsa = [ltrim($d['n'], "\0"), $d['e']];
        }
        return self::$rsa;
    }

    /** A P-256 public point: [x, y], 32 bytes each. */
    private static function ec(): array
    {
        if (self::$ec === null) {
            $d = openssl_pkey_get_details(self::newKey(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']))['ec'];
            self::$ec = [str_pad($d['x'], 32, "\0", STR_PAD_LEFT), str_pad($d['y'], 32, "\0", STR_PAD_LEFT)];
        }
        return self::$ec;
    }

    /** A fetch that answers every request with one response and records [url, headers, timeout]. */
    private static function serve(mixed $status, mixed $body, mixed $headers = [], ?array &$seen = null): \Closure
    {
        return static function (string $url, array $h, mixed $t) use ($status, $body, $headers, &$seen): array {
            $seen[] = [$url, $h, $t];
            return ['status' => $status, 'body' => $body, 'headers' => $headers];
        };
    }

    private static function discoverErr(mixed $issuer, mixed $opts): string
    {
        try {
            Oidc::discoverOidc($issuer, $opts);
        } catch (OidcDiscoveryError $e) {
            return $e->getMessage();
        }
        return 'no error';
    }

    /** A string-callable fetch (a public static method name): the default fetch is used instead. */
    public static function stringFetch(string $url, array $h, mixed $t): array
    {
        return ['status' => 200, 'body' => '{"issuer":"' . self::NOFILE . '","jwks_uri":"https://idp.invalid/jwks"}', 'headers' => []];
    }

    private static function thrown(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [$e::class, $e->getMessage()];
        }
        return ['none'];
    }

    // ---- error classes ----

    /** The error classes carry their message and fields. */
    public function testErrorClassesKeepTheirMessage(): void
    {
        $v = new OidcVerificationError('keys', 'm1');
        self::assertSame(['keys', 'm1'], [$v->codeName, $v->getMessage()]);
        $c = new OidcCodedError('ERR_X', 'm2');
        self::assertSame(['ERR_X', 'm2'], [$c->codeName, $c->getMessage()]);
        $f = new OidcClaimFailed('iat', 'm3', true);
        self::assertSame(['iat', 'm3', true], [$f->claim, $f->getMessage(), $f->expired]);
    }

    // ---- verifyIdToken: claims ----

    /** A good token verifies with Obj options, with and without a clock tolerance. */
    public function testAGoodTokenVerifies(): void
    {
        $c = Oidc::verifyIdToken(self::tok(self::claims()), Obj::of(self::opts()));
        self::assertSame([self::ISS, 'u1', 'client-1'], [$c['iss'], $c['sub'], $c['aud']]);
        self::assertSame((float)(self::NOW - 100), Js::num($c['iat']));
        self::assertSame((float)(self::NOW + 100), Js::num($c['exp']));
        self::assertSame(['ok'], self::verdict(self::tok(self::claims()), self::opts(['clockToleranceSec' => 5])));
    }

    /** exp must be strictly after now; nbf may equal now; the tolerance moves both edges by exactly its value. */
    public function testExpAndNbfBoundaries(): void
    {
        $expired = ['expired', 'id token has expired'];
        self::assertSame($expired, self::verdict(self::tok(self::claims(['exp' => self::NOW])), self::opts()));
        self::assertSame(['ok'], self::verdict(self::tok(self::claims(['exp' => self::NOW])), self::opts(['clockToleranceSec' => 1])));
        self::assertSame(['ok'], self::verdict(self::tok(self::claims(['exp' => self::NOW + 1])), self::opts()));
        self::assertSame(['ok'], self::verdict(self::tok(self::claims(['nbf' => self::NOW])), self::opts()));
        $nbf = ['not_before', '"nbf" claim timestamp check failed'];
        self::assertSame($nbf, self::verdict(self::tok(self::claims(['nbf' => self::NOW + 1])), self::opts()));
        self::assertSame(['ok'], self::verdict(self::tok(self::claims(['nbf' => self::NOW + 1])), self::opts(['clockToleranceSec' => 1])));
    }

    /** A fractional now is floored (never rounded up); a non-finite now fails nbf and exp. */
    public function testNowIsFlooredAndMustBeFinite(): void
    {
        self::assertSame(['ok'], self::verdict(self::tok(self::claims(['exp' => self::NOW + 1])), self::opts(['now' => self::NOW + 0.5])));
        self::assertSame(['not_before', '"nbf" claim timestamp check failed'],
            self::verdict(self::tok(self::claims(['nbf' => self::NOW])), self::opts(['now' => INF])));
        self::assertSame(['expired', 'id token has expired'], self::verdict(self::tok(self::claims()), self::opts(['now' => -INF])));
        self::assertSame(['issued_at', 'id token is older than the maximum accepted age'],
            self::verdict(self::tok(self::claims([], ['exp'])), self::opts(['now' => -INF, 'maxTokenAgeSec' => 100])));
    }

    /** Required claims: iss / aud always, iat only with a max age; each missing one is named. */
    public function testRequiredClaims(): void
    {
        $age = ['maxTokenAgeSec' => 1000];
        self::assertSame(['issuer', 'missing required "iss" claim'], self::verdict(self::tok(self::claims([], ['iss'])), self::opts()));
        self::assertSame(['issuer', 'missing required "iss" claim'], self::verdict(self::tok(self::claims([], ['iss'])), self::opts($age)));
        self::assertSame(['audience', 'missing required "aud" claim'], self::verdict(self::tok(self::claims([], ['aud'])), self::opts()));
        self::assertSame(['issued_at', 'missing required "iat" claim'], self::verdict(self::tok(self::claims([], ['iat'])), self::opts($age)));
        self::assertSame(['issued_at', 'id token is missing a numeric "iat" claim'],
            self::verdict(self::tok(self::claims([], ['iat'])), self::opts()));
        self::assertSame(['issued_at', '"iat" claim must be a number'], self::verdict(self::tok(self::claims(['iat' => 'x'])), self::opts()));
    }

    /** The max-age window: exactly the limit passes, one second more fails, a future iat fails unless tolerated. */
    public function testMaxAgeWindow(): void
    {
        $age = ['maxTokenAgeSec' => 100];
        self::assertSame(['ok'], self::verdict(self::tok(self::claims(['iat' => self::NOW - 100])), self::opts($age)));
        self::assertSame(['issued_at', 'id token is older than the maximum accepted age'],
            self::verdict(self::tok(self::claims(['iat' => self::NOW - 101])), self::opts($age)));
        self::assertSame(['issued_at', '"iat" claim timestamp check failed (it should be in the past)'],
            self::verdict(self::tok(self::claims(['iat' => self::NOW + 1])), self::opts($age)));
        self::assertSame(['ok'], self::verdict(self::tok(self::claims(['iat' => self::NOW + 1])), self::opts($age + ['clockToleranceSec' => 1])));
    }

    /** A string max age passes the config gate only when trim() leaves "" or a number >= 0 (then the span parser refuses it). */
    public function testStringMaxAgeGate(): void
    {
        $tok = self::tok(self::claims());
        $late = ['invalid_token', 'id token verification failed'];
        foreach (['5', '0', ' ', "5\0"] as $ma) {
            self::assertSame($late, self::verdict($tok, self::opts(['maxTokenAgeSec' => $ma])), json_encode($ma));
        }
        self::assertSame(['config', 'verifyIdToken: maxTokenAgeSec must be a number >= 0'], self::verdict($tok, self::opts(['maxTokenAgeSec' => "\0-5"])));
    }

    /** The nonce: missing and mismatched are told apart; a match is returned. */
    public function testNonce(): void
    {
        self::assertSame(['nonce', 'id token is missing the expected nonce'], self::verdict(self::tok(self::claims()), self::opts(['nonce' => 'n1'])));
        self::assertSame(['nonce', 'id token nonce does not match the expected value'],
            self::verdict(self::tok(self::claims(['nonce' => 'n2'])), self::opts(['nonce' => 'n1'])));
        self::assertSame('n1', Oidc::verifyIdToken(self::tok(self::claims(['nonce' => 'n1'])), self::opts(['nonce' => 'n1']))['nonce']);
    }

    // ---- verifyIdToken: config and key source ----

    /** Bad id tokens and bad option shapes are refused with their exact config reason. */
    public function testConfigRefusals(): void
    {
        $tok = self::tok(self::claims());
        self::assertSame(['invalid_token', 'verifyIdToken: idToken must be a non-empty string'], self::verdict('', self::opts()));
        self::assertSame(['invalid_token', 'verifyIdToken: idToken must be a non-empty string'], self::verdict(5, self::opts()));
        self::assertSame(['config', 'verifyIdToken: opts is required'], self::verdict($tok, null));
        self::assertSame(['config', 'verifyIdToken: opts is required'], self::verdict($tok, [1]));
        self::assertSame(['config', 'verifyIdToken: opts.issuer is required'], self::verdict($tok, []));
        self::assertSame(['config', 'verifyIdToken: no key source (pass opts.key, opts.jwksUri, or opts.discover)'],
            self::verdict($tok, self::opts([], ['key'])));
        self::assertSame(['config', 'verifyIdToken: createOidcJwks: jwksUri is required'],
            self::verdict($tok, self::opts(['jwksUri' => null], ['key'])));
        self::assertSame(['config', 'verifyIdToken: createOidcJwks: jwksUri must be https (pass requireHttps: false only for local tests)'],
            self::verdict($tok, self::opts(['jwksUri' => 'http://jwks.example/keys'], ['key'])));
    }

    /** Discovery honours requireHttps: false, and the discovered jwks_uri is fetched (and fails closed when unreachable). */
    public function testDiscoverPassesRequireHttps(): void
    {
        $iss = 'http://idp.test';
        $jwks = self::NOFILE . '/jwks';
        $fetch = self::serve(200, self::json(['issuer' => $iss, 'jwks_uri' => $jwks]));
        $o = ['issuer' => $iss, 'audience' => 'client-1', 'discover' => true, 'requireHttps' => false, 'fetch' => $fetch,
            'algorithms' => ['EdDSA'], 'now' => self::NOW];
        self::assertSame(['keys', "could not fetch the issuer signing keys from $jwks"], self::verdict(self::edTok(self::claims(['iss' => $iss])), $o));
    }

    // ---- verifyIdToken: header ----

    /** crit, alg and the allow-list refuse with the JOSE reasons. */
    public function testHeaderRefusals(): void
    {
        $c = self::claims();
        $critMsg = '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present';
        self::assertSame(['invalid_token', $critMsg], self::verdict(self::tok($c, ['alg' => 'HS256', 'crit' => 'x']), self::opts()));
        self::assertSame(['invalid_token', $critMsg], self::verdict(self::tok($c, ['alg' => 'HS256', 'crit' => [5]]), self::opts()));
        self::assertSame(['invalid_token', 'Extension Header Parameter "x" is not recognized'],
            self::verdict(self::tok($c, ['alg' => 'HS256', 'crit' => ['x']]), self::opts()));
        self::assertSame(['invalid_token', 'Extension Header Parameter "b64" is missing'],
            self::verdict(self::tok($c, ['alg' => 'HS256', 'crit' => ['b64']]), self::opts()));
        $algMsg = ['invalid_token', 'JWS "alg" (Algorithm) Header Parameter missing or invalid'];
        self::assertSame($algMsg, self::verdict(self::tok($c, ['alg' => 5]), self::opts()));
        self::assertSame($algMsg, self::verdict(self::tok($c, ['alg' => '']), self::opts()));
        self::assertSame(['invalid_token', 'id token verification failed'], self::verdict(self::tok($c), self::opts(['algorithms' => [5]])));
        self::assertSame(['invalid_token', '"alg" (Algorithm) Header Parameter value not allowed'],
            self::verdict(self::tok($c, ['alg' => 'HS384']), self::opts()));
    }

    // ---- verifyIdToken: symmetric keys ----

    /** HMAC keys: a string secret (even a callable name), an oct JWK; bad oct JWKs and unknown HS algs are refused. */
    public function testSymmetricKeys(): void
    {
        $c = self::claims();
        self::assertSame(['ok'], self::verdict(self::tok($c, ['alg' => 'HS256'], 'strlen'), self::opts(['key' => 'strlen'])));
        $oct = ['kty' => 'oct', 'k' => self::b64(self::SECRET)];
        self::assertSame(['ok'], self::verdict(self::tok($c), self::opts(['key' => $oct])));
        self::assertSame(['invalid_token', 'Invalid key for this operation, when present its use must be sig'],
            self::verdict(self::tok($c), self::opts(['key' => $oct + ['use' => 'enc']])));
        self::assertSame(['invalid_token', 'Invalid key for this operation, when present its key_ops must include verify'],
            self::verdict(self::tok($c), self::opts(['key' => $oct + ['key_ops' => 'verify']])));
        self::assertSame(['signature', 'id token signature verification failed'],
            self::verdict(self::tok($c), self::opts(['key' => ['kty' => 'oct', 'k' => 'a']])));
        self::assertSame(['invalid_token', 'Invalid key for a symmetric algorithm'],
            self::verdict(self::tok($c), self::opts(['key' => ['kty' => 'RSA', 'k' => 'abc']])));
        self::assertSame(['invalid_token', 'alg HS1 is not supported'],
            self::verdict(self::tok($c, ['alg' => 'HS1']), self::opts(['algorithms' => ['HS1']])));
    }

    // ---- verifyIdToken: asymmetric keys ----

    /** Asymmetric keys: the key must be a public JWK of the algorithm's family, with a known OKP curve. */
    public function testAsymmetricKeyChecks(): void
    {
        $c = self::claims();
        $ed = self::edTok($c);
        $o = static fn(mixed $key, string $alg = 'EdDSA'): array => self::opts(['key' => $key, 'algorithms' => [$alg]]);
        self::assertSame(['ok'], self::verdict($ed, $o(self::edJwk())));
        $pub = ['invalid_token', 'Invalid key for this operation: a public JWK is required'];
        self::assertSame($pub, self::verdict($ed, $o(Obj::of([]))));
        self::assertSame($pub, self::verdict($ed, $o('abc')));
        self::assertSame(['invalid_token', 'Invalid key for this operation, its crv must be Ed25519 or Ed448'],
            self::verdict($ed, $o(['kty' => 'OKP', 'crv' => 'X25519', 'x' => self::edJwk()['x']])));
        self::assertSame(['invalid_token', 'Invalid key for this operation, its kty must be RSA, OKP, or EC'],
            self::verdict($ed, $o(['kty' => 'foo', 'x' => 'AA'])));
        $sig64 = str_repeat("\x01", 64);
        self::assertSame(['invalid_token', 'Invalid key for this operation, its asymmetricKeyType must be ec'],
            self::verdict(self::tok($c, ['alg' => 'ES256'], null, $sig64), $o(self::edJwk(), 'ES256')));
        $sig256 = str_repeat("\x01", 256);
        self::assertSame(['invalid_token', 'Invalid key for this operation, its asymmetricKeyType must be rsa'],
            self::verdict(self::tok($c, ['alg' => 'RS256'], null, $sig256), $o(self::edJwk(), 'RS256')));
        $short = ['kty' => 'RSA', 'n' => self::b64(str_repeat("\xC5", 228)), 'e' => 'AQAB'];
        self::assertSame(['invalid_token', 'RS256 requires key modulusLength to be 2048 bits or larger'],
            self::verdict(self::tok($c, ['alg' => 'RS256'], null, $sig256), $o($short, 'RS256')));
    }

    /** A 2040-bit RSA modulus padded to 256 bytes passes the length gate but never verifies (directly or through a key set). */
    public function testPaddedShortRsaKeyNeverVerifies(): void
    {
        [$n, $e] = self::rsa();
        self::assertSame(255, strlen($n));
        $jwk = ['kty' => 'RSA', 'n' => self::b64("\0" . $n), 'e' => self::b64($e)];
        $tok = self::tok(self::claims(), ['alg' => 'RS256'], null, str_repeat("\x01", 256));
        $sig = ['signature', 'id token signature verification failed'];
        self::assertSame($sig, self::verdict($tok, self::opts(['key' => $jwk, 'algorithms' => ['RS256']])));
        self::assertSame($sig, self::verdict($tok, self::opts(['key' => Oidc::createLocalJwkSet(['keys' => [$jwk]]), 'algorithms' => ['RS256']])));
    }

    /** A loadable P-256 JWK reaches the signature check (a bad signature is a signature failure). */
    public function testEcKeyReachesTheSignatureCheck(): void
    {
        [$x, $y] = self::ec();
        $jwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => self::b64($x), 'y' => self::b64($y)];
        $tok = self::tok(self::claims(), ['alg' => 'ES256'], null, str_repeat("\x01", 64));
        self::assertSame(['signature', 'id token signature verification failed'],
            self::verdict($tok, self::opts(['key' => $jwk, 'algorithms' => ['ES256']])));
    }

    /** A resolver's key is checked for import; resolver failures map to invalid_token (JOSE / canonical reasons kept). */
    public function testResolverKeysAndFailures(): void
    {
        $ed = self::edTok(self::claims());
        $o = static fn(\Closure $r): array => self::opts(['key' => $r, 'algorithms' => ['EdDSA']]);
        $bad = ['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::b64(str_repeat("\x07", 31))];
        self::assertSame(['invalid_token', 'invalid JWK'], self::verdict($ed, $o(static fn(mixed $h): array => $bad)));
        self::assertSame(['ok'], self::verdict($ed, $o(static fn(mixed $h): array => self::edJwk())));
        self::assertSame(['invalid_token', 'non-canonical compact JWS: x'],
            self::verdict($ed, $o(static function (mixed $h): never {
                throw new CanonicalJwsError('x');
            })));
        self::assertSame(['invalid_token', 'id token verification failed'],
            self::verdict($ed, $o(static function (mixed $h): never {
                throw new \RuntimeException('boom');
            })));
    }

    // ---- at_hash ----

    /** at_hash is over Node's 'ascii' bytes (low byte of each UTF-16 unit, U+FFFD for a stray byte); missing is named. */
    public function testAtHashAsciiBytes(): void
    {
        $at = "a\x80\xC4\x80\xE0\xA3\x81\xE8\x80\x80\xEF\xBF\xBF\xF0\x80\x80\x80\xF1\x80\x80\x80\xF0\x90\x81\x81\xF0\x90\x8F\xBF\xF0\x90\x90\x80";
        $bytes = "a\xFD\x00\xC1\x00\xFF\x00\xC0\x00\x00\x41\x00\xFF\x01\x00";
        $h = self::b64(substr(hash('sha256', $bytes, true), 0, 16));
        $c = Oidc::verifyIdToken(self::tok(self::claims(['at_hash' => $h])), self::opts(['accessToken' => $at]));
        self::assertSame($h, $c['at_hash']);
        self::assertSame(['at_hash', 'id token is missing the expected at_hash'], self::verdict(self::tok(self::claims()), self::opts(['accessToken' => 'x'])));
    }

    // ---- local JWK sets ----

    /** createLocalJwkSet: an unknown alg family, an unimportable member and a short EC coordinate are refused; Ed448 resolves. */
    public function testLocalJwkSet(): void
    {
        $res = static fn(array $k, string $alg): array => self::thrown(static fn() => Oidc::createLocalJwkSet(['keys' => [$k]])(Obj::of(['alg' => $alg])));
        $invalid = [JoseError::class, 'invalid JWK in the JSON Web Key Set'];
        self::assertSame([JoseError::class, 'Unsupported "alg" value for a JSON Web Key Set'], $res(self::edJwk(), 'XX'));
        self::assertSame($invalid, $res(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => self::b64(str_repeat("\x07", 31))], 'EdDSA'));
        [$x, $y] = self::ec();
        self::assertSame($invalid, $res(['kty' => 'EC', 'crv' => 'P-256', 'x' => self::b64("\0" . $x), 'y' => self::b64($y)], 'ES256'));
        self::assertSame($invalid, $res(['kty' => 'EC', 'crv' => 'P-256', 'x' => self::b64($x), 'y' => self::b64("\0" . $y)], 'ES256'));
        [$n, $e] = self::rsa();
        self::assertSame($invalid, $res(['kty' => 'RSA', 'n' => '', 'e' => self::b64($e)], 'RS256'));
        self::assertSame($invalid, $res(['kty' => 'RSA', 'n' => self::b64($n), 'e' => self::b64($e), 'oth' => []], 'RS256'));
        $ed448 = ['kty' => 'OKP', 'crv' => 'Ed448', 'x' => self::b64(str_repeat("\x09", 57))];
        self::assertSame($ed448, Oidc::createLocalJwkSet(['keys' => [$ed448]])(Obj::of(['alg' => 'EdDSA'])));
        $ecJwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => self::b64($x), 'y' => self::b64($y)];
        self::assertSame($ecJwk, Oidc::createLocalJwkSet(['keys' => [$ecJwk]])(Obj::of(['alg' => 'ES256'])));
    }

    // ---- discovery ----

    /** Discovery fetches the well-known URL with an accept header and returns the metadata. */
    public function testDiscoverySuccess(): void
    {
        $seen = [];
        $m = Oidc::discoverOidc(self::ISS, ['fetch' => self::serve(200, self::META, [], $seen), 'maxBytes' => strlen(self::META)]);
        self::assertSame([self::ISS, 'https://idp.example/jwks'], [$m->get('issuer'), $m->get('jwks_uri')]);
        self::assertSame([[self::WK, ['accept' => 'application/json'], null]], $seen);
    }

    /** Size caps: booleans coerce to 1 / 0, a declared length counts, the first content-length header wins, any case. */
    public function testDiscoverySizeCaps(): void
    {
        $badJson = 'discoverOidc: ' . self::WK . ' did not return valid JSON';
        $big = static fn(string $n): string => 'discoverOidc: ' . self::WK . " response exceeds $n bytes";
        $d = static fn(mixed $max, mixed $body, mixed $hs): string => self::discoverErr(self::ISS, ['fetch' => self::serve(200, $body, $hs), 'maxBytes' => $max]);
        self::assertSame($badJson, $d(true, '', ['content-length' => '1']));
        self::assertSame($big('false'), $d(false, '', ['content-length' => '1']));
        self::assertSame($badJson, $d(0, '', []));
        self::assertSame($big('0'), $d(0, '', ['content-length' => '5']));
        $dd = static fn(mixed $hs): string => self::discoverErr(self::ISS, ['fetch' => self::serve(200, self::META, $hs)]);
        self::assertSame($big('1048576'), $dd(Obj::of(['Content-Length' => '99999999'])));
        self::assertSame($big('1048576'), $dd(['Content-Length' => '99999999']));
        self::assertSame('no error', $dd(['x']));
        self::assertSame('no error', $dd(['content-length' => '10', 'Content-Length' => '99999999']));
    }

    /** Discovery refusals keep their exact reasons. */
    public function testDiscoveryRefusals(): void
    {
        $f = static fn(mixed $status, mixed $body): array => ['fetch' => self::serve($status, $body)];
        self::assertSame('discoverOidc: ' . self::WK . ' returned HTTP 404', self::discoverErr(self::ISS, $f(404, self::META)));
        self::assertSame('discoverOidc: metadata is not a JSON object', self::discoverErr(self::ISS, $f(200, 5)));
        self::assertSame('discoverOidc: metadata is missing a string "issuer"', self::discoverErr(self::ISS, $f(200, '{"jwks_uri":"https://idp.example/jwks"}')));
        self::assertSame("discoverOidc: metadata issuer 'https://other.example' does not match requested 'https://idp.example'",
            self::discoverErr(self::ISS, $f(200, '{"issuer":"https://other.example","jwks_uri":"https://idp.example/jwks"}')));
        self::assertSame("discoverOidc: jwks_uri 'http://idp.example/jwks' is not an https URL",
            self::discoverErr(self::ISS, $f(200, '{"issuer":"https://idp.example","jwks_uri":"http://idp.example/jwks"}')));
        self::assertSame('discoverOidc: issuer must be a non-empty string', self::discoverErr(5, []));
        self::assertSame('discoverOidc: issuer must be a non-empty string', self::discoverErr('', []));
        self::assertSame([\TypeError::class, "Cannot read properties of null (reading 'requireHttps')"],
            self::thrown(static fn() => Oidc::discoverOidc(self::ISS, null)));
        self::assertSame([\TypeError::class, "Cannot read properties of null (reading 'endsWith')"],
            self::thrown(static fn() => Oidc::discoveryUrl(null)));
    }

    /** An invalid UTF-8 body decodes with U+FFFD (as a text decoder does), not refused. */
    public function testDiscoveryBodyIsDecodedLeniently(): void
    {
        $body = '{"issuer":"https://idp.example","jwks_uri":"https://idp.example/jwks","x":"' . "\xFF" . '"}';
        self::assertSame("\u{FFFD}", Oidc::discoverOidc(self::ISS, ['fetch' => self::serve(200, $body)])->get('x'));
    }

    /** A string callable is not a fetch: the default fetch runs (and fails closed on an unreachable URL). */
    public function testStringFetchIsIgnored(): void
    {
        $fn = self::class . '::stringFetch';
        self::assertTrue(is_callable($fn));
        self::assertSame('discoverOidc: fetch of ' . self::NOFILE . '/.well-known/openid-configuration failed',
            self::discoverErr(self::NOFILE, ['requireHttps' => false, 'fetch' => $fn]));
    }

    /** The default fetch is public and throws (without a warning) when the URL cannot be read. */
    public function testDefaultFetchFailsClosed(): void
    {
        $w = [];
        set_error_handler(static function (int $no, string $s) use (&$w): bool {
            if ((error_reporting() & $no) !== 0) {
                $w[] = $s;
            }
            return true;
        });
        try {
            $r = self::thrown(static fn() => Oidc::defaultFetch(self::NOFILE, ['accept' => 'x'], 1000));
        } finally {
            restore_error_handler();
        }
        self::assertSame([\RuntimeException::class, 'fetch of ' . self::NOFILE . ' failed'], $r);
        self::assertSame([], $w);
    }

    // ---- createOidcJwks ----

    private static function jwksBody(): string
    {
        return self::json(['keys' => [self::edJwk()]]);
    }

    /** createOidcJwks option refusals and a clock that is not a number. */
    public function testOidcJwksRefusals(): void
    {
        self::assertSame([\TypeError::class, 'createOidcJwks: jwksUri is required'], self::thrown(static fn() => Oidc::createOidcJwks(['jwksUri' => 5])));
        self::assertSame([\TypeError::class, 'createOidcJwks: jwksUri is required'], self::thrown(static fn() => Oidc::createOidcJwks(['jwksUri' => ''])));
        self::assertSame([\TypeError::class, 'createOidcJwks: cacheMaxAgeSec must be a finite number >= 0'],
            self::thrown(static fn() => Oidc::createOidcJwks(['jwksUri' => 'https://jwks.example', 'cacheMaxAgeSec' => 'abc'])));
        $r = Oidc::createOidcJwks(['jwksUri' => 'https://jwks.example', 'fetch' => self::serve(200, self::jwksBody()), 'now' => static fn(): string => 'x']);
        self::assertSame([OidcVerificationError::class, 'the clock returned a non-finite time'], self::thrown(static fn() => $r(Obj::of(['alg' => 'EdDSA']))));
    }

    /** The fetch gets the accept header and an int timeout; a non-2xx reply fails closed; a fresh cache is reused. */
    public function testOidcJwksFetchAndCache(): void
    {
        $seen = [];
        $r = Oidc::createOidcJwks(['jwksUri' => 'https://jwks.example', 'fetch' => self::serve(200, self::jwksBody(), [], $seen),
            'timeoutMs' => 2000, 'now' => static fn(): int => 1_000_000]);
        $h = Obj::of(['alg' => 'EdDSA']);
        self::assertSame(self::edJwk()['x'], Js::opt($r($h), 'x'));
        self::assertSame(self::edJwk()['x'], Js::opt($r($h), 'x'));
        self::assertSame([['https://jwks.example', ['accept' => 'application/json'], 2000]], $seen);
        $r5 = Oidc::createOidcJwks(['jwksUri' => 'https://jwks.example', 'fetch' => self::serve(500, self::jwksBody())]);
        self::assertSame([OidcVerificationError::class, 'could not fetch the issuer signing keys from https://jwks.example'], self::thrown(static fn() => $r5($h)));
    }

    /** The default body cap is exactly 1 MiB. */
    public function testOidcJwksDefaultCap(): void
    {
        $h = Obj::of(['alg' => 'EdDSA']);
        $at = Oidc::createOidcJwks(['jwksUri' => 'https://jwks.example', 'fetch' => self::serve(200, str_pad(self::jwksBody(), 1048576, ' '))]);
        self::assertSame(self::edJwk()['x'], Js::opt($at($h), 'x'));
        $over = Oidc::createOidcJwks(['jwksUri' => 'https://jwks.example', 'fetch' => self::serve(200, str_pad(self::jwksBody(), 1048577, ' '))]);
        self::assertSame([OidcVerificationError::class, 'could not fetch the issuer signing keys from https://jwks.example'], self::thrown(static fn() => $over($h)));
    }

    /** createOidcJwksFromIssuer copies Obj and array options (any key type) and uses the discovered jwks_uri. */
    public function testJwksFromIssuerCopiesOptions(): void
    {
        $iss = 'https://idp.invalid';
        $meta = self::json(['issuer' => $iss, 'jwks_uri' => 'https://idp.invalid/jwks']);
        $body = self::jwksBody();
        $fetch = static fn(string $url, array $h, mixed $t): array => ['status' => 200, 'body' => str_ends_with($url, '/jwks') ? $body : $meta, 'headers' => []];
        $h = Obj::of(['alg' => 'EdDSA']);
        self::assertSame(self::edJwk()['x'], Js::opt(Oidc::createOidcJwksFromIssuer($iss, Obj::of(['fetch' => $fetch]))($h), 'x'));
        self::assertSame(self::edJwk()['x'], Js::opt(Oidc::createOidcJwksFromIssuer($iss, ['fetch' => $fetch, 0 => 'x'])($h), 'x'));
    }

    // ---- principal ----

    /** oidcPrincipal(null) reads iss of null. */
    public function testPrincipalOfNull(): void
    {
        self::assertSame([\TypeError::class, "Cannot read properties of null (reading 'iss')"], self::thrown(static fn() => Oidc::oidcPrincipal(null)));
    }
}
