<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Jose.php';

use Atlas\Pca\Attest\CanonicalJwsError;
use Atlas\Pca\Attest\PubKey;
use Atlas\Pca\Jose;
use Atlas\Pca\JoseError;
use Atlas\Pca\Js;
use Atlas\Pca\NodeTypeError;
use Atlas\Pca\Obj;
use Atlas\Pca\OpensslEd448;
use PHPUnit\Framework\TestCase;

/** The JOSE layer's refusals hold with their exact reference reasons: canonical gate, key import, sign / verify, claims and time spans. */
final class CryptoSurvivorKill3JoseTest extends TestCase
{
    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/jose-kill-3', true);
    }

    private static function pub(): string
    {
        return sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::seed()));
    }

    private static function edJwk(): Obj
    {
        return Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => Jose::b64u(self::pub())]);
    }

    private static function ec(string $curve): \OpenSSLAsymmetricKey
    {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $k);
        return $k;
    }

    /** @return array{x:string,y:string,d:string} */
    private static function ecParts(\OpenSSLAsymmetricKey $k): array
    {
        $d = openssl_pkey_get_details($k);
        return ['x' => $d['ec']['x'], 'y' => $d['ec']['y'], 'd' => $d['ec']['d']];
    }

    private static function ecJwk(\OpenSSLAsymmetricKey $k, string $crv): Obj
    {
        $p = self::ecParts($k);
        return Obj::of(['kty' => 'EC', 'crv' => $crv, 'x' => Jose::b64u($p['x']), 'y' => Jose::b64u($p['y'])]);
    }

    private static function rsa1024(): \OpenSSLAsymmetricKey
    {
        $k = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $k);
        return $k;
    }

    private function joseRefuses(string $msg, callable $fn): JoseError
    {
        try {
            $fn();
        } catch (JoseError $e) {
            $this->assertSame($msg, $e->getMessage());
            return $e;
        }
        $this->fail("no JoseError: $msg");
    }

    private function gateRefuses(string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (CanonicalJwsError $e) {
            $this->assertSame($msg, $e->getMessage());
            return;
        }
        $this->fail("no CanonicalJwsError: $msg");
    }

    private function typeRefuses(string $msg, callable $fn): void
    {
        try {
            $fn();
        } catch (\TypeError $e) {
            $this->assertSame($msg, $e->getMessage());
            return;
        }
        $this->fail("no TypeError: $msg");
    }

    /** A compact JWS over `$header` / `$payload` signed with the test Ed25519 seed. */
    private static function token(array $header, string $payload = '{"sub":"a"}'): string
    {
        $input = Jose::b64u(Js::stringify(Obj::of($header))) . '.' . Jose::b64u($payload);
        return $input . '.' . Jose::b64u(Jose::jwsSign('EdDSA', self::seed(), $input));
    }

    // ---- errors

    /** NodeTypeError keeps its message and the reference error code. */
    public function testNodeTypeErrorCarriesMessageAndCode(): void
    {
        $e = new NodeTypeError('Invalid URL', 'ERR_INVALID_URL');
        $this->assertSame('Invalid URL', $e->getMessage());
        $this->assertSame('ERR_INVALID_URL', $e->codeName);
    }

    /** An undecodable, non-string or wrong-length private OKP `d` is the runtime's invalid-JWK refusal, code 0. */
    public function testInvalidPrivateOkpJwkRefusalsHaveCodeZero(): void
    {
        foreach (['!!!!', 5, Jose::b64u('short')] as $d) {
            $e = $this->joseRefuses('Invalid JWK OKP key', fn() => Jose::jwsSign('EdDSA', Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'd' => $d]), 'x'));
            $this->assertSame(0, $e->getCode());
            $this->assertSame('ERR_CRYPTO_INVALID_JWK', $e->codeName);
        }
    }

    // ---- canonical gate

    /** parseJsonBytes is public: a BOM is refused, a strict object parses. */
    public function testParseJsonBytes(): void
    {
        $this->assertInstanceOf(Obj::class, Jose::parseJsonBytes('{"a":1}'));
        $this->gateRefuses('non-canonical compact JWS: bom', fn() => Jose::parseJsonBytes("\xEF\xBB\xBF{}"));
    }

    /** A non-string token is refused as such; the byte limit holds at exactly maxBytes. */
    public function testCompactGateTypeAndLimit(): void
    {
        $this->gateRefuses('non-canonical compact JWS: not-a-string', fn() => Jose::assertCanonicalCompactJws(5));
        $t = Jose::b64u('{"a":1}') . '.' . Jose::b64u('{"b":2}') . '.AAAA';
        $r = Jose::assertCanonicalCompactJws($t, 3, strlen($t));
        $this->assertSame(explode('.', $t), $r['segments']);
        $this->assertSame(['b'], $r['payload']->keys());
        $this->gateRefuses('non-canonical compact JWS: too-long', fn() => Jose::assertCanonicalCompactJws($t, 3, strlen($t) - 1));
    }

    /** Only a JWE's encrypted-key segment (index 1 of 5) may be empty; every other segment is still decoded and checked. */
    public function testEmptySegmentRules(): void
    {
        $h = Jose::b64u('{"alg":"dir"}');
        $r = Jose::assertCanonicalCompactJws("$h..AAAA.AAAA.AAAA", 5);
        $this->assertCount(5, $r['segments']);
        $this->assertSame('', $r['segments'][1]);
        $this->assertArrayNotHasKey('payload', $r);
        $this->gateRefuses('non-canonical compact JWS: empty-segment (segment 2)', fn() => Jose::assertCanonicalCompactJws("$h.AAAA..AAAA.AAAA", 5));
        $this->gateRefuses('non-canonical compact JWS: bad-character', fn() => Jose::assertCanonicalCompactJws("$h..AAAA.!!.AAAA", 5));
        $this->gateRefuses('non-canonical compact JWS: empty-segment (segment 1)', fn() => Jose::assertCanonicalCompactJws("$h..AAAA", 3));
    }

    /** A detached (non-JSON) payload is not parsed when the caller says so. */
    public function testRawPayloadIsNotParsed(): void
    {
        $t = Jose::b64u('{"alg":"EdDSA"}') . '.' . Jose::b64u('raw!') . '.AAAA';
        $r = Jose::assertCanonicalCompactJws($t, 3, Jose::DEFAULT_MAX_JWS_BYTES, 'raw');
        $this->assertArrayNotHasKey('payload', $r);
        $this->assertSame(['alg'], $r['header']->keys());
    }

    /** isCanonicalCompactJws defaults to a 3-part JWS and is false for a refused token. */
    public function testIsCanonicalCompactJws(): void
    {
        $t = Jose::b64u('{"a":1}') . '.' . Jose::b64u('{"b":2}') . '.AAAA';
        $this->assertTrue(Jose::isCanonicalCompactJws($t));
        $this->assertFalse(Jose::isCanonicalCompactJws('a.b'));
    }

    /** Flattened segments: either part a non-string is refused as such; the byte limit is the sum, held at exactly maxBytes. */
    public function testFlattenedSegments(): void
    {
        $p = Jose::b64u('{"a":1}');
        $this->gateRefuses('non-canonical compact JWS: not-a-string', fn() => Jose::assertCanonicalJwsSegments($p, 5));
        $this->gateRefuses('non-canonical compact JWS: not-a-string', fn() => Jose::assertCanonicalJwsSegments(5, 'AAAA'));
        $max = strlen($p) + 4;
        $this->assertSame(['a'], Jose::assertCanonicalJwsSegments($p, 'AAAA', $max)->keys());
        $this->gateRefuses('non-canonical compact JWS: too-long', fn() => Jose::assertCanonicalJwsSegments($p, 'AAAA', $max - 1));
    }

    // ---- key import

    /** publicKeyFromJwk refusals, each with its own reason. */
    public function testPublicJwkRefusals(): void
    {
        $x = Jose::b64u(self::pub());
        $this->joseRefuses('JSON Web Key for this operation must be a public JWK',
            fn() => Jose::publicKeyFromJwk(Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x, 'd' => $x])));
        $this->joseRefuses('JWK member must be a string', fn() => Jose::publicKeyFromJwk(Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'x' => 5, 'y' => 'AA'])));
        $this->joseRefuses('unsupported EC curve', fn() => Jose::publicKeyFromJwk(Obj::of(['kty' => 'EC', 'crv' => 'P-999', 'x' => 'AA', 'y' => 'AA'])));
        $off = Jose::b64u(str_repeat("\x01", 32)); // (0x0101.., 0x0101..) is not on P-256
        $this->joseRefuses('invalid EC public key', fn() => Jose::publicKeyFromJwk(Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'x' => $off, 'y' => $off])));
        $this->joseRefuses('Unsupported "kty" (Key Type) Parameter value', fn() => Jose::publicKeyFromJwk(Obj::of(['kty' => 'foo'])));
        $this->assertSame(['ed', self::pub()], Jose::publicKeyFromJwk(self::edJwk()));
    }

    /** A JWK's use / key_ops / alg must fit the verification. */
    public function testJwkUseOpsAndAlgMustMatch(): void
    {
        $x = Jose::b64u(self::pub());
        $jwk = static fn(array $extra): Obj => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x] + $extra);
        $this->joseRefuses('Invalid key for this operation, when present its use must be sig', fn() => Jose::verifyKey('EdDSA', $jwk(['use' => 'enc'])));
        $this->joseRefuses('Invalid key for this operation, when present its key_ops must include verify', fn() => Jose::verifyKey('EdDSA', $jwk(['key_ops' => ['sign']])));
        $this->joseRefuses('Invalid key for this operation, when present its alg must be EdDSA', fn() => Jose::verifyKey('EdDSA', $jwk(['alg' => 'ES256'])));
        $this->assertSame(['ed', self::pub()], Jose::verifyKey('EdDSA', $jwk(['use' => 'sig', 'key_ops' => ['verify'], 'alg' => 'EdDSA'])));
    }

    /** verifyKey: unknown alg, symmetric key and a key of the wrong family are refused with the family the alg needs. */
    public function testVerifyKeyFamilyRefusals(): void
    {
        $this->joseRefuses('Unsupported "alg" value for a JSON Web Signature Algorithm', fn() => Jose::verifyKey('HS256', self::pub()));
        $this->joseRefuses('Invalid key for this operation: a symmetric key', fn() => Jose::verifyKey('EdDSA', Obj::of(['kty' => 'oct', 'k' => 'AA'])));
        $this->joseRefuses('Invalid key for this operation: ES256 needs an EC key', fn() => Jose::verifyKey('ES256', self::edJwk()));
        $this->joseRefuses('Invalid key for this operation: RS256 needs an RSA key', fn() => Jose::verifyKey('RS256', self::edJwk()));
        $this->joseRefuses('Invalid key for this operation: PS256 needs an RSA key', fn() => Jose::verifyKey('PS256', self::edJwk()));
        $p256 = self::ecJwk(self::ec('prime256v1'), 'P-256');
        $this->joseRefuses('Invalid key for this operation: RS256 needs an RSA key', fn() => Jose::verifyKey('RS256', $p256));
        $this->joseRefuses('Invalid key for this operation: ES384 needs an EC P-384 key', fn() => Jose::verifyKey('ES384', $p256));
        $this->assertSame('pk', Jose::verifyKey('ES256', $p256)[0]);
    }

    /** A caller-built RSA PubKey without a modulus is a too-small key, never a crash. */
    public function testRsaPubKeyWithoutModulusIsTooSmall(): void
    {
        $k = new PubKey(self::ec('prime256v1'), '', 'rsa', null, [], null);
        $this->joseRefuses('RS256 requires key modulusLength to be 2048 bits or larger', fn() => Jose::verifyKey('RS256', $k));
    }

    // ---- sign

    /** jwsSign refuses a missing alg and a symmetric alg with the reference texts. */
    public function testSignAlgRefusals(): void
    {
        $this->joseRefuses('JWS "alg" (Algorithm) Header Parameter missing or invalid', fn() => Jose::jwsSign(5, self::seed(), 'd'));
        $this->joseRefuses('KeyObject instances for symmetric algorithms must be of type "secret"', fn() => Jose::jwsSign('HS256', self::seed(), 'd'));
    }

    /** EdDSA signs with a seed or a 64-byte libsodium secret key; any other key is the EdDSA private-key refusal. */
    public function testEdDsaKeyForms(): void
    {
        $sk = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(self::seed()));
        $want = sodium_crypto_sign_detached('d', $sk);
        $this->assertSame($want, Jose::jwsSign('EdDSA', $sk, 'd'));
        $this->assertSame($want, Jose::jwsSign('EdDSA', self::seed(), 'd'));
        $msg = 'Invalid key for this operation: EdDSA needs an Ed25519 or Ed448 private key';
        $this->joseRefuses($msg, fn() => Jose::jwsSign('EdDSA', str_repeat('k', 10), 'd'));
        // not an OKP key: never treated as one, whatever its crv / d say
        $this->joseRefuses($msg, fn() => Jose::jwsSign('EdDSA', Obj::of(['kty' => 'EC', 'crv' => 'Ed25519', 'd' => 5]), 'd'));
        $this->joseRefuses($msg, fn() => Jose::jwsSign('EdDSA', Obj::of(['kty' => 'EC', 'crv' => 'Ed25519', 'd' => 'abc']), 'd'));
        $this->joseRefuses($msg, fn() => Jose::jwsSign('EdDSA', Obj::of(['kty' => 'RSA', 'crv' => 'P-256', 'd' => 5]), 'd'));
    }

    /** With no Ed448 backend an Ed448 private JWK fails with the backend's reason behind the invalid-key prefix. */
    public function testEd448SignWithoutBackend(): void
    {
        $tried = new \ReflectionProperty(OpensslEd448::class, 'tried');
        $ffi = new \ReflectionProperty(OpensslEd448::class, 'ffi');
        $saved = [$tried->getValue(), $ffi->getValue()];
        $tried->setValue(null, true);
        $ffi->setValue(null, null);
        try {
            $this->joseRefuses('Invalid key for this operation: Ed448 needs ext-ffi and an OpenSSL libcrypto (set ATLAS_PCA_LIBCRYPTO)',
                fn() => Jose::jwsSign('EdDSA', Obj::of(['kty' => 'OKP', 'crv' => 'Ed448', 'd' => Jose::b64u(str_repeat("\x07", 57))]), 'd'));
        } finally {
            $tried->setValue(null, $saved[0]);
            $ffi->setValue(null, $saved[1]);
        }
    }

    /** RS / ES signing names the key type it needs and never signs with a key of another type or curve. */
    public function testWrongKeyTypeIsRefused(): void
    {
        $this->joseRefuses('Invalid key for this operation, its asymmetricKeyType must be rsa', fn() => Jose::jwsSign('RS256', 'x', 'd'));
        $this->joseRefuses('Invalid key for this operation, its asymmetricKeyType must be ec', fn() => Jose::jwsSign('ES256', 'x', 'd'));
        $this->joseRefuses('Invalid key for this operation', fn() => Jose::jwsSign('RS256', 'x', 'd', true));
        $this->joseRefuses('Invalid key for this operation, its asymmetricKeyType must be rsa', fn() => Jose::jwsSign('RS256', self::ec('prime256v1'), 'd'));
        $this->joseRefuses('Invalid key for this operation, its asymmetricKeyType must be ec', fn() => Jose::jwsSign('ES256', self::ec('secp384r1'), 'd'));
        $this->assertSame(64, strlen(Jose::jwsSign('ES256', self::ec('prime256v1'), 'd')));
    }

    /** An RSA public key cannot sign: refused, never an empty signature. */
    public function testPublicRsaKeyCannotSign(): void
    {
        $pub = openssl_pkey_get_public(openssl_pkey_get_details(self::rsa1024())['key']);
        $this->assertInstanceOf(\OpenSSLAsymmetricKey::class, $pub);
        set_error_handler(static fn(): bool => true); // openssl_sign warns about the public key before returning false
        try {
            $this->joseRefuses('Invalid key for this operation', fn() => Jose::jwsSign('RS256', $pub, 'd'));
        } finally {
            restore_error_handler();
        }
    }

    /** PS signing: an unloadable JWK, a non-RSA key and a short RSA key are refused with their reasons. */
    public function testPssSignRefusals(): void
    {
        $this->joseRefuses('Invalid key for this operation', fn() => Jose::jwsSign('PS256', Obj::of(['kty' => 'RSA', 'd' => 'abc']), 'd'));
        $this->joseRefuses('Invalid key for this operation', fn() => Jose::jwsSign('PS256', self::ec('prime256v1'), 'd'));
        $this->joseRefuses('PS256 requires key modulusLength to be 2048 bits or larger', fn() => Jose::jwsSign('PS256', self::rsa1024(), 'd'));
    }

    /** An EC private JWK must be on the alg's curve and a valid key. */
    public function testEcPrivateJwkRefusals(): void
    {
        $p = self::ecParts(self::ec('secp384r1'));
        $jwk384 = Obj::of(['kty' => 'EC', 'crv' => 'P-384', 'x' => Jose::b64u($p['x']), 'y' => Jose::b64u($p['y']), 'd' => Jose::b64u($p['d'])]);
        $this->joseRefuses('Invalid key for this operation', fn() => Jose::jwsSign('ES256', $jwk384, 'd'));
        $off = Jose::b64u(str_repeat("\x01", 32));
        $this->joseRefuses('invalid private JWK', fn() => Jose::jwsSign('ES256', Obj::of(['kty' => 'EC', 'crv' => 'P-256', 'x' => $off, 'y' => $off, 'd' => $off]), 'd'));
    }

    /** signJwt refuses an empty alg before it serialises anything. */
    public function testSignJwtRefusesEmptyAlgFirst(): void
    {
        $this->joseRefuses('JWS "alg" (Algorithm) Header Parameter missing or invalid', fn() => Jose::signJwt(new \stdClass(), ['alg' => ''], self::seed()));
    }

    // ---- time spans and clocks

    /** The time-span parser: a sign and "ago" never combine; units and case follow the reference. */
    public function testSecs(): void
    {
        $this->typeRefuses('Invalid time period format', fn() => Jose::secs('-5m ago'));
        $this->assertSame(-300, Jose::secs('-5m'));
        $this->assertSame(-300, Jose::secs('5m ago'));
        $this->assertSame(300, Jose::secs('5m from now'));
        $this->assertSame(7200, Jose::secs('2 Hours'));
        $this->assertSame(300, Jose::secs('5M'));
        foreach (['1y' => 31557600, '1w' => 604800, '1d' => 86400, '1h' => 3600, '1m' => 60, '1s' => 1, '1.5h' => 5400] as $s => $n) {
            $this->assertSame($n, Jose::secs($s), $s);
        }
        // the number is a binary64 (parseFloat), so 2^53 + 1 is 2^53 before the unit multiplies it
        $this->assertSame(540431955284459520, Jose::secs('9007199254740993m'));
    }

    /** epochOfMs: the Date range holds at exactly 8.64e15 ms, beyond is NaN, and the ms are truncated toward zero first. */
    public function testEpochOfMs(): void
    {
        $this->typeRefuses('clock must be a number of milliseconds', fn() => Jose::epochOfMs('x'));
        $this->assertSame(8640000000000.0, Jose::epochOfMs(8.64e15));
        $this->assertNan(Jose::epochOfMs(9e15));
        $this->assertSame(-1.0, Jose::epochOfMs(-1000.5));
        $this->assertSame(1700000000.0, Jose::epochOfMs(1700000000000));
    }

    // ---- compact verify

    /** Malformed compact JWS input is refused with the reference reasons. */
    public function testCompactVerifyShapeRefusals(): void
    {
        $this->joseRefuses('Compact JWS must be a string or Uint8Array', fn() => Jose::compactVerify(5, self::pub()));
        $this->joseRefuses('Invalid Compact JWS', fn() => Jose::compactVerify('a.b', self::pub()));
        $this->joseRefuses('JWS Protected Header is invalid', fn() => Jose::compactVerify(Jose::b64u('[1]') . '.e30.AA', self::pub()));
        $crit = '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present';
        $this->joseRefuses($crit, fn() => Jose::compactVerify(Jose::b64u('{"alg":"EdDSA","crit":"x"}') . '.e30.AA', self::pub()));
        $this->joseRefuses($crit, fn() => Jose::compactVerify(Jose::b64u('{"alg":"EdDSA","crit":[5]}') . '.e30.AA', self::pub()));
        $this->joseRefuses('Extension Header Parameter "x" is missing',
            fn() => Jose::compactVerify(Jose::b64u('{"alg":"EdDSA","crit":["x"]}') . '.e30.AA', self::pub(), null, ['x' => true]));
        $this->typeRefuses('"algorithms" option must be an array of strings', fn() => Jose::compactVerify(Jose::b64u('{"alg":"EdDSA"}') . '.e30.AA', self::pub(), [5]));
    }

    /** EmbeddedJWK: the header's jwk must be an object holding a public key. */
    public function testEmbeddedJwkRefusals(): void
    {
        $this->joseRefuses('"jwk" (JSON Web Key) Header Parameter must be a JSON object',
            fn() => Jose::compactVerify(Jose::b64u('{"alg":"EdDSA"}') . '.e30.AA', Jose::EMBEDDED_JWK));
        $x = Jose::b64u(self::pub());
        $t = self::token(['alg' => 'EdDSA', 'jwk' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x, 'd' => Jose::b64u(self::seed())])]);
        $this->joseRefuses('"jwk" (JSON Web Key) Header Parameter must be a public key', fn() => Jose::compactVerify($t, Jose::EMBEDDED_JWK));
        $ok = self::token(['alg' => 'EdDSA', 'jwk' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x])]);
        $this->assertSame('{"sub":"a"}', Jose::compactVerify($ok, Jose::EMBEDDED_JWK)[0]);
    }

    /** jwtVerify passes the caller's recognised crit extensions through, and refuses only an unencoded (b64 false, crit b64) payload. */
    public function testJwtVerifyCritAndUnencodedPayload(): void
    {
        $t = self::token(['alg' => 'EdDSA', 'crit' => ['x'], 'x' => 1]);
        [$claims] = Jose::jwtVerify($t, self::pub(), ['crit' => ['x' => true]]);
        $this->assertSame('a', $claims->get('sub'));
        // b64 false without crit naming b64 is not an unencoded payload
        $t2 = self::token(['alg' => 'EdDSA', 'b64' => false, 'crit' => ['x'], 'x' => 1]);
        [$claims2] = Jose::jwtVerify($t2, self::pub(), ['crit' => ['x' => true]]);
        $this->assertSame('a', $claims2->get('sub'));
        $input = Jose::b64u('{"alg":"EdDSA","b64":false,"crit":["b64"]}') . '.{"sub":"a"}';
        $raw = $input . '.' . Jose::b64u(Jose::jwsSign('EdDSA', self::seed(), $input));
        $this->joseRefuses('JWTs MUST NOT use unencoded payload', fn() => Jose::jwtVerify($raw, self::pub()));
    }

    // ---- claims

    /** claimsCheck is public; a non-object claims set is refused. */
    public function testClaimsSetMustBeAnObject(): void
    {
        $this->joseRefuses('JWT Claims Set must be a top-level JSON object', fn() => Jose::claimsCheck('[1]', new Obj()));
    }

    /** Missing required claims are reported in the reference order: iss, sub, aud, iat, then requiredClaims (last first). */
    public function testMissingClaimOrder(): void
    {
        $this->joseRefuses('missing required "iss" claim', fn() => Jose::claimsCheck('{}', new Obj(), ['requiredClaims' => ['a'], 'issuer' => 'i']));
    }

    /** sub must equal the expected subject; a non-string, non-list audience is compared as a one-element list. */
    public function testSubjectAndAudience(): void
    {
        $this->assertSame('s', Jose::claimsCheck('{"sub":"s"}', new Obj(), ['subject' => 's'])->get('sub'));
        $this->joseRefuses('unexpected "sub" claim value', fn() => Jose::claimsCheck('{"sub":"t"}', new Obj(), ['subject' => 's']));
        $this->joseRefuses('unexpected "aud" claim value', fn() => Jose::claimsCheck('{"aud":5}', new Obj(), ['audience' => 5]));
    }

    /** maxTokenAge: the age bound holds at exactly the limit (tolerance subtracted), a future iat is refused (tolerance added). */
    public function testMaxTokenAgeBoundaries(): void
    {
        $now = 1700000000;
        $check = static fn(int $iat, array $o = []): Obj => Jose::claimsCheck('{"iat":' . $iat . '}', new Obj(), $o + ['nowMs' => $now * 1000, 'maxTokenAge' => 100]);
        $this->assertSame($now - 100, (int)Js::num($check($now - 100)->get('iat')));
        $this->assertSame($now - 1, (int)Js::num($check($now - 1)->get('iat')));
        $this->assertSame($now, (int)Js::num($check($now)->get('iat')));
        $this->assertSame($now - 105, (int)Js::num($check($now - 105, ['clockTolerance' => 10])->get('iat')));
        $this->assertSame($now + 5, (int)Js::num($check($now + 5, ['clockTolerance' => 10])->get('iat')));
        $this->joseRefuses('"iat" claim timestamp check failed (too far in the past)', fn() => $check($now - 200));
        $this->joseRefuses('"iat" claim timestamp check failed (it should not be in the future)', fn() => $check($now + 1));
        $this->assertSame($now - 50, (int)Js::num($check($now - 50, ['maxTokenAge' => '100s'])->get('iat')));
        $this->typeRefuses('Invalid time period format', fn() => $check($now, ['maxTokenAge' => true]));
    }

    /** A refused key or header is refused cleanly: the refusal raises no PHP warning on the way. */
    public function testRefusalsRaiseNoWarning(): void
    {
        $warnings = [];
        set_error_handler(static function (int $no, string $msg) use (&$warnings): bool {
            $warnings[] = $msg;
            return true;
        });
        try {
            $this->joseRefuses('Invalid key for this operation', fn() => Jose::jwsSign('PS256', Obj::of(['kty' => 'RSA', 'd' => 'abc']), 'd'));
            $this->joseRefuses('JWS Protected Header is invalid', fn() => Jose::compactVerify(Jose::b64u('{') . '.e30.AA', self::pub()));
        } finally {
            restore_error_handler();
        }
        $this->assertSame([], $warnings);
    }
}
