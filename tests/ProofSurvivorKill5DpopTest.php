<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Dpop;
use Atlas\Pca\DpopCodedError;
use Atlas\Pca\DpopNonceIssuer;
use Atlas\Pca\DpopReplayStore;
use Atlas\Pca\DpopVerificationError;
use Atlas\Pca\InMemoryDpopReplayStore;
use Atlas\Pca\Jose;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * DPoP proofs hold their bindings and refusals exactly: the algorithm allowlist, the replay store's key / expiry / clock, the jti
 * generator's UUIDv4 shape, server nonces from a time this verifier never issued, PEM decoding, the PCActn leaf-holder binding and
 * every refusal's exact message.
 */
final class ProofSurvivorKill5DpopTest extends TestCase
{
    private const IAT = 1800000000;
    private const URL = 'https://rs.example/r';

    private static function b64(string $s): string
    {
        return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
    }

    /** @return array{0: Obj, 1: Obj} [private JWK, public JWK] of a fixed Ed25519 key */
    private static function keys(): array
    {
        $seed = hash('sha256', 'atlas-pca/dpop-kill-5', true);
        $x = self::b64(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)));
        return [Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x, 'd' => self::b64($seed)]), Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => $x])];
    }

    private static function proof(array $extra = []): string
    {
        [$priv, $pub] = self::keys();
        return Dpop::createDpopProof(Obj::of(['method' => 'GET', 'url' => self::URL, 'iat' => self::IAT, 'jti' => 'j-1', 'privateKey' => $priv, 'publicJwk' => $pub] + $extra));
    }

    private static function base(array $extra = []): array
    {
        return $extra + ['method' => 'GET', 'url' => self::URL, 'nowSec' => self::IAT + 1, 'requireReplayStore' => false];
    }

    /** @return array{0: string, 1: string} [codeName, message] of the refusal */
    private static function refusal(callable $f): array
    {
        try {
            $f();
        } catch (DpopVerificationError $e) {
            return [$e->codeName, $e->getMessage()];
        }
        self::fail('no DpopVerificationError');
    }

    private static function recorder(?DpopReplayStore $inner = null): DpopReplayStore
    {
        return new class ($inner ?? new InMemoryDpopReplayStore()) implements DpopReplayStore {
            /** @var list<array{0:string,1:int|float,2:int|float}> */
            public array $calls = [];

            public function __construct(private readonly DpopReplayStore $inner)
            {
            }

            public function addIfAbsent(string $key, int|float $expiresAtSec, int|float $nowSec): bool
            {
                $this->calls[] = [$key, $expiresAtSec, $nowSec];
                return $this->inner->addIfAbsent($key, $expiresAtSec, $nowSec);
            }
        };
    }

    public function testTheCodedErrorCarriesItsMessage(): void
    {
        try {
            Dpop::normalizeHtu('not a url');
            self::fail('no throw');
        } catch (DpopCodedError $e) {
            self::assertSame('ERR_INVALID_URL', $e->codeName);
            self::assertSame('Invalid URL', $e->getMessage());
        }
    }

    /** An entry expired at one clock reading is still live for an earlier reading: only a full store may evict. */
    public function testAStoreWithRoomNeverEvicts(): void
    {
        $s = new InMemoryDpopReplayStore();
        self::assertTrue($s->addIfAbsent('a', 200, 100));
        self::assertTrue($s->addIfAbsent('b', 300, 250));
        self::assertFalse($s->addIfAbsent('a', 500, 150));
    }

    public function testANonFiniteNonceLifetimeIsRefused(): void
    {
        foreach ([INF, NAN, 0, -1] as $ttl) {
            self::assertSame(['misconfigured', 'nonce ttlSec must be positive'], self::refusal(static fn() => new DpopNonceIssuer(str_repeat('k', 32), $ttl)));
        }
    }

    /** A nonce whose MAC is right but whose time is above 2^63 was never issued by this verifier. */
    public function testANonceFromAboveTwoToTheSixtyThreeIsRefused(): void
    {
        $secret = str_repeat('s', 32);
        $iss = new DpopNonceIssuer($secret);
        $mac = static fn(string $ts): string => substr(hash_hmac('sha256', "dpop-nonce\0" . $ts, $secret, true), 0, 16);
        $good = pack('J', 1000);
        self::assertTrue($iss->check(Pca::b64u($good . $mac($good)), 1000));
        $ts = "\x80\0\0\0\0\0\0\0";
        self::assertFalse($iss->check(Pca::b64u($ts . $mac($ts)), 1000));
        $ts = "\xff\xff\xff\xff\xff\xff\xff\xff";
        self::assertFalse($iss->check(Pca::b64u($ts . $mac($ts)), 1000));
    }

    /** The conformance kit asks the store exactly these questions, in this order. */
    public function testTheConformanceKitCallsTheStoreWithTheseArguments(): void
    {
        $stores = [];
        $fail = Dpop::runReplayStoreConformance(static function () use (&$stores): DpopReplayStore {
            return $stores[] = self::recorder();
        });
        self::assertSame([], $fail);
        self::assertCount(3, $stores);
        self::assertSame([['a', 200, 100], ['a', 200, 101], ['b', 200, 101], ['a', 200, 199]], $stores[0]->calls);
        self::assertSame([['c', 200, 100], ['c', 400, 200]], $stores[1]->calls);
        self::assertSame(array_fill(0, 16, ['race', 200, 100]), $stores[2]->calls);
    }

    public function testThumbprintOfANonObjectIsATypeError(): void
    {
        foreach (['x', 5, null, [1, 2]] as $j) {
            try {
                Dpop::jwkThumbprint($j);
                self::fail('no throw');
            } catch (\TypeError $e) {
                self::assertSame('JWK must be an object', $e->getMessage());
            }
        }
    }

    public function testUnsupportedKeysAreRefusedWithTheirExactMessage(): void
    {
        self::assertSame(['unsupported_key', "unsupported OKP curve 'X25519' for DPoP"], self::refusal(static fn() => Dpop::algForJwk(['kty' => 'OKP', 'crv' => 'X25519'])));
        self::assertSame(['unsupported_key', "unsupported EC curve 'P-192' for DPoP"], self::refusal(static fn() => Dpop::algForJwk(['kty' => 'EC', 'crv' => 'P-192'])));
        self::assertSame(['unsupported_key', "unsupported key type 'oct' for DPoP"], self::refusal(static fn() => Dpop::algForJwk(['kty' => 'oct'])));
    }

    public function testANonStringMethodIsATypeError(): void
    {
        [$priv, $pub] = self::keys();
        try {
            Dpop::createDpopProof(Obj::of(['method' => 7, 'url' => self::URL, 'privateKey' => $priv, 'publicJwk' => $pub]));
            self::fail('no throw');
        } catch (\TypeError $e) {
            self::assertSame('toUpperCase is not a function', $e->getMessage());
        }
        try {
            Dpop::verifyDpopProof(self::proof(), ['url' => self::URL, 'nowSec' => self::IAT, 'requireReplayStore' => false]);
            self::fail('no throw');
        } catch (\TypeError $e) {
            self::assertSame('toUpperCase is not a function', $e->getMessage());
        }
    }

    /** A generated jti is a random RFC 4122 version-4 UUID: version and variant bits set, every other bit its own random bit. */
    public function testAGeneratedJtiIsARandomUuidV4(): void
    {
        [$priv, $pub] = self::keys();
        $low6 = $odd6 = $even6 = $b6vs5 = $b6vs7 = $b8vs7 = $b8vs9 = $odd8 = $even8 = $low8 = [];
        for ($i = 0; $i < 48; $i++) {
            $p = Dpop::createDpopProof(Obj::of(['method' => 'GET', 'url' => self::URL, 'iat' => self::IAT, 'privateKey' => $priv, 'publicJwk' => $pub]));
            $jti = json_decode((string) Pca::unb64u(explode('.', $p)[1]), true)['jti'];
            self::assertMatchesRegularExpression('/\A[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/', $jti);
            $b = array_values(unpack('C*', (string) hex2bin(str_replace('-', '', $jti))));
            self::assertCount(16, $b);
            $low6[$b[6] & 0x0f] = true;
            $b6vs5[] = ($b[6] & 0x0f) === ($b[5] & 0x0f);
            $b6vs7[] = ($b[6] & 0x0f) === ($b[7] & 0x0f);
            $b8vs7[] = ($b[8] & 0x3f) === ($b[7] & 0x3f);
            $b8vs9[] = ($b[8] & 0x3f) === ($b[9] & 0x3f);
            $low8[$b[8] & 0x0f] = true;
            ($b[6] & 1) === 1 ? $odd6[] = 1 : $even6[] = 1;
            ($b[8] & 1) === 1 ? $odd8[] = 1 : $even8[] = 1;
        }
        // 48 draws: a fixed nibble, a copied nibble or a fixed bit would show in every draw (chance of a false alarm about 2^-40)
        self::assertGreaterThan(1, count($low6));
        self::assertGreaterThan(1, count($low8));
        self::assertContains(false, $b6vs5);
        self::assertContains(false, $b6vs7);
        self::assertContains(false, $b8vs7);
        self::assertContains(false, $b8vs9);
        self::assertNotSame([], $odd6);
        self::assertNotSame([], $even6);
        self::assertNotSame([], $odd8);
        self::assertNotSame([], $even8);
    }

    public function testRefusalMessagesBeforeTheSignature(): void
    {
        self::assertSame(['oversize', 'proof is not a string or exceeds 8192 bytes'], self::refusal(static fn() => Dpop::verifyDpopProof(7, self::base())));
        [$code, $msg] = self::refusal(static fn() => Dpop::verifyDpopProof('a.b', self::base()));
        self::assertSame('malformed', $code);
        self::assertStringStartsWith('not a JWS: ', $msg);
        self::assertGreaterThan(strlen('not a JWS: '), strlen($msg));
        [$priv, $pub] = self::keys();
        $jwt = Jose::signJwt(Obj::of(['htm' => 'GET', 'htu' => self::URL, 'iat' => self::IAT, 'jti' => 'x']), Obj::of(['typ' => 'JWT', 'alg' => 'EdDSA', 'jwk' => $pub]), $priv);
        self::assertSame(['typ', "header typ must be 'dpop+jwt', got 'JWT'"], self::refusal(static fn() => Dpop::verifyDpopProof($jwt, self::base())));
    }

    /** An algorithm the verifier knows but DPoP does not allow (RS384) is refused even with a valid signature by the embedded key. */
    public function testAnAlgorithmOutsideTheAllowlistIsRefused(): void
    {
        $k = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertInstanceOf(\OpenSSLAsymmetricKey::class, $k);
        $d = openssl_pkey_get_details($k)['rsa'];
        $jwk = ['kty' => 'RSA', 'n' => self::b64($d['n']), 'e' => self::b64($d['e'])];
        $h = self::b64((string) json_encode(['typ' => 'dpop+jwt', 'alg' => 'RS384', 'jwk' => $jwk]));
        $p = self::b64((string) json_encode(['htm' => 'GET', 'htu' => self::URL, 'iat' => self::IAT, 'jti' => 'r']));
        self::assertTrue(openssl_sign("$h.$p", $sig, $k, OPENSSL_ALGO_SHA384));
        $proof = "$h.$p." . self::b64($sig);
        self::assertSame(['signature', 'DPoP signature did not verify: "alg" (Algorithm) Header Parameter value not allowed'],
            self::refusal(static fn() => Dpop::verifyDpopProof($proof, self::base())));
    }

    public function testABadSignatureNamesTheJoseReason(): void
    {
        $p = self::proof();
        $parts = explode('.', $p);
        $sig = (string) Pca::unb64u($parts[2]);
        $sig[0] = chr(ord($sig[0]) ^ 1);
        $bad = $parts[0] . '.' . $parts[1] . '.' . Pca::b64u($sig);
        self::assertSame(['signature', 'DPoP signature did not verify: signature verification failed'], self::refusal(static fn() => Dpop::verifyDpopProof($bad, self::base())));
    }

    /** A max age that is not a number never admits a proof, not even one of age zero. */
    public function testANonNumericMaxAgeIsStaleEvenAtAgeZero(): void
    {
        self::assertSame(['iat_stale', 'proof is older than xs'], self::refusal(static fn() => Dpop::verifyDpopProof(self::proof(), self::base(['nowSec' => self::IAT, 'maxAgeSec' => 'x']))));
        self::assertSame(['iat_stale', 'proof is older than 10s'], self::refusal(static fn() => Dpop::verifyDpopProof(self::proof(), self::base(['nowSec' => self::IAT + 11, 'maxAgeSec' => 10]))));
    }

    /** The store sees "<jkt>.<jti>", the expiry iat + maxAge + skew, and the verifier's clock as a float. */
    public function testTheReplayStoreGetsTheBoundKeyExpiryAndClock(): void
    {
        $rec = self::recorder();
        $r = Dpop::verifyDpopProof(self::proof(), ['method' => 'GET', 'url' => self::URL, 'nowSec' => self::IAT + 1, 'maxAgeSec' => 60, 'replayStore' => $rec]);
        self::assertSame([[$r['jkt'] . '.j-1', (float) (self::IAT + 65), (float) (self::IAT + 1)]], $rec->calls);
        [$priv, $pub] = self::keys();
        $now = time();
        $proof = Dpop::createDpopProof(Obj::of(['method' => 'GET', 'url' => self::URL, 'iat' => $now, 'jti' => 'j-2', 'privateKey' => $priv, 'publicJwk' => $pub]));
        $rec2 = self::recorder();
        Dpop::verifyDpopProof($proof, ['method' => 'GET', 'url' => self::URL, 'replayStore' => $rec2]);
        self::assertCount(1, $rec2->calls);
        self::assertTrue(is_float($rec2->calls[0][2]));
        self::assertTrue(is_float($rec2->calls[0][1]));
    }

    public function testAFailingReplayStoreNamesItsError(): void
    {
        $boom = new class () implements DpopReplayStore {
            public function addIfAbsent(string $key, int|float $expiresAtSec, int|float $nowSec): bool
            {
                throw new \RuntimeException('boom');
            }
        };
        self::assertSame(['replay_store_error', 'replay store failed: boom'], self::refusal(static fn() => Dpop::verifyDpopProof(self::proof(), self::base(['replayStore' => $boom]))));
    }

    /** PEM bodies are decoded leniently: junk skipped, any padding, a lone trailing sextet dropped; the hash is of the DER bytes. */
    public function testPemBodiesDecodeToTheirDerBytes(): void
    {
        foreach ([30, 31, 32, 33, 34, 35] as $len) {
            $der = '';
            for ($i = 0; $i < $len; $i++) {
                $der .= chr(($i * 37 + 11) & 0xff);
            }
            $want = Pca::b64u(hash('sha256', $der, true));
            $b64 = base64_encode($der);
            $bare = rtrim($b64, '=');
            foreach ([$b64, $bare, "-----BEGIN CERTIFICATE-----\n" . chunk_split($bare, 7, "\n") . "-----END CERTIFICATE-----\n"] as $pem) {
                self::assertSame(['x5t#S256' => $want], Dpop::mtlsCnf($pem), "len $len: $pem");
            }
            if (strlen($bare) % 4 === 0) {
                // one extra sextet carries no whole byte; text after the first '=' is ignored
                self::assertSame(['x5t#S256' => $want], Dpop::mtlsCnf($bare . 'Q'), "len $len + sextet");
                self::assertSame(['x5t#S256' => $want], Dpop::mtlsCnf($bare . '=QUJD'), "len $len + tail");
            }
        }
    }

    public function testAnUnparsableCertificateNamesTheOpensslError(): void
    {
        while (openssl_error_string() !== false) {
            // drain the queue so the refusal reads this parse's own error
        }
        [$code, $msg] = self::refusal(static fn() => Dpop::mtlsThumbprint("\x30\x03\x02\x01\x01"));
        self::assertSame('cert', $code);
        self::assertStringStartsWith('not an X.509 certificate: error:', $msg);
    }

    public function testANullChainIsATypeError(): void
    {
        foreach ([['cap_chain' => null], ['other' => 1]] as $p) {
            try {
                Dpop::leafHolderJwk($p);
                self::fail('no throw');
            } catch (\TypeError $e) {
                self::assertSame("Cannot read properties of null (reading 'length')", $e->getMessage());
            }
        }
    }

    /** An array-like chain object is read at index length - 1; a scalar chain has no leaf. */
    public function testAnArrayLikeChainIsReadAtItsLastIndex(): void
    {
        $chain = Obj::of(['length' => 2, '0' => Obj::of(['holder' => 'first']), '1' => Obj::of(['holder' => 'second'])]);
        self::assertSame(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'second'], Dpop::leafHolderJwk(['cap_chain' => $chain]));
        // a length that is not a number reads index "NaN" (JS: NaN - 1)
        self::assertSame(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => 'n'],
            Dpop::leafHolderJwk(['cap_chain' => Obj::of(['length' => 'x', '-1' => Obj::of(['holder' => 'h']), 'NaN' => Obj::of(['holder' => 'n'])])]));
        self::assertSame(['no_leaf', 'PCActn capability chain is empty; no bound holder key'], self::refusal(static fn() => Dpop::leafHolderJwk(['cap_chain' => 5])));
    }
}
