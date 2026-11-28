<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Connect;
use Atlas\Pca\EncryptedConnectionStore;
use Atlas\Pca\InMemoryConnectionStore;
use Atlas\Pca\Js;
use Atlas\Pca\Json;
use Atlas\Pca\LocalKeyWrapper;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RefreshFailedError;
use Atlas\Pca\RequestMismatchError;
use Atlas\Pca\ScopeExceededError;
use Atlas\Pca\StoreError;
use PHPUnit\Framework\TestCase;

/** An inner connection store that answers every get with the last record set (a store that ignores the key). */
final class K15AnyKeyStore
{
    public ?Obj $rec = null;

    public function get(mixed $key): ?Obj
    {
        return $this->rec === null ? null : Connect::cloneConnection($this->rec);
    }

    public function set(mixed $connection): void
    {
        $this->rec = Connect::cloneConnection($connection);
    }

    public function delete(mixed $key): void
    {
        $this->rec = null;
    }
}

/** group 15 mutation kills for src/Connect.php: envelope encryption of stored tokens, the key ring, the request extractor, receipts and refresh. */
final class ConsentSurvivorKill15ConnectTest extends TestCase
{
    private static function k1(): string
    {
        return str_repeat("\x01", 32);
    }

    private static function k2(): string
    {
        return str_repeat("\x02", 32);
    }

    private static function key(string $agent = 'a', string $provider = 'p', string $conn = 'c'): Obj
    {
        return Obj::of(['agentId' => $agent, 'provider' => $provider, 'connectionId' => $conn]);
    }

    private static function conn(string $agent = 'a', string $provider = 'p', string $conn = 'c', array $extra = ['refreshToken' => 'rt']): Obj
    {
        return Obj::of(['agentId' => $agent, 'provider' => $provider, 'connectionId' => $conn, 'accessToken' => 'tok', 'expiresAt' => 1000,
            'scopes' => ['s'], 'authority' => Obj::of(['scopes' => ['s']])] + $extra);
    }

    private static function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        self::fail('expected a throw');
    }

    private static function assertThrown(string $class, string $message, callable $f): \Throwable
    {
        $e = self::thrown($f);
        self::assertSame($class, get_class($e), $e->getMessage());
        self::assertSame($message, $e->getMessage());
        return $e;
    }

    private static function unb64(string $s): string
    {
        return (string)base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
    }

    // ---- errors ---------------------------------------------------------------------------------------------------------------

    /** code() is public; ScopeExceededError lists every field as a list and renders missing scopes in their JS string form. */
    public function testErrorShapes(): void
    {
        $this->assertSame('store_error', (new StoreError())->code());
        $e = new ScopeExceededError('p', [1 => 'a'], [2 => 'b'], [3 => true]);
        $this->assertSame("requested scopes exceed the capability's grant for 'p': not granted [true]", $e->getMessage());
        $this->assertSame(['a'], $e->requested);
        $this->assertSame(['b'], $e->granted);
        $this->assertSame([true], $e->missing);
    }

    // ---- the in-memory store ------------------------------------------------------------------------------------------------------

    /** Record keys never collide when one field's text moves into the next (agentId/provider and provider/connectionId). */
    public function testInMemoryKeysDoNotCollide(): void
    {
        $s = new InMemoryConnectionStore();
        $s->set(self::conn('ab', 'c', 'd'));
        $s->set(self::conn('q', 'r', 'st'));
        $this->assertNull($s->get(self::key('a', 'bc', 'd')));
        $this->assertNull($s->get(self::key('q', 'rs', 't')));
        $this->assertNotNull($s->get(self::key('ab', 'c', 'd')), 'control');
        $this->assertNotNull($s->get(self::key('q', 'r', 'st')), 'control');
    }

    // ---- the key ring -----------------------------------------------------------------------------------------------------------

    /** Key ring refusals: an unknown active id, an empty id, a key that is not 32 bytes, removing the active key, an unknown key id. */
    public function testKeyRingRefusals(): void
    {
        self::assertThrown(\InvalidArgumentException::class, 'LocalKeyWrapper: the active key id is not in the key ring', static fn() => new LocalKeyWrapper(['k1' => self::k1()], 'zz'));
        $w = new LocalKeyWrapper(['k1' => self::k1()], 'k1');
        self::assertThrown(\InvalidArgumentException::class, 'LocalKeyWrapper: key id must not be empty', static fn() => $w->addKey('', self::k1()));
        self::assertThrown(\InvalidArgumentException::class, 'LocalKeyWrapper: keys must be 32 bytes', static fn() => $w->addKey('x', 'short'));
        self::assertThrown(\InvalidArgumentException::class, 'LocalKeyWrapper: keys must be 32 bytes', static fn() => $w->addKey('x', 5));
        self::assertThrown(\InvalidArgumentException::class, 'LocalKeyWrapper: the active key id is not in the key ring', static fn() => $w->setActive('missing'));
        self::assertThrown(\InvalidArgumentException::class, 'LocalKeyWrapper: cannot remove the active key', static fn() => $w->removeKey('k1'));
        self::assertThrown(\RuntimeException::class, 'unknown key id', static fn() => $w->unwrap('missing', 'x', 'aad'));
        $this->assertSame(self::k1(), $w->unwrap('k1', $w->wrap(self::k1(), 'aad')['wrapped'], 'aad'), 'control');
    }

    /** wrap names the active key; rotation, removal of a retired key and destroy all take effect. */
    public function testKeyRingLifecycle(): void
    {
        $w = new LocalKeyWrapper(['1' => self::k1()], '1');
        $r = $w->wrap('dek', 'aad');
        $this->assertSame(['keyId', 'wrapped'], array_keys($r));
        $this->assertSame('1', $r['keyId']);
        $this->assertSame('dek', $w->unwrap('1', $r['wrapped'], 'aad'));
        $w->addKey('k2', self::k2());
        $w->setActive('k2');
        $this->assertSame('k2', $w->wrap('dek', 'aad')['keyId']);
        $w->removeKey('1');
        self::assertThrown(\RuntimeException::class, 'unknown key id', static fn() => $w->unwrap('1', $r['wrapped'], 'aad'));
        $w->destroy();
        self::assertThrown(\RuntimeException::class, 'no active key', static fn() => $w->wrap('dek', 'aad'));
    }

    // ---- the encrypted store -----------------------------------------------------------------------------------------------------

    /** Both tokens reach the inner store only as envelopes and read back as plaintext; delete removes the record. */
    public function testEncryptedStoreSealsBothTokens(): void
    {
        $inner = new InMemoryConnectionStore();
        $s = new EncryptedConnectionStore($inner, new LocalKeyWrapper(['k1' => self::k1()], 'k1'));
        $s->set(self::conn());
        $raw = $inner->get(self::key());
        $this->assertNotNull($raw);
        $this->assertStringStartsWith('pca1.', $raw->get('accessToken'));
        $this->assertStringStartsWith('pca1.', $raw->get('refreshToken'));
        $got = $s->get(self::key());
        $this->assertSame('tok', $got->get('accessToken'));
        $this->assertSame('rt', $got->get('refreshToken'));
        $s->set(self::conn('a', 'p', 'n', []));
        $this->assertFalse($s->get(self::key('a', 'p', 'n'))->has('refreshToken'));
        $s->delete(self::key());
        $this->assertNull($inner->get(self::key()));
        $this->assertNull($s->get(self::key()));
    }

    /** A token that cannot be encrypted stores nothing. */
    public function testEncryptedStoreRefusesANonStringToken(): void
    {
        $inner = new InMemoryConnectionStore();
        $s = new EncryptedConnectionStore($inner, new LocalKeyWrapper(['k1' => self::k1()], 'k1'));
        $c = self::conn();
        $c->set('accessToken', 5);
        self::assertThrown(StoreError::class, 'a token could not be encrypted; nothing was stored', static fn() => $s->set($c));
        $this->assertNull($inner->get(self::key()));
    }

    /** A record whose own key differs from the one asked for (in any single field) is refused, not decrypted and returned. */
    public function testEncryptedStoreRefusesAForeignRecord(): void
    {
        foreach ([['other', 'p', 'c'], ['a', 'other', 'c'], ['a', 'p', 'other']] as [$ag, $pr, $cn]) {
            $inner = new K15AnyKeyStore();
            $s = new EncryptedConnectionStore($inner, new LocalKeyWrapper(['k1' => self::k1()], 'k1'));
            $s->set(self::conn($ag, $pr, $cn));
            $this->assertSame('tok', $s->get(self::key($ag, $pr, $cn))->get('accessToken'), 'control');
            self::assertThrown(StoreError::class, 'a stored token could not be decrypted', static fn() => $s->get(self::key()));
        }
    }

    /** reencrypt moves a record to the active key (so the retired key can go) and reports an absent record. */
    public function testReencrypt(): void
    {
        $inner = new InMemoryConnectionStore();
        $w = new LocalKeyWrapper(['k1' => self::k1()], 'k1');
        $s = new EncryptedConnectionStore($inner, $w);
        $this->assertFalse($s->reencrypt(self::key()));
        $s->set(self::conn());
        $w->addKey('k2', self::k2());
        $w->setActive('k2');
        $this->assertTrue($s->reencrypt(self::key()));
        $this->assertSame(Pca::b64u('k2'), explode('.', $inner->get(self::key())->get('accessToken'))[1]);
        $w->removeKey('k1');
        $this->assertSame('tok', $s->get(self::key())->get('accessToken'));
    }

    // ---- AES-GCM and the envelope -------------------------------------------------------------------------------------------------

    /** seal is iv || ciphertext || tag with the given iv; a fresh iv is 12 bytes. */
    public function testSealLayout(): void
    {
        $iv = str_repeat("\x07", 12);
        $tag = '';
        $ct = openssl_encrypt('hello', 'aes-256-gcm', self::k1(), OPENSSL_RAW_DATA, $iv, $tag, 'aad', 16);
        $this->assertSame($iv . $ct . $tag, Connect::seal(self::k1(), 'aad', 'hello', $iv));
        $fresh = Connect::seal(self::k1(), 'aad', 'abc');
        $this->assertSame(31, strlen($fresh));
        $this->assertSame('abc', Connect::open(self::k1(), 'aad', $fresh));
    }

    /** An IV GCM cannot use fails the seal instead of returning something unauthenticated. */
    public function testSealFailureThrows(): void
    {
        set_error_handler(static fn(): bool => true);
        try {
            $e = self::thrown(static fn() => Connect::seal(self::k1(), 'aad', 'x', ''));
        } finally {
            restore_error_handler();
        }
        $this->assertSame(\RuntimeException::class, get_class($e));
        $this->assertSame('encryption failed', $e->getMessage());
    }

    /** open: exactly iv + tag (28 bytes) is the empty plaintext, 27 bytes is short, a flipped byte fails authentication. */
    public function testOpenBoundaries(): void
    {
        $empty = Connect::seal(self::k1(), 'aad', '', str_repeat("\x07", 12));
        $this->assertSame(28, strlen($empty));
        $this->assertSame('', Connect::open(self::k1(), 'aad', $empty));
        self::assertThrown(\InvalidArgumentException::class, 'short ciphertext', static fn() => Connect::open(self::k1(), 'aad', substr($empty, 0, 27)));
        $s = Connect::seal(self::k1(), 'aad', 'abc');
        $s[13] = chr(ord($s[13]) ^ 1);
        self::assertThrown(\RuntimeException::class, 'authentication failed', static fn() => Connect::open(self::k1(), 'aad', $s));
    }

    /** The envelope: pca1 prefix, the key id, a wrapped 256-bit data key, and a round trip (a token length whose padding is 2). */
    public function testEnvelopeRoundTrip(): void
    {
        $w = new LocalKeyWrapper(['k1' => self::k1()], 'k1');
        $env = Connect::encryptField($w, self::key(), 'access', 'abcdef');
        $parts = explode('.', $env);
        $this->assertCount(4, $parts);
        $this->assertSame('pca1', $parts[0]);
        $this->assertSame('k1', self::unb64($parts[1]));
        $this->assertSame(12 + 32 + 16, strlen(self::unb64($parts[2])));
        $this->assertSame(12 + 6 + 16, strlen(self::unb64($parts[3])));
        $this->assertSame('abcdef', Connect::decryptField($w, self::key(), 'access', $env));
    }

    /** Envelope refusals: non-string token or envelope, a non-string record key, bad base64url, undecodable base64url, non-UTF-8 plaintext. */
    public function testEnvelopeRefusals(): void
    {
        $w = new LocalKeyWrapper(['k1' => self::k1()], 'k1');
        self::assertThrown(\TypeError::class, 'token is not a string', static fn() => Connect::encryptField($w, self::key(), 'access', 5));
        self::assertThrown(\TypeError::class, 'the record key is not made of strings',
            static fn() => Connect::encryptField($w, Obj::of(['agentId' => 5, 'provider' => 'p', 'connectionId' => 'c']), 'access', 't'));
        self::assertThrown(\TypeError::class, 'not an envelope', static fn() => Connect::decryptField($w, self::key(), 'access', 5));
        self::assertThrown(\InvalidArgumentException::class, 'bad encoding', static fn() => Connect::decryptField($w, self::key(), 'access', 'pca1.a+bc.AAAA.AAAA'));
        self::assertThrown(\InvalidArgumentException::class, 'bad encoding', static fn() => Connect::decryptField($w, self::key(), 'access', 'pca1.A.AAAA.AAAA'));
        $bad = Connect::encryptField($w, self::key(), 'access', "\xFF");
        self::assertThrown(\InvalidArgumentException::class, 'not UTF-8', static fn() => Connect::decryptField($w, self::key(), 'access', $bad));
    }

    // ---- scopes and numbers ---------------------------------------------------------------------------------------------------------

    /** The granted scopes are a de-duplicated list, intersected across caveats; a null leaf throws, a non-object leaf grants nothing. */
    public function testGrantedOAuthScopes(): void
    {
        $cv = static fn(array $s): Obj => Obj::of(['type' => 'oauth_scope', 'provider' => 'p', 'scopes' => $s]);
        $this->assertSame(['a', 'b'], Connect::grantedOAuthScopes([Obj::of(['caveats' => [$cv(['a', 'a', 'b'])]])], 'p'));
        $this->assertSame(['b', 'c'], Connect::grantedOAuthScopes([Obj::of(['caveats' => [$cv(['a', 'b', 'c']), $cv(['c', 'b'])]])], 'p'));
        $this->assertNull(Connect::grantedOAuthScopes(['x'], 'p'));
        self::assertThrown(\TypeError::class, 'Cannot read properties of null', static fn() => Connect::grantedOAuthScopes([null], 'p'));
    }

    /** num(): integers as digits, fractions, 1e14 without exponent, 1e20 and NaN in their JS forms. */
    public function testNum(): void
    {
        $this->assertSame('5', Connect::num(5.0)->lexeme);
        $this->assertSame('5.5', Connect::num(5.5)->lexeme);
        $this->assertSame('100000000000000', Connect::num(1e14)->lexeme);
        $this->assertSame('100000000000000000000', Connect::num(1e20)->lexeme);
        $this->assertSame('NaN', Connect::num(NAN)->lexeme);
    }

    // ---- the request extractor ------------------------------------------------------------------------------------------------------

    /** urlFacts: tabs are stripped, the fragment and query are cut before the userinfo is read, an empty user with a password counts. */
    public function testUrlFacts(): void
    {
        $this->assertSame([false, false], Connect::urlFacts("https://\t@h/"));
        $this->assertSame([false, false], Connect::urlFacts("https://\n@h/"));
        $this->assertSame([false, true], Connect::urlFacts('https://h#u@x'));
        $this->assertSame([true, false], Connect::urlFacts(':/u@h#'));
        $this->assertSame([false, false], Connect::urlFacts('https://h?u@x'));
        $this->assertSame([true, false], Connect::urlFacts(':/u@h?'));
        $this->assertSame([false, false], Connect::urlFacts('xu@h'));
        $this->assertSame([true, false], Connect::urlFacts('a:u@h'));
        $this->assertSame([true, false], Connect::urlFacts('https://:p@h'));
    }

    /** Malformed specs are TypeErrors with their reasons. */
    public function testExtractorSpecRefusals(): void
    {
        $bad = static fn(array $s): \Closure => static fn() => Connect::httpExtractor(Obj::of($s));
        self::assertThrown(\TypeError::class, 'httpExtractor: url and method must be strings', $bad(['url' => 'https://api.example/x']));
        self::assertThrown(\TypeError::class, 'httpExtractor: url and method must be strings', $bad(['method' => 'GET']));
        $https = 'httpExtractor: url must be https without query, fragment or userinfo';
        self::assertThrown(\TypeError::class, $https, $bad(['method' => 'GET', 'url' => 'https://api.example/x?y=1']));
        self::assertThrown(\TypeError::class, $https, $bad(['method' => 'GET', 'url' => 'http://api.example/x']));
        self::assertThrown(\TypeError::class, 'httpExtractor: method must be upper case', $bad(['method' => "POST\u{e9}", 'url' => 'https://api.example/x']));
        self::assertThrown(\TypeError::class, "httpExtractor: body must be 'json' or 'form'", $bad(['method' => 'POST', 'url' => 'https://api.example/x', 'body' => 'xml']));
    }

    private static function req(string $method, string $url, ?Obj $headers = null, ?string $body = null): Obj
    {
        $r = Obj::of(['method' => $method, 'url' => $url, 'headers' => $headers ?? new Obj()]);
        if ($body !== null) {
            $r->set('body', $body);
        }
        return $r;
    }

    /** Path / query extraction refusals and the U+FFFD replacement of an undecodable query byte. */
    public function testExtractorRequests(): void
    {
        $x = Connect::httpExtractor(Obj::of(['method' => 'GET', 'url' => 'https://api.example/items/{id}', 'query' => ['q', 'id']]));
        $mm = static fn(string $m): string => 'outbound request refused: ' . $m;
        self::assertThrown(RequestMismatchError::class, $mm('method POST is not GET'), static fn() => $x(self::req('POST', 'https://api.example/items/1')));
        self::assertThrown(RequestMismatchError::class, $mm('the url does not parse'), static fn() => $x(self::req('GET', 'not a url')));
        self::assertThrown(RequestMismatchError::class, $mm('a path segment is not valid percent-encoding'), static fn() => $x(self::req('GET', 'https://api.example/items/%zz')));
        self::assertThrown(RequestMismatchError::class, $mm("parameter 'id' is carried twice"), static fn() => $x(self::req('GET', 'https://api.example/items/1?id=2')));
        self::assertThrown(RequestMismatchError::class, $mm("query key 'q' is repeated"), static fn() => $x(self::req('GET', 'https://api.example/items/1?q=1&q=2')));
        $p = $x(self::req('GET', 'https://api.example/items/1?q=%FF'));
        $this->assertSame(['id', 'q'], $p->keys());
        $this->assertSame('1', $p->get('id'));
        $this->assertSame("\u{FFFD}", $p->get('q'));
    }

    /** JSON bodies: the first content-type header counts, every fixed member must match exactly once, missing ones are named. */
    public function testExtractorJsonBodies(): void
    {
        $x = Connect::httpExtractor(Obj::of(['method' => 'POST', 'url' => 'https://api.example/pay', 'body' => 'json', 'fixed' => Json::parseStrict('{"a":1,"b":2}')]));
        $mm = static fn(string $m): string => 'outbound request refused: ' . $m;
        $ct = Obj::of(['content-type' => 'application/json']);
        $p = $x(self::req('POST', 'https://api.example/pay', Obj::of(['Content-Type' => 'application/json', 'content-type' => 'text/plain']), '{"a":1,"b":2,"x":"y"}'));
        $this->assertSame(['x'], $p->keys());
        $this->assertSame('y', $p->get('x'));
        self::assertThrown(RequestMismatchError::class, $mm("fixed member 'b' has another value"), static fn() => $x(self::req('POST', 'https://api.example/pay', $ct, '{"a":1,"b":3}')));
        self::assertThrown(RequestMismatchError::class, $mm('fixed member(s) a, b missing'), static fn() => $x(self::req('POST', 'https://api.example/pay', $ct, '{"c":3}')));
    }

    /** A repeated form key is refused as such. */
    public function testExtractorFormRepeat(): void
    {
        $x = Connect::httpExtractor(Obj::of(['method' => 'POST', 'url' => 'https://api.example/f', 'body' => 'form']));
        self::assertThrown(RequestMismatchError::class, "outbound request refused: form key 'x' is repeated",
            static fn() => $x(self::req('POST', 'https://api.example/f', Obj::of(['content-type' => 'application/x-www-form-urlencoded']), 'x=1&x=2')));
    }

    /** Header names are compared in full Unicode lower case. */
    public function testProxyHeadersLowerCaseUnicode(): void
    {
        $out = Connect::checkProxyHeaders(Obj::of(["X-\u{c9}" => 'v']), ["x-\u{e9}"]);
        $this->assertSame(["x-\u{e9}"], $out->keys());
    }

    // ---- receipts -------------------------------------------------------------------------------------------------------------------

    /** A seed || public key signs exactly as the seed; any other key length and a non-object PCActn are refused. */
    public function testReleaseReceiptKeys(): void
    {
        $seed = hash('sha256', 'atlas-pca-conformance/k15-receipt', true);
        $pk = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed));
        $body = Obj::of(['x' => 'y']);
        $this->assertSame(Js::stringify(Connect::signReleaseReceipt($body, $seed)), Js::stringify(Connect::signReleaseReceipt($body, $seed . $pk)));
        self::assertThrown(\InvalidArgumentException::class, 'signReleaseReceipt: the vault key is a 32-byte Ed25519 seed', static fn() => Connect::signReleaseReceipt($body, str_repeat('a', 31)));
        self::assertThrown(\TypeError::class, 'receiptActionDigest: the PCActn must be an object', static fn() => Connect::receiptActionDigest('x'));
    }

    // ---- refresh ------------------------------------------------------------------------------------------------------------------

    private static function refresh(mixed $fetchResult, array $config = [], mixed $requested = [], ?array &$calls = null): Obj
    {
        $calls = [];
        $fetch = static function (mixed $url, Obj $init) use ($fetchResult, &$calls): RefConnectResp {
            $calls[] = $init;
            if ($fetchResult instanceof \Throwable) {
                throw $fetchResult;
            }
            return new RefConnectResp(Obj::of(['ok' => true, 'status' => 200, 'json' => $fetchResult]));
        };
        return Connect::refreshConnection(self::conn(), Obj::of($config + ['tokenEndpoint' => 'https://op.example/t', 'clientId' => 'cid']), 'RT', $requested, $fetch, 1000, 5000);
    }

    /** Transport errors are redacted of every secret, extra params included; a non-string secret is left as it is. */
    public function testRefreshRedaction(): void
    {
        $e = self::thrown(static fn() => self::refresh(new \RuntimeException('leak SEKRET'), ['extraParams' => Obj::of(['resource' => 'SEKRET'])]));
        $this->assertSame(RefreshFailedError::class, get_class($e));
        $this->assertSame("refresh for 'p' failed: transport error: leak [redacted]", $e->getMessage());
        $e = self::thrown(static fn() => self::refresh(new \RuntimeException('boom 123'), ['clientSecret' => 123]));
        $this->assertSame(RefreshFailedError::class, get_class($e));
        $this->assertSame("refresh for 'p' failed: transport error: boom 123", $e->getMessage());
    }

    /** A non-string refresh_token in the reply keeps the old one; narrowed scopes go out as their JS strings and come back as a list. */
    public function testRefreshTokenAndScopes(): void
    {
        $r = self::refresh(Obj::of(['access_token' => 'NEW', 'refresh_token' => 5, 'expires_in' => 60]));
        $this->assertSame('RT', $r->get('refreshToken'));
        $this->assertSame('61000', $r->get('expiresAt')->lexeme);
        $r = self::refresh(Obj::of(['access_token' => 'NEW', 'expires_in' => 60]), ['supportsScopeNarrowing' => true], [1 => 'a', 3 => 'b']);
        $this->assertSame(['a', 'b'], $r->get('scopes'));
        self::refresh(Obj::of(['access_token' => 'NEW', 'expires_in' => 60]), ['supportsScopeNarrowing' => true], ['a', true], $calls);
        $this->assertStringContainsString('&scope=a%20true', $calls[0]->get('body'));
    }

    /** Without expires_in a JWT access token's exp is used: only the payload segment is checked, an infinite exp is ignored. */
    public function testRefreshJwtExpiry(): void
    {
        $p = rtrim(strtr(base64_encode('{"exp":200000}'), '+/', '-_'), '=');
        $this->assertSame(19, strlen($p));
        foreach (["h.$p.s", "+.$p.s", "h.$p.+"] as $tok) {
            $this->assertSame('200000000', self::refresh(Obj::of(['access_token' => $tok]))->get('expiresAt')->lexeme, $tok);
        }
        $inf = rtrim(strtr(base64_encode('{"exp":1e400}'), '+/', '-_'), '=');
        $this->assertSame('6000', self::refresh(Obj::of(['access_token' => "h.$inf.s"]))->get('expiresAt')->lexeme);
    }
}
