<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Audience;
use Atlas\Pca\Connect;
use Atlas\Pca\ConnectReplay;
use Atlas\Pca\EncryptedConnectionStore;
use Atlas\Pca\ExpiredNoRefreshError;
use Atlas\Pca\InMemoryConnectionStore;
use Atlas\Pca\InMemoryReplayStore;
use Atlas\Pca\Jsx;
use Atlas\Pca\LocalKeyWrapper;
use Atlas\Pca\NotAuthorizedError;
use Atlas\Pca\Obj;
use Atlas\Pca\Parser;
use Atlas\Pca\Pca;
use Atlas\Pca\ProxyFailedError;
use Atlas\Pca\RequestMismatchError;
use Atlas\Pca\ScopeExceededError;
use Atlas\Pca\StoreError;
use Atlas\Pca\TokenVault;
use PHPUnit\Framework\TestCase;

/** A connection store that keeps the record object exactly as given (no normalising copy). */
final class K15RawStore
{
    public ?Obj $rec = null;

    public function get(mixed $key): ?Obj
    {
        return $this->rec;
    }

    public function set(mixed $connection): void
    {
        $this->rec = $connection;
    }

    public function delete(mixed $key): void
    {
        $this->rec = null;
    }
}

/** A connection store whose every operation throws the given exception. */
final class K15FailStore
{
    public function __construct(private readonly \Throwable $e)
    {
    }

    public function get(mixed $key): ?Obj
    {
        throw $this->e;
    }

    public function set(mixed $connection): void
    {
        throw $this->e;
    }

    public function delete(mixed $key): void
    {
        throw $this->e;
    }
}

/** A clock reached as an [object, method] callable (not a Closure). */
final class K15Clock
{
    public function now(): int
    {
        return 1234;
    }
}

/** group 15 mutation kills for src/ConnectVault.php: strict-mode requirements, the release checks with their exact reasons, PQ pins, proxy mode and the store wrappers. */
final class ConsentSurvivorKill15ConnectVaultTest extends TestCase
{
    private const NOW = 1800000000000;
    private const MAX = 9007199254740991;
    /** @var array<string,Obj> */
    private static array $corpus = [];

    /** The args of a vault scenario of the TS-reference corpus (its PCActns verify under insecureSkipPlanRootCheck at NOW). */
    private static function corpus(string $name): Obj
    {
        if (!isset(self::$corpus[$name])) {
            $h = gzopen(Base::path('ref-connect-v2.json.gz'), 'rb');
            self::assertNotFalse($h);
            try {
                while (($l = gzgets($h)) !== false) {
                    if (str_contains($l, '"name":"' . $name . '"')) {
                        $l = rtrim($l, "\r\n");
                        $c = (new Parser(str_ends_with($l, ',') ? substr($l, 0, -1) : $l, PHP_INT_MAX))->run();
                        self::$corpus[$name] = $c->get('args')[0];
                        break;
                    }
                }
            } finally {
                gzclose($h);
            }
        }
        self::assertArrayHasKey($name, self::$corpus);
        return self::$corpus[$name];
    }

    /** @return array{0:Obj,1:Obj} the put args and the PCActn of a two-call scenario */
    private static function scenario(string $name): array
    {
        $calls = self::corpus($name)->get('calls');
        return [$calls[0]->get('args'), $calls[1]->get('pcActn')];
    }

    private static function put(TokenVault $v, Obj $a, array $over = []): Obj
    {
        $g = static fn(string $k): mixed => array_key_exists($k, $over) ? $over[$k] : $a->get($k);
        return $v->putConnection($g('agentId'), $g('provider'), $g('accessToken'), $g('expiresAt'), $g('scopes'), $g('authority'), $g('connectionId'), $g('refreshToken'));
    }

    private static function vault(array $kw = []): TokenVault
    {
        return new TokenVault($kw + ['strict' => false, 'store' => new InMemoryConnectionStore(), 'now' => static fn(): int => self::NOW,
            'insecureSkipPlanRootCheck' => true, 'insecureBearerRelease' => true]);
    }

    /** A vault holding the release scenario's connection (overridden by `$over`), and its PCActn. @return array{0:TokenVault,1:Obj} */
    private static function released(array $kw = [], array $over = []): array
    {
        [$a, $p] = self::scenario('vault/release');
        $v = self::vault($kw);
        self::put($v, $a, $over);
        return [$v, $p];
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

    /** The verifier's own verdict for `$p` under the vault's arguments. */
    private static function verdict(Obj $p, int $now = self::NOW, mixed $aud = Audience::Any): array
    {
        return Pca::verifyPcactnCore($p, $p->get('cap_chain')[0], $now, $aud, null, null, null, null, null, true);
    }

    private static function verifyFailed(Obj $p, int $now = self::NOW, mixed $aud = Audience::Any): string
    {
        $v = self::verdict($p, $now, $aud);
        self::assertFalse($v['allow'], 'the probe must not verify');
        return 'PCActn verification failed: ' . ($v['reason'] ?? 'rejected');
    }

    // ---- construction -----------------------------------------------------------------------------------------------------------

    /** Strict mode names every missing safeguard, accepts a fully configured vault, and a non-strict vault still needs a store. */
    public function testStrictModeRequirements(): void
    {
        self::assertThrown(\InvalidArgumentException::class, 'TokenVault strict mode requires an encrypting store, replay, isRevoked, audience',
            static fn() => new TokenVault(['store' => new InMemoryConnectionStore()]));
        $enc = new EncryptedConnectionStore(new InMemoryConnectionStore(), new LocalKeyWrapper(['k' => str_repeat("\x01", 32)], 'k'));
        $full = ['store' => $enc, 'replay' => new InMemoryReplayStore(), 'isRevoked' => static fn(): bool => false, 'audience' => 'rs'];
        $this->assertInstanceOf(TokenVault::class, new TokenVault($full));
        self::assertThrown(\InvalidArgumentException::class, 'TokenVault strict mode requires an encrypting store',
            static fn() => new TokenVault(['store' => new InMemoryConnectionStore()] + $full));
        self::assertThrown(\InvalidArgumentException::class, 'TokenVault strict mode requires audience', static fn() => new TokenVault(['audience' => null] + $full));
        self::assertThrown(\InvalidArgumentException::class, 'TokenVault strict mode requires audience', static fn() => new TokenVault(['audience' => ''] + $full));
        self::assertThrown(\InvalidArgumentException::class, 'TokenVault requires a store', static fn() => new TokenVault(['strict' => false]));
    }

    /** proxyHeaders are lower-cased in full Unicode (a number becomes its text); proxyCall without proxyFetch is refused first. */
    public function testProxyOptions(): void
    {
        $v = self::vault(['actions' => static fn() => null, 'proxyFetch' => static fn() => null, 'proxyHeaders' => ["X-\u{c9}", 5]]);
        $req = Obj::of(['headers' => Obj::of(["x-\u{e9}" => 'v', '5' => 'w'])]);
        self::assertThrown(\TypeError::class, "Cannot read properties of null (reading 'cap_chain')", static fn() => $v->proxyCall(null, $req, 'google'));
        self::assertThrown(\TypeError::class, 'proxyCall requires the vault to be constructed with `proxyFetch`',
            static fn() => self::vault(['actions' => static fn() => null])->proxyCall(null, new Obj(), 'google'));
        self::assertThrown(\TypeError::class, "Cannot read properties of null (reading 'cap_chain')", static fn() => self::vault()->getConnectionToken(null, 'google'));
    }

    /** Without `now` the vault reads the wall clock as integer epoch ms; an [object, method] clock is used as given. */
    public function testClockOption(): void
    {
        $v = new TokenVault(['strict' => false, 'store' => new InMemoryConnectionStore()]);
        $at = $v->putConnection('a', 'p', 'tok', 1, ['s'], ['principal' => 'P'])->get('createdAt');
        $this->assertIsInt($at);
        $this->assertLessThan(86400000, abs($at - time() * 1000), 'epoch milliseconds (a day of slack, no timing window)');
        $w = new TokenVault(['strict' => false, 'store' => new InMemoryConnectionStore(), 'now' => [new K15Clock(), 'now']]);
        $this->assertSame(1234, $w->putConnection('a', 'p', 'tok', 1, ['s'], ['principal' => 'P'])->get('createdAt'));
    }

    /** putConnection refuses a non-finite expiry and non-list scopes. */
    public function testPutConnectionRefusals(): void
    {
        $v = self::vault();
        foreach (['x', INF] as $bad) {
            self::assertThrown(\TypeError::class, 'putConnection: expiresAt must be a finite number', static fn() => $v->putConnection('a', 'p', 't', $bad, ['s'], ['principal' => 'P']));
        }
        self::assertThrown(\TypeError::class, 'putConnection: scopes must be a list of strings', static fn() => $v->putConnection('a', 'p', 't', 1, 'x', ['principal' => 'P']));
    }

    // ---- the release checks -----------------------------------------------------------------------------------------------------

    /** A non-callable resourceFor falls back to the default; a custom one and a custom useVerb bind the action, with their reasons. */
    public function testBindingOptions(): void
    {
        [$v, $p] = self::released(['resourceFor' => 'not-a-callable-k15']);
        $this->assertSame('AT-1', $v->getConnectionToken($p, 'google')->get('accessToken'));
        [$v, $p] = self::released(['resourceFor' => static fn($prov, $cid): string => 'custom:x']);
        self::assertThrown(NotAuthorizedError::class, "PCActn action resource 'oauth:google' is not for this connection (expected 'custom:x')", static fn() => $v->getConnectionToken($p, 'google'));
        [$v, $p] = self::released(['useVerb' => 'other']);
        self::assertThrown(NotAuthorizedError::class, "PCActn action verb 'use_connection' is not a connection-use verb (expected 'other')", static fn() => $v->getConnectionToken($p, 'google'));
    }

    private static function actionsFor(mixed $upstream): \Closure
    {
        return static fn($verb): ?Obj => $verb === 'use_connection' ? Obj::of(['verb' => 'use_connection', 'confirmed' => true, 'upstream' => $upstream]) : null;
    }

    /** A derived action must be for this provider and declare a non-empty list of scopes; asking beyond them names the request. */
    public function testDerivedActionChecks(): void
    {
        [$v, $p] = self::released(['actions' => self::actionsFor(Obj::of(['provider' => 'github', 'scopes_min' => ['read']]))]);
        self::assertThrown(NotAuthorizedError::class, "the action 'use_connection' is not for provider 'google'", static fn() => $v->getConnectionToken($p, 'google'));
        $none = "the action 'use_connection' declares no upstream scopes (nothing to release)";
        foreach ([[], ['a' => 'read']] as $smin) {
            [$v, $p] = self::released(['actions' => self::actionsFor(Obj::of(['provider' => 'google', 'scopes_min' => $smin]))]);
            self::assertThrown(NotAuthorizedError::class, $none, static fn() => $v->getConnectionToken($p, 'google'));
        }
        [$v, $p] = self::released(['actions' => self::actionsFor(Obj::of(['provider' => 'google', 'scopes_min' => ['read']]))]);
        $e = self::thrown(static fn() => $v->getConnectionToken($p, 'google', null, ['read', 'write']));
        $this->assertInstanceOf(ScopeExceededError::class, $e);
        $this->assertSame(['read', 'write'], $e->requested);
        $this->assertSame(['read'], $e->granted);
        $this->assertSame(['write'], $e->missing);
    }

    /** A chain that grants nothing for the provider is refused with that reason. */
    public function testNoAuthorityForProvider(): void
    {
        [$a, $p] = self::scenario('vault/release');
        $v = self::vault(['requireActionBinding' => false]);
        self::put($v, $a, ['provider' => 'github']);
        self::assertThrown(NotAuthorizedError::class, "capability grants no authority for provider 'github'", static fn() => $v->getConnectionToken($p, 'github'));
    }

    /** A failed verification carries the verifier's own reason and checks. */
    public function testVerificationFailureReason(): void
    {
        [$v, $p] = self::released(['audience' => 'wrong']);
        $want = self::verdict($p, self::NOW, 'wrong');
        $e = self::assertThrown(NotAuthorizedError::class, self::verifyFailed($p, self::NOW, 'wrong'), static fn() => $v->getConnectionToken($p, 'google'));
        $this->assertSame($want['checks'] ?? null, $e->checks);
    }

    /** The verifier clock must be an integer epoch-ms no larger than 2^53 - 1 (that bound itself is accepted). */
    public function testVerifierClock(): void
    {
        $clock = 'PCActn verification failed: the verifier clock is not an integer epoch-ms';
        foreach ([1.5, null] as $now) {
            [$v, $p] = self::released(['now' => static fn() => $now]);
            self::assertThrown(NotAuthorizedError::class, $clock, static fn() => $v->getConnectionToken($p, 'google'));
        }
        [$v, $p] = self::released(['now' => static fn(): int => self::MAX]);
        self::assertThrown(NotAuthorizedError::class, self::verifyFailed($p, self::MAX), static fn() => $v->getConnectionToken($p, 'google'));
    }

    /** A replayed nonce is refused with the guard's reason. */
    public function testReplayReason(): void
    {
        [$v, $p] = self::released(['replay' => new InMemoryReplayStore()]);
        $this->assertSame('AT-1', $v->getConnectionToken($p, 'google')->get('accessToken'));
        $rs = new InMemoryReplayStore();
        ConnectReplay::guardPcactnReplay($rs, $p, Jsx::get($p, 'aud'), self::NOW);
        $second = ConnectReplay::guardPcactnReplay($rs, $p, Jsx::get($p, 'aud'), self::NOW);
        $this->assertFalse($second['ok']);
        self::assertThrown(NotAuthorizedError::class, 'replay guard refused the action: ' . $second['reason'], static fn() => $v->getConnectionToken($p, 'google'));
    }

    // ---- post-quantum pins (checked before verification) ----------------------------------------------------------------------------

    /** A crafted PCActn whose single root has `$root` members, plus a vault holding a connection for holder H rooted at principal P. */
    private static function pinCase(array $root, mixed $pins, mixed $principal = 'P'): array
    {
        $store = new InMemoryConnectionStore();
        $store->set(Obj::of(['agentId' => 'H', 'provider' => 'google', 'connectionId' => 'default', 'accessToken' => 'AT', 'expiresAt' => self::NOW + 3600000,
            'scopes' => ['read'], 'authority' => Obj::of(['principal' => $principal, 'scopes' => ['read']])]));
        $kw = ['store' => $store];
        if ($pins !== null) {
            $kw['pqPins'] = $pins;
        }
        $p = Obj::of(['cap_chain' => [Obj::of($root + ['issuer' => $principal, 'holder' => 'H'])], 'aud' => 'rs']);
        return [self::vault($kw), $p];
    }

    /** A PQ root passes the pin gate only with an own string pin equal to its pq_pk (Obj or array pins); otherwise it is refused before verification. */
    public function testPqRootPins(): void
    {
        $pq = ['alg' => 'ml-dsa-65', 'pq_pk' => 'PQ'];
        $refused = 'a post-quantum root needs a server-side PQ pin for its issuer';
        foreach ([Obj::of(['P' => 'PQ']), ['P' => 'PQ']] as $pins) {
            [$v, $p] = self::pinCase($pq, $pins);
            self::assertThrown(NotAuthorizedError::class, self::verifyFailed($p), static fn() => $v->getConnectionToken($p, 'google'));
        }
        foreach ([null, Obj::of(['P' => 'OTHER']), Obj::of(['Q' => 'PQ'])] as $pins) {
            [$v, $p] = self::pinCase($pq, $pins);
            self::assertThrown(NotAuthorizedError::class, $refused, static fn() => $v->getConnectionToken($p, 'google'));
        }
        $same = new Obj(); // the very value of pq_pk, but not a string: still refused
        [$v, $p] = self::pinCase(['alg' => 'ml-dsa-65', 'pq_pk' => $same], Obj::of(['P' => $same]));
        self::assertThrown(NotAuthorizedError::class, $refused, static fn() => $v->getConnectionToken($p, 'google'));
    }

    /** A classical root (no alg, or alg ed25519) whose issuer has no pin goes on to verification (Obj pins without it, or a non-string issuer). */
    public function testClassicalRootWithoutPin(): void
    {
        foreach ([[[], Obj::of(['Q' => 'PQ']), 'P'], [[], ['Q' => 'PQ'], 'P'], [['alg' => 'ed25519'], null, 'P'], [[], null, 5]] as [$root, $pins, $principal]) {
            [$v, $p] = self::pinCase($root, $pins, $principal);
            self::assertThrown(NotAuthorizedError::class, self::verifyFailed($p), static fn() => $v->getConnectionToken($p, 'google'));
        }
    }

    /** A root that is not an object is classical (no alg to read) and goes on to verification, which refuses it. */
    public function testNonObjectRoot(): void
    {
        $store = new K15RawStore();
        $store->rec = Obj::of(['agentId' => 'H', 'provider' => 'google', 'connectionId' => 'default', 'accessToken' => 'AT', 'expiresAt' => self::NOW + 3600000,
            'scopes' => ['read'], 'authority' => Obj::of(['scopes' => ['read']])]);
        $p = Obj::of(['cap_chain' => ['x'], 'aud' => 'rs']);
        $v = self::vault(['store' => $store]);
        self::assertThrown(NotAuthorizedError::class, self::verifyFailed($p), static fn() => $v->getConnectionToken($p, 'google'));
    }

    /** The released scopes are returned as a list even when the store hands back a keyed array. */
    public function testReleasedScopesAreAList(): void
    {
        [$a, $p] = self::scenario('vault/release');
        $store = new K15RawStore();
        $store->rec = Obj::of(['agentId' => $a->get('agentId'), 'provider' => 'google', 'connectionId' => 'default', 'accessToken' => 'AT', 'expiresAt' => self::NOW + 3600000,
            'scopes' => ['k' => 'read'], 'authority' => Obj::of(['principal' => $a->get('authority')->get('principal'), 'scopes' => ['read']])]);
        $r = self::vault(['store' => $store])->getConnectionToken($p, 'google');
        $this->assertSame(['read'], $r->get('scopes'));
        $this->assertSame('AT', $r->get('accessToken'));
    }

    // ---- token freshness ----------------------------------------------------------------------------------------------------------

    /** The expiry leeway is 30000 ms by default (exclusive at 30001), configurable, and a non-numeric one counts as 0. */
    public function testLeeway(): void
    {
        $expired = "connection 'google/default' token is expired and has no refresh token";
        [$v, $p] = self::released([], ['expiresAt' => self::NOW + 30001, 'refreshToken' => null]);
        $this->assertFalse($v->getConnectionToken($p, 'google')->get('refreshed'));
        [$v, $p] = self::released([], ['expiresAt' => self::NOW + 30000, 'refreshToken' => null]);
        self::assertThrown(ExpiredNoRefreshError::class, $expired, static fn() => $v->getConnectionToken($p, 'google'));
        [$v, $p] = self::released(['expiryLeewayMs' => 0], ['expiresAt' => self::NOW + 1000, 'refreshToken' => null]);
        $this->assertFalse($v->getConnectionToken($p, 'google')->get('refreshed'));
        [$v, $p] = self::released(['expiryLeewayMs' => 'x'], ['expiresAt' => self::NOW - 1, 'refreshToken' => null]);
        self::assertThrown(ExpiredNoRefreshError::class, $expired, static fn() => $v->getConnectionToken($p, 'google'));
    }

    /** A stored expiry that is infinite or not a number is never fresh. */
    public function testNonFiniteStoredExpiry(): void
    {
        [$a, $p] = self::scenario('vault/release');
        foreach ([INF, 'soon'] as $ea) {
            $store = new InMemoryConnectionStore();
            $store->set(Obj::of(['agentId' => $a->get('agentId'), 'provider' => 'google', 'connectionId' => 'default', 'accessToken' => 'AT', 'expiresAt' => $ea,
                'scopes' => ['read'], 'authority' => Obj::of(['principal' => $a->get('authority')->get('principal'), 'scopes' => ['read']])]));
            $v = self::vault(['store' => $store]);
            self::assertThrown(ExpiredNoRefreshError::class, "connection 'google/default' token is expired and has no refresh token", static fn() => $v->getConnectionToken($p, 'google'));
        }
    }

    /** A refreshed opaque token without expires_in lives defaultTokenLifetimeMs. */
    public function testDefaultTokenLifetime(): void
    {
        $fetch = static fn(mixed $url, Obj $init): RefConnectResp => new RefConnectResp(Obj::of(['ok' => true, 'status' => 200, 'json' => Obj::of(['access_token' => 'NEW'])]));
        [$v, $p] = self::released(['defaultTokenLifetimeMs' => 1000, 'fetch' => $fetch,
            'providers' => Obj::of(['google' => Obj::of(['tokenEndpoint' => 'https://op.example/t', 'clientId' => 'c'])])], ['expiresAt' => self::NOW]);
        $r = $v->getConnectionToken($p, 'google');
        $this->assertTrue($r->get('refreshed'));
        $this->assertSame('NEW', $r->get('accessToken'));
        $this->assertSame('1800000001000', $r->get('expiresAt')->lexeme);
    }

    // ---- proxy mode -------------------------------------------------------------------------------------------------------------

    /** The proxy-ok scenario: a vault with its pinned action, put connection, PCActn and request; `$respond` answers the outbound call. */
    private static function proxied(array $kw, \Closure $respond, ?\Closure $extract = null, ?Obj $record = null): array
    {
        $s = self::corpus('vault/proxy-ok');
        $calls = $s->get('calls');
        $t = $s->get('actionsTable')->get('mail.send');
        $action = Obj::of(['verb' => 'mail.send', 'def_digest' => 'dd', 'confirmed' => true, 'upstream' => $t->get('upstream'),
            'extract' => $extract ?? Connect::httpExtractor($t->get('extract'))]);
        $kw += ['actions' => static fn($verb): ?Obj => $verb === 'mail.send' ? $action : null, 'proxyFetch' => $respond,
            'receipts' => Obj::of(['secretKey' => hash('sha256', 'atlas-pca-conformance/k15-vault', true)])];
        if ($record !== null) {
            $store = $kw['store'] ?? new InMemoryConnectionStore();
            $store->set($record);
            $kw['store'] = $store;
        }
        $v = self::vault($kw);
        if ($record === null) {
            self::put($v, $calls[0]->get('args'));
        }
        return [$v, $calls[1]->get('pcActn'), $calls[1]->get('request')];
    }

    private static function record(mixed $scopes, mixed $authScopes, mixed $token = 'AT-1'): Obj
    {
        [$a] = self::scenario('vault/proxy-ok');
        return Obj::of(['agentId' => $a->get('agentId'), 'provider' => 'google', 'connectionId' => 'default', 'accessToken' => $token, 'expiresAt' => self::NOW + 3600000,
            'scopes' => $scopes, 'authority' => Obj::of(['principal' => $a->get('authority')->get('principal'), 'scopes' => $authScopes])]);
    }

    private static function respond(mixed $status, mixed $headers, mixed $body): \Closure
    {
        return static function (Obj $req) use ($status, $headers, $body): Obj {
            $r = Obj::of(['body' => $body]);
            if ($status !== null) {
                $r->set('status', $status);
            }
            if ($headers !== null) {
                $r->set('headers', $headers);
            }
            return $r;
        };
    }

    /** The extractor's own mismatch reason reaches the caller; any other extractor failure and non-canonical params get the vault's reasons. */
    public function testProxyExtractionFailures(): void
    {
        [$v, $p, $req] = self::proxied([], self::respond(200, null, ''));
        $bad = Obj::of(['method' => $req->get('method'), 'url' => $req->get('url') . '&x=1', 'headers' => $req->get('headers'), 'body' => $req->get('body')]);
        self::assertThrown(RequestMismatchError::class, "outbound request refused: query key 'x' is not allowed", static fn() => $v->proxyCall($p, $bad, 'google'));
        [$v, $p, $req] = self::proxied([], self::respond(200, null, ''), static function (mixed $r): Obj {
            throw new \RuntimeException('extractor bug');
        });
        self::assertThrown(RequestMismatchError::class, 'the outbound request could not be mapped to the action parameters', static fn() => $v->proxyCall($p, $req, 'google'));
        [$v, $p, $req] = self::proxied([], self::respond(200, null, ''), static fn(mixed $r): Obj => Obj::of(['x' => INF]));
        self::assertThrown(RequestMismatchError::class, 'the outbound request parameters are not canonical', static fn() => $v->proxyCall($p, $req, 'google'));
    }

    /** The response size limit is 4 MiB by default (and when the option is not a number): exactly the limit passes, one byte more is refused. */
    public function testProxyResponseLimit(): void
    {
        $limit = 4 * 1024 * 1024;
        $tooBig = 'the response is larger than maxProxyResponseBytes (the call was made and the action is spent)';
        foreach ([[], ['maxProxyResponseBytes' => 'x']] as $kw) {
            [$v, $p, $req] = self::proxied($kw, self::respond(200, null, str_repeat('a', $limit)));
            $this->assertSame($limit, strlen($v->proxyCall($p, $req, 'google')->get('response')->get('body')));
            [$v, $p, $req] = self::proxied($kw, self::respond(200, null, str_repeat('a', $limit + 1)));
            self::assertThrown(ProxyFailedError::class, $tooBig, static fn() => $v->proxyCall($p, $req, 'google'));
        }
    }

    /** The receipt records an integer status up to 2^53 - 1 exactly, and no status for a fractional or missing one. */
    public function testProxyReceiptStatus(): void
    {
        foreach ([[self::MAX, '9007199254740991'], [200.5, null], [null, null]] as [$status, $want]) {
            [$v, $p, $req] = self::proxied([], self::respond($status, null, 'ok'));
            $got = $v->proxyCall($p, $req, 'google')->get('receipt')->get('http_status');
            $this->assertSame($want, $got === null ? null : $got->lexeme);
        }
    }

    /** Array response headers are copied by name (a numeric name as text), redacted, Set-Cookie dropped under Unicode lower-casing; a null body is empty. */
    public function testProxyResponseHeadersAndBody(): void
    {
        [$v, $p, $req] = self::proxied(['maxProxyResponseBytes' => INF],
            self::respond(200, ['X-Echo' => 'AT-1', 'Set-Cookie' => 'a=b', 5 => 'five', "SET-COO\u{212A}IE" => 'k'], null));
        $r = $v->proxyCall($p, $req, 'google')->get('response');
        $this->assertSame(['X-Echo', '5'], $r->get('headers')->keys());
        $this->assertSame('[redacted]', $r->get('headers')->get('X-Echo'));
        $this->assertSame('five', $r->get('headers')->get('5'));
        $this->assertSame('', $r->get('body'));
    }

    /** A stored token that is a number is still redacted from the response (as its text). */
    public function testProxyRedactsANumericToken(): void
    {
        [$v, $p, $req] = self::proxied([], self::respond(200, null, 'x5y'), null, self::record(['write'], ['write'], 5));
        $this->assertSame('x[redacted]y', $v->proxyCall($p, $req, 'google')->get('response')->get('body'));
    }

    /** Scopes held as a bare string (connection, authority) are read as one scope; the receipt sorts scopes that include a number. */
    public function testProxyOddScopes(): void
    {
        $store = new K15RawStore();
        [$v, $p, $req] = self::proxied(['store' => $store], self::respond(200, null, 'ok'), null, self::record('write', 'write'));
        $this->assertSame(['write'], $v->proxyCall($p, $req, 'google')->get('receipt')->get('scopes_released'));
        foreach ([[5, 'write'], ['write', 5]] as $scopes) {
            [$v, $p, $req] = self::proxied([], self::respond(200, null, 'ok'), null, self::record($scopes, ['write']));
            $s = $v->proxyCall($p, $req, 'google')->get('receipt')->get('scopes_released');
            $this->assertCount(2, $s);
            $this->assertSame('5', $s[0]->lexeme); // the signed receipt holds the number in its JSON form
            $this->assertSame('write', $s[1]);
        }
    }

    // ---- the store wrappers -------------------------------------------------------------------------------------------------------

    /** A vault error from the store passes through as it is; any other store failure becomes a StoreError without its text. */
    public function testStoreFailures(): void
    {
        [, $p] = self::scenario('vault/release');
        foreach ([[new StoreError('custom detail'), StoreError::class, 'custom detail'], [new \RuntimeException('record text'), StoreError::class, 'the connection store failed']] as [$ex, $cls, $msg]) {
            $v = self::vault(['store' => new K15FailStore($ex)]);
            self::assertThrown($cls, $msg, static fn() => $v->putConnection('a', 'p', 't', 1, ['s'], ['principal' => 'P']));
            self::assertThrown($cls, $msg, static fn() => $v->deleteConnection('a', 'p'));
            self::assertThrown($cls, $msg, static fn() => $v->getConnectionToken($p, 'google'));
        }
    }

    /** deleteConnection removes the named connection only. */
    public function testDeleteNamedConnection(): void
    {
        $store = new InMemoryConnectionStore();
        $v = self::vault(['store' => $store]);
        $v->putConnection('a', 'p', 't', 1, ['s'], ['principal' => 'P']);
        $v->putConnection('a', 'p', 't', 1, ['s'], ['principal' => 'P'], 'work');
        $v->deleteConnection('a', 'p', 'work');
        $this->assertNull($store->get(Obj::of(['agentId' => 'a', 'provider' => 'p', 'connectionId' => 'work'])));
        $this->assertNotNull($store->get(Obj::of(['agentId' => 'a', 'provider' => 'p', 'connectionId' => 'default'])));
    }
}
