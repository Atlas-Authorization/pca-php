<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\ConnectorError;
use Atlas\Pca\Connectors;
use Atlas\Pca\ManifestValidationError;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\ProviderRegistry;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/Connectors.php: the default registry, redirect-URI credential and fragment checks, PKCE/state generation and the token exchange. */
final class LedgerSurvivorKill19ConnectorsTest extends TestCase
{
    protected function tearDown(): void
    {
        Connectors::$clockHook = null;
    }

    private static function manifest(array $over = []): Obj
    {
        return Obj::of($over + ['id' => 'acme', 'displayName' => 'Acme', 'authorizeUrl' => 'https://auth.acme.test/authorize',
            'tokenUrl' => 'https://auth.acme.test/token', 'scopesAvailable' => ['read', 'write'], 'defaultScopes' => ['read'],
            'refresh' => Obj::of(['mode' => 'refresh_token']), 'tokenPlacement' => 'bearer']);
    }

    private static function registry(): ProviderRegistry
    {
        $r = new ProviderRegistry();
        $r->register(self::manifest(['refresh' => Obj::of(['mode' => 'refresh_token', 'extraParams' => Obj::of(['audience' => 'api'])])]));
        $r->register(self::manifest(['id' => 'acmeb', 'clientAuth' => 'basic']));
        return $r;
    }

    private static function thrown(callable $f): string
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return (new \ReflectionClass($e))->getShortName() . ': ' . $e->getMessage();
        }
        return 'nothing thrown';
    }

    private static function authorize(array $o): Obj
    {
        return Connectors::buildAuthorizeUrl('github', Obj::of($o + ['clientId' => 'cid', 'redirectUri' => 'https://app.example/cb', 'state' => str_repeat('s', 16)]));
    }

    /** @return array{0:object,1:Obj} a vault stub that records putConnection's arguments, and the exchange args */
    private static function exchange(mixed $body, array $over = []): array
    {
        $vault = new class {
            /** @var list<mixed> */
            public array $args = [];

            public function putConnection(mixed ...$a): Obj
            {
                $this->args = $a;
                return new Obj();
            }
        };
        $fetch = static fn(string $url, Obj $init): object => new class ($body) {
            public bool $ok = true;
            public int $status = 200;

            public function __construct(private mixed $b)
            {
            }

            public function json(): mixed
            {
                return $this->b;
            }

            public function text(): string
            {
                return '';
            }
        };
        $args = Obj::of($over + ['providerId' => 'acme', 'clientId' => 'cid', 'code' => 'the-code', 'redirectUri' => 'https://app.example/cb', 'fetch' => $fetch,
            'bind' => Obj::of(['vault' => $vault, 'agentId' => 'agent', 'authority' => Obj::of(['principal' => 'p'])]), 'registry' => self::registry(), 'now' => 1000]);
        return [$vault, $args];
    }

    /** A validation error's issues are a list whatever keys the caller passed. */
    public function testValidationErrorIssuesAreAList(): void
    {
        $e = new ManifestValidationError([3 => 'x', 7 => 'y']);
        $this->assertSame(['x', 'y'], $e->issues);
        $this->assertSame('invalid provider manifest: x; y', $e->getMessage());
    }

    /** Several bad scope entries in one list are reported once. */
    public function testBadScopeEntriesReportedOnce(): void
    {
        $r = Connectors::validateManifest(self::manifest(['scopesAvailable' => ['a b', 'c,d'], 'defaultScopes' => []]));
        $this->assertSame(['ok' => false, 'issues' => ['scopesAvailable entries must be non-empty and contain no whitespace or comma (a separator inside a scope would smuggle in another scope)']], $r);
    }

    /** The default registry is created once and shared; registerProvider adds to it. */
    public function testDefaultRegistryIsShared(): void
    {
        $p = new \ReflectionProperty(Connectors::class, 'default');
        $saved = $p->getValue();
        try {
            $p->setValue(null, null);
            $this->assertSame(Connectors::defaultRegistry(), Connectors::defaultRegistry());
            $this->assertNull(Connectors::getProvider('acme'));
            $this->assertSame('acme', Connectors::registerProvider(self::manifest())->get('id'));
            $got = Connectors::getProvider('acme');
            $this->assertSame('Acme', $got === null ? null : $got->get('displayName'));
        } finally {
            $p->setValue(null, $saved);
        }
    }

    /** Without a registry option the default catalog serves the URL; a missing state gets a random 43-character one. */
    public function testAuthorizeUrlFromTheDefaultCatalog(): void
    {
        $out = self::authorize([]);
        $this->assertSame('https://github.com/login/oauth/authorize?response_type=code&client_id=cid&redirect_uri=https%3A%2F%2Fapp.example%2Fcb'
            . '&scope=read%3Auser%20user%3Aemail&state=ssssssssssssssss', $out->get('url'));
        $this->assertFalse($out->has('pkce'));
        $gen = Connectors::buildAuthorizeUrl('github', Obj::of(['clientId' => 'cid', 'redirectUri' => 'https://app.example/cb']));
        $this->assertSame(43, strlen($gen->get('state')));
        $this->assertStringEndsWith('&state=' . $gen->get('state'), $gen->get('url'));
    }

    /** pkce: true generates a 43-character S256 verifier; pkce: null is the runtime's null read. */
    public function testPkceGeneration(): void
    {
        $pk = self::authorize(['pkce' => true])->get('pkce');
        $this->assertSame(43, strlen($pk->get('verifier')));
        $this->assertSame(['S256', Connectors::pkceChallenge($pk->get('verifier'))], [$pk->get('method'), $pk->get('challenge')]);
        $this->assertSame('TypeError: Cannot read properties of null', self::thrown(fn() => self::authorize(['pkce' => null])));
    }

    /** A non-special redirect URI: user or password makes credentials (an empty pair does not), only the authority is searched, and an empty fragment is none. */
    public function testOpaqueRedirectUriFacts(): void
    {
        $creds = 'ConnectorError: buildAuthorizeUrl: redirectUri must not carry credentials';
        $https = 'ConnectorError: buildAuthorizeUrl: redirectUri must be https (http only for localhost)';
        $frag = 'ConnectorError: buildAuthorizeUrl: redirectUri must not have a fragment (RFC 6749 3.1.2)';
        foreach (['myapp://u@h/cb' => $creds, 'myapp://:p@h/cb' => $creds, 'myapp://u:@h' => $creds, "myapp:/\t/u@h" => $creds, 'myapp://u@h' => $creds,
            'myapp://:@h/cb' => $https, 'myapp://@h' => $https, 'myapp://h/a@b' => $https, 'myapp:/cb#' => $https, 'myapp:/cb' => $https,
            'myapp:/cb#x' => $frag] as $uri => $want) {
            $this->assertSame($want, self::thrown(fn() => self::authorize(['redirectUri' => $uri])), $uri);
        }
    }

    /** The vault config and vault providers come from the given registry and keep the manifest's refresh extraParams. */
    public function testVaultProvidersFromAGivenRegistry(): void
    {
        $cfg = Connectors::buildVaultProviders(Obj::of(['acme' => Obj::of(['clientId' => 'cid'])]), self::registry())->get('acme');
        $this->assertSame(['https://auth.acme.test/token', 'cid', 'api'], [$cfg->get('tokenEndpoint'), $cfg->get('clientId'), $cfg->get('extraParams')->get('audience')]);
    }

    /** Exchange: a non-string refresh_token is ignored, basic auth needs a client id, and a missing transport is a transport error. */
    public function testExchangeRefusalsAndRefreshTokenShape(): void
    {
        [$vault, $args] = self::exchange(Obj::of(['access_token' => 'at', 'refresh_token' => 5]));
        Connectors::exchangeCode($args);
        $this->assertSame(['agent', 'acme', 'at', '3601000', ['read']], [$vault->args[0], $vault->args[1], $vault->args[2], $vault->args[3]->lexeme, $vault->args[4]]);
        $this->assertNull($vault->args[7]);
        [, $args] = self::exchange(Obj::of(['access_token' => 'at']), ['providerId' => 'acmeb', 'clientSecret' => 'sec']);
        $args = $args->without('clientId');
        $this->assertSame('ConnectorError: [acmeb] missing client_id for basic auth', self::thrown(fn() => Connectors::exchangeCode($args)));
        [, $args] = self::exchange(Obj::of(['access_token' => 'at']));
        $this->assertSame('ConnectorError: [acme] token transport error: fetchImpl is not a function', self::thrown(fn() => Connectors::exchangeCode($args->without('fetch'))));
    }

    /** Without `now` the exchange stamps whole epoch milliseconds from the wall clock. */
    public function testExchangeDefaultClock(): void
    {
        [$vault, $args] = self::exchange(Obj::of(['access_token' => 'at']));
        $args = $args->without('now');
        Connectors::$clockHook = static fn(): float => 2.0625;
        Connectors::exchangeCode($args);
        $this->assertSame('3602062', $vault->args[3]->lexeme);
        Connectors::$clockHook = null;
        $before = (int)(microtime(true) * 1000);
        Connectors::exchangeCode($args);
        $after = (int)(microtime(true) * 1000);
        $exp = $vault->args[3];
        $this->assertInstanceOf(Num::class, $exp);
        $this->assertTrue($exp->isInt());
        $this->assertGreaterThanOrEqual($before + 3_600_000, $exp->int());
        $this->assertLessThanOrEqual($after + 3_600_000, $exp->int());
    }

    /** A string extraParams splits into UTF-16 units: an astral character becomes two lone surrogates, which the form encoder refuses. */
    public function testAstralExtraParamsStringIsMalformed(): void
    {
        foreach (["\u{10000}", "a\u{10FFFF}", "\u{1F600}b"] as $s) {
            $this->assertSame('InvalidArgumentException: URI malformed', self::thrown(fn() => self::authorize(['extraParams' => $s])), bin2hex($s));
        }
        $this->assertStringEndsWith('&state=ssssssssssssssss&0=a&1=%C3%A9', self::authorize(['extraParams' => "a\u{E9}"])->get('url'));
    }

    /** An unknown provider in the vault credentials is refused by the given registry. */
    public function testVaultProvidersRequireKnownIds(): void
    {
        $this->expectException(ConnectorError::class);
        Connectors::buildVaultProviders(Obj::of(['nope' => Obj::of(['clientId' => 'cid'])]), self::registry());
    }
}
