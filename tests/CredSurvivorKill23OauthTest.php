<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Oauth;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** OAuth bridge: discovery / PRM parse refusals, the default discovery fetch, the 401 challenge and the scope and grant gates. */
final class CredSurvivorKill23OauthTest extends TestCase
{
    private const DOC = '{"audience":"rs1","pca_versions":[2],"signature_suites":["ed25519"],"action_header":"PCA-Action"}';

    /** Child server: prints its port, answers each connection with the next canned response pair ([with accept: application/json, without]). */
    private const SERVER = <<<'SRV'
$s = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
if ($s === false) {
    fwrite(STDERR, $errstr);
    exit(1);
}
$name = (string) stream_socket_get_name($s, false);
fwrite(STDOUT, substr($name, (int) strrpos($name, ':') + 1) . "\n");
foreach ($responses as [$yes, $no]) {
    $c = @stream_socket_accept($s, 5);
    if ($c === false) {
        break;
    }
    $req = '';
    while (!str_contains($req, "\r\n\r\n")) {
        $b = fread($c, 8192);
        if ($b === false || $b === '') {
            break;
        }
        $req .= $b;
    }
    fwrite($c, stripos($req, "\r\naccept: application/json\r\n") !== false ? $yes : $no);
    fclose($c);
}
SRV;

    private function throws(callable $f, string $msg): void
    {
        try {
            $f();
        } catch (\InvalidArgumentException $e) {
            $this->assertSame($msg, $e->getMessage());
            return;
        }
        $this->fail("expected InvalidArgumentException: $msg");
    }

    private static function resp(string $status, string $body, string $extra = ''): string
    {
        return "HTTP/1.1 $status\r\n{$extra}Content-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n$body";
    }

    /** One fetchDiscovery call per canned response; a 302 is not followed, a 300 or a trailing 1xx status line is not ok. */
    public function testDefaultFetch(): void
    {
        $ok = self::resp('200 OK', self::DOC, "X-Note: HTTP/1.1 500 x\r\n");
        $responses = [
            [$ok, self::resp('406 Not Acceptable', '')],
            [self::resp('300 Multiple Choices', self::DOC), self::resp('300 Multiple Choices', self::DOC)],
            [self::resp('200 OK', self::DOC, "HTTP/1.1 150 X\r\n"), self::resp('200 OK', self::DOC, "HTTP/1.1 150 X\r\n")],
            [self::resp('302 Found', '', "Location: /next\r\n"), self::resp('302 Found', '', "Location: /next\r\n")],
            [$ok, $ok],
        ];
        $code = '$responses = ' . var_export($responses, true) . ";\n" . self::SERVER;
        $p = proc_open([PHP_BINARY, '-d', 'display_errors=stderr', '-r', $code], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $this->assertIsResource($p);
        try {
            $port = (int)trim((string)fgets($pipes[1]));
            $this->assertGreaterThan(0, $port);
            $base = "http://127.0.0.1:$port";
            $url = $base . Oauth::WELL_KNOWN_PCA_PATH;
            $this->assertSame('rs1', Oauth::fetchDiscovery($base)->get('audience'));
            $this->throws(fn() => Oauth::fetchDiscovery($base), "fetchDiscovery: $url returned 300");
            $this->throws(fn() => Oauth::fetchDiscovery($base), "fetchDiscovery: $url returned 150");
            $this->throws(fn() => Oauth::fetchDiscovery($base), "fetchDiscovery: $url returned 302");
        } finally {
            proc_terminate($p);
            fclose($pipes[1]);
            fclose($pipes[2]);
            proc_close($p);
        }
    }

    /** A refused connection is status 0, not ok. */
    public function testDefaultFetchRefused(): void
    {
        $s = stream_socket_server('tcp://127.0.0.1:0');
        $this->assertIsResource($s);
        $name = (string)stream_socket_get_name($s, false);
        fclose($s);
        $base = 'http://127.0.0.1:' . substr($name, (int)strrpos($name, ':') + 1);
        $this->throws(fn() => Oauth::fetchDiscovery($base), "fetchDiscovery: $base/.well-known/pca-configuration returned 0");
    }

    /** An injected fetch must say ok === true; a missing status reads 0; the body is read as a string; non-JSON is refused. */
    public function testInjectedFetch(): void
    {
        $u = 'https://x/.well-known/pca-configuration';
        $this->throws(fn() => Oauth::fetchDiscovery('https://x', static fn() => ['status' => 500, 'body' => self::DOC]), "fetchDiscovery: $u returned 500");
        $this->throws(fn() => Oauth::fetchDiscovery('https://x', static fn() => ['ok' => false]), "fetchDiscovery: $u returned 0");
        $this->throws(fn() => Oauth::fetchDiscovery('https://x', static fn() => ['ok' => true, 'body' => 5]), 'parseDiscoveryDocument: not an object');
        $this->throws(fn() => Oauth::fetchDiscovery('https://x', static fn() => ['ok' => true, 'body' => 'nope']), 'fetchDiscovery: the response is not JSON');
    }

    /** prmUrlForResource refuses an unparsable URL and a URL with no origin with its own message. */
    public function testPrmUrlRefusals(): void
    {
        $this->assertSame('https://rs.example/.well-known/oauth-protected-resource/api', Oauth::prmUrlForResource('https://rs.example/api'));
        $this->throws(fn() => Oauth::prmUrlForResource('nope'), 'prmUrlForResource: invalid resource identifier');
        $this->throws(fn() => Oauth::prmUrlForResource('foo://host/p'), 'prmUrlForResource: invalid resource identifier');
    }

    /** intent.versions, schema_keys and tiers refusals; tier 4 and plain integer tiers are accepted. */
    public function testIntentRefusals(): void
    {
        $i = static fn(array $extra): Obj => Obj::of(['versions' => [1]] + $extra);
        $vm = 'parseDiscoveryDocument: intent.versions must list 1 and/or 2';
        $this->throws(fn() => Oauth::parseDiscoveryIntent(Obj::of(['versions' => '1'])), $vm);
        $this->throws(fn() => Oauth::parseDiscoveryIntent(Obj::of(['versions' => [3, 1]])), $vm);
        $this->throws(fn() => Oauth::parseDiscoveryIntent($i(['schema_keys' => 'x'])), 'parseDiscoveryDocument: intent.schema_keys must be an array');
        $km = 'parseDiscoveryDocument: intent.schema_keys entries are {kid, alg, pk, pq_pk?}';
        $this->throws(fn() => Oauth::parseDiscoveryIntent($i(['schema_keys' => ['x']])), $km);
        $this->throws(fn() => Oauth::parseDiscoveryIntent($i(['schema_keys' => [Obj::of(['kid' => 1, 'alg' => 'a', 'pk' => 'p'])]])), $km);
        $this->throws(fn() => Oauth::parseDiscoveryIntent($i(['schema_keys' => [Obj::of(['kid' => 'k', 'alg' => 'a', 'pk' => 'p', 'pq_pk' => 5])]])), $km);
        $good = Oauth::parseDiscoveryIntent($i(['schema_keys' => [Obj::of(['kid' => 'k', 'alg' => 'a', 'pk' => 'p', 'pq_pk' => 'q'])]]));
        $this->assertSame('q', $good->get('schema_keys')[0]->get('pq_pk'));
        $this->throws(fn() => Oauth::parseDiscoveryIntent($i(['tiers' => 5])), 'parseDiscoveryDocument: intent.tiers must be an object');
        $t = Oauth::parseDiscoveryIntent($i(['tiers' => Obj::of(['a' => 4, 'b' => 1])]))->get('tiers');
        $this->assertSame([4, 1], [$t->get('a'), $t->get('b')]);
        $this->throws(fn() => Oauth::parseDiscoveryIntent($i(['tiers' => Obj::of(['a' => new Num('-0')])])), 'parseDiscoveryDocument: intent.tiers values must be integers 0..4');
    }

    /** parseDiscoveryDocument refuses non-list pca_versions; acceptsSuite needs an Obj document. */
    public function testDiscoveryDocument(): void
    {
        $this->throws(fn() => Oauth::parseDiscoveryDocument(Obj::of(['audience' => 'a', 'pca_versions' => 'x'])), 'parseDiscoveryDocument: pca_versions must be a number[]');
        $this->assertTrue(Oauth::acceptsSuite(Obj::of(['signature_suites' => ['ed25519']]), 'ed25519'));
        $this->assertFalse(Oauth::acceptsSuite(['signature_suites' => ['ed25519']], 'ed25519'));
    }

    /** PRM build: resource required; the list members spread a string into its characters. */
    public function testProtectedResourceMetadata(): void
    {
        $this->throws(fn() => Oauth::protectedResourceMetadata([]), 'protectedResourceMetadata: `resource` (the RS id = PCActn audience) is required');
        $d = Oauth::protectedResourceMetadata(['resource' => 'https://rs.example/api', 'authorizationServers' => 'ab', 'scopesSupported' => 'cd',
            'resourceSigningAlgValuesSupported' => 'ef', 'authorizationDetailsTypesSupported' => 'gh', 'resourceName' => 'nm']);
        $this->assertSame([['a', 'b'], ['c', 'd'], ['e', 'f'], ['g', 'h'], 'nm'], [$d->get('authorization_servers'), $d->get('scopes_supported'),
            $d->get('resource_signing_alg_values_supported'), $d->get('authorization_details_types_supported'), $d->get('resource_name')]);
    }

    /** PRM parse: non-object, non-list versions, non-object pca and a non-https resource under strict each refuse with their reason. */
    public function testParsePrmRefusals(): void
    {
        $p = 'parseProtectedResourceMetadata: ';
        $base = ['resource' => 'http://rs.example', 'bearer_methods_supported' => ['header'], 'pca_action_header' => 'h', 'pca_signature_suites' => ['ed25519'],
            'pca_versions' => [2], 'pca' => ['audience' => 'http://rs.example']];
        $this->throws(fn() => Oauth::parseProtectedResourceMetadata(5), "{$p}not an object");
        $this->throws(fn() => Oauth::parseProtectedResourceMetadata(['pca_versions' => 'x'] + $base), "{$p}pca_versions must be a number[]");
        $this->throws(fn() => Oauth::parseProtectedResourceMetadata(['pca' => 5] + $base), "{$p}missing embedded `pca` discovery document");
        $this->throws(fn() => Oauth::parseProtectedResourceMetadata($base, ['expectedResource' => 'http://rs.example']), "{$p}resource identifier must use the https scheme");
        $this->assertSame('http://rs.example', Oauth::parseProtectedResourceMetadata($base, ['strict' => false])->get('resource'));
    }

    /** Non-string scope and pcaChallenge values are String()-ed. */
    public function testWwwAuthenticateNonStrings(): void
    {
        $this->assertStringContainsString(', scope="5", ', Oauth::wwwAuthenticate('https://u', ['scope' => 5]));
        $this->assertSame('Bearer resource_metadata="https://u", 5', Oauth::wwwAuthenticate('https://u', ['pcaChallenge' => 5]));
    }

    /** encodePcaNeed is public; an encoding of exactly 2048 characters is allowed, one more is refused. */
    public function testEncodePcaNeedLimit(): void
    {
        $need = static function (int $last): Obj {
            $sc = [...array_fill(0, 6, str_repeat('a', 128)), str_repeat('b', $last)];
            return Obj::of(['v' => new Num('1'), 'kind' => 'scope', 'verb' => str_repeat('v', 128), 'resource' => str_repeat('r', 512), 'scopes' => $sc]);
        };
        $this->assertSame(2048, strlen(Oauth::encodePcaNeed($need(50))));
        $this->throws(fn() => Oauth::encodePcaNeed($need(51)), 'encodePcaNeed: the need is too large for a header');
    }

    /** An array result keeps its members and an array of options keeps its error when the existing challenge is carried over. */
    public function testUpgradeArrayResult(): void
    {
        $r = Oauth::upgradeUnauthorizedChallenge(['status' => 401, 'wwwAuthenticate' => 'PCA realm="x"'], 'https://u', ['error' => 'invalid_token']);
        $this->assertSame(['status' => 401, 'wwwAuthenticate' => 'Bearer resource_metadata="https://u", error="invalid_token", PCA realm="x"'], $r);
    }

    /** Grant detail and grant token gates refuse missing chain ids / resource with their own message. */
    public function testGrantRefusals(): void
    {
        $this->throws(fn() => Oauth::buildPcaGrantDetail(['chainIds' => 'x']), 'buildPcaGrantDetail: chainIds must be a string[]');
        $m = 'authorizePcaGrantToken: resource and chainIds are required';
        $this->throws(fn() => Oauth::authorizePcaGrantToken(['authorizationDetails' => [], 'resource' => 5, 'chainIds' => ['a']]), $m);
        $this->throws(fn() => Oauth::authorizePcaGrantToken(['authorizationDetails' => []]), $m);
    }

    /** deriveActionScopes is public; a non-list scopes_min is no_scopes; a 256-character scope token is allowed. */
    public function testDeriveActionScopes(): void
    {
        $a = static fn(mixed $min): array => ['confirmed' => true, 'upstream' => ['scopes_min' => $min]];
        $this->assertSame(['ok' => false, 'code' => 'no_scopes'], Oauth::deriveActionScopes($a('x')));
        $s = str_repeat('a', 256);
        $this->assertSame(['ok' => true, 'scopes' => [$s], 'provider' => null, 'def_digest' => null], Oauth::deriveActionScopes($a([$s])));
        $this->assertSame(['ok' => false, 'code' => 'bad_scope'], Oauth::deriveActionScopes($a([$s . 'a'])));
    }
}
