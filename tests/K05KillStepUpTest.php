<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/StepUp.php';

use Atlas\Pca\MemorySecretStore;
use Atlas\Pca\PendingStepUp;
use Atlas\Pca\PrincipalDeviceKey;
use Atlas\Pca\StepUpClient;
use Atlas\Pca\StepUpException;
use PHPUnit\Framework\TestCase;

/**
 * A user stream wrapper the default transport (StepUpClient::streamHttp) runs against: it records the stream context options and
 * open flags, serves a canned body, and exposes canned header lines as public properties. For a user wrapper,
 * stream_get_meta_data()['wrapper_data'] is the wrapper object itself, and foreach over it yields its public properties in
 * declaration order: $context (a resource, not a string), then $l0..$l2.
 */
final class K05SuStreamWrapper
{
    /** @var resource|null set by PHP */
    public $context;
    public $l0 = null;
    public $l1 = null;
    public $l2 = null;

    /** @var list<?string> */
    public static array $lines = [];
    public static string $body = '';
    public static mixed $opts = null;
    public static ?int $openOptions = null;
    public static ?string $path = null;
    private int $pos = 0;

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        self::$path = $path;
        self::$openOptions = $options;
        self::$opts = stream_context_get_options($this->context);
        if (parse_url($path, PHP_URL_HOST) === 'down.example') {
            return false;
        }
        [$this->l0, $this->l1, $this->l2] = self::$lines + [null, null, null];
        return true;
    }

    public function stream_read(int $count): string
    {
        $chunk = (string)substr(self::$body, $this->pos, $count);
        $this->pos += strlen($chunk);
        return $chunk;
    }

    public function stream_eof(): bool
    {
        return $this->pos >= strlen(self::$body);
    }

    public function stream_stat(): array
    {
        return [];
    }

    public function stream_set_option($option, $arg1, $arg2): bool
    {
        return false;
    }

    public function stream_close(): void
    {
    }
}

/**
 * k05 mutation kills for StepUp.php: exception defaults, the seed-length check, constructor validation (schemes, ids, trailing
 * slashes, the clock), validId bounds, the default stream transport (context options, open flags, status-line parse, unreachable
 * host), call() (headers, transport errors, the body cast and 1 MiB cut, the 2xx range), bearer(), pending() (list/entry checks,
 * expiry boundary, continue, defaults) and approve() result folding.
 */
final class K05KillStepUpTest extends TestCase
{
    private const NOW = 1_800_000_000_000;
    private const MAX_BODY = 1048576;

    private static function client(callable $http, ?callable $token = null, string $dash = 'https://dash.example', string $inst = 'https://inst.example',
                                   ?PrincipalDeviceKey $key = null, string $acc = 'acc', string $ins = 'ins'): StepUpClient
    {
        if ($key === null) {
            $key = new PrincipalDeviceKey(new MemorySecretStore());
            $key->generate();
        }
        return new StepUpClient($dash, $inst, $acc, $ins, $key, $token ?? (fn () => 'dsk_x'), $http, fn () => self::NOW);
    }

    private static function iso(int $ms): string
    {
        return gmdate('Y-m-d\TH:i:s', intdiv($ms, 1000)) . sprintf('.%03dZ', $ms % 1000);
    }

    private static function su(string $id = 's'): PendingStepUp
    {
        return new PendingStepUp($id, 'g', 'v', 'r', 1, 'AAEC', 1);
    }

    private static function validId(string $id): bool
    {
        return (new \ReflectionMethod(StepUpClient::class, 'validId'))->invoke(null, $id);
    }

    /** @return array{0:mixed,1:mixed} */
    private static function stream(string $method, string $url, array $headers, ?string $body): array
    {
        if (!in_array('k05su', stream_get_wrappers(), true)) {
            stream_wrapper_register('k05su', K05SuStreamWrapper::class);
        }
        try {
            return (new \ReflectionMethod(StepUpClient::class, 'streamHttp'))->invoke(null, $method, $url, $headers, $body);
        } finally {
            stream_wrapper_unregister('k05su');
        }
    }

    private function thrown(callable $f): \Throwable
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return $e;
        }
        $this->fail('nothing thrown');
    }

    /** status/code defaults (69/71): public readonly status 0, exception code 0. */
    public function testExceptionDefaults(): void
    {
        $e = new StepUpException(StepUpException::TRANSPORT, 'm');
        $this->assertSame([0, 0, 'm', null], [$e->status, $e->getCode(), $e->getMessage(), $e->getPrevious()]);
        $a = new StepUpException(StepUpException::API, 'x', 409);
        $this->assertSame([409, 0, 'HTTP 409: x'], [$a->status, $a->getCode(), $a->getMessage()]);
    }

    /** 121: a stored seed of the wrong length is refused on every read. */
    public function testWrongLengthSeedRefused(): void
    {
        $store = new MemorySecretStore();
        $store->save(str_repeat("\x01", 16));
        $k = new PrincipalDeviceKey($store);
        foreach ([fn () => $k->exportSecret(), fn () => $k->publicKey(), fn () => $k->sign('m')] as $f) {
            $e = $this->thrown($f);
            $this->assertInstanceOf(StepUpException::class, $e);
            $this->assertSame([StepUpException::INVALID_SECRET, 'The principal secret must be a base64url-encoded 32-byte Ed25519 seed.'], [$e->kind, $e->getMessage()]);
        }
    }

    /** 204 (http accepted), 211/212 (trailing slashes trimmed). */
    public function testHttpSchemeAndTrailingSlashes(): void
    {
        $urls = [];
        $c = self::client(function (string $m, string $url) use (&$urls): array {
            $urls[] = $url;
            return [200, str_contains($url, '/cosign') ? '{}' : '{"stepups":[]}'];
        }, null, 'http://dash.example//', 'http://inst.example/');
        $this->assertSame([], $c->pending());
        $c->approve(self::su());
        $this->assertSame(['http://dash.example/v1/dashboard/accounts/acc/instances/ins/pca/stepups?status=pending',
            'http://inst.example/v1/pca/stepups/s/cosign'], $urls);
    }

    /** 208/209: either id invalid is refused with the exact message. */
    public function testConstructorRefusesInvalidIds(): void
    {
        $http = fn () => [200, '{}'];
        foreach ([['a/b', 'ok'], ['ok', '..']] as [$acc, $ins]) {
            $e = $this->thrown(fn () => self::client($http, null, 'https://d.example', 'https://i.example', null, $acc, $ins));
            $this->assertSame([\InvalidArgumentException::class, 'StepUpClient needs a valid accountId and instanceId'], [$e::class, $e->getMessage()]);
        }
        $e = $this->thrown(fn () => self::client($http, null, 'https://d.example', 'ftp://i.example'));
        $this->assertSame([\InvalidArgumentException::class, 'StepUpClient: instanceUrl must be an http(s) URL'], [$e::class, $e->getMessage()]);
        $e = $this->thrown(fn () => self::client($http, null, 'http:///nohost', 'https://i.example'));
        $this->assertSame([\InvalidArgumentException::class, 'StepUpClient: dashboardUrl must be an http(s) URL'], [$e::class, $e->getMessage()]);
    }

    /** 215: the injected clock is used as is; the default is wall-clock epoch ms as an int. */
    public function testClock(): void
    {
        $p = new \ReflectionProperty(StepUpClient::class, 'now');
        $this->assertSame(self::NOW, ($p->getValue(self::client(fn () => [200, '{}'])))());
        $k = new PrincipalDeviceKey(new MemorySecretStore());
        $k->generate();
        $clock = $p->getValue(new StepUpClient('https://d.example', 'https://i.example', 'a', 'b', $k, fn () => 't', fn () => [200, '{}']));
        $lo = (int)(microtime(true) * 1000);
        $v = $clock();
        $hi = (int)(microtime(true) * 1000);
        $this->assertIsInt($v);
        $this->assertTrue($lo <= $v && $v <= $hi, "$lo <= $v <= $hi");
    }

    /** 221: '', '.', '..' refused; 200 chars allowed, 201 refused; a trailing newline never passes (\z). */
    public function testValidId(): void
    {
        $cases = ['' => false, '.' => false, '..' => false, '...' => true, 'a.b' => true, 'A-z_9' => true, 'a b' => false, "a\n" => false,
            str_repeat('a', 200) => true, str_repeat('a', 201) => false];
        foreach ($cases as $id => $want) {
            $this->assertSame($want, self::validId((string)$id), var_export($id, true));
        }
    }

    /** 228-246: the context options, open flags, the last status line wins, the body is returned. */
    public function testStreamTransportPost(): void
    {
        K05SuStreamWrapper::$lines = ['HTTP/1.1 100 Continue', 'X-A: b', 'HTTP/1.0 201 Created'];
        K05SuStreamWrapper::$body = 'hello';
        $r = self::stream('POST', 'k05su://ok.example/p?q=1', ['Authorization' => 'Bearer t', 'Content-Type' => 'application/json'], '{"a":1}');
        $this->assertSame([201, 'hello'], $r);
        $this->assertSame('k05su://ok.example/p?q=1', K05SuStreamWrapper::$path);
        $this->assertSame(0, K05SuStreamWrapper::$openOptions & STREAM_USE_PATH);
        $this->assertSame(['http' => ['method' => 'POST', 'header' => "Authorization: Bearer t\r\nContent-Type: application/json", 'content' => '{"a":1}',
            'timeout' => 30, 'ignore_errors' => true, 'follow_location' => 0]], K05SuStreamWrapper::$opts);
    }

    /** 240: no status line leaves status 0; a null body sends empty content. */
    public function testStreamTransportNoStatusLine(): void
    {
        K05SuStreamWrapper::$lines = [null, 'X-A: b', null];
        K05SuStreamWrapper::$body = '';
        $this->assertSame([0, ''], self::stream('GET', 'k05su://ok.example/', [], null));
        $this->assertSame(['http' => ['method' => 'GET', 'header' => '', 'content' => '', 'timeout' => 30, 'ignore_errors' => true, 'follow_location' => 0]],
            K05SuStreamWrapper::$opts);
    }

    /** 234/235: an unreachable host is a RuntimeException naming the host. */
    public function testStreamTransportUnreachable(): void
    {
        $e = $this->thrown(fn () => self::stream('GET', 'k05su://down.example/x', [], null));
        $this->assertSame([\RuntimeException::class, 'could not reach down.example'], [$e::class, $e->getMessage()]);
    }

    /** 261 (Content-Type only with a body), 285 (token cast to string). */
    public function testHeaders(): void
    {
        $seen = [];
        $http = function (string $m, string $url, array $h, ?string $b) use (&$seen): array {
            $seen[] = [$h, $b];
            return [200, str_contains($url, '/stepups?') ? '{"stepups":[]}' : '{}'];
        };
        $c = self::client($http, fn () => 123);
        $c->pending();
        $c->approve(self::su());
        $c->deny(self::su());
        $this->assertSame([['Authorization' => 'Bearer 123'], null], $seen[0]);
        $this->assertSame(['Content-Type' => 'application/json'], $seen[1][0]);
        $this->assertSame([['Authorization' => 'Bearer 123', 'Content-Type' => 'application/json'], '{}'], $seen[2]);
    }

    /** 267 (transport status 0), 287 (token failure: thrown, status 0, previous kept). */
    public function testTransportAndTokenFailures(): void
    {
        $boom = new \RuntimeException('boom');
        $e = $this->thrown(fn () => self::client(function () use ($boom): array {
            throw $boom;
        })->approve(self::su()));
        $this->assertInstanceOf(StepUpException::class, $e);
        $this->assertSame([StepUpException::TRANSPORT, 'boom', 0, 0, $boom], [$e->kind, $e->getMessage(), $e->status, $e->getCode(), $e->getPrevious()]);

        $tokErr = new \LogicException('no token');
        $sent = 0;
        $c = self::client(function () use (&$sent): array {
            $sent++;
            return [200, '{"stepups":[]}'];
        }, function () use ($tokErr): string {
            throw $tokErr;
        });
        foreach ([fn () => $c->pending(), fn () => $c->deny(self::su())] as $f) {
            $e = $this->thrown($f);
            $this->assertInstanceOf(StepUpException::class, $e);
            $this->assertSame([StepUpException::TRANSPORT, 'Could not get the dashboard token.', 0, 0, $tokErr],
                [$e->kind, $e->getMessage(), $e->status, $e->getCode(), $e->getPrevious()]);
        }
        $this->assertSame(0, $sent);
    }

    /** 269 (body cast, 1 MiB cut), 270 (299 is success), 346 (status/allow folding). */
    public function testApproveResults(): void
    {
        $cut = '{"status":"cut","allow":true}';
        $cut = str_pad($cut, self::MAX_BODY, ' ') . 'x';
        $cases = [
            [[200, '{"status":"pending"}'], ['pending', false, 200]],
            [[202, '{"status":"x","allow":false}'], ['x', false, 202]],
            [[200, '{"allow":true}'], ['', true, 200]],
            [[200, '"str"'], ['', false, 200]],
            [[299, '{"status":"s","allow":true}'], ['s', true, 299]],
            [[200, null], ['', false, 200]],
            [[200, $cut], ['cut', true, 200]],
        ];
        foreach ($cases as [$resp, $want]) {
            $r = self::client(fn () => $resp)->approve(self::su());
            $this->assertSame($want, [$r->status, $r->anchored, $r->httpStatus]);
        }
        $e = $this->thrown(fn () => self::client(fn () => [300, '{"errors":"boom"}'])->approve(self::su()));
        $this->assertSame([StepUpException::API, 300, 'HTTP 300: The request failed.'], [$e->kind, $e->status, $e->getMessage()]);
    }

    /** 299: an object without a stepups array is unreadable, never an empty list. */
    public function testUnreadableList(): void
    {
        foreach (['{}', '{"stepups":5}', '5'] as $body) {
            $e = $this->thrown(fn () => self::client(fn () => [200, $body])->pending());
            $this->assertInstanceOf(StepUpException::class, $e);
            $this->assertSame([StepUpException::TRANSPORT, 'Unreadable step-up list.', 0], [$e->kind, $e->getMessage(), $e->status]);
        }
    }

    /** 306/314/316: each malformed entry throws; a missing expires_at is read without a warning. */
    public function testUnreadableEntries(): void
    {
        $ok = ['id' => 'a', 'grant_ref' => 'g', 'threshold_message' => 'AA', 'expires_at' => self::iso(self::NOW + 60_000)];
        $bad = [
            ['expires_at' => 'not a date'],
            ['expires_at' => null],
            ['id' => ''],
            ['id' => 5],
            ['grant_ref' => ''],
            ['grant_ref' => null],
            ['threshold_message' => ''],
            ['threshold_message' => 7],
        ];
        $errs = [];
        set_error_handler(function (int $no, string $msg) use (&$errs): bool {
            $errs[] = $msg;
            return true;
        });
        try {
            foreach ($bad as $patch) {
                $entry = array_filter(array_replace($ok, $patch), fn ($v) => $v !== null);
                $e = $this->thrown(fn () => self::client(fn () => [200, json_encode(['stepups' => [$entry]])])->pending());
                $this->assertInstanceOf(StepUpException::class, $e, json_encode($patch));
                $this->assertSame([StepUpException::TRANSPORT, 'Unreadable step-up entry.'], [$e->kind, $e->getMessage()], json_encode($patch));
            }
        } finally {
            restore_error_handler();
        }
        $this->assertSame([], $errs);
    }

    /** 309 (ms), 318 (expiry == now dropped), 319 (continue), 323 (required_t default/value), 326 (all kept). */
    public function testPendingEntries(): void
    {
        $list = ['stepups' => [
            ['id' => 'now', 'grant_ref' => 'g', 'threshold_message' => 'AA', 'expires_at' => self::iso(self::NOW)],
            ['id' => 'a', 'grant_ref' => 'g1', 'threshold_message' => 'AQ', 'required_t' => 3, 'action' => ['verb' => 'pay', 'resource' => 'o/1'],
                'expires_at' => self::iso(self::NOW + 600_123)],
            ['id' => 'b', 'grant_ref' => 'g2', 'threshold_message' => 'Ag', 'expires_at' => self::iso(self::NOW + 1)],
        ]];
        $items = self::client(fn () => [200, json_encode($list)])->pending();
        $this->assertSame([
            ['a', 'g1', 'pay', 'o/1', 3, 'AQ', self::NOW + 600_123],
            ['b', 'g2', '', '', 0, 'Ag', self::NOW + 1],
        ], array_map(fn (PendingStepUp $p) => [$p->id, $p->grantRef, $p->actionVerb, $p->actionResource, $p->requiredT, $p->thresholdMessageB64u, $p->expiresAt], $items));
    }
}
