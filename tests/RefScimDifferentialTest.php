<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MemoryAgentStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Scim;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * SCIM 2.0 /Agents against the TS reference: test-data/ref-scim.json.gz. A scimSession case names an options table entry
 * (kept identical to the generator's), runs some setup requests and records the responses of the rest. Push cases name a
 * fake fetch and record its calls.
 */
final class RefScimDifferentialTest extends TestCase
{
    private const FILE = 'ref-scim.json.gz';
    private const T0 = 1_700_000_000_000;

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function opts(string $name): array
    {
        $tick = 0;
        return match ($name) {
            'open' => ['baseUrl' => 'https://scim.acme.com/scim/v2', 'now' => fn() => self::T0, 'authenticate' => fn() => true],
            'slash' => ['baseUrl' => 'https://scim.acme.com/scim/v2///', 'now' => fn() => self::T0, 'authenticate' => fn() => true],
            'nobase' => ['now' => fn() => self::T0, 'allowUnauthenticated' => true],
            'tick' => ['baseUrl' => 'https://x.example', 'now' => function () use (&$tick) {
                return self::T0 + 1000 * $tick++;
            }, 'authenticate' => fn() => true],
            'deny' => ['now' => fn() => self::T0, 'authenticate' => fn() => false],
            'throwauth' => ['now' => fn() => self::T0, 'authenticate' => function () {
                throw new \RuntimeException('x');
            }],
            'truthy' => ['now' => fn() => self::T0, 'authenticate' => fn() => 'yes'],
            'noauth' => ['now' => fn() => self::T0],
            'notfn' => ['now' => fn() => self::T0, 'authenticate' => 'yes'],
        };
    }

    private static function session(string $opts, array $setup, array $reqs): array
    {
        $h = Scim::scimHandler(new MemoryAgentStore(), self::opts($opts));
        foreach ($setup as $r) {
            $h($r);
        }
        return array_map($h, $reqs);
    }

    private static function fetch(string $mode, array &$calls): \Closure
    {
        [$ok, $status, $json] = match ($mode) {
            'ok201' => [true, 201, fn() => Obj::of(['id' => 'obj-1'])],
            'err500' => [false, 500, fn() => Obj::of(['detail' => 'x'])],
            'badjson' => [true, 204, function () {
                throw new \RuntimeException('no body');
            }],
            'nullbody' => [true, 200, fn() => null],
        };
        return function (string $url, array $init) use (&$calls, $ok, $status, $json): array {
            $calls[] = ['url' => $url, 'init' => $init];
            return ['ok' => $ok, 'status' => $status, 'json' => $json];
        };
    }

    private static function push(string $fn, Obj $agent, string $mode, string $endpoint = 'https://dir.example/scim/Agents', string $token = 'TOK'): array
    {
        $calls = [];
        $target = ['endpoint' => $endpoint, 'token' => $token, 'fetch' => self::fetch($mode, $calls)];
        $result = match ($fn) {
            'pushToEntra' => Scim::pushToEntra($agent, $target),
            'pushToOkta' => Scim::pushToOkta($agent, $target),
            'pushProvision' => Scim::pushProvision(Scim::toEntraAgentPayload($agent), $target),
        };
        return ['result' => $result, 'calls' => $calls];
    }

    private static function registry(array $ps, string $id): array
    {
        $r = Scim::buildRegistry($ps);
        return ['all' => $r->all(), 'has' => $r->has($id), 'get' => $r->get($id)];
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'scimSession' => fn(array $a) => self::session($a[0], $a[1], $a[2]),
            'issuePassport' => fn(array $a) => Scim::issuePassport($a[0]),
            'passportFingerprint' => fn(array $a) => Scim::passportFingerprint($a[0]),
            'passportToScim' => fn(array $a, Obj $c) => str_starts_with((string)$c->get('name'), 'passportToScim/now')
                ? Scim::passportToScim($a[0], $a[1], ['now' => fn() => $a[2]])
                : Scim::passportToScim($a[0], $a[1], $a[2]),
            'scimToProvisioningRequest' => fn(array $a) => Scim::scimToProvisioningRequest($a[0]),
            'parseFilter' => fn(array $a) => Scim::parseFilter($a[0]),
            'scimError' => function (array $a) {
                $r = Scim::scimError($a[0], $a[1], $a[2] ?? null);
                if (array_key_exists(2, $a) && $a[2] === null) {
                    $r->set('scimType', null); // the oracle turns an undefined argument into null on both sides
                }
                return $r;
            },
            'scimListResponse' => fn(array $a) => Scim::scimListResponse($a[0], $a[1], $a[2]),
            'registry' => fn(array $a) => self::registry($a[0], $a[1]),
            'toEntraAgentPayload' => fn(array $a) => Scim::toEntraAgentPayload($a[0]),
            'toOktaScimPayload' => fn(array $a) => Scim::toOktaScimPayload($a[0]),
            'pushToEntra' => fn(array $a) => self::push('pushToEntra', $a[1], $a[2]),
            'pushToOkta' => fn(array $a) => self::push('pushToOkta', $a[1], $a[2]),
            'pushProvision' => fn(array $a) => self::push('pushProvision', $a[0], $a[1], 'e', 't'),
        ]);
    }
}
