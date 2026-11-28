<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MemoryAgentStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Scim;
use PHPUnit\Framework\TestCase;

/** Group 28 survivors in Scim: toISOString edges, the default clock, the /Agents handler (list paging, filters, PATCH, PUT, auth), push and the store. */
final class MixSurvivorKill28ScimTest extends TestCase
{
    protected function tearDown(): void
    {
        Scim::$clockHook = null;
    }

    private static function refuses(string $class, string $msg, callable $f): void
    {
        try {
            $f();
            self::fail("expected $class");
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [get_class($e), $e->getMessage()]);
        }
    }

    /** toISOString: the +-8.64e15 bounds, truncation towards zero, negative milliseconds, and the 4-digit / 6-digit signed year forms. */
    public function testIsoAt(): void
    {
        self::assertSame('+275760-09-13T00:00:00.000Z', Scim::isoAt(8.64e15));
        self::assertSame('-271821-04-20T00:00:00.000Z', Scim::isoAt(-8.64e15));
        foreach ([8640000000000001, NAN, 'x'] as $bad) {
            self::refuses(\RangeException::class, 'Invalid time value', static fn() => Scim::isoAt($bad));
        }
        self::assertSame('1969-12-31T23:59:59.999Z', Scim::isoAt(-1.5));
        self::assertSame('1969-12-31T23:59:59.001Z', Scim::isoAt(-999));
        self::assertSame('1969-12-31T23:59:59.000Z', Scim::isoAt(-1000));
        self::assertSame('0000-01-01T00:00:00.000Z', Scim::isoAt(-62167219200000));
        self::assertSame('+010000-01-01T00:00:00.000Z', Scim::isoAt(253402300800000));
    }

    private static function handler(?MemoryAgentStore $store = null, array $opts = ['allowUnauthenticated' => true, 'now' => null]): \Closure
    {
        $opts['now'] ??= static fn(): int => 1800000000000;
        return Scim::scimHandler($store ?? new MemoryAgentStore(), $opts);
    }

    private static function create(\Closure $h, string $model, string $name, bool $active = true): string
    {
        $r = $h(['method' => 'POST', 'body' => Obj::of(['schemas' => [Scim::AGENT_SCHEMA_URN], 'model' => $model, 'operator' => 'acme',
            'displayName' => $name, 'active' => $active])]);
        self::assertSame(201, $r->get('status'));
        return $r->get('body')->get('id');
    }

    /** @return list<string> display names of a list response */
    private static function names(Obj $r): array
    {
        self::assertSame(200, $r->get('status'));
        return array_map(static fn(Obj $a): string => $a->get('displayName'), $r->get('body')->get('Resources'));
    }

    /** Without a `now` option the meta times are the wall clock in whole milliseconds, rounded down. */
    public function testMetaUsesTheWallClock(): void
    {
        Scim::$clockHook = static fn(): float => 1800000000.0007;
        $h = Scim::scimHandler(new MemoryAgentStore(), ['allowUnauthenticated' => true]);
        $r = $h(['method' => 'POST', 'body' => Obj::of(['model' => 'm', 'operator' => 'acme'])]);
        self::assertSame(['2027-01-15T08:00:00.000Z', '2027-01-15T08:00:00.000Z'],
            [$r->get('body')->get('meta')->get('created'), $r->get('body')->get('meta')->get('lastModified')]);
    }

    /** List paging: startIndex/count as Number() of the query value (null is 0, true 1, false 0), and the startIndex echoed as an integer. */
    public function testListPaging(): void
    {
        $h = self::handler();
        foreach (['A', 'B', 'C'] as $n) {
            self::create($h, "m$n", $n);
        }
        $list = static fn(mixed $q): Obj => $h(['method' => 'GET', 'query' => $q]);
        self::assertSame(['B'], self::names($list(['startIndex' => 2, 'count' => 1])));
        self::assertSame([], self::names($list(['count' => null])));
        self::assertSame(['A'], self::names($list(['count' => true])));
        self::assertSame([], self::names($list(['count' => false])));
        self::assertSame(1, $list(['count' => 3])->get('body')->get('startIndex'));
        $far = $list(['startIndex' => 9007199254740992]);
        self::assertSame([9007199254740992, []], [$far->get('body')->get('startIndex'), $far->get('body')->get('Resources')]);
        self::assertSame(['A', 'B', 'C'], self::names($list([])));
        self::assertSame(400, $list(['x'])->get('status'));
    }

    /** Filters by displayName and userName read the display name; a filter in an object query is applied. */
    public function testFilters(): void
    {
        $h = self::handler();
        self::create($h, 'm1', 'A');
        self::create($h, 'm2', 'B');
        foreach (['displayName', 'userName'] as $attr) {
            self::assertSame(['B'], self::names($h(['method' => 'GET', 'query' => ['filter' => "$attr eq \"B\""]])));
        }
    }

    /** PATCH keeps an inactive agent inactive when another attribute changes; removing `active` makes it active again. */
    public function testPatchActive(): void
    {
        $h = self::handler();
        $id = self::create($h, 'm1', 'A', false);
        $patch = static fn(array $op): Obj => $h(['method' => 'PATCH', 'id' => $id, 'body' => Obj::of(['Operations' => [Obj::of($op)]])]);
        $r = $patch(['op' => 'replace', 'path' => 'displayName', 'value' => 'Z']);
        self::assertSame(['Z', false], [$r->get('body')->get('displayName'), $r->get('body')->get('active')]);
        self::assertTrue($patch(['op' => 'remove', 'path' => 'active'])->get('body')->get('active'));
    }

    /** PUT stores the replacement. */
    public function testPutPersists(): void
    {
        $h = self::handler();
        $id = self::create($h, 'm1', 'A');
        self::assertSame(200, $h(['method' => 'PUT', 'id' => $id, 'body' => Obj::of(['displayName' => 'P'])])->get('status'));
        self::assertSame('P', $h(['method' => 'GET', 'id' => $id])->get('body')->get('displayName'));
    }

    /** Without an owner, the body's operator is the owner before the nested passport's operator. */
    public function testOwnerFallbackOrder(): void
    {
        $req = Scim::scimToProvisioningRequest(Obj::of(['operator' => 'opA', 'passport' => Obj::of(['model_id' => 'm', 'operator' => 'opB'])]));
        self::assertSame('opA', $req->get('projection')->get('owner'));
    }

    /** `authenticate` must be a callable object: a string callable or a plain object is refused; an invokable object is used. */
    public function testAuthenticateMustBeACallableObject(): void
    {
        $msg = 'scimHandler: `authenticate` is required (or pass allowUnauthenticated: true explicitly)';
        foreach (['strlen', new \stdClass()] as $bad) {
            self::refuses(\TypeError::class, $msg, static fn() => Scim::scimHandler(new MemoryAgentStore(), ['authenticate' => $bad]));
        }
        $calls = new \ArrayObject();
        $auth = new class ($calls) {
            public function __construct(private \ArrayObject $calls)
            {
            }

            public function __invoke(mixed $req): bool
            {
                $this->calls->append($req);
                return true;
            }
        };
        $h = Scim::scimHandler(new MemoryAgentStore(), ['authenticate' => $auth]);
        self::assertSame(200, $h(['method' => 'GET'])->get('status'));
        self::assertCount(1, $calls);
    }

    /** pushProvision needs a non-string callable fetch, and reports `ok` as a boolean. */
    public function testPushProvision(): void
    {
        foreach ([null, 'strlen'] as $f) {
            self::refuses(\InvalidArgumentException::class, 'pushProvision: no fetch available — pass one explicitly',
                static fn() => Scim::pushProvision(new Obj(), ['fetch' => $f, 'endpoint' => 'https://x', 'token' => 't']));
        }
        $fetch = static fn(string $url, array $init): array => ['ok' => 1, 'status' => 201, 'json' => static fn(): array => []];
        self::assertTrue(Scim::pushProvision(new Obj(), ['fetch' => $fetch, 'endpoint' => 'https://x', 'token' => 't'])->get('ok'));
    }

    /** A seeded store holds its seed, and its registry is built from the passports. */
    public function testMemoryStoreSeedAndRegistry(): void
    {
        $a = new MemoryAgentStore();
        $id = self::create(self::handler($a), 'm1', 'A');
        $b = new MemoryAgentStore($a->all());
        self::assertSame($a->all(), $b->all());
        self::assertSame($a->get($id)['passport'], $b->registry()->get($id));
    }
}
