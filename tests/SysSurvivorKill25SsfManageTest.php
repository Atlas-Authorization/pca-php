<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MemoryStreamStore;
use Atlas\Pca\Obj;
use Atlas\Pca\SsfManage;
use Atlas\Pca\SsfManagementApi;
use Atlas\Pca\SsfStream;
use Atlas\Pca\StreamRecord;
use Atlas\Pca\StreamStore;
use PHPUnit\Framework\TestCase;

/** Group 25 kills for src/SsfManage.php: copies, limits and ids, events_delivered, the UTF-16 description cut, routing and update gates. */
final class SysSurvivorKill25SsfManageTest extends TestCase
{
    private const A = 'urn:example:event:a';
    private const B = 'urn:example:event:b';

    /** @param array<string,mixed> $over */
    private static function handler(array $over = [], ?StreamStore $store = null): \Closure
    {
        $n = 0;
        $o = [
            'store' => $store ?? new MemoryStreamStore(), 'issuer' => 'https://tx.example', 'eventsSupported' => [self::A, self::B],
            'pollEndpoint' => static fn(string $id): string => "https://tx.example/poll/$id",
            'now' => static fn(): int => 1000, 'deliver' => static function ($s, $set): void {
            },
            'newId' => static function () use (&$n): string {
                return 's' . (++$n);
            },
            'maxStreamsPerReceiver' => 20,
        ];
        foreach ($over as $k => $v) {
            if ($v === null) {
                unset($o[$k]);
            } else {
                $o[$k] = $v;
            }
        }
        return SsfManage::ssfManagementHandler($o, static fn($req) => Obj::of(['id' => 'rx1', 'aud' => 'rx']));
    }

    private static function call(\Closure $h, string $method, string $seg, ?Obj $body = null): array
    {
        return $h(['method' => $method, 'path' => "/ssf/$seg", 'query' => [], 'body' => $body]);
    }

    private static function description(string $d): mixed
    {
        $r = self::call(self::handler(), 'POST', 'configuration', Obj::of(['description' => $d]));
        self::assertSame(201, $r['status']);
        return $r['body']->get('description');
    }

    /** A record keeps the subjects it was built with; only a missing set starts empty. */
    public function testStreamRecordKeepsItsSubjects(): void
    {
        $r = new StreamRecord('rx1', new Obj(), subjects: Obj::of(['k' => true]));
        $this->assertSame(['k'], $r->subjects->keys());
        $this->assertSame([], (new StreamRecord('rx1', new Obj()))->subjects->keys());
    }

    /** deepCopy copies objects, nested and inside lists: changing the copy never changes the original. */
    public function testDeepCopyIsDeep(): void
    {
        $o = Obj::of(['a' => Obj::of(['b' => 1])]);
        $c = SsfManage::deepCopy($o);
        $this->assertNotSame($o, $c);
        $c->get('a')->set('b', 2);
        $this->assertSame(1, $o->get('a')->get('b'));
        $list = [Obj::of(['x' => 1])];
        $cl = SsfManage::deepCopy($list);
        $cl[0]->set('x', 2);
        $this->assertSame(1, $list[0]->get('x'));
    }

    /** The documented defaults: one stream per receiver, 10000 subjects per stream. */
    public function testDefaultLimits(): void
    {
        $api = new SsfManagementApi(['store' => new MemoryStreamStore()]);
        $this->assertSame(1.0, (new \ReflectionProperty(SsfManagementApi::class, 'maxStreams'))->getValue($api));
        $this->assertSame(10000.0, (new \ReflectionProperty(SsfManagementApi::class, 'maxSubjects'))->getValue($api));
    }

    /** A limit that is not a number admits nothing: no stream is created, no subject is added (fail closed). */
    public function testNonNumericLimitsAdmitNothing(): void
    {
        $this->assertSame(409, self::call(self::handler(['maxStreamsPerReceiver' => 'many']), 'POST', 'configuration', new Obj())['status']);
        $h = self::handler(['maxSubjectsPerStream' => 'many']);
        $this->assertSame(201, self::call($h, 'POST', 'configuration', new Obj())['status']);
        $r = self::call($h, 'POST', 'add_subject', Obj::of(['stream_id' => 's1', 'subject' => Obj::of(['format' => 'email', 'email' => 'a@example.com'])]));
        $this->assertSame(429, $r['status']);
    }

    /** Default stream ids are 16 base64url characters (12 random bytes). */
    public function testDefaultStreamId(): void
    {
        $r = self::call(self::handler(['newId' => null]), 'POST', 'configuration', new Obj());
        $this->assertSame(201, $r['status']);
        $this->assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{16}\z/', $r['body']->get('stream_id'));
    }

    /** events_supported and events_delivered are lists even when the configured or filtered arrays are not. */
    public function testEventListsAreLists(): void
    {
        $h = self::handler(['eventsSupported' => [1 => self::A, 2 => self::B]]);
        $r = self::call($h, 'POST', 'configuration', Obj::of(['events_requested' => [self::B]]));
        $this->assertSame(201, $r['status']);
        $this->assertSame([self::A, self::B], $r['body']->get('events_supported'));
        $this->assertSame([self::B], $r['body']->get('events_delivered'));
    }

    /** The description is cut at 256 UTF-16 units; a cut surrogate pair leaves its high surrogate (CESU-8 bytes), as JS slice does. */
    public function testDescriptionCutAtUtf16Units(): void
    {
        $a255 = str_repeat('a', 255);
        $this->assertSame($a255 . "\xED\xA0\xBD", self::description($a255 . "\u{1F600}b"));
        $this->assertSame($a255 . "\xED\xA0\x80", self::description($a255 . "\u{103FF}b"));
        $this->assertSame($a255 . "\xED\xA0\x81", self::description($a255 . "\u{10400}"));
        $this->assertSame($a255 . "\xED\xA1\x80", self::description($a255 . "\u{20000}"));
        $this->assertSame(str_repeat('a', 256), self::description(str_repeat('a', 256) . "\u{1F600}"));
        $this->assertSame($a255 . 'é', self::description($a255 . 'éé'));
        // control: exactly 256 units is kept whole
        $this->assertSame(str_repeat('a', 254) . "\u{1F600}", self::description(str_repeat('a', 254) . "\u{1F600}"));
    }

    /** A description that is not UTF-8 is cut by bytes when it is longer than 256 units, and kept whole at exactly 256. */
    public function testInvalidUtf8Description(): void
    {
        $this->assertSame("\xC1" . str_repeat("\xC0", 255), self::description("\xC1" . str_repeat("\xC0", 299)));
        $this->assertSame(str_repeat("\xC0\x80", 256), self::description(str_repeat("\xC0\x80", 256)));
    }

    /** A subject must be an object: an array with a format is refused as a bad request, not a server error. */
    public function testSubjectMustBeAnObject(): void
    {
        $h = self::handler();
        self::call($h, 'POST', 'configuration', new Obj());
        $r = self::call($h, 'POST', 'add_subject', Obj::of(['stream_id' => 's1', 'subject' => ['format' => 'email', 'email' => 'a@example.com']]));
        $this->assertSame(['status' => 400, 'body' => ['error' => 'invalid_request', 'description' => 'subject must be a Subject Identifier object with a format']], $r);
    }

    /** A request whose path or method is not a string fails with the reference's TypeError text. */
    public function testRouteTypeErrors(): void
    {
        $api = new SsfManagementApi(['store' => new MemoryStreamStore()]);
        $rcv = Obj::of(['id' => 'rx1', 'aud' => 'rx']);
        foreach ([[['path' => 5, 'method' => 'GET'], 'req.path.split is not a function'], [['path' => '/ssf/status', 'method' => 5], 'req.method.toUpperCase is not a function']] as [$req, $msg]) {
            try {
                $api->route($req, $rcv);
                $this->fail('expected a TypeError');
            } catch (\TypeError $e) {
                $this->assertSame($msg, $e->getMessage());
            }
        }
    }

    /** The method is upper-cased with Unicode rules, as JS toUpperCase: "poſt" is POST. */
    public function testMethodIsUnicodeUppercased(): void
    {
        $r = self::call(self::handler(), "po\u{017F}t", 'status');
        $this->assertSame(['status' => 400, 'body' => ['error' => 'invalid_request', 'description' => 'stream_id is required']], $r);
    }

    /** PATCH without a delivery keeps the stream's push delivery. */
    public function testPatchKeepsPushDelivery(): void
    {
        $h = self::handler();
        $c = self::call($h, 'POST', 'configuration', Obj::of(['delivery' => Obj::of(['method' => SsfStream::DELIVERY_PUSH, 'endpoint_url' => 'https://rx.example/push'])]));
        $this->assertSame(201, $c['status']);
        $r = self::call($h, 'PATCH', 'configuration', Obj::of(['stream_id' => 's1', 'description' => 'd']));
        $this->assertSame(200, $r['status']);
        $this->assertSame(SsfStream::DELIVERY_PUSH, $r['body']->get('delivery')->get('method'));
        $this->assertSame('d', $r['body']->get('description'));
    }

    private static function fixedStore(Obj $config): StreamStore
    {
        return new class (new StreamRecord('rx1', $config)) implements StreamStore {
            public function __construct(private StreamRecord $r)
            {
            }

            public function get(string $id): ?StreamRecord
            {
                return $this->r->copy();
            }

            public function put(string $id, StreamRecord $r): void
            {
            }

            public function delete(string $id): void
            {
            }

            public function listByReceiver(mixed $receiver): array
            {
                return [];
            }
        };
    }

    private static function config(string $id, array $extra = []): Obj
    {
        return Obj::of(['stream_id' => $id, 'iss' => 'https://tx.example', 'aud' => 'rx', 'events_supported' => [self::A, self::B], 'events_delivered' => [self::A, self::B],
            'delivery' => Obj::of(['method' => SsfStream::DELIVERY_POLL, 'endpoint_url' => "https://tx.example/poll/$id"])] + $extra);
    }

    /** A body stream_id that differs from the stored record's own stream_id is refused like any other transmitter-supplied member. */
    public function testStreamIdIsATransmitterSuppliedMember(): void
    {
        $h = self::handler([], self::fixedStore(self::config('other')));
        $r = self::call($h, 'PATCH', 'configuration', Obj::of(['stream_id' => 'x']));
        $this->assertSame(['status' => 400, 'body' => ['error' => 'invalid_request', 'description' => "'stream_id' is transmitter-supplied and does not match"]], $r);
    }

    /** An update keeps the stream's min_verification_interval. */
    public function testUpdateKeepsMinVerificationInterval(): void
    {
        $h = self::handler([], self::fixedStore(self::config('x', ['min_verification_interval' => 30])));
        $r = self::call($h, 'PATCH', 'configuration', Obj::of(['stream_id' => 'x', 'description' => 'd']));
        $this->assertSame(200, $r['status']);
        $this->assertSame(30, $r['body']->get('min_verification_interval'));
    }
}
