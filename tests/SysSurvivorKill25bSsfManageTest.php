<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SsfManage;
use Atlas\Pca\SsfStream;
use Atlas\Pca\StreamRecord;
use Atlas\Pca\StreamStore;
use PHPUnit\Framework\TestCase;

/** Group 25b kills for src/SsfManage.php: the verification route records the clock as the reference does and stores under the stream's own id. */
final class SysSurvivorKill25bSsfManageTest extends TestCase
{
    /** A clock that is not a number never rate-limits (NaN, as the reference's arithmetic); the record is stored under String(stream_id). */
    public function testVerificationRecordsTheClockAndTheStreamId(): void
    {
        $config = Obj::of(['stream_id' => 7, 'iss' => 'https://tx.example', 'aud' => 'rx', 'events_supported' => [], 'events_delivered' => [],
            'delivery' => Obj::of(['method' => SsfStream::DELIVERY_POLL, 'endpoint_url' => 'https://tx.example/poll/7']), 'min_verification_interval' => 30]);
        $store = new class (new StreamRecord('rx1', $config)) implements StreamStore {
            /** @var list<string> */
            public array $puts = [];

            public function __construct(public StreamRecord $r)
            {
            }

            public function get(string $id): ?StreamRecord
            {
                return $this->r->copy();
            }

            public function put(string $id, StreamRecord $r): void
            {
                $this->puts[] = $id;
                $this->r = $r;
            }

            public function delete(string $id): void
            {
            }

            public function listByReceiver(mixed $receiver): array
            {
                return [$this->r];
            }
        };
        $seed = str_repeat("\x07", 32);
        $t = 'x';
        $h = SsfManage::ssfManagementHandler([
            'store' => $store, 'issuer' => 'https://tx.example', 'eventsSupported' => [],
            'pollEndpoint' => static fn(string $id): string => "https://tx.example/poll/$id",
            'now' => static function () use (&$t): mixed {
                return $t;
            },
            'deliver' => static function ($s, $set): void {
            },
            'signingKey' => Obj::of(['kty' => 'OKP', 'crv' => 'Ed25519', 'x' => (new KeyPair($seed))->public, 'd' => Pca::b64u($seed)]),
        ], static fn($req) => Obj::of(['id' => 'rx1', 'aud' => 'rx']));
        $verify = static fn(): array => $h(['method' => 'POST', 'path' => '/ssf/verification', 'query' => [], 'body' => Obj::of(['stream_id' => '7'])]);

        $this->assertSame(['status' => 204], $verify());
        $this->assertSame(['7'], $store->puts);
        $this->assertNan($store->r->lastVerification);
        $t = 10;
        $this->assertSame(['status' => 204], $verify(), 'a NaN last verification never rate-limits');
        $this->assertSame(10.0, $store->r->lastVerification);
        $t = 20;
        $this->assertSame(429, $verify()['status'], 'control: 10 s after a numeric verification is too soon');
    }
}
