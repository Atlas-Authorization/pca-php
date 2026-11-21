<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Blueprint.php';

use Atlas\Pca\Blueprint;
use Atlas\Pca\BlueprintRegistry;
use Atlas\Pca\BlueprintStore;
use Atlas\Pca\Json;
use Atlas\Pca\KvBlueprintStore;
use Atlas\Pca\KvDoc;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryBlueprintStore;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Blueprint checks, stores and the registry: exact results at the edges the shared vectors do not reach. */
final class BlueprintMutationTest extends TestCase
{
    private static function obj(array $a): Obj
    {
        $o = Json::parseLax((string)json_encode($a));
        self::assertInstanceOf(Obj::class, $o);
        return $o;
    }

    private static function bp(array $over = []): Obj
    {
        return self::obj(array_replace(['v' => 1, 'id' => 'bp', 'key' => 'k1', 'ceiling' => [], 'epoch' => 1, 'status' => 'active', 'issued_at' => 1000, 'operator' => 'op'], $over));
    }

    private static function hop(string $issuer, string $holder): Obj
    {
        return self::obj(['issuer' => $issuer, 'holder' => $holder]);
    }

    public function testAnExplicitHaveEpochWinsOverTheStoreEpoch(): void
    {
        $chain = [self::hop('root', 'k1')];
        self::assertSame(['decision' => 'allow', 'governed' => []], Blueprint::check($chain, [], 1000, 'optional', 5, null, 7));
        self::assertSame(['decision' => 'escalate', 'code' => 'stale_blueprint_state', 'have' => 3, 'need' => 5],
            Blueprint::check($chain, ['k0' => self::bp(['key' => 'k0', 'epoch' => 9])], 1000, 'optional', 5, null, 3));
    }

    public function testAThrowingAdmissionHookDenies(): void
    {
        $chain = [self::hop('root', 'k1'), self::hop('k1', 'inst')];
        $store = ['k1' => self::bp(['runtime_pins' => [['model_id' => 'm']]])];
        $deny = ['decision' => 'deny', 'code' => 'not_admitted', 'blueprint' => 'bp'];
        self::assertSame($deny, Blueprint::check($chain, $store, 1000, 'require', null, static function (): bool {
            throw new \RuntimeException('down');
        }));
        self::assertSame($deny, Blueprint::check($chain, $store, 1000, 'require', null, static fn(): bool => false));
        self::assertSame(['decision' => 'allow', 'governed' => ['bp']], Blueprint::check($chain, $store, 1000, 'require', null, static fn(): bool => true));
    }

    public function testAnEmptyMemoryStoreHasEpochZero(): void
    {
        self::assertSame(0, (new MemoryBlueprintStore())->maxEpoch());
    }

    public function testTheKvStoreKeepsAMonotoneIntegerEpoch(): void
    {
        $kv = new MemoryAtomicKv();
        $store = new KvBlueprintStore($kv);
        $store->put(self::bp(['epoch' => 0]));
        self::assertNull($kv->get('blueprint/epoch'), 'epoch 0 is not above the empty maximum');
        self::assertSame(0, $store->maxEpoch());
        $store->put(self::bp(['epoch' => 1]));
        self::assertSame('{"epoch":1}', $kv->get('blueprint/epoch'));
        $store->put(self::bp(['epoch' => 5]));
        self::assertSame('{"epoch":5}', $kv->get('blueprint/epoch'));
        $store->put(self::bp(['epoch' => 3]));
        self::assertSame('{"epoch":5}', $kv->get('blueprint/epoch'));
        self::assertSame(5, $store->maxEpoch());

        $kv2 = new MemoryAtomicKv();
        (new KvBlueprintStore($kv2))->put(self::bp(['epoch' => 1.5]));
        self::assertSame('{"epoch":1}', $kv2->get('blueprint/epoch'));
    }

    public function testAStoredRecordWithoutANumericEpochIsReplaced(): void
    {
        foreach (['{"epoch":"x","stale":true}', '{"stale":true}', '{"epoch":null}'] as $stored) {
            $kv = new MemoryAtomicKv();
            $kv->update('blueprint/rec/k1', static fn(): string => $stored);
            $bp = self::bp(['epoch' => 1]);
            (new KvBlueprintStore($kv))->put($bp);
            self::assertSame(KvDoc::enc($bp), $kv->get('blueprint/rec/k1'), $stored);
        }
    }

    public function testAnEpochDocumentWithoutANumberReadsAsZero(): void
    {
        $kv = new MemoryAtomicKv();
        $kv->update('blueprint/epoch', static fn(): string => '{"epoch":"x"}');
        $store = new KvBlueprintStore($kv);
        self::assertSame(0, $store->maxEpoch());
        $store->put(self::bp(['epoch' => 2]));
        self::assertSame('{"epoch":2}', $kv->get('blueprint/epoch'));
        $kv->update('blueprint/epoch', static fn(): string => '{}');
        self::assertSame(0, $store->maxEpoch());
    }

    public function testTheRegistryRefusesAndStoresExactly(): void
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat("\x07", 32));
        $pk = Pca::b64u(sodium_crypto_sign_publickey($kp));
        $b = self::bp(['operator' => $pk]);
        $b->set('sig', Pca::b64u(sodium_crypto_sign_detached(Blueprint::DOMAIN . Json::canonicalizeStrict($b), sodium_crypto_sign_secretkey($kp))));

        $store = new class implements BlueprintStore {
            public int $puts = 0;
            private MemoryBlueprintStore $m;
            public function __construct()
            {
                $this->m = new MemoryBlueprintStore();
            }
            public function get(string $key): ?Obj
            {
                return $this->m->get($key);
            }
            public function put(Obj $b): void
            {
                $this->puts++;
                $this->m->put($b);
            }
            public function maxEpoch(): int
            {
                return $this->m->maxEpoch();
            }
        };
        $reg = new BlueprintRegistry([$pk], $store);
        self::assertSame(['ok' => false, 'code' => 'bad_record'], $reg->accept('x'));
        self::assertSame(['ok' => true, 'replaced' => true], $reg->accept($b));
        self::assertSame(['ok' => true, 'replaced' => false], $reg->accept($b));
        self::assertSame(1, $store->puts, 'the same record again is not written again');

        // a hop that is not an object is bad input, not a store failure
        self::assertSame(['decision' => 'deny', 'code' => 'bad_input'], $reg->check([5], 1000, 'optional'));
    }
}
