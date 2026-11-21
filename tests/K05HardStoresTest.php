<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AtomicKv;
use Atlas\Pca\Blueprint;
use Atlas\Pca\BlueprintRegistry;
use Atlas\Pca\BreakGlass;
use Atlas\Pca\BreakGlassRegistry;
use Atlas\Pca\Json;
use Atlas\Pca\KvBlueprintStore;
use Atlas\Pca\Lease;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryBlueprintStore;
use Atlas\Pca\MemoryLeaseKv;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/**
 * H15 (a lease, break-glass or blueprint registry runs over a durable store and refuses to run without one) and F5 (revocation
 * pruning against maxTtlCeiling). Every state a restart or a second instance could lose is read back through a NEW registry over the
 * same store.
 */
final class K05HardStoresTest extends TestCase
{
    private static function key(string $byte): array
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat($byte, 32));
        return [sodium_crypto_sign_secretkey($kp), Pca::b64u(sodium_crypto_sign_publickey($kp))];
    }

    private static function obj(array $a): Obj
    {
        $o = Json::parseLax((string)json_encode($a));
        self::assertInstanceOf(Obj::class, $o);
        return $o;
    }

    private static function signed(string $domain, array $body, string $sk): Obj
    {
        $o = self::obj($body);
        $o->set('sig', Pca::b64u(sodium_crypto_sign_detached($domain . Json::canonicalizeStrict($o), $sk)));
        return $o;
    }

    private static function lease(string $sk, string $pk, array $over = []): Obj
    {
        return self::signed(Lease::DOMAIN, array_replace(['v' => 1, 'lease_id' => 'L1', 'path' => 'svc/db', 'grant_ref' => 'g1', 'holder' => 'h1', 'requester' => 'r1',
            'approvers' => ['a1'], 'justification_digest' => 'j1', 'seq' => 1, 'issued_at' => 1000, 'renewed_at' => 1000, 'expires_at' => 2000, 'max_ttl' => 10000,
            'authority' => $pk], $over), $sk);
    }

    private static function revocation(string $sk, string $pk, array $over = []): Obj
    {
        return self::signed(Lease::REVOKE_DOMAIN, array_replace(['v' => 1, 'target' => 'lease', 'value' => 'L1', 'revoked_at' => 5000, 'authority' => $pk], $over), $sk);
    }

    private static function throwingKv(): AtomicKv
    {
        return new class () implements AtomicKv {
            public function get(string $key): ?string
            {
                throw new \RuntimeException('down');
            }

            public function update(string $key, callable $fn): void
            {
                throw new \RuntimeException('down');
            }
        };
    }

    // ------------------------------------------------------------------------------------------------------------- lease

    public function testALeaseRegistryNeedsAStore(): void
    {
        foreach ([null, 5, 'kv', new \stdClass()] as $bad) {
            try {
                new LeaseRegistry(['authorities' => []], $bad);
                $this->fail('built without a store');
            } catch (\TypeError $e) {
                $this->assertSame('LeaseRegistry: a durable key-value store is required (MemoryLeaseKv is for tests and single-process use)', $e->getMessage());
            }
        }
        foreach ([0, -1, 4097, 1.5, '4'] as $n) {
            try {
                new LeaseRegistry(['authorities' => []], new MemoryLeaseKv(), ['shards' => $n]);
                $this->fail("accepted shards " . json_encode($n));
            } catch (\RangeException $e) {
                $this->assertSame('LeaseRegistry: shards must be an integer from 1 to 4096', $e->getMessage());
            }
        }
        $this->assertSame(16, (new LeaseRegistry(['authorities' => []], new MemoryLeaseKv()))->shardCount());
        $this->assertSame(4096, (new LeaseRegistry(['authorities' => []], new MemoryLeaseKv(), ['shards' => 4096]))->shardCount());
        $this->assertSame(1, (new LeaseRegistry(['authorities' => []], new MemoryLeaseKv(), ['shards' => 1]))->shardCount());
    }

    public function testARevocationSurvivesARestart(): void
    {
        [$sk, $pk] = self::key("\x01");
        $kv = new MemoryLeaseKv();
        $first = new LeaseRegistry(['authorities' => [$pk]], $kv);
        $l1 = self::lease($sk, $pk);
        $this->assertSame(['ok' => true, 'replaced' => true, 'seq' => 1], $first->accept($l1));
        $this->assertSame('allow', Lease::check($l1, $first, 1500)['decision']);
        $this->assertSame(['ok' => true, 'revoked' => 1], $first->revoke(self::revocation($sk, $pk)));
        $second = new LeaseRegistry(['authorities' => [$pk]], $kv); // a restart, or another instance
        $this->assertSame(['decision' => 'deny', 'code' => 'revoked', 'lease_id' => 'L1'], Lease::check($l1, $second, 1500));
        $this->assertSame(['ok' => false, 'code' => 'revoked'], $second->accept($l1));
        $this->assertSame(['ok' => false, 'code' => 'revoked'], $second->accept(self::lease($sk, $pk, ['seq' => 2, 'expires_at' => 3000, 'justification_digest' => 'j2'])));
    }

    public function testAPrefixRevocationReachesEveryShard(): void
    {
        [$sk, $pk] = self::key("\x01");
        $kv = new MemoryLeaseKv();
        $reg = new LeaseRegistry(['authorities' => [$pk]], $kv, ['shards' => 4]);
        $ids = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
        foreach ($ids as $id) {
            $this->assertTrue($reg->accept(self::lease($sk, $pk, ['lease_id' => $id]))['ok'], $id);
        }
        $this->assertSame(['ok' => true, 'revoked' => 8], $reg->revoke(self::revocation($sk, $pk, ['target' => 'prefix', 'value' => 'svc'])));
        $again = new LeaseRegistry(['authorities' => [$pk]], $kv, ['shards' => 4]);
        foreach ($ids as $id) {
            $this->assertSame('revoked', Lease::check(self::lease($sk, $pk, ['lease_id' => $id]), $again, 1500)['code'], $id);
        }
        $this->assertCount(1, $again->revocations(), 'one signature, however many shards hold it');
        $this->assertSame(['ok' => true, 'revoked' => 8], $again->revoke(self::revocation($sk, $pk, ['target' => 'prefix', 'value' => 'svc'])), 'idempotent');
    }

    public function testAThrowingStoreIsStoreUnreachable(): void
    {
        [$sk, $pk] = self::key("\x01");
        $reg = new LeaseRegistry(['authorities' => [$pk]], self::throwingKv());
        $l1 = self::lease($sk, $pk);
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept($l1));
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->revoke(self::revocation($sk, $pk)));
        $this->assertSame(['decision' => 'deny', 'code' => 'store_unreachable', 'lease_id' => 'L1'], Lease::check($l1, $reg, 1500));
    }

    public function testADifferentShardCountOverTheSameStoreIsRefused(): void
    {
        [$sk, $pk] = self::key("\x01");
        $kv = new MemoryLeaseKv();
        $this->assertTrue((new LeaseRegistry(['authorities' => [$pk]], $kv, ['shards' => 4]))->accept(self::lease($sk, $pk))['ok']);
        $other = new LeaseRegistry(['authorities' => [$pk]], $kv, ['shards' => 8]);
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $other->accept(self::lease($sk, $pk, ['lease_id' => 'L2'])));
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $other->revoke(self::revocation($sk, $pk)));
    }

    public function testTwoRenewalsOfOneSeqExactlyOneWins(): void
    {
        [$sk, $pk] = self::key("\x01");
        $kv = new MemoryLeaseKv();
        $a = new LeaseRegistry(['authorities' => [$pk]], $kv);
        $b = new LeaseRegistry(['authorities' => [$pk]], $kv);
        $this->assertTrue($a->accept(self::lease($sk, $pk))['ok']);
        $r1 = self::lease($sk, $pk, ['seq' => 2, 'expires_at' => 3000, 'justification_digest' => 'j2']);
        $r2 = self::lease($sk, $pk, ['seq' => 2, 'expires_at' => 3500, 'justification_digest' => 'j3']);
        $this->assertSame(['ok' => true, 'replaced' => true, 'seq' => 2], $a->accept($r1));
        $this->assertSame(['ok' => false, 'code' => 'lease_fork'], $b->accept($r2));
        $this->assertSame('allow', Lease::check($r1, $b, 1500)['decision']);
        $this->assertSame('superseded', Lease::check($r2, $b, 1500)['code']);
        $this->assertSame(2, $b->history('L1')[1]['seq']);
        $this->assertCount(2, $b->history('L1'));
    }

    public function testRevocationsArePrunedAfterTheCeilingOnlyWhenOneIsSet(): void
    {
        [$sk, $pk] = self::key("\x01");
        $lease = static fn(string $id): Obj => self::lease($sk, $pk, ['lease_id' => $id, 'issued_at' => 3000, 'renewed_at' => 3000, 'expires_at' => 4000, 'max_ttl' => 1000]);
        foreach ([1000, null] as $ceiling) {
            $now = 1000;
            $policy = ['authorities' => [$pk]] + ($ceiling === null ? [] : ['maxTtlCeiling' => $ceiling]);
            $reg = new LeaseRegistry($policy, new MemoryLeaseKv(), ['shards' => 1, 'clock' => static function () use (&$now): int {
                return $now;
            }]);
            $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke(self::revocation($sk, $pk, ['value' => 'LX', 'revoked_at' => 1000])));
            $this->assertCount(1, $reg->revocations());
            $now = 2000; // revoked_at + ceiling == now: still kept
            $this->assertTrue($reg->accept($lease('LY'))['ok']);
            $this->assertCount(1, $reg->revocations(), 'at the boundary the revocation is kept');
            $now = 2001;
            $this->assertTrue($reg->accept($lease('LZ'))['ok']);
            $this->assertCount($ceiling === null ? 1 : 0, $reg->revocations(), $ceiling === null ? 'no ceiling: nothing is ever pruned' : 'past revoked_at + ceiling the revocation is pruned');
        }
    }

    // ----------------------------------------------------------------------------------------------------------- break-glass

    private static function grant(string $sk, string $pk, array $over = []): Obj
    {
        return self::signed(BreakGlass::DOMAIN, array_replace(['v' => 1, 'id' => 'bg1', 'holder' => 'h1', 'grant_ref' => 'g', 'reason_digest' => 'r', 'max_uses' => 1,
            'issued_at' => 1000, 'expires_at' => 100000, 'review_within' => 5000, 'notify_to' => 'n', 'authority' => $pk], $over), $sk);
    }

    public function testABreakGlassRegistryNeedsAStore(): void
    {
        foreach ([null, 5, new \stdClass()] as $bad) {
            try {
                new BreakGlassRegistry(['authorities' => [], 'reviewers' => []], $bad);
                $this->fail('built without a store');
            } catch (\TypeError $e) {
                $this->assertSame('BreakGlassRegistry: a durable key-value store is required (MemoryLeaseKv is for tests and single-process use)', $e->getMessage());
            }
        }
        try {
            new BreakGlassRegistry(['authorities' => [], 'reviewers' => []], new MemoryLeaseKv(), ['shards' => 0]);
            $this->fail('accepted');
        } catch (\RangeException $e) {
            $this->assertSame('BreakGlassRegistry: shards must be an integer from 1 to 4096', $e->getMessage());
        }
    }

    public function testAUseBudgetSurvivesARestart(): void
    {
        [$sk, $pk] = self::key("\x01");
        $kv = new MemoryLeaseKv();
        $policy = ['authorities' => [$pk], 'reviewers' => []];
        $first = new BreakGlassRegistry($policy, $kv);
        $this->assertSame(['ok' => true, 'replaced' => true], $first->accept(self::grant($sk, $pk), 1000));
        $this->assertSame('allow', $first->use('bg1', 'h1', 'd1', 2000, true)['decision']);
        $second = new BreakGlassRegistry($policy, $kv);
        $this->assertSame(['decision' => 'deny', 'code' => 'budget_exhausted', 'id' => 'bg1'], $second->use('bg1', 'h1', 'd2', 2100, true));
        $this->assertSame(['ok' => true, 'replaced' => false], $second->accept(self::grant($sk, $pk), 2100), 'the same record again is a no-op');
        // an unreviewed grant freezes its holder once the review clock runs out, in every instance
        $this->assertTrue($second->frozen('h1', 7000));
        $this->assertTrue((new BreakGlassRegistry($policy, $kv))->frozen('h1', 7000));
        $this->assertFalse((new BreakGlassRegistry($policy, $kv))->frozen('h1', 6999));
        $this->assertFalse((new BreakGlassRegistry($policy, $kv))->frozen('other', 7000));
    }

    public function testBreakGlassStoreFailuresAreClosed(): void
    {
        [$sk, $pk] = self::key("\x01");
        $reg = new BreakGlassRegistry(['authorities' => [$pk], 'reviewers' => []], self::throwingKv());
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept(self::grant($sk, $pk), 1000));
        $this->assertSame(['decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'bg1'], $reg->use('bg1', 'h1', 'd', 2000, true));
        $this->assertTrue($reg->frozen('h1', 2000), 'an unreadable store freezes (fail closed)');
    }

    // ------------------------------------------------------------------------------------------------------------ blueprint

    private static function blueprint(string $sk, string $pk, int $epoch, string $status, array $over = []): Obj
    {
        return self::signed(Blueprint::DOMAIN, array_replace(['v' => 1, 'id' => 'support-bot', 'key' => 'bpkey', 'ceiling' => [], 'max_depth' => 2, 'epoch' => $epoch,
            'status' => $status, 'issued_at' => 1000, 'operator' => $pk], $over), $sk);
    }

    public function testABlueprintRegistryNeedsAStore(): void
    {
        foreach ([null, 5, new \stdClass(), new MemoryAtomicKv()] as $bad) {
            try {
                new BlueprintRegistry(['op'], $bad);
                $this->fail('built without a store');
            } catch (\TypeError $e) {
                $this->assertSame('BlueprintRegistry: a durable BlueprintStore is required (MemoryBlueprintStore is for tests and single-process use)', $e->getMessage());
            }
        }
    }

    public function testADisabledBlueprintStaysDisabledAfterARestart(): void
    {
        [$sk, $pk] = self::key("\x01");
        foreach ([fn() => new MemoryBlueprintStore(), static function (): KvBlueprintStore {
            return new KvBlueprintStore(new MemoryAtomicKv());
        }] as $mk) {
            $store = $mk();
            $first = new BlueprintRegistry([$pk], $store);
            $this->assertSame(['ok' => true, 'replaced' => true], $first->accept(self::blueprint($sk, $pk, 5, 'disabled')));
            $second = new BlueprintRegistry([$pk], $store);
            $this->assertSame(['ok' => false, 'code' => 'stale_epoch'], $second->accept(self::blueprint($sk, $pk, 4, 'active')), 'replaying the active epoch 4');
            $this->assertSame(['ok' => true, 'replaced' => false], $second->accept(self::blueprint($sk, $pk, 5, 'disabled')));
            $this->assertSame(5, $second->epoch());
            $this->assertSame('disabled', $second->get('bpkey')->get('status'));
            $d = $second->check(Json::parseLax('[{"issuer":"principal","holder":"bpkey"},{"issuer":"bpkey","holder":"inst1"}]'), 1800000000000, 'require');
            $this->assertSame(['decision' => 'deny', 'code' => 'blueprint_disabled', 'blueprint' => 'support-bot'], $d);
        }
    }

    public function testTheKvBlueprintStoreKeepsTheHighestEpoch(): void
    {
        [$sk, $pk] = self::key("\x01");
        $kv = new MemoryAtomicKv();
        $s = new KvBlueprintStore($kv);
        $this->assertSame(0, $s->maxEpoch());
        $this->assertNull($s->get('bpkey'));
        $s->put(self::blueprint($sk, $pk, 3, 'active'));
        $s->put(self::blueprint($sk, $pk, 9, 'active', ['key' => 'other']));
        $s->put(self::blueprint($sk, $pk, 4, 'active'));
        $again = new KvBlueprintStore($kv);
        $this->assertSame(9, $again->maxEpoch(), 'the maximum never goes down');
        $this->assertSame(4, $again->get('bpkey')->get('epoch')->int());
    }

    public function testTheKvBlueprintStorePutKeepsTheStoredRecordUnlessTheEpochIsHigher(): void
    {
        [$sk, $pk] = self::key("\x01");
        $s = new KvBlueprintStore(new MemoryAtomicKv());
        $s->put(self::blueprint($sk, $pk, 5, 'disabled', ['id' => 'first']));
        $s->put(self::blueprint($sk, $pk, 3, 'active', ['id' => 'older']));
        $this->assertSame('first', $s->get('bpkey')->get('id'));
        $s->put(self::blueprint($sk, $pk, 5, 'active', ['id' => 'same-epoch']));
        $this->assertSame('first', $s->get('bpkey')->get('id'));
        $s->put(self::blueprint($sk, $pk, 6, 'active', ['id' => 'newer']));
        $this->assertSame('newer', $s->get('bpkey')->get('id'));
        $s->put(self::blueprint($sk, $pk, 1, 'active', ['key' => 'other', 'id' => 'x']));
        $this->assertSame('x', $s->get('other')->get('id'));
        $this->assertSame(6, $s->maxEpoch());
    }

    public function testABlueprintStoreFailureIsClosed(): void
    {
        [$sk, $pk] = self::key("\x01");
        $reg = new BlueprintRegistry([$pk], new KvBlueprintStore(self::throwingKv()));
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept(self::blueprint($sk, $pk, 1, 'active')));
        $this->assertSame(['decision' => 'deny', 'code' => 'store_unreachable'], $reg->check(Json::parseLax('[{"issuer":"a","holder":"b"}]'), 1, 'any'));
    }
}
