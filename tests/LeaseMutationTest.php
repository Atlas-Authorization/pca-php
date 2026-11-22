<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Lease.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvDoc;
use Atlas\Pca\Lease;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** An in-memory kv that records the key of every update. */
final class LsCountingKv implements AtomicKv
{
    /** @var list<string> */
    public array $updates = [];
    private MemoryAtomicKv $m;

    public function __construct()
    {
        $this->m = new MemoryAtomicKv();
    }

    public function get(string $key): ?string
    {
        return $this->m->get($key);
    }

    public function update(string $key, callable $fn): void
    {
        $this->updates[] = $key;
        $this->m->update($key, $fn);
    }
}

/** A kv that stores the shard-count pin and silently drops every other write (the callback is never called). */
final class LsPinOnlyKv implements AtomicKv
{
    private MemoryAtomicKv $m;

    public function __construct()
    {
        $this->m = new MemoryAtomicKv();
    }

    public function get(string $key): ?string
    {
        return $this->m->get($key);
    }

    public function update(string $key, callable $fn): void
    {
        if ($key === 'lease/meta') {
            $this->m->update($key, $fn);
        }
    }
}

/** LeaseRegistry: stored-document loading, shard bookkeeping, every refusal code of accept, revoke bookkeeping and pruning. */
final class LeaseMutationTest extends TestCase
{
    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    private static function lease(array $over = [], ?KeyPair $k = null): Obj
    {
        $f = ['v' => 1, 'lease_id' => 'L1', 'path' => 'svc/db', 'grant_ref' => 'g1', 'holder' => 'h1', 'requester' => 'r1',
            'approvers' => ['a1'], 'justification_digest' => 'j1', 'seq' => 1, 'issued_at' => 1000, 'renewed_at' => 1000,
            'expires_at' => 2000, 'max_ttl' => 10000, 'authority' => $k?->public ?? 'auth'];
        return self::build(array_replace($f, $over), Lease::DOMAIN, $k);
    }

    private static function rev(array $over = [], ?KeyPair $k = null): Obj
    {
        $f = ['v' => 1, 'target' => 'lease', 'value' => 'L1', 'revoked_at' => 5000, 'authority' => $k?->public ?? 'auth'];
        return self::build(array_replace($f, $over), Lease::REVOKE_DOMAIN, $k);
    }

    private static function build(array $f, string $domain, ?KeyPair $k): Obj
    {
        $o = new Obj();
        foreach ($f as $key => $v) {
            $o->set($key, is_int($v) ? new Num((string)$v) : $v);
        }
        $k === null || $o->set('sig', Pca::b64u($k->sign($domain . Json::canonicalizeStrict($o))));
        return $o;
    }

    private static function seed(AtomicKv $kv, string $key, string $doc): void
    {
        $kv->update($key, static fn(?string $prev): string => $doc);
    }

    /** @return list<string> */
    private static function sigs(AtomicKv $kv, string $key): array
    {
        $doc = json_decode((string)$kv->get($key), true);
        return array_column($doc['revocations'], 'sig');
    }

    public function testTheDefaultClockIsWallTimeInMilliseconds(): void
    {
        $a = self::kp(1);
        $now = time() * 1000;
        // a revocation whose window ends a long way (about 11 days) after / before now is kept / pruned by the default clock
        foreach ([[$now + 1_000_000_000, 1], [$now - 1_000_000_000, 0]] as [$windowEnd, $kept]) {
            $reg = new LeaseRegistry(['authorities' => [$a->public], 'maxTtlCeiling' => 1000], new MemoryAtomicKv());
            $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke(self::rev(['revoked_at' => $windowEnd - 1000], $a)));
            $this->assertCount($kept, $reg->revocations(), "window ends at $windowEnd");
        }
    }

    public function testTheShardCountIsPinnedOnceAndCached(): void
    {
        $a = self::kp(1);
        $kv = new LsCountingKv();
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
        $this->assertNull($reg->lookup('L1'));
        $this->assertNull($reg->current('L1'));
        $this->assertSame([], $reg->history('L1'));
        $this->assertSame([], $reg->revocations());
        $this->assertSame(['lease/meta'], $kv->updates);
    }

    public function testAMismatchedShardCountIsRefusedEverywhere(): void
    {
        $a = self::kp(1);
        $kv = new MemoryAtomicKv();
        self::seed($kv, 'lease/meta', '{"shards":8,"v":1}');
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
        foreach ([
            'lookup' => static fn() => $reg->lookup('L1'),
            'current' => static fn() => $reg->current('L1'),
            'history' => static fn() => $reg->history('L1'),
            'revocations' => static fn() => $reg->revocations(),
        ] as $name => $call) {
            try {
                $call();
                $this->fail("$name did not throw");
            } catch (\RuntimeException $e) {
                $this->assertSame('shard count mismatch', $e->getMessage(), $name);
            }
        }
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept(self::lease([], $a)));
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->revoke(self::rev([], $a)));
    }

    public function testCurrentAndLookupFindALeaseByItsId(): void
    {
        $a = self::kp(1);
        $reg = new LeaseRegistry(['authorities' => [$a->public]], new MemoryAtomicKv());
        $l = self::lease([], $a);
        $this->assertTrue($reg->accept($l)['ok']);
        $cur = $reg->current('L1');
        $this->assertInstanceOf(Obj::class, $cur);
        $this->assertSame($l->get('sig'), $cur->get('sig'));
        $this->assertNull($reg->current('L2'));
        $this->assertNull($reg->current('k'));
        $this->assertNull($reg->current('L1k'));
        $found = $reg->lookup('L1');
        $this->assertSame($l->get('sig'), $found['current']->get('sig'));
        $this->assertFalse($found['revoked']);
    }

    public function testStoredEntriesOfTheWrongShapeAreIgnored(): void
    {
        $a = self::kp(1);
        $good = KvDoc::enc(self::lease([], $a));
        $docs = [
            'leases is not an object' => '{"leases":"x","revocations":[]}',
            'revocations is not a list' => '{"leases":{},"revocations":"x"}',
            'an entry is a number' => '{"leases":{"L1":5},"revocations":[]}',
            'an entry is a list' => '{"leases":{"L1":[1]},"revocations":[]}',
            'current is not an object' => '{"leases":{"L1":{"current":"x","history":[]}},"revocations":[]}',
            'history is not a list' => '{"leases":{"L1":{"current":' . $good . ',"history":"x"}},"revocations":[]}',
        ];
        foreach ($docs as $why => $doc) {
            $kv = new MemoryAtomicKv();
            self::seed($kv, 'lease/16/' . KvDoc::shardOf('L1', 16), $doc);
            $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
            $this->assertNull($reg->current('L1'), $why);
            $this->assertNull($reg->lookup('L1'), $why);
        }
        $kv = new MemoryAtomicKv();
        self::seed($kv, 'lease/16/' . KvDoc::shardOf('L1', 16), '{"leases":{"L1":{"current":' . $good . ',"history":[]}},"revocations":[]}');
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
        $this->assertSame('L1', $reg->current('L1')?->get('lease_id'));
    }

    public function testStoredRevocationsThatAreNotObjectsAreDropped(): void
    {
        $a = self::kp(1);
        $kv = new MemoryAtomicKv();
        $r1 = self::rev(['value' => 'x1'], $a);
        $key = 'lease/16/' . KvDoc::shardOf('L1', 16);
        self::seed($kv, $key, '{"leases":{},"revocations":[5,"x",null,' . KvDoc::enc($r1) . ']}');
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
        $this->assertSame([$r1->get('sig')], array_map(static fn(Obj $r) => $r->get('sig'), $reg->revocations()));
        $r2 = self::rev(['value' => 'L1', 'revoked_at' => 6000], $a);
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($r2));
        $raw = json_decode((string)$kv->get($key), true);
        $this->assertTrue(array_is_list($raw['revocations']));
        $this->assertSame([$r1->get('sig'), $r2->get('sig')], array_column($raw['revocations'], 'sig'));
    }

    public function testPruningDropsExpiredRevocationsAndKeepsAList(): void
    {
        $a = self::kp(1);
        $kv = new MemoryAtomicKv();
        $old = self::rev(['value' => 'x1', 'revoked_at' => 9899], $a); // 9899 + 100 < 10000
        $edge = self::rev(['value' => 'x2', 'revoked_at' => 9900], $a); // 9900 + 100 = 10000: kept
        $key = 'lease/16/' . KvDoc::shardOf('L1', 16);
        self::seed($kv, $key, '{"leases":{},"revocations":[' . KvDoc::enc($old) . ',' . KvDoc::enc($edge) . ']}');
        $reg = new LeaseRegistry(['authorities' => [$a->public], 'maxTtlCeiling' => 100], $kv, ['clock' => static fn(): int => 10000]);
        $third = self::rev(['value' => 'L1', 'revoked_at' => 10000], $a);
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($third));
        $raw = json_decode((string)$kv->get($key), true);
        $this->assertTrue(array_is_list($raw['revocations']));
        $this->assertSame([$edge->get('sig'), $third->get('sig')], array_column($raw['revocations'], 'sig'));
    }

    public function testRevocationsAreTheUnionOverExactlyTheShards(): void
    {
        $a = self::kp(1);
        $kv = new MemoryAtomicKv();
        $out = self::rev(['value' => 'x1'], $a);
        $out2 = self::rev(['value' => 'x2'], $a);
        $in = self::rev(['value' => 'x3'], $a);
        $in2 = self::rev(['value' => 'x4'], $a);
        $doc = static fn(Obj $r): string => '{"leases":{},"revocations":[' . KvDoc::enc($r) . ']}';
        self::seed($kv, 'lease/16/-1', $doc($out));
        self::seed($kv, 'lease/16/16', $doc($out2));
        self::seed($kv, 'lease/16/3', $doc($in));
        self::seed($kv, 'lease/16/15', $doc($in2));
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
        $got = $reg->revocations();
        $this->assertTrue(array_is_list($got));
        $this->assertSame([$in->get('sig'), $in2->get('sig')], array_map(static fn(Obj $r) => $r->get('sig'), $got));
    }

    public function testARevocationSignatureMustBeAStringWhenKeyed(): void
    {
        $a = self::kp(1);
        $kv = new MemoryAtomicKv();
        self::seed($kv, 'lease/16/0', '{"leases":{},"revocations":[{"v":1,"sig":5}]}');
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
        try {
            $reg->revocations();
            $this->fail('a revocation with a non-string signature was keyed');
        } catch (\Error $e) {
            $this->assertStringContainsString('converted to string', $e->getMessage());
        }
    }

    public function testAcceptReportsNoStoreWriteAsUnreachableAndRevokeCountsZero(): void
    {
        $a = self::kp(1);
        $reg = new LeaseRegistry(['authorities' => [$a->public]], new LsPinOnlyKv());
        $this->assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept(self::lease([], $a)));
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke(self::rev([], $a)));
    }

    public function testAcceptSequenceRefusalsLeaveTheStoreUntouched(): void
    {
        $a = self::kp(1);
        $reg = new LeaseRegistry(['authorities' => [$a->public]], new MemoryAtomicKv());
        $renew = ['seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2'];
        $this->assertSame(['ok' => false, 'code' => 'bad_seq'], $reg->accept(self::lease(['seq' => 2], $a)));
        $this->assertNull($reg->current('L1'));
        $l1 = self::lease([], $a);
        $this->assertSame(['ok' => true, 'replaced' => true, 'seq' => 1], $reg->accept($l1));
        $this->assertSame(['ok' => true, 'replaced' => false, 'seq' => 1], $reg->accept($l1));
        $this->assertCount(1, $reg->history('L1'));
        $this->assertSame(['ok' => false, 'code' => 'lease_fork'], $reg->accept(self::lease(['justification_digest' => 'jX'], $a)));
        $this->assertSame(['ok' => false, 'code' => 'bad_seq'], $reg->accept(self::lease(array_replace($renew, ['seq' => 3]), $a)));
        $this->assertCount(1, $reg->history('L1'));
        $this->assertSame(['ok' => true, 'replaced' => true, 'seq' => 2], $reg->accept(self::lease($renew, $a)));
        $this->assertSame(['ok' => false, 'code' => 'stale_seq'], $reg->accept($l1));
        $this->assertSame(['ok' => false, 'code' => 'bad_seq'], $reg->accept(self::lease(['seq' => 4, 'renewed_at' => 1600, 'expires_at' => 3500, 'justification_digest' => 'j4'], $a)));
        $this->assertCount(2, $reg->history('L1'));
        $this->assertSame(2, $reg->current('L1')->get('seq')->int());
    }

    public function testARevokedLeaseIsRefusedAndNotStored(): void
    {
        $a = self::kp(1);
        $reg = new LeaseRegistry(['authorities' => [$a->public]], new MemoryAtomicKv());
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke(self::rev(['value' => 'L1'], $a)));
        $this->assertSame(['ok' => false, 'code' => 'revoked'], $reg->accept(self::lease([], $a)));
        $this->assertNull($reg->current('L1'));
        $this->assertSame([], $reg->history('L1'));
    }

    public function testEveryRenewalFieldMustMatchTheCurrentRecord(): void
    {
        $a = self::kp(1);
        $b = self::kp(2);
        $renew = ['seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2'];
        $cases = [
            'authority' => [[], $b],
            'path' => [['path' => 'svc/other'], $a],
            'grant_ref' => [['grant_ref' => 'g2'], $a],
            'holder' => [['holder' => 'h2'], $a],
            'requester' => [['requester' => 'r2'], $a],
            'max_ttl' => [['max_ttl' => 20000], $a],
            'issued_at' => [['issued_at' => 900], $a],
        ];
        foreach ($cases as $field => [$over, $signer]) {
            $reg = new LeaseRegistry(['authorities' => [$a->public, $b->public]], new MemoryAtomicKv());
            $this->assertTrue($reg->accept(self::lease([], $a))['ok']);
            $this->assertSame(['ok' => false, 'code' => 'renewal_mismatch'], $reg->accept(self::lease($renew + $over, $signer)), $field);
            $this->assertCount(1, $reg->history('L1'), $field);
            $this->assertSame(1, $reg->current('L1')->get('seq')->int(), $field);
        }
    }

    public function testRenewalTimeAndJustificationRules(): void
    {
        $a = self::kp(1);
        $mk = static function (array $policy = []) use ($a): LeaseRegistry {
            $reg = new LeaseRegistry(['authorities' => [$a->public]] + $policy, new MemoryAtomicKv());
            self::assertTrue($reg->accept(self::lease([], $a))['ok']);
            return $reg;
        };
        $renew = ['seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2'];
        $ok = ['ok' => true, 'replaced' => true, 'seq' => 2];

        // a renewal on or after the current expiry is an expired lease
        $reg = $mk();
        $this->assertSame(['ok' => false, 'code' => 'expired_lease'], $reg->accept(self::lease(array_replace($renew, ['renewed_at' => 2000]), $a)));
        $this->assertCount(1, $reg->history('L1'));
        $this->assertSame($ok, $mk()->accept(self::lease(array_replace($renew, ['renewed_at' => 1999]), $a)));

        // renewed_at may not go back, expires_at must move forward
        $reg = $mk();
        $this->assertSame($ok, $reg->accept(self::lease($renew, $a)));
        $seq3 = ['seq' => 3, 'expires_at' => 4000, 'justification_digest' => 'j3'];
        $this->assertSame(['ok' => false, 'code' => 'not_extending'], $reg->accept(self::lease($seq3 + ['renewed_at' => 1200], $a)));
        $this->assertCount(2, $reg->history('L1'));
        $this->assertSame(['ok' => true, 'replaced' => true, 'seq' => 3], $reg->accept(self::lease($seq3 + ['renewed_at' => 1500], $a)));

        $reg = $mk();
        $this->assertSame(['ok' => false, 'code' => 'not_extending'], $reg->accept(self::lease(array_replace($renew, ['renewed_at' => 1000, 'expires_at' => 2000]), $a)));
        $this->assertCount(1, $reg->history('L1'));
        $this->assertSame($ok, $mk()->accept(self::lease(array_replace($renew, ['renewed_at' => 1000, 'expires_at' => 2001]), $a)));

        // a renewal must carry a fresh justification unless the policy waives it
        $reg = $mk();
        $this->assertSame(['ok' => false, 'code' => 'stale_justification'], $reg->accept(self::lease(array_replace($renew, ['justification_digest' => 'j1']), $a)));
        $this->assertCount(1, $reg->history('L1'));
        $this->assertSame($ok, $mk(['freshJustification' => false])->accept(self::lease(array_replace($renew, ['justification_digest' => 'j1']), $a)));
    }

    public function testRevokeWritesOnlyTheShardsItCovers(): void
    {
        $a = self::kp(1);
        $one = new LsCountingKv();
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $one, ['shards' => 3]);
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke(self::rev(['value' => 'L1'], $a)));
        $this->assertSame(['lease/meta', 'lease/3/1'], $one->updates); // 'L1' lives in shard 1 of 3

        $kv = new LsCountingKv();
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv, ['shards' => 3]);
        $this->assertTrue($reg->accept(self::lease([], $a))['ok']);
        $p = self::rev(['target' => 'prefix', 'value' => 'svc'], $a);
        $this->assertSame(['ok' => true, 'revoked' => 1], $reg->revoke($p));
        $this->assertSame(['lease/meta', 'lease/3/1', 'lease/3/0', 'lease/3/1', 'lease/3/2'], $kv->updates);
        foreach ([0, 1, 2] as $i) {
            $this->assertContains($p->get('sig'), self::sigs($kv, "lease/3/$i"), "shard $i");
        }
        $this->assertTrue($reg->lookup('L1')['revoked']);
    }

    public function testRevokeIsIdempotentPerShard(): void
    {
        $a = self::kp(1);
        $kv = new MemoryAtomicKv();
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv, ['shards' => 1]);
        $r1 = self::rev(['value' => 'v1'], $a);
        $r2 = self::rev(['value' => 'v2'], $a);
        $r3 = self::rev(['value' => 'v3'], $a);
        $steps = [[$r1, [$r1]], [$r1, [$r1]], [$r2, [$r1, $r2]], [$r2, [$r1, $r2]], [$r1, [$r1, $r2]], [$r3, [$r1, $r2, $r3]], [$r2, [$r1, $r2, $r3]]];
        foreach ($steps as $i => [$rec, $want]) {
            $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($rec), "step $i");
            $this->assertSame(array_map(static fn(Obj $r) => $r->get('sig'), $want), self::sigs($kv, 'lease/1/0'), "step $i");
        }
    }
}
