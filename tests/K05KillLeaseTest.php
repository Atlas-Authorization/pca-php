<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Lease.php';

use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Lease;
use Atlas\Pca\MemoryLeaseKv;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for Lease / LeaseRegistry: every wellFormed bound, revocation shape, sod limits, renewal and revoke rules. */
final class K05KillLeaseTest extends TestCase
{
    private static function kp(int $b): KeyPair
    {
        return new KeyPair(str_repeat(chr($b), 32));
    }

    /** A lease record (PHP ints become Num); signed by $k (whose key is then the authority) when given. */
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

    public function testWellFormed(): void
    {
        self::assertTrue(Lease::wellFormed(self::lease()));
        self::assertFalse(Lease::wellFormed('x'));
        self::assertFalse(Lease::wellFormed(self::lease(['v' => 2])));
        foreach (['lease_id' => 128, 'grant_ref' => 256, 'holder' => 128, 'requester' => 128, 'authority' => 128, 'justification_digest' => 128] as $k => $max) {
            self::assertTrue(Lease::wellFormed(self::lease([$k => str_repeat('k', $max)])), "$k at $max");
            self::assertFalse(Lease::wellFormed(self::lease([$k => str_repeat('k', $max + 1)])), "$k over $max");
            self::assertFalse(Lease::wellFormed(self::lease([$k => null])), "$k missing");
        }
        self::assertFalse(Lease::wellFormed(self::lease(['path' => 'BAD'])));
        self::assertFalse(Lease::wellFormed(self::lease(['path' => 5])));
        self::assertFalse(Lease::wellFormed(self::lease(['seq' => new Num('1.5')])));
        self::assertTrue(Lease::wellFormed(self::lease(['max_ttl' => 1])));
        self::assertFalse(Lease::wellFormed(self::lease(['seq' => 0])));
        self::assertFalse(Lease::wellFormed(self::lease(['expires_at' => 1000])));
        self::assertFalse(Lease::wellFormed(self::lease(['seq' => 2, 'renewed_at' => 900])));
        self::assertTrue(Lease::wellFormed(self::lease(['seq' => 2])));
        self::assertFalse(Lease::wellFormed(self::lease(['renewed_at' => 1500])));
        $ap = array_map(static fn (int $i): string => "a$i", range(1, 16));
        self::assertTrue(Lease::wellFormed(self::lease(['approvers' => $ap])));
        self::assertFalse(Lease::wellFormed(self::lease(['approvers' => [...$ap, 'a17']])));
        self::assertFalse(Lease::wellFormed(self::lease(['approvers' => 'x'])));
        self::assertFalse(Lease::wellFormed(self::lease(['approvers' => ['']])));
        self::assertTrue(Lease::wellFormed(self::lease(['approvers' => [str_repeat('a', 128)]])));
        self::assertFalse(Lease::wellFormed(self::lease(['approvers' => [str_repeat('a', 129)]])));
    }

    public function testRevocationWellFormed(): void
    {
        self::assertTrue(Lease::revocationWellFormed(self::rev()));
        self::assertFalse(Lease::revocationWellFormed('x'));
        self::assertFalse(Lease::revocationWellFormed(self::rev(['v' => 2])));
        self::assertTrue(Lease::revocationWellFormed(self::rev(['value' => str_repeat('v', 256)])));
        self::assertFalse(Lease::revocationWellFormed(self::rev(['value' => str_repeat('v', 257)])));
        self::assertFalse(Lease::revocationWellFormed(self::rev(['value' => ''])));
        self::assertTrue(Lease::revocationWellFormed(self::rev(['authority' => str_repeat('a', 128)])));
        self::assertFalse(Lease::revocationWellFormed(self::rev(['authority' => str_repeat('a', 129)])));
        self::assertFalse(Lease::revocationWellFormed(self::rev(['authority' => ''])));
        self::assertFalse(Lease::revocationWellFormed(self::rev(['target' => 'bogus'])));
    }

    public function testPathCapCovers(): void
    {
        self::assertTrue(Lease::pathUnder('a/b', 'a'));
        self::assertFalse(Lease::pathUnder('ab', 'a'));
        self::assertSame(0.0, Lease::cap(new Obj()));
        self::assertSame(11000.0, Lease::cap(self::lease()));
        self::assertTrue(Lease::covers(self::rev(['revoked_at' => 1000]), self::lease()));
        self::assertFalse(Lease::covers(self::rev(['revoked_at' => 999]), self::lease()));
    }

    public function testSodMinApprovals(): void
    {
        $l = self::lease();
        self::assertSame('1 approver(s), need 9007199254740991', Lease::sodError($l, ['minApprovals' => 9007199254740991]));
        $bad = 'minApprovals must be a positive integer';
        self::assertSame($bad, Lease::sodError($l, ['minApprovals' => '2']));
        self::assertSame($bad, Lease::sodError($l, ['minApprovals' => 0]));
        self::assertNull(Lease::sodError($l));
    }

    public function testAcceptHistoryAndRenewal(): void
    {
        $a = self::kp(1);
        $reg = new LeaseRegistry(['authorities' => [$a->public]], new MemoryLeaseKv());
        self::assertSame(['ok' => true, 'replaced' => true, 'seq' => 1], $reg->accept(self::lease([], $a)));
        $h1 = ['seq' => 1, 'renewed_at' => 1000, 'expires_at' => 2000, 'justification_digest' => 'j1'];
        self::assertSame([$h1], $reg->history('L1'));
        self::assertSame([], $reg->history('L2'));
        // a renewal at the same renewed_at that extends expires_at is accepted
        self::assertSame(['ok' => true, 'replaced' => true, 'seq' => 2],
            $reg->accept(self::lease(['seq' => 2, 'expires_at' => 3000, 'justification_digest' => 'j2'], $a)));
        self::assertSame([$h1, ['seq' => 2, 'renewed_at' => 1000, 'expires_at' => 3000, 'justification_digest' => 'j2']], $reg->history('L1'));
    }

    public function testRenewalMismatch(): void
    {
        $a = self::kp(1);
        $b = self::kp(2);
        $reg = new LeaseRegistry(['authorities' => [$a->public, $b->public]], new MemoryLeaseKv());
        self::assertTrue($reg->accept(self::lease([], $a))['ok']);
        $renew = ['seq' => 2, 'renewed_at' => 1500, 'expires_at' => 3000, 'justification_digest' => 'j2'];
        self::assertSame(['ok' => false, 'code' => 'renewal_mismatch'], $reg->accept(self::lease($renew, $b)));
        self::assertSame(['ok' => false, 'code' => 'renewal_mismatch'], $reg->accept(self::lease($renew + ['max_ttl' => 20000], $a)));
        self::assertSame(['ok' => true, 'replaced' => true, 'seq' => 2], $reg->accept(self::lease($renew, $a)));
    }

    public function testStoreUnreachable(): void
    {
        $a = self::kp(1);
        $reg = new LeaseRegistry(['authorities' => 'not-a-list'], new MemoryLeaseKv()); // in_array throws: the store fails closed
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept(self::lease([], $a)));
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->revoke(self::rev([], $a)));
    }

    public function testRevokeIdempotentAndAuthority(): void
    {
        $a = self::kp(1);
        $ra = self::rev([], $a);
        $rb = self::rev(['target' => 'grant', 'value' => 'g9'], $a);
        $reg = new LeaseRegistry(['authorities' => [$a->public]], new MemoryLeaseKv());
        self::assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($ra));
        self::assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($ra));
        self::assertCount(1, $reg->revocations());
        self::assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($rb));
        self::assertCount(2, $reg->revocations());
        $sigs = array_map(static fn($r) => $r->get('sig'), $reg->revocations()); // the order is the shards', not the arrival order
        self::assertContains($rb->get('sig'), $sigs);
        self::assertContains($ra->get('sig'), $sigs);
        $other = new LeaseRegistry(['authorities' => [self::kp(2)->public]], new MemoryLeaseKv());
        self::assertSame(['ok' => false, 'code' => 'unknown_authority'], $other->revoke($ra));
    }

    /** A stored record whose number was corrupted in the store reads its bad number as 0.0 (bad_seq), never as a crash. */
    public function testACorruptStoredRecordReadsAsZero(): void
    {
        $a = self::kp(1);
        $kv = new MemoryLeaseKv();
        $reg = new LeaseRegistry(['authorities' => [$a->public]], $kv);
        self::assertTrue($reg->accept(self::lease([], $a))['ok']);
        $key = 'lease/16/' . \Atlas\Pca\KvDoc::shardOf('L1', 16);
        $doc = $kv->get($key);
        self::assertStringContainsString('"seq":1', $doc);
        $kv->update($key, static fn(?string $prev): string => str_replace('"seq":1', '"seq":"x"', (string)$prev));
        self::assertSame(['ok' => false, 'code' => 'bad_seq'],
            $reg->accept(self::lease(['seq' => 2, 'expires_at' => 3000, 'justification_digest' => 'j2'], $a)));
    }

    public function testMaxTtlCeiling(): void
    {
        // lease.ts:245: right after over_max_ttl, at / below the ceiling accepted, above refused, absent = no ceiling
        $a = self::kp(1);
        $accept = static fn(array $policy, array $over = []): array => (new LeaseRegistry(['authorities' => [$a->public]] + $policy, new MemoryLeaseKv()))->accept(self::lease($over, $a));
        $this->assertTrue($accept(['maxTtlCeiling' => 10000])['ok']);
        $this->assertTrue($accept(['maxTtlCeiling' => 10001])['ok']);
        $this->assertSame(['ok' => false, 'code' => 'ttl_ceiling'], $accept(['maxTtlCeiling' => 9999]));
        $this->assertTrue($accept([])['ok']);
        $this->assertSame(['ok' => false, 'code' => 'over_max_ttl'], $accept(['maxTtlCeiling' => 9999], ['expires_at' => 99999]));
        foreach ([0, -1, 1.5, '5'] as $bad) {
            try {
                new LeaseRegistry(['authorities' => [], 'maxTtlCeiling' => $bad], new MemoryLeaseKv());
                $this->fail('accepted ceiling ' . json_encode($bad));
            } catch (\RangeException $e) {
                $this->assertSame('LeaseRegistry: maxTtlCeiling must be a positive integer', $e->getMessage());
            }
        }
        $this->assertSame([], (new LeaseRegistry(['authorities' => [], 'maxTtlCeiling' => 1], new MemoryLeaseKv()))->revocations());
    }
}
