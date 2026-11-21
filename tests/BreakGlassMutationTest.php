<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/BreakGlass.php';

use Atlas\Pca\AtomicKv;
use Atlas\Pca\BreakGlass;
use Atlas\Pca\BreakGlassRegistry;
use Atlas\Pca\Json;
use Atlas\Pca\KvDoc;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\MemoryLeaseKv;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Break-glass registry: stored-document parsing, shard keys, untouched-store and store-failure paths. */
final class BreakGlassMutationTest extends TestCase
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

    private static function arr(Obj $o): array
    {
        return json_decode(Json::canonicalizeLenient($o), true);
    }

    private static function signed(string $domain, array $body, string $sk): Obj
    {
        $o = self::obj($body);
        $o->set('sig', Pca::b64u(sodium_crypto_sign_detached($domain . Json::canonicalizeStrict($o), $sk)));
        return $o;
    }

    private static function grantBody(array $over = []): array
    {
        return array_merge(['v' => 1, 'id' => 'bg1', 'holder' => 'h1', 'grant_ref' => 'g', 'reason_digest' => 'r', 'max_uses' => 2,
            'issued_at' => 1000, 'expires_at' => 100000, 'review_within' => 5000, 'notify_to' => 'n', 'authority' => 'auth'], $over);
    }

    private static function reviewBody(array $over = []): array
    {
        return array_merge(['v' => 1, 'id' => 'bg1', 'outcome' => 'justified', 'notes_digest' => 'nd', 'at' => 2000, 'reviewer' => 'rev'], $over);
    }

    private static function shardKey(string $holder, int $shards = 16): string
    {
        return 'breakglass/' . $shards . '/' . KvDoc::shardOf($holder, $shards);
    }

    /** Writes a raw shard document (and the pinned shard count) into a fresh store. @return array{0:MemoryLeaseKv,1:string} */
    private static function seed(array $ids, string $holder = 'h1'): array
    {
        $kv = new MemoryLeaseKv();
        $kv->update('breakglass/meta', static fn(): string => '{"shards":16,"v":1}');
        $raw = (string)json_encode(['holders' => [$holder => $ids]]);
        $kv->update(self::shardKey($holder), static fn(): string => $raw);
        return [$kv, $raw];
    }

    private static function entry(array $recOver = [], array $uses = [], mixed $review = null): array
    {
        return ['rec' => self::grantBody($recOver), 'uses' => $uses, 'review' => $review];
    }

    private static function reg(AtomicKv $kv, array $policy = ['authorities' => ['auth'], 'reviewers' => ['rev']], array $opts = []): BreakGlassRegistry
    {
        return new BreakGlassRegistry($policy, $kv, $opts);
    }

    private const UNKNOWN = ['decision' => 'deny', 'code' => 'unknown_break_glass', 'id' => 'bg1'];

    public function testTheShardKeyAndMetaPinAreUsedExactly(): void
    {
        [$ask, $apk] = self::key("\x01");
        $grant = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk]), $ask);
        foreach ([[16, []], [3, ['shards' => 3]]] as [$n, $opts]) {
            $inner = new MemoryAtomicKv();
            $log = new \ArrayObject();
            $kv = new class($inner, $log) implements AtomicKv {
                public function __construct(private MemoryAtomicKv $m, private \ArrayObject $log) {}
                public function get(string $key): ?string
                {
                    return $this->m->get($key);
                }
                public function update(string $key, callable $fn): void
                {
                    $this->log->append($key);
                    $this->m->update($key, $fn);
                }
            };
            $reg = self::reg($kv, ['authorities' => [$apk], 'reviewers' => []], $opts);
            self::assertSame(['ok' => true, 'replaced' => true], $reg->accept($grant, 1000));
            self::assertSame(['breakglass/meta', 'breakglass/' . $n . '/' . KvDoc::shardOf('h1', $n)], $log->getArrayCopy());
            // the pin is read once for the registry, not once per operation
            $reg->use('bg1', 'h1', 'd', 2000, true);
            $reg->frozen('h1', 2000);
            self::assertSame(['breakglass/meta', 'breakglass/' . $n . '/' . KvDoc::shardOf('h1', $n), 'breakglass/' . $n . '/' . KvDoc::shardOf('h1', $n)], $log->getArrayCopy());
        }
    }

    public function testMalformedStoredDocumentsLoadAsEmpty(): void
    {
        foreach ([
            ['holders' => 5],
            ['holders' => ['h1' => 5]],
        ] as $doc) {
            $kv = new MemoryLeaseKv();
            $kv->update('breakglass/meta', static fn(): string => '{"shards":16,"v":1}');
            $kv->update(self::shardKey('h1'), static fn(): string => (string)json_encode($doc));
            self::assertSame(self::UNKNOWN, self::reg($kv)->use('bg1', 'h1', 'd', 2000, true));
        }
        foreach ([5, ['rec' => 5, 'uses' => []], ['rec' => self::grantBody(), 'uses' => 5]] as $bad) {
            [$kv] = self::seed(['bg1' => $bad]);
            self::assertSame(self::UNKNOWN, self::reg($kv)->use('bg1', 'h1', 'd', 2000, true));
        }
        // a bad entry is skipped, the good one after it still loads
        [$kv] = self::seed(['a' => 5, 'bg1' => self::entry()]);
        self::assertSame(['decision' => 'allow', 'id' => 'bg1', 'use' => 1, 'remaining' => 1, 'review_due' => 7000], self::reg($kv)->use('bg1', 'h1', 'd', 2000, true));
    }

    public function testStoredUsesAreFilteredAndNormalised(): void
    {
        $use = ['n' => 1, 'action_digest' => 'd', 'at' => 2000];
        [$kv] = self::seed(['bg1' => self::entry([], [5, $use])]);
        $reg = self::reg($kv);
        self::assertFalse($reg->frozen('h1', 6000), 'the non-object use is dropped and the list re-indexed');
        self::assertSame(['decision' => 'allow', 'id' => 'bg1', 'use' => 2, 'remaining' => 0, 'review_due' => 7000], $reg->use('bg1', 'h1', 'd2', 6000, true));

        // a stored use without a time reads as 0
        [$kv] = self::seed(['bg1' => self::entry([], [['n' => 1, 'action_digest' => 'd']])]);
        self::assertSame(['decision' => 'allow', 'id' => 'bg1', 'use' => 2, 'remaining' => 0, 'review_due' => 5000], self::reg($kv)->use('bg1', 'h1', 'd2', 2000, true));

        // a stored review that is not an object is no review
        [$kv] = self::seed(['bg1' => self::entry([], [], 5)]);
        self::assertFalse(self::reg($kv)->frozen('h1', 0));
    }

    public function testUsesAreRewrittenAsIntegersWithTheirNumber(): void
    {
        [$kv] = self::seed(['bg1' => self::entry([], [['n' => 1, 'action_digest' => 'd', 'at' => 1500.7]])]);
        self::assertSame('allow', self::reg($kv)->use('bg1', 'h1', 'd2', 2000, true)['decision']);
        $d = json_decode((string)$kv->get(self::shardKey('h1')), true);
        self::assertSame([['action_digest' => 'd', 'at' => 1500, 'n' => 1], ['action_digest' => 'd2', 'at' => 2000, 'n' => 2]], $d['holders']['h1']['bg1']['uses']);
    }

    public function testEveryHolderOfAShardSurvivesAnUpdate(): void
    {
        [$ask, $apk] = self::key("\x01");
        $kv = new MemoryLeaseKv();
        $reg = self::reg($kv, ['authorities' => [$apk], 'reviewers' => []], ['shards' => 1]);
        $g1 = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk]), $ask);
        $g2 = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk, 'id' => 'bg2', 'holder' => 'h2']), $ask);
        self::assertSame(['ok' => true, 'replaced' => true], $reg->accept($g1, 1000));
        self::assertSame(['ok' => true, 'replaced' => true], $reg->accept($g2, 1000));
        self::assertSame('allow', $reg->use('bg1', 'h1', 'd', 2000, true)['decision']);
        self::assertSame(['decision' => 'allow', 'id' => 'bg2', 'use' => 1, 'remaining' => 1, 'review_due' => 7000], $reg->use('bg2', 'h2', 'd', 2000, true));
    }

    public function testAMismatchedShardCountFailsClosed(): void
    {
        [$ask, $apk] = self::key("\x01");
        [$rsk, $rpk] = self::key("\x02");
        $kv = new MemoryLeaseKv();
        $kv->update('breakglass/meta', static fn(): string => '{"shards":8,"v":1}');
        $reg = self::reg($kv, ['authorities' => [$apk], 'reviewers' => [$rpk]]);
        $grant = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk]), $ask);
        $review = self::signed(BreakGlass::REVIEW_DOMAIN, self::reviewBody(['reviewer' => $rpk]), $rsk);
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept($grant, 1000));
        self::assertSame(['decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'bg1'], $reg->use('bg1', 'h1', 'd', 2000, true));
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->review($review, 'h1', 2000));
        self::assertTrue($reg->frozen('h1', 2000));
    }

    public function testAStoreThatDropsUpdatesAnswersStoreUnreachable(): void
    {
        [$ask, $apk] = self::key("\x01");
        [$rsk, $rpk] = self::key("\x02");
        $kv = new class implements AtomicKv {
            public function get(string $key): ?string
            {
                return $key === 'breakglass/meta' ? '{"shards":16,"v":1}' : null;
            }
            public function update(string $key, callable $fn): void {}
        };
        $reg = self::reg($kv, ['authorities' => [$apk], 'reviewers' => [$rpk]]);
        $grant = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk]), $ask);
        $review = self::signed(BreakGlass::REVIEW_DOMAIN, self::reviewBody(['reviewer' => $rpk]), $rsk);
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->accept($grant, 1000));
        self::assertSame(['decision' => 'deny', 'code' => 'store_unreachable', 'id' => 'bg1'], $reg->use('bg1', 'h1', 'd', 2000, true));
        self::assertSame(['ok' => false, 'code' => 'store_unreachable'], $reg->review($review, 'h1', 2000));
    }

    public function testRefusedOperationsNeverRewriteTheStore(): void
    {
        [$ask, $apk] = self::key("\x01");
        [$rsk, $rpk] = self::key("\x02");
        $grant = self::signed(BreakGlass::DOMAIN, self::grantBody(['authority' => $apk]), $ask);
        $review = self::signed(BreakGlass::REVIEW_DOMAIN, self::reviewBody(['reviewer' => $rpk]), $rsk);
        $policy = ['authorities' => [$apk], 'reviewers' => [$rpk]];
        $use1 = ['n' => 1, 'action_digest' => 'd', 'at' => 3000];

        $cases = [
            // accept: the same record again
            'accept replay' => [['bg1' => ['rec' => self::arr($grant), 'uses' => [], 'review' => null], 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->accept($grant, 1000), ['ok' => true, 'replaced' => false]],
            // accept: the holder is frozen by an unreviewed use
            'accept frozen' => [['bg0' => self::entry(['id' => 'bg0'], [['n' => 1, 'action_digest' => 'd', 'at' => 1000]]), 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->accept($grant, 7000), ['ok' => false, 'code' => 'holder_frozen']],
            // use: unknown grant
            'use unknown' => [['bg0' => self::entry(['id' => 'bg0']), 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->use('bg1', 'h1', 'd', 2000, true), self::UNKNOWN],
            // review: unknown grant
            'review unknown' => [['bg0' => self::entry(['id' => 'bg0']), 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->review($review, 'h1', 2000), ['ok' => false, 'code' => 'unknown_break_glass']],
            // review: the reviewer is the grant's authority
            'review sod' => [['bg1' => self::entry(['authority' => $rpk], [$use1]), 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->review($review, 'h1', 4000), ['ok' => false, 'code' => 'sod']],
            // review: already reviewed with the same review
            'review replay' => [['bg1' => self::entry([], [$use1], self::arr($review)), 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->review($review, 'h1', 4000), ['ok' => true, 'replaced' => false]],
            // review: nothing was used
            'review nothing' => [['bg1' => self::entry(), 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->review($review, 'h1', 4000), ['ok' => false, 'code' => 'nothing_to_review']],
            // review: before the first use
            'review bad time' => [['bg1' => self::entry([], [$use1]), 'junk' => 5],
                static fn(BreakGlassRegistry $r) => $r->review($review, 'h1', 4000), ['ok' => false, 'code' => 'bad_time']],
        ];
        foreach ($cases as $name => [$ids, $op, $expect]) {
            [$kv, $raw] = self::seed($ids);
            self::assertSame($expect, $op(self::reg($kv, $policy)), $name);
            self::assertSame($raw, $kv->get(self::shardKey('h1')), "$name leaves the stored document byte for byte");
        }
    }
}
