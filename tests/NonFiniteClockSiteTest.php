<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\K3;
use Atlas\Pca\KeyPair;
use Atlas\Pca\KvDoc;
use Atlas\Pca\Json;
use Atlas\Pca\Lease;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\MemoryAtomicKv;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PlanRegistry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A NaN or infinite clock or revision is never read as 0 (a null sentinel coerced to zero is epoch 0, which is before every expiry):
 * the lease revocation prune keeps its revocations, a plan whose approval has an expiry is not executable, and a pinned last revision
 * that is not a finite number is refused as a rollback.
 */
final class NonFiniteClockSiteTest extends TestCase
{
    /** @return list<array{float}> */
    public static function nonFinite(): array
    {
        return [[NAN], [INF], [-INF]];
    }

    private static function revocation(string $value, int $at, KeyPair $k): Obj
    {
        $o = Obj::of(['v' => new Num('1'), 'target' => 'lease', 'value' => $value, 'revoked_at' => new Num((string)$at), 'authority' => $k->public]);
        $o->set('sig', Pca::b64u($k->sign(Lease::REVOKE_DOMAIN . Json::canonicalizeStrict($o))));
        return $o;
    }

    #[DataProvider('nonFinite')]
    public function testLeasePruneKeepsRevocationsOnANonFiniteClock(float $now): void
    {
        $a = new KeyPair(str_repeat(chr(1), 32));
        $kv = new MemoryAtomicKv();
        $old = self::revocation('x1', 9899, $a); // 9899 + 100 < 10000: pruned by a finite clock
        $key = 'lease/16/' . KvDoc::shardOf('L1', 16);
        $kv->update($key, static fn(?string $prev): string => '{"leases":{},"revocations":[' . KvDoc::enc($old) . ']}');
        $reg = new LeaseRegistry(['authorities' => [$a->public], 'maxTtlCeiling' => 100], $kv, ['clock' => static fn(): float => $now]);
        $third = self::revocation('L1', 10000, $a);
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($third));
        $raw = json_decode((string)$kv->get($key), true);
        $this->assertSame([$old->get('sig'), $third->get('sig')], array_column($raw['revocations'], 'sig')); // was: every revocation dropped
    }

    public function testLeasePruneStillDropsAnExpiredRevocationOnAFiniteClock(): void
    {
        $a = new KeyPair(str_repeat(chr(1), 32));
        $kv = new MemoryAtomicKv();
        $old = self::revocation('x1', 9899, $a);
        $key = 'lease/16/' . KvDoc::shardOf('L1', 16);
        $kv->update($key, static fn(?string $prev): string => '{"leases":{},"revocations":[' . KvDoc::enc($old) . ']}');
        $reg = new LeaseRegistry(['authorities' => [$a->public], 'maxTtlCeiling' => 100], $kv, ['clock' => static fn(): int => 10000]);
        $third = self::revocation('L1', 10000, $a);
        $this->assertSame(['ok' => true, 'revoked' => 0], $reg->revoke($third));
        $raw = json_decode((string)$kv->get($key), true);
        $this->assertSame([$third->get('sig')], array_column($raw['revocations'], 'sig'));
    }

    /** @return list<array{mixed, string}> a pinned last revision that is not a finite number, and how the refusal names it */
    public static function badLastRevisions(): array
    {
        return [
            [new Num('1e999'), 'Infinity'], [new Num('-1e999'), '-Infinity'], [INF, 'Infinity'], [-INF, '-Infinity'], [NAN, 'NaN'],
            ['x', 'x'], [null, 'null'], [true, 'true'], [[1], '[1]'],
        ];
    }

    #[DataProvider('badLastRevisions')]
    public function testVerifyBundleRefusesAPinnedLastRevisionThatIsNotFinite(mixed $lastRevision, string $named): void
    {
        $kp = sodium_crypto_sign_seed_keypair(str_repeat(chr(3), 32));
        $pk = Pca::b64u(sodium_crypto_sign_publickey($kp));
        $b = Obj::of(['v' => new Num('1'), 'kind' => 'pca-policy-bundle', 'revision' => new Num('1'), 'issued_at' => new Num('100'),
            'grants' => ['g'], 'template_digests' => [], 'min_verifier_version' => '1.0']);
        $b->set('sigs', [Obj::of(['signer' => $pk, 'sig' => Pca::b64u(sodium_crypto_sign_detached(K3::BUNDLE_DOMAIN . Json::canonicalizeStrict($b), sodium_crypto_sign_secretkey($kp)))])]);
        $o = Obj::of(['signers' => [$pk], 'threshold' => new Num('1'), 'verifierVersion' => '1.0']);
        $this->assertTrue(K3::verifyBundle($b, $o)['ok']);
        $o->set('last', Obj::of(['revision' => $lastRevision, 'digest' => 'd']));
        // was: the check was skipped, so any rollback was accepted
        $this->assertSame(['ok' => false, 'code' => 'rollback', 'reason' => 'revision 1 < accepted ' . $named], K3::verifyBundle($b, $o));
    }

    #[DataProvider('nonFinite')]
    public function testAPlanWithAnApprovalExpiryIsNotExecutableOnANonFiniteClock(float $bad): void
    {
        $t = 1000.0;
        $reg = new PlanRegistry(null, 'pca-plan:', static function () use (&$t) {
            return $t;
        });
        $d = $reg->draft('g', [['id' => 'n1', 'verb' => 'orders.read', 'resource' => '/orders/1']]);
        $this->assertTrue($d['ok']);
        $root = $d['record']->get('root');
        $this->assertTrue($reg->validate('g', $root)['ok']);
        $this->assertTrue($reg->commit('g', $root)['ok']);
        $this->assertTrue($reg->authorize('g', $root, ['by' => 'p', 'expiresAt' => 5000])['ok']);
        $this->assertTrue($reg->isPlanAuthorized('g', $root)); // a finite clock before the expiry
        $t = $bad;
        $this->assertFalse($reg->isPlanAuthorized('g', $root)); // was: the int cast read the clock as epoch 0, before the expiry
        $this->expectException(\InvalidArgumentException::class);
        $reg->status('g', $root);
    }
}
