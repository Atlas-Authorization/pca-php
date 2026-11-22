<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RevocationState;
use Atlas\Pca\RevocationStaleness;
use Atlas\Pca\RevocationStalenessPolicy;
use PHPUnit\Framework\TestCase;

/**
 * H13: the revocation-epoch rollback pin is automatic. With revocation staleness on, the effective last accepted epoch is the larger of
 * the host's and the pin the state store holds under `<grant id>:epoch`; an allowed action whose freshness passed raises the pin
 * (monotone); a denied action never does; a store that cannot hold pins is refused.
 */
final class K05HardEpochPinTest extends TestCase
{
    private const SEED = "\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d";

    private Obj $fix;
    private Obj $grant;
    private Obj $p;
    private Obj $op;
    private int $now;

    protected function setUp(): void
    {
        $this->fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        foreach ($this->fix->get('cases') as $c) {
            if ($c->get('name') === 'envelope-max-spend-within') {
                $this->grant = $c->get('grant');
                $this->p = $c->get('steps')[0]->get('pcactn');
                $this->op = $c->get('steps')[0]->get('operation');
            }
        }
        $this->now = $this->fix->get('now')->int();
        $all = ['wire', 'version', 'audience', 'validity', 'chain', 'grant_ref_bound', 'plan_inclusion', 'leaf_signature', 'counter_format'];
        Authorize::$coreHook = static fn(array $c): array => ['allow' => true, 'checks' => array_fill_keys($all, true), 'reason' => '', 'reasons' => []];
    }

    protected function tearDown(): void
    {
        Authorize::$coreHook = null;
    }

    private static function copy(Obj $o): Obj
    {
        return Json::parseLax(Json::canonicalizeStrict($o));
    }

    private function guardian(): string
    {
        return Pca::b64u(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(self::SEED)));
    }

    private function epoch(int $n): Obj
    {
        return RevocationStaleness::signEpoch(self::SEED, ['instance_id' => 'i', 'grant_ref' => $this->grant->get('id'), 'epoch' => $n, 'set_size' => 0,
            'root' => 'r', 'issued_at' => $this->now - 1000, 'not_after' => $this->now + 1000000]);
    }

    /** One authorize() call: PCActn counter `$counter`, signed epoch `$epoch`, optional host pin, optional wrong operation. */
    private function az(MemoryStateStore $store, int $counter, int $epoch, ?float $hostLast = null, bool $badOp = false): AuthorizeResult
    {
        $p = self::copy($this->p);
        $p->set('counter', new Num((string)$counter));
        // A fresh action anchors its freshness to the current revocation epoch, so the anchor check passes and these
        // vectors isolate the rollback pin; the flagship skips the anchor only when freshness.epoch is absent.
        $p->get('freshness')->set('epoch', new Num((string)$epoch));
        $op = $this->op;
        if ($badOp) {
            $op = self::copy($this->op);
            $op->set('verb', 'other');
        }
        $ep = $this->epoch($epoch);
        $g = $this->grant;
        return Authorize::authorize(pcactn: $p, operation: $op, audience: $this->fix->get('audience'), resolveGrant: static fn($ref) => $g,
            stateStore: $store, isRevoked: static fn() => false, now: $this->now, plan: 'single-step',
            provenance: ProvHarness::bundle($op), provenanceMediators: [ProvHarness::pin()],
            revocationStaleness: new RevocationStalenessPolicy(1000000.0, null, false, static fn() => []),
            revocationState: static fn() => new RevocationState($ep, null, null, $hostLast), guardianPublic: $this->guardian(), hard: CalmRisk::hard());
    }

    private function pinKey(): string
    {
        return $this->grant->get('id') . ':epoch';
    }

    public function testAnOlderEpochIsARollbackWithoutAnyHostPin(): void
    {
        $store = new MemoryStateStore();
        $a = $this->az($store, 1, 5);
        $this->assertTrue($a->allow, implode('; ', $a->reasons));
        $this->assertSame(5, $store->pin($this->pinKey()), 'an allowed action with a passing freshness raises the pin');
        $b = $this->az($store, 2, 4);
        $this->assertFalse($b->allow);
        $this->assertSame('fail', $b->checks['freshness']);
        $this->assertContains('freshness: revocation epoch 4 is older than the last accepted 5 (rollback)', $b->reasons);
        $this->assertSame(5, $store->pin($this->pinKey()), 'a denied action never raises, and never lowers');
        $c = $this->az($store, 3, 6);
        $this->assertTrue($c->allow, implode('; ', $c->reasons));
        $this->assertSame(6, $store->pin($this->pinKey()));
    }

    public function testADeniedActionLeavesThePin(): void
    {
        $store = new MemoryStateStore();
        $this->assertTrue($this->az($store, 1, 5)->allow);
        $d = $this->az($store, 2, 9, null, true);
        $this->assertFalse($d->allow);
        $this->assertSame(5, $store->pin($this->pinKey()));
    }

    public function testTheLargerOfTheHostAndThePinWins(): void
    {
        $store = new MemoryStateStore();
        $this->assertTrue($this->az($store, 1, 5)->allow);
        $r = $this->az($store, 2, 6, 8.0);
        $this->assertFalse($r->allow);
        $this->assertContains('freshness: revocation epoch 6 is older than the last accepted 8 (rollback)', $r->reasons, 'the host pin 8 beats the stored 5');
        $this->assertTrue($this->az($store, 3, 7, 3.0)->allow, 'the stored pin 5 beats the host pin 3 and 7 is newer than both');
        $this->assertSame(7, $store->pin($this->pinKey()));
    }

    public function testTheSameEpochIsNotARollback(): void
    {
        $store = new MemoryStateStore();
        $this->assertTrue($this->az($store, 1, 5)->allow);
        $this->assertTrue($this->az($store, 2, 5)->allow);
    }

    public function testPinsAreMonotone(): void
    {
        $s = new MemoryStateStore();
        $this->assertNull($s->pin('k'));
        $s->raisePin('k', 7);
        $s->raisePin('k', 6);
        $this->assertSame(7, $s->pin('k'));
        $s->raisePin('k', 9);
        $this->assertSame(9, $s->pin('k'));
        $this->assertNull($s->pin('other'));
    }

    public function testAStoreWithoutPinsIsRefused(): void
    {
        $store = new class () {
            public function claim(string $key, int $counter): \Atlas\Pca\ClaimResult
            {
                return new \Atlas\Pca\ClaimResult(true);
            }
        };
        try {
            new AuthorizeOptions($store, static fn() => false, revocationStaleness: new RevocationStalenessPolicy(1000.0), revocationState: static fn() => null);
            $this->fail('accepted');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('revocation staleness needs a state store that implements pins (rollback protection)', $e->getMessage());
        }
        $p = self::copy($this->p);
        $g = $this->grant;
        $r = Authorize::authorize(pcactn: $p, operation: $this->op, audience: $this->fix->get('audience'), resolveGrant: static fn($ref) => $g,
            stateStore: $store, isRevoked: static fn() => false, now: $this->now, plan: 'single-step',
            revocationStaleness: new RevocationStalenessPolicy(1000.0), revocationState: static fn() => null);
        $this->assertFalse($r->allow);
        $this->assertStringContainsString('stateStore.pin/raisePin', $r->reason);
    }
}
