<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Authorize;
use Atlas\Pca\AuthorizeResult;
use Atlas\Pca\Json;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\RevocationState;
use Atlas\Pca\RevocationStaleness;
use Atlas\Pca\RevocationStalenessPolicy;
use PHPUnit\Framework\TestCase;

/**
 * Revocation staleness (T9): the shared staleness-vectors.json (max_age, effective_reversibility, age, epoch, gate, membership, gate_ids), the
 * policy / epoch edge cases, and the Authorize wiring (`freshness`). A missing vector file fails the test.
 */
final class RevocationStalenessTest extends TestCase
{
    private const SEED = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";

    public function testSharedVectors(): void
    {
        [$n, $fails] = NativeParityVectors::staleness();
        $this->assertSame([], $fails);
        $this->assertSame(136, $n); // 99 freshness rows + 27 membership + 10 gate_ids
    }

    public function testInvalidPolicyRefusedAndGateClosed(): void
    {
        $bad = [
            'zero' => new RevocationStalenessPolicy(0.0),
            'negative' => new RevocationStalenessPolicy(null, ['irreversible' => -1.0]),
            'nan' => new RevocationStalenessPolicy(null, ['costly' => NAN]),
            'infinite' => new RevocationStalenessPolicy(INF),
            'not-number' => RevocationStalenessPolicy::fromJson(Obj::of(['maxRevocationAgeMs' => '300000'])),
        ];
        foreach ($bad as $name => $p) {
            $this->assertNotNull($p->validate(), $name);
            $r = RevocationStaleness::gate(['policy' => $p, 'now' => 1, 'root' => 'r', 'rootIssuedAt' => 1.0, 'signedClass' => 'reversible']);
            $this->assertFalse($r['ok'], "$name: the gate opened under an invalid policy");
        }
        $this->assertFalse((new RevocationStalenessPolicy())->on());
    }

    public function testEpochSuitesUnderPins(): void
    {
        $ep = RevocationStaleness::signEpoch(self::SEED, ['instance_id' => 'i', 'grant_ref' => 'g1', 'epoch' => 0, 'set_size' => 0,
            'root' => 'r', 'issued_at' => 1000, 'not_after' => 2000]);
        $o = ['guardianPublic' => $ep->get('guardian'), 'now' => 1500];
        $this->assertTrue(RevocationStaleness::checkEpoch($ep, $o)['ok']);
        $mut = static function (string $k, mixed $v) use ($ep): Obj {
            $m = Obj::of([]);
            foreach ($ep->keys() as $a) {
                $m->set($a, $ep->get($a));
            }
            $m->set($k, $v);
            return $m;
        };
        $r = RevocationStaleness::checkEpoch($mut('root', 'other'), $o);
        $this->assertSame([false, 'revocation epoch signature invalid'], [$r['ok'], $r['reason']]);
        $this->assertFalse(RevocationStaleness::checkEpoch($mut('alg', 'ml-dsa-65'), $o)['ok'], 'a PQ suite without a pin');
        $pinned = $o + ['pins' => [$o['guardianPublic'] => 'AAAA']];
        $this->assertFalse(RevocationStaleness::checkEpoch($mut('alg', 'ml-dsa-65'), $pinned)['ok'], 'a pq_pk that is not the pinned key');
        $r = RevocationStaleness::checkEpoch($mut('alg', 'no-such-suite'), $o);
        $this->assertSame('revocation epoch not signed by the pinned guardian', $r['reason']);
        $r = RevocationStaleness::checkEpoch(new Obj(), $o);
        $this->assertSame('revocation epoch not signed by the pinned guardian', $r['reason']);
        $this->expectException(\InvalidArgumentException::class);
        RevocationStaleness::signEpoch("\x01", []);
    }

    // ---- Authorize wiring

    /** @param callable(int,string):?RevocationState|null $state */
    private function authorizeWith(?RevocationStalenessPolicy $policy, ?callable $state, int $ageMs): AuthorizeResult
    {
        $fix = Json::parseLax(file_get_contents(__DIR__ . '/../test-data/authorize-fixtures.json'));
        $c = $fix->get('cases')[0]; // signed class irreversible
        $s = $c->get('steps')[0];
        $now = $fix->get('now')->int();
        $grantRef = $s->get('pcactn')->get('grant_ref');
        $probe = RevocationStaleness::signEpoch(self::SEED, ['instance_id' => 'i', 'grant_ref' => 'g', 'epoch' => 0, 'set_size' => 0,
            'root' => 'root', 'issued_at' => 0, 'not_after' => 1]);
        $hook = $state === null ? null : function (Obj $p, Obj $g) use ($state, $ageMs, $now, $grantRef): ?RevocationState {
            $st = $state($ageMs, 'root');
            if ($st !== null && $st->epoch !== null) {
                $st = new RevocationState(RevocationStaleness::signEpoch(self::SEED, ['instance_id' => 'i', 'grant_ref' => $grantRef,
                    'epoch' => 0, 'set_size' => 0, 'root' => 'root', 'issued_at' => $now - $ageMs, 'not_after' => $now + 600000]));
            }
            return $st;
        };
        return Authorize::authorize($s->get('pcactn'), $s->get('operation'), $fix->get('audience'), fn ($r) => $c->get('grant'),
            new MemoryStateStore(), fn ($p, $g) => false, $now, 'single-step', null, null, null, null, [], null, null,
            $policy, $hook, $probe->get('guardian'), provenance: ProvHarness::bundle($s->get('operation')), provenanceMediators: [ProvHarness::pin()]);
    }

    public function testAuthorizeRevocationStalenessIrreversible(): void
    {
        $on = new RevocationStalenessPolicy(300000.0, null, false, fn (): array => []); // freshness only
        $epoch = fn (int $age, string $root): ?RevocationState => new RevocationState(new Obj());
        $r = $this->authorizeWith($on, $epoch, 30000);
        $this->assertTrue($r->allow, (string)$r->reason);
        $this->assertSame('pass', $r->checks['freshness']);
        $r = $this->authorizeWith($on, $epoch, 180000);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertStringContainsString("revocation epoch is 180000 ms old, over the verifier's maximum of 120000 ms", (string)$r->reason);
        $root = fn (int $age, string $root): ?RevocationState => new RevocationState(null, 'root', 1.0);
        $r = $this->authorizeWith($on, $root, 0);
        $this->assertFalse($r->allow);
        $this->assertStringContainsString('unsigned revocation root refused for an irreversible action', (string)$r->reason);
        $r = $this->authorizeWith($on, fn (int $a, string $b): ?RevocationState => null, 0);
        $this->assertFalse($r->allow);
        $this->assertStringContainsString('no verifiable (guardian-signed) revocation state', (string)$r->reason);
        // a throwing state source denies
        $r = $this->authorizeWith($on, function (): ?RevocationState { throw new \RuntimeException('down'); }, 0);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['freshness']);
        // off (null or empty policy): unchanged behaviour, no freshness check
        $r = $this->authorizeWith(null, null, 0);
        $this->assertTrue($r->allow);
        $this->assertFalse(isset($r->checks['freshness']));
        $this->assertTrue($this->authorizeWith(new RevocationStalenessPolicy(), null, 0)->allow);
    }

    public function testAuthorizeEveryChainCapabilityNeedsAProof(): void
    {
        $epoch = fn (int $age, string $root): ?RevocationState => new RevocationState(new Obj());
        // default ids = the cap_chain; no proof source: denied
        $r = $this->authorizeWith(new RevocationStalenessPolicy(300000.0), $epoch, 30000);
        $this->assertFalse($r->allow);
        $this->assertSame('fail', $r->checks['freshness']);
        $this->assertStringContainsString('no non-membership proof for ', (string)$r->reason);
        // a proof that does not fold to the epoch root: denied
        $bad = new RevocationStalenessPolicy(300000.0, null, false, null, fn (string $id, Obj $p): Obj => Obj::of(['size' => new Num('0')]));
        $r = $this->authorizeWith($bad, $epoch, 30000);
        $this->assertFalse($r->allow);
        $this->assertStringContainsString(' is revoked or proof invalid', (string)$r->reason);
        $this->assertNotNull((new RevocationStalenessPolicy(null, null, false, 5))->validate());
    }

    public function testAuthorizeRevocationStalenessMisconfigured(): void
    {
        $r = $this->authorizeWith(new RevocationStalenessPolicy(300000.0), null, 0);
        $this->assertFalse($r->allow);
        $this->assertSame(403, $r->status);
        $this->assertCount(1, $r->missing);
        $this->assertStringContainsString('revocationState', $r->missing[0]);
        $bad = $this->authorizeWith(new RevocationStalenessPolicy(-1.0), fn (int $a, string $b): ?RevocationState => null, 0);
        $this->assertFalse($bad->allow);
        $this->assertCount(1, $bad->missing);
        $this->assertStringContainsString('revocationStaleness', $bad->missing[0]);
    }
}
