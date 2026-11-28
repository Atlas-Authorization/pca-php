<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AdmissionRegistry;
use Atlas\Pca\BlueprintRegistry;
use Atlas\Pca\DecisionLog;
use Atlas\Pca\FreshAtIssuer;
use Atlas\Pca\Grants;
use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\LeaseRegistry;
use Atlas\Pca\MemoryBlueprintStore;
use Atlas\Pca\MemoryLeaseKv;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 1 survivors of src/Grants.php: bundle shadows, masking, Merkle proofs, freshness tokens, lease renewal, admission, the decision log. */
final class CoreSurvivorKill1GrantsTest extends TestCase
{
    private static function key(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/' . $label, true));
    }

    /** copy() of a non-object is empty; a secret that is not a KeyPair is refused with its own TypeError. */
    public function testCopyAndKeyGuards(): void
    {
        self::assertSame([], Grants::copy('x')->keys());
        self::assertSame([], Grants::copy(null)->keys());
        try {
            Grants::signerOf('x');
            self::fail('expected a TypeError');
        } catch (\TypeError $e) {
            self::assertSame('expected a KeyPair secret key', $e->getMessage());
        }
    }

    private static function bundle(): Obj
    {
        return Obj::of(['v' => 1, 'kind' => 'pca-policy-bundle', 'revision' => 1, 'issued_at' => 1, 'grants' => [], 'template_digests' => [],
            'min_verifier_version' => '1']);
    }

    private static function shadowed(mixed $s, ?Obj $b = null): Obj
    {
        $b ??= self::bundle();
        $b->set('shadow', $s);
        return $b;
    }

    /** `shadow`: 1 to 16 distinct non-empty strings of at most 128 units; the bundle's own shape error comes first. */
    public function testBundleShadowRules(): void
    {
        self::assertNull(Grants::bundleShapeErrorFull(self::bundle()));
        $sixteen = array_map(static fn(int $i): string => "d$i", range(1, 16));
        self::assertNull(Grants::bundleShapeErrorFull(self::shadowed($sixteen)));
        self::assertSame('bad shadow', Grants::bundleShapeErrorFull(self::shadowed([...$sixteen, 'd17'])));
        self::assertSame('bad shadow', Grants::bundleShapeErrorFull(self::shadowed([5])));
        self::assertNull(Grants::bundleShapeErrorFull(self::shadowed([str_repeat('a', 128)])));
        self::assertSame('bad shadow', Grants::bundleShapeErrorFull(self::shadowed([str_repeat('a', 129)])));
        self::assertSame('bad shadow', Grants::bundleShapeErrorFull(self::shadowed(['a', 'a'])));
        $bad = self::bundle();
        $bad->set('kind', 'x');
        self::assertSame('not a policy bundle', Grants::bundleShapeErrorFull(self::shadowed(['a', 'a'], $bad)));
        try {
            Grants::signBundle($bad, self::key('op'));
            self::fail('expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('signBundle: not a policy bundle', $e->getMessage());
        }
    }

    /** Masking reads a list detail by index, and only an object `classes` names classes. */
    public function testMaskRecordDetailForms(): void
    {
        $m = Grants::maskRecord(Obj::of(['detail' => ['a', 'b'], 'classes' => Obj::of(['0' => 'pii'])]), ['pii']);
        $d = $m->get('detail');
        self::assertSame(['0', '1'], $d->keys());
        self::assertStringStartsWith('masked:pii:', $d->get('0'));
        self::assertSame('b', $d->get('1'));
        $m = Grants::maskRecord(Obj::of(['detail' => Obj::of(['a' => 'x']), 'classes' => ['a' => 'pii']]), ['pii']);
        self::assertSame('x', $m->get('detail')->get('a'));
    }

    /** merkleProof: a non-number index is out of range; leaf keys are ignored; the caller's Num index is returned as given; -0 is 0. */
    public function testMerkleProofInputs(): void
    {
        try {
            Grants::merkleProof(['a', 'b'], 'x');
            self::fail('expected RangeException');
        } catch (\RangeException $e) {
            self::assertSame('merkleProof: index out of range', $e->getMessage());
        }
        self::assertSame(Json::canonicalizeStrict(Grants::merkleProof(['x', 'y'], 0)),
            Json::canonicalizeStrict(Grants::merkleProof(['a' => 'x', 'b' => 'y'], 0)));
        $idx = new Num('1.0');
        self::assertSame($idx, Grants::merkleProof(['x', 'y'], $idx)->get('index'));
        self::assertSame('0', Grants::merkleProof(['x', 'y'], -0.0)->get('index')->lexeme);
    }

    /** Small helpers: gt needs both numbers, deepCopy copies nested objects inside lists, isSafeInt is public. */
    public function testSmallHelpers(): void
    {
        self::assertFalse(Grants::gt(1, null));
        self::assertFalse(Grants::gt(null, 1));
        self::assertTrue(Grants::gt(2, 1));
        $inner = Obj::of(['a' => 'x']);
        $copy = Grants::deepCopy([$inner]);
        $inner->set('a', 'changed');
        self::assertSame('x', $copy[0]->get('a'));
        self::assertTrue(Grants::isSafeInt(5));
        self::assertFalse(Grants::isSafeInt(1.5));
        self::assertSame('allow', Grants::gateDecision('allow', null));
    }

    private static function state(string $digest = 'pd'): Obj
    {
        return Obj::of(['revocation_epoch' => 0, 'ledger_tree_size' => 0, 'budget_version' => 0, 'policy_revision' => 0, 'policy_digest' => $digest]);
    }

    /** signFreshAt bounds: scope up to 256 units, policy_digest up to 128; a non-object state is a malformed state. */
    public function testSignFreshAtBounds(): void
    {
        $k = self::key('iss');
        $t = Grants::signFreshAt($k, str_repeat('s', 256), self::state(str_repeat('d', 128)), 1);
        self::assertSame(str_repeat('s', 256), $t->get('scope'));
        foreach ([[str_repeat('s', 257), self::state()], ['s', self::state(str_repeat('d', 129))], ['s', 'x']] as [$scope, $st]) {
            try {
                Grants::signFreshAt($k, $scope, $st, 1);
                self::fail('expected InvalidArgumentException');
            } catch (\InvalidArgumentException $e) {
                self::assertSame('signFreshAt: a malformed state', $e->getMessage());
            }
        }
    }

    /** mergeFreshAt: equal counters keep `$a`'s value; a non-object state is refused with its own message. */
    public function testMergeFreshAt(): void
    {
        $a = Obj::of(['revocation_epoch' => new Num('1'), 'ledger_tree_size' => new Num('1'), 'budget_version' => new Num('1'), 'policy_revision' => new Num('1'), 'policy_digest' => 'pa']);
        $b = Obj::of(['revocation_epoch' => new Num('1.0'), 'ledger_tree_size' => new Num('1.0'), 'budget_version' => new Num('1.0'), 'policy_revision' => new Num('1.0'), 'policy_digest' => 'pb']);
        $m = Grants::mergeFreshAt($a, $b);
        foreach (['revocation_epoch', 'ledger_tree_size', 'budget_version', 'policy_revision'] as $k) {
            self::assertSame($a->get($k), $m->get($k), $k);
        }
        self::assertSame('pa', $m->get('policy_digest'));
        try {
            Grants::mergeFreshAt('x', $b);
            self::fail('expected InvalidArgumentException');
        } catch (\InvalidArgumentException $e) {
            self::assertSame('freshAt: revocation_epoch is not a number', $e->getMessage());
        }
    }

    /** FreshAtIssuer::advance with no patch re-signs the current state. */
    public function testAdvanceWithoutPatch(): void
    {
        $iss = new FreshAtIssuer(self::key('iss'), 'scope', self::state());
        $t = $iss->advance(null, 5);
        self::assertSame('scope', $t->get('scope'));
        self::assertSame(0, $t->get('revocation_epoch'));
    }

    /** @return array{0:KeyPair,1:LeaseRegistry} */
    private static function leased(int $maxTtl = 10000, int $expires = 2000): array
    {
        $a = self::key('authority');
        $reg = new LeaseRegistry(['authorities' => [$a->public]], new MemoryLeaseKv());
        $l = Obj::of(['lease_id' => 'L1', 'path' => 'p', 'grant_ref' => 'g', 'holder' => 'h', 'requester' => 'r', 'approvers' => ['ap'],
            'justification_digest' => 'j0', 'seq' => 1, 'issued_at' => 1000, 'renewed_at' => 1000, 'expires_at' => $expires, 'max_ttl' => $maxTtl]);
        self::assertTrue($reg->accept(Grants::signLease($a, $l))['ok']);
        return [$a, $reg];
    }

    /** renewLease: input checked first, a veto is a whole refusal, the delegation chain reaches the registry, the record's counters are ints. */
    public function testRenewLease(): void
    {
        [$a, $reg] = self::leased();
        self::assertSame(['ok' => false, 'code' => 'bad_input'], Grants::renewLease($a, $reg, 'nope', 'x', 1000, 'j1'));
        self::assertSame(['ok' => false, 'code' => 'vetoed'], Grants::renewLease($a, $reg, 'L1', 1500, 1000, 'j1', null, static fn(Obj $c): bool => true));
        self::assertSame(['ok' => false, 'code' => 'sod'], Grants::renewLease($a, $reg, 'L1', 1500, 1000, 'j1', null, null, ['ap']));
        $r = Grants::renewLease($a, $reg, 'L1', 1500, 1000, 'j1');
        self::assertTrue($r['ok']);
        self::assertSame(2, $r['record']->get('seq'));
        self::assertSame(2500, $r['record']->get('expires_at'));
    }

    /** A renewal at exactly the cap has no time left: expired_lease, not bad_input. */
    public function testRenewalAtTheCapIsExpired(): void
    {
        [$a, $reg] = self::leased(1000, 2000);
        self::assertSame(['ok' => false, 'code' => 'expired_lease'], Grants::renewLease($a, $reg, 'L1', 2000, 1000, 'j1'));
    }

    /** groupKill signs the next epoch as an integer. */
    public function testGroupKillEpochIsAnInteger(): void
    {
        $op = self::key('op');
        $reg = new BlueprintRegistry([$op->public], new MemoryBlueprintStore());
        $bp = Grants::signBlueprint($op, Obj::of(['id' => 'bp1', 'key' => 'k1', 'epoch' => 1, 'issued_at' => 1, 'status' => 'active', 'ceiling' => []]));
        self::assertTrue($reg->accept($bp)['ok']);
        $r = Grants::groupKill($op, $reg, 'k1', 5);
        self::assertTrue($r['ok']);
        self::assertSame(2, $r['record']->get('epoch'));
    }

    /** Admission needs a non-empty pin list and evidence; the verifier gets every input; ok, bound, measured and reason are carried. */
    public function testBlueprintAdmission(): void
    {
        $noPins = ['admitted' => false, 'code' => 'no_pins'];
        $v = static fn(array $i): array => ['ok' => true, 'bound' => true, 'measured' => Obj::of(['a' => '1'])];
        foreach (['x', [], null] as $pins) {
            $bp = Obj::of(['runtime_pins' => $pins]);
            self::assertSame($noPins, Grants::admitBlueprintInstance($bp, 'doc', $v, 5));
            self::assertSame($noPins, Grants::admitWithEvidence($bp, static fn(): array => []));
        }
        $pin = Obj::of(['a' => '1']);
        $bp = Obj::of(['runtime_pins' => [$pin]]);
        self::assertSame(['admitted' => false, 'code' => 'not_ok', 'reason' => 'no evidence'], Grants::admitBlueprintInstance($bp, null, $v, 5));
        $seen = null;
        $measured = Obj::of(['a' => '1']);
        $r = Grants::admitBlueprintInstance($bp, 'doc', static function (array $i) use (&$seen, $measured): array {
            $seen = $i;
            return ['ok' => true, 'bound' => true, 'measured' => $measured];
        }, 5, 'c', 'e');
        self::assertSame(['document' => 'doc', 'ctx' => 'c', 'nowMs' => 5, 'expected' => 'e'], $seen);
        self::assertSame(['admitted' => true, 'identity' => $measured, 'pin' => $pin], $r);
        self::assertSame(['admitted' => false, 'code' => 'not_ok', 'reason' => 'boom'],
            Grants::admitBlueprintInstance($bp, 'doc', static fn(array $i): array => ['ok' => false, 'reason' => 'boom'], 5));
        self::assertSame(['admitted' => false, 'code' => 'not_bound'],
            Grants::admitBlueprintInstance($bp, 'doc', static fn(array $i): array => ['ok' => true, 'measured' => $measured], 5));
    }

    /** The admission key separates the blueprint key from the instance key: no concatenation collides. */
    public function testAdmissionKeysDoNotCollide(): void
    {
        $adm = new AdmissionRegistry();
        $bp = static fn(string $k): Obj => Obj::of(['key' => $k, 'epoch' => new Num('1')]);
        $adm->admit('b', $bp('a'), new Num('100'));
        $check = $adm->checker(5);
        self::assertTrue($check('b', $bp('a')));
        self::assertFalse($check('', $bp('ab')));
        self::assertFalse($check('b', $bp('other')));
        self::assertTrue($adm->revoke('b', 'a'));
    }

    /** The decision log exposes its signer and slices by [start, end), empty when end <= start. */
    public function testDecisionLogSlice(): void
    {
        $k = self::key('log');
        $log = new DecisionLog($k);
        self::assertSame($k->public, $log->signer());
        foreach (['a', 'b', 'c'] as $x) {
            $log->append(Obj::of(['decision' => $x]));
        }
        self::assertSame([], $log->slice(1, 0));
        self::assertSame([], $log->slice(1, 1));
        self::assertCount(2, $log->slice(0, 2));
    }
}
