<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\RevocationState;
use Atlas\Pca\RevocationStaleness;
use Atlas\Pca\RevocationStalenessPolicy;
use PHPUnit\Framework\TestCase;

/** Kills the RevocationStaleness.php mutation survivors: policy parsing/validation, maxAgeMs, checkEpoch, signEpoch, gate, freshness. */
final class K05KillRevocationStalenessTest extends TestCase
{
    private const SEED = "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
    private const CHECK_ERROR = ['ok' => false, 'reason' => 'revocation epoch check error'];

    private static function epoch(array $over = []): Obj
    {
        return RevocationStaleness::signEpoch(self::SEED, $over + ['instance_id' => 'i', 'grant_ref' => 'g1', 'epoch' => 5, 'set_size' => 0,
            'root' => 'r', 'issued_at' => 1000, 'not_after' => 2000]);
    }

    /** A copy of `$ep` with `$k` set to `$v` (or dropped when `$drop`). */
    private static function with(Obj $ep, string $k, mixed $v, bool $drop = false): Obj
    {
        $m = new Obj();
        foreach ($ep->keys() as $a) {
            if ($a !== $k) {
                $m->set($a, $ep->get($a));
            }
        }
        if (!$drop) {
            $m->set($k, $v);
        }
        return $m;
    }

    public function testPolicyDefaultsAndValidation(): void
    {
        $p = new RevocationStalenessPolicy(1000.0);
        $this->assertFalse($p->allowUnsignedRootForIrreversible);
        $this->assertSame(['ok' => false, 'reason' => 'unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)'],
            RevocationStaleness::gate(['policy' => $p, 'now' => 1000, 'root' => 'r', 'rootIssuedAt' => 900.0, 'signedClass' => 'irreversible']));

        $this->assertSame('proofs must be callable or an array', (new RevocationStalenessPolicy(null, null, false, null, 5))->validate());
        $this->assertNull((new RevocationStalenessPolicy(null, null, false, null, []))->validate());
        $this->assertNull((new RevocationStalenessPolicy(null, null, false, null, static fn() => null))->validate());

        $msg = ' must be a positive number of milliseconds';
        $this->assertSame('maxRevocationAgeMs' . $msg, (new RevocationStalenessPolicy(-1.0, ['irreversible' => -1.0, 'costly' => -1.0]))->validate());
        $this->assertSame('staleness.irreversible' . $msg, (new RevocationStalenessPolicy(null, ['irreversible' => -1.0, 'costly' => -1.0]))->validate());
    }

    public function testFromJsonArray(): void
    {
        $p = RevocationStalenessPolicy::fromJson(['maxRevocationAgeMs' => 1000, 'staleness' => ['costly' => 1000, 'rate_limited' => 2000.5]]);
        $this->assertSame(1000.0, $p->maxRevocationAgeMs);
        $this->assertSame(['irreversible' => null, 'costly' => 2000.5], $p->staleness);
        $this->assertFalse($p->allowUnsignedRootForIrreversible);
        $this->assertTrue(RevocationStalenessPolicy::fromJson(['allowUnsignedRootForIrreversible' => true])->allowUnsignedRootForIrreversible);
        $this->assertFalse(RevocationStalenessPolicy::fromJson(['allowUnsignedRootForIrreversible' => false])->allowUnsignedRootForIrreversible);
    }

    public function testMaxAgeMs(): void
    {
        $this->assertNan(RevocationStaleness::maxAgeMs(new RevocationStalenessPolicy(null, ['irreversible' => NAN]), 'irreversible'));
        $this->assertSame(1000.0, RevocationStaleness::maxAgeMs(new RevocationStalenessPolicy(null, ['rate_limited' => 1000.0, 'costly' => 2000.0]), 'costly'));
    }

    public function testCheckEpoch(): void
    {
        $ep = self::epoch();
        $g = $ep->get('guardian');
        $o = ['guardianPublic' => $g, 'now' => 1500];
        $this->assertSame(['ok' => true], RevocationStaleness::checkEpoch($ep, $o));
        // set_size at exactly 2^53-1 is a safe integer
        $this->assertSame(['ok' => true], RevocationStaleness::checkEpoch(self::epoch(['set_size' => 9007199254740991]), $o));
        // an absent body member, and a native int (not wire form) that cannot be canonicalized
        $this->assertSame(self::CHECK_ERROR, RevocationStaleness::checkEpoch(self::with($ep, 'root', null, true), $o));
        $this->assertSame(self::CHECK_ERROR, RevocationStaleness::checkEpoch(self::with($ep, 'set_size', 0), $o));
        // numeric strings are cast to floats
        $this->assertSame(['ok' => true], RevocationStaleness::checkEpoch($ep, ['guardianPublic' => $g, 'now' => '1500', 'maxAgeMs' => 1000.0]));
        $this->assertSame(['ok' => true], RevocationStaleness::checkEpoch($ep, ['guardianPublic' => $g, 'now' => 1500, 'maxAgeMs' => '1000']));
        $this->assertSame(['ok' => false, 'reason' => 'revocation epoch 5 is older than the last accepted 9 (rollback)'],
            RevocationStaleness::checkEpoch($ep, $o + ['lastAcceptedEpoch' => '9']));
        $this->assertSame(['ok' => false, 'reason' => 'PCActn freshness.epoch 1 predates the revocation epoch 5'],
            RevocationStaleness::checkEpoch($ep, $o + ['pcactnEpoch' => '1']));
    }

    public function testSignEpochRefusals(): void
    {
        try {
            RevocationStaleness::signEpoch("\x01", []);
            $this->fail('a short seed signed');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('signEpoch: the guardian seed must be 32 bytes', $e->getMessage());
        }
        try {
            RevocationStaleness::signEpoch(self::SEED, ['instance_id' => 'i']);
            $this->fail('a body without grant_ref signed');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('signEpoch: missing grant_ref', $e->getMessage());
        }
    }

    public function testGate(): void
    {
        $off = new RevocationStalenessPolicy();
        $this->assertSame(['ok' => true, 'root' => 'r'], RevocationStaleness::gate(['policy' => new RevocationStalenessPolicy(1000.0), 'now' => '1000',
            'root' => 'r', 'rootIssuedAt' => 900.0, 'signedClass' => 'reversible']));
        $this->assertSame(['ok' => false, 'reason' => 'no revocation root'], RevocationStaleness::gate(['policy' => $off, 'now' => 0]));
        $this->assertSame(['ok' => false, 'reason' => 'capability id is not a string (fail closed)'],
            RevocationStaleness::gate(['policy' => $off, 'now' => 0, 'root' => 'r', 'ids' => [5]]));
        $this->assertSame(['ok' => false, 'reason' => 'revocation staleness check error (fail closed)'],
            RevocationStaleness::gate(['policy' => 'not a policy', 'now' => 0]));
    }

    private static function pcactn(array $over = []): Obj
    {
        return Obj::of($over + ['grant_ref' => 'g1', 'action' => Obj::of(['reversibility_class' => 'reversible']), 'cap_chain' => []]);
    }

    public function testFreshnessWithoutState(): void
    {
        $off = new RevocationStalenessPolicy();
        $none = 'no signed revocation epoch';
        $irr = 'no verifiable (guardian-signed) revocation state for an irreversible action';
        $this->assertSame($none, RevocationStaleness::freshness($off, null, null, self::pcactn(), null, 1000.0, null));
        $this->assertSame($none, RevocationStaleness::freshness($off, null, null, self::pcactn(), null, 1000.0, new RevocationState()));
        $this->assertSame($irr, RevocationStaleness::freshness($off, null, null, Obj::of(['grant_ref' => 'g1']), null, 1000.0, null));
    }

    public function testFreshnessWithEpoch(): void
    {
        $off = new RevocationStalenessPolicy();
        $ep = self::epoch();
        $g = $ep->get('guardian');
        $st = new RevocationState($ep);
        $f = static fn(Obj $p, ?RevocationState $s = null): ?string => RevocationStaleness::freshness($off, $g, null, $p, null, 1500.0, $s ?? $st);
        $this->assertNull($f(self::pcactn()), 'no freshness member');
        $this->assertNull($f(self::pcactn(['freshness' => Obj::of(['epoch' => new Num('5')])])));
        $this->assertNull($f(self::pcactn(['freshness' => Obj::of(['epoch' => 'x'])])), 'a non-number epoch is ignored');
        $pre = 'PCActn freshness.epoch 1 predates the revocation epoch 5';
        $this->assertSame($pre, $f(self::pcactn(['freshness' => Obj::of(['epoch' => new Num('1')])])));
        $this->assertSame($pre, $f(self::pcactn(['freshness' => Obj::of(['epoch' => 1])])));
        $this->assertSame($pre, $f(self::pcactn(['freshness' => Obj::of(['epoch' => 1.0])])));
        $this->assertSame('revocation epoch is for a different grant', $f(self::pcactn(['grant_ref' => 'g2'])));
        $this->assertSame('revocation epoch 5 is older than the last accepted 9 (rollback)', $f(self::pcactn(), new RevocationState($ep, null, null, 9.0)));
    }

    public function testFreshnessWithBareRoot(): void
    {
        $off = new RevocationStalenessPolicy();
        $root = new RevocationState(null, 'r', 900.0);
        $this->assertNull(RevocationStaleness::freshness($off, null, null, self::pcactn(), null, 1000.0, $root));
        $this->assertNull(RevocationStaleness::freshness(new RevocationStalenessPolicy(1000.0), null, null, self::pcactn(), 'reversible', 1000.0, $root));
        $this->assertSame('capability id is not a string (fail closed)',
            RevocationStaleness::freshness($off, null, null, self::pcactn(['cap_chain' => ['x']]), null, 1000.0, $root));
        $withProofs = new RevocationStalenessPolicy(null, null, false, null, ['c1' => 'junk']);
        $this->assertSame('capability c1 is revoked or proof invalid', RevocationStaleness::freshness($withProofs, null, null,
            self::pcactn(['cap_chain' => [Obj::of(['id' => 'c1'])]]), null, 1000.0, $root));
    }

    /** verifyNonMembership is fail-closed: a throw while checking a proof that would verify answers false, never true. */
    public function testVerifyNonMembershipThrowFailsClosed(): void
    {
        $tree = (new \ReflectionMethod(\Atlas\Pca\Mesh::class, 'emptyRevTree'))->invoke(null);
        $root = (new \ReflectionMethod(\Atlas\Pca\Mesh::class, 'bindRevRoot'))->invoke(null, 0, $tree);
        $proof = Obj::of(['size' => new Num('0')]);
        $this->assertTrue(RevocationStaleness::verifyNonMembership($root, $proof, 'x'));
        RevocationStaleness::$nonMembershipHook = static function (): void {
            throw new \RuntimeException('boom');
        };
        try {
            $this->assertFalse(RevocationStaleness::verifyNonMembership($root, $proof, 'x'));
        } finally {
            RevocationStaleness::$nonMembershipHook = null;
        }
        $this->assertTrue(RevocationStaleness::verifyNonMembership($root, $proof, 'x'));
    }
}
