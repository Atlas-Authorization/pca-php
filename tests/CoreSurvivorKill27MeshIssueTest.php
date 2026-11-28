<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/MeshIssue.php';

use Atlas\Pca\Json;
use Atlas\Pca\KeyPair;
use Atlas\Pca\MeshIssue;
use Atlas\Pca\Obj;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** Mesh issuing-side refusal paths: caveat shapes, proof-size accounting, translated capabilities, budget-tree bounds, cross-reference commitments. */
final class CoreSurvivorKill27MeshIssueTest extends TestCase
{
    private static function throws(callable $f): array
    {
        try {
            $f();
        } catch (\Throwable $e) {
            return [get_class($e), $e->getMessage()];
        }
        return ['none', ''];
    }

    private static function duck(Obj $o): object
    {
        return new class ($o) {
            public function __construct(private Obj $o)
            {
            }

            public function get(string $k): mixed
            {
                return $this->o->get($k);
            }

            public function has(string $k): bool
            {
                return $this->o->has($k);
            }
        };
    }

    private static function kp(string $label): KeyPair
    {
        return new KeyPair(hash('sha256', 'atlas-pca-conformance/k27-mesh-issue/' . $label, true));
    }

    /** A translated capability whose source root carries only a resource caveat and whose bridge adds a scope and a zero max_amount. */
    private static function translated(): Obj
    {
        $kp = self::kp('root');
        $root = Sign::mintRoot($kp, $kp->public, [['type' => 'resource', 'prefix' => '/']]);
        return MeshIssue::translateCapability([$root], 'org-A', 'org-B', self::kp('bridge'), 1000, Sign::n([['type' => 'scope', 'actions' => ['x']], ['type' => 'max_amount', 'max' => 0]]));
    }

    /** A null caveat throws; a caveat list with a non-object entry is malformed. */
    public function testCaveatShapes(): void
    {
        $this->assertSame(['InvalidArgumentException', 'effectiveAuthority: null caveat'], self::throws(static fn() => MeshIssue::effectiveAuthority([null])));
        $this->assertSame(['error' => 'malformed translated capability'], MeshIssue::translatedEffectiveAuthority(Obj::of(['caveats' => ['x']])));
        $kp = self::kp('root');
        $root = Sign::mintRoot($kp, $kp->public, [['type' => 'resource', 'prefix' => '/']]);
        $this->assertSame(['InvalidArgumentException', 'translateCapability: additionalCaveats must be an array of caveats'],
            self::throws(static fn() => MeshIssue::translateCapability([$root], 'org-A', 'org-B', self::kp('bridge'), 1000, ['x'])));
    }

    /** Constraints the bridge adds where the source had none (a scope, a zero amount) are a narrowing, not a widening. */
    public function testTranslationAddingConstraintsVerifies(): void
    {
        $r = MeshIssue::verifyTranslatedCapability(self::translated());
        $this->assertTrue($r['ok'], $r['reason'] ?? '');
        $this->assertSame(['prefixes' => ['/'], 'actions' => ['x'], 'maxAmount' => 0.0], $r['effective']);
    }

    /** A translated capability that is not an Obj is malformed even when its fields are valid. */
    public function testDuckTranslatedCapabilityRefused(): void
    {
        $this->assertSame(['ok' => false, 'reason' => 'malformed translated capability'], MeshIssue::verifyTranslatedCapability(self::duck(self::translated())));
    }

    private static function proof(mixed $heads, array $hops, array $leaves = ['leaf0']): Obj
    {
        return Obj::of(['chain' => [], 'action' => new Obj(), 'action_sig' => 's', 'heads' => $heads, 'rev_leaves' => $leaves, 'hops' => $hops]);
    }

    private static function hop(mixed $head, mixed $cap): Obj
    {
        return Obj::of(['head' => $head, 'revocation' => Obj::of(['cap' => $cap, 'issuer_key' => Obj::of(['size' => 0])])]);
    }

    /** Heads are found by object key and by a decimal string list index, and a lo/hi leaf reference is inlined in the uncompacted layout. */
    public function testMeshProofSizeResolvesHeadsAndLeaves(): void
    {
        $head = Obj::of(['x' => 'head']);
        $cap = Obj::of(['size' => 1, 'lo' => 0, 'hi' => 0]);
        $full = Obj::of(['head' => $head, 'revocation' => Obj::of(['cap' => Obj::of(['size' => 1, 'lo' => 'leaf0', 'hi' => 'leaf0']), 'issuer_key' => Obj::of(['size' => 0])])]);
        $want = strlen('[]') + strlen('{}') + strlen('"s"') + strlen(Json::canonicalizeNative($full));
        $this->assertSame($want, MeshIssue::meshProofSize(self::proof(Obj::of(['h0' => $head]), [self::hop('h0', $cap)]))['uncompacted_bytes']);
        $this->assertSame($want, MeshIssue::meshProofSize(self::proof([$head], [self::hop('0', $cap)]))['uncompacted_bytes']);
    }

    /** meshProofSize refuses a non-proof, a non-object hop, a hop without a head or revocation, and a non-object revocation proof. */
    public function testMeshProofSizeRefusals(): void
    {
        $head = Obj::of(['x' => 'head']);
        $hop = ['InvalidArgumentException', 'meshProofSize: malformed hop'];
        $this->assertSame(['InvalidArgumentException', 'meshProofSize: not a proof'], self::throws(static fn() => MeshIssue::meshProofSize(null)));
        $this->assertSame($hop, self::throws(static fn() => MeshIssue::meshProofSize(self::proof([$head], ['x']))));
        $this->assertSame($hop, self::throws(static fn() => MeshIssue::meshProofSize(self::proof(Obj::of(['null' => $head]), [Obj::of(['revocation' => Obj::of(['cap' => Obj::of(['size' => 0]), 'issuer_key' => Obj::of(['size' => 0])])])]))));
        $this->assertSame($hop, self::throws(static fn() => MeshIssue::meshProofSize(self::proof(Obj::of(['h0' => $head]), [Obj::of(['head' => 'h0'])]))));
        $this->assertSame(['InvalidArgumentException', 'meshProofSize: malformed revocation proof'], self::throws(static fn() => MeshIssue::meshProofSize(self::proof([$head], [self::hop(0, 'x')]))));
    }

    /** A budget tree with bMax 0 and a zero-budget root is valid and can spend 0; a numeric-looking node id is kept as a string. */
    public function testBudgetBoundsAndNumericIds(): void
    {
        $z = MeshIssue::createFederatedBudget(Obj::of(['rootId' => 'r', 'rootDomain' => 'd', 'B0' => 0, 'kappa' => 1, 'bMax' => 0]));
        $this->assertTrue($z['ok']);
        $this->assertTrue(MeshIssue::spendFederated($z['state'], 'r', 0)['ok']);
        $s = MeshIssue::createFederatedBudget(Obj::of(['rootId' => 'r', 'rootDomain' => 'd', 'B0' => 10, 'kappa' => 1, 'bMax' => 10]));
        $a = MeshIssue::allocateSub($s['state'], Obj::of(['id' => '7', 'domain' => 'd', 'parent' => 'r', 'alloc' => 5]));
        $this->assertTrue($a['ok']);
        $this->assertSame(['r', '7'], $a['state']->get('nodes')->keys());
    }

    /** crossReferenceCommit refuses null and a non-object with their own messages; a non-Obj cross-reference is malformed before the anchors are read. */
    public function testCrossReferenceRefusals(): void
    {
        $this->assertSame(['InvalidArgumentException', 'crossReferenceCommit: null'], self::throws(static fn() => MeshIssue::crossReferenceCommit(null)));
        $this->assertSame(['InvalidArgumentException', 'canonicalize: member action_digest is missing'], self::throws(static fn() => MeshIssue::crossReferenceCommit('x')));
        $x = Obj::of(['action_digest' => 'a', 'fromGuardian' => 'f', 'toGuardian' => 't', 'nonce' => 'n', 'at' => 1]);
        $this->assertSame(['ok' => false, 'reason' => 'malformed anchors'], MeshIssue::verifyCrossReference($x, null));
        $this->assertSame(['ok' => false, 'reason' => 'malformed cross-reference'], MeshIssue::verifyCrossReference(self::duck($x), null));
    }
}
