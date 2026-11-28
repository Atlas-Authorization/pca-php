<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Mesh.php';

use Atlas\Pca\Mesh;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Mesh.php: membership of a non-object proof and the revocation-leaf table bound (2 per capability is allowed). */
final class GuardSurvivorKill33MeshTest extends TestCase
{
    public function testMembershipOfANonObjectProofIsFalse(): void
    {
        $this->assertFalse(Mesh::membership('r', 5, 'id'));
        $this->assertFalse(Mesh::membership('r', null, 'id'));
    }

    /** Exactly two revocation leaves per capability pass the table bound and are then checked one by one. */
    public function testTwoLeavesPerCapabilityPassTheBound(): void
    {
        $base = null;
        foreach (Vectors::load('mesh-vectors.json')->get('mesh') as $r) {
            if ($r->get('name') === 'valid/base') {
                $base = $r;
            }
        }
        $this->assertInstanceOf(Obj::class, $base);
        $proof = $base->get('proof');
        $this->assertCount(4, $proof->get('chain'));
        $p = $proof->without();
        $p->set('rev_leaves', array_fill(0, 8, null));
        $this->assertSame(['ok' => false, 'reason' => 'malformed revocation leaves', 'hop' => -1], Mesh::verify($p, $base->get('trust')));
    }
}
