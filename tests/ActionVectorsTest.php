<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Actions;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** The shared action-kit vectors, the pinned registry digests, the pack proof tamper checks and whole-document rule 22. */
final class ActionVectorsTest extends TestCase
{
    public function testEveryVectorReplays(): void
    {
        [$n, $fails] = ActionVectors::run();
        $this->assertSame([], array_slice($fails, 0, 20), count($fails) . ' failure(s) of ' . $n);
        $this->assertGreaterThanOrEqual(400, $n);
    }

    public function testApprovalProfileVectorsReplay(): void
    {
        [$n, $fails] = ActionVectors::runProfiles();
        $this->assertSame([], array_slice($fails, 0, 20), count($fails) . ' failure(s) of ' . $n);
        $this->assertGreaterThanOrEqual(12, $n);
    }

    public function testPinnedDigests(): void
    {
        $this->assertSame('W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM', Actions::traitsDigest(Actions::coreRegistry()));
        $this->assertSame('I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU', Actions::tablesDigest());
    }

    private function byId(string $id): Obj
    {
        foreach (ActionVectors::cases() as $c) {
            if ($c->get('id') === $id) {
                return $c;
            }
        }
        $this->fail("vector $id missing");
    }

    public function testPackProofVerifiesAndTamperFails(): void
    {
        $c = $this->byId('pack-builtin');
        $ds = $c->get('input')->get('digests');
        $root = $c->get('expect')->get('root');
        foreach ($ds as $d) {
            $this->assertTrue(Actions::verifyPackProof($root, Actions::packProof($ds, $d), $d));
        }
        $this->assertFalse(Actions::verifyPackProof($root, Actions::packProof($ds, $ds[0]), $ds[1]));
        $this->assertFalse(Actions::verifyPackProof(str_repeat('A', 43), Actions::packProof($ds, $ds[0]), $ds[0]));
    }

    public function testWholeDocumentRule22(): void
    {
        $doc = Obj::of(['verbs' => [$this->byId('schema-verb-adv-honest')->get('input')->get('verb')]]);
        $this->assertNull(Actions::schemaFloorError($doc));
        $doc->set('traits_digest', str_repeat('A', 43));
        $this->assertStringStartsWith('traits_digest_mismatch', (string)Actions::schemaFloorError($doc));
    }
}
