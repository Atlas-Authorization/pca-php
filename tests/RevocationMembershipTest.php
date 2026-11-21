<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/RevocationStaleness.php';

use Atlas\Pca\Json;
use Atlas\Pca\Mesh;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\RevocationStaleness;
use PHPUnit\Framework\TestCase;

/** verifyMembership (revocation.ts): the inclusion proof against a size-bound revocation root. */
final class RevocationMembershipTest extends TestCase
{
    private static function singleLeafRoot(string $id): string
    {
        $leaf = hash('sha256', "\x00" . Json::canonicalizeStrict($id), true);
        return (new \ReflectionMethod(Mesh::class, 'bindRevRoot'))->invoke(null, 1, Pca::b64u($leaf));
    }

    public function testInclusionOfTheOnlyLeaf(): void
    {
        $root = self::singleLeafRoot('cap-1');
        $proof = Obj::of(['size' => new Num('1'), 'index' => new Num('0'), 'path' => []]);
        self::assertTrue(RevocationStaleness::verifyMembership($root, $proof, 'cap-1'));
        self::assertFalse(RevocationStaleness::verifyMembership($root, $proof, 'cap-2'), 'another id is not in the set');
        self::assertFalse(RevocationStaleness::verifyMembership($root, Obj::of(['size' => new Num('1'), 'index' => new Num('1'), 'path' => []]), 'cap-1'));
        self::assertFalse(RevocationStaleness::verifyMembership($root, Obj::of(['size' => new Num('2'), 'index' => new Num('0'), 'path' => []]), 'cap-1'), 'a proof of another size');
        self::assertFalse(RevocationStaleness::verifyMembership($root, null, 'cap-1'));
        self::assertFalse(RevocationStaleness::verifyMembership(5, $proof, 'cap-1'));
        self::assertFalse(RevocationStaleness::verifyMembership($root, $proof, 7));
        self::assertFalse(RevocationStaleness::verifyMembership(self::singleLeafRoot('other'), $proof, 'cap-1'));
    }
}
