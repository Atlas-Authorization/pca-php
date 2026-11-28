<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AbePolicy;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/AbePolicy.php: the public node builders, ill-formed text, ambiguous gates and the wire-tree node budget. */
final class GuardSurvivorKill33AbePolicyTest extends TestCase
{
    private static function leaf(mixed $a): Obj
    {
        return Obj::of(['kind' => 'leaf', 'attr' => $a]);
    }

    private static function gate(array $of): Obj
    {
        return Obj::of(['kind' => 'gate', 't' => new Num('1'), 'of' => $of]);
    }

    public function testPublicBuilders(): void
    {
        $this->assertSame(['leaf' => true, 'attr' => 'a'], AbePolicy::leaf('a'));
        $this->assertSame(['leaf' => false, 't' => 1, 'of' => [AbePolicy::leaf('a')]], AbePolicy::gate(1, [AbePolicy::leaf('a')]));
        $this->assertSame(2.0, AbePolicy::posInt(new Num('2')));
        $this->assertNull(AbePolicy::posInt(2));
    }

    public function testInvalidUtf8IsIllFormed(): void
    {
        $this->assertTrue(AbePolicy::illFormed("\xff"));
        $this->assertFalse(AbePolicy::illFormed('ok'));
    }

    public function testAllOfWithThresholdIsAmbiguous(): void
    {
        $p = Obj::of(['allOf' => [Obj::of(['attr' => 'a'])], 'threshold' => new Num('1'), 'of' => [Obj::of(['attr' => 'a'])]]);
        $this->assertSame(['tree' => null, 'reason' => 'policy: ambiguous node (allOf, threshold); a gate must use exactly one of allOf/anyOf/threshold'],
            AbePolicy::normalize($p));
    }

    public function testWireLeafRefusalsAndAttributeTypes(): void
    {
        $this->assertNull(AbePolicy::policyAttributes(self::leaf(5)));
        $this->assertNull(AbePolicy::policyAttributes(self::leaf('')));
        $this->assertSame(['1'], AbePolicy::policyAttributes(self::leaf('1')));
    }

    /** The wire-tree budget is 1024 nodes in all: a 1024-node tree parses, a 1025-node one does not. */
    public function testWireTreeNodeBudget(): void
    {
        $tree = static fn(int $inner): Obj => self::gate([self::gate(array_map(static fn(int $i): Obj => self::leaf("a$i"), range(1, $inner))), self::leaf('z')]);
        $this->assertNotNull(AbePolicy::policyAttributes($tree(1021))); // 1 + 1 + 1021 + 1 = 1024 nodes
        $this->assertNull(AbePolicy::policyAttributes($tree(1022)));    // 1025 nodes
    }
}
