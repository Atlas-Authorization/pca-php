<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\MpcNetPartyMain;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Mutation kills for the node's JSON-model view of a result (the one-line stdout report): GMP, Num, Obj, lists and scalars. */
final class ProtoSurvivorKill17MpcNetPartyMainTest extends TestCase
{
    /** GMP is a decimal string, Num a float, an Obj a map (recursively), a list is mapped, a scalar is itself. */
    public function testPlainView(): void
    {
        $plain = new \ReflectionMethod(MpcNetPartyMain::class, 'plain');
        $this->assertSame('12345678901234567890', $plain->invoke(null, gmp_init('12345678901234567890')));
        $this->assertSame(2.5, $plain->invoke(null, new Num('2.5')));
        $this->assertSame('x', $plain->invoke(null, 'x'));
        $this->assertSame(7, $plain->invoke(null, 7));
        $this->assertNull($plain->invoke(null, null));
        $o = $plain->invoke(null, Obj::of(['a' => gmp_init(3), 'b' => Obj::of(['c' => new Num('1')])]));
        $this->assertInstanceOf(\stdClass::class, $o);
        $this->assertSame(['a' => '3', 'b' => ['c' => 1.0]], json_decode(json_encode($o), true));
        $this->assertSame('3', $o->a);
        $this->assertSame(['9', 'y', 1.0], $plain->invoke(null, [gmp_init(9), 'y', new Num('1')]));
    }
}
