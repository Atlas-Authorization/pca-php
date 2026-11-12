<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/K3Sig.php';

use Atlas\Pca\K3Sig;
use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** Mutation kills for K3Sig (the JS-shaped predicates and the domain-separated body signature). */
final class K05KillK3SigTest extends TestCase
{
    public function testPredicates(): void
    {
        $this->assertTrue(K3Sig::isObj(new Obj()));
        $this->assertFalse(K3Sig::isObj([]));
        $this->assertTrue(K3Sig::anySafeInt(new Num('9007199254740991')));
        $this->assertTrue(K3Sig::anySafeInt(9007199254740991));
        $this->assertFalse(K3Sig::anySafeInt(new Num('9007199254740993')));
        $this->assertTrue(K3Sig::isStr(str_repeat('a', 512)));
        $this->assertFalse(K3Sig::isStr(str_repeat('a', 513)));
    }

    public function testVerifyBodyNeverThrows(): void
    {
        // a well-shaped signature over a body that has no strict canonical form (a native int) is false, not an exception
        $this->assertFalse(K3Sig::verifyBody('d', Obj::of(['x' => 5]), Pca::b64u(str_repeat("\x01", 32)), Pca::b64u(str_repeat("\0", 64))));
    }
}
