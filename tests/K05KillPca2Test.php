<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use PHPUnit\Framework\TestCase;

/** k05 mutation kills for src/Pca.php (round 2): inclusion-path shape, strict base64url, and the PQ key/sig gate. */
final class K05KillPca2Test extends TestCase
{
    private static function priv(string $name, mixed ...$args): mixed
    {
        return (new \ReflectionMethod(Pca::class, $name))->invoke(null, ...$args);
    }

    private static function step(string $hash): Obj
    {
        return Obj::of(['side' => 'R', 'hash' => Pca::b64u($hash)]);
    }

    private static function proof(array $path, int $size): Obj
    {
        return Obj::of(['path' => $path, 'index' => new Num('0'), 'size' => new Num((string)$size)]);
    }

    /** A path whose keys are 0..n-1 but out of order is not a list: refused even when walking it in that order reaches the root. */
    public function testInclusionPathMustBeAList(): void
    {
        $this->assertSame(['R', 'R'], Pca::pathShape(0, 4));
        $hA = str_repeat("\1", 32);
        $hB = str_repeat("\2", 32);
        $root = Pca::b64u(self::priv('nodeHash', self::priv('nodeHash', self::priv('leafHash', 'leaf'), $hA), $hB));
        $this->assertTrue(Pca::verifyInclusion($root, self::proof([self::step($hA), self::step($hB)], 4), 'leaf'), 'control');
        $this->assertFalse(Pca::verifyInclusion($root, self::proof([1 => self::step($hA), 0 => self::step($hB)], 4), 'leaf'));
    }

    /** A step that only looks like an Obj (get()/has()) is refused. */
    public function testInclusionStepMustBeAnObj(): void
    {
        $hA = str_repeat("\1", 32);
        $root = Pca::b64u(self::priv('nodeHash', self::priv('leafHash', 'leaf'), $hA));
        $this->assertTrue(Pca::verifyInclusion($root, self::proof([self::step($hA)], 2), 'leaf'), 'control');
        $fake = new class(self::step($hA)) {
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
        $this->assertFalse(Pca::verifyInclusion($root, self::proof([$fake], 2), 'leaf'));
    }

    public function testStrictBase64url(): void
    {
        $this->assertSame("\0", Pca::unb64u('AA'));
        $this->assertSame("\0\0\0", Pca::unb64u('AAAA', 3));
        $this->assertSame("\xff\xff", Pca::unb64u('__8', 2));
        foreach (['A', 'AAAAA', 'AB', 'AA=', 'A+', "AA\n"] as $bad) {
            $this->assertNull(Pca::unb64u($bad), $bad);
        }
        $this->assertNull(Pca::unb64u('AAA', 3));
        $this->assertNull(Pca::unb64u('AAAA', 2));
    }

    /** A malformed PQ key is refused before the verifier is reached, even with a well-formed signature. */
    public function testPqVerifyRefusesAMalformedKeyUpFront(): void
    {
        $sig = Pca::b64u(str_repeat("\0", 3309));
        $this->assertFalse(self::priv('pqVerifyB64u', 'ML-DSA-65', 'not-a-key', 'msg', $sig));
        $this->assertFalse(self::priv('pqVerifyB64u', 'ML-DSA-65', null, 'msg', $sig));
    }
}
