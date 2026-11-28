<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/SandboxHandles.php';

use Atlas\Pca\Num;
use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\SandboxHandleTable;
use Atlas\Pca\SandboxReceiptLog;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/SandboxHandles.php: the runtime-class refusal text and attenuation's integer uses bound. */
final class GuardSurvivorKill33SandboxHandlesTest extends TestCase
{
    private static function op(): Obj
    {
        return Obj::of(['verb' => 'read', 'resource' => 'r', 'params' => Obj::of(['a' => 'b'])]);
    }

    private static function handlesResult(): Obj
    {
        return Obj::of(['allow' => true, 'operation' => Obj::of(['verb' => 'read', 'resource' => 'r', 'params_digest' => Pca::hashCanonical(self::op()->get('params')), 'id' => 'op1'])]);
    }

    /** A table weaker than the grant requires refuses to mint, naming both classes. */
    public function testRuntimeClassTooWeakText(): void
    {
        $t = new SandboxHandleTable('none', new SandboxReceiptLog(), []);
        try {
            $t->mint(self::handlesResult(), self::op(), Obj::of(['requires' => 'wasi_no_ambient']));
            $this->fail('minted on a too-weak table');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame('runtime_class_too_weak: table is none, grant requires wasi_no_ambient', $e->getMessage());
        }
    }

    /** Attenuation takes a whole number of uses of at least 1: 1.5 and 0 are refused, 2 is granted. */
    public function testAttenuateUsesMustBeAPositiveInteger(): void
    {
        $t = new SandboxHandleTable('none', new SandboxReceiptLog(), []);
        $h = $t->mint(self::handlesResult(), self::op(), Obj::of(['uses' => new Num('5')]));
        foreach (['1.5', '0'] as $u) {
            try {
                $t->attenuate($h, Obj::of(['uses' => new Num($u)]));
                $this->fail("uses $u was granted");
            } catch (\InvalidArgumentException $e) {
                $this->assertSame('attenuate_widens', $e->getMessage());
            }
        }
        $this->assertIsInt($t->attenuate($h, Obj::of(['uses' => new Num('2')])), 'control');
    }
}
