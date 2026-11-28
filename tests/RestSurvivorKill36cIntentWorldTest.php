<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/IntentWorld.php';

use Atlas\Pca\IntentWorld;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/IntentWorld.php: cut dedup by value, the duplicate-dimension message, and list indices in provenance paths. */
final class RestSurvivorKill36cIntentWorldTest extends TestCase
{
    /** Cuts equal by value (1 and 1.0) are one cut. */
    public function testCutsDedupByValue(): void
    {
        $d = IntentWorld::worldDim('x', Obj::of(['lo' => 0, 'hi' => 5, 'cuts' => [3, 1, 1.0, 9]]));
        $this->assertSame([1, 3], $d->get('cuts'));
    }

    /** Adding a dimension the verb already has names the verb and the path. */
    public function testDuplicateDimensionMessage(): void
    {
        $omega = Obj::of(['verbs' => [Obj::of(['verb' => 'pay', 'dims' => [Obj::of(['path' => 'env.world.x'])]])]]);
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('withDims: pay already has a dimension env.world.x');
        IntentWorld::withDims($omega, 'pay', [Obj::of(['path' => 'env.world.x'])]);
    }

    private static function prov(mixed $a, string $path): mixed
    {
        $o = Obj::of(['verb' => 'pay', 'values' => new Obj()]);
        $env = Obj::of(['prov' => Obj::of(['a' => $a])]);
        return IntentWorld::liftOutcome($o, $env, [$path])->get('values')->get($path);
    }

    /** A provenance path indexes into a list; an index at or past the end, or into a string, is absent (the tainted cell), with no PHP warning. */
    public function testProvenanceListIndex(): void
    {
        $errors = [];
        set_error_handler(static function (int $no, string $msg) use (&$errors): bool {
            $errors[] = $msg;
            return true;
        });
        try {
            $this->assertSame('first_party', self::prov(['first_party', 'trusted'], 'env.prov.a.0'));
            $this->assertSame('trusted', self::prov(['first_party', 'trusted'], 'env.prov.a.1'));
            $this->assertSame('agent', self::prov(['first_party', 'trusted'], 'env.prov.a.2'));
            $this->assertSame('agent', self::prov(['first_party', 'trusted'], 'env.prov.a.01'));
            $this->assertSame('agent', self::prov('trusted', 'env.prov.a.0'));
        } finally {
            restore_error_handler();
        }
        $this->assertSame([], $errors);
    }
}
