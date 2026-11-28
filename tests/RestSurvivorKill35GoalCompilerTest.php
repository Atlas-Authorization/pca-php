<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalCompiler;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Survivor kills for the typed goal-compiler front door, on two committed goal vectors. */
final class RestSurvivorKill35GoalCompilerTest extends TestCase
{
    private static function vector(string $id): Obj
    {
        foreach ([__DIR__ . '/../../../packages/pca-conformance/vectors/goal', __DIR__ . '/../packages/pca-conformance/vectors/goal', __DIR__ . '/../conformance/goal'] as $d) {
            if (is_file("$d/$id.json")) {
                return Json::parseLax((string)file_get_contents("$d/$id.json"));
            }
        }
        throw new \RuntimeException("goal vector $id not found");
    }

    /** A well-typed goal typechecks to no reasons and compiles. */
    public function testWellTypedGoal(): void
    {
        $v = self::vector('w-w8-06');
        $this->assertSame([], GoalCompiler::typecheck($v->get('goal'), $v->get('ontology')));
        $this->assertTrue(GoalCompiler::compileGoal($v->get('goal'), $v->get('ontology'))->get('ok'));
    }

    /** An ill-typed goal does not compile, and the policy decision reports the same reasons instead of throwing. */
    public function testIllTypedGoal(): void
    {
        $v = self::vector('w-w18-16');
        $p = self::vector('w-w8-06')->get('probes')[0];
        $c = GoalCompiler::compileGoal($v->get('goal'), $v->get('ontology'));
        $this->assertSame([false, ['ill_typed_grant']], [$c->get('ok'), $c->get('reasons')]);
        $d = GoalCompiler::decidePolicy($v->get('goal'), $v->get('ontology'), $p->get('action'), $p->get('history'));
        $this->assertSame([false, ['ill_typed_grant']], [$d->get('ok'), $d->get('reasons')]);
    }
}
