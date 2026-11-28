<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\GoalCompiler;
use Atlas\Pca\Json;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 37 survivor kills for the goal-compiler front door: every type reason is reported, not just the first. */
final class RestSurvivorKill37GoalCompilerTest extends TestCase
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

    /** A goal with two type faults (a USD ceiling on an EUR param and a delegation depth over 16) reports both reasons, in order. */
    public function testTwoTypeReasonsAreBothReported(): void
    {
        $v = self::vector('w-w18-16');
        $this->assertSame(['ill_typed_grant'], GoalCompiler::typecheck($v->get('goal'), $v->get('ontology')), 'control: one fault');
        $v->get('goal')->get('deleg')->set('maxDepth', 17);
        $both = ['ill_typed_grant', 'bad_validity_or_delegation'];
        $this->assertSame($both, GoalCompiler::typecheck($v->get('goal'), $v->get('ontology')));
        $c = GoalCompiler::compileGoal($v->get('goal'), $v->get('ontology'));
        $this->assertSame([false, $both], [$c->get('ok'), $c->get('reasons')]);
    }
}
