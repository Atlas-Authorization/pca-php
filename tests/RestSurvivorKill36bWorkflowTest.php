<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Workflow.php';
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\Obj;
use Atlas\Pca\Workflow;
use PHPUnit\Framework\TestCase;

/** workflowCommitmentError: a commitment with an extra member is malformed, and it is valid from exactly issued_at. */
final class RestSurvivorKill36bWorkflowTest extends TestCase
{
    private function signed(): Obj
    {
        $doc = Vectors::load('producer-vectors.json');
        $case = array_values(array_filter($doc->get('cases'), static fn(Obj $c) => $c->get('name') === 'workflow-sign'))[0];
        return Obj::of(['body' => $case->get('args')->get('body'), 'sig' => $case->get('expect')->get('sig')]);
    }

    /** A validly signed commitment that carries a member besides body and sig is refused as bad_workflow. */
    public function testExtraMemberRefused(): void
    {
        $sw = $this->signed();
        $p = $sw->get('body')->get('principal');
        self::assertNull(Workflow::workflowCommitmentError($sw, $p, 1800000000500));
        $extra = Obj::of(['body' => $sw->get('body'), 'sig' => $sw->get('sig'), 'x' => 1]);
        self::assertSame('bad_workflow', Workflow::workflowCommitmentError($extra, $p, 1800000000500));
    }

    /** At exactly issued_at the commitment is valid (not "not yet"). */
    public function testValidFromIssuedAt(): void
    {
        $sw = $this->signed();
        $b = $sw->get('body');
        $at = $b->get('issued_at')->int();
        self::assertNull(Workflow::workflowCommitmentError($sw, $b->get('principal'), $at));
        self::assertSame('not_yet', Workflow::workflowCommitmentError($sw, $b->get('principal'), $at - 1));
    }
}
