<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Workflow.php';
require_once __DIR__ . '/Vectors.php';

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\Workflow;
use PHPUnit\Framework\TestCase;

/** workflowCommitmentError / workflowReceiptError over the signed workflow of the shared producer vectors. */
final class WorkflowCommitmentTest extends TestCase
{
    private function signed(): Obj
    {
        $doc = Vectors::load('producer-vectors.json');
        $case = array_values(array_filter($doc->get('cases'), static fn(Obj $c) => $c->get('name') === 'workflow-sign'))[0];
        return Obj::of(['body' => $case->get('args')->get('body'), 'sig' => $case->get('expect')->get('sig')]);
    }

    public function testCommitmentError(): void
    {
        $sw = $this->signed();
        $p = $sw->get('body')->get('principal');
        self::assertNull(Workflow::workflowCommitmentError($sw, $p, 1800000000500));
        self::assertSame('not_yet', Workflow::workflowCommitmentError($sw, $p, 1799999999999));
        self::assertSame('expired', Workflow::workflowCommitmentError($sw, $p, 1800003600000));
        self::assertSame('bad_signature', Workflow::workflowCommitmentError($sw, Pca::b64u(str_repeat("\7", 32)), 1800000000500));
        $forged = Obj::of(['body' => $sw->get('body'), 'sig' => Pca::b64u(str_repeat("\0", 64))]);
        self::assertSame('bad_signature', Workflow::workflowCommitmentError($forged, $p, 1800000000500));
        self::assertSame('bad_workflow', Workflow::workflowCommitmentError(5, $p, 1800000000500));
        self::assertSame('bad_workflow', Workflow::workflowCommitmentError($sw, 'nope', 1800000000500));
        self::assertSame('bad_workflow', Workflow::workflowCommitmentError($sw, $p, -1));
        self::assertSame(64, Workflow::WORKFLOW_LIMITS['steps']);
    }

    public function testReceiptError(): void
    {
        $w = $this->signed()->get('body');
        $rs = Pca::b64u(str_repeat("\3", 32));
        self::assertNull(Workflow::workflowReceiptError($w, $rs, [], 1800000000500));
        self::assertSame(['at' => 0], Workflow::workflowReceiptError($w, $rs, [Obj::of(['step' => 's1'])], 1800000000500));
    }
}
