<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** A goal, ontology, action or history that does not fit the IR (the reference's IrError). */
final class GoalIrError extends \RuntimeException
{
    public function __construct(string $msg = '')
    {
        parent::__construct('pca-goal: ' . $msg);
    }
}
