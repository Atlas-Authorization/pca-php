<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/GoalBinding.php';

use Atlas\Pca\Decision;
use Atlas\Pca\GoalBinding;
use PHPUnit\Framework\TestCase;

/** mutation kills for src/GoalBinding.php: a non-numeric replay always tightens, and openCommit refuses a non-string commit itself. */
final class RestSurvivorKill36cGoalBindingTest extends TestCase
{
    /** A non-numeric replayed fidelity is unconfirmed: it tightens even against a minimum of 0. */
    public function testNonNumericReplayTightensAtMinZero(): void
    {
        $tight = Decision::tighten('allow', 'escalate');
        $this->assertNotSame('allow', $tight);
        $this->assertSame($tight, GoalBinding::claimGate('allow', 0, null, 'x'));
        $this->assertSame('allow', GoalBinding::claimGate('allow', 0, null, 0), 'control: a replay at the minimum passes');
    }

    /** A non-string commit is refused with the module's own TypeError message. */
    public function testOpenCommitNeedsAString(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('commit must be a string');
        GoalBinding::openCommit(5, 'g', 'p', 's');
    }
}
