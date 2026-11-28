<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Facade.php';

use Atlas\Pca\AgentHandle;
use Atlas\Pca\Catalog;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\PcaAgentError;
use Atlas\Pca\Sign;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Facade.php: the agent error keeps its message; a numeric-string budget is read as a number. */
final class GuardSurvivorKill33FacadeTest extends TestCase
{
    private static function handle(mixed $bMax): AgentHandle
    {
        $policy = ['predicates' => [['verb' => 'files.read', 'resource' => '*']], 'caveats' => [],
            'riskPolicy' => ['bMax' => $bMax] + Sign::defaultRiskPolicy(), 'budgetModel' => 'risk'];
        return new AgentHandle(new Obj(), [new Obj()], 's', $policy, new KeyPair(str_repeat("\x07", 32)), 'pk', new Catalog(), 'rs', 0, null);
    }

    /** PcaAgentError carries its message and code. */
    public function testAgentErrorKeepsItsMessage(): void
    {
        $e = new PcaAgentError('network', 'the server is unreachable', 503);
        $this->assertSame('the server is unreachable', $e->getMessage());
        $this->assertSame('network', $e->errorCode);
        $this->assertSame(503, $e->httpStatus);
    }

    /** A budget given as a numeric string is converted before the finiteness check, as for a number. */
    public function testNumericStringBudget(): void
    {
        $want = self::handle(1000)->dryRun('files.read', 'f', null, 0);
        $this->assertTrue($want['allowed'], 'control');
        $this->assertSame($want, self::handle('1000')->dryRun('files.read', 'f', null, 0));
    }
}
