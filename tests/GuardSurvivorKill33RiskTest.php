<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/Risk.php';

use Atlas\Pca\Risk;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/Risk.php: a path debit that exactly spends a node succeeds and returns a list. */
final class GuardSurvivorKill33RiskTest extends TestCase
{
    /** A node holding exactly the cost covers it; the result is ok with the debited nodes as a list. */
    public function testPathDebitAtExactBudget(): void
    {
        $this->assertSame(['ok' => true, 'nodes' => [['B' => 0.0, 'tau' => 1.0, 'asOf' => null], ['B' => 2.0, 'tau' => 1.0, 'asOf' => null]]],
            Risk::debitConsolidatedPath([3 => ['B' => 5.0, 'tau' => 1.0], 7 => ['B' => 7.0, 'tau' => 1.0]], 5.0));
        $r = Risk::debitConsolidatedPath([['B' => 4.0, 'tau' => 1.0]], 5.0);
        $this->assertFalse($r['ok'], 'control: one unit short is refused');
    }
}
