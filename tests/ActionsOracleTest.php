<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use PHPUnit\Framework\TestCase;

/** Differential / mutation-kill oracles for src/Actions.php (see ActionsOracle). */
final class ActionsOracleTest extends TestCase
{
    public function testOraclesAgree(): void
    {
        $this->assertSame([], array_slice(ActionsOracle::run(), 0, 20));
    }
}
