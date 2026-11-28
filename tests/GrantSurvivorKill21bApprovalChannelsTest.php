<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ApprovalChannels.php';

use Atlas\Pca\ApprovalChannels;
use PHPUnit\Framework\TestCase;

/** The default webhook transport's documented timeout. */
final class GrantSurvivorKill21bApprovalChannelsTest extends TestCase
{
    public function testDefaultTransportTimeout(): void
    {
        $this->assertSame(5, ApprovalChannels::HTTP_TIMEOUT_S);
    }
}
