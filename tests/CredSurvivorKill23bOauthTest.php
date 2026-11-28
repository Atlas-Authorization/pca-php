<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Oauth;
use PHPUnit\Framework\TestCase;

/** The default fetchDiscovery transport timeout. */
final class CredSurvivorKill23bOauthTest extends TestCase
{
    /** The default transport waits 5 seconds. */
    public function testDiscoveryTimeout(): void
    {
        $this->assertSame(5, Oauth::DISCOVERY_TIMEOUT_SEC);
    }
}
