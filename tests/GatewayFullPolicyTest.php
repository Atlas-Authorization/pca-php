<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Gateway;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Full-policy mode configuration: what is refused at construction (fail closed). */
final class GatewayFullPolicyTest extends TestCase
{
    private static function opts(array $policy): array
    {
        return ['audience' => 'https://api.example', 'routes' => [], 'resolveGrant' => static fn($r = null, $p = null) => null,
            'policy' => $policy];
    }

    public function testMissingComponentsNamed(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('full policy mode is missing state, isRevoked');
        Gateway::createGateway(self::opts(['mode' => 'full', 'params' => 'body']));
    }

    public function testUnknownOptionRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Gateway::createGateway(self::opts(['mode' => 'full', 'params' => 'body', 'state' => new MemoryStateStore(),
            'isRevoked' => static fn() => false, 'bogus' => true]));
    }

    public function testCompleteConfigurationBuilds(): void
    {
        $g = Gateway::createGateway(self::opts(['mode' => 'full', 'params' => 'body', 'state' => new MemoryStateStore(),
            'isRevoked' => static fn() => false]));
        $this->assertInstanceOf(\Closure::class, $g);
    }
}
