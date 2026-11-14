<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\AuthorizeOptions;
use Atlas\Pca\MemoryStateStore;
use Atlas\Pca\PdoStateStore;
use PHPUnit\Framework\TestCase;

/** P3 (a bare guard has no plan) and H16 (multiInstance over a process-scoped store). */
final class K05HardGuardConfigTest extends TestCase
{
    private const MULTI = 'multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)';

    public function testABareGuardHasNoPlan(): void
    {
        $this->assertNull((new AuthorizeOptions())->plan);
        $this->assertSame('single-step', (new AuthorizeOptions(plan: 'single-step'))->plan);
    }

    public function testAProcessStoreRefusesMultiInstance(): void
    {
        try {
            new AuthorizeOptions(new MemoryStateStore(), static fn() => false, multiInstance: true);
            $this->fail('accepted');
        } catch (\InvalidArgumentException $e) {
            $this->assertSame(self::MULTI, $e->getMessage());
        }
        $this->assertSame('process', (new MemoryStateStore())->scope());
        $this->assertFalse((new AuthorizeOptions(new MemoryStateStore(), static fn() => false, multiInstance: false))->multiInstanceOn());
    }

    public function testAStoreWithoutAScopeIsShared(): void
    {
        $store = new class () {
            public function claim(string $key, int $counter): \Atlas\Pca\ClaimResult
            {
                return new \Atlas\Pca\ClaimResult(true);
            }
        };
        $o = new AuthorizeOptions($store, static fn() => false, multiInstance: true);
        $this->assertTrue($o->multiInstanceOn());
        $this->assertTrue((new AuthorizeOptions($store, static fn() => false))->multiInstanceOn(), 'default on for a shared store');
    }

    public function testTheDefaults(): void
    {
        $this->assertFalse((new AuthorizeOptions(new MemoryStateStore(), static fn() => false))->multiInstanceOn(), 'process store: off');
        $this->assertFalse((new AuthorizeOptions())->multiInstanceOn(), 'no store: off');
    }

    public function testASharedPdoStoreAllowsMultiInstance(): void
    {
        if (!extension_loaded('pdo_sqlite')) {
            $this->markTestSkipped('pdo_sqlite is not loaded');
        }
        $store = new PdoStateStore(new \PDO('sqlite::memory:'));
        $this->assertSame('shared', $store->scope());
        $o = new AuthorizeOptions($store, static fn() => false, multiInstance: true);
        $this->assertTrue($o->multiInstanceOn());
        $this->assertTrue((new AuthorizeOptions($store, static fn() => false))->multiInstanceOn());
    }
}
