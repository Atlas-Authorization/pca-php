<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PqThresholdExperimental.php';

use Atlas\Pca\PqThresholdExperimental as X;
use PHPUnit\Framework\TestCase;

/** group 33 kills for src/PqThresholdExperimental.php: the design data, the n bound, the sampler (custom and default range) and the share loop. */
final class GuardSurvivorKill33PqThresholdExperimentalTest extends TestCase
{
    private const OK = ['iUnderstandThisIsNotProduction' => true];

    protected function tearDown(): void
    {
        X::$randomIntHook = null;
    }

    /** The documented design names its scheme and both illustrative parameter sets in full. */
    public function testDesignData(): void
    {
        $d = X::raccoonDesign();
        $this->assertSame(['scheme', 'status', 'productionReady', 'banner', 'assumption', 'construction', 'whyNoLibraryYet', 'shippableAlternative',
            'parameterSets', 'references'], array_keys($d));
        $this->assertSame('Raccoon/Ringtail-style lattice threshold (RESEARCH)', $d['scheme']);
        $this->assertSame([
            ['name' => 'Raccoon-128 (illustrative)', 'nistCategory' => 1, 'note' => 'Research parameters only; not implemented here.'],
            ['name' => 'Raccoon-192 (illustrative)', 'nistCategory' => 3, 'note' => 'Matches ML-DSA-65 category; not implemented here.'],
        ], $d['parameterSets']);
    }

    /** A caller's sampler is used for shares 1..n-1 (never the OS source); the last share absorbs the remainder. */
    public function testCustomSamplerAndShareLoop(): void
    {
        X::$randomIntHook = static function (int $a, int $b): int {
            throw new \LogicException('the default sampler ran');
        };
        $q = X::TOY_DEFAULT_PARAMS['q'];
        $shares = X::additiveShareLatticeKey([1, 2, 3, 4], 3, self::OK, X::TOY_DEFAULT_PARAMS, static fn(int $m): int => 7);
        $this->assertSame([
            ['index' => 1, 'coeffs' => [7, 7, 7, 7]],
            ['index' => 2, 'coeffs' => [7, 7, 7, 7]],
            ['index' => 3, 'coeffs' => [1 - 14 + $q, 2 - 14 + $q, 3 - 14 + $q, 4 - 14 + $q]],
        ], $shares);
    }

    /** n = 1024 is the largest accepted share count. */
    public function testMaxShareCount(): void
    {
        $this->assertCount(1024, X::additiveShareLatticeKey([1, 2, 3, 4], 1024, self::OK, X::TOY_DEFAULT_PARAMS, static fn(int $m): int => 0));
    }

    /** The default sampler draws each share coefficient uniformly from [0, q). */
    public function testDefaultSamplerRange(): void
    {
        $calls = [];
        X::$randomIntHook = static function (int $a, int $b) use (&$calls): int {
            $calls[] = [$a, $b];
            return $b;
        };
        $q = X::TOY_DEFAULT_PARAMS['q'];
        $shares = X::additiveShareLatticeKey([1, 2, 3, 4], 2, self::OK);
        $this->assertSame(array_fill(0, 4, [0, $q - 1]), $calls);
        $this->assertSame([$q - 1, $q - 1, $q - 1, $q - 1], $shares[0]['coeffs']);
        $this->assertSame([1, 2, 3, 4], X::reconstructLatticeKey($shares, self::OK));
    }
}
