<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/PqThresholdExperimental.php';

use Atlas\Pca\Obj;
use Atlas\Pca\PqThresholdExperimental as X;
use PHPUnit\Framework\TestCase;

/** The experimental lattice-threshold sketch: refuses without the explicit opt-in, shares n-of-n additively over Z_q, reconstructs only from every share. */
final class PqThresholdExperimentalTest extends TestCase
{
    private const OK = ['iUnderstandThisIsNotProduction' => true];

    public function testEveryRoutineRefusesWithoutTheOptIn(): void
    {
        foreach ([null, [], ['iUnderstandThisIsNotProduction' => false], ['iUnderstandThisIsNotProduction' => 1], Obj::of(['iUnderstandThisIsNotProduction' => 'true'])] as $bad) {
            try {
                X::additiveShareLatticeKey([1, 2, 3, 4], 2, $bad);
                $this->fail('refused');
            } catch (\RuntimeException $e) {
                $this->assertStringStartsWith('EXPERIMENTAL', $e->getMessage());
                $this->assertStringContainsString('iUnderstandThisIsNotProduction: true', $e->getMessage());
            }
        }
        $this->expectException(\RuntimeException::class);
        X::reconstructLatticeKey([['index' => 1, 'coeffs' => [0, 0, 0, 0]]], ['iUnderstandThisIsNotProduction' => false]);
    }

    public function testSharesSumToTheKeyAndNeedEveryShare(): void
    {
        $q = X::TOY_DEFAULT_PARAMS['q'];
        $key = [5, $q - 1, 0, 123456];
        $n = 0;
        $shares = X::additiveShareLatticeKey($key, 4, Obj::of(self::OK), X::TOY_DEFAULT_PARAMS, static function (int $m) use (&$n): int {
            return ($n++ * 7919 + 13) % $m;
        });
        $this->assertCount(4, $shares);
        $this->assertSame([1, 2, 3, 4], array_column($shares, 'index'));
        $this->assertSame($key, X::reconstructLatticeKey($shares, self::OK));
        $this->assertNotSame($key, X::reconstructLatticeKey(array_slice($shares, 0, 3), self::OK)); // n-of-n: a missing share gives another vector
        // a negative key coefficient is reduced mod q
        $neg = X::additiveShareLatticeKey([-1, 0, 0, 0], 1, self::OK);
        $this->assertSame([$q - 1, 0, 0, 0], X::reconstructLatticeKey($neg, self::OK));
        // the default sampler is the OS source: still a valid sharing
        $this->assertSame($key, X::reconstructLatticeKey(X::additiveShareLatticeKey($key, 5, self::OK), self::OK));
    }

    public function testShapeChecks(): void
    {
        foreach ([[[1, 2, 3], 2], [[1, 2, 3, 4], 0], [[1, 2, 3, 4], 1025]] as [$key, $n]) {
            try {
                X::additiveShareLatticeKey($key, $n, self::OK);
                $this->fail('range');
            } catch (\RangeException) {
                $this->addToAssertionCount(1);
            }
        }
        $s = ['index' => 1, 'coeffs' => [0, 0, 0, 0]];
        foreach ([[], [$s, $s], [['index' => 1, 'coeffs' => [0]]]] as $bad) {
            try {
                X::reconstructLatticeKey($bad, self::OK);
                $this->fail('range');
            } catch (\RangeException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testTheDesignIsDocumentedDataThatSaysNotProduction(): void
    {
        $d = X::raccoonDesign();
        $this->assertFalse($d['productionReady']);
        $this->assertSame('research-prototype', $d['status']);
        $this->assertSame(X::BANNER, $d['banner']);
        $this->assertCount(5, $d['construction']);
        $this->assertCount(4, $d['whyNoLibraryYet']);
        $this->assertCount(3, $d['references']);
        $this->assertCount(2, $d['parameterSets']);
    }
}
