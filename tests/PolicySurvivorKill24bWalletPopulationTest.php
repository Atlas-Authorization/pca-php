<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Obj;
use Atlas\Pca\Pca;
use Atlas\Pca\PopulationAggregator;
use Atlas\Pca\WalletPopulation;
use PHPUnit\Framework\TestCase;

/** Mutation kills (group 24b) for src/WalletPopulation.php: rounding, the CSPRNG draw, the DP helpers, the aggregator and the prior. */
final class PolicySurvivorKill24bWalletPopulationTest extends TestCase
{
    protected function tearDown(): void
    {
        WalletPopulation::$randomBytesHook = null;
    }

    private static function digest(): string
    {
        return Pca::b64u(hash('sha256', 'atlas-pca-conformance/kill24b-population', true));
    }

    private static function throws(callable $f, string $class, string $msg): void
    {
        try {
            $f();
        } catch (\Throwable $e) {
            self::assertSame([$class, $msg], [$e::class, $e->getMessage()]);
            return;
        }
        self::fail("no $class thrown");
    }

    /** jsRound is JavaScript's Math.round: halves go up, also where PHP's round() leaves a value beyond its precision unchanged. */
    public function testJsRound(): void
    {
        $this->assertSame(3, WalletPopulation::jsRound(2.5));
        $this->assertSame(0, WalletPopulation::jsRound(-0.5));
        $this->assertSame(4503599627370496, WalletPopulation::jsRound(4503599627370495.5));
    }

    /** cryptoRand reads 8 bytes: the top 27 bits of the first big-endian word and the top 26 of the second, plus one half, over 2^53. */
    public function testCryptoRandFromBytes(): void
    {
        $lens = [];
        WalletPopulation::$randomBytesHook = static function (int $n) use (&$lens): string {
            $lens[] = $n;
            return substr("\x00\x00\x00\x20\x00\x00\x00\x40", 0, $n);
        };
        $this->assertSame(67108865.5 / 9007199254740992, WalletPopulation::cryptoRand());
        $this->assertSame([8], $lens);
        WalletPopulation::$randomBytesHook = null;
        $u = WalletPopulation::cryptoRand();
        $this->assertTrue($u > 0 && $u < 1);
    }

    /** Box-Muller draws again while u is 0 (log 0 would be infinite). */
    public function testGaussianRedrawsZero(): void
    {
        $seq = [0.0, 0.5, 0.25];
        $rand = static function () use (&$seq): float {
            return array_shift($seq);
        };
        $this->assertSame(sqrt(-2 * log(0.5)) * cos(2 * M_PI * 0.25), WalletPopulation::gaussian($rand));
    }

    /** gaussianSigma refuses delta 0 with its own message, and a non-number with TypeError 'a number is required'. */
    public function testGaussianSigmaGuards(): void
    {
        self::throws(static fn() => WalletPopulation::gaussianSigma(0.5, 0, 1), \InvalidArgumentException::class, 'gaussianSigma: delta must be in (0, 1)');
        self::throws(static fn() => WalletPopulation::gaussianSigma('x', 0.5, 1), \TypeError::class, 'a number is required');
    }

    /** A uniform draw exactly at the keep probability flips the answer (keep needs rand < p). */
    public function testRandomizedResponseBoundary(): void
    {
        $p = WalletPopulation::rrKeepProbability(1.0);
        $this->assertSame(0.0, WalletPopulation::randomizedResponse(1, 1.0, static fn(): float => $p));
    }

    /** debias refuses a non-number count and a non-integer one beyond PHP round()'s precision. */
    public function testDebiasCounts(): void
    {
        self::throws(static fn() => WalletPopulation::debiasRandomizedResponse('x', 2, 1.0), \InvalidArgumentException::class, 'debias: bad counts');
        self::throws(static fn() => WalletPopulation::debiasRandomizedResponse(1000000000000000.5, 2000000000000000, 1.0), \InvalidArgumentException::class, 'debias: bad counts');
    }

    /** The aggregator's cell cap must be a finite positive integer. */
    public function testMaxCellsMustBeAPositiveInteger(): void
    {
        foreach (['x', INF, 1000000000000000.5] as $bad) {
            self::throws(static fn() => new PopulationAggregator(self::digest(), 7, ['maxCellsPerPrincipal' => $bad]), \InvalidArgumentException::class,
                'PopulationAggregator: maxCellsPerPrincipal must be a positive integer');
        }
    }

    private static function vote(mixed $key, string $principal = 'p1', mixed $period = 7): array
    {
        return ['principal' => $principal, 'schemaDigest' => self::digest(), 'cellKey' => $key, 'y' => 1, 'period' => $period];
    }

    /** Cell keys are set members as in Python: true and 1 are the same cell, 1 and 2 are not; an object key is unhashable; a vote must be an object. */
    public function testVoteKeys(): void
    {
        $agg = new PopulationAggregator(self::digest(), 7);
        $this->assertSame(['ok' => true], $agg->contribute(self::vote(true)));
        $this->assertSame(['ok' => false, 'reason' => 'one vote per principal per cell per period (sensitivity 1)'], $agg->contribute(self::vote(1)));
        $this->assertSame(['ok' => true], $agg->contribute(self::vote(2)));
        self::throws(static fn() => $agg->contribute(self::vote([1])), \TypeError::class, 'unhashable type');
        self::throws(static fn() => $agg->contribute('x'), \TypeError::class, 'a vote must be an object');
    }

    /** A period that has no JSON form never matches, not even itself. */
    public function testUnserializablePeriodNeverMatches(): void
    {
        $period = new \stdClass();
        $agg = new PopulationAggregator(self::digest(), $period);
        $this->assertSame(['ok' => false, 'reason' => 'vote for another period'], $agg->contribute(self::vote('k', 'p1', $period)));
    }

    /** An aggregator whose noise is exactly zero (u = v = 1). */
    private static function quiet(): PopulationAggregator
    {
        return new PopulationAggregator(self::digest(), 7, ['rand' => static fn(): float => 1.0]);
    }

    /** A noisy total exactly at minCount is released; a suppressed cell does not stop the cells after it. */
    public function testReleaseMinCount(): void
    {
        $agg = self::quiet();
        $agg->contribute(self::vote('k1'));
        $this->assertSame(['k1'], $agg->release(['epsilon' => 0.5, 'delta' => 0.5, 'minCount' => 1])->get('cells')->keys());
        $agg = self::quiet();
        $agg->contribute(self::vote('a'));
        $agg->contribute(self::vote('b'));
        $agg->contribute(self::vote('b', 'p2'));
        $cells = $agg->release(['epsilon' => 0.5, 'delta' => 0.5, 'minCount' => 2])->get('cells');
        $this->assertSame(['b'], $cells->keys());
        $this->assertSame([0.98, 2], [$cells->get('b')->get('q'), $cells->get('b')->get('n')]);
    }

    /** release refuses qMin 0, a non-number qMin, and non-string cell keys. */
    public function testReleaseGuards(): void
    {
        $agg = self::quiet();
        $agg->contribute(self::vote('k1'));
        self::throws(static fn() => $agg->release(['epsilon' => 0.5, 'delta' => 0.5, 'qMin' => 0]), \InvalidArgumentException::class, 'release: qMin must be in (0, 0.5)');
        self::throws(static fn() => $agg->release(['epsilon' => 0.5, 'delta' => 0.5, 'qMin' => 'x']), \TypeError::class, 'a number is required');
        $agg = self::quiet();
        $agg->contribute(self::vote(5));
        self::throws(static fn() => $agg->release(['epsilon' => 0.5, 'delta' => 0.5]), \TypeError::class, 'cell keys must be strings');
    }

    /** The beta guard names the bound. */
    public function testPriorBetaMessage(): void
    {
        self::throws(static fn() => WalletPopulation::populationPrior(Obj::of(['schema' => self::digest(), 'cells' => new Obj()]), 1),
            \InvalidArgumentException::class, 'populationPrior: beta must be in [0, 0.9] (full support needs beta < 1)');
    }

    /** The prior skips unreleased cells (and goes on to the released ones) and keeps the tables it built for a verb space. */
    public function testPriorTablesSkipAndCache(): void
    {
        $vs = Obj::of(['verb' => 'zz.pp', 'reversibility' => 'reversible', 'weight' => 1, 'dims' => [Obj::of(['kind' => 'cat', 'path' => 'action.resource',
            'values' => [Obj::of(['kind' => 'exact', 'value' => 'a']), Obj::of(['kind' => 'exact', 'value' => 'b']), Obj::of(['kind' => 'other', 'value' => "\u{22A5}"])]])]]);
        $key = WalletPopulation::populationCellKey(self::digest(), $vs, [1]);
        $cells = new Obj();
        $cells->set($key, Obj::of(['q' => 0.25]));
        $pm = WalletPopulation::populationPrior(Obj::of(['schema' => self::digest(), 'cells' => $cells]), 0.5);
        $in1 = static fn(mixed $c): bool => $c === 1;
        $this->assertSame(exp(0.0 + log(0.25)), ($pm['weight'])($vs, $in1));
        $cells->set($key, Obj::of(['q' => 0.5]));
        $this->assertSame(exp(0.0 + log(0.25)), ($pm['weight'])($vs, $in1));
    }

    private static function lverb(string $verb, float $weight, array $values): Obj
    {
        $vals = array_map(static fn(string $v): Obj => Obj::of(['kind' => 'exact', 'value' => $v]), $values);
        $vals[] = Obj::of(['kind' => 'other', 'value' => "\u{22A5}"]);
        return Obj::of(['verb' => $verb, 'reversibility' => 'reversible', 'weight' => $weight, 'dims' => [Obj::of(['kind' => 'cat', 'path' => 'action.resource', 'values' => $vals])]]);
    }

    /**
     * Four verbs at tau 0.7, nullMass 0, no observations: without the prior every two-cell verb has p = 2/3 (out) and the one-cell verb p = 1 (in).
     * The prior pulls cell 0 of v1 (mass 0.5) and v2 (mass 0.25) in, leaves v4 out and v3 in: 0.75 of mass is admitted only by the prior.
     */
    public function testPriorAdmittedPpm(): void
    {
        $omega = Obj::of(['v' => 1, 'approximate' => [], 'verbs' => [self::lverb('v1', 1.0, ['a']), self::lverb('v2', 0.5, ['a']), self::lverb('v3', 0.25, []),
            self::lverb('v4', 0.5, ['a'])]]);
        $mix = ['beta' => 0.5, 'weight' => static function (mixed $vs, \Closure $contains): float {
            return match ($vs->get('verb')) {
                'v3' => $contains(0) ? 1.0 : 0.0,
                'v4' => 1.0,
                default => $contains(0) && !$contains(1) ? 1.0 : 0.0,
            };
        }];
        $this->assertSame(750000, PopulationAggregator::priorAdmittedPpm($omega, [0 => 'x', 'tau' => 0.7, 'nullMass' => 0, 'priorMix' => 'dropped'], [], $mix));
        $this->assertSame(750000, PopulationAggregator::priorAdmittedPpm($omega, Obj::of(['tau' => 0.7, 'nullMass' => 0]), [], $mix));
        // no options at all: tau 1 and nullMass 0.2, nothing is admitted either way
        $this->assertSame(0, PopulationAggregator::priorAdmittedPpm($omega, null, [], $mix));
    }
}
