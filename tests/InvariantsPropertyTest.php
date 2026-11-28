<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\InvariantFailure;
use Atlas\Pca\Invariants;
use Atlas\Pca\InvariantsProps;
use Atlas\Pca\InvariantsRng;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The invariant property runner over the real native core, its determinism, option validation and failure report, and the negative
 * controls: every invariant must FAIL against a core that has been broken on purpose (the reference's teeth suite).
 */
final class InvariantsPropertyTest extends TestCase
{
    public function testEveryInvariantHoldsUnderTheRunner(): void
    {
        $results = InvariantsProps::checkInvariants(['numRuns' => 60, 'seed' => Invariants::DEFAULT_SEED]);
        $failures = array_values(array_filter($results, static fn(array $r): bool => $r['ok'] !== true));
        $this->assertSame([], array_map(static fn(array $f): string => $f['name'] . ': ' . ($f['error'] ?? ''), $failures));
        $this->assertSame(Invariants::INVARIANT_NAMES, array_map(static fn(array $r): string => $r['name'], $results));
        $this->assertGreaterThanOrEqual(11, count($results));
    }

    public function testDefaultsAndResultShape(): void
    {
        $this->assertSame(1000, InvariantsProps::DEFAULT_NUM_RUNS);
        $this->assertSame(20260108, InvariantsProps::DEFAULT_SEED);
        $this->assertSame(Invariants::INVARIANT_NAMES, InvariantsProps::names());
        $this->assertCount(count(InvariantsProps::names()), array_unique(InvariantsProps::names()));
        foreach (InvariantsProps::checkInvariants(['numRuns' => 5, 'seed' => 3]) as $x) {
            $this->assertSame(['name' => $x['name'], 'ok' => true, 'numRuns' => 5, 'seed' => 3], $x);
        }
    }

    public static function badNumRuns(): array
    {
        return [[0], [-1], [1.5], [NAN], [INF], ['10']];
    }

    #[DataProvider('badNumRuns')]
    public function testANonPositiveIntegerNumRunsIsRefused(mixed $numRuns): void
    {
        $this->expectException(\RangeException::class);
        $this->expectExceptionMessage('checkInvariants: numRuns must be a positive integer');
        InvariantsProps::checkInvariants(['numRuns' => $numRuns]);
    }

    public static function badSeed(): array
    {
        return [[1.5], [NAN], [INF], ['3']];
    }

    #[DataProvider('badSeed')]
    public function testANonIntegerSeedIsRefused(mixed $seed): void
    {
        $this->expectException(\RangeException::class);
        $this->expectExceptionMessage('checkInvariants: seed must be an integer');
        InvariantsProps::checkInvariants(['seed' => $seed]);
    }

    public function testTheSameSeedGivesTheSameOutcomeAndCases(): void
    {
        $this->assertSame(InvariantsProps::checkInvariants(['numRuns' => 15, 'seed' => 11]), InvariantsProps::checkInvariants(['numRuns' => 15, 'seed' => 11]));
        foreach (InvariantsProps::names() as $name) {
            $this->assertSame(InvariantsProps::caseDigest($name, 25, 11), InvariantsProps::caseDigest($name, 25, 11), $name);
        }
    }

    public function testAnotherSeedDrawsAnotherCaseStream(): void
    {
        foreach (InvariantsProps::names() as $name) {
            if ($name === 'fail-closed:undecidable-groups') {
                continue; // a constant property: its single case does not depend on the stream
            }
            $this->assertNotSame(InvariantsProps::caseDigest($name, 25, 11), InvariantsProps::caseDigest($name, 25, 12), $name);
        }
    }

    public function testThePropertiesDrawFromDistinctStreams(): void
    {
        $this->assertNotSame(InvariantsRng::forProperty(1, 0)->next(), InvariantsRng::forProperty(1, 1)->next());
        $this->assertNotSame(InvariantsRng::forProperty(1, 0)->next(), InvariantsRng::forProperty(1 + (1 << 32), 0)->next());
    }

    public function testMulberry32MatchesTheReferenceStream(): void
    {
        $expect = [
            1 => [0.6270739405881613, 0.002735721180215478, 0.5274470399599522, 0.9810509674716741],
            20260108 => [0.16171224368736148, 0.6280037518590689, 0.013519245898351073, 0.5213279332965612],
            4294967295 => [0.8964226141106337, 0.189478256739676, 0.7156526781618595, 0.9440599093213677],
        ];
        foreach ($expect as $seed => $xs) {
            $g = new InvariantsRng($seed);
            foreach ($xs as $i => $x) {
                $this->assertSame($x, $g->next(), "seed $seed value $i");
            }
        }
    }

    public function testTheRngDrawsStayInRange(): void
    {
        $g = new InvariantsRng(5);
        for ($i = 0; $i < 500; $i++) {
            $this->assertContains($g->int(2, 4), [2, 3, 4]);
            $this->assertGreaterThanOrEqual(-3, $g->intB(-3, 3));
            $this->assertLessThanOrEqual(3, $g->intB(-3, 3));
            $d = $g->dbl(0.0, 1.0);
            $this->assertTrue($d >= 0.0 && $d <= 1.0);
        }
        $this->assertSame(32, strlen($g->bytes(32)));
        $s = $g->string(1, 12);
        $this->assertTrue(strlen($s) >= 1 && strlen($s) <= 12 && preg_match('/\A[\x20-\x7e]+\z/', $s) === 1);
    }

    public function testAFailureIsReportedWithItsSeedAndCounterexample(): void
    {
        $results = InvariantsProps::withCore(
            ['verifyChain' => static fn(): array => ['ok' => true, 'reason' => '']],
            static fn(): array => InvariantsProps::checkInvariants(['numRuns' => 40, 'seed' => 9]),
        );
        $by = [];
        foreach ($results as $r) {
            $by[$r['name']] = $r;
        }
        $bad = $by['fail-closed:garbage-chain-rejected'];
        $this->assertFalse($bad['ok']);
        $this->assertSame(['property', 'seed', 'counterexample', 'case', 'error'], array_keys($bad['report']));
        $this->assertSame('fail-closed:garbage-chain-rejected', $bad['report']['property']);
        $this->assertSame(9, $bad['report']['seed']);
        $this->assertNotSame('', $bad['report']['counterexample']);
        $this->assertStringContainsString('fail-closed:garbage-chain-rejected', $bad['error']);
        $this->assertTrue($by['risk-wellformed-and-monotone']['ok']); // an unrelated property is untouched
    }

    public function testBailStopsAtTheFirstFailure(): void
    {
        $results = InvariantsProps::withCore(
            ['verifyChain' => static fn(): array => ['ok' => false, 'reason' => 'x']],
            static fn(): array => InvariantsProps::checkInvariants(['numRuns' => 10, 'seed' => 1, 'bail' => true]),
        );
        $this->assertFalse($results[count($results) - 1]['ok']);
        $this->assertLessThan(count(InvariantsProps::names()), count($results));
    }

    public function testACheckThatThrowsIsAFailure(): void
    {
        $this->expectException(InvariantFailure::class);
        InvariantsProps::withCore(
            ['riskScore' => static function (): float { throw new \RuntimeException('boom'); }],
            static fn() => InvariantsProps::run('risk-wellformed-and-monotone', 5, 1),
        );
    }

    public function testAnUnknownInvariantIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        InvariantsProps::run('no-such-invariant', 1, 1);
    }

    // ---- negative controls ------------------------------------------------------------

    private function assertFailsAgainst(array $patch, string $name): void
    {
        $failed = InvariantsProps::withCore($patch, static function () use ($name): bool {
            try {
                InvariantsProps::run($name, 300, 7);
                return false;
            } catch (InvariantFailure) {
                return true;
            }
        });
        $this->assertTrue($failed, "$name must fail against a broken core");
    }

    public function testAdmissionSoundnessFailsWhenEverythingIsAdmittedUnmetered(): void
    {
        $this->assertFailsAgainst(['admit' => static fn(): array => ['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => false]], 'admission-soundness');
    }

    public function testUnknownCaveatTypeFailsWhenTheEvaluatorAcceptsWhatItDoesNotKnow(): void
    {
        $this->assertFailsAgainst(['evaluateCaveats' => static fn(): array => ['ok' => true, 'failed' => []]], 'fail-closed:unknown-caveat-type');
    }

    public function testForbidMonotoneFailsWhenAPermitCanBeatAForbid(): void
    {
        $real = InvariantsProps::real('decideClauses');
        $this->assertFailsAgainst(['decideClauses' => static fn(array $cl, Obj $ctx): array => $real(
            array_values(array_filter($cl, static fn(Obj $c): bool => $c->get('kind') !== 'forbid')),
            $ctx,
        )], 'forbid-monotone');
    }

    public function testForgedChainFailsAgainstAVerifierThatAcceptsEverything(): void
    {
        $this->assertFailsAgainst(['verifyChain' => static fn(): array => ['ok' => true, 'reason' => '']], 'fail-closed:forged-chain-rejected');
    }

    public function testGarbageChainFailsAgainstAVerifierThatAcceptsEverything(): void
    {
        $this->assertFailsAgainst(['verifyChain' => static fn(): array => ['ok' => true, 'reason' => '']], 'fail-closed:garbage-chain-rejected');
    }

    public function testDeterminismFailsWhenTheRiskScoreIsNotAFunctionOfItsInputs(): void
    {
        $real = InvariantsProps::real('riskScore');
        $this->assertFailsAgainst(['riskScore' => static fn(array $i, array $w): float => $real($i, $w) + mt_rand() / mt_getrandmax() * 1e-3], 'determinism');
    }

    public function testRiskMonotoneFailsWhenTheScoreGoesDownAsInputsGetWorse(): void
    {
        $real = InvariantsProps::real('riskScore');
        $this->assertFailsAgainst(['riskScore' => static fn(array $i, array $w): float => 1 - $real($i, $w)], 'risk-wellformed-and-monotone');
    }

    public function testUndecidableLeafFailsWhenUnknownCountsAsTrue(): void
    {
        $this->assertFailsAgainst([
            'evaluateConditionTri' => static fn(): string => 'true',
            'evaluateCondition' => static fn(): bool => true,
        ], 'fail-closed:undecidable-leaf');
    }

    public function testAttenuationFailsWhenADelegateDropsTheParentCaveats(): void
    {
        $real = InvariantsProps::real('buildChain');
        $this->assertFailsAgainst(['buildChain' => static function (Obj $m) use ($real): array {
            $chain = $real($m);
            foreach ($chain['caps'] as $i => $cap) {
                if ($i > 0) {
                    $cap->set('caveats', []);
                }
            }
            return $chain;
        }], 'attenuation-monotonicity');
    }

    public function testAttenuationFailsWhenTheVerifierRejectsALegalChain(): void
    {
        $this->assertFailsAgainst(['verifyChain' => static fn(): array => ['ok' => false, 'reason' => 'no']], 'attenuation-monotonicity');
    }

    public function testCumulativeBudgetFailsWhenAdmitIgnoresTheRemainingBudget(): void
    {
        $this->assertFailsAgainst(['admit' => static fn(): array => ['admit' => true, 'needStepUp' => false, 't' => 1, 'metered' => true]], 'cumulative-budget-bound');
    }

    public function testUndecidableGroupsFailWhenTheEvaluatorSaysTrueForEverything(): void
    {
        $this->assertFailsAgainst(['evaluateConditionTri' => static fn(): string => 'true'], 'fail-closed:undecidable-groups');
    }

    public function testMemberOfCycleFailsWhenNoTargetIsReachable(): void
    {
        $this->assertFailsAgainst(['evaluateConditionTri' => static fn(): string => 'false'], 'fail-closed:member-of-cycle-safe');
    }

    public function testTheUnbrokenCorePassesTheSameCases(): void
    {
        $results = InvariantsProps::withCore([], static fn(): array => InvariantsProps::checkInvariants(['numRuns' => 100, 'seed' => 7]));
        foreach ($results as $r) {
            $this->assertTrue($r['ok'], $r['name'] . ': ' . ($r['error'] ?? ''));
        }
    }

    public function testEveryRegisteredInvariantHasANegativeControlAbove(): void
    {
        $covered = ['admission-soundness', 'fail-closed:unknown-caveat-type', 'fail-closed:forged-chain-rejected', 'fail-closed:garbage-chain-rejected',
            'determinism', 'risk-wellformed-and-monotone', 'fail-closed:undecidable-leaf', 'attenuation-monotonicity', 'cumulative-budget-bound',
            'fail-closed:undecidable-groups', 'fail-closed:member-of-cycle-safe', 'forbid-monotone'];
        $names = InvariantsProps::names();
        sort($names);
        sort($covered);
        $this->assertSame($covered, $names);
    }
}
