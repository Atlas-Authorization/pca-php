<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\HarmModel;
use Atlas\Pca\IntentRuntime;
use Atlas\Pca\IntentV2;
use Atlas\Pca\Obj;
use PHPUnit\Framework\TestCase;

/** Group 32 mutation kills for src/IntentRuntime.php: bond sizing, routing, the IC-Att, the semantic risk clamp and the JIT request. */
final class IntentSurvivorKill32IntentRuntimeTest extends TestCase
{
    protected function setUp(): void
    {
        set_error_handler(static function (int $no, string $msg): bool {
            throw new \ErrorException($msg, 0, $no);
        });
    }

    protected function tearDown(): void
    {
        restore_error_handler();
    }

    private static function vs(): Obj
    {
        return Obj::of(['verb' => 'v', 'reversibility' => 'reversible', 'weight' => 1, 'dims' => []]);
    }

    /** A learner stub: a fixed acceptance, always in the grant, never vetoed, with the given `harm` member. */
    private static function learner(float $p, mixed $harm): object
    {
        return new class ($p, $harm, Obj::of(['verbs' => [self::vs()]])) {
            public function __construct(public float $p, public mixed $harm, public Obj $omega)
            {
            }

            public function acceptance(mixed $o): float
            {
                return $this->p;
            }

            public function admitsOutcome(mixed $o): bool
            {
                return true;
            }

            public function isVetoed(mixed $o): bool
            {
                return false;
            }
        };
    }

    private static function outcome(): Obj
    {
        return Obj::of(['verb' => 'v', 'values' => new Obj()]);
    }

    /** The default bond policy is floor 1, k 1, at most 100 open claims, no amount cap. */
    public function testTheDefaultBondPolicy(): void
    {
        $p = IntentRuntime::defaultBondPolicy();
        self::assertSame(['floor', 'k', 'maxOpenClaims', 'maxOpenAmount'], $p->keys());
        self::assertSame(1, $p->get('floor'));
        self::assertSame(1, $p->get('k'));
        self::assertSame(100, $p->get('maxOpenClaims'));
        self::assertSame(INF, $p->get('maxOpenAmount'));
    }

    /** A non-positive amount is returned unchanged by the micro-grid snap (its sign of zero and its sub-micro digits kept). */
    public function testANonPositiveAmountIsNotSnapped(): void
    {
        self::assertSame(-INF, fdiv(1.0, IntentRuntime::bondAmount(['floor' => -0.0, 'k' => -1], 0)), 'negative zero stays negative zero');
        self::assertSame(-4.0E-7, IntentRuntime::bondAmount(['floor' => -4.0E-7, 'k' => -1], 1));
    }

    /** Noise of at most 1e-3 micro-units is absorbed, exactly at the limit too; an amount already on the grid stays put even when its product is noisy. */
    public function testTheMicroGridSnap(): void
    {
        self::assertSame(0.0, IntentRuntime::bondAmount(['floor' => 1.0E-9, 'k' => 0], 0), '1e-9 * 1e6 is exactly 1e-3: absorbed');
        self::assertSame(138761186.11419, IntentRuntime::bondAmount(['floor' => 138761186.11419, 'k' => 0], 0), 'r / 1e6 === x keeps x');
        self::assertSame(1.000001, IntentRuntime::bondAmount(['floor' => 1.0000005, 'k' => 0], 0), 'half a micro rounds up');
    }

    /** A negative zero or a negative exposure is treated as no exposure (the floor decides). */
    public function testANonPositiveExposureIsZero(): void
    {
        self::assertSame(INF, fdiv(1.0, IntentRuntime::bondAmount(['floor' => -1, 'k' => 1], -0.0)), 'positive zero');
        self::assertSame(0.0, IntentRuntime::bondAmount(['floor' => -10, 'k' => 1], -5));
    }

    /** The curve kind is read from an associative-array curve as well as an object one. */
    public function testAnArrayCurveIsRead(): void
    {
        self::assertSame(10.0, IntentRuntime::bondAmount(['floor' => 0, 'k' => 2, 'curve' => ['kind' => 'linear']], 5));
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('bondAmount: power curve requires finite gamma >= 1');
        IntentRuntime::bondAmount(['floor' => 0, 'k' => 1, 'curve' => ['kind' => 'power', 'gamma' => 0.5]], 5);
    }

    /** An infinite gamma is refused. */
    public function testAnInfiniteGammaIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('bondAmount: power curve requires finite gamma >= 1');
        IntentRuntime::bondAmount(['floor' => 0, 'k' => 1, 'curve' => ['kind' => 'power', 'gamma' => INF]], 5);
    }

    /** A piecewise curve without tiers is refused with its own reason. */
    public function testAPiecewiseCurveWithoutTiersIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('bondAmount: piecewise curve requires at least one tier');
        IntentRuntime::bondAmount(['floor' => 0, 'k' => 1, 'curve' => ['kind' => 'piecewise']], 5);
    }

    /** A negative marginal rate is refused as such (not as a convexity break). */
    public function testANegativeMarginalRateIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('bondAmount: piecewise `marginalK` must be a finite number >= 0');
        IntentRuntime::bondAmount(['floor' => 0, 'k' => 1, 'curve' => ['kind' => 'piecewise', 'tiers' => [['upTo' => 10, 'marginalK' => -1]]]], 5);
    }

    /** A learner's own HarmModel sizes the harm; a `harm` member that is not a HarmModel is ignored. */
    public function testTheLearnersHarmModel(): void
    {
        $five = new HarmModel(static fn($vs): int => 5, static fn($d, $x): int => 1);
        $r = IntentRuntime::routeAction(self::learner(0.5, $five), self::outcome());
        self::assertSame(5, $r['harm']);
        $r = IntentRuntime::routeAction(self::learner(0.5, 'not a model'), self::outcome());
        self::assertSame(1, $r['harm']);
        self::assertSame('optimistic', $r['route']);
    }

    /** A negative harm never gives a negative risk: the risk is clamped at 0. */
    public function testRiskIsClampedAtZero(): void
    {
        $neg = new HarmModel(static fn($vs): int => -2, static fn($d, $x): int => 1);
        $r = IntentRuntime::routeAction(self::learner(0.5, $neg), self::outcome(), ['hMax' => 4]);
        self::assertSame(0, $r['risk']);
    }

    /** p exactly 1 - 1e-12 is the confirmed region: low risk allows, a zero threshold judges for risk (not for an unconfirmed region). */
    public function testTheConfirmedRegionBoundary(): void
    {
        $p = 1 - 1e-12;
        $r = IntentRuntime::routeAction(self::learner($p, null), self::outcome());
        self::assertSame('allow', $r['route']);
        self::assertFalse($r['judges']);
        $r = IntentRuntime::routeAction(self::learner($p, null), self::outcome(), ['theta2' => 0]);
        self::assertSame('optimistic', $r['route']);
        self::assertSame("risk \u{2265} \u{03B8}\u{2082}: bonded claim + judges", $r['reason']);
        self::assertSame(1.0, $r['bond']);
    }

    /** actionDigest is the canonical hash of the action. */
    public function testActionDigest(): void
    {
        $a = Obj::of(['verb' => 'v', 'resource' => 'r']);
        self::assertSame(IntentV2::hashCanonical($a), IntentRuntime::actionDigest($a));
    }

    /** A JIT request for an outcome without values carries an empty values object and an integer p_ppm. */
    public function testTheJitRequest(): void
    {
        $r = IntentRuntime::jitConsentRequest(self::vs(), Obj::of(['verb' => 'v']), 0.5, 'ref', 'md');
        self::assertSame([], $r->get('values')->keys());
        self::assertSame(500000, $r->get('p_ppm'));
        self::assertSame(1, $r->get('v'));
    }

    /** The IC-Att: v 1, the caller's verdict digest (sorted), the attestation forwarded only when given, a missing score as 0 ppm and an infinite cutoff as null. */
    public function testTheIcAttFields(): void
    {
        $seen = [];
        $verify = static function ($verdicts, Obj $vo) use (&$seen): Obj {
            $seen[] = $vo;
            return Obj::of(['ok' => true, 'agreeCount' => 2, 'cutoff' => INF]);
        };
        $digest = static fn($v): string => 'd:' . $v;
        $input = Obj::of(['intentRef' => 'ir', 'mapDigest' => 'md', 'actionDigest' => 'ad', 'goalCommitment' => 'gc']);
        $att = IntentRuntime::intentConformanceAttestation($input, ['b', 'a'], ['k' => 2, 'attestation' => 'ATT'], $verify, $digest);
        self::assertSame(1, $att->get('v'));
        self::assertSame(['d:a', 'd:b'], $att->get('verdict_digests'));
        self::assertSame(0, $att->get('aggregate_score_ppm'));
        self::assertNull($att->get('cutoff_ppm'));
        self::assertSame('ATT', $seen[0]->get('attestation'));
        IntentRuntime::intentConformanceAttestation($input, [], ['k' => 2], $verify, $digest);
        self::assertFalse($seen[1]->has('attestation'));
    }

    /** A truthy but non-true ok bit that the recomputation reproduces passes re-verification. */
    public function testATruthyOkPasses(): void
    {
        $verify = static fn($verdicts, Obj $vo): Obj => Obj::of(['ok' => 1, 'agreeCount' => 1, 'aggregateScore' => 0.5]);
        $input = Obj::of(['intentRef' => 'ir', 'mapDigest' => 'md', 'actionDigest' => 'ad', 'goalCommitment' => 'gc']);
        $att = IntentRuntime::intentConformanceAttestation($input, [], ['k' => 1], $verify);
        self::assertSame(['ok' => true, 'problems' => []], IntentRuntime::verifyIcAtt($att, $input, [], ['k' => 1], $verify));
    }

    /** The semantic risk contribution: 1 for a non-number or a non-finite score, else 1 - score clamped to [0, 1]. */
    public function testSemanticRiskContribution(): void
    {
        self::assertSame(1, IntentRuntime::semanticRiskContribution('x'));
        self::assertSame(1, IntentRuntime::semanticRiskContribution(INF));
        self::assertSame(0, IntentRuntime::semanticRiskContribution(2));
        self::assertSame(1.0, IntentRuntime::semanticRiskContribution(0));
        self::assertSame(0.0, IntentRuntime::semanticRiskContribution(1));
        self::assertSame(0.75, IntentRuntime::semanticRiskContribution(0.25));
    }
}
