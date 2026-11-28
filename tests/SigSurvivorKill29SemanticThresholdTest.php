<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Pca;
use Atlas\Pca\Obj;
use Atlas\Pca\SemanticThreshold;
use PHPUnit\Framework\TestCase;

/** Mutation kills for SemanticThreshold: the public digest, the unknown-alg refusal, the Ed25519 statement, the verdict member types and the risk clamp. */
final class SigSurvivorKill29SemanticThresholdTest extends TestCase
{
    private static function seed(): string
    {
        return hash('sha256', 'atlas-pca-conformance/g29-semantic/judge', true);
    }

    private static function sign(array $v): Obj
    {
        return SemanticThreshold::signJudgeVerdict(self::seed(), Obj::of($v + ['actionDigest' => 'ad', 'goalCommitment' => 'gc', 'faithful' => true, 'score' => 0.5,
            'judgeMeasurement' => 'm']));
    }

    private static function expected(mixed $ad = 'ad'): Obj
    {
        return Obj::of(['actionDigest' => $ad, 'goalCommitment' => 'gc']);
    }

    public function testActionDigestIsPublic(): void
    {
        $a = Obj::of(['verb' => 'v']);
        $this->assertSame(Pca::hashCanonical($a), SemanticThreshold::actionDigest($a));
    }

    public function testUnknownAlgIsNamed(): void
    {
        try {
            SemanticThreshold::signJudgeVerdict(self::seed(), Obj::of([]), ['alg' => 'nope']);
            $this->fail('expected a refusal');
        } catch (\RangeException $e) {
            $this->assertSame("signJudgeVerdict: unknown signature alg 'nope'", $e->getMessage());
        }
    }

    /** An Ed25519 verdict is signed over the Ed25519 statement even when the input carries another alg. */
    public function testAnEd25519VerdictIgnoresAnInputAlg(): void
    {
        $this->assertTrue(SemanticThreshold::verifyJudgeVerdict(self::sign([]), self::expected()), 'control');
        $this->assertTrue(SemanticThreshold::verifyJudgeVerdict(self::sign(['alg' => 'ml-dsa-65']), self::expected()));
    }

    /** The bindings must be text, the score a number in [0, 1], the measurement text, whatever the signature covers. */
    public function testVerdictMemberTypes(): void
    {
        $this->assertFalse(SemanticThreshold::verifyJudgeVerdict(self::sign(['actionDigest' => 5]), self::expected(5)));
        $this->assertFalse(SemanticThreshold::verifyJudgeVerdict(self::sign(['score' => 'x']), self::expected()));
        $this->assertFalse(SemanticThreshold::verifyJudgeVerdict(self::sign(['score' => -0.5]), self::expected()));
        $v = self::sign(['judgeMeasurement' => '5']);
        $this->assertTrue(SemanticThreshold::verifyJudgeVerdict($v, self::expected()), 'control');
        $v->set('judgeMeasurement', 5);
        $this->assertFalse(SemanticThreshold::verifyJudgeVerdict($v, self::expected()));
    }

    /** The clamp keeps the float at the ends of [0, 1]. */
    public function testRiskContributionEnds(): void
    {
        $this->assertSame(1.0, SemanticThreshold::riskContribution(0));
        $this->assertSame(0.0, SemanticThreshold::riskContribution(1));
        $this->assertSame(1, SemanticThreshold::riskContribution(INF));
    }
}
