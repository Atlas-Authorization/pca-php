<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

/**
 * The one test-side risk source: calm inputs (nothing far from the goal, fully reversible, no blast radius, no taint, full confidence, no
 * age). A fixture grant with a priced risk policy needs SOME risk source or Authorize denies it at the threshold (the production default
 * stays strict, the weights stay as signed); tests that are not about risk pass `hard: CalmRisk::hard()`.
 */
final class CalmRisk
{
    /** @return array{semanticDistance: float, reversibility: float, blastRadius: float, taint: float, confidence: float, age: float} */
    public static function inputs(): array
    {
        return ['semanticDistance' => 0.0, 'reversibility' => 1.0, 'blastRadius' => 0.0, 'taint' => 0.0, 'confidence' => 1.0, 'age' => 0.0];
    }

    public static function source(): \Closure
    {
        return static fn(): array => self::inputs();
    }

    /** The `hard` argument of Authorize::authorize with the calm source, plus extra members. @return array<string, mixed> */
    public static function hard(array $more = []): array
    {
        return ['risk' => self::source()] + $more;
    }
}
