<?php
declare(strict_types=1);

namespace Atlas\Pca;

/**
 * Per-stakeholder decision vector helpers. A decision vector is ['allow' => 0|1, 't' => 1..3, 'rQuant' => 0..Q] (the decision a
 * party contributes to the MPC).
 */
final class MpcParty
{
    public const DEFAULT_Q = 100;

    /** Quantizes r in [0,1] to {0..Q}; non-finite is the worst case (Q). */
    public static function quantizeR(float $r, int $Q = self::DEFAULT_Q): int
    {
        if (is_nan($r) || is_infinite($r)) {
            return $Q;
        }
        $q = (int) floor(max(0.0, min(1.0, $r)) * $Q + 0.5); // JS Math.round for the non-negative values reached here
        return max(0, min($Q, $q));
    }

    /**
     * Evaluates a party's own decide input (an Obj, see Decide) through the Policy VM to its decision vector: allow = the guardian
     * share is released, t = the required threshold, rQuant = the quantized risk.
     * @return array{allow:int,t:int,rQuant:int}
     */
    public static function evaluateParty(mixed $decideInput, int $Q = self::DEFAULT_Q): array
    {
        $d = Decide::decide($decideInput);
        $r = $d['r'];
        return ['allow' => $d['releaseGuardianShare'] === true ? 1 : 0, 't' => $d['requiredThreshold']['t'],
            'rQuant' => self::quantizeR(is_int($r) || is_float($r) ? (float) $r : NAN, $Q)];
    }
}
