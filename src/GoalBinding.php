<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Decision.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';

/** Decision-to-effect binding and the claimed-fidelity gate. */
final class GoalBinding
{
    /** Digest of exactly the action that was decided: verb, resource and every parameter. */
    public static function actionDigest(mixed $a): string
    {
        return Pca::hashCanonical(AnalyzerJs::uobj(['d' => 'atlas-pca/goal-action/v1', 'act' => $a]));
    }

    public static function bindDecision(mixed $a, mixed $decision): Obj
    {
        return AnalyzerJs::uobj(['decision' => $decision, 'action_digest' => self::actionDigest($a)]);
    }

    /** True only for an `allow` bound to exactly this action (swapped params or verb, escalate, deny all refuse). Total. */
    public static function guardExecute(mixed $b, mixed $executed): bool
    {
        try {
            if (AnalyzerJs::jget($b, 'decision') !== 'allow') {
                return false;
            }
            $x = AnalyzerJs::jget($b, 'action_digest');
            return is_string($x) && hash_equals($x, self::actionDigest($executed));
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * An agent-claimed fidelity never moves the outcome; only a replayed fidelity below the minimum can, only downward
     * (escalate); a NaN or non-numeric replay is unconfirmed and tightens. A null / undefined replay is absent.
     */
    public static function claimGate(mixed $base, mixed $minPpm, mixed $claimedPpm = null, mixed $replayedPpm = null): mixed
    {
        if ($replayedPpm === null || AnalyzerJs::isUndef($replayedPpm)) {
            return $base;
        }
        $ok = Js::isNum($replayedPpm) && Js::isNum($minPpm) && Js::num($replayedPpm) >= Js::num($minPpm);
        return $ok ? $base : Decision::tighten($base, 'escalate');
    }

    /** Hiding goal commitment: sha256("pca-goal:v3:commit:<goal>:<policy>:<salt>"), base64url. */
    public static function goalCommit(mixed $goalDigest, mixed $policyDigest, mixed $salt): string
    {
        $s = 'pca-goal:v3:commit:' . AnalyzerJs::jsStr($goalDigest) . ':' . AnalyzerJs::jsStr($policyDigest) . ':' . AnalyzerJs::jsStr($salt);
        return Pca::b64u(hash('sha256', Js::utf8($s), true));
    }

    /** Constant-time check that `commit` opens to (goal, policy, salt). */
    public static function openCommit(mixed $commit, mixed $goalDigest, mixed $policyDigest, mixed $salt): bool
    {
        if (!is_string($commit)) {
            throw new \TypeError('commit must be a string');
        }
        return hash_equals($commit, self::goalCommit($goalDigest, $policyDigest, $salt));
    }
}
