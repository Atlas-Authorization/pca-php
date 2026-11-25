<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/AnalyzerJs.php';

/**
 * The one signer of the goal-to-decision flow: artifacts (approvals, test sets, policy pins, precedents) signed with the
 * suite-agile signer under a per-kind domain over STRICT canonical bytes.
 */
final class GoalSign
{
    /** Domain separation: an artifact of one kind never verifies as another kind. */
    public static function goalDomain(string $kind): string
    {
        return "atlas-pca/goal/$kind/v1\0";
    }

    private static function kp(mixed $secret): KeyPair
    {
        return $secret instanceof KeyPair ? $secret : new KeyPair((string)$secret);
    }

    /** The pinned public identity (b64u Ed25519) of a signer secret (a 32-byte seed or a KeyPair). */
    public static function signerId(mixed $secret): string
    {
        return self::kp($secret)->public;
    }

    /** Sign a flat artifact body (it must already carry its signer identity member). Throws on a non-canonical body. */
    public static function signGoalArtifact(string $kind, mixed $body, mixed $secret, mixed $opts = null): Obj
    {
        return Sign::signArtifact(self::goalDomain($kind), $body, self::kp($secret), self::alg($opts), self::pq($opts));
    }

    private static function alg(mixed $opts): ?string
    {
        $a = Js::opt($opts, 'alg');
        return is_string($a) ? $a : null;
    }

    private static function pq(mixed $opts): ?PqKeyPair
    {
        $p = Js::opt($opts, 'pq');
        return $p instanceof PqKeyPair ? $p : null;
    }

    /** Verify against the caller's PINNED signers: the pin whose `pk` equals the artifact's own signer member must verify. Total. */
    public static function verifyGoalArtifact(mixed $kind, mixed $artifact, mixed $signerField, mixed $pins): bool
    {
        try {
            if (!($artifact instanceof Obj) || !is_string($kind) || !is_string($signerField)) {
                return false;
            }
            if (IntentWb::artifactSuiteError($artifact) !== null) {
                return false;
            }
            $who = $artifact->has($signerField) ? $artifact->get($signerField) : null;
            if (!is_string($who)) {
                return false;
            }
            foreach (AnalyzerJs::reqList($pins) as $p) {
                if ($p === null) {
                    return false; // a null pin makes the reference throw: refuse
                }
                $pk = is_string($p) ? $p : (($p instanceof Obj && $p->has('pk')) ? $p->get('pk') : null);
                if ($pk === $who) {
                    return IntentWb::verifyArtifactSig(self::goalDomain($kind), $artifact, $p) === true;
                }
            }
            return false;
        } catch (\Throwable) {
            return false;
        }
    }

    /** A payload wrapped with its kind and signer: the envelope used by tests, pins and precedents. */
    public static function signPayload(string $kind, mixed $payload, mixed $secret, mixed $opts = null): Obj
    {
        return self::signGoalArtifact($kind, AnalyzerJs::uobj(['v' => 1, 'kind' => $kind, 'signer' => self::signerId($secret), 'payload' => $payload]), $secret, $opts);
    }

    public static function verifyPayload(mixed $s, mixed $kind, mixed $pins): bool
    {
        return $s instanceof Obj && AnalyzerJs::strictEq($s->has('v') ? $s->get('v') : null, 1)
            && ($s->has('kind') ? $s->get('kind') : null) === $kind && self::verifyGoalArtifact($kind, $s, 'signer', $pins);
    }
}
