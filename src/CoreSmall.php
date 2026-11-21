<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/Agent.php';
require_once __DIR__ . '/Js.php';
require_once __DIR__ . '/IntentWb.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentV2Session.php';
require_once __DIR__ . '/FreshAt.php';

/**
 * Small public helpers of the PCA core: the verify-hook placeholder, the budget-allocation monotonicity check, the bound threshold-share
 * message, the revocation message and the intent session goal. Pure; the messages are bytes (PHP strings).
 */
final class CoreSmall
{
    public const REVOKE_DOMAIN = "atlas-pca/revoke/v1\0";

    /** The verify hook of a layer that is not enforced here: `{enforced: false}`. */
    public static function notEnforced(mixed $ctx = null): array
    {
        return ['enforced' => false];
    }

    /** The carried-allocation caveat `{type: 'budget_alloc', limit}` of a delegation hop. */
    public static function budgetAllocCaveat(int|float $limit): Obj
    {
        return Sign::n(['type' => 'budget_alloc', 'limit' => $limit]);
    }

    /**
     * The carried allocations in a (flattened, append-only) caveat list are well-formed and MONOTONE non-increasing in delegation order:
     * every `budget_alloc.limit` is finite and >= 0, and never greater than the previous one. A list with none trivially passes.
     * @return array{ok:bool,reason?:string}
     */
    public static function allocationsMonotone(mixed $caveats): array
    {
        if (!is_array($caveats) || !array_is_list($caveats)) {
            return ['ok' => false, 'reason' => 'malformed caveats'];
        }
        $prev = INF;
        foreach ($caveats as $i => $cv) {
            if (!($cv instanceof Obj) || $cv->get('type') !== 'budget_alloc') {
                continue;
            }
            $lim = Js::num($cv->get('limit'));
            if ($lim === null || !is_finite($lim) || $lim < 0) {
                return ['ok' => false, 'reason' => "budget_alloc caveat $i: limit must be a finite number >= 0"];
            }
            if ($lim > $prev) {
                return ['ok' => false, 'reason' => "budget_alloc caveat $i: allocation " . IntentWb::jsStr($lim) . " widens the parent's carried allocation "
                    . IntentWb::jsStr($prev) . ' (monotone: a child can only allocate <= its parent)'];
            }
            $prev = $lim;
        }
        return ['ok' => true];
    }

    /**
     * The bound threshold-share message `"atlas-pca/share/<role>\0" || sha256(message) || signerSetHash || t(1 byte) [|| suite tag]`: a share
     * can only be replayed into the same signer set and threshold. Throws for a `$t` other than 1, 2 or 3 and for a malformed signer set.
     */
    public static function shareMessage(string $role, string $message, mixed $signerSet, mixed $t, ?string $alg = null): string
    {
        $n = Js::num($t);
        if ($n !== 1.0 && $n !== 2.0 && $n !== 3.0) {
            throw new \RangeException('shareMessage: t must be 1, 2 or 3');
        }
        $ssh = Pca::signerSetHashRaw(Sign::n($signerSet)) ?? throw new \InvalidArgumentException('shareMessage: malformed signer set');
        $tag = $alg !== null && $alg !== 'ed25519' && in_array($alg, Pca::REGISTERED_SUITES, true) ? Pca::SHARE_SUITE_TAG . $alg : '';
        return Pca::SHARE_DOMAIN_PREFIX . Js::utf8($role) . "\0" . hash('sha256', $message, true) . $ssh . chr((int)$n) . $tag;
    }

    /** Domain-separated bytes a PRINCIPAL signs to revoke a capability under their own grant. */
    public static function revokeMessage(string $grantRef, string $revokedCapId): string
    {
        return self::REVOKE_DOMAIN . Json::canonicalizeNative(Obj::of(['grant_ref' => $grantRef, 'revoked_cap_id' => $revokedCapId]));
    }

    /** The goal a session grant (G_0 or D_k) commits to: `pca-intent:v2:<session>:<map_digest>` (`pca-intent:v2c:` over a committed map). */
    public static function intentGoalV2(string $session, string $mapDigest, ?string $mapForm = null): string
    {
        return ($mapForm === 'commit' ? Pca::INTENT_GOAL_V2C_PREFIX : Pca::INTENT_GOAL_V2_PREFIX) . $session . ':' . $mapDigest;
    }

    /** `{session, mapDigest}` of a `pca-intent:v2:` goal, or null (both parts must be canonical base64url of 32 bytes). @return ?array{session:string,mapDigest:string} */
    public static function parseIntentGoalV2(mixed $goal): ?array
    {
        if (!is_string($goal) || !str_starts_with($goal, Pca::INTENT_GOAL_V2_PREFIX)) {
            return null;
        }
        $parts = explode(':', substr($goal, strlen(Pca::INTENT_GOAL_V2_PREFIX)));
        if (count($parts) !== 2 || !Pca::isCanonicalB64u($parts[0], 32) || !Pca::isCanonicalB64u($parts[1], 32)) {
            return null;
        }
        return ['session' => $parts[0], 'mapDigest' => $parts[1]];
    }
}
