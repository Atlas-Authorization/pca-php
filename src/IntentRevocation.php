<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/IntentWb.php';

/**
 * Identifiers and scopes of the intent layer's revocation (`pca-intent:` ids of sessions, committed maps, delta grants and profile
 * versions, the `grant_ref` scopes of the epochs that revoke them) and the T22 exposure bound. Pure string builders.
 */
final class IntentRevocation
{
    public const PREFIX = 'pca-intent:';
    /** Default exposure skew: 60 s. */
    public const DEFAULT_SKEW_MS = 60_000;
    /** The default maximum age (s) of a revocation epoch by tier (§3.9): 60 s for payment tiers, 300 s otherwise. */
    public const DEFAULT_MAX_AGE_S = ['payment' => 60, 'default' => 300];

    public static function sessionRevocationId(string $session): string
    {
        return self::PREFIX . 'session:' . $session;
    }

    public static function mapRevocationId(string $mapDigest): string
    {
        return self::PREFIX . 'map:' . $mapDigest;
    }

    public static function deltaRevocationId(string $grantId): string
    {
        return self::PREFIX . 'delta:' . $grantId;
    }

    /** `pca-intent:profile:<id>@<version>` (the version as JavaScript prints a number). */
    public static function profileRevocationId(string $profileId, int|float $version): string
    {
        return self::PREFIX . 'profile:' . $profileId . '@' . IntentWb::jsStr($version);
    }

    /** The `grant_ref` of a session revocation epoch. */
    public static function sessionRevocationScope(string $session): string
    {
        return 'pca-intent-session:' . $session;
    }

    /** The `grant_ref` of a profile's revocation epoch (the owner publishes it at `revocation.epoch_uri`). */
    public static function profileRevocationScope(string $profileId): string
    {
        return 'pca-intent-profile:' . $profileId;
    }

    /**
     * The exposure window of T22 for an honest publisher: an action verified at `$now` can rely on an epoch that predates a revocation at
     * `$tRevoked` only while `$now <= $tRevoked + $maxAgeMs + $skewMs`. Hosts use it to report the bound.
     */
    public static function revocationExposureEnd(int|float $tRevoked, int|float $maxAgeMs, int|float $skewMs = self::DEFAULT_SKEW_MS): int|float
    {
        return $tRevoked + $maxAgeMs + $skewMs;
    }
}
