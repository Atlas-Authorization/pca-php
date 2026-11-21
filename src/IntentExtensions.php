<?php
declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Pca.php';
require_once __DIR__ . '/FreshAt.php';
require_once __DIR__ . '/IntentV2.php';
require_once __DIR__ . '/IntentV2Session.php';

/**
 * The reference's INTENT_WIRE_EXTENSION and INTENT_EXTENSIONS. This verifier always has the intent layer loaded; the values are exported so a caller can run the
 * same checks or compare against the reference. Each wire validator returns null when the slot is well formed, else a short reason.
 */
final class IntentExtensions
{
    /** @return array{intent:\Closure,intentSession:\Closure,freshAt:\Closure} the Intent Layer's wire validators (`INTENT_WIRE_EXTENSION`) */
    public static function wire(): array
    {
        return [
            'intent' => static fn(mixed $v): ?string => Pca::validateIntentWire($v),
            'intentSession' => static fn(mixed $v): ?string => IntentV2::validateIntentSessionWire($v),
            'freshAt' => static fn(mixed $v): ?string => FreshAt::validateWire($v),
        ];
    }

    /** @return array{wire:array,intentBinding:\Closure,intentV2:\Closure,freshAt:\Closure} the full extension set (`INTENT_EXTENSIONS`) */
    public static function full(): array
    {
        return ['wire' => self::wire(),
            'intentBinding' => static fn(mixed ...$a): array => Pca::decideIntentBinding(...$a),
            'intentV2' => static fn(mixed $p, mixed $grant, mixed $ctx, int $now): array => IntentV2::decideIntentV2($p, $grant, $ctx, $now),
            'freshAt' => static fn(bool $has, mixed $member, mixed $policy, int $now): array => FreshAt::decide($has, $member, $policy, $now)];
    }

    /** @see full() */
    public static function all(): array
    {
        return self::full();
    }
}
