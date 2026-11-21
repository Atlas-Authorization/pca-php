<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

require_once __DIR__ . '/Common.php';

/** Constructor-time typing of optional policy allowlists: absent/null means "no list"; anything else must be an array of strings. */
final class PolicyLists
{
    /** @throws AttestConstructError */
    public static function assertOptionalStringList(string $ctor, string $key, mixed $v): void
    {
        if ($v === null) {
            return;
        }
        if (!Common::isList($v) || array_filter($v, 'is_string') !== $v) {
            throw new AttestConstructError("$ctor: policy.$key must be an array of strings");
        }
    }
}
