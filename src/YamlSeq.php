<?php

declare(strict_types=1);

namespace Atlas\Pca;

/** A sequence with object identity, so the YAML writer can anchor it when the same list is reachable twice (a PHP array is a value and has none). */
final class YamlSeq
{
    /** @param list<mixed> $items */
    public function __construct(public array $items = [])
    {
    }
}
