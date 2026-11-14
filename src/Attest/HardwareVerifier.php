<?php
declare(strict_types=1);

namespace Atlas\Pca\Attest;

/** What every vendor verifier answers to: `verify(document, expected, nowMs)` -> `{ok, bound?, reason?, measured?, hostAsserted?}`. */
interface HardwareVerifier
{
    /** @return array<string,mixed> */
    public function verify(mixed $document, mixed $expected, mixed $nowMs): array;
}
