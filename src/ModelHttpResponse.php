<?php

declare(strict_types=1);

namespace Atlas\Pca;

/** What an injected transport returns (the PHP form of the reference's fetch response): `ok`, `status` and a `json()` that may throw. */
final class ModelHttpResponse
{
    /** @param \Closure():mixed $body */
    public function __construct(public readonly bool $ok, public readonly int $status, private readonly \Closure $body)
    {
    }

    public function json(): mixed
    {
        return ($this->body)();
    }
}
