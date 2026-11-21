<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';

/** provider and model; the key is held only to be handed to the adapter and is never serialised or dumped. */
final class ModelEnvConfig
{
    public function __construct(public readonly string $provider, public readonly string $model, private readonly string $apiKey)
    {
    }

    public function apiKey(): string
    {
        return $this->apiKey;
    }

    /** {provider, model}: what may be shown or stored. */
    public function toObj(): Obj
    {
        return Obj::of(['provider' => $this->provider, 'model' => $this->model]);
    }

    /** @return array<string,string> */
    public function __debugInfo(): array
    {
        return ['provider' => $this->provider, 'model' => $this->model];
    }

    public function __serialize(): array
    {
        throw new \LogicException('a ModelEnvConfig holds a credential and is never serialised');
    }
}
