<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Js;
use Atlas\Pca\Obj;

/** A scripted token-endpoint response (ok / status / json() / text()). */
final class RefConnectResp
{
    public bool $ok;
    public mixed $status;

    public function __construct(private readonly Obj $r)
    {
        $this->ok = $r->get('ok') === true;
        $this->status = $r->get('status');
    }

    public function json(): mixed
    {
        if (Js::truthy($this->r->get('jsonThrows'))) {
            throw new \RuntimeException('bad json');
        }
        return $this->r->get('json');
    }

    public function text(): string
    {
        if (Js::truthy($this->r->get('textThrows'))) {
            throw new \RuntimeException('bad text');
        }
        $t = $this->r->get('text');
        return is_string($t) ? $t : '';
    }
}
