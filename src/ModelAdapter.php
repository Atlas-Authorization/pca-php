<?php

declare(strict_types=1);

namespace Atlas\Pca;

require_once __DIR__ . '/Json.php';

/** A model behind an object. The caller binds the model id, version and transport; this package holds no credentials and no network client. */
interface ModelAdapter
{
    /** Pinned model id (e.g. a dated snapshot); recorded. */
    public function id(): string;

    public function version(): ?string;

    /** Returns the raw completion text for a request {system, user, temperature}. A throw is caught and recorded as "no suggestion". */
    public function complete(Obj $req): mixed;
}
