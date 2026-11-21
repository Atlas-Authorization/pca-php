<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** One FN-DSA suite of the registry (see {@see Fndsa}). */
final class FnDsaSuite
{
    public function __construct(
        public readonly string $alg,
        public readonly string $variant,
        public readonly bool $hasEd25519,
        public readonly int $sigBytes,
        public readonly bool $needsPqPk,
        public readonly int $pqPkBytes,
        public readonly bool $needsPqSig,
        public readonly int $pqSigBytes,
        public readonly int $fnSigBytes,
    ) {
    }
}
