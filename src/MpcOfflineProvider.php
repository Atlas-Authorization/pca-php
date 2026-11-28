<?php
declare(strict_types=1);

namespace Atlas\Pca;

/** A source of the SPDZ offline phase: the MAC key, authenticated triples and authenticated input sharings. */
interface MpcOfflineProvider
{
    public function n(): int;

    /** @return array{n:int,alphaShares:list<\GMP>,alpha:\GMP,extraKeys:list<array{alphaShares:list<\GMP>,alpha:\GMP}>} */
    public function macContext(): array;

    /** @return array{a:array,b:array,c:array} an authenticated triple (see MpcSpdz) */
    public function genAuthTriple(): array;

    /** Authenticated sharing of $value contributed by party $owner. */
    public function authInput(\GMP $value, int $owner): array;
}
