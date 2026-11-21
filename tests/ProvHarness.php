<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

require_once __DIR__ . '/../src/ArgProvenance.php';

use Atlas\Pca\ArgProvenance;
use Atlas\Pca\KeyPair;
use Atlas\Pca\Obj;
use Atlas\Pca\ProvenanceRecorder;

/**
 * Provenance by default in the authorize harnesses (as the reference's harnesses do): every operation the signed fixtures run
 * comes straight from the principal, so the harness presents a principal-direct bundle recorded under a fixed, pinned harness
 * mediator (Ed25519 seed = 32 bytes of 0x01, mediator `conformance-harness`, kid `k1`). The gate then passes and the recorded
 * outcomes are those of the rules under test. The gate is never turned off.
 */
final class ProvHarness
{
    public const MEDIATOR = 'conformance-harness';
    public const KID = 'k1';

    public static function recorder(): ProvenanceRecorder
    {
        return new ProvenanceRecorder(self::MEDIATOR, self::KID, new KeyPair(str_repeat("\x01", 32)));
    }

    public static function pin(): Obj
    {
        return self::recorder()->pin;
    }

    /** The principal-direct bundle of `$operation`; null for a malformed operation (the pipeline refuses those before the gate). */
    public static function bundle(mixed $operation): ?Obj
    {
        try {
            return ArgProvenance::principalDirect(self::recorder(), $operation);
        } catch (\Throwable) {
            return null;
        }
    }

    /** Named arguments of Authorize::authorize: this operation's bundle and the harness pin. */
    public static function args(mixed $operation): array
    {
        return ['provenance' => self::bundle($operation), 'provenanceMediators' => [self::pin()]];
    }

    /** A bundle reader (Authorize `provenanceBundle` or AuthorizeOptions `provenanceBundle`): the principal-direct bundle of the operation being authorized (its last argument). */
    public static function reader(): \Closure
    {
        return static fn (mixed ...$a): ?Obj => self::bundle($a[count($a) - 1]);
    }

    /** Named arguments of AuthorizeOptions / Protect::protect / an Executor's authorize configuration: the harness pin and {@see reader}. */
    public static function options(): array
    {
        return ['provenanceMediators' => [self::pin()], 'provenanceBundle' => self::reader()];
    }
}
