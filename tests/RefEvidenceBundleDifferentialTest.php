<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\EvidenceVerify;
use Atlas\Pca\Obj;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The deterministic dispute-evidence replay (findings, summary and report digest over the chargeback walkthrough and its tampered /
 * re-trusted variants) against the TS reference: test-data/ref-evidence-bundle-py.json.gz. `trust.verifiers` members are constant
 * verdicts the native ports return.
 */
final class RefEvidenceBundleDifferentialTest extends TestCase
{
    private const FILE = 'ref-evidence-bundle-py.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function verify(mixed $bundle, mixed $trust): Obj
    {
        if ($trust instanceof Obj && $trust->get('verifiers') instanceof Obj) {
            $ports = new Obj();
            foreach ($trust->get('verifiers')->keys() as $name) {
                $verdict = $trust->get('verifiers')->get($name);
                $ports->set($name, static fn($artifact, $b) => $verdict);
            }
            $t = new Obj();
            foreach ($trust->keys() as $k) {
                $t->set($k, $k === 'verifiers' ? $ports : $trust->get($k));
            }
            $trust = $t;
        }
        return EvidenceVerify::verifyEvidenceBundle($bundle, $trust);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'verifyEvidenceBundle' => fn(array $a) => self::verify($a[0] ?? null, $a[1] ?? null),
        ]);
    }
}
