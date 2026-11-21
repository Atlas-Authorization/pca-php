<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Pca;
use Atlas\Pca\ProvenanceGate;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** Build provenance as a K1 discharge against the TS reference: test-data/base-provgate.json.gz (oracles-base/provgate-oracle.mts). */
final class BaseProvenanceGateDifferentialKillTest extends TestCase
{
    private const FILE = 'base-provgate.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    private static function raw(string $b64u): string
    {
        return Pca::unb64u($b64u) ?? throw new \InvalidArgumentException('oracle bytes');
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'provenanceFactsError' => fn(array $a) => ProvenanceGate::factsError($a[0]),
            'provenancePolicyError' => fn(array $a) => ProvenanceGate::policyError($a[0]),
            'provenanceGate' => fn(array $a) => ProvenanceGate::gate($a[0]),
            // wire form: (leaf b64u, index, size, [proof b64u], root b64u)
            'verifyRfc9162Inclusion' => fn(array $a) => ProvenanceGate::verifyRfc9162Inclusion(self::raw($a[0]), $a[1], $a[2],
                array_map(self::raw(...), $a[3]), self::raw($a[4])),
            'rfc9162LeafHash' => fn(array $a) => Base::outBytes(ProvenanceGate::rfc9162LeafHash(self::raw($a[0]))),
            'provenanceCaveat' => function (array $a) {
                $o = [];
                foreach ($a[0]->keys() as $key) {
                    $o[$key] = $a[0]->get($key);
                }
                return ProvenanceGate::caveat($o);
            },
        ]);
    }
}
