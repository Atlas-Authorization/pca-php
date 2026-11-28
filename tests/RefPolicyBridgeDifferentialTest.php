<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\PolicyBridge;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** The policy bridge (Cedar / Rego / OpenFGA / strict CEL / decide) against the TS reference: test-data/ref-policy-bridge.json.gz. */
final class RefPolicyBridgeDifferentialTest extends TestCase
{
    private const FILE = 'ref-policy-bridge.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'cedarToPca' => fn(array $a) => PolicyBridge::cedarToPca(...$a),
            'translateCedar' => fn(array $a) => PolicyBridge::translateCedar(...$a),
            'regoToPca' => fn(array $a) => PolicyBridge::regoToPca(...$a),
            'openfgaToPca' => fn(array $a) => PolicyBridge::openfgaToPca(...$a),
            'decide' => fn(array $a) => PolicyBridge::decide(...$a),
            'celToCondition' => fn(array $a) => PolicyBridge::celToCondition(...$a),
            'celToPredicate' => fn(array $a) => PolicyBridge::celToPredicate(...$a),
            'celConditionsToPca' => fn(array $a) => PolicyBridge::celConditionsToPca(...$a),
            'parseCel' => fn(array $a) => PolicyBridge::parseCel(...$a),
        ]);
    }
}
