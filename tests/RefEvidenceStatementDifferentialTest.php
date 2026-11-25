<?php

declare(strict_types=1);

namespace Atlas\Pca\Tests;

use Atlas\Pca\Evidence;
use Atlas\Pca\Js;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The COSE signed statement over the evidence bundle reference (Ed25519, byte for byte) against the TS reference:
 * test-data/ref-evidence-statement.json.gz. The signing key is sha256("atlas-pca-conformance/" + label).
 */
final class RefEvidenceStatementDifferentialTest extends TestCase
{
    private const FILE = 'ref-evidence-statement.json.gz';

    public static function provide(): array
    {
        return Base::datasets(self::FILE);
    }

    #[DataProvider('provide')]
    public function testAgreesWithTheReference(string $file, string $fn, int $k): void
    {
        Base::run($file, $fn, $k, [
            'evidenceSignedStatement' => function (array $a) {
                $spec = $a[1];
                $opts = ['alg' => $spec->get('alg'), 'issuer' => $spec->get('issuer'),
                    'key' => hash('sha256', 'atlas-pca-conformance/' . $spec->get('label'), true)];
                if ($spec->has('subject')) {
                    $opts['subject'] = $spec->get('subject');
                }
                return Base::outBytes(Evidence::evidenceSignedStatement($a[0], $opts));
            },
        ]);
    }
}
